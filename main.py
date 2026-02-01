# main.py

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional

import aiohttp
import xxhash

import config
from utils import JSON_LOADS
from realms import REALMS
from api_parser import SafeAuction
from ilvl_fetcher import resolve_ilvl, fetch_tww_static_data


# ---------------------------------------------------------
# Global setup
# ---------------------------------------------------------

# All connected realm IDs from realms.py (92 EU realms in your case).
REALM_IDS = list(set(REALMS.values()))

# connected_realm_id -> readable name (first name we saw for this id)
CONNECTED_REALM_NAMES: Dict[int, str] = {}
for name, rid in REALMS.items():
    CONNECTED_REALM_NAMES.setdefault(rid, name)

ACCESS_TOKEN: Optional[str] = None
TOKEN_EXPIRES_AT: float = 0.0
TOKEN_LOCK = asyncio.Lock()

# realm_id -> last xxhash of the payload
REALM_HASHES: Dict[int, str] = {}


# ---------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------

def _ts() -> str:
    """Return current time as HH:MM:SS for log lines."""
    return datetime.now().strftime("%H:%M:%S")


def log_info(msg: str) -> None:
    # neutral grey log line, timestamp only
    print(f"[{_ts()}] {msg}")


def log_warn(msg: str) -> None:
    print(f"[{_ts()}] [WARN] {msg}")


def log_error(msg: str) -> None:
    print(f"[{_ts()}] [ERROR] {msg}")


def log_snipe(msg: str) -> None:
    # highlight snipes with a flame emoji
    print(f"[{_ts()}] 🔥 SNIPE {msg}")


def print_banner() -> None:
    line = "=" * 60
    print()
    print(line)
    print("🎯  WoW Twink Tool - Simple Item Sniper")
    print(line)
    print()


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------

@dataclass
class WatchEntry:
    """
    One watch rule: item_id + target ilvl + max price.
    'note' is just for display in logs/Discord.
    """
    item_id: int
    target_ilvl: int
    max_price_copper: int
    note: str = ""


# ---------------------------------------------------------
# Discord helpers (optional)
# ---------------------------------------------------------

def _chunk_message(content: str, limit: int = 1900) -> List[str]:
    """
    Split a long message into chunks so Discord accepts it.
    """
    lines = content.splitlines()
    chunks: List[str] = []
    current: List[str] = []
    current_len = 0

    for line in lines:
        line_len = len(line) + 1
        if current and current_len + line_len > limit:
            chunks.append("\n".join(current))
            current = [line]
            current_len = line_len
        else:
            current.append(line)
            current_len += line_len

    if current:
        chunks.append("\n".join(current))

    return chunks


async def send_discord_message(session: aiohttp.ClientSession, content: str) -> None:
    """
    Send a single message to the Discord webhook (if configured).
    """
    url = (config.DISCORD_WEBHOOK_URL or "").strip()
    if not url:
        return

    payload = {"content": content}
    try:
        async with session.post(url, json=payload, timeout=10) as resp:
            if resp.status >= 400:
                log_warn(f"Discord webhook status {resp.status}")
    except Exception as e:
        log_warn(f"Discord webhook error: {e!r}")


async def notify_snipes_via_discord(
    session: aiohttp.ClientSession,
    snipes: List[str],
) -> None:
    """
    Send all snipe lines to Discord in one or more messages.
    """
    url = (config.DISCORD_WEBHOOK_URL or "").strip()
    if not url or not snipes:
        return

    full = "\n".join(snipes)
    for chunk in _chunk_message(full):
        await send_discord_message(session, chunk)


# ---------------------------------------------------------
# Token handling
# ---------------------------------------------------------

async def get_valid_token(session: aiohttp.ClientSession) -> Optional[str]:
    """
    Get or refresh the Blizzard OAuth token.
    """
    global ACCESS_TOKEN, TOKEN_EXPIRES_AT

    async with TOKEN_LOCK:
        loop = asyncio.get_event_loop()
        now = loop.time()

        # Reuse token if still valid for at least 120 seconds.
        if ACCESS_TOKEN and now < TOKEN_EXPIRES_AT - 120:
            return ACCESS_TOKEN

        # Try a few times in case of hiccups.
        for _ in range(3):
            try:
                async with session.post(
                    config.OAUTH_TOKEN_URL,
                    data={"grant_type": "client_credentials"},
                    auth=aiohttp.BasicAuth(config.CLIENT_ID, config.CLIENT_SECRET),
                    timeout=10,
                ) as resp:
                    if resp.status != 200:
                        log_warn(f"Token status {resp.status}")
                        continue

                    data = await resp.json()
                    token = data.get("access_token")
                    expires_in = int(data.get("expires_in", 0) or 0)
                    if not token or expires_in <= 0:
                        log_warn("Invalid token response")
                        continue

                    ACCESS_TOKEN = token
                    TOKEN_EXPIRES_AT = now + expires_in
                    return ACCESS_TOKEN
            except Exception as e:
                log_warn(f"Token request error: {e!r}")
                await asyncio.sleep(1)

        return None


# ---------------------------------------------------------
# Watchlist loading
# ---------------------------------------------------------

def load_watch_items_from_json() -> List[dict]:
    """
    Load desired_items.json from the path defined in config.
    """
    path = config.DESIRED_ITEMS_FILE
    if not path.is_file():
        raise FileNotFoundError(f"desired_items.json not found: {path}")

    raw = path.read_bytes()
    data = JSON_LOADS(raw)

    items = data.get("items", [])
    if not isinstance(items, list):
        raise ValueError("desired_items.json: 'items' must be a list")

    return items


def build_watch_map() -> Dict[int, List[WatchEntry]]:
    """
    Build item_id -> list[WatchEntry] from desired_items.json.

    Every entry is active. "note" is only used for display.
    """
    watch_map: Dict[int, List[WatchEntry]] = {}
    raw_items = load_watch_items_from_json()

    for entry in raw_items:
        try:
            item_id = int(entry["item_id"])
            target_ilvl = int(entry["target_ilvl"])
            max_price_g = float(entry["max_price_g"])
            note = str(entry.get("note", "")).strip()
        except (KeyError, ValueError, TypeError) as e:
            log_warn(f"Invalid watch entry {entry!r}: {e!r}")
            continue

        max_price_copper = int(max_price_g * 10_000)

        w = WatchEntry(
            item_id=item_id,
            target_ilvl=target_ilvl,
            max_price_copper=max_price_copper,
            note=note,
        )
        watch_map.setdefault(item_id, []).append(w)

    return watch_map


# ---------------------------------------------------------
# Auction fetching
# ---------------------------------------------------------

def hash_bytes(data: bytes) -> str:
    """
    Hash the auction payload for change detection.
    """
    return xxhash.xxh64(data).hexdigest()


async def fetch_auctions_for_realm(
    session: aiohttp.ClientSession,
    token: str,
    realm_id: int,
    skip_if_unchanged: bool = True,
) -> List[SafeAuction]:
    """
    Fetch and parse auctions for a single connected realm.
    """
    url = (
        f"https://{config.REGION}.api.blizzard.com/"
        f"data/wow/connected-realm/{realm_id}/auctions"
    )
    params = {
        "namespace": config.NAMESPACE,
        "locale": config.LOCALE,
    }
    headers = {
        "Authorization": f"Bearer {token}",
    }

    async with session.get(url, params=params, headers=headers, timeout=30) as resp:
        if resp.status != 200:
            log_warn(f"Realm {realm_id} status {resp.status}")
            return []

        raw_bytes = await resp.read()

    current_hash = hash_bytes(raw_bytes)
    if skip_if_unchanged:
        last_hash = REALM_HASHES.get(realm_id)
        if last_hash == current_hash:
            # Same dump as last time → skip.
            return []
        REALM_HASHES[realm_id] = current_hash

    payload = JSON_LOADS(raw_bytes)
    auctions_raw = payload.get("auctions", [])

    out: List[SafeAuction] = []
    for raw in auctions_raw:
        auc = SafeAuction.from_raw(raw)
        if auc is not None:
            out.append(auc)

    return out


# ---------------------------------------------------------
# Matching logic
# ---------------------------------------------------------

def matches_watch_entry(
    auc: SafeAuction,
    watch_entries: List[WatchEntry],
    final_ilvl: int,
) -> Optional[WatchEntry]:
    """
    Check if this auction matches any watch entry.
    """
    for entry in watch_entries:
        if final_ilvl != entry.target_ilvl:
            continue
        if auc.price > entry.max_price_copper:
            continue
        return entry
    return None


# ---------------------------------------------------------
# Single scan
# ---------------------------------------------------------

async def run_single_scan(session: aiohttp.ClientSession) -> None:
    """
    One full scan over all realms.
    """
    token = await get_valid_token(session)
    if not token:
        log_error("No access token.")
        return

    watch_map = build_watch_map()
    if not watch_map:
        log_warn("No watch entries in desired_items.json.")
        return

    log_info("Fetching base item levels for watched items...")
    # Preload base ilvl + bonus data for all watched item_ids using my Raidbots/static logic.
    await fetch_tww_static_data(session, token, list(watch_map.keys()))

    realm_ids = REALM_IDS
    if not realm_ids:
        log_warn("No realm IDs from REALMS.")
        return

    log_info(f"✅ Starting scan on {len(realm_ids)} realm(s)...")

    tasks = [
        fetch_auctions_for_realm(session, token, realm_id, skip_if_unchanged=True)
        for realm_id in realm_ids
    ]

    all_snipes: List[str] = []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for realm_id, result in zip(realm_ids, results):
        if isinstance(result, Exception):
            log_warn(f"Realm {realm_id} fetch error: {result!r}")
            continue

        auctions = result
        if not auctions:
            continue

        realm_name = CONNECTED_REALM_NAMES.get(realm_id, str(realm_id))

        for auc in auctions:
            entries = watch_map.get(auc.item_id)
            if not entries:
                continue

            # Use my SafeItemLevel logic via ilvl_fetcher, including Raidbots+caches.
            final_ilvl = resolve_ilvl(auc.item_id, auc.bonus_lists, auc.modifiers)
            if final_ilvl <= 0:
                continue

            match = matches_watch_entry(auc, entries, final_ilvl)
            if not match:
                continue

            # Gold as integer (no decimals)
            price_g = auc.price // 10_000
            max_g = match.max_price_copper // 10_000

            # Append note if present
            note_suffix = f" | {match.note}" if match.note else ""

            line = (
                f"{realm_name} | item={auc.item_id} | "
                f"ilvl={final_ilvl} | price={price_g}g / max={max_g}g | "
                f"auc={auc.id}{note_suffix}"
            )
            all_snipes.append(line)

    if not all_snipes:
        log_info("❌ No matching auctions this scan.")
    else:
        for line in all_snipes:
            log_snipe(line)
        await notify_snipes_via_discord(session, all_snipes)


# ---------------------------------------------------------
# Main loop
# ---------------------------------------------------------

async def run_loop() -> None:
    """
    Main loop: scan + sleep.
    """
    print_banner()

    interval = int(getattr(config, "SCAN_INTERVAL_SECONDS", 3600) or 3600)
    if interval <= 0:
        interval = 3600

    limit = int(getattr(config, "MAX_PARALLEL_REALMS", 10) or 10)

    log_info("Twink tool started.")
    log_info(
        f"interval={interval}s (~{interval/60:.1f} min) | "
        f"parallel_realms={limit} | total_realms={len(REALM_IDS)}"
    )

    connector = aiohttp.TCPConnector(limit=limit)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            try:
                await run_single_scan(session)
            except Exception as e:
                log_error(f"Scan failed: {e!r}")

            log_info(f"Next scan in {interval} seconds (~{interval/60:.1f} min)...")
            await asyncio.sleep(interval)


def main() -> None:
    """
    Entry point. Just run:

        python main.py
    """
    try:
        asyncio.run(run_loop())
    except KeyboardInterrupt:
        print()
        log_info("Shutdown requested (Ctrl+C). Exiting Twink tool.")


if __name__ == "__main__":
    main()
