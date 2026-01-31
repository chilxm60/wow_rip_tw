# main.py

import asyncio
from dataclasses import dataclass
from typing import List, Dict, Optional

import aiohttp
import xxhash

import config
from utils import JSON_LOADS
from realms import REALMS
from colorama import init as colorama_init, Fore, Style



# ---------------------------------------------------------
# Simple models
# ---------------------------------------------------------

@dataclass
class SafeAuction:
    """
    Minimal auction model for this tool.
    """
    id: int
    item_id: int
    quantity: int
    price: int           # total price in copper
    bonus_lists: List[int]
    modifiers: List[dict]

    @classmethod
    def from_raw(cls, raw: dict) -> Optional["SafeAuction"]:
        """
        Build a SafeAuction from the Blizzard auction payload.
        """
        try:
            auc_id = int(raw["id"])
            item = raw.get("item") or {}
            item_id = int(item["id"])

            quantity = int(raw.get("quantity", 1))

            unit_price = raw.get("unit_price")
            buyout = raw.get("buyout")

            if unit_price is not None:
                price = int(unit_price) * quantity
            elif buyout is not None:
                price = int(buyout)
            else:
                return None

            bonus_lists = list(item.get("bonus_lists", []))
            modifiers = list(item.get("modifiers", []))

            return cls(
                id=auc_id,
                item_id=item_id,
                quantity=quantity,
                price=price,
                bonus_lists=bonus_lists,
                modifiers=modifiers,
            )
        except Exception:
            # If something is weird, just skip this auction.
            return None


@dataclass
class WatchEntry:
    """
    One watch rule: item_id + target ilvl + max price.
    """
    item_id: int
    target_ilvl: int
    max_price_copper: int


# ---------------------------------------------------------
# Global state
# ---------------------------------------------------------

# All connected realm IDs from realms.py (92 EU realms in your case).
REALM_IDS = list(set(REALMS.values()))

ACCESS_TOKEN: Optional[str] = None
TOKEN_EXPIRES_AT: float = 0.0
TOKEN_LOCK = asyncio.Lock()

# realm_id -> last xxhash of the payload
REALM_HASHES: Dict[int, str] = {}

# init colorama once
colorama_init(autoreset=True)


def log_info(msg: str) -> None:
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")


def log_warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {msg}")


def log_error(msg: str) -> None:
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")


def log_hit(msg: str) -> None:
    print(f"{Fore.GREEN}[HIT]{Style.RESET_ALL} {msg}")


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
                        print(f"[WARN] Token status {resp.status}")
                        continue

                    data = await resp.json()
                    token = data.get("access_token")
                    expires_in = int(data.get("expires_in", 0) or 0)
                    if not token or expires_in <= 0:
                        print("[WARN] Invalid token response")
                        continue

                    ACCESS_TOKEN = token
                    TOKEN_EXPIRES_AT = now + expires_in
                    return ACCESS_TOKEN
            except Exception as e:
                print(f"[WARN] Token request error: {e!r}")
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

    Every entry is active. "note" is only for humans and ignored by the tool.
    """
    watch_map: Dict[int, List[WatchEntry]] = {}
    raw_items = load_watch_items_from_json()

    for entry in raw_items:
        try:
            item_id = int(entry["item_id"])
            target_ilvl = int(entry["target_ilvl"])
            max_price_g = float(entry["max_price_g"])
        except (KeyError, ValueError, TypeError) as e:
            print(f"[WARN] Invalid watch entry {entry!r}: {e!r}")
            continue

        max_price_copper = int(max_price_g * 10_000)

        w = WatchEntry(
            item_id=item_id,
            target_ilvl=target_ilvl,
            max_price_copper=max_price_copper,
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
            print(f"[WARN] Realm {realm_id} status {resp.status}")
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
# Ilvl extraction + matching
# ---------------------------------------------------------

def extract_ilvl_from_modifiers(modifiers: List[dict]) -> Optional[int]:
    """
    Read ilvl from modifiers (type == 9).
    """
    for m in modifiers:
        try:
            if int(m.get("type", -1)) == 9:
                return int(m.get("value", 0))
        except Exception:
            continue
    return None


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
        print("[ERROR] No access token.")
        return

    watch_map = build_watch_map()
    if not watch_map:
        print("[WARN] No watch entries in desired_items.json.")
        return

    realm_ids = REALM_IDS
    if not realm_ids:
        print("[WARN] No realm IDs from REALMS.")
        return

    print(f"[INFO] Starting scan on {len(realm_ids)} realm(s)...")

    tasks = [
        fetch_auctions_for_realm(session, token, realm_id, skip_if_unchanged=True)
        for realm_id in realm_ids
    ]

    all_hits: List[str] = []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for realm_id, result in zip(realm_ids, results):
        if isinstance(result, Exception):
            print(f"[WARN] Realm {realm_id} fetch error: {result!r}")
            continue

        auctions = result
        if not auctions:
            continue

        for auc in auctions:
            entries = watch_map.get(auc.item_id)
            if not entries:
                continue

            final_ilvl = extract_ilvl_from_modifiers(auc.modifiers)
            if final_ilvl is None or final_ilvl <= 0:
                continue

            match = matches_watch_entry(auc, entries, final_ilvl)
            if not match:
                continue

            price_g = auc.price / 10_000
            max_g = match.max_price_copper / 10_000

            line = (
                f"[HIT] realm_id={realm_id} | item_id={auc.item_id} | "
                f"ilvl={final_ilvl} | price={price_g:.1f}g (limit {max_g:.1f}g) | "
                f"auction_id={auc.id}"
            )
            all_hits.append(line)

    if not all_hits:
        print("[INFO] No matching auctions this scan.")


# ---------------------------------------------------------
# Main loop
# ---------------------------------------------------------

async def run_loop() -> None:
    """
    Main loop: scan + sleep.
    """
    interval = int(getattr(config, "SCAN_INTERVAL_SECONDS", 3600) or 3600)
    if interval <= 0:
        interval = 3600

    limit = int(getattr(config, "MAX_PARALLEL_REALMS", 10) or 10)

    connector = aiohttp.TCPConnector(limit=limit)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            try:
                await run_single_scan(session)
            except Exception as e:
                print(f"[ERROR] Scan failed: {e!r}")

            print(f"[INFO] Sleeping for {interval} seconds...\n")
            await asyncio.sleep(interval)


def main() -> None:
    """
    Entry point. Just run:

        python main.py
    """
    asyncio.run(run_loop())


if __name__ == "__main__":
    main()
