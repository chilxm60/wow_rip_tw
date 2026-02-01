# ilvl_fetcher.py

"""
Item level fetcher/solver for the twink tool.

I plug in my existing base_ilvl and bonus_ilvl caches
so this tool can reuse the same hardened logic.
Additionally, I cache item names for nicer logs/Discord messages.
"""

from typing import Dict, List
import asyncio
import time

import config
from api_parser import SafeItemLevel


# URL for Raidbots bonus data (public static JSON used by many tools).
# Big Shoutouts to Raidbots for doing this.
RAIDBOTS_BONUS_URL = "https://www.raidbots.com/static/data/live/bonuses.json"

# These caches are filled at runtime.
# - BASE_ILVL_CACHE: item_id -> base item level
# - BONUS_VAL_CACHE: bonus_id -> bonus ilvl delta
# - ITEM_NAME_CACHE: item_id -> localized item name
BASE_ILVL_CACHE: Dict[int, int] = {}
BONUS_VAL_CACHE: Dict[int, int] = {}
ITEM_NAME_CACHE: Dict[int, str] = {}
LAST_RAIDBOTS_FETCH: float = 0.0


async def fetch_tww_static_data(session, token: str, item_ids: List[int]) -> None:
    """
    Fetch base item levels and bonus values for a list of item_ids.

    - Bonus values are pulled from Raidbots (cached for 24h).
    - Base ilvl and item name are fetched from Blizzard's static item endpoints.
    """
    global LAST_RAIDBOTS_FETCH

    now = time.time()

    # Refresh Raidbots bonus data at most once per day.
    if now - LAST_RAIDBOTS_FETCH > 86400:
        try:
            async with session.get(RAIDBOTS_BONUS_URL, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for _, v in data.items():
                        try:
                            bid = int(v.get("id"))
                            lvl = int(v.get("level", 0) or 0)
                            if bid > 0 and lvl > 0:
                                BONUS_VAL_CACHE[bid] = lvl
                        except Exception:
                            continue
            LAST_RAIDBOTS_FETCH = now
        except Exception as e:
            # For this tool I just log and continue; modifier fallback will still work.
            print(f"[WARN] Failed to fetch Raidbots bonus data: {e!r}")

    # Only fetch base ilvl for item_ids we actually care about and don't have cached yet.
    valid_ids = [
        i for i in item_ids
        if isinstance(i, int) and i > 0 and i != 82800 and i not in BASE_ILVL_CACHE
    ]

    if not valid_ids:
        return


    sem = asyncio.Semaphore(10)

    async def fetch_item_ilvl(item_id: int) -> None:
        async with sem:
            # small delay to avoid hammering the API
            await asyncio.sleep(0.1)

            url = (
                f"https://{config.REGION}.api.blizzard.com/data/wow/item/{item_id}"
                f"?namespace={config.NAMESPACE.replace('dynamic', 'static')}"
                f"&locale={config.LOCALE}"
            )
            headers = {"Authorization": f"Bearer {token}"}

            try:
                async with session.get(url, headers=headers, timeout=10) as resp:
                    if resp.status != 200:
                        return

                    data = await resp.json()

                    # base ilvl
                    lvl = int(data.get("level", 0) or 0)
                    if 1 <= lvl <= 1500:
                        BASE_ILVL_CACHE[item_id] = lvl

                    # item name (locale aware, but also handle simple string case)
                    name_val = data.get("name")
                    item_name: str | None = None

                    if isinstance(name_val, dict):
                        # Try exact locale, then language part, then any value.
                        loc = config.LOCALE
                        item_name = name_val.get(loc)
                        if not item_name and "_" in loc:
                            lang = loc.split("_", 1)[0]
                            item_name = name_val.get(lang)
                        if not item_name and name_val:
                            # fallback: first value from the dict
                            try:
                                item_name = next(iter(name_val.values()))
                            except Exception:
                                item_name = None
                    elif isinstance(name_val, str):
                        item_name = name_val

                    if item_name:
                        ITEM_NAME_CACHE[item_id] = str(item_name)
            except Exception:
                # If static data fails, SafeItemLevel will still try modifiers as fallback.
                return

    await asyncio.gather(*(fetch_item_ilvl(i) for i in valid_ids))


def resolve_ilvl(item_id: int, bonus_lists: List[int], modifiers: List[dict]) -> int:
    """
    Return the final item level using my SafeItemLevel logic.

    This combines:
    - Base ilvl (from BASE_ILVL_CACHE)
    - Bonus ilvl (from BONUS_VAL_CACHE, which comes from Raidbots)
    - Modifier fallback (type 9) if base/bonus is missing

    If no valid ilvl can be determined, returns 0.
    """
    sil = SafeItemLevel.calculate(
        item_id=item_id,
        bonus_lists=bonus_lists,
        modifiers=modifiers,
        base_cache=BASE_ILVL_CACHE,
        bonus_cache=BONUS_VAL_CACHE,
    )
    return sil.final_ilvl or 0
