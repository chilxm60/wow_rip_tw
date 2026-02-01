# api_parser.py

"""
Slim API parser for the twink tool.

- SafeAuction: minimal, validated auction model (no pets)
- SafeItemLevel: hybrid ilvl calculation (base + bonus + modifier)
"""

from dataclasses import dataclass
from typing import Any, Optional, List, Dict


# ---------------------------------------------------------
# SafeAuction (slim version)
# ---------------------------------------------------------

@dataclass
class SafeAuction:
    """
    Minimal, validated auction data for this tool.
    """
    id: int
    item_id: int
    quantity: int
    price: int           # total price in copper
    bonus_lists: List[int]
    modifiers: List[dict]

    @classmethod
    def from_raw(cls, raw_auc: Dict[str, Any]) -> Optional["SafeAuction"]:
        """
        Parse raw Blizzard auction JSON.
        Returns None if something important is missing or invalid.
        """
        try:
            # --- AUCTION ID ---
            auc_id = raw_auc.get("id")
            if not isinstance(auc_id, int) or auc_id <= 0:
                return None

            # --- ITEM DATA ---
            item_data = raw_auc.get("item")
            if not isinstance(item_data, dict):
                return None

            item_id = item_data.get("id")
            if not isinstance(item_id, int) or item_id <= 0:
                return None

            # --- PRICE (COMMODITY/NON-COMMODITY) ---
            unit_price = raw_auc.get("unit_price", 0)
            buyout = raw_auc.get("buyout", 0)

            try:
                unit_price = int(unit_price) if unit_price else 0
                buyout = int(buyout) if buyout else 0
            except (ValueError, TypeError):
                return None

            # quantity first, because for commodities we want unit_price * quantity
            quantity = raw_auc.get("quantity", 1)
            try:
                quantity = int(quantity)
            except (ValueError, TypeError):
                return None
            if quantity < 1 or quantity > 100_000:
                return None

            # If unit_price is present, treat price as total = unit_price * quantity
            if unit_price > 0:
                price = unit_price * quantity
            else:
                price = buyout

            # sanity: 1 copper .. 100B copper (~10M gold)
            if price <= 0 or price > 100_000_000_000:
                return None

            # --- BONUS LISTS ---
            raw_bonuses = item_data.get("bonus_lists", [])
            bonuses: List[int] = []
            if isinstance(raw_bonuses, list):
                for b in raw_bonuses:
                    try:
                        b_int = int(b)
                        # 1..999999 is a safe range for bonus IDs
                        if 1 <= b_int <= 999_999:
                            bonuses.append(b_int)
                    except (ValueError, TypeError):
                        continue

            # --- MODIFIERS (FOR ILVL CALC) ---
            raw_mods = item_data.get("modifiers", [])
            mods: List[dict] = []
            if isinstance(raw_mods, list):
                for m in raw_mods:
                    if not isinstance(m, dict):
                        continue

                    m_type = m.get("type")
                    m_value = m.get("value")

                    # basic structure check: both fields must be int-convertible
                    try:
                        int(m_type) if m_type is not None else None
                        int(m_value) if m_value is not None else None
                        mods.append(m)
                    except (ValueError, TypeError):
                        continue

            # --- BUILD SAFE OBJECT ---
            return cls(
                id=auc_id,
                item_id=item_id,
                quantity=quantity,
                price=price,
                bonus_lists=bonuses,
                modifiers=mods,
            )

        except Exception:
            # Catch-all for unexpected structure changes.
            return None


# ---------------------------------------------------------
# SafeItemLevel (hybrid ilvl logic)
# ---------------------------------------------------------

@dataclass
class SafeItemLevel:
    """
    Safe item level result.
    """
    base_ilvl: int
    bonus_ilvl: int
    final_ilvl: int
    source: str  # "BASE+BONUS", "MODIFIER", "FAILED"

    @classmethod
    def calculate(
        cls,
        item_id: int,
        bonus_lists: List[int],
        modifiers: List[dict],
        base_cache: Dict[int, int],
        bonus_cache: Dict[int, int],
    ) -> "SafeItemLevel":
        """
        Hybrid TWW item level calculation:

        1. Try base_ilvl (static item API) + bonus ilvl (Raidbots bonuses).
        2. Fallback to modifier type 9 (direct ilvl).
        3. If all fails, return final_ilvl = 0.
        """
        # --- PATH 1: BASE + BONUSES ---
        base_ilvl = base_cache.get(item_id, 0)

        try:
            base_ilvl = int(base_ilvl)
            if base_ilvl < 0 or base_ilvl > 1500:
                base_ilvl = 0
        except (ValueError, TypeError):
            base_ilvl = 0

        if base_ilvl > 0:
            bonus_val = 0
            for b_id in bonus_lists:
                cached_bonus = bonus_cache.get(b_id, 0)
                try:
                    bonus_int = int(cached_bonus)
                    # sanity: 0 < bonus < 500 is reasonable for ilvl deltas
                    if 0 < bonus_int < 500:
                        bonus_val += bonus_int
                except (ValueError, TypeError):
                    continue

            final_ilvl = base_ilvl + bonus_val
            if 1 <= final_ilvl <= 1500:
                return cls(
                    base_ilvl=base_ilvl,
                    bonus_ilvl=bonus_val,
                    final_ilvl=final_ilvl,
                    source="BASE+BONUS",
                )

        # --- PATH 2: MODIFIER FALLBACK ---
        for mod in modifiers:
            if not isinstance(mod, dict):
                continue

            m_type = mod.get("type")
            m_val = mod.get("value")

            try:
                type_int = int(m_type) if m_type is not None else -1
                val_int = int(m_val) if m_val is not None else 0

                # type 9 = item level modifier in Blizzard API
                if type_int == 9 and 1 <= val_int <= 1500:
                    return cls(
                        base_ilvl=0,
                        bonus_ilvl=0,
                        final_ilvl=val_int,
                        source="MODIFIER",
                    )
            except (ValueError, TypeError):
                continue

        # --- PATH 3: FAILED ---
        return cls(0, 0, 0, "FAILED")
