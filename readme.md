# WoW Twink Helper

Small tool that watches the World of Warcraft Auction House for specific items (item id + item level + max price) and prints a line when it finds one.

Optionally, it can send the same line to a Discord channel via webhook.

---

## Requirements

- Windows
- Python 3.10+ installed
- Blizzard API application (client id + client secret)
- Discord webhook (optional)

---

## 1. Install Python

1. Download Python: https://www.python.org/downloads/
2. Run the installer.
3. Enable **"Add Python to PATH"**.
4. Finish the installation.

Test in Command Prompt:

```bat
py --version
```

If you see `Python 3.x`, you are good.

---

## 2. Download this tool

1. Open: `https://github.com/chilxm60/wow-twink-helper`
2. Click Code → Download ZIP.
3. Extract the ZIP to a folder, e.g.:

```
C:\wow-twink-helper
```

All files (`main.py`, `config.py`, `desired_items.json`, etc.) should be inside this folder.

---

## 3. Create virtualenv and install packages

Open Command Prompt:

```bat
cd C:\wow-twink-helper
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

For future runs you only need:

```bat
cd C:\wow-twink-helper
.\.venv\Scripts\activate
```

---

## 4. Configure `config.py`

Open `config.py` and set:

```python
CLIENT_ID = "your blizzard client id"
CLIENT_SECRET = "your blizzard client secret"
```
Go to https://develop.battle.net/access/clients and create a client, get the blizzard oauth client and secret ids.
You will put these values in config.py `WOW_CLIENT_ID` and `WOW_CLIENT_SECRET`.

Region / locale (EU default):

```python
REGION = "eu"
NAMESPACE = "dynamic-eu"
LOCALE = "en_GB"
```

Scan interval and parallel realms:

```python
SCAN_INTERVAL_SECONDS = 3600   # 3600 = one scan per hour
MAX_PARALLEL_REALMS = 10       # 10 is very relaxed; 20 is faster
```

Discord webhook (optional):

```python
DISCORD_WEBHOOK_URL = ""       # or "https://discord.com/api/webhoms/...."
```
 [Setup a discord channel with a webhook url for sending the alert messages](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) You will use this for the Discord Alerts.

Desired Items File (normally leave as is):

```python
from pathlib import Path
DESIRED_ITEMS_FILE = Path("desired_items.json")
```

Save the file.

---

## 5. Configure `desired_items.json`

Open `desired_items.json`.

Example:

```json
{
  "items": [
    {
      "item_id": 31318,
      "target_ilvl": 31,
      "max_price_g": 23000,
      "note": "Singing Crystal Axe 31"
    }
  ]
}
```

More items:

```json
{
  "items": [
    {
      "item_id": 31318,
      "target_ilvl": 31,
      "max_price_g": 23000,
      "note": "Singing Crystal Axe 31"
    },
    {
      "item_id": 12345,
      "target_ilvl": 25,
      "max_price_g": 5000,
      "note": "Some twink sword"
    }
  ]
}


```
You can also watch multiple item levels of the same item by adding multiple entries with the same item_id but different target_ilvl / max_price_g.

**Fields:**
- `item_id` – WoW item ID
- `target_ilvl` – desired item level
- `max_price_g` – max price in gold (`23000` = 23,000g)
- `note` – label/comment (shown in log/Discord)

Save the file.

---

## 6. Run the tool

```bat
cd C:\wow-twink-helper
.\.venv\Scripts\activate
py main.py
```

Example output:

```
============================================================
🎯  WoW Twink Helper
============================================================

[01:11:04] Twink tool started.
[01:11:04] interval=3600s (~60.0 min) | parallel_realms=10 | total_realms=92
[01:11:30] 🔥 SNIPE Argent Dawn | item=31318 | ilvl=31 | price=22000g / max=23000g | auc=1821336895 | Singing Crystal Axe 31
[01:11:32] Next scan in 3600 seconds (~60.0 min)...
```

If `DISCORD_WEBHOOK_URL` is set, the same SNIPE lines are also sent to Discord.