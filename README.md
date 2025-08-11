# Discord-A2S-QueryBot


A lightweight **Steam A2S query bot** for Discord that displays live server info and notifies you when a server goes down.  
No plugins, RCON, or server mods required — it talks to your game servers the same way the Steam server browser does.

---

## ✨ Features
- **Automatic Discord embeds** showing:
  - Server name & map
  - Player count & player list
  - Optional daily restart time in your local timezone
- **Down detection & notifications** (with per-server ping overrides)
- **Multiple server groups** (separate embeds per group)
- **Emoji or icon thumbnails**
- **Timezone support** for restart times
- **First-run example mode** (prevents accidental pings before setup)
- Supports any game with Steam A2S query protocol (Source, GoldSrc, Unreal Engine, etc.)

---

## 📦 Requirements
- Python 3.9+
- python-a2s
- requests
- A Discord webhook URL for your channel

---

## 🚀 Getting Started

### 1. Download the bot
Clone or download this repository.

### 2. Install dependencies
```bash
pip install python-a2s requests
```

### 3. Configure Discord webhook
- Create a webhook in your Discord channel  
- Copy the URL and paste it into the `DEFAULT_WEBHOOK_URL` at the top of the script.

### 4. First run
```bash
python a2s-status.py
```
- On first run, it creates a sample `servers.json` file and runs in **example mode**:
  - Shows a yellow embed in Discord
  - Does **not** ping anyone
  - Console will say:  
    ```
    [INIT] Created example servers.json — edit this file and restart to begin monitoring real servers.
    ```

### 5. Edit `servers.json`
Replace the example entry with your own server info.  
When all example entries are gone, pings are enabled.

---

## ⚙️ servers.json Format

| Field             | Required | Type             | Description |
|-------------------|----------|------------------|-------------|
| `name`            | ✅       | string           | Display name for the server. |
| `ip`              | ✅       | string           | Server IP address. |
| `port`            | ✅       | integer          | **Query port**, not game port. |
| `group`           | ❌       | string           | Group name for grouped embeds. |
| `restart`         | ❌       | boolean          | If `true`, shows restart schedule. |
| `restart_hour`    | ❌       | string / number  | Restart hour (0–23). `"04"`, `"4"`, `4` all work. |
| `restart_minute`  | ❌       | string / number  | Restart minute (0–59). `"09"`, `9`, `"0"`, `0` all work. |
| `timezone`        | ❌       | string           | Timezone (IANA format, e.g., `"America/Edmonton"`). |
| `emoji`           | ❌       | string           | Emoji to replace icon (e.g., `"⚔️"`). |
| `icon_url`        | ❌       | string           | URL to image thumbnail (overrides emoji). |
| `webhook_url`     | ❌       | string           | Per-server webhook override. |
| `ping_id`         | ❌       | string           | Per-server ping override (Discord user or role mention). |

---

### Example Multi-Server Setup
```json
[
  {
    "name": "Mirage EU 1",
    "ip": "123.45.67.89",
    "port": 27016,
    "group": "Mirage: Arcane Warfare",
    "restart": true,
    "restart_hour": "04",
    "restart_minute": "30",
    "timezone": "America/Edmonton",
    "emoji": "🧙",
    "ping_id": "<@123456789012345678>"
  },
  {
    "name": "Chivalry NA",
    "ip": "123.45.67.90",
    "port": 27015,
    "group": "Chivalry: Medieval Warfare",
    "restart": false,
    "emoji": "⚔️"
  },
  {
    "name": "CDW Asia",
    "ip": "123.45.67.91",
    "port": 27017,
    "group": "Chivalry: Deadliest Warrior",
    "restart": true,
    "restart_hour": 6,
    "restart_minute": 0,
    "timezone": "Asia/Tokyo",
    "icon_url": "https://example.com/icon.png"
  }
]
```

---

## 🔔 Ping Behavior
- **Default**: Uses `DEFAULT_USER_PING_ID` at top of script.
- **Override**: If `ping_id` is set in `servers.json`, only that ID is pinged.
- **Example mode**: Pings are disabled entirely until all example entries are removed.

---

## ⏳ Restart Time Behavior
- If `restart=true` and hour/minute are valid, embed shows:  
  `🔄 Restarts daily at <time> (your local time)`
- If enabled but **missing** hour/minute:
  - Console: `[WARN] Restart enabled but restart_hour/minute not set`
  - Embed: `⚠️ Restart time not configured — set restart_hour and restart_minute in servers.json`
- If enabled but **invalid** range:
  - Console: `[WARN] Restart time invalid (hour 0–23, minute 0–59)`
  - Embed: `⚠️ Restart time invalid — use hour 0–23 and minute 0–59`

---

## 🖼️ Example Output

**Group Embed Example:**
```
🎮 Mirage: Arcane Warfare — Mirage EU 1
📜 Map: mp_mirage
👥 Players: 12 / 32
🔄 Restarts daily at 4:30 AM (your local time)

**Current Players:**
- Alice
- Bob
- Charlie
...
```
(Yellow embed if example mode is active)

---

## 🛡️ Safeguards
- **Example mode** prevents unwanted pings until real servers are configured.
- **3-minute retry** before marking a server as down.
- **Auto-clears ping** when server is back up.

---

## 🛠 Troubleshooting

**🔸 “Why isn’t it pinging me?”**  
- You’re still in **example mode**. Remove or replace all example servers in `servers.json`.
- You set the wrong Discord ID in the script/servers.json

**🔸 “Why does it say ‘Restart time not configured’?”**  
- You set `"restart": true` but didn’t set `restart_hour` and `restart_minute`.

**🔸 “Bot says restart time is invalid.”**  
- `restart_hour` must be **0–23** and `restart_minute` must be **0–59**.  
- You can use strings (`"09"`) or numbers (`9`), both work.

**🔸 “Server shows as down but it’s online.”**  
- Make sure you’re using the **query port** (not the game port).  
- Check your firewall and Steam query settings.

**🔸 “Multiple servers are in one embed when I don’t want that.”**  
- Set a unique `"group"` name for each server you want in a separate embed.

**🔸 “How do I set up the Steam API for downtime detection?”**  
- This feature lets the bot check Steam’s backend health after **two failed queries** to avoid false pings during maintenance.  
- **Get your API key**: https://steamcommunity.com/dev/apikey  
  - Sign in with your Steam account.  
  - Enter any domain (can be `localhost`).  
  - Click **Register** and copy your key.  
- **Add it to the bot**: In the script, find:  
  ```python
  STEAM_API_KEY = "PUT_YOUR_STEAM_WEB_API_KEY_HERE"
  ```
  Replace `"PUT_YOUR_STEAM_WEB_API_KEY_HERE"` with your key.  
- When enabled:
  - If Steam is unhealthy, downtime counters freeze.
  - A banner is added to embeds: “⚠️ Steam may be down at the moment”.
  - The bot ignores noisy keys like `IEconItems` that are often offline.
- If not set, the bot will skip Steam health checks and use the old 3-fail rule for pings.

---

## 📄 License
MIT License — feel free to use, modify, and share.
