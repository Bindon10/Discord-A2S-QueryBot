# Discord-A2S-QueryBot (v2.0.4c)

## Changelog

### v2.0.5 (2025-11-30)
- Added a primary admin entry option to embed into the server information

A lightweight **Steam A2S query bot** for Discord that displays live server info and notifies you when a server goes down.
No plugins, RCON, or server mods required — it talks to your game servers the same way the Steam server browser does.

---
## 📸 Example Screenshot

![alt text](https://i.imgur.com/79QDD7A.png)
![alt text](https://i.imgur.com/qNubzov.png)

---

## ✨ Features
- **Live Discord embeds**: server name, map, player count, and player list.
- **Optional restart schedule** per server (with local-time display).
- **Down detection + pings** with per-server overrides (`ping_id` or `ping_role_id`).
- **Flexible routing/merging**: same **group + webhook** → one message; otherwise separate messages. No “Ungrouped” filler.
- **Per-server-only setup supported**: `DEFAULT_WEBHOOK_URL` can stay `CHANGE_ME` if each server has its own `webhook_url`.
- **Alerts webhook (optional)** for critical errors/warnings (deduped). Falls back to **console** if unset.
- **Message ID resilience**: re-creates missing messages and updates `message_ids.json` automatically.
- **Optional stale cleanup** of message IDs (`STALE_PURGE_ENABLED`).
- **Embed safety**: trims to Discord limits (10 embeds/message, 4096 chars/description) and sanitizes player names.
- **Rate-limit backoff** + **session reuse** for reliable Discord API calls.
- **Graceful shutdown** persists state on exit.
- **Example mode** on first run (no pings until you replace sample config).
- Works with any game that supports **Steam A2S** (Source, GoldSrc, UE servers exposing A2S, etc.).

---

## 📦 Requirements
- Python **3.9+**
- `python-a2s`
- `requests`
- A Discord **Webhook URL** (at least one — either a default or per-server override)

Install deps:
```bash
pip install python-a2s requests
```

---

## 🚀 Quick Start
1) **Download** or clone this repo.
2) Open `a2s-status.py`. All user settings are at the **top** under `# === USER CONFIG (edit me) ===`.
3) Pick one of these setups:
   - **Per-server only (recommended for multi-channel):** leave `DEFAULT_WEBHOOK_URL` as `CHANGE_ME`, and put a `webhook_url` on each server in `servers.json`.
   - **Single channel for everything:** set `DEFAULT_WEBHOOK_URL` and omit `webhook_url` on servers you want routed there.
4) **First run**:
```bash
python a2s-status.py
```
On first run the bot creates an example `servers.json`, shows a **yellow** example embed, and **does not ping** anyone until you replace the example.

---

## ⚙️ User Config (top of script)
| Setting | Purpose | Tips |
|---|---|---|
| `DEFAULT_WEBHOOK_URL` | Fallback webhook for servers without their own `webhook_url`. | Can stay `CHANGE_ME` if you only use per-server webhooks. |
| `ALERTS_WEBHOOK` | Optional webhook for **errors/warnings only**. | Leave empty to log alerts to console. Alerts are de-duplicated. |
| `INTERVAL_SECONDS` | How often embeds refresh. | Default `60`.
| `DEFAULT_USER_PING_ID` | Default mention when a server goes down. | Set to `""` to disable default pings. |
| `STEAM_STATUS_CHECK_ENABLED` | Enable Steam backend health gate. | Requires `STEAM_API_KEY` to do anything. |
| `STEAM_API_KEY` | Steam Web API key for outage gating. | See “Steam health gating” below. |
| `STEAM_STATUS_POLL_SECONDS` | Cache window for Steam health checks. | Default `180`.
| `IGNORED_STEAM_SERVICE_KEYS` | Keys to ignore in Steam health. | Default ignores `IEconItems`.
| `DOWN_FAIL_THRESHOLD` | Consecutive failed polls before a **down** ping. | Default `3`.
| `GROUP_EMBED_LIMIT` | Max embeds per message. | Discord hard cap is 10. |
| `EMBED_DESC_LIMIT` | Max characters in one embed description. | Discord hard cap is 4096. |
| `STALE_PURGE_ENABLED` | Purge obsolete message IDs. | Leave `False` unless you want automatic cleanup. |
| `SHOW_VISIBILITY_BY_DEFAULT` | Shows if a server is password protected | Leave false to hide this information by default. |
| `DEBUG_LOG_ENABLED` | Enables debug logging to file in case of an issue | Defaults to false, messages still log to console. |

---

## 🗂️ `servers.json` format
| Field | Req | Type | Description |
|---|---|---|---|
| `name` | ✅ | string | Display name for the server. |
| `ip` | ✅ | string | Server IP address. |
| `port` | ✅ | integer | **Query port**, not game port. |
| `group` | ❌ | string | Group name to merge servers into one embed **per webhook**. Leave blank for standalone messages. |
| `restart` | ❌ | boolean | If `true`, shows restart info. |
| `restart_hour` | ❌ | string/number | Hour `0–23`. Accepts `"04"`, `"4"`, `4`. |
| `restart_minute` | ❌ | string/number | Minute `0–59`. Accepts `"09"`, `9`, `0`. |
| `timezone` | ❌ | string | IANA TZ (e.g. `"America/Edmonton"`). Falls back to UTC if invalid. |
| `icon_url` | ❌ | string | Thumbnail URL (overrides emoji). |
| `webhook_url` | ❌ | string | Per-server webhook override. |
| `ping_id` | ❌ | string | Per-server user mention for down pings (e.g., `<@123...>`). |
| `ping_role_id` | ❌ | string/int | Per-server **role** mention for down pings (e.g., role id `987654...`). |
| `show_players` | ❌ | boolean | If SHOW_PLAYERS_BY_DEFAULT is false, setting this to true in your servers.json will re-enable the player list for that specific server. |
| `show_visibility` | ❌ | boolean | if SHOW_VISIBILITY_BY_DEFAULT is false, setting this to true in your servers.json will show if that specific server is password protected or public. |
| `downtime_counter` | ❌ | boolean | if downtime_counter is set to true, will count the amount of times the server goes down, poke the server admins about it. |
| `owner` | ❌ | string | Displays the primary server admin above the map and players information |

### Example
```json
[
  {
    "name": "EU 1",
    "ip": "123.45.67.89",
    "port": 27016,
    "group": "Mirage: Arcane Warfare",
	"admin": "<@123456789012345678>",
    "restart": true,
    "restart_hour": "04",
    "restart_minute": "30",
    "timezone": "America/Edmonton",
    "ping_role_id": "<@123456789012345678>",
    "webhook_url": "https://discord.com/api/webhooks/.../..."
  },
  {
    "name": "NA 1",
    "ip": "123.45.67.90",
    "port": 27015,
    "group": "Chivalry: Medieval Warfare",
	"admin": "<@123456789012345678>",
	"ping_id": "<@123456789012345678>",
    "restart": false,
    "webhook_url": "https://discord.com/api/webhooks/.../..."
  },
  {
    "name": "NA 2",
    "ip": "123.45.67.90",
    "port": 27015,
    "group": "Chivalry: Medieval Warfare",
	"admin": "<@123456789012345678>",
	"ping_id": "<@123456789012345678>",
    "restart": false,
    "webhooks": [
		"https://discord.com/api/webhooks/.../...",
		"https://discord.com/api/webhooks/.../..."
	]
  }
]
```

---

## 🧩 Grouping & routing
- Servers **merge into a single message** only when **both** the `group` **and** the **webhook URL** match.
- If `group` is empty, the server **never merges**; its embed title shows just the server name (no “Ungrouped”).
- If a Discord status **message is deleted**, the bot **re-creates** it and updates `message_ids.json` automatically.
- If a server’s **webhook changes**, Discord won’t allow editing the old message via the new webhook. The bot will create a **new** message and track that going forward.
- **Per-server-only setups:** it’s fine if `DEFAULT_WEBHOOK_URL` is still `CHANGE_ME`. Routes that would rely on the default produce a small **route-scoped** notice and are skipped; everything with a real `webhook_url` works normally.

---

## 🔔 Pings
- **Default:** uses `DEFAULT_USER_PING_ID` if a server does not specify its own.
- **Per-server user:** set `ping_id` (e.g., `<@123...>`). The bot restricts `allowed_mentions` to that user.
- **Per-server role:** set `ping_role_id` (e.g., `987654...`). The bot will mention that role with safe `allowed_mentions`.
- **Example mode:** pings are **disabled** until you remove the example server(s).

---

## ⏳ Restart info
- If `restart: true` and `restart_hour`/`restart_minute` are valid, embeds show:
  `🔄 Restarts daily at <time> (your local time)`
- If the timezone is invalid, the bot falls back to **UTC**.
- If times are missing/invalid, a friendly warning appears in the embed + a console warning.

---

## 🛡️ Safeguards & reliability
- **Rate-limit backoff:** automatic retry on `429` (`Retry-After`) and transient `5xx` with jittered backoff.
- **Session reuse:** persistent `requests.Session` for fewer TCP handshakes.
- **Embed safety:** trims to 10 embeds per message; escape basic Markdown in player names; caps embed description to 4096 chars.
- **Graceful shutdown:** handles SIGINT/SIGTERM and persists state files (`message_ids.json`, `ping_message_ids.json`, `server_down.json`).
- **Stale IDs (optional):** set `STALE_PURGE_ENABLED=True` to auto-remove message IDs that no longer correspond to any configured route. The bot protects expected routes during downtime so it won’t delete active messages just because servers are temporarily unreachable.

---

## 🛰️ Steam health gating (optional)
- Set `STEAM_STATUS_CHECK_ENABLED=True` **and** provide `STEAM_API_KEY`.
- When Steam’s backend looks unhealthy, the bot **freezes downtime counters** and adds a small banner to embeds so you don’t get false pings.
- Noisy keys (e.g., `IEconItems`) are ignored by default.
- If `STEAM_API_KEY` isn’t set, the bot **skips** health gating but continues normal operation.

How to get a key:
1. Visit <https://steamcommunity.com/dev/apikey>
2. Sign in, use any domain (e.g., `localhost`), and copy the key.
3. Paste it into `STEAM_API_KEY` at the top of the script.

---

## 🧰 Troubleshooting
**“Why isn’t it pinging me?”**
- You’re still in example mode — replace/remove the example server.
- Check the server’s `ping_id`/`ping_role_id` or the global `DEFAULT_USER_PING_ID`.

**“Multiple servers are in one embed when I don’t want that.”**
- Give them **different `group` values** (or leave `group` empty for standalone messages).

**“It says restart time not configured/invalid.”**
- Set `restart_hour` and `restart_minute` and ensure they’re in valid ranges.
- Verify the timezone; if invalid, the bot will fall back to UTC.

**“DEFAULT_WEBHOOK_URL is CHANGE_ME — is that OK?”**
- Yes, if **every server** has its own `webhook_url`. Any route relying on the default will be skipped with a small notice (no spam).

**“I changed the webhook and now it doesn’t update the old message.”**
- Discord doesn’t allow editing a message from a **different** webhook. The bot will post a **new** message and track that ID going forward.

**“I hit Discord rate limits.”**
- The bot obeys `Retry-After` and backs off automatically. If you see many rate-limit logs, consider raising `INTERVAL_SECONDS`.

---

## 📄 License
MIT — use, modify, and share freely.
