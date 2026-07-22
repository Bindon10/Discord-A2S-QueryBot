# Discord-A2S-QueryBot (v2.5.1)

A lightweight **Steam A2S query bot** for Discord that displays live server info and notifies you when a server goes down — now with a built-in **web UI** for managing everything from your browser.
No plugins, RCON, or server mods required — it talks to your game servers the same way the Steam server browser does.

---

## Changelog (highlights)

### v2.5.1 (2026-07-21)
- Included fix for downtime counters not counting when pings are disabled

### v2.5.0 (2026-07-15)
- Servers are now queried **concurrently** — big server lists and down servers no longer slow the refresh cycle.
- **Crash guard**: an unexpected error no longer kills the bot; it logs, alerts, and continues next cycle.
- Web UI runs on a production server (waitress) when installed.

### v2.4.x
- **Enable/disable servers** without removing them from the list.
- Optional **Connect line** in embeds (`display_port` — the game port, since `port` is the query port).
- Hostnames/domains are fully supported and re-resolved every query (dynamic IP friendly), with an automatic retry on DNS flaps.
- Rearranged web UI tabs; "last active" tracking for users.

### v2.3.x
- **Messages tab**: view and revoke stuck downtime pings from the browser.
- **Settings tab**: adjust bot basics live without editing the script.
- **Server ownership**: servers record their creator; editing is limited to the creator, chosen editors, or admins.
- **Ghost player fix** (optional): some games report a phantom player with no name — the bot can treat that as 0.

### v2.2.0
- **Steam sign-in** for the web UI (whitelist-only) with roles: admin / manager / viewer.

### v2.1.x
- **Embedded web UI**: live dashboard, server editor, groups with emoji, full emoji picker, logs, and controls.
- Fixed longstanding embed formatting bugs (layout flips while unreachable, oversized descriptions during Steam outages, unsanitized names breaking markdown).

---

## 📸 Example Screenshot

![alt text](https://i.imgur.com/79QDD7A.png)
![alt text](https://i.imgur.com/qNubzov.png)

---

## ✨ Features

**Discord side**
- **Live embeds**: server name, map, player count, player list, optional Connect address, admin/owner line, restart schedule (local-time display).
- **Down detection + pings** with per-server user or role mentions — just paste the raw ID, the bot formats the mention for you.
- **Flexible routing/merging**: same **group + webhook** → one message; otherwise separate messages. Groups can have an emoji prefix.
- **Multi-webhook**: one server can post its status to several channels.
- **Steam health gating** (optional): freezes downtime counters during Steam-wide outages so you don't get false pings.
- **Network outage detection**: if the bot's own host loses connectivity, counters and pings freeze until it recovers.

**Web UI** (`http://<host>:8500` by default)
- **Status** — live dashboard of every server.
- **Servers** — add, edit, enable/disable, or remove servers with a full editor (every option, no JSON editing needed).
- **Groups** — create reusable group presets with optional emoji.
- **Controls** — force a refresh, send test pings, reset downtime counters.
- **Messages** — see active downtime pings and revoke stuck ones.
- **Settings** (admin) — adjust embed limits, player list options, down threshold, query workers — applied live.
- **Advanced** (admin) — raw `servers.json` editor with validation.
- **Users** (admin) — Steam sign-in whitelist with roles; managers can only edit their own servers (plus servers they're added to as editors).
- Sign-in persists across bot restarts (30-day sliding sessions).

**Reliability**
- Concurrent queries keep the cycle fast no matter how many servers are down.
- Crash guard: one bad cycle can't kill the bot.
- Corrupt/empty state files are backed up and regenerated instead of crashing.
- A bad `servers.json` edit mid-run keeps the last good config instead of crashing.
- Rate-limit backoff (obeys Discord's `Retry-After`), session reuse, graceful shutdown, message re-creation if someone deletes a status message.

Works with any game that supports **Steam A2S** (Source, GoldSrc, UE servers exposing A2S, etc.).

---

## 📦 Requirements
- Python **3.10+**
- `python-a2s`, `requests`
- `flask` — for the web UI (the bot runs headless without it)
- `waitress` — recommended, serves the web UI properly in production
- A Discord **Webhook URL** (at least one — either a default or per-server override)

```bash
pip install python-a2s requests flask waitress
```

---

## 🚀 Quick Start
1) **Download** or clone this repo.
2) Open `a2s-status.py`. All user settings are at the **top** under `# === USER CONFIG (edit me) ===`.
3) Pick a webhook setup:
   - **Per-server only (recommended for multi-channel):** leave `DEFAULT_WEBHOOK_URL` as `CHANGE_ME`, put a `webhook_url` on each server.
   - **Single channel for everything:** set `DEFAULT_WEBHOOK_URL`.
4) **Set a web UI password** — the UI listens on your network (`0.0.0.0:8500`) by default:
```bash
export WEBUI_PASSWORD="something-strong"   # or edit WEB_UI_PASSWORD in the script "WEB_UI_PASSWORD = os.getenv("WEBUI_PASSWORD", "LukeIAmYourPassword").strip()"
```
5) **First run**:
```bash
python a2s-status.py
```
On first run the bot creates an example `servers.json`, shows a **yellow** example embed, and **does not ping** anyone until you replace the example. From here you can do everything else in the web UI — open `http://<host>:8500`, sign in, and add your servers under the **Servers** tab.

---

## ⚙️ User Config (top of script)
| Setting | Purpose | Tips |
|---|---|---|
| `DEFAULT_WEBHOOK_URL` | Fallback webhook for servers without their own `webhook_url`. | Can stay `CHANGE_ME` if you only use per-server webhooks. |
| `ALERTS_WEBHOOK` | Optional webhook for **errors/warnings only**. | Leave empty to log alerts to console. Alerts are de-duplicated. |
| `INTERVAL_SECONDS` | How often embeds refresh. | Default `60`. |
| `DEFAULT_USER_PING_ID` | Default mention when a server goes down. | Set to `""` to disable default pings. |
| `DOWN_FAIL_THRESHOLD` | Consecutive failed polls before a **down** ping. | Default `3`. Also adjustable live in Settings. |
| `QUERY_MAX_WORKERS` | Concurrent server queries per cycle. | Default `16`. Also adjustable live in Settings. |
| `STEAM_STATUS_CHECK_ENABLED` / `STEAM_API_KEY` | Steam backend health gate + persona fetching for web UI users. | See "Steam health gating" below. |
| `WEB_UI_ENABLED` | Turn the web UI on/off. | Default `True`. |
| `WEB_UI_HOST` / `WEB_UI_PORT` | Where the web UI listens. | Default `0.0.0.0:8500` — set a password! |
| `WEB_UI_PASSWORD` | Break-glass admin login for the web UI. | Or use the `WEBUI_PASSWORD` env var. Blank + no users = auth disabled. |
| `WEB_UI_PUBLIC_URL` | Public base URL for Steam sign-in redirects. | Only needed behind a proxy/domain; blank = auto-detect. |
| `SHOW_PLAYERS_BY_DEFAULT` / `SHOW_VISIBILITY_BY_DEFAULT` | Default embed display options. | Per-server overrides available; also in Settings tab. |
| `GHOST_PLAYER_FIX_BY_DEFAULT` | Treat a player count with an empty name list as 0. | Some games report a phantom player — see Troubleshooting. |
| `PLAYER_LIST_LIMIT` | Max player names shown per server. | Default `20`. |
| `GROUP_EMBED_LIMIT` / `EMBED_DESC_LIMIT` | Discord safety caps. | Hard caps are 10 embeds / 4096 chars. |
| `DEBUG_LOG_ENABLED` | Also write DEBUG logs to a rotating file. | Console logging is always on. |

> Settings changed in the web UI **Settings tab** are stored in `webui_settings.json` and override the script values on startup.

---

## 🗂️ `servers.json` format
Most people can ignore this section and use the web UI's server editor — every field below has a form field. For hand-editing:

| Field | Req | Type | Description |
|---|---|---|---|
| `name` | ✅ | string | Display name for the server. |
| `ip` | ✅ | string | Server IP **or hostname/domain** (kept as-is, re-resolved every query — dynamic IP friendly). |
| `port` | ✅ | integer | **Query port**, not game port. |
| `display_port` | ❌ | integer | Game port — adds a `Connect: host:port` line to the embed. |
| `enabled` | ❌ | boolean | Set `false` to stop querying/posting without removing the server. Its Discord message is cleaned up until re-enabled. |
| `group` | ❌ | string | Merge servers into one embed **per webhook**. Leave blank for standalone messages. |
| `webhook_url` | ❌ | string | Per-server webhook override. |
| `webhooks` | ❌ | list | Multiple webhooks — status posts to every listed channel. |
| `owner` | ❌ | string | Admin line in the embed. Raw user ID or `<@id>` → user mention, `&roleid` or `<@&roleid>` → role mention, anything else shows as text. |
| `ping_id` | ❌ | string | User to ping on downtime — raw ID is fine. |
| `ping_role_id` | ❌ | string/int | Role to ping on downtime (takes priority over `ping_id`). |
| `disable_pings` | ❌ | boolean | Never ping for this server. |
| `restart` / `restart_hour` / `restart_minute` / `timezone` | ❌ | — | Daily restart notice, shown in each viewer's local time. |
| `emoji` | ❌ | string | Emoji prefix for the server (shows in grouped embeds and standalone titles). |
| `icon_url` | ❌ | string | Thumbnail URL (overrides emoji on standalone embeds). |
| `max_players` | ❌ | integer | Shown while the server is unreachable. |
| `show_players` / `show_visibility` / `downtime_counter` / `ghost_player_fix` | ❌ | boolean | Per-server overrides of the bot-wide defaults. |
| `editors` | ❌ | list | SteamID64s allowed to edit this server in the web UI (besides its creator and admins). Managed from the editor's "Edit access" box. |
| `created_by` / `created_by_name` | — | — | Set automatically when a server is added via the web UI. |

### Example
```json
[
  {
    "name": "EU 1",
    "ip": "12.345.678.90",
    "port": 27016,
    "display_port": 27015,
    "group": "Mirage: Arcane Warfare",
    "owner": "<@&123456789012345678>",
    "restart": true,
    "restart_hour": "04",
    "restart_minute": "30",
    "timezone": "America/Edmonton",
    "ping_role_id": "123456789012345678",
    "webhook_url": "https://discord.com/api/webhooks/.../..."
  },
  {
    "name": "NA 1",
    "ip": "12.345.678.90",
    "port": 27017,
    "group": "Chivalry: Medieval Warfare",
    "owner": "<@123456789012345678>",
    "ping_id": "123456789012345678",
    "webhooks": [
      "https://discord.com/api/webhooks/.../...",
      "https://discord.com/api/webhooks/.../..."
    ]
  }
]
```

---

## 🌐 Web UI

Open `http://<host>:8500`. Two ways to sign in:
- **Password** — the `WEBUI_PASSWORD` value, always an admin (your break-glass login).
- **Steam** — "Sign in through Steam". Whitelist-only: an admin must add your **SteamID64** on the Users tab first; unknown Steam accounts are rejected.

**Roles**
| Role | Can do |
|---|---|
| `viewer` | See the status dashboard. |
| `manager` | Everything viewers can, plus manage servers*, groups, controls, and downtime ping messages. |
| `admin` | Everything: users, live settings, raw config, logs. |

\* Managers can only edit/remove **their own** servers (ones they created) plus servers where they're listed as an editor. Admins can edit anything.

**Steam sign-in notes**
- Works out of the box on LAN/localhost. If the UI lives behind a domain or reverse proxy, set `WEB_UI_PUBLIC_URL` (e.g. `https://status.example.com`) so Steam redirects back to the right place.
- With `STEAM_API_KEY` set, user names/avatars come from Steam automatically ("Refresh Steam names" on the Users tab re-fetches them).
- Sessions persist across bot restarts and renew as long as you keep visiting. Deleting `webui_sessions.json` signs everyone out.

---

## 🧩 Grouping & routing
- Servers **merge into a single message** only when **both** the `group` **and** the **webhook URL** match.
- If `group` is empty, the server gets its own message; its embed title shows just the server name (no "Ungrouped").
- Group presets (with optional emoji prefix) are managed on the **Groups** tab and picked from a dropdown in the server editor.
- If a Discord status **message is deleted**, the bot **re-creates** it automatically.
- If a server's **webhook changes**, Discord won't allow editing the old message via the new webhook — the bot posts a **new** message and tracks that going forward. Stale messages from removed/changed routes are cleaned up automatically.

---

## 🔔 Pings
- **Default:** uses `DEFAULT_USER_PING_ID` if a server doesn't specify its own.
- **Per-server:** set `ping_id` (user) or `ping_role_id` (role — takes priority). Raw IDs are fine; the bot builds the mention and restricts `allowed_mentions` to exactly that user/role.
- **Stuck ping?** If a "server down" ping ever sticks around after recovery, revoke it from the **Messages** tab — no need to touch Discord or the state files.
- **Example mode:** pings are **disabled** until you replace the example server(s).

---

## 🛰️ Steam health gating (optional)
- Set `STEAM_STATUS_CHECK_ENABLED=True` **and** provide `STEAM_API_KEY`.
- When Steam's backend looks unhealthy, the bot **freezes downtime counters** and adds a banner to embeds so you don't get false pings.
- If `STEAM_API_KEY` isn't set, health gating is skipped and everything else works normally.

How to get a key:
1. Visit <https://steamcommunity.com/dev/apikey>
2. Sign in, use any domain (e.g., `localhost`), and copy the key.
3. Paste it into `STEAM_API_KEY` at the top of the script.

---

## 🧰 Troubleshooting

**"Why isn't it pinging me?"**
- You're still in example mode — replace/remove the example server.
- Check the server's `ping_id`/`ping_role_id`, the global `DEFAULT_USER_PING_ID`, or whether `disable_pings` is on.

**"It says 1 player online but nobody's there."**
- Some games' A2S replies report a phantom player with an empty name list. Turn on the **ghost player fix** (Settings tab for all servers, or per server in the editor).

**"My server uses a domain with a dynamic IP — will that cause false downs?"**
- Domains are kept as-is and re-resolved on **every** query, and hostname queries retry once on failure. If your IP rotates often, keep your DNS TTL low; you can also raise the down threshold in Settings.

**"A downtime ping is stuck / the server changed but the ping stayed."**
- Web UI → **Messages** → Revoke. Deletes the Discord message and clears the bot's record.

**"I keep having to log into the web UI."**
- You shouldn't (sessions survive restarts and renew on activity). If it persists, make sure the bot can write `webui_sessions.json` in its working directory.

**"DEFAULT_WEBHOOK_URL is CHANGE_ME — is that OK?"**
- Yes, if **every server** has its own `webhook_url`. Routes relying on the default are skipped with a small notice.

**"I hit Discord rate limits."**
- The bot obeys `Retry-After` and backs off automatically. Discord traffic is one edit per status message per cycle, so this should be rare; if you see many rate-limit logs, raise `INTERVAL_SECONDS` or spread groups across webhooks.

**"The bot crashed?"**
- It shouldn't anymore — cycle errors are caught, logged, and alerted while the bot keeps running. Check the **Logs** tab or your alerts webhook for the traceback.

---

## 📁 Files the bot creates
`servers.json` (config) • `message_ids.json`, `ping_message_ids.json`, `ping_routes.json`, `server_down.json`, `has_pinged_down.json`, `downtime_counters.json`, `alerts_state.json`, `net_state.json` (state) • `webui_settings.json`, `webui_users.json`, `webui_sessions.json` (web UI). Corrupt state files are backed up as `<name>.corrupt` and regenerated. Keep `webui_sessions.json` private — it contains live session tokens.

---

## 📄 License
MIT — use, modify, and share freely. - Use this code however you would like. I do not care; just leave me out of whatever petty legal bullshit you come up with. I will not respond to emails regarding this project.
