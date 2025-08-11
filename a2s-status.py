# Discord-A2S-QueryBot v1.8.1 — Steam Banner + Freeze/Reset + 403 Handling + Multi-Webhook Routing
# - Dynamic Steam banner (with last-checked + reasons)
# - Freeze+reset counters on outage start; no pings while unhealthy
# - Example mode (0.0.0.0); restart validation; per-server ping override; message routing by (group|webhook)
# - NEW: Ignore noisy Steam service keys (e.g., IEconItems) so they don't cause false outage flags

import a2s
import requests
import time
import os
import json
from datetime import datetime
from zoneinfo import ZoneInfo

# === CONFIG ===
CONFIG_FILE = "servers.json"
DEFAULT_WEBHOOK_URL = "https://discord.com/api/webhooks/CHANGE_ME"
INTERVAL_SECONDS = 60
DEFAULT_USER_PING_ID = "<@123456789012345678>"

# Steam backend health gate
STEAM_STATUS_CHECK_ENABLED = True
STEAM_API_KEY = "PUT_YOUR_STEAM_WEB_API_KEY_HERE" # You can find your API key at https://steamcommunity.com/dev/apikey (Domain name isn't important but if you own one, I would use that.)
STEAM_STATUS_POLL_SECONDS = 180  # cache Steam health for this many seconds

# Noisy Steam service keys (ignored when computing health)
IGNORED_STEAM_SERVICE_KEYS = {"IEconItems"}  # add more if needed, e.g. {"IEconItems", "Leaderboards"}

# === STATE ===
message_ids = {}
ping_message_ids = {}
server_down = {}
downtime_counter = {}
has_pinged_down = {}

_last_steam_check = 0.0
_last_steam_unhealthy = False
_last_steam_snapshot = None

# === JSON IO ===
def load_json(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

message_ids = load_json("message_ids.json")
ping_message_ids = load_json("ping_message_ids.json")
server_down = load_json("server_down.json")
has_pinged_down = load_json("has_pinged_down.json")

# One-time migration to route-based keys
if message_ids and any("|" not in k for k in list(message_ids.keys())):
    print("[INIT] Detected legacy message_ids.json (group-only keys). Resetting for route-based keys.")
    message_ids = {}
    save_json("message_ids.json", message_ids)

# === Example config ===
def create_example_servers_file():
    example_servers = [
        {
            "name": "⚠️ Example Server — Please Edit servers.json",
            "ip": "0.0.0.0",              # sentinel triggers example mode
            "port": 27015,
            "group": "Example Group",
            "restart": True,
            "restart_hour": "04",
            "restart_minute": "30",
            "timezone": "America/Edmonton",
            "emoji": "⚠️",
            "ping_id": "<@123456789012345678>"
        }
    ]
    save_json(CONFIG_FILE, example_servers)
    print("[INIT] Created example servers.json — edit this file and restart to begin monitoring real servers.")

def load_servers_and_detect_example_mode():
    if not os.path.exists(CONFIG_FILE):
        create_example_servers_file()
        return [], True
    with open(CONFIG_FILE, "r") as f:
        servers = json.load(f)
    if not isinstance(servers, list):
        print("[ERROR] servers.json must be a JSON array. Disabling pings for safety.")
        return [], True
    if len(servers) > 0 and all(s.get("ip") == "0.0.0.0" for s in servers):
        print("[INIT] Detected example servers.json — edit this file and restart to enable pings.")
        return servers, True
    return servers, False

def make_server_key(ip, port):
    return f"{ip}:{port}"

def route_key(group, webhook):
    return f"{group}|{webhook}"

# === Steam Health Check & Banner ===
def _interpret_steam_health(payload) -> bool:
    """
    Return True if Steam is unhealthy (issues), False if healthy.
    - Ignores noisy service keys via IGNORED_STEAM_SERVICE_KEYS (e.g., IEconItems).
    - Logs both considered and ignored reasons for transparency.
    """
    try:
        result = payload.get("result") or payload.get("data") or payload
        suspicious = []
        ignored = []

        services = result.get("services", {}) or {}
        matchmaking = result.get("matchmaking", {}) or {}

        missing_sections = []
        if not services:
            missing_sections.append("services")
        if not matchmaking:
            missing_sections.append("matchmaking")

        def is_bad(v):
            return isinstance(v, str) and v.lower() in ("offline", "critical", "degraded", "delayed")

        # Services: collect reasons, ignoring known noisy keys
        for k, v in services.items():
            if is_bad(v):
                if k in IGNORED_STEAM_SERVICE_KEYS:
                    ignored.append((f"services.{k}", v))
                else:
                    suspicious.append((f"services.{k}", v))

        # Matchmaking: include as-is (generally relevant)
        for k, v in matchmaking.items():
            if is_bad(v):
                suspicious.append((f"matchmaking.{k}", v))

        if suspicious:
            print(f"[DEBUG] Steam unhealthy reasons (considered): {suspicious}")
        if ignored:
            print(f"[DEBUG] Steam unhealthy reasons (ignored noisy): {ignored}")

        if not suspicious:
            if missing_sections:
                print(f"[DEBUG] Steam status missing keys: {missing_sections}")
            else:
                print(f"[DEBUG] Steam returned OK states (after ignoring noisy keys).")

        return len(suspicious) > 0
    except Exception as e:
        print(f"[DEBUG] Failed to interpret Steam health (possible false unhealthy): {e}")
        return False  # on parse error, don't block pings

def steam_is_unhealthy() -> bool:
    """
    Checks Steam API health (CS servers) with caching and robust handling:
    - 403 Forbidden -> DEBUG + treat as healthy (likely key/rate limit)
    - Non-200 -> DEBUG + treat as healthy
    """
    global _last_steam_check, _last_steam_unhealthy, _last_steam_snapshot

    if not STEAM_STATUS_CHECK_ENABLED:
        return False
    if not STEAM_API_KEY or STEAM_API_KEY == "PUT_YOUR_STEAM_WEB_API_KEY_HERE":
        print("[WARN] Steam status check enabled but STEAM_API_KEY is not set. Disabling Steam health gating.")
        return False

    now = time.time()
    if now - _last_steam_check < STEAM_STATUS_POLL_SECONDS:
        return _last_steam_unhealthy

    url = "https://api.steampowered.com/ICSGOServers_730/GetGameServersStatus/v1/"
    try:
        resp = requests.get(url, params={"key": STEAM_API_KEY}, timeout=10)
        _last_steam_check = now

        if resp.status_code == 403:
            print("[DEBUG] Steam API request returned 403 Forbidden — possible key issue or rate limit. Treating as healthy this cycle.")
            _last_steam_unhealthy = False
            _last_steam_snapshot = None
            return _last_steam_unhealthy

        if resp.status_code != 200:
            print(f"[DEBUG] Steam API request failed with status {resp.status_code}. Treating as healthy this cycle.")
            _last_steam_unhealthy = False
            _last_steam_snapshot = None
            return _last_steam_unhealthy

        data = resp.json()
        unhealthy = _interpret_steam_health(data)
        if unhealthy and not _last_steam_unhealthy:
            print("[WARN] Steam backend appears unhealthy — entering freeze mode (reset counters).")
        if not unhealthy and _last_steam_unhealthy:
            print("[INFO] Steam backend recovered — exiting freeze mode (counters resume).")
        _last_steam_unhealthy = unhealthy
        _last_steam_snapshot = data
        return unhealthy

    except requests.exceptions.RequestException as e:
        print(f"[DEBUG] Steam API request error: {e}. Treating as healthy this cycle.")
        _last_steam_check = now
        _last_steam_unhealthy = False
        _last_steam_snapshot = None
        return False

def _summarize_unhealthy_reasons(snapshot) -> list:
    """Return short reason strings like 'services.Steam: offline'."""
    try:
        result = (snapshot or {}).get("result") or (snapshot or {}).get("data") or (snapshot or {})
        out = []
        def bad(v: str) -> bool:
            return isinstance(v, str) and v.lower() in ("offline", "critical", "degraded", "delayed")
        for k, v in (result.get("services", {}) or {}).items():
            if bad(v) and k not in IGNORED_STEAM_SERVICE_KEYS:
                out.append(f"services.{k}: {v}")
        for k, v in (result.get("matchmaking", {}) or {}).items():
            if bad(v):
                out.append(f"matchmaking.{k}: {v}")
        return out
    except Exception:
        return []

def build_steam_banner(steam_unhealthy: bool, last_check_epoch: float, snapshot) -> str:
    """
    Returns a dynamic banner string (or '' if healthy).
    Example:
    ⚠️ **Steam may be down at the moment** — server status may be inaccurate.
    (last checked: 12:34:56 UTC • reasons: services.Steam: offline, matchmaking.scheduler: delayed)
    """
    if not steam_unhealthy:
        return ""
    reasons = _summarize_unhealthy_reasons(snapshot)
    checked = datetime.utcfromtimestamp(last_check_epoch).strftime("%H:%M:%S UTC") if last_check_epoch else "unknown"
    reason_text = (", ".join(reasons[:3]) + ("…" if len(reasons) > 3 else "")) if reasons else "unavailable"
    return (
        "⚠️ **Steam may be down at the moment** — server status may be inaccurate.\n"
        f"(last checked: {checked} • reasons: {reason_text})\n\n"
    )

# === A2S ===
def fetch_stats(ip, port):
    addr = (ip, port)
    try:
        info = a2s.info(addr, timeout=2.0)
        players = a2s.players(addr, timeout=2.0)
        names = [p.name for p in players if p.name.strip()]
        return {
            "name": info.server_name,
            "map": info.map_name,
            "players": info.player_count,
            "max_players": info.max_players,
            "player_names": names,
        }
    except Exception as e:
        print(f"[ERROR] Query failed for {ip}:{port}: {e}")
        return None

# === Restart parsing (accept strings OR numbers) ===
def _to_int_or_none(v):
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except Exception:
        return None

def parse_restart_time(server):
    if not server.get("restart", False):
        return None, None, None
    h = _to_int_or_none(server.get("restart_hour"))
    m = _to_int_or_none(server.get("restart_minute"))
    if h is None or m is None:
        return None, None, "missing"
    if not (0 <= h <= 23) or not (0 <= m <= 59):
        return None, None, "invalid"
    return h, m, None

# === Discord ===
def build_grouped_embeds(grouped_servers, steam_banner: str = ""):
    """
    grouped_servers: { group_name: [(server_dict, stats_dict), ...] }
    returns: { group_name: [embed, embed, ...] }
    """
    group_embeds = {}
    for group_name, pairs in grouped_servers.items():
        embeds = []
        for server, stats in pairs:
            desc = steam_banner + f"**{stats['name']}**\n\n📜 Map: `{stats['map']}`\n👥 Players: `{stats['players']} / {stats['max_players']}`"

            # Restart block
            h, m, err = parse_restart_time(server)
            if server.get("restart", False):
                if err is None:
                    tz = server.get("timezone", "UTC")
                    local_restart = datetime.now(ZoneInfo(tz)).replace(
                        hour=h, minute=m, second=0, microsecond=0
                    )
                    restart_utc = local_restart.astimezone(ZoneInfo("UTC"))
                    restart_ts = int(restart_utc.timestamp())
                    desc += f"\n\n🔄 Restarts daily at <t:{restart_ts}:t> _(your local time)_"
                elif err == "missing":
                    print(f"[WARN] Restart enabled for '{server.get('name','?')}' but restart_hour/minute not set.")
                    desc += "\n\n⚠️ Restart time not configured — set restart_hour and restart_minute in servers.json"
                else:
                    print(f"[WARN] Restart time invalid for '{server.get('name','?')}'. Use hour 0–23 and minute 0–59.")
                    desc += "\n\n⚠️ Restart time invalid — use hour 0–23 and minute 0–59"

            desc += "\n\n"
            if stats["player_names"]:
                player_list = "\n".join(f"- {n}" for n in stats["player_names"][:stats["max_players"]])
            else:
                player_list = "*No players online*"
            desc += f"**Current Players:**\n{player_list}"

            icon = server.get("icon_url") or server.get("emoji")
            embed = {
                "title": f"🎮 {group_name} — {server['name']}",
                "description": desc,
                "color": 0x7F00FF,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "Updated every 60 seconds"},
            }

            if server.get("ip") == "0.0.0.0":
                embed["color"] = 0xFFCC00  # yellow for example

            if icon:
                if isinstance(icon, str) and icon.startswith("http"):
                    embed["thumbnail"] = {"url": icon}
                else:
                    embed["title"] = f"{icon} {group_name} — {server['name']}"

            embeds.append(embed)

        group_embeds[group_name] = embeds
    return group_embeds

def send_initial_messages(grouped_embeds, group_webhooks):
    new_ids = {}
    for group, embeds in grouped_embeds.items():
        webhook = group_webhooks.get(group, DEFAULT_WEBHOOK_URL)
        resp = requests.post(webhook + "?wait=true", json={"embeds": embeds})
        if resp.status_code in (200, 204):
            try:
                data = resp.json()
                new_ids[group] = int(data["id"])
            except Exception as e:
                print(f"[ERROR] Couldn't parse message ID for group {group}: {e}")
        else:
            print(f"[ERROR] Post failed for group {group}: {resp.status_code} - {resp.text}")
    return new_ids

def edit_discord_message(group, msg_id, embeds, webhook_url):
    resp = requests.patch(f"{webhook_url}/messages/{msg_id}", json={"embeds": embeds})
    if resp.status_code not in (200, 204):
        print(f"[ERROR] Failed to update message for group {group}: {resp.status_code} - {resp.text}")

def post_ping(server):
    ping_id = server.get("ping_id", DEFAULT_USER_PING_ID)
    webhook = server.get("webhook_url", DEFAULT_WEBHOOK_URL)
    payload = {
        "content": f"{ping_id} ⚠️ The `{server['name']}` server appears to be down!",
        "allowed_mentions": {"users": [ping_id.strip('<@>')]},
    }
    resp = requests.post(webhook + "?wait=true", json=payload)
    if resp.status_code in (200, 204):
        try:
            data = resp.json()
            return int(data["id"])
        except:
            return None
    return None

def delete_ping(msg_id, webhook):
    resp = requests.delete(f"{webhook}/messages/{msg_id}")
    return resp.status_code in (200, 204)

# === MAIN ===
if __name__ == "__main__":
    servers, example_mode = load_servers_and_detect_example_mode()

    # Initialize per-server state
    for s in servers:
        ip, port = s["ip"], s["port"]
        key = make_server_key(ip, port)
        server_down.setdefault(key, False)
        has_pinged_down.setdefault(key, False)
        downtime_counter[key] = 0  # start fresh

    # Main loop
    while True:
        # Check Steam status (cached); detect transition for freeze/reset behavior
        prev_unhealthy = _last_steam_unhealthy
        steam_unhealthy = steam_is_unhealthy()

        if steam_unhealthy and not prev_unhealthy:
            # Just entered unhealthy: reset counters for servers not already down
            for s in servers:
                key = make_server_key(s["ip"], s["port"])
                if not server_down.get(key, False):
                    downtime_counter[key] = 0
            print("[INFO] Entered Steam outage freeze: counters reset to 0 (non-down servers) & frozen until recovery.")

        if not steam_unhealthy and prev_unhealthy:
            print("[INFO] Steam recovered: counters will resume normal increments.")

        steam_banner = build_steam_banner(steam_unhealthy, _last_steam_check, _last_steam_snapshot)

        grouped_routes = {}   # route_key -> list[(server, stats)]
        route_webhooks = {}   # route_key -> webhook_url

        for s in servers:
            name = s["name"]
            group = s.get("group", "Ungrouped")
            ip, port = s["ip"], s["port"]
            key = make_server_key(ip, port)
            effective_webhook = s.get("webhook_url", DEFAULT_WEBHOOK_URL)
            rk = route_key(group, effective_webhook)

            stats = fetch_stats(ip, port)
            if stats:
                grouped_routes.setdefault(rk, []).append((s, stats))
                if rk not in route_webhooks:
                    route_webhooks[rk] = effective_webhook

                print(f"[{datetime.now()}] {name} is up: {stats['players']} on {stats['map']}")

                # Recover logic: if we had posted a ping earlier, delete it
                if server_down.get(key, False):
                    server_down[key] = False
                    downtime_counter[key] = 0
                    has_pinged_down[key] = False
                    if key in ping_message_ids:
                        if delete_ping(ping_message_ids[key], s.get("webhook_url", DEFAULT_WEBHOOK_URL)):
                            ping_message_ids.pop(key)
                            save_json("ping_message_ids.json", ping_message_ids)
                else:
                    # Healthy tick: keep counter at 0
                    downtime_counter[key] = 0
                    has_pinged_down[key] = False

            else:
                print(f"[{datetime.now()}] {name} is DOWN!")

                if example_mode:
                    # Example mode: never increment, never ping
                    continue

                if steam_unhealthy:
                    # Freeze while unhealthy; keep counter at 0 to avoid latent pings after recovery
                    downtime_counter[key] = 0
                    continue

                # Normal path: increment and evaluate threshold
                prev = downtime_counter.get(key, 0)
                cur = prev + 1
                downtime_counter[key] = cur

                if cur >= 3:
                    if not server_down.get(key, False):
                        server_down[key] = True
                    if not has_pinged_down.get(key, False):
                        has_pinged_down[key] = True
                        if key not in ping_message_ids:
                            pid = post_ping(s)
                            if pid:
                                ping_message_ids[key] = pid
                                save_json("ping_message_ids.json", ping_message_ids)

        # Build and send/edit embeds per (group, webhook) route
        if grouped_routes:
            for rk, pairs in grouped_routes.items():
                group_name, webhook_url = rk.split("|", 1)
                built = build_grouped_embeds({group_name: pairs}, steam_banner=steam_banner)
                embeds = built[group_name]

                if rk in message_ids:
                    edit_discord_message(group_name, message_ids[rk], embeds, webhook_url)
                else:
                    new_ids = send_initial_messages({group_name: embeds}, {group_name: webhook_url})
                    if group_name in new_ids:
                        message_ids[rk] = new_ids[group_name]
                        save_json("message_ids.json", message_ids)

        # Persist state each loop
        save_json("server_down.json", server_down)
        save_json("has_pinged_down.json", has_pinged_down)

        time.sleep(INTERVAL_SECONDS)
