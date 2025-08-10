# Discord-A2S-QueryBot v1.3.1 — Restart Time accepts strings/numbers + validation
# - restart_hour / restart_minute can be "09", 9, "0", 0, etc.
# - Validates ranges (hour 0–23, minute 0–59); warns if invalid/missing
# - Keeps first-run example mode (no pings) and yellow example embed

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

message_ids = {}
ping_message_ids = {}
server_down = {}
downtime_counter = {}
has_pinged_down = {}

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

# === Example config ===
def create_example_servers_file():
    example_servers = [
        {
            "name": "⚠️ Example Server — Please Edit servers.json",
            "ip": "0.0.0.0",
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
        # Handles "09", "9", 9, etc.
        return int(str(v).strip())
    except Exception:
        return None

def parse_restart_time(server):
    """
    Returns (hour, minute, error_text)
    - If restart disabled: (None, None, None)
    - If enabled & valid: (hour, minute, None)
    - If enabled & missing: (None, None, "missing")
    - If enabled & invalid range/type: (None, None, "invalid")
    """
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
def build_grouped_embeds(grouped_servers):
    group_embeds = {}
    for group_name, pairs in grouped_servers.items():
        embeds = []
        for server, stats in pairs:
            desc = f"**{stats['name']}**\n\n📜 Map: `{stats['map']}`\n👥 Players: `{stats['players']} / {stats['max_players']}`"

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
                else:  # invalid
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

            # Yellow for example entry
            if server.get("ip") == "0.0.0.0":
                embed["color"] = 0xFFCC00

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
        "allowed_mentions": {"users": [ping_id.strip("<@>")]},
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

    # Initialize & possible init pings (not in example mode)
    for s in servers:
        ip, port = s["ip"], s["port"]
        key = make_server_key(ip, port)
        server_down.setdefault(key, False)
        has_pinged_down.setdefault(key, False)

        stats = fetch_stats(ip, port)
        if stats:
            downtime_counter[key] = 0
        else:
            downtime_counter[key] = 3
            server_down[key] = True
            if not example_mode:
                print(f"[INIT] {s['name']} is already down — triggering ping.")
                if not has_pinged_down[key]:
                    has_pinged_down[key] = True
                    pid = post_ping(s)
                    if pid:
                        ping_message_ids[key] = pid
                        save_json("ping_message_ids.json", ping_message_ids)
            else:
                print(f"[INIT] Example mode active — skipping pings for {s['name']}")

    # Loop
    while True:
        grouped = {}
        group_webhooks = {}
        for s in servers:
            name = s["name"]
            group = s.get("group", "Ungrouped")
            ip, port = s["ip"], s["port"]
            key = make_server_key(ip, port)

            stats = fetch_stats(ip, port)
            if stats:
                grouped.setdefault(group, []).append((s, stats))
                print(f"[{datetime.now()}] {name} is up: {stats['players']} on {stats['map']}")

                if server_down.get(key, False):
                    server_down[key] = False
                    downtime_counter[key] = 0
                    has_pinged_down[key] = False
                    if key in ping_message_ids:
                        if delete_ping(ping_message_ids[key], s.get("webhook_url", DEFAULT_WEBHOOK_URL)):
                            ping_message_ids.pop(key)
                            save_json("ping_message_ids.json", ping_message_ids)
            else:
                print(f"[{datetime.now()}] {name} is DOWN!")
                downtime_counter[key] = downtime_counter.get(key, 0) + 1

                if downtime_counter[key] >= 3 and not example_mode:
                    if not server_down.get(key, False):
                        server_down[key] = True
                    if not has_pinged_down.get(key, False):
                        has_pinged_down[key] = True
                        if key not in ping_message_ids:
                            pid = post_ping(s)
                            if pid:
                                ping_message_ids[key] = pid
                                save_json("ping_message_ids.json", ping_message_ids)

            if group not in group_webhooks:
                group_webhooks[group] = s.get("webhook_url", DEFAULT_WEBHOOK_URL)

        if grouped:
            embeds_by_group = build_grouped_embeds(grouped)
            for group, embeds in embeds_by_group.items():
                webhook_url = group_webhooks.get(group, DEFAULT_WEBHOOK_URL)
                if group in message_ids:
                    edit_discord_message(group, message_ids[group], embeds, webhook_url)
                else:
                    new_ids = send_initial_messages({group: embeds}, group_webhooks)
                    if group in new_ids:
                        message_ids[group] = new_ids[group]
                        save_json("message_ids.json", message_ids)

        save_json("server_down.json", server_down)
        save_json("has_pinged_down.json", has_pinged_down)

        time.sleep(INTERVAL_SECONDS)
