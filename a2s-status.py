import a2s
import requests
import time
import os
import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# === CONFIG ===
CONFIG_FILE = "servers.json"
DEFAULT_WEBHOOK_URL = "WebhookURL Here"
INTERVAL_SECONDS = 60
DEFAULT_USER_PING_ID = "<@123456789012345678>"

message_ids = {}  # Keyed by group
ping_message_ids = {}  # Keyed by server key
server_down = {}  # Track status per server key
downtime_counter = {}  # Tracks failed checks per server key
has_pinged_down = {}  # Prevent duplicate pings per server key

# === FILE IO HELPERS ===
def load_json(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)

message_ids = load_json("message_ids.json")
ping_message_ids = load_json("ping_message_ids.json")
server_down = load_json("server_down.json")
has_pinged_down = load_json("has_pinged_down.json")

# === SERVER CONFIG ===
def load_servers():
    if not os.path.exists(CONFIG_FILE):
        print(f"[ERROR] {CONFIG_FILE} not found.")
        return []
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def make_server_key(ip, port):
    return f"{ip}:{port}"

def fetch_stats(ip, port):
    address = (ip, port)
    try:
        info = a2s.info(address, timeout=2.0)
        players = a2s.players(address, timeout=2.0)
        player_names = [p.name for p in players if p.name.strip() != ""]
        return {
            "name": info.server_name,
            "map": info.map_name,
            "players": info.player_count,
            "max_players": info.max_players,
            "player_names": player_names
        }
    except Exception as e:
        print(f"[ERROR] Query failed for {ip}:{port}: {e}")
        return None

def build_grouped_embeds(grouped_servers):
    group_embeds = {}
    for group_name, server_list in grouped_servers.items():
        embeds = []
        for server, stats in server_list:
            description = f"""**{stats['name']}**\n\n📜 Map: `{stats['map']}`\n👥 Players: `{stats['players']} / {stats['max_players']}`"""

            if server.get("restart", False):
                tz = server.get("timezone", "UTC")
                local_restart = datetime.now(ZoneInfo(tz)).replace(hour=6, minute=0, second=0, microsecond=0)
                restart_time = local_restart.astimezone(ZoneInfo("UTC"))
                restart_timestamp = int(restart_time.timestamp())
                description += f"\n\n🔄 Restarts daily at <t:{restart_timestamp}:t> _(your local time)_"

            description += "\n\n"  # Ensure spacing before player list

            if stats["player_names"]:
                player_list = "\n".join(f"- {name}" for name in stats["player_names"][:stats["max_players"]])
            else:
                player_list = "*No players online*"

            description += f"**Current Players:**\n{player_list}"

            icon = server.get("icon_url") or server.get("emoji")
            embed = {
                "title": f"🎮 {group_name} — {server['name']}",
                "description": description,
                "color": 0x7f00ff,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "Updated every 60 seconds"}
            }
            if icon:
                if icon.startswith("http"):
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
        response = requests.post(webhook + "?wait=true", json={"embeds": embeds})
        if response.status_code in (200, 204):
            try:
                data = response.json()
                new_ids[group] = int(data["id"])
            except Exception as e:
                print(f"[ERROR] Couldn't parse message ID for group {group}: {e}")
        else:
            print(f"[ERROR] Post failed for group {group}: {response.status_code} - {response.text}")
    return new_ids

def edit_discord_message(group, msg_id, embeds, webhook_url):
    headers = {"Content-Type": "application/json"}
    response = requests.patch(
        f"{webhook_url}/messages/{msg_id}",
        headers=headers,
        json={"embeds": embeds}
    )
    if response.status_code not in (200, 204):
        print(f"[ERROR] Failed to update message for group {group}: {response.status_code} - {response.text}")

def post_ping(server):
    ping_id = server.get("ping_id", DEFAULT_USER_PING_ID)
    webhook = server.get("webhook_url", DEFAULT_WEBHOOK_URL)
    payload = {
        "content": f"{ping_id} ⚠️ The `{server['name']}` server appears to be down!",
        "allowed_mentions": {"users": [ping_id.strip("<@>")]}
    }
    response = requests.post(webhook + "?wait=true", json=payload)
    if response.status_code in (200, 204):
        try:
            data = response.json()
            return int(data["id"])
        except:
            return None
    return None

def delete_ping(msg_id, webhook):
    response = requests.delete(f"{webhook}/messages/{msg_id}")
    return response.status_code in (200, 204)

# === MAIN LOOP ===
if __name__ == "__main__":
    servers = load_servers()
    for s in servers:
        ip = s["ip"]
        port = s["port"]
        server_key = make_server_key(ip, port)
        if server_key not in server_down:
            server_down[server_key] = False
        if server_key not in has_pinged_down:
            has_pinged_down[server_key] = False

        initial_stats = fetch_stats(ip, port)
        if initial_stats:
            downtime_counter[server_key] = 0
        else:
            downtime_counter[server_key] = 3
            server_down[server_key] = True
            print(f"[INIT] {s['name']} is already down — triggering ping.")
            if not has_pinged_down[server_key]:
                has_pinged_down[server_key] = True
                ping_id = post_ping(s)
                if ping_id:
                    ping_message_ids[server_key] = ping_id
                    save_json("ping_message_ids.json", ping_message_ids)

    while True:
        grouped_servers = {}
        group_webhooks = {}
        for server in servers:
            name = server["name"]
            group = server.get("group", "Ungrouped")
            ip = server["ip"]
            port = server["port"]
            server_key = make_server_key(ip, port)

            stats = fetch_stats(ip, port)
            if stats:
                grouped_servers.setdefault(group, []).append((server, stats))
                print(f"[{datetime.now()}] {name} is up: {stats['players']} players on {stats['map']}")

                if server_down.get(server_key, False):
                    server_down[server_key] = False
                    downtime_counter[server_key] = 0
                    has_pinged_down[server_key] = False
                    if server_key in ping_message_ids:
                        if delete_ping(ping_message_ids[server_key], server.get("webhook_url", DEFAULT_WEBHOOK_URL)):
                            ping_message_ids.pop(server_key)
                            save_json("ping_message_ids.json", ping_message_ids)
                else:
                    downtime_counter[server_key] = 0
                    has_pinged_down[server_key] = False
            else:
                print(f"[{datetime.now()}] {name} is DOWN!")
                downtime_counter[server_key] = downtime_counter.get(server_key, 0) + 1

                if downtime_counter[server_key] >= 3:
                    if not server_down.get(server_key, False):
                        server_down[server_key] = True
                    if not has_pinged_down.get(server_key, False):
                        has_pinged_down[server_key] = True
                        if server_key not in ping_message_ids:
                            ping_id = post_ping(server)
                            if ping_id:
                                ping_message_ids[server_key] = ping_id
                                save_json("ping_message_ids.json", ping_message_ids)

            if group not in group_webhooks:
                group_webhooks[group] = server.get("webhook_url", DEFAULT_WEBHOOK_URL)

        if grouped_servers:
            group_embeds = build_grouped_embeds(grouped_servers)
            for group, embeds in group_embeds.items():
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
