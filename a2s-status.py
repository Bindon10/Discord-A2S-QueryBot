# ============================================================
# Discord-A2S-QueryBot
# Version: v2.0.3
#
# CHANGELOG
# v2.0.3 (2025-09-18)
# - Added SHOW_QUERIED_NAME_IN_HEADER toggle + failsafe in config
# - Consolidated grouped embeds (one embed per group)
# - Added subtle dividers between servers in grouped embeds
# - Multi-webhook support (webhooks[] and webhook_url)
# - Independent message_id per webhook (no overwrites)
# - Quiet logging unless warnings/errors
# ============================================================


import a2s
import requests
import time
import os
import json
import random
import signal
import sys
import shutil
from datetime import datetime
from zoneinfo import ZoneInfo
import socket
import logging
from logging.handlers import RotatingFileHandler

# === USER CONFIG (edit me) ===
# Quick setup:
# 1) Set DEFAULT_WEBHOOK_URL (master channel for servers without per-server override)
# 2) (Optional) Set ALERTS_WEBHOOK for a debug/errors channel — or leave blank to log to console
# 3) (Optional) Put your STEAM_API_KEY and keep STEAM_STATUS_CHECK_ENABLED=True to freeze during Steam-wide outages
# 4) (Optional) Tweak INTERVAL_SECONDS and DOWN_FAIL_THRESHOLD
# 5) (Optional) Toggle STALE_PURGE_ENABLED if you want message_id cleanup

# Debug logging (global): console is always on at INFO; set True to also write DEBUG logs to debug.log (rotating).
DEBUG_LOG_ENABLED = False  # Also save console logs to debug.log (rotates). Console output is always shown.

# Required: master webhook for servers that don't specify their own `webhook_url` in servers.json
DEFAULT_WEBHOOK_URL = "https://discord.com/api/webhooks/CHANGE_ME"

# Optional: alerts/debug/warnings webhook (critical issues only).
# Leave blank to log to console. You can also set the ALERTS_WEBHOOK env var.
ALERTS_WEBHOOK = os.getenv("ALERTS_WEBHOOK", "").strip()

# How often to refresh embeds (seconds)
INTERVAL_SECONDS = 60

# Default mention used for down pings when a server doesn't set `ping_id` or `ping_role_id`.
# You can set this to "" to disable default pings.
DEFAULT_USER_PING_ID = "<@123456789012345678>"

# Steam backend health gate (optional). If enabled AND `STEAM_API_KEY` is set,
# the bot freezes downtime counters during Steam-wide issues to avoid false alarms.
STEAM_STATUS_CHECK_ENABLED = True
STEAM_API_KEY = "PUT_YOUR_STEAM_WEB_API_KEY_HERE"   # https://steamcommunity.com/dev/apikey
STEAM_STATUS_POLL_SECONDS = 180                       # cache Steam health for this many seconds
IGNORED_STEAM_SERVICE_KEYS = {"IEconItems"}          # noisy keys to ignore when judging health

# Behavior knobs
DOWN_FAIL_THRESHOLD = 3        # consecutive failures before a server is considered down (and pinged)
GROUP_EMBED_LIMIT   = 10       # Discord hard cap per message
EMBED_DESC_LIMIT    = 4096     # Discord hard cap per embed description
STALE_PURGE_ENABLED = False    # if True, purge message_ids for routes no longer present in config
SHOW_PLAYERS_BY_DEFAULT = True # default: show player list in embeds (override per-server with 'show_players')
SHOW_VISIBILITY_BY_DEFAULT = False # default: show visibility line (Public/Passworded) per server; override with 'show_visibility'
PLAYER_LIST_LIMIT   = 20       # max number of player names to show in embeds

# Failsafe: make sure SHOW_QUERIED_NAME_IN_HEADER is always defined
try:
    SHOW_QUERIED_NAME_IN_HEADER
except NameError:
    SHOW_QUERIED_NAME_IN_HEADER = False


# === INTERNAL (you usually don't need to touch below this line) ===

# Debug logging setup: console always ON (INFO+); optional rotating file for DEBUG
logger = logging.getLogger("a2sbot")
logger.setLevel(logging.DEBUG)  # master gate

_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_console_handler)

if DEBUG_LOG_ENABLED:
    _file_handler = RotatingFileHandler("debug.log", maxBytes=5 * 1024 * 1024, backupCount=3)
    _file_handler.setLevel(logging.DEBUG)
    _file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(_file_handler)

# === HTTP Session & helpers ===
SESSION = requests.Session()
try:
    from requests.adapters import HTTPAdapter
    SESSION.mount("https://", HTTPAdapter(pool_connections=8, pool_maxsize=16))
    SESSION.mount("http://", HTTPAdapter(pool_connections=4, pool_maxsize=8))
except Exception:
    pass
SESSION.headers.update({"User-Agent": "Discord-A2S-QueryBot/2.0.3"})

def _sleep_backoff(attempt: int, base: float = 0.75, cap: float = 5.0):
    delay = min(cap, base * (2 ** attempt)) + random.uniform(0, 0.25)
    time.sleep(delay)

def discord_request(method: str, url: str, *, json_payload=None, timeout: float = 15, max_retries: int = 3):
    """Request wrapper with 429 Retry-After + 5xx backoff. Returns (resp, errstr|None)."""
    for attempt in range(max_retries + 1):
        try:
            resp = SESSION.request(method, url, json=json_payload, timeout=timeout)
        except Exception as e:
            if attempt >= max_retries:
                return None, f"request exception: {e}"
            _sleep_backoff(attempt)
            continue

        # Global / regular 429
        if resp.status_code == 429:
            try:
                ra = resp.headers.get("Retry-After")
                if not ra:
                    data = resp.json()
                    ra = data.get("retry_after")
                delay = float(ra) if ra else 1.0
            except Exception:
                delay = 1.0
            time.sleep(delay + random.uniform(0, 0.25))
            if attempt >= max_retries:
                return resp, f"429 Too Many Requests (gave up after {max_retries} retries)"
            continue

        # Transient 5xx
        if 500 <= resp.status_code < 600:
            if attempt >= max_retries:
                return resp, f"{resp.status_code} server error"
            _sleep_backoff(attempt)
            continue

        return resp, None
    return None, "exhausted retries"

# === JSON IO ===

def load_json(filename):
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    """Atomic-ish write with .bak."""
    tmp = f"{filename}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if os.path.exists(filename):
            try:
                shutil.copyfile(filename, f"{filename}.bak")
            except Exception:
                pass
        os.replace(tmp, filename)
    except Exception:
        # Fallback best-effort
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

message_ids = load_json("message_ids.json")
ping_message_ids = load_json("ping_message_ids.json")
server_down = load_json("server_down.json")
has_pinged_down = load_json("has_pinged_down.json")
alerts_state = load_json("alerts_state.json")
ping_routes = load_json("ping_routes.json")

# Net-freeze (host network outage)
NET_FREEZE_ACTIVE = False
NET_OUTAGE_STARTED_AT = None
_net_fail_streak = 0
_net_ok_streak = 0

# Steam health cache/state
STEAM_HEALTH_ENABLED = False
_last_steam_check = 0.0
_last_steam_unhealthy = False
_last_steam_snapshot = None

# Restore prior net-freeze state if present (survives restarts)
try:
    _ns = load_json("net_state.json")
    NET_FREEZE_ACTIVE = bool(_ns.get("active", False))
    NET_OUTAGE_STARTED_AT = _ns.get("started_at", None)
except Exception:
    pass

def _save_net_state():
    try:
        save_json("net_state.json", {"active": NET_FREEZE_ACTIVE, "started_at": NET_OUTAGE_STARTED_AT})
    except Exception:
        pass

# --- network probes ---
def _tcp_ping(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def _https_ping_discord(timeout: float = 2.5) -> bool:
    try:
        resp, err = discord_request("HEAD", "https://discord.com/api", timeout=timeout)
        if resp is None:
            return False
        return 200 <= resp.status_code < 500
    except Exception:
        return False

def net_probe_ok() -> bool:
    dns_ok = _tcp_ping("1.1.1.1", 53) or _tcp_ping("8.8.8.8", 53)
    disc_ok = _https_ping_discord()
    return dns_ok and disc_ok

# One-time migration to route-based keys
if message_ids and any("|" not in k for k in list(message_ids.keys())):
    logger.info("[INIT] Detected legacy message_ids.json (group-only keys). Resetting for route-based keys.")
    message_ids = {}
    save_json("message_ids.json", message_ids)

# === Example config ===

CONFIG_FILE = "servers.json"

def create_example_servers_file():
    example_servers = [
        {
            "name": "⚠️ Example Server — Please Edit servers.json",
            "ip": "0.0.0.0",  # sentinel triggers example mode
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
    logger.info("[INIT] Created example servers.json — edit this file and restart to begin monitoring real servers.")

def load_servers_and_detect_example_mode():
    if not os.path.exists(CONFIG_FILE):
        create_example_servers_file()
        return [], True
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        servers = json.load(f)
    if not isinstance(servers, list):
        msg = "servers.json must be a JSON array. Pings disabled for safety."
        logger.error("[ERROR] %s", msg)
        alert_issue("Invalid servers.json shape", msg, {"type": type(servers).__name__})
        return [], True
    if len(servers) > 0 and all(s.get("ip") == "0.0.0.0" for s in servers):
        logger.info("[INIT] Detected example servers.json — edit this file and restart to enable pings.")
        return servers, True
    return servers, False

# === ALERTS HELPERS ===
def _alerts_save():
    try:
        save_json("alerts_state.json", alerts_state)
    except Exception:
        pass

def alert_should_post(key: str) -> bool:
    state = alerts_state.get(key)
    if not state or not state.get("active"):
        alerts_state[key] = {"active": True, "first_seen": time.time()}
        _alerts_save()
        return True
    return False

def alert_resolve(key: str):
    st = alerts_state.get(key)
    if st and st.get("active"):
        alerts_state[key]["active"] = False
        alerts_state[key]["resolved_at"] = time.time()
        _alerts_save()

def _now_iso_local():
    try:
        return datetime.now(ZoneInfo("America/Edmonton")).isoformat(timespec="seconds")
    except Exception:
        return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def _post_alert(payload: dict) -> bool:
    if not ALERTS_WEBHOOK:
        logger.info("[ALERT] %s", payload)
        return False
    resp, err = discord_request("POST", ALERTS_WEBHOOK, json_payload=payload, timeout=15)
    return bool(resp and (200 <= resp.status_code < 300))

def alert_issue(title: str, description: str, extras: dict | None = None, key: str | None = None):
    if key is not None and not alert_should_post(key):
        return
    embed = {
        "title": f"⚠️ {title}",
        "description": description,
        "timestamp": _now_iso_local(),
        "color": 0xFF8800,
        "fields": ([{"name": k, "value": str(v)[:1000], "inline": False} for k, v in (extras or {}).items()])
    }
    _post_alert({"embeds": [embed]})

# === Steam Health Check & Banner ===
def _interpret_steam_health(payload) -> bool:
    try:
        result = payload.get("result") or payload.get("data") or payload
        suspicious, ignored = [], []
        services = result.get("services", {}) or {}
        matchmaking = result.get("matchmaking", {}) or {}
        def is_bad(v):
            return isinstance(v, str) and v.lower() in ("offline", "critical", "degraded", "delayed")
        for k, v in services.items():
            if is_bad(v):
                (ignored if k in IGNORED_STEAM_SERVICE_KEYS else suspicious).append((f"services.{k}", v))
        for k, v in matchmaking.items():
            if is_bad(v):
                suspicious.append((f"matchmaking.{k}", v))
        if suspicious:
            logger.debug("[DEBUG] Steam unhealthy reasons (considered): %s", suspicious)
        if ignored:
            logger.debug("[DEBUG] Steam unhealthy reasons (ignored noisy): %s", ignored)
        return len(suspicious) > 0
    except Exception as e:
        logger.debug("[DEBUG] Failed to interpret Steam health (possible false unhealthy): %s", e)
        return False

def steam_is_unhealthy() -> bool:
    global _last_steam_check, _last_steam_unhealthy, _last_steam_snapshot
    if not STEAM_HEALTH_ENABLED or not STEAM_STATUS_CHECK_ENABLED:
        return False
    if not STEAM_API_KEY or STEAM_API_KEY == "PUT_YOUR_STEAM_WEB_API_KEY_HERE":
        return False
    now = time.time()
    if now - _last_steam_check < STEAM_STATUS_POLL_SECONDS:
        return _last_steam_unhealthy
    url = "https://api.steampowered.com/ICSGOServers_730/GetGameServersStatus/v1/"
    try:
        resp, err = discord_request("GET", url + f"?key={STEAM_API_KEY}", timeout=10)
        _last_steam_check = now
        if not resp or resp.status_code == 403 or (resp.status_code and resp.status_code != 200):
            _last_steam_unhealthy = False
            _last_steam_snapshot = None
            return False
        data = resp.json()
        unhealthy = _interpret_steam_health(data)
        _last_steam_unhealthy = unhealthy
        _last_steam_snapshot = data
        return unhealthy
    except Exception as e:
        logger.debug("[DEBUG] Steam API request error: %s. Treating as healthy this cycle.", e)
        _last_steam_check = now
        _last_steam_unhealthy = False
        _last_steam_snapshot = None
        return False

def _summarize_unhealthy_reasons(snapshot) -> list:
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

        # Password visibility (library field) + fallback via rules
        passworded = getattr(info, "password_protected", None)
        if passworded is None:
            try:
                rules = a2s.rules(addr, timeout=2.5)
                if "sv_password" in rules:
                    passworded = (str(rules["sv_password"]).strip() not in ("", "0"))
            except Exception:
                passworded = None

        return {
            "name": info.server_name,
            "map": info.map_name,
            "players": info.player_count,
            "max_players": info.max_players,
            "player_names": names,
            "password_protected": passworded,
        }
    except Exception as e:
        logger.info("[INFO] Query failed for %s:%s: %s", ip, port, e)
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

# === Display/Grouping helpers ===
def get_display_group(server):
    g = (server.get("group") or "").strip()
    return g  # "" if not set

def get_merge_group_key(server):
    g = (server.get("group") or "").strip()
    if g:
        return g
    return f"__solo__:{server.get('ip')}:{server.get('port')}"

# === Safety utilities ===
def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"

def _is_placeholder_webhook(url: str | None) -> bool:
    return (not url) or ("CHANGE_ME" in str(url))

def _safe_tz(tz: str):
    try:
        return ZoneInfo(tz)
    except Exception:
        return ZoneInfo("UTC")

def _san(n: str) -> str:
    # escape simple markdown and trim very long names
    for ch in ("`", "*", "_", "~", "|", ">"):
        n = n.replace(ch, f"\\{ch}")
    return n[:64]



def delete_discord_message(msg_id: int | str, webhook_url: str, label: str = "unknown") -> bool:
    """Best-effort delete of a Discord message by id."""
    if not webhook_url or _is_placeholder_webhook(webhook_url):
        return False
    try:
        resp, err = discord_request("DELETE", f"{webhook_url}/messages/{msg_id}", timeout=10)
        if resp and resp.status_code in (200, 204):
            logger.info("[CLEANUP] Deleted message %s (%s)", msg_id, label)
            return True
        if resp and resp.status_code == 404:
            logger.info("[CLEANUP] Message %s already gone (%s)", msg_id, label)
            return True
        errtxt = err or (f"{getattr(resp,'status_code','???')} - {getattr(resp,'text','')[:180]}")
        logger.warning("[WARN] Failed to delete message %s (%s): %s", msg_id, label, errtxt)
    except Exception as e:
        logger.warning("[WARN] Exception deleting message %s (%s): %s", msg_id, label, e)
    return False
# === Discord ===

def build_grouped_embeds(grouped_servers, steam_banner: str = ""):
    group_embeds = {}
    for group_name, pairs in grouped_servers.items():
        embeds = []
        if group_name:
            # Consolidate all servers in this group into one embed
            sections = []
            for idx, (server, stats) in enumerate(pairs):
                vis_enabled = bool(server.get("show_visibility", SHOW_VISIBILITY_BY_DEFAULT))
                vis_line = ""
                if vis_enabled and (stats.get("password_protected") is not None):
                    if bool(stats.get("password_protected")):
                        vis_line = "\n🔐 Passworded"
                    else:
                        vis_line = "\n🔓 Public"

                display_name = stats.get('queried_name') if SHOW_QUERIED_NAME_IN_HEADER and stats.get('queried_name') else server['name']
                header = f"**{display_name}**\n\n"
                header += (
                    f"📜 Map: `{stats['map']}`\n"
                    f"👥 Players: `{stats['players']} / {stats['max_players']}`" + vis_line
                )

                body_lines = []
                h, m, err = parse_restart_time(server)
                if server.get("restart", False):
                    if err is None:
                        tz = _safe_tz(server.get("timezone", "UTC"))
                        local_restart = datetime.now(tz).replace(hour=h, minute=m, second=0, microsecond=0)
                        restart_utc = local_restart.astimezone(ZoneInfo("UTC"))
                        restart_ts = int(restart_utc.timestamp())
                        body_lines.append(f"🔄 Restarts daily at <t:{restart_ts}:t> _(your local time)_")
                    elif err == "missing":
                        logger.warning("[WARN] Restart enabled in config for '%s' but restart_hour/minute not set.", server.get("name","?"))
                        body_lines.append("⚠️ Restart time not configured — set restart_hour and restart_minute in servers.json")
                    else:
                        logger.warning("[WARN] Restart time invalid in config for '%s'. Use hour 0–23 and minute 0–59.", server.get("name","?"))
                        body_lines.append("⚠️ Restart time invalid — use hour 0–23 and minute 0–59")

                show_players = bool(server.get("show_players", SHOW_PLAYERS_BY_DEFAULT))
                players_block = ""
                if stats.get("players", 0) > 0 and stats.get("player_names"):
                    players_block = "\n".join(f"- {_san(p)}" for p in stats["player_names"][:PLAYER_LIST_LIMIT])
                    if len(stats["player_names"]) > PLAYER_LIST_LIMIT:
                        players_block += "\n…"
                else:
                    players_block = "No players online"

                parts = [header]
                if body_lines:
                    parts.append("\n".join(body_lines))
                if show_players:
                    parts.append("**Current Players:**\n" + players_block)
                section_desc = "\n\n".join(parts)
                section_desc = _truncate(section_desc, EMBED_DESC_LIMIT)

                # Add subtle divider except after the last server
                if idx < len(pairs) - 1:
                    section_desc += "\n────────────"

                sections.append(section_desc)

            combined_desc = "\n\n".join(sections)
            combined_desc = _truncate(combined_desc, EMBED_DESC_LIMIT)

            embed = {
                "title": group_name,
                "description": combined_desc,
                "color": 0x7F00FF,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "Updated every 60 seconds"},
            }
            if steam_banner:
                embed["description"] = steam_banner + "\n" + embed.get("description", "")

            embeds.append(embed)
        else:
            # Not grouped: one embed per server
            for server, stats in pairs:
                vis_enabled = bool(server.get("show_visibility", SHOW_VISIBILITY_BY_DEFAULT))
                vis_line = ""
                if vis_enabled and (stats.get("password_protected") is not None):
                    if bool(stats.get("password_protected")):
                        vis_line = "\n🔐 Passworded"
                    else:
                        vis_line = "\n🔓 Public"

                header = ""
                if SHOW_QUERIED_NAME_IN_HEADER and stats.get('queried_name'):
                    header = f"**{stats['queried_name']}**\n\n"
                header += (
                    f"📜 Map: `{stats['map']}`\n"
                    f"👥 Players: `{stats['players']} / {stats['max_players']}`" + vis_line
                )

                body_lines = []
                h, m, err = parse_restart_time(server)
                if server.get("restart", False):
                    if err is None:
                        tz = _safe_tz(server.get("timezone", "UTC"))
                        local_restart = datetime.now(tz).replace(hour=h, minute=m, second=0, microsecond=0)
                        restart_utc = local_restart.astimezone(ZoneInfo("UTC"))
                        restart_ts = int(restart_utc.timestamp())
                        body_lines.append(f"🔄 Restarts daily at <t:{restart_ts}:t> _(your local time)_")
                    elif err == "missing":
                        logger.warning("[WARN] Restart enabled in config for '%s' but restart_hour/minute not set.", server.get("name","?"))
                        body_lines.append("⚠️ Restart time not configured — set restart_hour and restart_minute in servers.json")
                    else:
                        logger.warning("[WARN] Restart time invalid in config for '%s'. Use hour 0–23 and minute 0–59.", server.get("name","?"))
                        body_lines.append("⚠️ Restart time invalid — use hour 0–23 and minute 0–59")

                show_players = bool(server.get("show_players", SHOW_PLAYERS_BY_DEFAULT))
                players_block = ""
                if stats.get("players", 0) > 0 and stats.get("player_names"):
                    players_block = "\n".join(f"- {_san(p)}" for p in stats["player_names"][:PLAYER_LIST_LIMIT])
                    if len(stats["player_names"]) > PLAYER_LIST_LIMIT:
                        players_block += "\n…"
                else:
                    players_block = "No players online"

                parts = [header]
                if body_lines:
                    parts.append("\n".join(body_lines))
                if show_players:
                    parts.append("**Current Players:**\n" + players_block)
                desc = "\n\n".join(parts)
                desc = _truncate(desc, EMBED_DESC_LIMIT)

                icon = server.get("icon_url") or server.get("emoji")
                title_text = (server['name'] if not (SHOW_QUERIED_NAME_IN_HEADER and stats.get('queried_name')) else stats['queried_name'])

                embed = {
                    "title": title_text,
                    "description": desc,
                    "color": 0x7F00FF,
                    "timestamp": datetime.utcnow().isoformat(),
                    "footer": {"text": "Updated every 60 seconds"},
                }

                if server.get("ip") == "0.0.0.0":
                    embed["color"] = 0xFFCC00

                if icon:
                    if isinstance(icon, str) and str(icon).startswith("http"):
                        embed["thumbnail"] = {"url": icon}
                    else:
                        embed["title"] = f"{icon} {embed['title']}"

                embeds.append(embed)

        if len(embeds) > GROUP_EMBED_LIMIT:
            alert_issue(
                "Embed limit exceeded",
                "Trimming to 10 embeds for this route to satisfy Discord limits.",
                {"group": group_name or "(no group)", "trimmed": len(embeds) - GROUP_EMBED_LIMIT},
                key=f"embedlimit:{group_name or 'nogroup'}"
            )
            embeds = embeds[:GROUP_EMBED_LIMIT]

        group_embeds[group_name] = embeds
    return group_embeds


def send_initial_messages(grouped_embeds, group_webhooks):
    new_ids = {}
    for group, embeds in grouped_embeds.items():
        webhook = group_webhooks.get(group, DEFAULT_WEBHOOK_URL)
        # If the DEFAULT webhook is a placeholder but users are intentionally using per-server webhooks,
        # don't raise a global error — only skip when this *route* actually points at a placeholder.
        if _is_placeholder_webhook(webhook):
            # One-time, route-scoped notice so users know why nothing appears for this group
            alert_issue(
                "No webhook for this route",
                "This route has no valid webhook (server webhook_url missing and DEFAULT_WEBHOOK_URL is a placeholder).",
                {"group": group, "webhook": str(webhook)[:80]},
                key=f"missing:init:{group}"
            )
            continue
        resp, err = discord_request("POST", webhook + "?wait=true", json_payload={"embeds": embeds}, timeout=20)
        if resp and resp.status_code in (200, 204):
            try:
                data = resp.json()
                new_ids[group] = int(data["id"])
            except Exception as e:
                logger.warning("[WARN] Couldn't parse message ID for group %s: %s", group, e)
        else:
            errtxt = err or (f"{getattr(resp,'status_code', '???')} - {getattr(resp,'text','')[:180]}")
            logger.error("[ERROR] Post failed for group %s: %s", group, errtxt)
            alert_issue("Failed to post initial status", "Discord rejected the create message request.",
                        {"group": group, "webhook": webhook, "error": errtxt}, key=f"post:init:{group}|{webhook}")
    return new_ids

def edit_discord_message(group, msg_id, embeds, webhook_url, rk):
    # Safeguard against empty or malformed embeds
    if not embeds or not any(e.get("description") or e.get("title") for e in embeds):
        logger.warning("[WARN] Skipping update for %s — empty embed payload", group)
        return

    # If this points at a placeholder (e.g., DEFAULT is unused by design), treat as stale and drop quietly.
    if _is_placeholder_webhook(webhook_url):
        if rk in message_ids:
            message_ids.pop(rk, None)
            save_json("message_ids.json", message_ids)
        return
    resp, err = discord_request("PATCH", f"{webhook_url}/messages/{msg_id}", json_payload={"embeds": embeds}, timeout=20)
    if resp and resp.status_code in (200, 204):
        alert_resolve(f"post:init:{group}|{webhook_url}")
        alert_resolve(f"edit:fail:{rk}")
        return
    errtxt = err or (f"{getattr(resp,'status_code','???')} - {getattr(resp,'text','')[:180]}")
    logger.error("[ERROR] Failed to update message for group %s: %s", group, errtxt)
    if resp and resp.status_code == 404:
        r2, err2 = discord_request("POST", webhook_url + "?wait=true", json_payload={"embeds": embeds}, timeout=20)
        if r2 and r2.status_code in (200, 204):
            try:
                data = r2.json()
                new_id = int(data.get("id"))
                message_ids[rk] = new_id
                save_json("message_ids.json", message_ids)
                logger.info("[INFO] Recreated missing message for route %s with new id %s", rk, new_id)
                alert_resolve(f"post:init:{group}|{webhook_url}")
                alert_resolve(f"edit:fail:{rk}")
                return
            except Exception as e2:
                logger.warning("[WARN] Recreate succeeded but couldn't parse message id: %s", e2)
    alert_issue("Failed to update status message", "Discord rejected the edit message request.",
                {"group": group, "webhook": webhook_url, "msg_id": msg_id, "error": errtxt}, key=f"edit:fail:{rk}")

def post_ping(server):
    role_id = server.get("ping_role_id")
    raw = None
    allowed = {"users": [], "roles": []}
    if role_id:
        role_id_str = str(role_id).strip()
        raw = f"<@&{role_id_str}>"
        allowed["roles"] = [role_id_str]
    else:
        ping_id = server.get("ping_id", DEFAULT_USER_PING_ID)
        if ping_id:
            raw = ping_id
            cleaned = "".join(ch for ch in ping_id if ch.isdigit())
            if cleaned:
                allowed["users"] = [cleaned]

    webhook = server.get("webhook_url", DEFAULT_WEBHOOK_URL)
    if _is_placeholder_webhook(webhook):
        alert_issue("Missing webhook for ping", "Server down ping could not be delivered (no webhook).",
                    {"server": server.get("name")}, key=f"missing:ping:{server.get('name')}:{server.get('ip')}:{server.get('port')}")
        return None
    content = (f"{raw} ⚠️ The `{server['name']}` server appears to be down!" if raw else
               f"⚠️ The `{server['name']}` server appears to be down!")
    payload = {"content": content, "allowed_mentions": allowed}
    resp, err = discord_request("POST", webhook + "?wait=true", json_payload=payload, timeout=20)
    if resp and resp.status_code in (200, 204):
        try:
            data = resp.json()
            return int(data["id"])
        except Exception:
            return None
    errtxt = err or (f"{getattr(resp,'status_code','???')} - {getattr(resp,'text','')[:180]}")
    logger.error("[ERROR] Ping post failed for %s: %s", server.get("name"), errtxt)
    alert_issue("Failed to post down ping", "Discord rejected the ping message.",
                {"server": server.get("name"), "webhook": webhook, "error": errtxt}, key=f"ping:fail:{server.get('name')}|{webhook}")
    return None

# === Config sanity checks ===
def validate_config(servers):
    seen = {}
    dups = []
    for s in servers:
        k = f"{s.get('ip')}:{s.get('port')}"
        seen[k] = seen.get(k, 0) + 1
    for k, c in seen.items():
        if c > 1:
            dups.append((k, c))
    if dups:
        alert_issue("Duplicate servers in config", "Multiple entries share the same ip:port.",
                    {"duplicates": ", ".join([f"{k}×{c}" for k, c in dups])}, key="config:dups")
    for s in servers:
        nm = (s.get("name") or "")
        gp = (s.get("group") or "")
        if len(nm) > 100:
            logger.warning("[WARN] Server name is very long (>100): %s…", nm[:100])
        if len(gp) > 100:
            logger.warning("[WARN] Group name is very long (>100): %s…", gp[:100])
    groups = {}
    for s in servers:
        key = (s.get("group") or "") + "|" + (s.get("webhook_url") or DEFAULT_WEBHOOK_URL)
        groups[key] = groups.get(key, 0) + 1
    for key, count in groups.items():
        if count > GROUP_EMBED_LIMIT:
            gname, wh = key.split("|", 1)
            alert_issue("Group may exceed embed limit", "This group has more than 10 servers; trims will apply.",
                        {"group": gname or "(no group)", "webhook": wh, "count": count}, key=f"config:group>{GROUP_EMBED_LIMIT}:{gname or 'nogroup'}")

# === Main helpers ===
def make_server_key(ip, port):
    return f"{ip}:{port}"

def route_key(display_key, webhook):
    return f"{display_key}|{webhook}"

# === MAIN ===
if __name__ == "__main__":
    logger.info("[INIT] Starting Discord-A2S-QueryBot v2.0.3 (user-config at top)")

    # Graceful shutdown: flush state
    def _graceful_exit(signum, frame):
        logger.info("[SHUTDOWN] Signal %s received. Saving state…", signum)
        try:
            save_json("server_down.json", server_down)
            save_json("has_pinged_down.json", has_pinged_down)
            save_json("message_ids.json", message_ids)
            save_json("ping_message_ids.json", ping_message_ids)
            _save_net_state()
        finally:
            sys.exit(0)
    for _sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if _sig:
            signal.signal(_sig, _graceful_exit)

    servers, example_mode = load_servers_and_detect_example_mode()
    validate_config(servers)

    # Initialize per-server state
    downtime_counter = {}
    for s in servers:
        ip, port = s["ip"], s["port"]
        key = make_server_key(ip, port)
        server_down.setdefault(key, False)
        has_pinged_down.setdefault(key, False)
        downtime_counter[key] = 0

    # Steam API key check → enable flag
    if STEAM_STATUS_CHECK_ENABLED:
        if (not STEAM_API_KEY) or (STEAM_API_KEY.strip() == "") or (STEAM_API_KEY == "PUT_YOUR_STEAM_WEB_API_KEY_HERE"):
            alert_issue("Steam API key missing", "Skipping Steam backend health checks until configured.",
                        {"env": "STEAM_API_KEY"}, key="config:steam_api_key_missing")
            STEAM_HEALTH_ENABLED = False
        else:
            STEAM_HEALTH_ENABLED = True
    else:
        STEAM_HEALTH_ENABLED = False

    if STEAM_HEALTH_ENABLED:
        logger.info("[Steam Health] Enabled: Steam backend health checks are active.")
    else:
        logger.info("[Steam Health] Disabled: Steam backend health checks are skipped.")
        if STEAM_STATUS_CHECK_ENABLED and ((not STEAM_API_KEY) or (STEAM_API_KEY.strip() == "") or (STEAM_API_KEY == "PUT_YOUR_STEAM_WEB_API_KEY_HERE")):
            logger.info("[Steam Health] Reason: enabled=True but STEAM_API_KEY is missing; updates continue without gating.")

    # Main loop
    while True:

        # Hot reload servers.json each cycle
        servers, example_mode = load_servers_and_detect_example_mode()

        # Reconcile state dicts vs current servers.json

        # Reconcile route keys (handles group/webhook changes)
        expected_route_keys = set()
        for s in servers:
            hooks = s.get("webhooks") or [s.get("webhook_url", DEFAULT_WEBHOOK_URL)]
            merge_key = get_merge_group_key(s)
            for wh in hooks:
                expected_route_keys.add(route_key(merge_key, wh))

        stale_routes = [rk for rk in list(message_ids.keys()) if rk not in expected_route_keys]
        if stale_routes:
            logger.info("[CLEANUP] Routes changed or removed: %s", stale_routes)
            for rk in stale_routes:
                msg_id = message_ids.pop(rk, None)
                try:
                    merge_key, wh = rk.split("|", 1)
                except ValueError:
                    wh = DEFAULT_WEBHOOK_URL
                if msg_id:
                    delete_discord_message(msg_id, wh, label=f"stale/changed route {rk}")
            save_json("message_ids.json", message_ids)
        active_keys = {f"{s['ip']}:{s['port']}" for s in servers}
        for key in list(server_down.keys()):
            if key not in active_keys:
                server_down.pop(key, None)
                has_pinged_down.pop(key, None)
        for key in list(downtime_counter.keys()):
            if key not in active_keys:
                downtime_counter.pop(key, None)
        removed_with_pings = [k for k in list(ping_message_ids.keys()) if k not in active_keys]
        for key in removed_with_pings:
            msg_id = ping_message_ids.pop(key, None)
            webhook = ping_routes.pop(key, DEFAULT_WEBHOOK_URL)
            if msg_id:
                delete_discord_message(msg_id, webhook, label=f"removed-server ping {key}")
        if removed_with_pings:
            save_json("ping_message_ids.json", ping_message_ids)
            save_json("ping_routes.json", ping_routes)
        up_count = 0
        down_count = 0

        # --- network health guard (net-freeze) ---
        if net_probe_ok():
            _net_ok_streak += 1; _net_fail_streak = 0
            if NET_FREEZE_ACTIVE and _net_ok_streak >= 2:
                NET_FREEZE_ACTIVE = False
                dur = None
                try:
                    dur = int(time.time() - (NET_OUTAGE_STARTED_AT or time.time()))
                except Exception:
                    pass
                NET_OUTAGE_STARTED_AT = None
                _save_net_state()
                alert_issue("Network outage recovered", f"Host connectivity restored after ~{dur}s.",
                            {"duration_s": dur}, key="net:outage:recovered")
                alert_resolve("net:outage")
                logger.info("[NET] Recovered: leaving net-freeze (updates resume).")
        else:
            _net_fail_streak += 1; _net_ok_streak = 0
            if not NET_FREEZE_ACTIVE and _net_fail_streak >= 3:
                NET_FREEZE_ACTIVE = True
                NET_OUTAGE_STARTED_AT = time.time()
                _save_net_state()
                try:
                    with open("net_outages.jsonl", "a", encoding="utf-8") as f:
                        f.write(json.dumps({"started_at": NET_OUTAGE_STARTED_AT}) + "\n")
                except Exception:
                    pass
                alert_issue("Network outage suspected",
                            "Host appears offline to Discord/DNS. Freezing counters, pings, and cleanup until connectivity recovers.",
                            {"fails": _net_fail_streak}, key="net:outage")
                logger.info("[NET] Entered net-freeze: suppressing pings, freezing counters, skipping cleanup.")

        # --- Optional Steam health gate ---
        prev_unhealthy = _last_steam_unhealthy
        steam_unhealthy = steam_is_unhealthy() if (STEAM_STATUS_CHECK_ENABLED and STEAM_HEALTH_ENABLED) else False
        if not (STEAM_STATUS_CHECK_ENABLED and STEAM_HEALTH_ENABLED):
            _last_steam_unhealthy = False

        if steam_unhealthy and not prev_unhealthy:
            for s in servers:
                key = make_server_key(s["ip"], s["port"])
                if not server_down.get(key, False):
                    downtime_counter[key] = 0
            logger.info("[INFO] Entered Steam outage freeze: counters reset to 0 (non-down servers) & frozen until recovery.")
        if (not steam_unhealthy) and prev_unhealthy:
            logger.info("[INFO] Steam recovered: counters will resume normal increments.")

        steam_banner = build_steam_banner(steam_unhealthy, _last_steam_check, _last_steam_snapshot)

        # --- Build routes and gather stats ---
        grouped_routes = {}

        for s in servers:
            name = s["name"]
            ip, port = s["ip"], s["port"]
            key = make_server_key(ip, port)

            stats = fetch_stats(ip, port)
            if stats:
                hooks = s.get("webhooks") or [s.get("webhook_url", DEFAULT_WEBHOOK_URL)]
                for server_hook in hooks:
                    merge_key = get_merge_group_key(s)
                    rk = route_key(merge_key, server_hook)
                    grouped_routes.setdefault(rk, []).append((s, stats))

                up_count += 1
                logger.info("[%s] %s is up: %s on %s", datetime.now(), name, stats['players'], stats['map'])

                # Recover logic
                if server_down.get(key, False):
                    server_down[key] = False
                    downtime_counter[key] = 0
                    has_pinged_down[key] = False
                    if key in ping_message_ids:
                        try:
                            delete_ping_url = s.get("webhook_url", DEFAULT_WEBHOOK_URL)
                            if delete_ping_url and not _is_placeholder_webhook(delete_ping_url):
                                discord_request("DELETE", f"{delete_ping_url}/messages/{ping_message_ids[key]}", timeout=10)
                        except Exception:
                            pass
                        ping_message_ids.pop(key, None)
                        save_json("ping_message_ids.json", ping_message_ids)
                else:
                    downtime_counter[key] = 0
                    has_pinged_down[key] = False

            else:
                down_count += 1
                logger.info("[%s] %s is DOWN!", datetime.now(), name)
                if example_mode:
                    continue
                if steam_unhealthy or NET_FREEZE_ACTIVE:
                    downtime_counter[key] = 0
                    continue
                prev = downtime_counter.get(key, 0)
                cur = prev + 1
                downtime_counter[key] = cur
                if cur >= DOWN_FAIL_THRESHOLD:
                    if not server_down.get(key, False):
                        server_down[key] = True
                    if not has_pinged_down.get(key, False):
                        has_pinged_down[key] = True
                        if key not in ping_message_ids:
                            pid = post_ping(s)
                            if pid:
                                ping_message_ids[key] = pid
                                webhook_url = s.get("webhook_url", DEFAULT_WEBHOOK_URL)
                                ping_routes[key] = webhook_url
                                save_json("ping_message_ids.json", ping_message_ids)
                                save_json("ping_routes.json", ping_routes)

        logger.info("[CYCLE] Up: %s  Down: %s  Routes: %s", up_count, down_count, len(grouped_routes))

        # --- Stale message_ids cleanup guard (optional) ---
        if STALE_PURGE_ENABLED:
            if NET_FREEZE_ACTIVE:
                logger.info("[CLEANUP] Skipped (net-freeze active).")
            else:
                try:
                    stale_guard = load_json("stale_guard.json")
                except Exception:
                    stale_guard = {}
                empty_cycles = int(stale_guard.get("empty_cycles", 0))
                if len(grouped_routes) == 0:
                    empty_cycles += 1
                else:
                    empty_cycles = 0
                stale_guard["empty_cycles"] = empty_cycles
                save_json("stale_guard.json", stale_guard)

                expected_route_keys = set()
                for s in servers:
                    hooks = s.get("webhooks") or [s.get("webhook_url", DEFAULT_WEBHOOK_URL)]
                    merge_key = get_merge_group_key(s)
                    for expected_hook in hooks:
                        rk_expected = route_key(merge_key, expected_hook)
                        expected_route_keys.add(rk_expected)

                do_cleanup = (len(grouped_routes) > 0) or (empty_cycles >= 10)
                if do_cleanup:
                    active_route_keys = set(grouped_routes.keys())
                    protected_keys = active_route_keys.union(expected_route_keys)
                    stale = [rk for rk in list(message_ids.keys()) if rk not in protected_keys]
                    if stale:
                        logger.info("[INFO] Purging stale routes: %s", stale)
                        for rk in stale:
                            msg_id = message_ids.get(rk)
                            try:
                                merge_key, webhook_url = rk.split("|", 1)
                            except ValueError:
                                webhook_url = DEFAULT_WEBHOOK_URL
                            if msg_id:
                                delete_discord_message(msg_id, webhook_url, label=f"stale route {rk}")
                            message_ids.pop(rk, None)
                        save_json("message_ids.json", message_ids)

        # --- Build and send/edit embeds per route ---
        # Always purge obviously invalid stored routes that point to placeholder DEFAULT webhook
        _invalid_routes = [rk for rk in list(message_ids.keys()) if ("|" in rk and _is_placeholder_webhook(rk.split("|",1)[1]))]
        if _invalid_routes:
            logger.info("[CLEANUP] Dropping placeholder-webhook routes from message_ids: %s", _invalid_routes)
            for rk in _invalid_routes:
                message_ids.pop(rk, None)
            save_json("message_ids.json", message_ids)

        if grouped_routes:
            for rk, pairs in grouped_routes.items():
                merge_key, webhook_url = rk.split("|", 1)
                display_label = get_display_group(pairs[0][0])
                embeds = build_grouped_embeds({display_label: pairs}, steam_banner=steam_banner)[display_label]
                if rk in message_ids:
                    edit_discord_message(display_label, message_ids[rk], embeds, webhook_url, rk)
                else:
                    if _is_placeholder_webhook(webhook_url):
                        alert_issue("Default webhook not set", "Cannot create status message: webhook is placeholder or empty.",
                                    {"group": display_label or "(no group)", "webhook": str(webhook_url)[:80]}, key=f"missing:init:{display_label}")
                        continue
                    new_ids = send_initial_messages({display_label: embeds}, {display_label: webhook_url})
                    if display_label in new_ids:
                        message_ids[rk] = new_ids[display_label]
                        save_json("message_ids.json", message_ids)
                        alert_resolve(f"post:init:{display_label}|{webhook_url}")

        # Persist state each loop
        save_json("server_down.json", server_down)
        save_json("has_pinged_down.json", has_pinged_down)

        time.sleep(INTERVAL_SECONDS)