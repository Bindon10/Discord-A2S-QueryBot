# Discord-A2S-QueryBot v2.0.3 — Hot Reload + .bak Diff Cleanup + Webhook Allow-List + Ping Fix

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
import urllib.parse
import re

# === USER CONFIG (edit me) ===
DEBUG_LOG_ENABLED = False
DEFAULT_WEBHOOK_URL = "https://discord.com/api/webhooks/CHANGE_ME"
ALERTS_WEBHOOK = os.getenv("ALERTS_WEBHOOK", "").strip()
INTERVAL_SECONDS = 60
DEFAULT_USER_PING_ID = "<@123456789012345678>"

# Steam backend health gate (optional). If enabled AND `STEAM_API_KEY` is set,
# the bot freezes downtime counters during Steam-wide issues to avoid false alarms.
STEAM_STATUS_CHECK_ENABLED = True
STEAM_API_KEY = "PUT_YOUR_STEAM_WEB_API_KEY_HERE"   # https://steamcommunity.com/dev/apikey
STEAM_STATUS_POLL_SECONDS = 180
IGNORED_STEAM_SERVICE_KEYS = {"IEconItems"}

# Behavior knobs
DOWN_FAIL_THRESHOLD = 3        # consecutive failures before a server is considered down (and pinged)
GROUP_EMBED_LIMIT   = 10       # Discord hard cap per message
EMBED_DESC_LIMIT    = 4096     # Discord hard cap per embed description
STALE_PURGE_ENABLED = False    # if True, purge message_ids for routes no longer present in config
SHOW_PLAYERS_BY_DEFAULT = True # default: show player list in embeds (override per-server with 'show_players')
SHOW_VISIBILITY_BY_DEFAULT = False # default: show visibility line

# Cleanup controls
DELETE_ON_EMPTY_ROUTES = True      # delete route's status message when no servers are up in that route
CLEANUP_REMOVED_ROUTES = True      # delete route's status message if route no longer exists in config
ORPHANS_FILE = "orphans_to_delete.json"  # optional manual cleanup list

# Webhook allow-list (Discord-only)
ALLOWED_WEBHOOK_HOSTS = {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}

# === INTERNAL ===
logger = logging.getLogger("a2sbot")
logger.setLevel(logging.DEBUG)
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_console_handler)
if DEBUG_LOG_ENABLED:
    _file_handler = RotatingFileHandler("debug.log", maxBytes=5 * 1024 * 1024, backupCount=3)
    _file_handler.setLevel(logging.DEBUG)
    _file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(_file_handler)

# HTTP session
SESSION = requests.Session()
try:
    from requests.adapters import HTTPAdapter
    SESSION.mount("https://", HTTPAdapter(pool_connections=8, pool_maxsize=16))
    SESSION.mount("http://", HTTPAdapter(pool_connections=4, pool_maxsize=8))
except Exception:
    pass
SESSION.headers.update({"User-Agent": "Discord-A2S-QueryBot/2.0.3"})

def _sleep_backoff(attempt: int, base: float = 0.75, cap: float = 5.0):
    time.sleep(min(cap, base * (2 ** attempt)) + random.uniform(0, 0.25))

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
            try:
                return json.load(f)
            except Exception:
                return {}
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
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

message_ids = load_json("message_ids.json")
ping_message_ids = load_json("ping_message_ids.json")
server_down = load_json("server_down.json")
has_pinged_down = load_json("has_pinged_down.json")
alerts_state = load_json("alerts_state.json")

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

# Restore prior net-freeze state if present
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

# Migration to route-based keys
if message_ids and any("|" not in k for k in list(message_ids.keys())):
    logger.info("[INIT] Detected legacy message_ids.json; resetting for route-based keys.")
    message_ids = {}
    save_json("message_ids.json", message_ids)

# === Example config ===
CONFIG_FILE = "servers.json"

def create_example_servers_file():
    example_servers = [{
        "name": "⚠️ Example Server — Please Edit servers.json",
        "ip": "0.0.0.0", "port": 27015, "group": "Example Group",
        "restart": True, "restart_hour": "04", "restart_minute": "30",
        "timezone": "America/Edmonton", "emoji": "⚠️", "ping_id": "<@123456789012345678>"
    }]
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

# === ALERTS ===
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

# === Steam Health ===
def _interpret_steam_health(payload) -> bool:
    try:
        result = payload.get("result") or payload.get("data") or payload
        suspicious, ignored = [], []
        services = result.get("services", {}) or {}
        matchmaking = result.get("matchmaking", {}) or {}
        def bad(v): return isinstance(v, str) and v.lower() in ("offline", "critical", "degraded", "delayed")
        for k, v in services.items():
            ((ignored if k in IGNORED_STEAM_SERVICE_KEYS else suspicious)
             .append((f"services.{k}", v))) if bad(v) else None
        for k, v in matchmaking.items():
            suspicious.append((f"matchmaking.{k}", v)) if bad(v) else None
        return len(suspicious) > 0
    except Exception:
        return False

def steam_is_unhealthy() -> bool:
    global _last_steam_check, _last_steam_unhealthy, _last_steam_snapshot
    if not (STEAM_STATUS_CHECK_ENABLED):
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
        if not resp or resp.status_code in (403,) or (resp.status_code and resp.status_code != 200):
            _last_steam_unhealthy = False; _last_steam_snapshot = None; return False
        data = resp.json()
        _last_steam_unhealthy = _interpret_steam_health(data)
        _last_steam_snapshot = data
        return _last_steam_unhealthy
    except Exception:
        _last_steam_check = now; _last_steam_unhealthy = False; _last_steam_snapshot = None
        return False

def _summarize_unhealthy_reasons(snapshot) -> list:
    try:
        result = (snapshot or {}).get("result") or (snapshot or {}).get("data") or (snapshot or {})
        out = []
        def bad(v): return isinstance(v, str) and v.lower() in ("offline", "critical", "degraded", "delayed")
        for k, v in (result.get("services", {}) or {}).items():
            if bad(v) and k not in IGNORED_STEAM_SERVICE_KEYS: out.append(f"services.{k}: {v}")
        for k, v in (result.get("matchmaking", {}) or {}).items():
            if bad(v): out.append(f"matchmaking.{k}: {v}")
        return out
    except Exception:
        return []

def build_steam_banner(steam_unhealthy: bool, last_check_epoch: float, snapshot) -> str:
    if not steam_unhealthy: return ""
    checked = datetime.utcfromtimestamp(last_check_epoch).strftime("%H:%M:%S UTC") if last_check_epoch else "unknown"
    reasons = _summarize_unhealthy_reasons(snapshot)
    reason_text = (", ".join(reasons[:3]) + ("…" if len(reasons) > 3 else "")) if reasons else "unavailable"
    return ("⚠️ **Steam may be down at the moment** — server status may be inaccurate.\n"
            f"(last checked: {checked} • reasons: {reason_text})\n\n")

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

# === Restart parsing ===
def _to_int_or_none(v):
    if v is None: return None
    try: return int(str(v).strip())
    except Exception: return None

def parse_restart_time(server):
    if not server.get("restart", False): return (None, None, None)
    h = _to_int_or_none(server.get("restart_hour")); m = _to_int_or_none(server.get("restart_minute"))
    if h is None or m is None: return (None, None, "missing")
    if not (0 <= h <= 23) or not (0 <= m <= 59): return (None, None, "invalid")
    return (h, m, None)

# === Grouping & utils ===
def get_display_group(server): return (server.get("group") or "").strip()
def get_merge_group_key(server):
    g = (server.get("group") or "").strip()
    return g if g else f"__solo__:{server.get('ip')}:{server.get('port')}"
def _truncate(text: str, limit: int) -> str: return text if len(text) <= limit else text[:limit-1] + "…"
def _is_placeholder_webhook(url: str | None) -> bool: return (not url) or ("CHANGE_ME" in str(url))
def _is_valid_discord_webhook(url: str | None) -> bool:
    if not url: return False
    try:
        u = urllib.parse.urlparse(url)
        return u.scheme == "https" and (u.hostname or "") in ALLOWED_WEBHOOK_HOSTS and (u.path or "").startswith("/api/webhooks/")
    except Exception:
        return False
def _safe_tz(tz: str):
    try: return ZoneInfo(tz)
    except Exception: return ZoneInfo("UTC")
def _san(n: str) -> str:
    for ch in ("`", "*", "_", "~", "|", ">", "@"): n = n.replace(ch, f"\\{ch}")
    return n[:64]

# === Ping target resolution (PING FIX) ===
def resolve_ping_target(server) -> tuple[str | None, dict]:
    """
    Returns (content_mention_str_or_none, allowed_mentions_dict).
    Supports:
      - server["ping_role_id"] (preferred for roles)
      - server["ping_id"] with either <@123> (user) or <@&123> (role) or bare digits
      - DEFAULT_USER_PING_ID fallback
    """
    rid = server.get("ping_role_id")
    if rid:
        rid_str = str(rid).strip()
        return f"<@&{rid_str}>", {"users": [], "roles": [rid_str]}

    raw = (server.get("ping_id") or DEFAULT_USER_PING_ID or "").strip()
    if not raw:
        return None, {"users": [], "roles": []}

    m_role = re.fullmatch(r"<@&(\d+)>", raw)
    if m_role:
        rid = m_role.group(1)
        return f"<@&{rid}>", {"users": [], "roles": [rid]}

    m_user = re.fullmatch(r"<@!?(\d+)>", raw)
    if m_user:
        uid = m_user.group(1)
        return f"<@{uid}>", {"users": [uid], "roles": []}

    digits = "".join(ch for ch in raw if ch.isdigit())
    if digits:
        return f"<@{digits}>", {"users": [digits], "roles": []}

    return None, {"users": [], "roles": []}

# === Discord embed building ===
def build_grouped_embeds(grouped_servers, steam_banner: str = ""):
    group_embeds = {}
    for group_name, pairs in grouped_servers.items():
        embeds = []
        for server, stats in pairs:
            vis_enabled = bool(server.get("show_visibility", SHOW_VISIBILITY_BY_DEFAULT))
            vis_line = ""
            if vis_enabled and (stats.get("password_protected") is not None):
                vis_line = ("\n🔐 Passworded" if bool(stats.get("password_protected")) else "\n🔓 Public")

            header = (f"**{stats['name']}**\n\n"
                      f"📜 Map: `{stats['map']}`\n"
                      f"👥 Players: `{stats['players']} / {stats['max_players']}`" + vis_line)

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
                    logger.warning("[WARN] Restart enabled but time not set for '%s'.", server.get("name","?"))
                    body_lines.append("⚠️ Restart time not configured — set restart_hour and restart_minute in servers.json")
                else:
                    logger.warning("[WARN] Invalid restart time for '%s'.", server.get("name","?"))
                    body_lines.append("⚠️ Restart time invalid — use hour 0–23 and minute 0–59")
            body = ("\n\n" + "\n".join(body_lines)) if body_lines else ""

            show_players = bool(server.get("show_players", SHOW_PLAYERS_BY_DEFAULT))
            players_block = None
            if show_players:
                if stats["player_names"]:
                    names = []
                    for n in stats["player_names"][: stats["max_players"]]:
                        names.append(f"- {_san(n)}")
                        test_desc = (steam_banner or "") + header + body + "\n\n**Current Players:**\n" + "\n".join(names)
                        if len(test_desc) > EMBED_DESC_LIMIT:
                            names.pop(); names.append("…"); break
                    players_block = "\n".join(names)
                else:
                    players_block = "*No players online*"

            parts = []
            banner = (steam_banner or "").strip()
            if banner: parts.append(banner)
            parts.append(header + body)
            if show_players: parts.append("**Current Players:**\n" + players_block)
            desc = _truncate("\n\n".join(parts), EMBED_DESC_LIMIT)

            icon = server.get("icon_url") or server.get("emoji")
            title_text = f" {group_name} — {server['name']}" if group_name else f" {server['name']}"
            embed = {
                "title": title_text,
                "description": desc,
                "color": 0x7F00FF,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "A2S v2.0.3 • Updated every 60s"},
            }
            if server.get("ip") == "0.0.0.0": embed["color"] = 0xFFCC00
            if icon:
                if isinstance(icon, str) and icon.startswith("http"):
                    embed["thumbnail"] = {"url": icon}
                else:
                    embed["title"] = f"{icon} {embed['title']}"
            embeds.append(embed)

        if len(embeds) > GROUP_EMBED_LIMIT:
            alert_issue("Embed limit exceeded", "Trimming to 10 embeds for this route.",
                        {"group": group_name or "(no group)", "trimmed": len(embeds) - GROUP_EMBED_LIMIT},
                        key=f"embedlimit:{group_name or 'nogroup'}")
            embeds = embeds[:GROUP_EMBED_LIMIT]

        group_embeds[group_name] = embeds
    return group_embeds

def send_initial_messages(grouped_embeds, group_webhooks):
    new_ids = {}
    for group, embeds in grouped_embeds.items():
        webhook = group_webhooks.get(group, DEFAULT_WEBHOOK_URL)
        if _is_placeholder_webhook(webhook) or not _is_valid_discord_webhook(webhook):
            alert_issue("No/invalid webhook for this route",
                        "Route has no valid Discord webhook (or DEFAULT is placeholder).",
                        {"group": group, "webhook": str(webhook)[:120]}, key=f"missing:init:{group}")
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
    if _is_placeholder_webhook(webhook_url) or not _is_valid_discord_webhook(webhook_url):
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

def delete_route_message(rk: str):
    try:
        if "|" not in rk: return
        merge_key, webhook_url = rk.split("|", 1)
        msg_id = message_ids.get(rk)
        if not msg_id:
            message_ids.pop(rk, None); save_json("message_ids.json", message_ids); return
        if _is_placeholder_webhook(webhook_url) or not _is_valid_discord_webhook(webhook_url):
            message_ids.pop(rk, None); save_json("message_ids.json", message_ids); return
        resp, err = discord_request("DELETE", f"{webhook_url}/messages/{msg_id}", timeout=15)
        message_ids.pop(rk, None); save_json("message_ids.json", message_ids)
        if resp and resp.status_code in (200, 204, 404):
            logger.info("[CLEANUP] Deleted route message for %s (status %s)", rk, getattr(resp, "status_code", "?"))
            alert_resolve(f"post:init:{merge_key}|{webhook_url}"); alert_resolve(f"edit:fail:{rk}")
        else:
            errtxt = err or (f"{getattr(resp,'status_code','???')} - {getattr(resp,'text','')[:180]}")
            logger.warning("[WARN] Cleanup delete for %s returned: %s", rk, errtxt)
    except Exception as e:
        logger.warning("[WARN] Exception during route message delete for %s: %s", rk, e)

def post_ping(server):
    """Post a down ping to the server's webhook (robust mention + allow-list)."""
    # Safety: never ping for servers no longer in current config
    try:
        if not any((s.get('ip'), s.get('port')) == (server.get('ip'), server.get('port')) for s in servers):
            logger.info("[PING] Skipping ping for removed server %s:%s", server.get('ip'), server.get('port'))
            return None
    except Exception:
        pass

    mention, allowed = resolve_ping_target(server)
    webhook = server.get("webhook_url", DEFAULT_WEBHOOK_URL)
    if _is_placeholder_webhook(webhook) or not _is_valid_discord_webhook(webhook):
        alert_issue("Missing/invalid webhook for ping",
                    "Down ping could not be delivered (no/invalid webhook).",
                    {"server": server.get("name")},
                    key=f"missing:ping:{server.get('name')}:{server.get('ip')}:{server.get('port')}")
        return None

    content = (f"{mention} ⚠️ The `{server['name']}` server appears to be down!"
               if mention else f"⚠️ The `{server['name']}` server appears to be down!")
    payload = {"content": content, "allowed_mentions": allowed}
    logger.info("[PING] Posting ping for %s:%s (allowed=%s, content=%r)",
                server.get("ip"), server.get("port"), allowed, content)

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

# === Config sanity ===
def validate_config(servers):
    seen = {}; dups = []
    for s in servers:
        k = f"{s.get('ip')}:{s.get('port')}"; seen[k] = seen.get(k, 0) + 1
    for k, c in seen.items():
        if c > 1: dups.append((k, c))
    if dups:
        alert_issue("Duplicate servers in config", "Multiple entries share the same ip:port.",
                    {"duplicates": ", ".join([f"{k}×{c}" for k, c in dups])}, key="config:dups")
    for s in servers:
        wh = s.get("webhook_url", DEFAULT_WEBHOOK_URL)
        if len((s.get("name") or "")) > 100: logger.warning("[WARN] Long server name (>100)")
        if len((s.get("group") or "")) > 100: logger.warning("[WARN] Long group name (>100)")
        if _is_placeholder_webhook(wh) or not _is_valid_discord_webhook(wh):
            alert_issue("Invalid webhook in config", "A server has a missing/invalid Discord webhook.",
                        {"server": s.get("name","?"), "webhook": str(wh)[:120]}, key=f"config:invalid_webhook:{s.get('name','?')}")

# === Route computations ===
def make_server_key(ip, port): return f"{ip}:{port}"
def route_key(display_key, webhook): return f"{display_key}|{webhook}"
def compute_expected_route_keys(servers):
    expected = set()
    for s in servers:
        expected.add(route_key(get_merge_group_key(s), s.get("webhook_url", DEFAULT_WEBHOOK_URL)))
    return expected

# --- BAK-assisted cleanup helpers + hot-reload helpers ---
def load_previous_config_bak(path: str) -> list:
    bak = f"{path}.bak"
    if not os.path.exists(bak): return []
    try:
        with open(bak, "r", encoding="utf-8") as f:
            data = json.load(f); return data if isinstance(data, list) else []
    except Exception: return []

def server_uid(s: dict) -> str: return f"{s.get('ip')}:{s.get('port')}"
def route_of(server: dict) -> str:
    return route_key(get_merge_group_key(server), server.get("webhook_url", DEFAULT_WEBHOOK_URL))
def compute_expected_route_keys_from_list(servers_list: list) -> set:
    exp = set()
    for s in (servers_list or []): exp.add(route_of(s))
    return exp

def _clear_ping_for_uid(uid: str):
    try:
        if uid in ping_message_ids:
            deleted = False
            for rk in list(message_ids.keys()):
                try: webhook_url = rk.split("|", 1)[1]
                except Exception: continue
                if _is_placeholder_webhook(webhook_url) or not _is_valid_discord_webhook(webhook_url): continue
                try:
                    discord_request("DELETE", f"{webhook_url}/messages/{ping_message_ids[uid]}", timeout=10)
                    deleted = True; break
                except Exception: pass
            ping_message_ids.pop(uid, None); save_json("ping_message_ids.json", ping_message_ids)
            if deleted: logger.info("[PING] Cleared lingering ping message for removed %s", uid)
    except Exception as e:
        logger.warning("[PING] Failed clearing ping for %s: %s", uid, e)

def bak_compare_cleanup(previous_servers: list, current_servers: list):
    """Delete messages for removed/moved routes and clear state for removed servers (no ping)."""
    if NET_FREEZE_ACTIVE or _last_steam_unhealthy:
        logger.info("[BAK] Skipping bak-compare cleanup (net-freeze or Steam unhealthy)."); return

    prev_routes = compute_expected_route_keys_from_list(previous_servers)
    curr_routes = compute_expected_route_keys_from_list(current_servers)
    removed_routes = [rk for rk in prev_routes if rk not in curr_routes]
    if removed_routes:
        logger.info("[BAK] Deleting messages for %d routes removed since last config.", len(removed_routes))
        for rk in removed_routes:
            if rk in message_ids: delete_route_message(rk)

    prev_uids = {server_uid(s) for s in previous_servers or []}
    curr_uids = {server_uid(s) for s in current_servers or []}
    removed_uids = prev_uids - curr_uids
    if removed_uids:
        for uid in removed_uids:
            server_down.pop(uid, None)
            has_pinged_down.pop(uid, None)
            _clear_ping_for_uid(uid)
        save_json("server_down.json", server_down)
        save_json("has_pinged_down.json", has_pinged_down)
        save_json("ping_message_ids.json", ping_message_ids)

# Hot-reload helpers
def _deepcopy_jsonable(obj):
    try: return json.loads(json.dumps(obj))
    except Exception: return obj

def _rebuild_downtime_counter(existing_dc: dict, new_servers: list) -> dict:
    """Keep counters for still-present servers; start at 0 for brand-new ones."""
    new_dc = {}
    for s in new_servers or []:
        uid = f"{s.get('ip')}:{s.get('port')}"
        new_dc[uid] = int(existing_dc.get(uid, 0))
    return new_dc

def _init_per_server_state(new_servers: list):
    """Ensure state dicts have entries for new servers (idempotent)."""
    changed = False
    for s in new_servers or []:
        uid = f"{s.get('ip')}:{s.get('port')}"
        if uid not in server_down:
            server_down[uid] = False; changed = True
        if uid not in has_pinged_down:
            has_pinged_down[uid] = False; changed = True
    if changed:
        save_json("server_down.json", server_down)
        save_json("has_pinged_down.json", has_pinged_down)

# Manual orphan cleanup
def cleanup_orphans_file_once():
    data = load_json(ORPHANS_FILE)
    if not data: return
    kept = []
    if not isinstance(data, list):
        logger.warning("[ORPHAN] %s is not a list; ignoring.", ORPHANS_FILE); return
    for entry in data:
        wh = (entry.get("webhook_url") or "").strip()
        mid = str(entry.get("message_id") or "").strip()
        if not wh or not mid or _is_placeholder_webhook(wh) or not _is_valid_discord_webhook(wh): continue
        try:
            resp, err = discord_request("DELETE", f"{wh}/messages/{mid}", timeout=15)
            if resp and resp.status_code in (200, 204, 404):
                logger.info("[ORPHAN] Deleted orphan message %s via webhook", mid)
            else:
                kept.append(entry)
                logger.warning("[ORPHAN] Delete failed (%s). Keeping for retry.", getattr(resp, "status_code", err))
        except Exception as e:
            kept.append(entry); logger.warning("[ORPHAN] Exception deleting %s: %s", mid, e)
    save_json(ORPHANS_FILE, kept)

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
    cleanup_orphans_file_once()

    # .bak compare at startup + refresh snapshot
    prev_servers = load_previous_config_bak(CONFIG_FILE)
    try:
        if prev_servers: bak_compare_cleanup(prev_servers, servers)
        else: logger.info("[BAK] No servers.json.bak found or unreadable; skipping bak compare.")
    except Exception as e:
        logger.warning("[BAK] Exception during bak compare: %s", e)
    try:
        save_json(f"{CONFIG_FILE}.bak", servers)
        logger.info("[BAK] Snapshot refreshed -> %s.bak", CONFIG_FILE)
    except Exception as e:
        logger.warning("[BAK] Failed to refresh bak snapshot: %s", e)

    # Track config changes
    try: last_mtime = os.path.getmtime(CONFIG_FILE)
    except Exception: last_mtime = None
    prev_servers_snapshot = _deepcopy_jsonable(servers)

    # Initialize per-server state & counters (in-memory)
    downtime_counter = {}
    for s in servers:
        key = make_server_key(s["ip"], s["port"])
        server_down.setdefault(key, False)
        has_pinged_down.setdefault(key, False)
        downtime_counter[key] = 0

    # Steam health gate enable/disable
    if STEAM_STATUS_CHECK_ENABLED:
        if (not STEAM_API_KEY) or (STEAM_API_KEY.strip() == "") or (STEAM_API_KEY == "PUT_YOUR_STEAM_WEB_API_KEY_HERE"):
            alert_issue("Steam API key missing", "Skipping Steam backend health checks until configured.",
                        {"env": "STEAM_API_KEY"}, key="config:steam_api_key_missing")
            STEAM_HEALTH_ENABLED = False
        else:
            STEAM_HEALTH_ENABLED = True
    else:
        STEAM_HEALTH_ENABLED = False
    logger.info("[Steam Health] %s", "Enabled" if STEAM_HEALTH_ENABLED else "Disabled")

    # Main loop
    while True:
        # --- CONFIG HOT-RELOAD (only if servers.json changed) ---
        try: current_mtime = os.path.getmtime(CONFIG_FILE)
        except Exception: current_mtime = last_mtime

        if current_mtime != last_mtime:
            logger.info("[CONFIG] Detected servers.json change -> reloading")
            new_servers, example_mode = load_servers_and_detect_example_mode()
            validate_config(new_servers)
            try:
                bak_compare_cleanup(prev_servers_snapshot, new_servers)
            except Exception as e:
                logger.warning("[BAK] Exception during bak compare on reload: %s", e)
            try:
                save_json(f"{CONFIG_FILE}.bak", new_servers)
                logger.info("[BAK] Snapshot refreshed -> %s.bak", CONFIG_FILE)
            except Exception as e:
                logger.warning("[BAK] Failed to refresh bak snapshot: %s", e)
            _init_per_server_state(new_servers)
            downtime_counter = _rebuild_downtime_counter(downtime_counter, new_servers)
            servers = new_servers
            prev_servers_snapshot = _deepcopy_jsonable(new_servers)
            last_mtime = current_mtime
            logger.info("[CONFIG] Reloaded %d server(s).", len(servers))

        up_count = 0
        down_count = 0

        # --- network health guard ---
        if net_probe_ok():
            _net_ok_streak += 1; _net_fail_streak = 0
            if NET_FREEZE_ACTIVE and _net_ok_streak >= 2:
                NET_FREEZE_ACTIVE = False
                dur = None
                try: dur = int(time.time() - (NET_OUTAGE_STARTED_AT or time.time()))
                except Exception: pass
                NET_OUTAGE_STARTED_AT = None; _save_net_state()
                alert_issue("Network outage recovered", f"Host connectivity restored after ~{dur}s.",
                            {"duration_s": dur}, key="net:outage:recovered")
                alert_resolve("net:outage")
                logger.info("[NET] Recovered: leaving net-freeze (updates resume).")
        else:
            _net_fail_streak += 1; _net_ok_streak = 0
            if not NET_FREEZE_ACTIVE and _net_fail_streak >= 3:
                NET_FREEZE_ACTIVE = True; NET_OUTAGE_STARTED_AT = time.time(); _save_net_state()
                try:
                    with open("net_outages.jsonl", "a", encoding="utf-8") as f:
                        f.write(json.dumps({"started_at": NET_OUTAGE_STARTED_AT}) + "\n")
                except Exception: pass
                alert_issue("Network outage suspected",
                            "Host appears offline to Discord/DNS. Freezing counters, pings, and cleanup until connectivity recovers.",
                            {"fails": _net_fail_streak}, key="net:outage")
                logger.info("[NET] Entered net-freeze: suppressing pings, freezing counters, skipping cleanup.")

        # --- Steam health ---
        prev_unhealthy = _last_steam_unhealthy
        steam_unhealthy = steam_is_unhealthy() if (STEAM_STATUS_CHECK_ENABLED and STEAM_HEALTH_ENABLED) else False
        if not (STEAM_STATUS_CHECK_ENABLED and STEAM_HEALTH_ENABLED):
            _last_steam_unhealthy = False
        if steam_unhealthy and not prev_unhealthy:
            logger.info("[INFO] Entered Steam outage freeze: counters reset to 0 (non-down servers) & frozen until recovery.")
            for s in servers:
                key = make_server_key(s["ip"], s["port"])
                if not server_down.get(key, False):
                    downtime_counter[key] = 0
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
                server_hook = s.get("webhook_url", DEFAULT_WEBHOOK_URL)
                merge_key = get_merge_group_key(s)
                rk = route_key(merge_key, server_hook)

                grouped_routes.setdefault(rk, []).append((s, stats))

                up_count += 1
                logger.info("[%s] %s is up: %s on %s", datetime.now(), name, stats['players'], stats['map'])

                # Recover logic: clear down flags and delete any lingering ping
                if server_down.get(key, False):
                    server_down[key] = False
                    downtime_counter[key] = 0
                    has_pinged_down[key] = False
                    if key in ping_message_ids:
                        try:
                            delete_ping_url = s.get("webhook_url", DEFAULT_WEBHOOK_URL)
                            if delete_ping_url and not _is_placeholder_webhook(delete_ping_url) and _is_valid_discord_webhook(delete_ping_url):
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
                    # Freeze counters during global issues
                    continue

                # Increment consecutive-failure counter
                prev_cnt = int(downtime_counter.get(key, 0))
                cur = prev_cnt + 1
                downtime_counter[key] = cur

                # Mark as down once threshold reached (idempotent)
                if cur >= DOWN_FAIL_THRESHOLD and not server_down.get(key, False):
                    server_down[key] = True
                    save_json("server_down.json", server_down)

                # Send a single ping exactly when we cross the threshold
                if (cur == DOWN_FAIL_THRESHOLD) and not has_pinged_down.get(key, False):
                    pid = post_ping(s)
                    if pid:
                        ping_message_ids[key] = pid
                        save_json("ping_message_ids.json", ping_message_ids)
                    has_pinged_down[key] = True
                    save_json("has_pinged_down.json", has_pinged_down)

        logger.info("[CYCLE] Up: %s  Down: %s  Routes: %s", up_count, down_count, len(grouped_routes))

        # --- Route message deletion for removed/empty routes ---
        if (not NET_FREEZE_ACTIVE) and (not _last_steam_unhealthy):
            try:
                stored_routes = set(message_ids.keys())

                if CLEANUP_REMOVED_ROUTES:
                    expected_route_keys = compute_expected_route_keys(servers)
                    removed_routes = [rk for rk in stored_routes if rk not in expected_route_keys]
                    if removed_routes:
                        logger.info("[CLEANUP] Deleting messages for %d removed routes", len(removed_routes))
                        for rk in removed_routes:
                            delete_route_message(rk)
                        stored_routes = set(message_ids.keys())

                if DELETE_ON_EMPTY_ROUTES:
                    current_active_routes = set(grouped_routes.keys())
                    empty_routes = [rk for rk in stored_routes if rk not in current_active_routes]
                    if empty_routes:
                        logger.info("[CLEANUP] Deleting messages for %d empty routes (no up servers)", len(empty_routes))
                        for rk in empty_routes:
                            delete_route_message(rk)
            except Exception as e:
                logger.warning("[WARN] Failed route cleanup: %s", e)

        # --- Optional stale-id cleanup ---
        if STALE_PURGE_ENABLED and (not NET_FREEZE_ACTIVE):
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

            expected_route_keys = compute_expected_route_keys(servers)
            do_cleanup = (len(grouped_routes) > 0) or (empty_cycles >= 10)
            if do_cleanup:
                active_route_keys = set(grouped_routes.keys())
                protected_keys = active_route_keys.union(expected_route_keys)
                stale = [rk for rk in list(message_ids.keys()) if rk not in protected_keys]
                if stale:
                    logger.info("[INFO] Removing stale message IDs: %s", stale)
                    for rk in stale:
                        message_ids.pop(rk, None)
                    save_json("message_ids.json", message_ids)

        # --- Invalid route cache cleanup (placeholder/invalid webhooks) ---
        _invalid_routes = [
            rk for rk in list(message_ids.keys())
            if ("|" in rk and (
                _is_placeholder_webhook(rk.split("|", 1)[1]) or
                not _is_valid_discord_webhook(rk.split("|", 1)[1])
            ))
        ]
        if _invalid_routes:
            logger.info("[CLEANUP] Dropping invalid-webhook routes from message_ids: %s", _invalid_routes)
            for rk in _invalid_routes:
                message_ids.pop(rk, None)
            save_json("message_ids.json", message_ids)

        # --- Build & send/edit embeds ---
        if grouped_routes:
            for rk, pairs in grouped_routes.items():
                merge_key, webhook_url = rk.split("|", 1)
                display_label = get_display_group(pairs[0][0])
                embeds = build_grouped_embeds({display_label: pairs}, steam_banner=steam_banner)[display_label]
                if rk in message_ids:
                    edit_discord_message(display_label, message_ids[rk], embeds, webhook_url, rk)
                else:
                    if _is_placeholder_webhook(webhook_url) or not _is_valid_discord_webhook(webhook_url):
                        alert_issue("Default webhook not set/invalid", "Cannot create status message.",
                                    {"group": display_label or "(no group)", "webhook": str(webhook_url)[:120]},
                                    key=f"missing:init:{display_label}")
                        continue
                    new_ids = send_initial_messages({display_label: embeds}, {display_label: webhook_url})
                    if display_label in new_ids:
                        message_ids[rk] = new_ids[display_label]
                        save_json("message_ids.json", message_ids)
                        alert_resolve(f"post:init:{display_label}|{webhook_url}")

        time.sleep(INTERVAL_SECONDS)
