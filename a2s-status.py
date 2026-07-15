# ============================================================
# Discord-A2S-QueryBot
# Version: v2.3.4
# ============================================================


import a2s
import requests
import time
import os
import re
import json
import random
import signal
import sys
import shutil
from datetime import datetime
from datetime import timezone
from zoneinfo import ZoneInfo
import socket
import logging
import threading
from collections import deque
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
SHOW_PLAYERS_BY_DEFAULT = True # default: show player list in embeds (override per-server with 'show_players')
SHOW_VISIBILITY_BY_DEFAULT = False # default: show visibility line (Public/Passworded) per server; override with 'show_visibility'
GHOST_PLAYER_FIX_BY_DEFAULT = False # treat a nonzero player count with an EMPTY name list as 0 players (A2S ghost-player quirk); override per server with 'ghost_player_fix'
PLAYER_LIST_LIMIT   = 20       # max number of player names to show in embeds

# === Web UI (optional) ===
WEB_UI_ENABLED  = True          # set False to disable the embedded web UI
WEB_UI_HOST     = "0.0.0.0"     # bind address (LAN-exposed by default — set WEBUI_PASSWORD and/or add users!)
WEB_UI_PORT     = 8500
WEB_UI_PASSWORD = os.getenv("WEBUI_PASSWORD", "ThisIsADefaultPasswordChangeMe").strip()  # break-glass admin login; blank + no users = auth disabled (keep it on localhost then)
WEB_UI_PUBLIC_URL = os.getenv("WEBUI_PUBLIC_URL", "").strip()  # base URL browsers use (e.g. "https://status.example.com") — needed for Steam sign-in behind a proxy; blank = auto-detect

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

# In-memory ring buffer of recent log lines (surfaced in the web UI)
LOG_BUFFER = deque(maxlen=400)

class _RingBufferHandler(logging.Handler):
    def emit(self, record):
        try:
            LOG_BUFFER.append(self.format(record))
        except Exception:
            pass

_ring_handler = _RingBufferHandler()
_ring_handler.setLevel(logging.INFO)
_ring_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_ring_handler)

# Shared state for the web UI (read by the Flask thread, written by the main loop)
WEB_STATE = {"servers": [], "last_cycle": None, "up": 0, "down": 0,
             "steam_unhealthy": False, "net_freeze": False, "example_mode": False,
             "started_at": time.time()}
FORCE_REFRESH = threading.Event()

# === HTTP Session & helpers ===
SESSION = requests.Session()
try:
    from requests.adapters import HTTPAdapter
    SESSION.mount("https://", HTTPAdapter(pool_connections=8, pool_maxsize=16))
    SESSION.mount("http://", HTTPAdapter(pool_connections=4, pool_maxsize=8))
except Exception:
    pass
SESSION.headers.update({"User-Agent": "Discord-A2S-QueryBot/2.3.4"})

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
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            # Empty or corrupt state file (hand-edited, or truncated by a crash):
            # back it up and start fresh instead of killing the bot at startup.
            logger.warning("[STATE] %s is unreadable (%s) — backing it up as %s.corrupt and starting fresh.",
                           filename, e, filename)
            try:
                shutil.copyfile(filename, filename + ".corrupt")
            except Exception:
                pass
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
        # Fallback best-effort
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

message_ids = load_json("message_ids.json")
ping_message_ids = load_json("ping_message_ids.json")
server_down = load_json("server_down.json")
has_pinged_down = load_json("has_pinged_down.json")
alerts_state = load_json("alerts_state.json")
ping_routes = load_json("ping_routes.json")
# Startup reconciliation: remove orphaned routes with no corresponding message id
try:
    _orphans = [k for k in list(ping_routes.keys()) if k not in ping_message_ids]
    if _orphans:
        for _k in _orphans:
            ping_routes.pop(_k, None)
        save_json("ping_routes.json", ping_routes)
except Exception:
    pass

# NOTE (v2.1.0): the old "startup backfill" block that lived here was removed.
# It called functions defined later in the file, always raised NameError, and the
# error was silently swallowed. The runtime backfill inside the main loop covers it.



# === Persistent downtime counters (opt-in per server) ===
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DOWNTIME_COUNTERS_PATH = os.environ.get("DOWNTIME_COUNTERS_PATH", os.path.join(_BASE_DIR, "downtime_counters.json"))
_downtime_counters = {}

def _load_downtime_counters():
    global _downtime_counters
    try:
        if os.path.exists(_DOWNTIME_COUNTERS_PATH):
            with open(_DOWNTIME_COUNTERS_PATH, "r", encoding="utf-8") as f:
                _downtime_counters = json.load(f) or {}
        else:
            _downtime_counters = {}
    except Exception:
        _downtime_counters = {}

def _save_downtime_counters():
    os.makedirs(os.path.dirname(_DOWNTIME_COUNTERS_PATH), exist_ok=True)
    try:
        tmp = _DOWNTIME_COUNTERS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_downtime_counters, f, indent=2, sort_keys=True)
        os.replace(tmp, _DOWNTIME_COUNTERS_PATH)
    except Exception:
        pass

def _srv_key(ip, port):
    return f"{ip}:{port}"

def _inc_downtime_counter_for(server):
    try:
        if server.get("downtime_counter") is True:
            key = _srv_key(server.get("ip"), server.get("port"))
            _downtime_counters[key] = int(_downtime_counters.get(key, 0)) + 1
            _save_downtime_counters()
    except Exception:
        pass

def get_downtime_count_for(server):
    key = _srv_key(server.get("ip"), server.get("port"))
    try:
        return int(_downtime_counters.get(key, 0))
    except Exception:
        return 0

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

_LAST_GOOD_SERVERS = None

def load_servers_and_detect_example_mode():
    global _LAST_GOOD_SERVERS
    if not os.path.exists(CONFIG_FILE):
        create_example_servers_file()
        return [], True
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            servers = json.load(f)
    except Exception as e:
        # servers.json is hot-reloaded every cycle — a bad edit must not crash the
        # bot mid-run. Keep the last good config and raise an alert instead.
        msg = f"servers.json is unreadable ({e})."
        logger.error("[ERROR] %s %s", msg,
                     "Keeping last good config this cycle." if _LAST_GOOD_SERVERS is not None else "No previous config — pings disabled for safety.")
        alert_issue("Invalid servers.json", msg, key="config:unreadable")
        if _LAST_GOOD_SERVERS is not None:
            return _LAST_GOOD_SERVERS, False
        return [], True
    if not isinstance(servers, list):
        msg = "servers.json must be a JSON array. Pings disabled for safety."
        logger.error("[ERROR] %s", msg)
        alert_issue("Invalid servers.json shape", msg, {"type": type(servers).__name__})
        return [], True
    if len(servers) > 0 and all(s.get("ip") == "0.0.0.0" for s in servers):
        logger.info("[INIT] Detected example servers.json — edit this file and restart to enable pings.")
        return servers, True
    _LAST_GOOD_SERVERS = servers
    alert_resolve("config:unreadable")
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
    checked = datetime.fromtimestamp(last_check_epoch, timezone.utc).strftime("%H:%M:%S UTC") if last_check_epoch else "unknown"
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
    cut = text[: max(0, limit - 1)]
    # Prefer cutting at a line boundary so we never slice through **bold** or
    # `code` spans — a mid-span cut leaves unbalanced markdown that garbles
    # everything rendered after it.
    nl = cut.rfind("\n")
    if nl > limit // 2:
        cut = cut[:nl]
    return cut + "…"

def _is_placeholder_webhook(url: str | None) -> bool:
    return (not url) or ("CHANGE_ME" in str(url))

def _safe_tz(tz: str):
    try:
        return ZoneInfo(tz)
    except Exception:
        return ZoneInfo("UTC")

def _san(n: str, limit: int = 64) -> str:
    # escape simple markdown and trim very long names
    n = str(n)
    for ch in ("`", "*", "_", "~", "|", ">"):
        n = n.replace(ch, f"\\{ch}")
    return n[:limit]

UNREACHABLE_MAP = "🟥 Temporarily unreachable"

def _san_code(s) -> str:
    # sanitize text placed inside inline `code` spans — a backtick would break the span
    return str(s).replace("`", "'")[:100]

_MENTION_ID_RE = re.compile(r"^<@([!&]?)(\d{5,20})>$")

def _fmt_user_ref(v) -> str:
    """Owner/admin values: raw user IDs and <@id>/<@!id> become user mentions;
    <@&id> and the '&id' shorthand become ROLE mentions (kept distinct — a role
    rebuilt as <@id> would never resolve). Anything else is plain text,
    markdown-sanitized. Never _san() a mention — escaping '>' breaks it."""
    s = str(v or "").strip()
    m = _MENTION_ID_RE.match(s)
    if m:
        return f"<@&{m.group(2)}>" if m.group(1) == "&" else f"<@{m.group(2)}>"
    if s.startswith("&") and s[1:].isdigit() and 5 <= len(s) - 1 <= 20:
        return f"<@&{s[1:]}>"
    if s.isdigit() and 5 <= len(s) <= 20:
        return f"<@{s}>"
    return _san(s, 100)



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

                # Ghost player fix: some A2S servers report a phantom player with an
                # empty name list while nobody is connected. If enabled, show 0.
                _pshown = stats.get('players', 0)
                if not stats.get('player_names') and bool(server.get('ghost_player_fix', GHOST_PLAYER_FIX_BY_DEFAULT)):
                    _pshown = 0
                display_name = stats.get('queried_name') if SHOW_QUERIED_NAME_IN_HEADER and stats.get('queried_name') else server['name']
                _emj = server.get("emoji")
                _pfx = f"{_emj} " if _emj else ""
                header = f"**{_pfx}{_san(display_name, 100)}**\n\n"
                
                # NEW — owner/admin field
                owner = server.get("owner")
                if owner:
                    header += f"🛡️ Admin: {_fmt_user_ref(owner)}\n"
                
                header += (
                    f"📜 Map: `{_san_code(stats['map'])}`\n"
                    f"👥 Players: `{_pshown} / {stats['max_players']}`"
                    + vis_line
                    + (
                        f"\n❌ Downtime Counter: {get_downtime_count_for(server)}"
                        if server.get("downtime_counter") is True
                        else ""
                    )
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
                if stats.get("player_names"):
                    players_block = "\n".join(f"- {_san(p)}" for p in stats["player_names"][:PLAYER_LIST_LIMIT])
                    if len(stats["player_names"]) > PLAYER_LIST_LIMIT:
                        players_block += "\n…"
                elif _pshown > 0:
                    players_block = f"{_pshown} player(s) online (names unavailable)"
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
            # Prepend the banner BEFORE truncation — adding it after could push the
            # description past Discord's 4096 limit and make every edit fail (400).
            if steam_banner:
                combined_desc = steam_banner + combined_desc
            combined_desc = _truncate(combined_desc, EMBED_DESC_LIMIT)

            _g_emoji = _group_emoji(group_name)
            embed = {
                "title": f"{_g_emoji} {group_name}" if _g_emoji else group_name,
                "description": combined_desc,
                "color": 0x7F00FF,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": f"Updated every {INTERVAL_SECONDS} seconds"},
            }

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

                _pshown = stats.get('players', 0)
                if not stats.get('player_names') and bool(server.get('ghost_player_fix', GHOST_PLAYER_FIX_BY_DEFAULT)):
                    _pshown = 0
                header = ""
                if SHOW_QUERIED_NAME_IN_HEADER and stats.get('queried_name'):
                    header = f"**{_san(stats['queried_name'], 100)}**\n\n"
                owner = server.get("owner")
                if owner:
                    header += f"🛡️ Admin: {_fmt_user_ref(owner)}\n"
                header += (
                    f"📜 Map: `{_san_code(stats['map'])}`\n"
                    f"👥 Players: `{_pshown} / {stats['max_players']}`" + vis_line + (f"\n❌ Downtime Counter: {get_downtime_count_for(server)}" if server.get("downtime_counter") is True else "")
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
                if stats.get("player_names"):
                    players_block = "\n".join(f"- {_san(p)}" for p in stats["player_names"][:PLAYER_LIST_LIMIT])
                    if len(stats["player_names"]) > PLAYER_LIST_LIMIT:
                        players_block += "\n…"
                elif _pshown > 0:
                    players_block = f"{_pshown} player(s) online (names unavailable)"
                else:
                    players_block = "No players online"

                parts = [header]
                if body_lines:
                    parts.append("\n".join(body_lines))
                if show_players:
                    parts.append("**Current Players:**\n" + players_block)
                desc = "\n\n".join(parts)
                if steam_banner:
                    desc = steam_banner + desc
                desc = _truncate(desc, EMBED_DESC_LIMIT)

                icon = server.get("icon_url") or server.get("emoji")
                title_text = (server['name'] if not (SHOW_QUERIED_NAME_IN_HEADER and stats.get('queried_name')) else stats['queried_name'])

                embed = {
                    "title": title_text,
                    "description": desc,
                    "color": 0x7F00FF,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "footer": {"text": f"Updated every {INTERVAL_SECONDS} seconds"},
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


def selftest_ping(server):
    """Send a one-off ping to validate role/user mentions and webhook routing."""
    try:
        webhook = _server_primary_webhook(server)
    except Exception:
        webhook = server.get("webhook_url") or DEFAULT_WEBHOOK_URL

    if _is_placeholder_webhook(webhook):
        logger.error("[SELFTEST] Missing/placeholder webhook for %s", server.get("name"))
        return False

    allowed = {"parse": [], "users": [], "roles": []}
    mention = None

    role_id = server.get("ping_role_id")
    if role_id:
        rid = re.sub(r"\D", "", str(role_id))  # sanitize: keep digits only
        mention = f"<@&{rid}>" if rid else None
        allowed["roles"] = [rid] if rid else []
    else:
        ping_id = server.get("ping_id", DEFAULT_USER_PING_ID)
        if ping_id:
            digits = "".join(ch for ch in str(ping_id) if ch.isdigit())
            if digits:
                mention = f"<@{digits}>"
                allowed["users"] = [digits]

    content = (f"{mention} ✅ SELFTEST: role/user mention delivery check for `{server['name']}`"
               if mention else f"✅ SELFTEST: basic message for `{server['name']}` (no mention configured)")
    payload = {"content": content, "allowed_mentions": allowed}

    resp, err = discord_request("POST", webhook + "?wait=true", json_payload=payload, timeout=20)
    if resp and resp.status_code in (200, 204):
        try:
            data = resp.json()
            logger.info("[SELFTEST] Delivered to %s as message %s", server.get("name"), data.get("id"))
        except Exception:
            logger.info("[SELFTEST] Delivered to %s", server.get("name"))
        return True

    errtxt = err or (f"{getattr(resp,'status_code','???')} - {getattr(resp,'text','')[:160]}")
    logger.error("[SELFTEST] Failed for %s: %s", server.get("name"), errtxt)
    return False

def _server_primary_webhook(server):
    """Pick the webhook to ping: explicit webhook_url, else first in webhooks list, else DEFAULT."""
    wh = server.get("webhook_url")
    if wh and not _is_placeholder_webhook(wh):
        return wh
    hooks = server.get("webhooks")
    if isinstance(hooks, list) and hooks:
        return hooks[0]
    return DEFAULT_WEBHOOK_URL


def post_ping(server):
    role_id = server.get("ping_role_id")
    raw = None
    allowed = {"parse": [], "users": [], "roles": []}
    if role_id:
        role_id_str = re.sub(r"\D", "", str(role_id))  # sanitize digits only
        raw = f"<@&{role_id_str}>" if role_id_str else None
        allowed["roles"] = [role_id_str] if role_id_str else []
    else:
        ping_id = server.get("ping_id", DEFAULT_USER_PING_ID)
        if ping_id:
            cleaned = "".join(ch for ch in str(ping_id) if ch.isdigit())
            raw = f"<@{cleaned}>" if cleaned else None
            if cleaned:
                allowed["users"] = [cleaned]

    webhook = _server_primary_webhook(server)
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
    _load_downtime_counters()  # load persistent downtime counters
# --- Optional self-test ping and exit ---
    # ENV: SELFTEST=1 and optional SELFTEST_SERVER="name or ip:port"
    # CLI: --selftest  or --selftest=<name|ip:port>
    run_selftest = False
    targets = servers

    if str(os.environ.get("SELFTEST", "")).strip().lower() in ("1", "true", "yes"):
        run_selftest = True
        target_name = os.environ.get("SELFTEST_SERVER")
        if target_name and target_name.lower() != "all":
            tn = target_name.strip().lower()
            def _match(s):
                name = str(s.get("name","")).lower()
                ip = str(s.get("ip","")).strip()
                port = str(s.get("port","")).strip()
                return (tn in name) or (tn == f"{ip}:{port}")
            targets = [s for s in servers if _match(s)]
            if not targets:
                logger.warning("[SELFTEST] No servers matched SELFTEST_SERVER=%s; defaulting to all.", target_name)
                targets = servers

    for arg in list(sys.argv[1:]):
        if arg.startswith("--selftest"):
            run_selftest = True
            if "=" in arg:
                tn = arg.split("=",1)[1].strip().lower()
                if tn and tn != "all":
                    def _match(s):
                        name = str(s.get("name","")).lower()
                        ip = str(s.get("ip","")).strip()
                        port = str(s.get("port","")).strip()
                        return (tn in name) or (tn == f"{ip}:{port}")
                    targets = [s for s in servers if _match(s)]
                    if not targets:
                        logger.warning("[SELFTEST] No servers matched --selftest=%s; defaulting to all.", tn)
                        targets = servers

    if run_selftest:
        ok = 0
        for s in targets:
            try:
                if selftest_ping(s):
                    ok += 1
            except Exception as e:
                logger.error("[SELFTEST] Exception for %s: %s", s.get("name"), e)
        logger.info("[SELFTEST] Completed: %d/%d delivered.", ok, len(targets))
        sys.exit(0)
        
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


# === WEB UI (embedded Flask, optional) ===
import secrets
from urllib.parse import urlencode

_CFG_LOCK = threading.Lock()      # guards read-modify-write of servers.json / users
_SESSION_TTL = 30 * 24 * 3600     # 30 days, sliding — renewed on activity
SESSIONS_FILE = "webui_sessions.json"

def _load_sessions():
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        now = time.time()
        return {t: sess for t, sess in d.items()
                if isinstance(sess, dict) and now - sess.get("created", 0) < _SESSION_TTL}
    except Exception:
        return {}

def _save_sessions():
    try:
        now = time.time()
        for t in [t for t, sess in list(_WEB_SESSIONS.items())
                  if now - sess.get("created", 0) >= _SESSION_TTL]:
            _WEB_SESSIONS.pop(t, None)
        save_json(SESSIONS_FILE, _WEB_SESSIONS)
    except Exception:
        pass

# Sessions persist across bot restarts so users stay signed in.
_WEB_SESSIONS = _load_sessions()  # token -> {"user","role","perms","steamid","created"}

# --- users & roles ---
USERS_FILE = "webui_users.json"

# Roles are bundles of granular permission flags; custom roles can be added
# here later (or moved to a config file) without touching enforcement code.
ROLE_PERMS = {
    "admin":   {"*"},
    "manager": {"view", "servers.manage", "groups.manage", "controls", "pings.manage"},
    "viewer":  {"view"},
}

def _role_perms(role):
    return ROLE_PERMS.get(role, set())

def _load_users():
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d.get("users", {}) if isinstance(d, dict) else {}
    except Exception:
        return {}

def _save_users(users):
    save_json(USERS_FILE, {"users": users})

def _check_login(username: str, password: str):
    """Single shared credential for now. To expand into a full user/permission
    system later, replace this dict with a users.json lookup — the session and
    gate plumbing already carry a user record with a 'perms' list."""
    users = {"admin": {"name": "admin", "password": WEB_UI_PASSWORD, "perms": ["*"]}}
    u = users.get(str(username or "admin"))
    if u and u["password"] and password and secrets.compare_digest(str(password), u["password"]):
        return u
    return None


def _validate_servers_payload(data):
    errs = []
    if not isinstance(data, list):
        return ["config must be a JSON array of server objects"]
    for i, s in enumerate(data):
        if not isinstance(s, dict):
            errs.append(f"entry {i}: not an object")
            continue
        label = s.get("name") or f"entry {i}"
        if not s.get("name"):
            errs.append(f"entry {i}: missing 'name'")
        if not s.get("ip"):
            errs.append(f"{label}: missing 'ip'")
        try:
            p = int(s.get("port", 0))
            if not (1 <= p <= 65535):
                raise ValueError
        except Exception:
            errs.append(f"{label}: invalid 'port'")
        if s.get("webhooks") is not None and not (
                isinstance(s.get("webhooks"), list) and all(isinstance(w, str) for w in s["webhooks"])):
            errs.append(f"{label}: 'webhooks' must be a list of URLs")
        if s.get("editors") is not None and not (
                isinstance(s.get("editors"), list) and all(isinstance(x, str) for x in s["editors"])):
            errs.append(f"{label}: 'editors' must be a list of SteamID64 strings")
        if s.get("restart"):
            _h, _m, err = parse_restart_time(s)
            if err:
                errs.append(f"{label}: restart time {err} (need restart_hour 0-23 and restart_minute 0-59)")
    return errs


def _load_config_list():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


WEBUI_SETTINGS_FILE = "webui_settings.json"

def _load_webui_settings():
    try:
        with open(WEBUI_SETTINGS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def _save_webui_settings(d):
    save_json(WEBUI_SETTINGS_FILE, d)

def _normalized_groups(d=None):
    """Group presets as [{'name':..., 'emoji':...}]; migrates legacy plain strings."""
    if d is None:
        d = _load_webui_settings()
    out = []
    for g in d.get("groups", []):
        if isinstance(g, str):
            out.append({"name": g, "emoji": ""})
        elif isinstance(g, dict) and g.get("name"):
            out.append({"name": str(g["name"]), "emoji": str(g.get("emoji") or "")})
    return out

_GRP_EMOJI_CACHE = {"mtime": None, "map": {}}

def _group_emoji(group_name: str) -> str:
    """Emoji prefix for a group embed title, from webui_settings.json (mtime-cached)."""
    try:
        mt = os.path.getmtime(WEBUI_SETTINGS_FILE)
    except OSError:
        return ""
    if _GRP_EMOJI_CACHE["mtime"] != mt:
        m = {}
        for g in _normalized_groups():
            if g["emoji"]:
                m[g["name"]] = g["emoji"]
        _GRP_EMOJI_CACHE["mtime"] = mt
        _GRP_EMOJI_CACHE["map"] = m
    m = _GRP_EMOJI_CACHE["map"]
    if group_name in m:
        return m[group_name]
    base = group_name.replace(" ⚠️ Temporarily unreachable", "")
    return m.get(base, "")


# --- Runtime-adjustable basic settings (web UI Settings tab, admin only) ---
# Saved in webui_settings.json under "settings"; applied to the module globals
# the bot reads each cycle, and re-applied on startup (overrides script-top values).
RUNTIME_SETTINGS = {
    "GROUP_EMBED_LIMIT":          {"type": int,  "min": 1,   "max": 10,   "label": "Group embed limit (Discord caps at 10)"},
    "EMBED_DESC_LIMIT":           {"type": int,  "min": 256, "max": 4096, "label": "Embed description limit (Discord caps at 4096)"},
    "SHOW_PLAYERS_BY_DEFAULT":    {"type": bool, "label": "Show player list by default"},
    "SHOW_VISIBILITY_BY_DEFAULT": {"type": bool, "label": "Show visibility (public/passworded) by default"},
    "PLAYER_LIST_LIMIT":          {"type": int,  "min": 1,   "max": 100,  "label": "Player list limit"},
    "GHOST_PLAYER_FIX_BY_DEFAULT": {"type": bool, "label": "Ghost player fix by default (count with empty name list -> 0)"},
}

def _apply_settings_overrides():
    try:
        saved = _load_webui_settings().get("settings", {})
        for k, spec in RUNTIME_SETTINGS.items():
            if k not in saved:
                continue
            v = saved[k]
            if spec["type"] is bool:
                globals()[k] = bool(v)
            else:
                try:
                    v = int(v)
                except Exception:
                    continue
                globals()[k] = max(spec["min"], min(spec["max"], v))
        if saved:
            logger.info("[WEBUI] Applied saved settings overrides: %s",
                        {k: globals()[k] for k in RUNTIME_SETTINGS if k in saved})
    except Exception as e:
        logger.warning("[WEBUI] Failed to apply settings overrides: %s", e)

_apply_settings_overrides()


def start_web_ui():
    """Start the embedded Flask web UI in a daemon thread (no-op if disabled/unavailable)."""
    if not WEB_UI_ENABLED:
        logger.info("[WEBUI] Disabled (WEB_UI_ENABLED=False).")
        return
    try:
        from flask import Flask, jsonify, request, Response, redirect
    except ImportError:
        logger.warning("[WEBUI] Flask not installed - web UI disabled. Install with: pip install flask")
        return

    app = Flask("a2sbot-webui")

    def _auth_enabled():
        return bool(WEB_UI_PASSWORD) or bool(_load_users())

    def _current():
        """Session record for this request; synthetic admin when auth is disabled."""
        if not _auth_enabled():
            return {"user": "local", "role": "admin", "perms": ["*"], "steamid": None}
        hdr = request.headers.get("X-Auth-Token", "")
        if hdr and WEB_UI_PASSWORD and secrets.compare_digest(hdr, WEB_UI_PASSWORD):
            return {"user": "token", "role": "admin", "perms": ["*"], "steamid": None}
        tok = request.cookies.get("a2s_session")
        sess = _WEB_SESSIONS.get(tok)
        if sess:
            age = time.time() - sess["created"]
            if age < _SESSION_TTL:
                if age > 86400:  # sliding renewal, at most once/day per session
                    sess["created"] = time.time()
                    _save_sessions()
                return sess
            _WEB_SESSIONS.pop(tok, None)
            _save_sessions()
        return None

    def _has_perm(sess, perm):
        if not sess:
            return False
        perms = set(sess.get("perms") or [])
        return "*" in perms or perm in perms

    def _deny(perm):
        """403 response if the current session lacks a permission, else None."""
        if not _has_perm(_current(), perm):
            return jsonify({"error": "forbidden", "missing": perm}), 403
        return None

    def _can_edit_server(sess, s):
        """Creator, listed editors, or admins. Legacy entries (no created_by)
        remain editable by any manager."""
        if not sess:
            return False
        perms = set(sess.get("perms") or [])
        if "*" in perms:
            return True
        if "servers.manage" not in perms:
            return False
        cb = s.get("created_by")
        if not cb:
            return True
        uid = sess.get("steamid") or sess.get("user")
        return uid == cb or uid in (s.get("editors") or [])

    _PUBLIC_PATHS = ("/", "/api/login", "/api/me", "/auth/steam", "/auth/steam/return")

    @app.before_request
    def _gate():
        if request.path in _PUBLIC_PATHS or _current() is not None:
            return None
        return jsonify({"error": "unauthorized"}), 401

    def _new_session(resp, user, role, steamid=None):
        tok = secrets.token_urlsafe(32)
        _WEB_SESSIONS[tok] = {"user": user, "role": role,
                              "perms": sorted(_role_perms(role)),
                              "steamid": steamid, "created": time.time()}
        _save_sessions()
        if isinstance(resp, dict):
            resp = jsonify(resp)
        resp.set_cookie("a2s_session", tok, httponly=True, samesite="Lax", max_age=_SESSION_TTL)
        return resp

    @app.route("/")
    def index():
        return Response(WEB_UI_HTML, mimetype="text/html")

    # --- auth ---
    @app.route("/api/me")
    def api_me():
        sess = _current()
        return jsonify({
            "auth_required": _auth_enabled(),
            "authed": sess is not None,
            "user": (sess or {}).get("user"),
            "role": (sess or {}).get("role"),
            "perms": (sess or {}).get("perms") or [],
        })

    @app.route("/api/login", methods=["POST"])
    def api_login():
        body = request.get_json(silent=True) or {}
        if not _auth_enabled():
            return jsonify({"ok": True, "user": "local", "role": "admin", "auth": False})
        user = _check_login(body.get("username", "admin"), body.get("password", ""))
        if not user:
            time.sleep(0.4)  # mild brute-force damper
            return jsonify({"ok": False, "error": "invalid credentials"}), 401
        logger.info("[WEBUI] Password (break-glass) admin login.")
        return _new_session({"ok": True, "user": "admin", "role": "admin", "auth": True}, "admin", "admin")

    @app.route("/api/logout", methods=["POST"])
    def api_logout():
        _WEB_SESSIONS.pop(request.cookies.get("a2s_session"), None)
        _save_sessions()
        resp = jsonify({"ok": True})
        resp.delete_cookie("a2s_session")
        return resp

    # --- Steam OpenID 2.0 ("Sign in through Steam") ---
    STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"

    def _public_base():
        return (WEB_UI_PUBLIC_URL or request.host_url).rstrip("/")

    def _steam_persona(sid):
        key = STEAM_API_KEY
        if not key or key == "PUT_YOUR_STEAM_WEB_API_KEY_HERE":
            return None
        try:
            r = SESSION.get("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
                            params={"key": key, "steamids": sid}, timeout=6)
            pl = (r.json().get("response", {}).get("players") or [{}])[0]
            return {"name": pl.get("personaname"), "avatar": pl.get("avatarfull")}
        except Exception:
            return None

    @app.route("/auth/steam")
    def auth_steam():
        base = _public_base()
        params = {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "checkid_setup",
            "openid.return_to": f"{base}/auth/steam/return",
            "openid.realm": base,
            "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
        }
        return redirect(f"{STEAM_OPENID_URL}?{urlencode(params)}")

    @app.route("/auth/steam/return")
    def auth_steam_return():
        args = dict(request.args)
        args["openid.mode"] = "check_authentication"
        try:
            r = SESSION.post(STEAM_OPENID_URL, data=args, timeout=10)
            valid = "is_valid:true" in (r.text or "")
        except Exception as e:
            logger.warning("[WEBUI] Steam OpenID verification error: %s", e)
            valid = False
        m = re.search(r"/openid/id/(\d{17})$", str(request.args.get("openid.claimed_id", "")))
        if not valid or not m:
            return redirect("/?steam=failed")
        sid = m.group(1)
        with _CFG_LOCK:
            users = _load_users()
            u = users.get(sid)
            if not u:
                logger.info("[WEBUI] Steam login rejected — SteamID not on user list: %s", sid)
                return redirect("/?steam=notauthorized")
            p = _steam_persona(sid)
            if p:
                u["name"] = p.get("name") or u.get("name")
                u["avatar"] = p.get("avatar") or u.get("avatar")
            u["last_login"] = time.time()
            users[sid] = u
            _save_users(users)
        logger.info("[WEBUI] Steam login: %s (%s, role=%s)", u.get("name") or sid, sid, u.get("role"))
        return _new_session(redirect("/"), u.get("name") or sid, u.get("role", "viewer"), steamid=sid)

    # --- user management (admin) ---
    def _admins_left(users, excluding=None):
        return sum(1 for s, u in users.items() if u.get("role") == "admin" and s != excluding)

    @app.route("/api/users", methods=["GET", "POST"])
    def api_users():
        err = _deny("users.manage")
        if err:
            return err
        if request.method == "GET":
            return jsonify({"users": _load_users(), "roles": sorted(ROLE_PERMS.keys()),
                            "role_perms": {k: sorted(v) for k, v in ROLE_PERMS.items()}})
        body = request.get_json(silent=True) or {}
        sid = re.sub(r"\D", "", str(body.get("steamid", "")))
        role = str(body.get("role", "viewer"))
        if not re.fullmatch(r"7656\d{13}", sid):
            return jsonify({"ok": False, "error": "invalid SteamID64 (17 digits, starts with 7656)"}), 400
        if role not in ROLE_PERMS:
            return jsonify({"ok": False, "error": f"unknown role '{role}'"}), 400
        with _CFG_LOCK:
            users = _load_users()
            if sid in users:
                return jsonify({"ok": False, "error": "user already exists"}), 400
            p = _steam_persona(sid) or {}
            users[sid] = {"name": str(body.get("name") or p.get("name") or ""),
                          "avatar": p.get("avatar") or "", "role": role,
                          "added_by": (_current() or {}).get("user"),
                          "added_at": time.time(), "last_login": None}
            _save_users(users)
        logger.info("[WEBUI] User added: %s (%s) role=%s", users[sid]["name"] or sid, sid, role)
        return jsonify({"ok": True, "users": users})

    @app.route("/api/users/update", methods=["POST"])
    def api_users_update():
        err = _deny("users.manage")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        sid = re.sub(r"\D", "", str(body.get("steamid", "")))
        role = str(body.get("role", ""))
        if role not in ROLE_PERMS:
            return jsonify({"ok": False, "error": f"unknown role '{role}'"}), 400
        with _CFG_LOCK:
            users = _load_users()
            if sid not in users:
                return jsonify({"ok": False, "error": "user not found"}), 404
            if users[sid].get("role") == "admin" and role != "admin"                     and not WEB_UI_PASSWORD and _admins_left(users, excluding=sid) == 0:
                return jsonify({"ok": False, "error": "cannot demote the last admin — no password fallback configured"}), 400
            users[sid]["role"] = role
            _save_users(users)
        for t, s in list(_WEB_SESSIONS.items()):  # live sessions pick up the new role
            if s.get("steamid") == sid:
                s["role"] = role
                s["perms"] = sorted(_role_perms(role))
        _save_sessions()
        logger.info("[WEBUI] User role changed: %s -> %s", sid, role)
        return jsonify({"ok": True, "users": users})

    @app.route("/api/users/delete", methods=["POST"])
    def api_users_delete():
        err = _deny("users.manage")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        sid = re.sub(r"\D", "", str(body.get("steamid", "")))
        with _CFG_LOCK:
            users = _load_users()
            u = users.pop(sid, None)
            if u is None:
                return jsonify({"ok": False, "error": "user not found"}), 404
            if u.get("role") == "admin" and not WEB_UI_PASSWORD and _admins_left(users) == 0:
                users[sid] = u
                return jsonify({"ok": False, "error": "cannot remove the last admin — no password fallback configured"}), 400
            _save_users(users)
        for t, s in list(_WEB_SESSIONS.items()):  # kill their live sessions
            if s.get("steamid") == sid:
                _WEB_SESSIONS.pop(t, None)
        _save_sessions()
        logger.info("[WEBUI] User removed: %s", sid)
        return jsonify({"ok": True, "users": users})

    # --- status / logs ---    # --- status / logs ---
    @app.route("/api/status")
    def api_status():
        err = _deny("view")
        if err:
            return err
        st = dict(WEB_STATE)
        st["interval"] = INTERVAL_SECONDS
        st["version"] = "2.3.4"
        st["uptime_s"] = int(time.time() - WEB_STATE.get("started_at", time.time()))
        return jsonify(st)

    @app.route("/api/logs")
    def api_logs():
        err = _deny("logs.view")   # admin-only: log lines can contain webhook URLs
        if err:
            return err
        active_alerts = {k: v for k, v in alerts_state.items() if v.get("active")}
        return jsonify({
            "lines": list(LOG_BUFFER)[-300:],
            "alerts": active_alerts,
            "net_freeze": bool(NET_FREEZE_ACTIVE),
            "steam_unhealthy": bool(_last_steam_unhealthy),
        })

    # --- per-server CRUD (Servers tab) ---
    @app.route("/api/servers", methods=["GET", "POST"])
    def api_servers():
        if request.method == "GET":
            err = _deny("view")
            if err:
                return err
            sess = _current()
            out = []
            for s in _load_config_list():
                s = dict(s)
                s["_can_edit"] = _can_edit_server(sess, s)
                out.append(s)
            return jsonify(out)
        err = _deny("servers.manage")
        if err:
            return err
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "expected a server object"}), 400
        body = {k: v for k, v in body.items() if not str(k).startswith("_")}
        _sess = _current() or {}
        body.setdefault("created_by", _sess.get("steamid") or _sess.get("user") or "unknown")
        body.setdefault("created_by_name", _sess.get("user") or "unknown")
        with _CFG_LOCK:
            servers = _load_config_list()
            servers.append(body)
            errs = _validate_servers_payload(servers)
            if errs:
                return jsonify({"ok": False, "error": "\n".join(errs)}), 400
            save_json(CONFIG_FILE, servers)
        logger.info("[WEBUI] Server added via web UI: %s (%s:%s)", body.get("name"), body.get("ip"), body.get("port"))
        return jsonify({"ok": True, "index": len(servers) - 1})

    @app.route("/api/servers/<int:idx>", methods=["PUT", "DELETE"])
    def api_server_item(idx):
        err = _deny("servers.manage")
        if err:
            return err
        with _CFG_LOCK:
            servers = _load_config_list()
            if not (0 <= idx < len(servers)):
                return jsonify({"ok": False, "error": "server index out of range"}), 404
            target = servers[idx]
            if not _can_edit_server(_current(), target):
                return jsonify({"ok": False, "error": "only this server's creator, its listed editors, or an admin can modify it"}), 403
            if request.method == "DELETE":
                removed = servers.pop(idx)
                save_json(CONFIG_FILE, servers)
                logger.info("[WEBUI] Server removed via web UI: %s (%s:%s) — Discord message cleanup next cycle.",
                            removed.get("name"), removed.get("ip"), removed.get("port"))
                return jsonify({"ok": True})
            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                return jsonify({"ok": False, "error": "expected a server object"}), 400
            body = {k: v for k, v in body.items() if not str(k).startswith("_")}
            for _ck in ("created_by", "created_by_name"):  # creator record is immutable via API
                if _ck in target:
                    body[_ck] = target[_ck]
                else:
                    body.pop(_ck, None)
            servers[idx] = body
            errs = _validate_servers_payload(servers)
            if errs:
                return jsonify({"ok": False, "error": "\n".join(errs)}), 400
            save_json(CONFIG_FILE, servers)
        logger.info("[WEBUI] Server updated via web UI: %s (%s:%s)", body.get("name"), body.get("ip"), body.get("port"))
        return jsonify({"ok": True})

    # --- group presets (Groups tab) ---
    @app.route("/api/groups", methods=["GET", "POST"])
    def api_groups():
        if request.method == "GET":
            err = _deny("view")
            if err:
                return err
            in_use = {}
            for s in _load_config_list():
                g = (s.get("group") or "").strip()
                if g:
                    in_use[g] = in_use.get(g, 0) + 1
            return jsonify({"defined": _normalized_groups(), "in_use": in_use})
        err = _deny("groups.manage")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        emoji_v = str(body.get("emoji", "") or "").strip()[:16]
        if not name:
            return jsonify({"ok": False, "error": "group name required"}), 400
        if len(name) > 100:
            return jsonify({"ok": False, "error": "group name too long (max 100)"}), 400
        with _CFG_LOCK:
            d = _load_webui_settings()
            groups = _normalized_groups(d)
            if any(g["name"] == name for g in groups):
                return jsonify({"ok": False, "error": "group already exists"}), 400
            groups.append({"name": name, "emoji": emoji_v})
            d["groups"] = groups
            _save_webui_settings(d)
        logger.info("[WEBUI] Group preset added: %s", name)
        return jsonify({"ok": True, "groups": groups})

    @app.route("/api/groups/update", methods=["POST"])
    def api_groups_update():
        err = _deny("groups.manage")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        emoji_v = str(body.get("emoji", "") or "").strip()[:16]
        if not name:
            return jsonify({"ok": False, "error": "group name required"}), 400
        with _CFG_LOCK:
            d = _load_webui_settings()
            groups = _normalized_groups(d)
            for g in groups:
                if g["name"] == name:
                    g["emoji"] = emoji_v
                    break
            else:
                groups.append({"name": name, "emoji": emoji_v})
            d["groups"] = groups
            _save_webui_settings(d)
        logger.info("[WEBUI] Group preset updated: %s (emoji=%s)", name, emoji_v or "-")
        return jsonify({"ok": True, "groups": groups})

    @app.route("/api/groups/delete", methods=["POST"])
    def api_groups_delete():
        err = _deny("groups.manage")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        with _CFG_LOCK:
            d = _load_webui_settings()
            groups = [g for g in _normalized_groups(d) if g["name"] != name]
            d["groups"] = groups
            _save_webui_settings(d)
        logger.info("[WEBUI] Group preset removed: %s", name)
        return jsonify({"ok": True, "groups": groups})

    # --- downtime ping messages (Messages tab) ---
    def _mask_webhook(wh):
        s = str(wh or "")
        return ("…" + s[-10:]) if len(s) > 10 else s

    @app.route("/api/pings")
    def api_pings():
        err = _deny("pings.manage")
        if err:
            return err
        srv_names = {f"{s.get('ip')}:{s.get('port')}": s.get("name") for s in _load_config_list()}
        out = []
        for key, mid in list(ping_message_ids.items()):
            out.append({"key": key, "message_id": mid,
                        "server": srv_names.get(key),
                        "still_configured": key in srv_names,
                        "marked_down": bool(server_down.get(key, False)),
                        "webhook_hint": _mask_webhook(ping_routes.get(key))})
        return jsonify({"pings": out})

    @app.route("/api/pings/delete", methods=["POST"])
    def api_pings_delete():
        err = _deny("pings.manage")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        key = str(body.get("key", "")).strip()
        if key not in ping_message_ids:
            return jsonify({"ok": False, "error": "no ping message recorded for that server"}), 404
        msg_id = ping_message_ids.get(key)
        webhook = ping_routes.get(key, DEFAULT_WEBHOOK_URL)
        deleted = False
        try:
            deleted = delete_discord_message(msg_id, webhook, label=f"webui revoke {key}")
        except Exception as e:
            logger.warning("[WEBUI] Revoke delete failed for %s: %s", key, e)
        ping_message_ids.pop(key, None)
        ping_routes.pop(key, None)
        has_pinged_down[key] = False
        save_json("ping_message_ids.json", ping_message_ids)
        save_json("ping_routes.json", ping_routes)
        save_json("has_pinged_down.json", has_pinged_down)
        logger.info("[WEBUI] Downtime ping revoked for %s (discord delete: %s)", key, "ok" if deleted else "failed/skipped")
        return jsonify({"ok": True, "discord_deleted": bool(deleted)})

    # --- runtime settings (Settings tab, admin) ---
    @app.route("/api/settings", methods=["GET", "POST"])
    def api_settings():
        err = _deny("settings.manage")
        if err:
            return err
        if request.method == "GET":
            return jsonify({"settings": {k: globals()[k] for k in RUNTIME_SETTINGS},
                            "spec": {k: {"label": s["label"],
                                         "type": ("bool" if s["type"] is bool else "int"),
                                         "min": s.get("min"), "max": s.get("max")}
                                     for k, s in RUNTIME_SETTINGS.items()}})
        body = request.get_json(silent=True) or {}
        newvals, errs = {}, []
        for k, spec in RUNTIME_SETTINGS.items():
            if k not in body:
                continue
            v = body[k]
            if spec["type"] is bool:
                newvals[k] = bool(v)
            else:
                try:
                    v = int(v)
                except Exception:
                    errs.append(f"{spec['label']}: must be a number")
                    continue
                if not (spec["min"] <= v <= spec["max"]):
                    errs.append(f"{spec['label']}: must be {spec['min']}-{spec['max']}")
                    continue
                newvals[k] = v
        if errs:
            return jsonify({"ok": False, "error": "\n".join(errs)}), 400
        with _CFG_LOCK:
            d = _load_webui_settings()
            d.setdefault("settings", {}).update(newvals)
            _save_webui_settings(d)
        for k, v in newvals.items():
            globals()[k] = v
        logger.info("[WEBUI] Settings updated: %s", newvals)
        return jsonify({"ok": True, "settings": {k: globals()[k] for k in RUNTIME_SETTINGS}})

    # --- lightweight user list for editor selection (managers) ---
    @app.route("/api/users/simple")
    def api_users_simple():
        err = _deny("servers.manage")
        if err:
            return err
        return jsonify([{"steamid": sid, "name": u.get("name") or sid}
                        for sid, u in _load_users().items()])

    # --- refresh Steam personas (admin) ---
    @app.route("/api/users/refresh", methods=["POST"])
    def api_users_refresh():
        err = _deny("users.manage")
        if err:
            return err
        if not STEAM_API_KEY or STEAM_API_KEY == "PUT_YOUR_STEAM_WEB_API_KEY_HERE":
            return jsonify({"ok": False, "error": "STEAM_API_KEY is not configured — set it at the top of the script to fetch Steam personas"}), 400
        with _CFG_LOCK:
            users = _load_users()
            if not users:
                return jsonify({"ok": True, "updated": 0})
            try:
                r = SESSION.get("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
                                params={"key": STEAM_API_KEY, "steamids": ",".join(users.keys())}, timeout=10)
                players = {p.get("steamid"): p for p in (r.json().get("response", {}).get("players") or [])}
            except Exception as e:
                return jsonify({"ok": False, "error": f"Steam API request failed: {e}"}), 502
            updated = 0
            for sid, u in users.items():
                p = players.get(sid)
                if p:
                    u["name"] = p.get("personaname") or u.get("name")
                    u["avatar"] = p.get("avatarfull") or u.get("avatar")
                    updated += 1
            _save_users(users)
        logger.info("[WEBUI] Steam personas refreshed for %d user(s).", updated)
        return jsonify({"ok": True, "updated": updated})

    # --- raw config (Advanced tab) ---
    @app.route("/api/config", methods=["GET", "POST"])
    def api_config():
        err = _deny("config.raw")   # admin-only: raw config contains webhook URLs
        if err:
            return err
        if request.method == "GET":
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return Response(f.read(), mimetype="application/json")
            except FileNotFoundError:
                return jsonify([])
        try:
            data = request.get_json(force=True)
        except Exception as e:
            return jsonify({"ok": False, "error": f"invalid JSON: {e}"}), 400
        errs = _validate_servers_payload(data)
        if errs:
            return jsonify({"ok": False, "error": "\n".join(errs)}), 400
        with _CFG_LOCK:
            save_json(CONFIG_FILE, data)
        logger.info("[WEBUI] servers.json replaced via Advanced editor (%d servers).", len(data))
        return jsonify({"ok": True, "servers": len(data)})

    # --- controls ---
    @app.route("/api/control/refresh", methods=["POST"])
    def api_refresh():
        err = _deny("controls")
        if err:
            return err
        FORCE_REFRESH.set()
        logger.info("[WEBUI] Manual refresh requested.")
        return jsonify({"ok": True})

    @app.route("/api/control/selftest", methods=["POST"])
    def api_selftest():
        err = _deny("controls")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip().lower()
        srvs, _ex = load_servers_and_detect_example_mode()
        if target and target != "all":
            srvs = [s for s in srvs
                    if target in str(s.get("name", "")).lower()
                    or target == f"{s.get('ip')}:{s.get('port')}"]
        if not srvs:
            return jsonify({"ok": False, "error": "no matching servers"}), 404
        ok = 0
        for s in srvs:
            try:
                if selftest_ping(s):
                    ok += 1
            except Exception as e:
                logger.error("[WEBUI] Selftest exception for %s: %s", s.get("name"), e)
        return jsonify({"ok": True, "delivered": ok, "total": len(srvs)})

    @app.route("/api/control/reset_counters", methods=["POST"])
    def api_reset_counters():
        err = _deny("controls")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        k = body.get("key")
        if k:
            _downtime_counters.pop(str(k), None)
        else:
            _downtime_counters.clear()
        _save_downtime_counters()
        logger.info("[WEBUI] Downtime counters reset (%s).", k or "all")
        return jsonify({"ok": True})

    def _run():
        try:
            app.run(host=WEB_UI_HOST, port=WEB_UI_PORT, debug=False, use_reloader=False, threaded=True)
        except Exception as e:
            logger.error("[WEBUI] Failed to start: %s", e)

    threading.Thread(target=_run, name="webui", daemon=True).start()
    logger.info("[WEBUI] Running at http://%s:%s", WEB_UI_HOST, WEB_UI_PORT)


WEB_UI_HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>A2S Statusbot</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#12141a;--card:#1c1f2a;--fg:#e8eaf0;--mut:#8b90a0;--up:#3ecf6f;--down:#ff5c5c;--acc:#7f00ff}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,'Segoe UI',sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;flex-wrap:wrap;align-items:center;gap:14px;padding:14px 20px;background:var(--card);border-bottom:2px solid var(--acc)}
h1{font-size:16px;margin:0}
.badge{padding:2px 9px;border-radius:10px;font-size:12px;font-weight:600}
.badge.ok{background:#14532d;color:#86efac}.badge.bad{background:#7f1d1d;color:#fca5a5}
.badge.warn{background:#78350f;color:#fcd34d}
nav{display:flex;gap:4px;padding:10px 20px 0;flex-wrap:wrap}
nav button{background:none;border:none;color:var(--mut);padding:8px 14px;cursor:pointer;font-size:14px;border-bottom:2px solid transparent}
nav button.active{color:var(--fg);border-color:var(--acc)}
main{padding:16px 20px;max-width:1100px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.card{background:var(--card);border-radius:10px;padding:14px}
.card h3{margin:0 0 6px;font-size:15px;display:flex;justify-content:space-between;gap:8px;align-items:center}
.mut{color:var(--mut);font-size:12px}
pre{background:#0d0f14;padding:12px;border-radius:8px;overflow:auto;max-height:60vh;font-size:12px;white-space:pre-wrap}
textarea{width:100%;background:#0d0f14;color:var(--fg);border:1px solid #333;border-radius:8px;padding:10px;font:12px/1.4 monospace}
#cfg{min-height:50vh}
button.act{background:var(--acc);color:#fff;border:none;border-radius:6px;padding:8px 14px;cursor:pointer;margin:4px 6px 4px 0}
button.act.warn{background:#a33}
button.act.ghost{background:#2a2e3d}
input[type=text],input[type=password],input[type=number],select{background:#0d0f14;color:var(--fg);border:1px solid #333;border-radius:6px;padding:8px;width:100%}
.err{color:#ff8080;white-space:pre-wrap}.okmsg{color:var(--up)}
details{margin-top:6px}summary{cursor:pointer;color:var(--mut);font-size:12px}
ul{margin:6px 0;padding-left:18px;font-size:13px}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;z-index:20;padding:16px}
.overlay[hidden]{display:none}
.dialog{background:var(--card);border-radius:12px;padding:20px;max-width:680px;width:100%;max-height:92vh;overflow:auto}
.dialog h2{margin:0 0 10px;font-size:17px}
fieldset{border:1px solid #333;border-radius:8px;margin:12px 0;padding:10px 12px}
legend{color:var(--mut);font-size:12px;padding:0 6px}
label{display:block;font-size:12px;color:var(--mut);margin:8px 0 3px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
@media (max-width:600px){.row,.row3{grid-template-columns:1fr}}
</style></head><body>
<header><h1>A2S Statusbot</h1><span id="summary" class="mut">loading&hellip;</span><span id="flags"></span>
<span id="whoami" class="mut" style="margin-left:auto"></span>
<button class="act ghost" id="logoutbtn" style="display:none" onclick="doLogout()">Sign out</button></header>
<nav>
<button data-tab="status" class="active">Status</button>
<button data-tab="servers">Servers</button>
<button data-tab="logs">Logs</button>
<button data-tab="controls">Controls</button>
<button data-tab="messages">Messages</button>
<button data-tab="groups">Groups</button>
<button data-tab="users">Users</button>
<button data-tab="settings">Settings</button>
<button data-tab="advanced">Advanced</button>
</nav>
<main>
<section id="tab-status"><div class="grid" id="servers"><div class="mut">loading&hellip;</div></div></section>

<section id="tab-servers" hidden>
  <button class="act" id="addsrvbtn" onclick="openEditor(-1)">+ Add server</button>
  <div class="grid" id="srvlist" style="margin-top:10px"><div class="mut">loading&hellip;</div></div>
</section>

<section id="tab-logs" hidden>
  <div id="alerts"></div>
  <pre id="loglines">loading&hellip;</pre>
</section>

<section id="tab-controls" hidden>
  <div class="card"><h3>Force refresh</h3><p class="mut">Skip the current wait and run a query cycle now.</p>
    <button class="act" onclick="ctl('refresh')">Refresh now</button></div>
  <div class="card" style="margin-top:12px"><h3>Selftest ping</h3>
    <p class="mut">Sends a test mention through the server's webhook. Leave blank for all servers.</p>
    <input type="text" id="selftarget" placeholder="name or ip:port" style="max-width:280px">
    <button class="act" onclick="selftest()">Send selftest</button></div>
  <div class="card" style="margin-top:12px"><h3>Downtime counters</h3>
    <p class="mut">Clears the persistent per-server downtime totals.</p>
    <button class="act warn" onclick="ctl('reset_counters')">Reset all counters</button></div>
  <div id="ctlmsg" style="margin-top:10px"></div>
</section>

<section id="tab-groups" hidden>
  <div class="card"><h3>Server groups</h3>
  <p class="mut">Servers sharing a group are merged into one Discord embed. Groups defined here appear
  in the server editor's dropdown; the optional emoji is shown as a prefix on the group's embed title.
  Deleting a preset does not change servers already using it.</p>
  <div id="groupaddrow" style="display:flex;gap:8px;max-width:560px">
    <input type="text" id="newgroupemoji" placeholder="&#128512;" title="Optional emoji prefix" style="max-width:60px;text-align:center">
    <button class="act ghost" style="margin:0;padding:6px 10px" onclick="toggleEmojiPicker(event,'newgroupemoji')" title="Pick an emoji">&#128512;</button>
    <input type="text" id="newgroup" placeholder="New group name" onkeydown="if(event.key==='Enter')addGroup()">
    <button class="act" style="margin:0" onclick="addGroup()">Add</button></div>
  <ul id="grouplist" style="list-style:none;padding:0;margin-top:10px"></ul>
  <div id="grpmsg"></div></div>
</section>

<section id="tab-messages" hidden>
  <div class="card"><h3>Downtime ping messages</h3>
  <p class="mut">Active "server down" pings the bot has posted. Revoke one to delete the Discord message and
  clear the bot's record — for pings that stick after a server recovers or its config changes. If the server
  is still down, the bot may post a fresh ping on a later cycle.</p>
  <div id="pinglist" class="mut">loading&hellip;</div>
  <div id="pingmsg" style="margin-top:8px"></div></div>
</section>

<section id="tab-settings" hidden>
  <div class="card"><h3>Bot settings</h3>
  <p class="mut">Applied immediately and persisted across restarts (overrides the values at the top of the script).</p>
  <div id="settingsform" style="max-width:480px"></div>
  <button class="act" onclick="saveSettings()">Save</button>
  <span id="setmsg"></span></div>
</section>

<section id="tab-users" hidden>
  <div class="card"><h3>Users</h3>
  <p class="mut">Steam sign-in is whitelist-only: add a SteamID64 and assign a role. Unknown Steam accounts
  are rejected at sign-in. Roles — <b>admin</b>: everything • <b>manager</b>: servers, groups, controls •
  <b>viewer</b>: read-only status. The password login remains available as a break-glass admin.</p>
  <div style="display:flex;gap:8px;max-width:620px;flex-wrap:wrap">
    <input type="text" id="newuser_sid" placeholder="SteamID64 (7656...)" style="flex:2;min-width:220px">
    <select id="newuser_role" style="flex:1;min-width:110px"><option value="viewer">viewer</option><option value="manager">manager</option><option value="admin">admin</option></select>
    <button class="act" style="margin:0" onclick="addUser()">Add user</button>
    <button class="act ghost" style="margin:0" onclick="refreshUsers()" title="Re-fetch Steam personas (needs STEAM_API_KEY)">Refresh Steam names</button>
  </div>
  <div id="userlist" style="margin-top:12px"></div>
  <div id="usermsg"></div></div>
</section>

<section id="tab-advanced" hidden>
  <div class="card" style="margin-bottom:12px"><h3>Raw servers.json</h3>
  <p class="mut">Direct config editing — prefer the Servers tab for day-to-day changes. Saved config is validated and hot-reloaded next cycle.</p>
  <textarea id="cfg" spellcheck="false"></textarea><br>
  <button class="act" onclick="loadCfg()">Reload</button>
  <button class="act" onclick="saveCfg()">Save</button>
  <div id="cfgmsg"></div></div>
</section>
</main>

<!-- Server editor modal -->
<div id="modal" class="overlay" hidden>
 <div class="dialog">
  <h2 id="mtitle">Edit server</h2>
  <fieldset><legend>Basics</legend>
    <div class="row"><div><label>Name *</label><input type="text" id="f_name"></div>
    <div><label>Group <span class="mut">(servers sharing a group merge into one embed)</span></label>
    <select id="f_group" onchange="groupSelChange()"></select>
    <input type="text" id="f_group_custom" placeholder="New group name" style="margin-top:6px;display:none"></div></div>
    <div class="row3"><div><label>IP *</label><input type="text" id="f_ip"></div>
    <div><label>Port *</label><input type="number" id="f_port" min="1" max="65535"></div>
    <div><label>Max players <span class="mut">(shown while unreachable)</span></label><input type="number" id="f_maxp" min="0"></div></div>
    <div class="row3"><div><label>Owner / admin <span class="mut">(user ID &rarr; @user, &amp;id or &lt;@&amp;id&gt; &rarr; @role, or plain text)</span></label><input type="text" id="f_owner" placeholder="user ID, &roleID, or a name"></div>
    <div><label>Emoji <span class="mut">(title prefix)</span></label>
    <div style="display:flex;gap:6px"><input type="text" id="f_emoji">
    <button class="act ghost" style="margin:0;padding:6px 10px" onclick="toggleEmojiPicker(event,'f_emoji')" title="Pick an emoji">😀</button></div></div>
    <div><label>Icon URL <span class="mut">(thumbnail, overrides emoji)</span></label><input type="text" id="f_icon"></div></div>
  </fieldset>
  <fieldset><legend>Webhook routing</legend>
    <label>Webhook URL <span class="mut">(blank = bot default webhook)</span></label><input type="text" id="f_webhook">
    <label>Additional webhooks <span class="mut">(one URL per line — status posts to every listed channel)</span></label>
    <textarea id="f_webhooks" rows="3"></textarea>
  </fieldset>
  <fieldset><legend>Down pings</legend>
    <div class="row3">
    <div><label>Ping role ID <span class="mut">(takes priority)</span></label><input type="text" id="f_role" placeholder="123456789012345678"></div>
    <div><label>Ping user <span class="mut">(just the user ID)</span></label><input type="text" id="f_ping" placeholder="123456789012345678"></div>
    <div><label>Disable pings</label><select id="f_disable"><option value="">Default (off)</option><option value="true">On — never ping</option><option value="false">Off — ping normally</option></select></div>
    </div>
  </fieldset>
  <fieldset><legend>Daily restart notice</legend>
    <label><input type="checkbox" id="f_restart" onchange="toggleRestart()" style="width:auto"> Show a daily restart time on the embed</label>
    <div class="row3" id="restartrow">
    <div><label>Hour (0–23)</label><input type="number" id="f_rh" min="0" max="23"></div>
    <div><label>Minute (0–59)</label><input type="number" id="f_rm" min="0" max="59"></div>
    <div><label>Timezone</label><input type="text" id="f_tz" list="tzlist" placeholder="America/Edmonton">
      <datalist id="tzlist"><option>UTC</option><option>America/Edmonton</option><option>America/Vancouver</option>
      <option>America/Toronto</option><option>America/Winnipeg</option><option>America/New_York</option>
      <option>America/Chicago</option><option>America/Denver</option><option>America/Los_Angeles</option>
      <option>Europe/London</option><option>Europe/Berlin</option><option>Australia/Sydney</option></datalist></div>
    </div>
  </fieldset>
  <fieldset><legend>Display <span class="mut">(Default inherits the bot-wide setting)</span></legend>
    <div class="row3">
    <div><label>Show player list</label><select id="f_showp"><option value="">Default</option><option value="true">On</option><option value="false">Off</option></select></div>
    <div><label>Show visibility (public/passworded)</label><select id="f_showv"><option value="">Default</option><option value="true">On</option><option value="false">Off</option></select></div>
    <div><label>Persistent downtime counter</label><select id="f_dtc"><option value="">Default (off)</option><option value="true">On</option><option value="false">Off</option></select></div>
    <div><label>Ghost player fix <span class="mut">(empty name list &rarr; count 0)</span></label><select id="f_ghost"><option value="">Default</option><option value="true">On</option><option value="false">Off</option></select></div>
    </div>
  </fieldset>
  <fieldset><legend>Edit access</legend>
    <div class="mut" id="createdby"></div>
    <div id="editorchecks" style="margin-top:6px"></div>
  </fieldset>
  <div><button class="act" onclick="saveServer()">Save</button>
  <button class="act ghost" onclick="closeModal()">Cancel</button></div>
  <div id="mmsg" style="margin-top:8px"></div>
 </div>
</div>

<div id="emojipicker" hidden style="position:fixed;background:#0d0f14;border:1px solid #333;border-radius:10px;z-index:40;box-shadow:0 8px 30px rgba(0,0,0,.5)"></div>

<!-- Login overlay -->
<div id="login" class="overlay" hidden>
 <div class="dialog" style="max-width:360px">
  <h2>Sign in</h2>
  <a href="/auth/steam" style="display:block;text-align:center;text-decoration:none;background:#171a21;border:1px solid #2a475e;color:#fff;border-radius:6px;padding:11px 14px;font-weight:600">Sign in through Steam</a>
  <details style="margin-top:14px"><summary>Admin password login</summary>
  <label>Username</label><input type="text" id="luser" value="admin" autocomplete="username">
  <label>Password</label><input type="password" id="lpass" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()">
  <div style="margin-top:12px"><button class="act" onclick="doLogin()">Sign in</button></div>
  </details>
  <div id="lmsg" class="err" style="margin-top:8px"></div>
 </div>
</div>

<script>
let ME = {authed:false, auth_required:false, user:null, role:null, perms:[]};
function can(p){return !ME.auth_required || ME.perms.includes('*') || ME.perms.includes(p);}
const TAB_PERMS = {status:'view', servers:'view', groups:'view', logs:'logs.view',
                   controls:'controls', messages:'pings.manage', users:'users.manage',
                   settings:'settings.manage', advanced:'config.raw'};
function applyPerms(){
  document.querySelectorAll('nav button').forEach(b=>{
    b.style.display = can(TAB_PERMS[b.dataset.tab]) ? '' : 'none';
  });
  const act = document.querySelector('nav button.active');
  if (act && act.style.display === 'none') document.querySelector('nav button').click();
  document.getElementById('whoami').textContent =
    (ME.authed && ME.auth_required) ? (ME.user + ' (' + ME.role + ')') : '';
  document.getElementById('logoutbtn').style.display = (ME.authed && ME.auth_required) ? '' : 'none';
  const ab = document.getElementById('addsrvbtn');
  if (ab) ab.style.display = can('servers.manage') ? '' : 'none';
  const gar = document.getElementById('groupaddrow');
  if (gar) gar.style.display = can('groups.manage') ? 'flex' : 'none';
}
async function loadMe(){
  try{
    const r = await fetch('/api/me');
    ME = await r.json();
    document.getElementById('login').hidden = !(ME.auth_required && !ME.authed);
    applyPerms();
  }catch(e){}
}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmtAgo(t){if(!t)return 'never';const s=Math.max(0,Math.round(Date.now()/1000-t));return s<90?s+'s ago':Math.round(s/60)+'m ago';}

async function api(path, opts={}){
  opts.headers = Object.assign({'Content-Type': 'application/json'}, opts.headers || {});
  const r = await fetch(path, opts);
  if (r.status === 401 && path !== '/api/login'){
    document.getElementById('login').hidden = false;
    throw new Error('unauthorized');
  }
  return r;
}

async function doLogin(){
  const el = document.getElementById('lmsg');
  el.textContent = '';
  const body = JSON.stringify({username: document.getElementById('luser').value.trim() || 'admin',
                               password: document.getElementById('lpass').value});
  const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body});
  const d = await r.json().catch(()=>({}));
  if (r.ok && d.ok){
    document.getElementById('lpass').value = '';
    await loadMe();
    refreshActiveTab(); loadStatus();
  } else {
    el.textContent = d.error || 'login failed';
  }
}
async function doLogout(){
  await fetch('/api/logout', {method:'POST'});
  await loadMe();
}

const tabs = document.querySelectorAll('nav button');
function activeTab(){const b=document.querySelector('nav button.active');return b?b.dataset.tab:'status';}
function refreshActiveTab(){
  const t = activeTab();
  if (t==='status') loadStatus();
  if (t==='servers') loadServers();
  if (t==='logs') loadLogs();
  if (t==='groups') loadGroups();
  if (t==='messages') loadPings();
  if (t==='users') loadUsers();
  if (t==='settings') loadSettings();
  if (t==='advanced') loadCfg();
}
tabs.forEach(b=>b.onclick=()=>{
  tabs.forEach(x=>x.classList.toggle('active',x===b));
  document.querySelectorAll('main section').forEach(s=>s.hidden = s.id !== 'tab-'+b.dataset.tab);
  refreshActiveTab();
});

// ---- Status tab ----
async function loadStatus(){
  try{
    const r = await api('/api/status'); if(!r.ok) return;
    const d = await r.json();
    document.getElementById('summary').textContent =
      `v${d.version} • up ${d.up} / down ${d.down} • cycle ${fmtAgo(d.last_cycle)} • every ${d.interval}s`;
    let flags = '';
    if (d.net_freeze) flags += '<span class="badge warn">NET FREEZE</span> ';
    if (d.steam_unhealthy) flags += '<span class="badge warn">STEAM DEGRADED</span> ';
    if (d.example_mode) flags += '<span class="badge warn">EXAMPLE MODE</span>';
    document.getElementById('flags').innerHTML = flags;
    const grid = document.getElementById('servers');
    if (!d.servers || !d.servers.length){
      grid.innerHTML = '<div class="mut">No servers yet — waiting for first cycle (or add servers in the Servers tab).</div>';
      return;
    }
    grid.innerHTML = d.servers.map(s=>{
      const badge = s.up ? '<span class="badge ok">UP</span>'
                  : (s.down_marked ? '<span class="badge bad">DOWN</span>' : '<span class="badge warn">UNSTABLE</span>');
      const players = (s.player_names && s.player_names.length)
        ? `<details><summary>${s.player_names.length} player name(s)</summary><ul>` +
          s.player_names.map(p=>`<li>${esc(p)}</li>`).join('') + '</ul></details>' : '';
      return `<div class="card"><h3>${esc(s.name)} ${badge}</h3>
        <div class="mut">${esc(s.ip)}:${esc(s.port)}${s.group?' • '+esc(s.group):''}</div>
        <div>${s.up ? '\u{1F4DC} '+esc(s.map)+'<br>\u{1F465} '+s.players+' / '+s.max_players
                    : 'Unreachable (streak: '+s.fail_streak+')'}</div>
        ${s.downtime_total ? '<div class="mut">Total downtime events: '+s.downtime_total+'</div>' : ''}
        ${players}</div>`;
    }).join('');
  }catch(e){}
}

// ---- Servers tab ----
let serversCache = [], editIndex = -1, editOrig = null;

async function loadServers(){
  try{
    const r = await api('/api/servers'); if(!r.ok) return;
    serversCache = await r.json();
    let live = {};
    try{ const s = await (await api('/api/status')).json();
         (s.servers||[]).forEach(x=>live[x.ip+':'+x.port]=x); }catch(e){}
    const grid = document.getElementById('srvlist');
    if (!serversCache.length){
      grid.innerHTML = '<div class="mut">No servers configured yet — click "Add server".</div>';
      return;
    }
    grid.innerHTML = serversCache.map((s,i)=>{
      const st = live[s.ip+':'+s.port];
      const badge = !st ? '<span class="badge warn">PENDING</span>'
        : st.up ? '<span class="badge ok">UP</span>'
        : st.down_marked ? '<span class="badge bad">DOWN</span>' : '<span class="badge warn">UNSTABLE</span>';
      const tags = [];
      if (s.restart) tags.push('restarts '+esc(s.restart_hour)+':'+esc(s.restart_minute)+(s.timezone?' '+esc(s.timezone):''));
      if (s.disable_pings) tags.push('pings off');
      if (s.webhooks && s.webhooks.length) tags.push(s.webhooks.length+' extra webhook(s)');
      if (s.downtime_counter) tags.push('downtime counter');
      return `<div class="card"><h3>${esc(s.name)||'(unnamed)'} ${badge}</h3>
        <div class="mut">${esc(s.ip)}:${esc(s.port)}${s.group?' • '+esc(s.group):''}${s.owner?' • admin: '+esc(s.owner):''}${s.created_by_name?' • by '+esc(s.created_by_name):''}</div>
        ${tags.length?'<div class="mut">'+tags.join(' • ')+'</div>':''}
        ${s._can_edit ? `<div style="margin-top:8px"><button class="act" onclick="openEditor(${i})">Edit</button>
        <button class="act warn" onclick="delServer(${i})">Remove</button></div>` : ''}</div>`;
    }).join('');
  }catch(e){}
}

function toggleRestart(){
  document.getElementById('restartrow').style.opacity =
    document.getElementById('f_restart').checked ? '1' : '0.4';
}
function closeModal(){
  document.getElementById('modal').hidden = true;
  document.getElementById('emojipicker').hidden = true;
}

async function openEditor(i){
  editIndex = i;
  editOrig = i >= 0 ? serversCache[i] : null;
  const s = editOrig || {};
  try{ const r = await api('/api/groups'); if (r.ok) groupsCache = await r.json(); }catch(e){}
  const set = (id,v)=>{document.getElementById(id).value = (v==null?'':v);};
  set('f_name', s.name); set('f_ip', s.ip); set('f_port', s.port);
  populateGroupSelect((s.group||'').trim());
  set('f_owner', s.owner); set('f_emoji', s.emoji);
  set('f_icon', s.icon_url); set('f_maxp', s.max_players);
  set('f_webhook', s.webhook_url);
  set('f_webhooks', (s.webhooks||[]).join('\n'));
  set('f_role', s.ping_role_id); set('f_ping', s.ping_id);
  const tri = (id,v)=>{document.getElementById(id).value = (v===undefined||v===null)?'':String(!!v);};
  tri('f_disable', s.disable_pings); tri('f_showp', s.show_players);
  tri('f_showv', s.show_visibility); tri('f_dtc', s.downtime_counter);
  tri('f_ghost', s.ghost_player_fix);
  document.getElementById('f_restart').checked = !!s.restart;
  set('f_rh', s.restart_hour); set('f_rm', s.restart_minute); set('f_tz', s.timezone);
  toggleRestart();
  const cb = document.getElementById('createdby');
  cb.textContent = editOrig
    ? (s.created_by ? ('Created by: ' + (s.created_by_name || s.created_by)) : 'Legacy entry — any manager can edit')
    : 'This server will be recorded as created by you.';
  let ulist = [];
  try{ const r2 = await api('/api/users/simple'); if (r2.ok) ulist = await r2.json(); }catch(e){}
  document.getElementById('editorchecks').innerHTML = ulist.length
    ? '<div class="mut" style="margin-bottom:4px">Additional editors (besides the creator and admins):</div>' +
      ulist.map(u=>`<label style="display:inline-flex;align-items:center;gap:6px;margin:2px 12px 2px 0;font-size:13px;color:var(--fg)">
        <input type="checkbox" value="${esc(u.steamid)}" ${(s.editors||[]).includes(u.steamid)?'checked':''} style="width:auto">${esc(u.name)}</label>`).join('')
    : '<span class="mut">No Steam users yet — add users (Users tab) to grant per-server edit access.</span>';
  document.getElementById('mtitle').textContent = i>=0 ? 'Edit server — '+(s.name||'') : 'Add server';
  document.getElementById('mmsg').innerHTML = '';
  document.getElementById('modal').hidden = false;
}

function collectServer(){
  // Start from a copy of the original so custom/unknown JSON keys survive edits.
  const o = Object.assign({}, editOrig || {});
  const v = id => document.getElementById(id).value.trim();
  o.name = v('f_name'); o.ip = v('f_ip');
  o.port = parseInt(v('f_port'), 10) || 0;
  const optStr = (key,id)=>{const x=v(id); if(x) o[key]=x; else delete o[key];};
  let grp = document.getElementById('f_group').value;
  if (grp === '__custom__') grp = v('f_group_custom');
  if (grp) o.group = grp; else delete o.group;
  optStr('owner','f_owner'); optStr('emoji','f_emoji');
  optStr('icon_url','f_icon'); optStr('webhook_url','f_webhook');
  optStr('ping_role_id','f_role'); optStr('ping_id','f_ping'); optStr('timezone','f_tz');
  const mp = v('f_maxp'); if (mp) o.max_players = parseInt(mp,10); else delete o.max_players;
  const hooks = v('f_webhooks').split('\n').map(x=>x.trim()).filter(Boolean);
  if (hooks.length) o.webhooks = hooks; else delete o.webhooks;
  delete o._can_edit;
  const eds = [...document.querySelectorAll('#editorchecks input:checked')].map(x=>x.value);
  if (eds.length) o.editors = eds; else delete o.editors;
  const tri = (key,id)=>{const x=v(id); if(x==='') delete o[key]; else o[key]=(x==='true');};
  tri('disable_pings','f_disable'); tri('show_players','f_showp');
  tri('show_visibility','f_showv'); tri('downtime_counter','f_dtc');
  tri('ghost_player_fix','f_ghost');
  if (document.getElementById('f_restart').checked){
    o.restart = true;
    o.restart_hour = v('f_rh'); o.restart_minute = v('f_rm');
  } else {
    delete o.restart; delete o.restart_hour; delete o.restart_minute;
    if (!v('f_tz')) delete o.timezone;
  }
  return o;
}

async function saveServer(){
  const el = document.getElementById('mmsg');
  const o = collectServer();
  if (!o.name || !o.ip || !o.port){
    el.innerHTML = '<div class="err">Name, IP and port are required.</div>'; return;
  }
  try{
    const r = editIndex >= 0
      ? await api('/api/servers/'+editIndex, {method:'PUT', body: JSON.stringify(o)})
      : await api('/api/servers', {method:'POST', body: JSON.stringify(o)});
    const d = await r.json().catch(()=>({}));
    if (r.ok){
      if (document.getElementById('f_group').value === '__custom__' && o.group){
        api('/api/groups', {method:'POST', body: JSON.stringify({name: o.group})}).catch(()=>{});
      }
      closeModal(); loadServers();
    }
    else el.innerHTML = '<div class="err">'+esc(d.error || 'save failed')+'</div>';
  }catch(e){}
}

async function delServer(i){
  const s = serversCache[i] || {};
  if (!confirm('Remove "'+(s.name||'server')+'"?\nIts Discord status message is cleaned up automatically on the next cycle.')) return;
  try{
    const r = await api('/api/servers/'+i, {method:'DELETE'});
    if (r.ok) loadServers();
  }catch(e){}
}

// ---- Groups tab: group presets ----
let groupsCache = {defined: [], in_use: {}};
function defMap(){const m={};(groupsCache.defined||[]).forEach(g=>m[g.name]=g.emoji||'');return m;}

function populateGroupSelect(current){
  const sel = document.getElementById('f_group');
  const dm = defMap();
  const all = [...new Set([...Object.keys(dm), ...Object.keys(groupsCache.in_use||{})])].sort();
  if (current && !all.includes(current)) all.push(current);
  sel.innerHTML = '<option value="">(no group — own embed)</option>' +
    all.map(g=>`<option value="${esc(g)}">${esc((dm[g]?dm[g]+' ':'')+g)}</option>`).join('') +
    '<option value="__custom__">Custom…</option>';
  sel.value = current || '';
  document.getElementById('f_group_custom').value = '';
  groupSelChange();
}
function groupSelChange(){
  document.getElementById('f_group_custom').style.display =
    document.getElementById('f_group').value === '__custom__' ? '' : 'none';
}

async function loadGroups(){
  try{
    const r = await api('/api/groups'); if(!r.ok) return;
    groupsCache = await r.json();
    const dm = defMap();
    const ul = document.getElementById('grouplist');
    const all = [...new Set([...Object.keys(dm), ...Object.keys(groupsCache.in_use||{})])].sort();
    if (!all.length){ ul.innerHTML = '<li class="mut">No groups yet — add one above.</li>'; return; }
    ul.innerHTML = all.map((g,i)=>{
      const n = groupsCache.in_use[g] || 0;
      const isPreset = g in dm;
      return `<li style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid #2a2e3d">
        <span style="min-width:26px;text-align:center;font-size:18px">${esc(dm[g]||'')}</span>
        <span>${esc(g)}</span>
        <span class="mut">${n} server(s)${isPreset ? '' : ' • in use only'}</span>
        ${!can('groups.manage') ? '' : isPreset
          ? `<button class="act ghost" style="margin-left:auto;padding:4px 10px" data-em="${i}" title="Set emoji">😀</button>
             <button class="act warn" style="padding:4px 10px" data-del="${i}">Delete</button>`
          : `<button class="act ghost" style="margin-left:auto;padding:4px 10px" data-add="${i}">Save as preset</button>`}
      </li>`;
    }).join('');
    ul.querySelectorAll('button[data-del]').forEach(b=>b.onclick=()=>delGroup(all[+b.dataset.del]));
    ul.querySelectorAll('button[data-add]').forEach(b=>b.onclick=()=>addGroup(all[+b.dataset.add]));
    ul.querySelectorAll('button[data-em]').forEach(b=>b.onclick=ev=>{
      const name = all[+b.dataset.em];
      toggleEmojiPicker(ev, async em=>{
        await api('/api/groups/update', {method:'POST', body: JSON.stringify({name, emoji: em})});
        loadGroups();
      });
    });
  }catch(e){}
}

async function addGroup(name){
  let emoji = '';
  if (typeof name !== 'string'){
    name = document.getElementById('newgroup').value;
    emoji = document.getElementById('newgroupemoji').value.trim();
  }
  name = (name || '').trim();
  if (!name) return;
  try{
    const r = await api('/api/groups', {method:'POST', body: JSON.stringify({name, emoji})});
    const d = await r.json().catch(()=>({}));
    document.getElementById('grpmsg').innerHTML = r.ok ? '' : '<div class="err">'+esc(d.error||'failed')+'</div>';
    if (r.ok){
      document.getElementById('newgroup').value = '';
      document.getElementById('newgroupemoji').value = '';
      loadGroups();
    }
  }catch(e){}
}

async function delGroup(name){
  if (!confirm('Delete group preset "'+name+'"?\nServers already using it are not changed.')) return;
  try{
    await api('/api/groups/delete', {method:'POST', body: JSON.stringify({name})});
    loadGroups();
  }catch(e){}
}

// ---- Emoji picker: full set via emoji-picker-element (CDN), curated fallback ----
const EMOJIS = {
  "Status": ["✅","❌","⚠️","🟢","🟡","🔴","🟠","🔵","🟣","⚪","⚫","🟥","🟧","🟨","🟩","🟦","🟪","🚨","🔔","📢"],
  "Games & combat": ["🎮","🕹️","👾","🎯","🎲","🏆","🥇","🥈","🥉","⚔️","🗡️","🛡️","🏹","💣","🔫","🧨","🪓","🚀","🛸","🏰"],
  "Tech": ["💻","🖥️","🖱️","⌨️","📡","🛰️","💿","💾","🔌","🔋","⚙️","🔧","🔨","🛠️","📦","🗄️","🌐","📶","🧭","🗺️"],
  "Faces & spooky": ["😀","😄","😁","😂","🙂","😉","😊","😍","😎","🤩","🤔","😤","😈","🤖","👻","💀","☠️","🤡","👽","🎃"],
  "Animals": ["🐶","🐱","🦊","🐺","🐻","🐼","🦁","🐯","🐸","🐍","🦅","🦉","🐉","🦖","🦈","🐙","🦀","🐢","🐬","🐧"],
  "Nature": ["🔥","💧","🌊","⚡","❄️","🌪️","🌋","⛰️","🌲","🌵","🌙","☀️","⭐","🌟","💫","☄️","🌈","🌍","🪐","🌌"],
  "Symbols": ["❤️","🧡","💛","💚","💙","💜","🖤","💯","✨","💥","💢","❗","❓","♻️","🔱","⚜️","🔰","♠️","♥️","🎵"]
};

let emojiTarget = null; // input element id OR callback(emoji)
function applyEmoji(em){
  if (typeof emojiTarget === 'function') emojiTarget(em);
  else if (emojiTarget){ const el = document.getElementById(emojiTarget); if (el) el.value = em; }
  document.getElementById('emojipicker').hidden = true;
}
function buildCurated(p){
  const wrap = document.createElement('div');
  wrap.style.cssText = 'width:300px;max-height:300px;overflow:auto;padding:8px';
  wrap.innerHTML = Object.entries(EMOJIS).map(([cat, list]) =>
    `<div class="mut" style="margin:6px 2px 2px">${cat}</div><div>` +
    list.map(e=>`<span class="emoji-opt" style="cursor:pointer;font-size:20px;padding:3px;display:inline-block">${e}</span>`).join('') +
    '</div>').join('');
  wrap.querySelectorAll('.emoji-opt').forEach(el=>el.onclick=()=>applyEmoji(el.textContent));
  p.appendChild(wrap);
}
async function ensurePicker(){
  const p = document.getElementById('emojipicker');
  if (p.dataset.ready) return;
  p.dataset.ready = '1';
  try{
    // Full emoji set (search, categories, skin tones) — same coverage as Discord's default emojis
    await import('https://cdn.jsdelivr.net/npm/emoji-picker-element@1/index.js');
    const ep = document.createElement('emoji-picker');
    ep.classList.add('dark');
    ep.style.cssText = 'height:390px;--background:#0d0f14;--border-color:#333;--input-border-color:#333;--input-font-color:#e8eaf0;--category-font-color:#8b90a0';
    ep.addEventListener('emoji-click', e=>applyEmoji(e.detail.unicode));
    p.appendChild(ep);
  }catch(err){
    buildCurated(p); // offline / CDN blocked — curated fallback still works
  }
}
async function toggleEmojiPicker(ev, target){
  ev.preventDefault(); ev.stopPropagation();
  emojiTarget = target || 'f_emoji';
  const p = document.getElementById('emojipicker');
  if (!p.hidden){ p.hidden = true; return; }
  await ensurePicker();
  const r = ev.target.getBoundingClientRect();
  p.style.top = Math.max(8, Math.min(window.innerHeight - 410, r.bottom + 6)) + 'px';
  p.style.left = Math.max(8, Math.min(window.innerWidth - 370, r.left - 160)) + 'px';
  p.hidden = false;
}
document.addEventListener('click', ev=>{
  const p = document.getElementById('emojipicker');
  if (!p.hidden && !p.contains(ev.target)) p.hidden = true;
});

// ---- Users tab (admin) ----
async function loadUsers(){
  try{
    const r = await api('/api/users'); if(!r.ok) return;
    const d = await r.json();
    const rows = Object.entries(d.users || {});
    const el = document.getElementById('userlist');
    if (!rows.length){
      el.innerHTML = '<div class="mut">No users yet — add a SteamID64 above. Password login stays available as break-glass admin.</div>';
      return;
    }
    el.innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:13px">' +
      '<tr class="mut" style="text-align:left"><th style="padding:6px">User</th><th>SteamID64</th><th>Role</th><th>Last login</th><th></th></tr>' +
      rows.map(([sid,u])=>`<tr style="border-top:1px solid #2a2e3d">
        <td style="padding:6px">${u.avatar?`<img src="${esc(u.avatar)}" style="width:22px;height:22px;border-radius:4px;vertical-align:middle;margin-right:6px">`:''}${esc(u.name||'(unknown)')}</td>
        <td class="mut">${esc(sid)}</td>
        <td><select class="rolesel" data-sid="${esc(sid)}" style="width:auto">${(d.roles||[]).map(x=>`<option ${x===u.role?'selected':''}>${x}</option>`).join('')}</select></td>
        <td class="mut">${u.last_login?fmtAgo(u.last_login):'never'}</td>
        <td style="text-align:right"><button class="act warn" style="padding:4px 10px" data-usdel="${esc(sid)}">Remove</button></td>
      </tr>`).join('') + '</table>';
    el.querySelectorAll('.rolesel').forEach(s=>s.onchange=async()=>{
      const r2 = await api('/api/users/update', {method:'POST', body: JSON.stringify({steamid: s.dataset.sid, role: s.value})});
      const d2 = await r2.json().catch(()=>({}));
      document.getElementById('usermsg').innerHTML = r2.ok ? '' : '<div class="err">'+esc(d2.error||'update failed')+'</div>';
      loadUsers();
    });
    el.querySelectorAll('button[data-usdel]').forEach(b=>b.onclick=async()=>{
      if (!confirm('Remove this user? Their active sessions end immediately.')) return;
      const r2 = await api('/api/users/delete', {method:'POST', body: JSON.stringify({steamid: b.dataset.usdel})});
      const d2 = await r2.json().catch(()=>({}));
      document.getElementById('usermsg').innerHTML = r2.ok ? '' : '<div class="err">'+esc(d2.error||'delete failed')+'</div>';
      loadUsers();
    });
  }catch(e){}
}
async function addUser(){
  const sid = document.getElementById('newuser_sid').value.trim();
  const role = document.getElementById('newuser_role').value;
  try{
    const r = await api('/api/users', {method:'POST', body: JSON.stringify({steamid: sid, role})});
    const d = await r.json().catch(()=>({}));
    document.getElementById('usermsg').innerHTML = r.ok ? '' : '<div class="err">'+esc(d.error||'add failed')+'</div>';
    if (r.ok){ document.getElementById('newuser_sid').value = ''; loadUsers(); }
  }catch(e){}
}

// ---- Messages tab: downtime pings ----
async function loadPings(){
  try{
    const r = await api('/api/pings'); if(!r.ok) return;
    const d = await r.json();
    const el = document.getElementById('pinglist');
    if (!(d.pings||[]).length){ el.innerHTML = '<div class="mut">No active downtime ping messages.</div>'; return; }
    el.innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:13px">' +
      '<tr class="mut" style="text-align:left"><th style="padding:6px">Server</th><th>Address</th><th>Status</th><th>Message ID</th><th>Webhook</th><th></th></tr>' +
      d.pings.map(p=>`<tr style="border-top:1px solid #2a2e3d">
        <td style="padding:6px">${esc(p.server||'(removed from config)')}</td>
        <td class="mut">${esc(p.key)}</td>
        <td>${p.marked_down?'<span class="badge bad">DOWN</span>':'<span class="badge warn">STALE?</span>'}${p.still_configured?'':' <span class="mut">not in config</span>'}</td>
        <td class="mut">${esc(p.message_id)}</td>
        <td class="mut">${esc(p.webhook_hint||'')}</td>
        <td style="text-align:right"><button class="act warn" style="padding:4px 10px" data-rv="${esc(p.key)}">Revoke</button></td>
      </tr>`).join('') + '</table>';
    el.querySelectorAll('button[data-rv]').forEach(b=>b.onclick=async()=>{
      if (!confirm('Revoke this downtime ping?\nThe Discord message is deleted and the record cleared. If the server is still down, a fresh ping may be posted later.')) return;
      const r2 = await api('/api/pings/delete', {method:'POST', body: JSON.stringify({key: b.dataset.rv})});
      const d2 = await r2.json().catch(()=>({}));
      document.getElementById('pingmsg').innerHTML = r2.ok
        ? '<div class="okmsg">Revoked.'+(d2.discord_deleted?'':' (record cleared; the Discord delete failed — check Logs)')+'</div>'
        : '<div class="err">'+esc(d2.error||'revoke failed')+'</div>';
      loadPings();
    });
  }catch(e){}
}

// ---- Settings tab (admin) ----
let settingsSpec = {};
async function loadSettings(){
  try{
    const r = await api('/api/settings'); if(!r.ok) return;
    const d = await r.json();
    settingsSpec = d.spec;
    document.getElementById('settingsform').innerHTML = Object.entries(d.spec).map(([k,s])=>{
      const v = d.settings[k];
      if (s.type === 'bool')
        return `<label style="display:flex;align-items:center;gap:8px;margin:10px 0;color:var(--fg);font-size:13px">
          <input type="checkbox" id="set_${k}" ${v?'checked':''} style="width:auto"> ${esc(s.label)}</label>`;
      return `<label>${esc(s.label)} <span class="mut">(${s.min}&ndash;${s.max})</span></label>
        <input type="number" id="set_${k}" value="${v}" min="${s.min}" max="${s.max}" style="max-width:160px;margin-bottom:6px">`;
    }).join('');
    document.getElementById('setmsg').innerHTML = '';
  }catch(e){}
}
async function saveSettings(){
  const body = {};
  Object.entries(settingsSpec).forEach(([k,s])=>{
    const el = document.getElementById('set_'+k);
    if (el) body[k] = s.type === 'bool' ? el.checked : parseInt(el.value, 10);
  });
  try{
    const r = await api('/api/settings', {method:'POST', body: JSON.stringify(body)});
    const d = await r.json().catch(()=>({}));
    document.getElementById('setmsg').innerHTML = r.ok
      ? '<span class="okmsg"> Saved &amp; applied.</span>'
      : '<span class="err"> '+esc(d.error||'save failed')+'</span>';
  }catch(e){}
}

// ---- Steam persona refresh ----
async function refreshUsers(){
  try{
    const r = await api('/api/users/refresh', {method:'POST', body:'{}'});
    const d = await r.json().catch(()=>({}));
    document.getElementById('usermsg').innerHTML = r.ok
      ? '<div class="okmsg">Refreshed '+d.updated+' user(s) from Steam.</div>'
      : '<div class="err">'+esc(d.error||'refresh failed')+'</div>';
    if (r.ok) loadUsers();
  }catch(e){}
}

// ---- Advanced tab ----
async function loadCfg(){
  try{
    const r = await api('/api/config'); if(!r.ok) return;
    const txt = await r.text();
    try{ document.getElementById('cfg').value = JSON.stringify(JSON.parse(txt), null, 2); }
    catch(e){ document.getElementById('cfg').value = txt; }
    document.getElementById('cfgmsg').innerHTML = '';
  }catch(e){}
}
async function saveCfg(){
  const el = document.getElementById('cfgmsg');
  let data;
  try{ data = JSON.parse(document.getElementById('cfg').value); }
  catch(e){ el.innerHTML = '<div class="err">Invalid JSON: '+esc(e.message)+'</div>'; return; }
  try{
    const r = await api('/api/config', {method:'POST', body: JSON.stringify(data)});
    const d = await r.json().catch(()=>({}));
    el.innerHTML = r.ok ? '<div class="okmsg">Saved '+d.servers+' server(s). Applied next cycle.</div>'
                        : '<div class="err">'+esc(d.error || 'save failed')+'</div>';
  }catch(e){}
}

// ---- Logs & controls ----
async function loadLogs(){
  try{
    const r = await api('/api/logs'); if(!r.ok) return;
    const d = await r.json();
    const keys = Object.keys(d.alerts || {});
    document.getElementById('alerts').innerHTML = keys.length
      ? '<div class="card" style="margin-bottom:10px"><h3>Active alerts</h3><ul>' +
        keys.map(k=>`<li>${esc(k)}</li>`).join('') + '</ul></div>' : '';
    const pre = document.getElementById('loglines');
    pre.textContent = (d.lines || []).join('\n') || '(no log lines yet)';
    pre.scrollTop = pre.scrollHeight;
  }catch(e){}
}
async function ctl(action){
  try{
    const r = await api('/api/control/'+action, {method:'POST', body:'{}'});
    document.getElementById('ctlmsg').innerHTML = r.ok
      ? '<span class="okmsg">'+action.replace('_',' ')+': OK</span>'
      : '<span class="err">'+action+' failed</span>';
  }catch(e){}
}
async function selftest(){
  const target = document.getElementById('selftarget').value.trim();
  const el = document.getElementById('ctlmsg');
  el.innerHTML = '<span class="mut">sending…</span>';
  try{
    const r = await api('/api/control/selftest', {method:'POST', body: JSON.stringify({target})});
    const d = await r.json().catch(()=>({}));
    el.innerHTML = r.ok ? '<span class="okmsg">Selftest delivered '+d.delivered+'/'+d.total+'</span>'
                        : '<span class="err">'+esc(d.error || 'selftest failed')+'</span>';
  }catch(e){}
}

const _qs = new URLSearchParams(location.search);
if (_qs.get('steam')){
  document.getElementById('lmsg').textContent =
    _qs.get('steam') === 'notauthorized'
      ? 'Your Steam account is not on the user list — ask an admin to add your SteamID64.'
      : 'Steam sign-in failed — please try again.';
  history.replaceState(null, '', '/');
}
loadMe().then(()=>loadStatus());
setInterval(()=>{ if(activeTab()==='status') loadStatus(); }, 10000);
setInterval(()=>{ if(activeTab()==='logs') loadLogs(); }, 10000);
setInterval(()=>{ if(activeTab()==='servers') loadServers(); }, 15000);
</script></body></html>"""

# === MAIN ===
if __name__ == "__main__":
    logger.info("[INIT] Starting Discord-A2S-QueryBot v2.3.4 (user-config at top)")

    # Graceful shutdown: flush state
    def _graceful_exit(signum, frame):
        logger.info("[SHUTDOWN] Signal %s received. Saving state…", signum)
        try:
            save_json("server_down.json", server_down)
            save_json("has_pinged_down.json", has_pinged_down)
            save_json("message_ids.json", message_ids)
            save_json("ping_message_ids.json", ping_message_ids)
            _save_downtime_counters()  # flush persistent downtime counters
            _save_net_state()
        finally:
            sys.exit(0)
    for _sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if _sig:
            signal.signal(_sig, _graceful_exit)
    servers, example_mode = load_servers_and_detect_example_mode()

    validate_config(servers)

    # Initialize per-server state

    # Reconcile 'has_pinged_down' flags with stored ping message ids at startup.
    _reconciled = False
    for _rk, _flag in list(has_pinged_down.items()):
        if _flag and _rk not in ping_message_ids:
            has_pinged_down[_rk] = False
            _reconciled = True
    if _reconciled:
        save_json("has_pinged_down.json", has_pinged_down)
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

    start_web_ui()

    # Main loop
    while True:

        # Hot reload servers.json each cycle
        servers, example_mode = load_servers_and_detect_example_mode()


        # Runtime backfill: ensure ping_routes exist for any existing ping messages (first loop & hot-reloads)
        try:
            _added_rt = False
            # Build quick ip:port -> server map for this cycle
            _srv_index = {f"{_s.get('ip')}:{int(_s.get('port', 0))}": _s for _s in servers if _s.get('ip') and _s.get('port')}
            for _key in list(ping_message_ids.keys()):
                if _key not in ping_routes:
                    _s = _srv_index.get(_key)
                    if _s:
                        _wh = _server_primary_webhook(_s)
                        if _wh and not _is_placeholder_webhook(_wh):
                            ping_routes[_key] = _wh
                            _added_rt = True
            if _added_rt:
                save_json("ping_routes.json", ping_routes)
        except Exception:
            pass

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
        _web_servers = []

        for s in servers:
            name = s["name"]
            ip, port = s["ip"], s["port"]
            key = make_server_key(ip, port)

            stats = fetch_stats(ip, port)
            _wpc = (stats or {}).get("players", 0)
            if stats and not stats.get("player_names") and bool(s.get("ghost_player_fix", GHOST_PLAYER_FIX_BY_DEFAULT)):
                _wpc = 0
            _web_servers.append({
                "name": name, "ip": ip, "port": port,
                "group": get_display_group(s),
                "up": bool(stats),
                "map": (stats or {}).get("map"),
                "players": _wpc,
                "max_players": (stats or {}).get("max_players", s.get("max_players", 0)),
                "player_names": (stats or {}).get("player_names", []),
                "down_marked": bool(server_down.get(key, False)),
                "fail_streak": int(downtime_counter.get(key, 0)),
                "downtime_total": get_downtime_count_for(s),
            })
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
                
                    # Clean up ping message only if it existed (won't for disable_pings)
                    if key in ping_message_ids:
                        try:
                            delete_ping_url = ping_routes.get(key, _server_primary_webhook(s))
                            msg_id = ping_message_ids.get(key)
                            if msg_id and delete_ping_url and not _is_placeholder_webhook(delete_ping_url):
                                delete_discord_message(msg_id, delete_ping_url, label=f"recovered ping {key}")
                        except Exception:
                            pass
                
                        ping_message_ids.pop(key, None)
                        ping_routes.pop(key, None)
                        save_json("ping_message_ids.json", ping_message_ids)
                        save_json("ping_routes.json", ping_routes)
                
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
                    # Mark server as down
                    if not server_down.get(key, False):
                        server_down[key] = True
                
                    # NEW: disable_pings flag
                    pings_disabled = bool(s.get("disable_pings", False))
                
                    # If pings are disabled, do NOT post downtime pings
                    if pings_disabled:
                        has_pinged_down[key] = False
                    else:
                        # Normal ping behavior
                        if not has_pinged_down.get(key, False):
                            if key not in ping_message_ids:
                                pid = post_ping(s)
                                if pid:
                                    ping_message_ids[key] = pid
                                    has_pinged_down[key] = True
                                    save_json("has_pinged_down.json", has_pinged_down)
                                    webhook_url = _server_primary_webhook(s)
                                    ping_routes[key] = webhook_url
                                    save_json("ping_message_ids.json", ping_message_ids)
                                    save_json("ping_routes.json", ping_routes)
                                    _inc_downtime_counter_for(s)
                
# If we haven't sent a downtime ping yet, keep this server visible with an unreachable banner
                if not has_pinged_down.get(key, False):
                    display_stats = {
                        "name": s.get("name"),
                        "map": UNREACHABLE_MAP,
                        "players": 0,
                        "max_players": s.get("max_players", 0),
                        "player_names": [],
                        "password_protected": None,
                        "queried_name": s.get("name"),
                    }
                    hooks = s.get("webhooks") or [s.get("webhook_url", DEFAULT_WEBHOOK_URL)]
                    for server_hook in hooks:
                        merge_key = get_merge_group_key(s)
                        rk = route_key(merge_key, server_hook)
                        grouped_routes.setdefault(rk, []).append((s, display_stats))

        logger.info("[CYCLE] Up: %s  Down: %s  Routes: %s", up_count, down_count, len(grouped_routes))
        WEB_STATE.update({
            "servers": _web_servers,
            "last_cycle": time.time(),
            "up": up_count,
            "down": down_count,
            "steam_unhealthy": bool(steam_unhealthy),
            "net_freeze": bool(NET_FREEZE_ACTIVE),
            "example_mode": bool(example_mode),
        })

        # (v2.3.0) The optional STALE_PURGE block that lived here was removed — the
        # route reconciliation at the top of the loop already deletes messages for
        # stale/changed routes every cycle.

        # --- Build and send/edit embeds per route ---        # --- Build and send/edit embeds per route ---
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
                # Only annotate GROUPED routes. Appending to an empty label made it
                # truthy, which flipped ungrouped servers into the consolidated group
                # layout while unreachable — the "random formatting change" bug.
                if display_label and all((ps.get('map') == UNREACHABLE_MAP) for (_sv, ps) in pairs):
                    display_label += ' ⚠️ Temporarily unreachable'
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

        FORCE_REFRESH.wait(INTERVAL_SECONDS)  # interruptible: web UI "Refresh now"
        FORCE_REFRESH.clear()