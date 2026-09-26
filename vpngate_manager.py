#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import secrets
import select
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

import global_exit
import singbox_exit
import speedtest

# Mark every urllib connection the manager (and vpn_utils) makes so that the
# global-exit policy routing keeps management traffic on the physical NIC.
global_exit.install_marked_urllib_opener()

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server
import snapshot_utils

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

def ports_conflict(web_port: Any, proxy_port: Any) -> bool:
    try:
        return int(web_port) == int(proxy_port)
    except (TypeError, ValueError):
        return False

API_HTTPS_URL = os.environ.get("VPNGATE_API_HTTPS_URL", "https://www.vpngate.net/api/iphone/").strip()
API_HTTP_URL = os.environ.get("VPNGATE_API_HTTP_URL", "http://www.vpngate.net/api/iphone/").strip()
MIRROR_HTTPS_URL = os.environ.get(
    "VPNGATE_MIRROR_HTTPS_URL",
    "https://baoweise-bot.github.io/aimili-vpngate/vpngate.csv",
).strip()
MIRROR_HTTP_URL = os.environ.get(
    "VPNGATE_MIRROR_HTTP_URL",
    "http://baoweise-bot.github.io/aimili-vpngate/vpngate.csv",
).strip()
MIRROR_META_URL = os.environ.get(
    "VPNGATE_MIRROR_META_URL",
    "https://baoweise-bot.github.io/aimili-vpngate/vpngate.meta.json",
).strip()
# Kept as the primary URL for diagnostics and backwards-compatible state output.
API_URL = API_HTTPS_URL
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
API_FETCH_TIMEOUT_SECONDS = env_int("API_FETCH_TIMEOUT_SECONDS", 10, 1, 60)
API_SOURCE_DEADLINE_SECONDS = env_int("API_SOURCE_DEADLINE_SECONDS", 6, 2, 30)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
MANUAL_TEST_NODE_LIMIT = env_int("MANUAL_TEST_NODE_LIMIT", 5, 1, 20)
INITIAL_CONNECT_TEST_LIMIT = env_int("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50)
NODE_PROBE_WORKERS = env_int("NODE_PROBE_WORKERS", 10, 1, 20)
PROXY_FAILURE_THRESHOLD = env_int("PROXY_FAILURE_THRESHOLD", 3, 1, 10)
SWITCH_PREFLIGHT_MAX_AGE_SECONDS = env_int("SWITCH_PREFLIGHT_MAX_AGE_SECONDS", 180, 0, 3600)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8787, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)
DEPLOYMENT_MODE = os.environ.get("DEPLOYMENT_MODE", "source").strip().lower()
if DEPLOYMENT_MODE not in {"source", "docker"}:
    DEPLOYMENT_MODE = "source"
DEPLOYMENT_MODE_LABEL = "Docker 容器" if DEPLOYMENT_MODE == "docker" else "Python 源码"
UPDATE_COMMAND = (
    "docker compose pull && docker compose up -d"
    if DEPLOYMENT_MODE == "docker"
    else "ml update"
)

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DEFAULT_APP_VERSION = "2.2.0"
try:
    _version_text = (ROOT_DIR / "VERSION").read_text(encoding="utf-8").strip()
except OSError:
    _version_text = DEFAULT_APP_VERSION
APP_VERSION = _version_text if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", _version_text) else DEFAULT_APP_VERSION
APP_VERSION_LABEL = f"V{APP_VERSION} 正式版"
GITHUB_REPOSITORY = "kadidalax/aimili-vpngate"
GITHUB_REPOSITORY_URL = f"https://github.com/{GITHUB_REPOSITORY}"
GITHUB_MAIN_BRANCH_URL = f"{GITHUB_REPOSITORY_URL}/tree/main"
GITHUB_LATEST_RELEASE_API = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest"
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
API_CACHE_FILE = DATA_DIR / "api_snapshot.csv"
API_CACHE_META_FILE = DATA_DIR / "api_snapshot.meta.json"
BUNDLED_SNAPSHOT_FILE = ROOT_DIR / "mirror" / "vpngate.csv"
SPEED_HISTORY_FILE = DATA_DIR / "speed_history.json"
SPEED_HISTORY_PER_NODE = 10
SPEED_HISTORY_MAX_NODES = 300
SPEED_HISTORY_MSG_LIMIT = 160
WEB_LOG_MAX_ENTRIES = 500

lock = threading.RLock()
maintenance_lock = threading.Lock()
connection_attempt_lock = threading.Lock()
background_refill_lock = threading.Lock()
background_refill_cancel_event = threading.Event()
background_refill_thread: threading.Thread | None = None
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
pending_openvpn_process: subprocess.Popen[str] | None = None
active_connection_cancel_event: threading.Event | None = None
connection_epoch = 0
active_openvpn_node_id = ""
is_connecting = False
last_active_ping_time = 0.0
last_active_latency = 0
consecutive_proxy_failures = 0
last_proxy_failure_node_id = ""

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0

PIPELINE_TRIGGERS = ("periodic", "manual_update", "manual_speedtest", "forced")
PIPELINE_STAGES = ("idle", "fetch", "probe", "speedtest", "switch")
RUNTIME_STATE_KEYS = ("pipeline", "singbox_exit", "global_exit", "speedtest_settings", "check_interval_hours", "speed_history")

def new_pipeline_status() -> dict[str, Any]:
    return {
        "running": False,
        "run_id": "",
        "trigger": "",
        "stage": "idle",
        "with_speedtest": False,
        "started_at": 0.0,
        "finished_at": 0.0,
        "probe_total": 0,
        "probe_done": 0,
        "speed_total": 0,
        "speed_done": 0,
        "current_node_id": "",
        "best_node_id": "",
        "best_speed_mbps": 0.0,
        "stop_requested": False,
        "stopped_reason": "",
        "message": "",
    }

pipeline_status: dict[str, Any] = new_pipeline_status()
pipeline_cancel_event = threading.Event()
collector_wakeup = threading.Event()
last_pipeline_end = 0.0
exit_runner = singbox_exit.CommandRunner()
exit_status: dict[str, dict[str, Any]] = {
    "singbox": {
        "supported": False, "unsupported_reason": "", "enabled": True, "applied": False,
        "service_active": None, "last_error": "", "config_path": "", "verified": None,
    },
    "global": {
        "supported": False, "unsupported_reason": "", "enabled": False, "applied": False,
        "last_error": "", "physical_interface": "", "physical_ips": [], "ssh_ports": [], "gateway": "",
    },
}

def pipeline_set(**fields: Any) -> None:
    with lock:
        pipeline_status.update(fields)

def pipeline_snapshot() -> dict[str, Any]:
    with lock:
        return json.loads(json.dumps(pipeline_status))
last_pinger_heartbeat = 0.0
server_start_time = time.time()
ip_enrichment_wakeup = threading.Event()

IP_ENRICHMENT_FIELDS = (
    "owner",
    "asn",
    "as_name",
    "location",
    "ip_type",
    "quality",
    "is_proxy",
    "is_hosting",
    "is_mobile",
    "ip_type_reason",
    "ip_type_confidence",
    "ip_type_sources",
    "geo_country_short",
)

class ConnectionCancelled(RuntimeError):
    pass

class SourceDeadlineExceeded(TimeoutError):
    pass

def purge_expired_sessions(now: float | None = None) -> int:
    current_time = time.time() if now is None else now
    with lock:
        expired_tokens = [
            token for token, expires_at in active_sessions.items()
            if expires_at <= current_time
        ]
        for token in expired_tokens:
            active_sessions.pop(token, None)
    return len(expired_tokens)

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        if path.name == "ui_auth.json":
            try:
                tmp.chmod(0o600)
            except OSError:
                pass
        tmp.replace(path)
        if path.name == "ui_auth.json":
            try:
                path.chmod(0o600)
            except OSError:
                pass

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

def read_speed_history() -> dict[str, list[dict[str, Any]]]:
    """读取测速历史。文件缺失、损坏或结构不对一律当空记录，绝不抛异常。"""
    try:
        try:
            with lock:
                raw: Any = json.loads(SPEED_HISTORY_FILE.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        if not isinstance(raw, dict):
            raise ValueError("speed history root is not an object")
        nodes = raw.get("nodes", {})
        if not isinstance(nodes, dict):
            raise ValueError("speed history nodes is not an object")
        cleaned: dict[str, list[dict[str, Any]]] = {}
        for node_id, records in nodes.items():
            if not isinstance(node_id, str) or not node_id or not isinstance(records, list):
                continue
            valid = [r for r in records if isinstance(r, dict)][-SPEED_HISTORY_PER_NODE:]
            if valid:
                cleaned[node_id] = valid
        return cleaned
    except Exception as exc:
        log_to_json("WARN", "SpeedHistory", f"读取测速历史失败，按空记录处理: {exc}")
        return {}

def append_speed_history(node_id: str, record: dict[str, Any]) -> None:
    """追加一条测速历史并原子落盘。任何异常只记 WARN，绝不影响测速流程。"""
    if not node_id or not isinstance(record, dict):
        return
    try:
        with lock:
            data = read_speed_history()
            records = list(data.get(node_id, []))
            stored = dict(record)
            msg = str(stored.get("msg") or "")
            if len(msg) > SPEED_HISTORY_MSG_LIMIT:
                stored["msg"] = msg[:SPEED_HISTORY_MSG_LIMIT] + "..."
            records.append(stored)
            data[node_id] = records[-SPEED_HISTORY_PER_NODE:]
            if len(data) > SPEED_HISTORY_MAX_NODES:
                def latest_ts(entries: list[dict[str, Any]]) -> float:
                    try:
                        return float(entries[-1].get("t") or 0)
                    except (TypeError, ValueError):
                        return 0.0
                for old_id in sorted(data, key=lambda key: latest_ts(data[key]))[: len(data) - SPEED_HISTORY_MAX_NODES]:
                    if old_id != node_id:
                        data.pop(old_id, None)
            write_json(SPEED_HISTORY_FILE, {"version": 1, "nodes": data})
    except Exception as exc:
        log_to_json("WARN", "SpeedHistory", f"写入测速历史失败: {exc}")

def speed_history_snapshot() -> dict[str, list[dict[str, Any]]]:
    return read_speed_history()

import hashlib

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(secrets.choice(chars) for _ in range(12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def normalize_discovery_countries(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        code = str(item or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code) or code in seen:
            continue
        normalized.append(code)
        seen.add(code)
        if len(normalized) >= 250:
            break
    return normalized

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT,
            "proxy_port": LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": False,
            "discovery_countries": [],
            "check_interval_hours": 24,
            "singbox_exit_enabled": True,
            "global_exit_enabled": False,
            "speedtest": speedtest.normalize_settings(None),
        }
        updated = False
        if auth_file.exists():
            try:
                auth_file.chmod(0o600)
            except OSError:
                pass
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "discovery_countries", "check_interval_hours", "singbox_exit_enabled", "global_exit_enabled", "speedtest"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True

        normalized_discovery_countries = normalize_discovery_countries(config.get("discovery_countries"))
        if normalized_discovery_countries != config.get("discovery_countries"):
            config["discovery_countries"] = normalized_discovery_countries
            updated = True

        normalized_interval = bounded_int(config.get("check_interval_hours"), 24, 1, 72)
        if normalized_interval != config.get("check_interval_hours"):
            config["check_interval_hours"] = normalized_interval
            updated = True

        for flag_key, flag_default in (("singbox_exit_enabled", True), ("global_exit_enabled", False)):
            raw_flag = config.get(flag_key, flag_default)
            normalized_flag = raw_flag if isinstance(raw_flag, bool) else flag_default
            if normalized_flag is not raw_flag:
                config[flag_key] = normalized_flag
                updated = True

        normalized_speedtest = speedtest.normalize_settings(config.get("speedtest"))
        if normalized_speedtest != config.get("speedtest"):
            config["speedtest"] = normalized_speedtest
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                write_json(auth_file, config)
            except Exception:
                pass
                
        return config

def persist_discovery_countries(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("国家筛选范围必须是国家代码列表")
    countries = normalize_discovery_countries(value)
    ui_cfg = load_ui_config()
    ui_cfg["discovery_countries"] = countries
    auth_file = DATA_DIR / "ui_auth.json"
    with lock:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        write_json(auth_file, ui_cfg)
    return countries

def save_ui_config(ui_cfg: dict[str, Any]) -> None:
    auth_file = DATA_DIR / "ui_auth.json"
    with lock:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        write_json(auth_file, ui_cfg)

def update_ui_config(**updates: Any) -> dict[str, Any]:
    with lock:
        ui_cfg = load_ui_config()
        ui_cfg.update(updates)
        save_ui_config(ui_cfg)
        return ui_cfg

def check_interval_seconds() -> int:
    return bounded_int(load_ui_config().get("check_interval_hours"), 24, 1, 72) * 3600

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def read_recent_log_entries(log_file: Path, limit: int = WEB_LOG_MAX_ENTRIES) -> list[dict[str, Any]]:
    if limit <= 0 or not log_file.exists():
        return []
    entries: deque[dict[str, Any]] = deque(maxlen=limit)
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    return list(entries)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

singbox_exit.set_logger(log_to_json)
global_exit.set_logger(log_to_json)

def set_state(**updates: Any) -> None:
    # Keep the read-modify-write transaction atomic across background threads.
    with lock:
        state = get_state()
        state.update(updates)
        for key in RUNTIME_STATE_KEYS:
            state.pop(key, None)
        write_json(STATE_FILE, state)

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state["maintenance_running"] = maintenance_lock.locked()
    state.setdefault("api_url", API_URL)
    state.setdefault("mirror_url", MIRROR_HTTPS_URL)
    state.setdefault("last_fetch_source", "")
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("pending_node_id", "")
    state.setdefault("tunnel_ready", False)
    state.setdefault("proxy_ready", bool(state.get("proxy_ok", False)))
    state.setdefault("blacklisted_nodes", 0)
    state["app_version"] = APP_VERSION
    state["app_version_label"] = APP_VERSION_LABEL
    state["deployment_mode"] = DEPLOYMENT_MODE
    state["deployment_mode_label"] = DEPLOYMENT_MODE_LABEL
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["discovery_countries"] = normalize_discovery_countries(ui_cfg.get("discovery_countries"))
    state["fav_fail_fallback"] = False
    state["check_interval_hours"] = bounded_int(ui_cfg.get("check_interval_hours"), 24, 1, 72)
    state.setdefault("next_check_at", 0)
    state["speedtest_settings"] = speedtest.normalize_settings(ui_cfg.get("speedtest"))
    state["pipeline"] = pipeline_snapshot()
    state["speed_history"] = speed_history_snapshot()
    with lock:
        state["singbox_exit"] = dict(exit_status["singbox"])
        state["global_exit"] = dict(exit_status["global"])
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def clear_active_connection_state(message: str) -> None:
    stop_active_openvpn()
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        pending_node_id="",
        active_node_latency="无活动连接",
        proxy_ok=False,
        tunnel_ready=False,
        proxy_ready=False,
        proxy_ip="-",
        proxy_latency_ms=0,
        proxy_error=message,
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        global_exit.mark_socket(s)
        s.settimeout(API_FETCH_TIMEOUT_SECONDS)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path
            
        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > snapshot_utils.MAX_SNAPSHOT_BYTES + 65536:
                raise RuntimeError("API response exceeds the maximum allowed size")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"Mozilla/5.0 AimiliVPN/{APP_VERSION}",
            "Accept": "text/plain,*/*",
        },
    )
    def read_limited(response: Any) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > snapshot_utils.MAX_SNAPSHOT_BYTES:
                raise RuntimeError("API response exceeds the maximum allowed size")
            chunks.append(chunk)
        return b"".join(chunks)

    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=API_FETCH_TIMEOUT_SECONDS, context=ctx) as response:
            return read_limited(response).decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=API_FETCH_TIMEOUT_SECONDS) as response:
            return read_limited(response).decode("utf-8", errors="replace")

def fetch_api_text_with_deadline(
    url: str,
    use_ssl_verify: bool = True,
    deadline_seconds: int | None = None,
) -> str:
    deadline = deadline_seconds or API_SOURCE_DEADLINE_SECONDS
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put((True, fetch_api_text(url, use_ssl_verify)))
        except BaseException as exc:
            result_queue.put((False, exc))

    threading.Thread(target=worker, daemon=True).start()
    try:
        ok, value = result_queue.get(timeout=deadline)
    except queue.Empty as exc:
        raise SourceDeadlineExceeded(f"节点源超过 {deadline} 秒总时限") from exc
    if ok:
        return str(value)
    raise value

def parse_release_version(value: Any) -> tuple[int, int, int]:
    match = re.search(r"(?i)(?:^|[^a-z0-9])v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(value or "").strip())
    if not match:
        raise ValueError("GitHub Release 版本号格式无效")
    return tuple(int(part or 0) for part in match.groups())

def check_latest_release() -> dict[str, Any]:
    payload = json.loads(fetch_api_text(GITHUB_LATEST_RELEASE_API, True))
    if not isinstance(payload, dict):
        raise ValueError("GitHub Release API 返回格式无效")
    if payload.get("draft") or payload.get("prerelease"):
        raise ValueError("GitHub 最新版本不是正式版")

    latest_tag = str(payload.get("tag_name") or "").strip()
    latest_version = parse_release_version(latest_tag)
    current_version = parse_release_version(APP_VERSION)
    release_url = f"{GITHUB_REPOSITORY_URL}/releases/tag/{urllib.parse.quote(latest_tag, safe='')}"

    return {
        "ok": True,
        "current_version": APP_VERSION,
        "current_version_label": APP_VERSION_LABEL,
        "latest_version": ".".join(str(part) for part in latest_version),
        "latest_tag": latest_tag,
        "latest_name": str(payload.get("name") or latest_tag),
        "published_at": str(payload.get("published_at") or ""),
        "update_available": latest_version > current_version,
        "release_url": release_url,
        "main_branch_url": GITHUB_MAIN_BRANCH_URL,
        "deployment_mode": DEPLOYMENT_MODE,
        "deployment_mode_label": DEPLOYMENT_MODE_LABEL,
        "update_command": UPDATE_COMMAND,
    }

def is_certificate_verification_error(exc: BaseException) -> bool:
    import ssl

    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        reason = getattr(current, "reason", None)
        cause = getattr(current, "__cause__", None)
        current = reason if isinstance(reason, BaseException) else cause
    return False

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    return snapshot_utils.parse_and_validate_snapshot(text, max_rows=MAX_SCAN_ROWS)

def decode_config(encoded: str) -> str:
    return snapshot_utils.decode_config(encoded)

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def api_network_sources() -> list[tuple[str, str]]:
    configured = [
        ("official_https", API_HTTPS_URL),
        ("official_http", API_HTTP_URL),
        ("github_pages_https", MIRROR_HTTPS_URL),
        ("github_pages_http_redirect_https", MIRROR_HTTP_URL),
    ]
    sources: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, url in configured:
        normalized = str(url or "").strip()
        if not normalized or normalized in seen:
            continue
        if not normalized.startswith(("https://", "http://")):
            print(f"[配置警告] 忽略不支持的节点源 URL: {normalized}", flush=True)
            continue
        seen.add(normalized)
        sources.append((label, normalized))
    return sources

def read_snapshot_file(path: Path) -> str:
    size = path.stat().st_size
    if size <= 0 or size > snapshot_utils.MAX_SNAPSHOT_BYTES:
        raise ValueError(f"本地快照大小无效: {size}")
    return path.read_bytes().decode("utf-8", errors="strict")

def cache_api_snapshot(text: str, source: str) -> None:
    validated_rows = snapshot_utils.parse_and_validate_snapshot(text, max_rows=MAX_SCAN_ROWS)
    encoded = text.encode("utf-8")
    with lock:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        tmp = API_CACHE_FILE.with_suffix(API_CACHE_FILE.suffix + ".tmp")
        tmp.write_bytes(encoded)
        tmp.replace(API_CACHE_FILE)
        write_json(
            API_CACHE_META_FILE,
            {
                "source": source,
                "cached_at": time.time(),
                "row_count": len(validated_rows),
                "byte_count": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            },
        )

def read_mirror_freshness() -> tuple[float, str]:
    if not MIRROR_META_URL:
        return 0.0, ""
    try:
        raw = fetch_api_text_with_deadline(MIRROR_META_URL, True, deadline_seconds=2)
        meta = json.loads(raw)
        generated_at = float(meta.get("generated_at", 0) or 0)
        if generated_at <= 0:
            return 0.0, ""
        age_seconds = max(0, int(time.time() - generated_at))
        if age_seconds < 3600:
            age_text = f"{max(1, age_seconds // 60)} 分钟"
        else:
            age_text = f"{age_seconds / 3600:.1f} 小时"
        return generated_at, f"镜像生成于 {age_text}前"
    except Exception as exc:
        print(f"[镜像元数据] 读取失败: {exc}", flush=True)
        return 0.0, "镜像生成时间未知"

def rows_to_candidates(
    rows: list[dict[str, str]],
    blacklist: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for row in rows[:MAX_SCAN_ROWS]:
        ip = row.get("IP", "")
        if not ip or ip in seen_ips:
            continue
        try:
            config_text = decode_config(row.get("OpenVPN_ConfigData_Base64", ""))
            snapshot_utils.validate_openvpn_config(config_text)
            node = row_to_node(row, config_text)
        except Exception as row_exc:
            print(f"[fetch_candidates] 跳过损坏或不安全的节点配置记录: {row_exc}", flush=True)
            log_to_json("WARNING", "Main", f"跳过损坏或不安全的节点配置记录: {row_exc}")
            continue
        entry = blacklist.get(node["id"])
        if entry and float(entry.get("until", 0) or 0) > time.time():
            continue
        candidates.append(node)
        seen_ips.add(ip)
    return candidates

def filter_candidates_by_discovery_countries(
    candidates: list[dict[str, Any]],
    country_codes: Any,
) -> list[dict[str, Any]]:
    selected = set(normalize_discovery_countries(country_codes))
    if not selected:
        return candidates
    return [
        candidate
        for candidate in candidates
        if str(candidate.get("country_short") or "").strip().upper() in selected
    ]

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    discovery_countries = normalize_discovery_countries(
        load_ui_config().get("discovery_countries")
    )
    last_err: Exception | None = None
    log_to_json("INFO", "Main", "开始按官方、GitHub Pages、本地缓存顺序拉取节点列表...")

    for source_name, url in api_network_sources():
        try:
            msg = f"尝试节点源 {source_name}: {url}"
            print(f"[fetch_candidates] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)
            api_text = fetch_api_text_with_deadline(url, True)
            rows = parse_vpngate_rows(api_text)
            candidates = rows_to_candidates(rows, blacklist)
            if not candidates:
                raise ValueError("节点源通过格式校验，但没有未被屏蔽的候选节点")

            # Plain HTTP remains available for older machines, but never replaces
            # the last snapshot obtained through an authenticated HTTPS channel.
            if url.startswith("https://"):
                cache_api_snapshot(api_text, source_name)

            filtered_candidates = filter_candidates_by_discovery_countries(
                candidates,
                discovery_countries,
            )
            scope_message = (
                f"按国家范围 {', '.join(discovery_countries)} 筛选后保留 {len(filtered_candidates)} 个"
                if discovery_countries
                else f"保留全部 {len(filtered_candidates)} 个"
            )
            mirror_generated_at = 0.0
            mirror_freshness = ""
            if source_name.startswith("github_pages"):
                mirror_generated_at, mirror_freshness = read_mirror_freshness()
            source_note = f"，{mirror_freshness}" if mirror_freshness else ""

            set_state(
                last_fetch_at=time.time(),
                last_fetch_status="ok",
                last_fetch_source=source_name,
                last_fetch_message=(
                    f"从 {source_name} 成功获取 {len(candidates)} 个候选节点，{scope_message}{source_note}。"
                ),
                mirror_generated_at=mirror_generated_at,
                mirror_freshness=mirror_freshness,
                blacklisted_nodes=len(blacklist),
            )
            log_to_json(
                "INFO",
                "Main",
                f"节点源 {source_name} 获取成功，共 {len(candidates)} 个候选节点，{scope_message}",
            )
            return filtered_candidates
        except Exception as e:
            last_err = e
            print(f"[fetch_candidates] 节点源 {source_name} 失败: {e}", flush=True)
            log_to_json("WARNING", "Main", f"节点源 {source_name} 失败: {e}")

    local_sources = [("local_cache", API_CACHE_FILE)]
    if BUNDLED_SNAPSHOT_FILE != API_CACHE_FILE:
        local_sources.append(("bundled_initial", BUNDLED_SNAPSHOT_FILE))
    for source_name, path in local_sources:
        try:
            if not path.exists():
                continue
            api_text = read_snapshot_file(path)
            rows = parse_vpngate_rows(api_text)
            candidates = rows_to_candidates(rows, blacklist)
            if not candidates:
                raise ValueError("本地快照没有未被屏蔽的候选节点")
            if source_name == "bundled_initial" and not API_CACHE_FILE.exists():
                cache_api_snapshot(api_text, source_name)
            filtered_candidates = filter_candidates_by_discovery_countries(
                candidates,
                discovery_countries,
            )
            scope_message = (
                f"按国家范围 {', '.join(discovery_countries)} 筛选后保留 {len(filtered_candidates)} 个"
                if discovery_countries
                else f"保留全部 {len(filtered_candidates)} 个"
            )
            set_state(
                last_fetch_at=time.time(),
                last_fetch_status="cached",
                last_fetch_source=source_name,
                last_fetch_message=(
                    f"网络节点源不可用，已载入 {source_name} 的 {len(candidates)} 个候选节点，"
                    f"{scope_message}。"
                ),
                blacklisted_nodes=len(blacklist),
            )
            log_to_json(
                "WARNING",
                "Main",
                f"网络节点源不可用，使用 {source_name}，共 {len(candidates)} 个候选节点，{scope_message}",
            )
            return filtered_candidates
        except Exception as e:
            last_err = e
            print(f"[fetch_candidates] 本地节点源 {source_name} 失败: {e}", flush=True)
            log_to_json("WARNING", "Main", f"本地节点源 {source_name} 失败: {e}")

    err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
    full_err_msg = f"所有节点源和本地缓存均失败: {last_err} | 诊断结果: {diag_msg}"
    print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
    log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
    set_state(
        last_fetch_status="error",
        last_fetch_error_code=err_code,
        last_fetch_source="",
        last_fetch_message=diag_msg,
    )
    if last_err:
        raise RuntimeError(diag_msg) from last_err
    raise RuntimeError(diag_msg)

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
            "--remote-cert-tls",
            "server",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(global_exit.openvpn_mark_args())
    command.extend(["--verb", "3"])
    
    if os.path.exists("/etc/ssl/certs"):
        command.extend(["--capath", "/etc/ssl/certs"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
    except OSError:
        return
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass

def begin_connection_attempt() -> tuple[int, threading.Event]:
    global connection_epoch, active_connection_cancel_event, is_connecting
    if not connection_attempt_lock.acquire(blocking=False):
        raise RuntimeError("当前已有连接切换任务正在运行，请稍后再试")

    cancel_event = threading.Event()
    with lock:
        if is_connecting:
            connection_attempt_lock.release()
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        connection_epoch += 1
        token = connection_epoch
        active_connection_cancel_event = cancel_event
        is_connecting = True
    return token, cancel_event

def connection_attempt_is_current(token: int, cancel_event: threading.Event) -> bool:
    with lock:
        return token == connection_epoch and not cancel_event.is_set()

def finish_connection_attempt(token: int, cancel_event: threading.Event) -> None:
    global active_connection_cancel_event, is_connecting
    with lock:
        if active_connection_cancel_event is cancel_event:
            active_connection_cancel_event = None
        if token == connection_epoch:
            is_connecting = False
    connection_attempt_lock.release()

def cancel_pending_connection_attempt() -> None:
    global connection_epoch, pending_openvpn_process, is_connecting
    pending = None
    with lock:
        if active_connection_cancel_event is None:
            return
        connection_epoch += 1
        active_connection_cancel_event.set()
        pending = pending_openvpn_process
        pending_openvpn_process = None
        is_connecting = False
    stop_process(pending)

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated AimiliVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(
    config_file: str,
    keep_alive: bool,
    route_nopull: bool,
    timeout: int | None = None,
    dev: str = "tun0",
    cancel_event: threading.Event | None = None,
    track_pending: bool = False,
    report_state: bool = True,
    log_prefix: str = "[OpenVPN]",
) -> tuple[bool, str, subprocess.Popen[str] | None]:
    global pending_openvpn_process
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    if track_pending:
        with lock:
            if cancel_event is not None and cancel_event.is_set():
                stop_process(process)
                return False, "连接操作已取消", None
            pending_openvpn_process = process

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"{log_prefix} {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"{log_prefix} {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    cancelled = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            message = "连接操作已取消"
            break
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"{log_prefix} {line}", flush=True)
        lower = line.lower()
        if keep_alive and report_state:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                message = "连接操作已取消"
            else:
                ok = True
                message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"{log_prefix} {line_str}")

    if not ok and not cancelled:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    if track_pending:
        with lock:
            if pending_openvpn_process is process or pending_openvpn_process is not None and pending_openvpn_process.poll() is not None:
                pending_openvpn_process = None
    return ok, message, process


def _run_ip(args: list[str], timeout: float = 2) -> int:
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout).returncode
    except Exception:
        return 127

def remove_policy_rules(interface: str, table: int) -> None:
    """Delete every `oif <interface> lookup <table>` rule (exact match, no table-wide wildcard)."""
    table_str = str(table)
    for _ in range(20):
        if _run_ip(["ip", "rule", "del", "oif", interface, "table", table_str]) != 0:
            break

def remove_policy_routes(interface: str, table: int) -> None:
    """Table 100 keeps the global-exit fallback route, so only its tun0 default is removed.
    Speed-test tables (101+) are fully owned by us and get flushed."""
    table_str = str(table)
    if table == 100:
        _run_ip(["ip", "route", "del", "default", "dev", interface, "table", table_str])
    else:
        _run_ip(["ip", "route", "flush", "table", table_str])

def setup_policy_routing(interface: str = "tun0", table: int = 100) -> bool:
    table_str = str(table)
    remove_policy_rules(interface, table)
    remove_policy_routes(interface, table)

    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "replace", "default", "dev", interface, "table", table_str], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", table_str], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} table {table_str} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)

    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", f"[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 {table_str} 添加默认路由")
    elif table == 100:
        try:
            if load_ui_config().get("global_exit_enabled"):
                global_exit.ensure_table_fallback(exit_runner)
        except Exception as exc:
            log_to_json("WARNING", "GlobalExit", f"确认表 100 兜底路由失败: {exc}")
    return success

def cleanup_policy_routing(interface: str = "tun0", table: int = 100) -> None:
    try:
        remove_policy_rules(interface, table)
        remove_policy_routes(interface, table)
        print(f"[policy_routing] Cleared policy routing for {interface} table {table}", flush=True)
    except Exception:
        pass

def cleanup_stale_speedtest_routes() -> None:
    """Remove leftover `oif tunN lookup 1xx` rules and tables from interrupted speed tests."""
    try:
        result = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, timeout=3)
    except Exception:
        return
    if result.returncode != 0:
        return
    for line in result.stdout.splitlines():
        match = re.search(r"\boif\s+(tun\d+)\s+lookup\s+(1\d\d)\b", line)
        if not match:
            continue
        dev, table = match.group(1), int(match.group(2))
        if dev == "tun0" or not 101 <= table <= 199:
            continue
        print(f"[policy_routing] Removing stale speed-test routing for {dev} table {table}", flush=True)
        remove_policy_rules(dev, table)
        remove_policy_routes(dev, table)

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing("tun0", 100)
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")
                
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        
        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def connection_ready_for_ui(state: dict[str, Any] | None = None) -> bool:
    current = get_state() if state is None else state
    return bool(
        active_openvpn_node_id
        and active_openvpn_running()
        and current.get("tunnel_ready")
        and current.get("proxy_ready")
        and current.get("proxy_ok")
        and not current.get("pending_node_id")
    )

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") in ("not_checked", "testing") and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

def enrich_stored_nodes() -> int:
    """Enrich every listed IP, then merge only metadata into the latest state."""
    with lock:
        snapshot = read_nodes()
    if not snapshot:
        return 0

    vpn_utils.enrich_ip_info(snapshot)
    enriched_by_id = {
        str(node.get("id") or ""): node
        for node in snapshot
        if node.get("id") and node.get("ip_type")
    }
    if not enriched_by_id:
        return 0

    changed = 0
    with lock:
        current_nodes = read_nodes()
        for current in current_nodes:
            enriched = enriched_by_id.get(str(current.get("id") or ""))
            if not enriched:
                continue
            for field in IP_ENRICHMENT_FIELDS:
                new_value = enriched.get(field, "")
                if current.get(field, "") != new_value:
                    current[field] = new_value
                    changed += 1
        if changed:
            write_json(NODES_FILE, sort_all_nodes(current_nodes))
    return changed

def ip_enrichment_loop() -> None:
    while True:
        nodes_exist = bool(read_nodes())
        if nodes_exist:
            try:
                enrich_stored_nodes()
            except Exception as exc:
                print(f"[IP 类型] 后台批量识别失败: {exc}", flush=True)
                log_to_json("WARNING", "Main", f"后台批量识别 IP 类型失败: {exc}")
        ip_enrichment_wakeup.wait(300 if nodes_exist else 5)
        ip_enrichment_wakeup.clear()

def apply_routing_filters(
    nodes: list[dict[str, Any]],
    ui_cfg: dict[str, Any],
    include_unknown_ip_type: bool = False,
) -> list[dict[str, Any]]:
    candidates = list(nodes)
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_region" and target_country:
        candidates = [
            n for n in candidates
            if country_matches(n.get("country"), target_country, n.get("country_short"))
        ]
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        candidates = [n for n in candidates if n.get("id") in fav_ids]

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    if routing_ip_type == "residential":
        candidates = [
            n for n in candidates
            if (
                n.get("ip_type") in ("residential", "mobile")
                and n.get("ip_type_confidence") in ("medium", "high")
            )
            or (include_unknown_ip_type and not n.get("ip_type"))
        ]
    elif routing_ip_type == "hosting":
        candidates = [
            n for n in candidates
            if n.get("ip_type") == "hosting"
            or (include_unknown_ip_type and not n.get("ip_type"))
        ]

    return candidates

def normalized_country_name(country: Any) -> str:
    value = str(country or "").strip()
    return vpn_utils.COUNTRY_TRANSLATIONS.get(value, value)

def normalize_routing_country(value: Any, nodes: list[dict[str, Any]] | None = None) -> str:
    target = str(value or "").strip()
    if not target:
        return ""
    upper = target.upper()
    if re.fullmatch(r"[A-Z]{2}", upper):
        return upper
    normalized_target = normalized_country_name(target).casefold()
    for node in nodes if nodes is not None else read_nodes():
        code = str(node.get("country_short") or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            continue
        if normalized_country_name(node.get("country")).casefold() == normalized_target:
            return code
    return target

def country_matches(
    node_country: Any,
    target_country: Any,
    node_country_short: Any = "",
) -> bool:
    target = str(target_country or "").strip()
    if not target:
        return False
    target_upper = target.upper()
    if re.fullmatch(r"[A-Z]{2}", target_upper):
        return str(node_country_short or "").strip().upper() == target_upper
    return normalized_country_name(node_country).casefold() == normalized_country_name(target).casefold()

def probe_priority_key(node: dict[str, Any]) -> tuple[int, int, int, int]:
    ping = parse_int(node.get("ping")) or 999999
    return (
        ping,
        -parse_int(node.get("score")),
        -parse_int(node.get("speed")),
        parse_int(node.get("sessions")),
    )

def current_fixed_node_id(ui_cfg: dict[str, Any]) -> str:
    if active_openvpn_node_id:
        return active_openvpn_node_id
    nodes = read_nodes()
    active_node = next((n for n in nodes if n.get("active") and n.get("id")), None)
    if active_node:
        return str(active_node.get("id") or "")
    return str(ui_cfg.get("fixed_node_id") or "").strip()

def validate_node_allowed_by_routing(node: dict[str, Any], ui_cfg: dict[str, Any]) -> None:
    routing_mode = ui_cfg.get("routing_mode", "auto")
    node_id = str(node.get("id") or "")

    if routing_mode == "fixed_region":
        target_country = ui_cfg.get("force_country", "")
        if target_country and not country_matches(node.get("country"), target_country, node.get("country_short")):
            raise RuntimeError(f"当前已锁定国家【{target_country}】，不能连接其他国家节点")
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        if node_id not in fav_ids:
            raise RuntimeError("当前处于仅用收藏模式，不能连接未收藏节点")

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    node_ip_type = node.get("ip_type")
    if routing_ip_type == "residential" and node_ip_type not in ("residential", "mobile"):
        raise RuntimeError("当前已锁定住宅 IP 出站，不能连接非住宅节点")
    if routing_ip_type == "hosting" and node_ip_type != "hosting":
        raise RuntimeError("当前已锁定机房 IP 出站，不能连接非机房节点")

def enforce_active_node_allowed_by_routing(ui_cfg: dict[str, Any], reason: str = "路由规则已更新") -> str | None:
    active_id = active_openvpn_node_id
    if not active_id:
        return None

    nodes = read_nodes()
    active_node = next((item for item in nodes if item.get("id") == active_id), None)
    if not active_node:
        clear_active_connection_state(f"{reason}，当前活动节点已不在节点列表中，已断开连接")
        return "当前活动节点已不在节点列表中，已断开连接"

    try:
        validate_node_allowed_by_routing(active_node, ui_cfg)
        return None
    except Exception as exc:
        msg = f"{reason}，当前活动节点 {active_id} 不符合新规则，已断开连接: {exc}"
        print(f"[路由规则] {msg}", flush=True)
        log_to_json("WARNING", "Routing", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(
            active_openvpn_node_id="",
            active_node_latency="无活动连接",
            proxy_ok=False,
            proxy_ip="-",
            proxy_latency_ms=0,
            proxy_error=msg,
            last_check_message=msg,
        )

        if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
            threading.Thread(target=auto_switch_node, daemon=True).start()
        return msg

def reconnect_fixed_node_if_needed(ui_cfg: dict[str, Any]) -> bool:
    global is_connecting
    if ui_cfg.get("routing_mode") != "fixed_ip" or active_openvpn_running():
        return False
    target_id = current_fixed_node_id(ui_cfg)
    if not target_id:
        return False
    nodes = read_nodes()
    if not any(n.get("id") == target_id for n in nodes):
        return False

    print(f"[维护线程] 固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
    previous_connecting = is_connecting
    is_connecting = False
    try:
        connect_node(target_id)
        return active_openvpn_running()
    except Exception as e:
        print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
        return False
    finally:
        is_connecting = previous_connecting

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = None
    try:
        idx = get_free_test_index()
        ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}")
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                for field in IP_ENRICHMENT_FIELDS:
                    value = temp_node.get(field)
                    if value not in (None, ""):
                        node[field] = value
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def is_systemic_probe_failure(message: Any) -> bool:
    normalized = str(message or "").lower()
    return any(
        token in normalized
        for token in (
            "err_ovpn_cmd_not_found",
            "err_ovpn_permission_denied",
            "err_ovpn_tun_not_available",
            "no such file or directory",
            "cannot open tun/tap dev",
            "cannot allocate tun",
        )
    )

def test_multiple_nodes(
    node_ids: list[str],
    target_available: int | None = None,
    cancel_event: threading.Event | None = None,
    progress_cb: Any = None,
) -> list[dict[str, Any]]:
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))
        
        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
            }
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=dev_name, cancel_event=cancel_event)
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
            
        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
        }
        return temp_node

    updated_nodes_map: dict[str, dict[str, Any]] = {}
    available_count = 0
    systemic_failure = ""
    max_workers = min(NODE_PROBE_WORKERS, max(1, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for batch_start in range(0, len(to_test), max_workers):
            if systemic_failure or (target_available is not None and available_count >= target_available):
                break
            if cancel_event is not None and cancel_event.is_set():
                break

            batch = to_test[batch_start : batch_start + max_workers]
            batch_ids = {str(n.get("id") or "") for n in batch}
            with lock:
                current_nodes = read_nodes()
                now = time.time()
                for current in current_nodes:
                    if current.get("id") in batch_ids and not current.get("active"):
                        current["probe_status"] = "testing"
                        current["probe_message"] = "正在检测节点连通性..."
                        current["probed_at"] = now
                write_json(NODES_FILE, sort_all_nodes(current_nodes))

            futures = {
                executor.submit(test_worker, (batch_start + idx, node)): node["id"]
                for idx, node in enumerate(batch)
            }
            for future in concurrent.futures.as_completed(futures):
                nid = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "id": nid,
                        "probe_status": "unavailable",
                        "probe_message": f"Test exception: {exc}",
                        "latency_ms": 0,
                    }
                updated_nodes_map[nid] = result
                if result.get("probe_status") == "available":
                    available_count += 1
                if is_systemic_probe_failure(result.get("probe_message")):
                    systemic_failure = str(result.get("probe_message") or "")
                with lock:
                    current_nodes = read_nodes()
                    for current in current_nodes:
                        if current.get("id") == nid:
                            current.update(result)
                            break
                    write_json(NODES_FILE, sort_all_nodes(current_nodes))
                if progress_cb is not None:
                    try:
                        progress_cb(len(updated_nodes_map), len(to_test))
                    except Exception:
                        pass

            if systemic_failure:
                message = f"检测到系统级 OpenVPN 故障，已停止剩余节点探测: {systemic_failure}"
                print(f"[节点检测] {message}", flush=True)
                log_to_json("ERROR", "VPN", message)
                set_state(last_check_message=message)
                break
                
    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        
    return list(updated_nodes_map.values())

def cancel_background_refill() -> None:
    background_refill_cancel_event.set()

def schedule_background_refill() -> bool:
    global background_refill_thread
    with background_refill_lock:
        if background_refill_thread is not None and background_refill_thread.is_alive():
            return False
        background_refill_cancel_event.clear()

        def refill_worker() -> None:
            global background_refill_thread
            try:
                for delay in (60, 120, 300):
                    if background_refill_cancel_event.wait(delay):
                        return
                    ui_cfg = load_ui_config()
                    if not ui_cfg.get("connection_enabled", True):
                        return
                    try:
                        maintain_valid_nodes(force=False)
                    except Exception as exc:
                        log_to_json("WARNING", "Main", f"后台节点补齐失败: {exc}")
                    if active_openvpn_running():
                        return
            finally:
                with background_refill_lock:
                    if background_refill_thread is threading.current_thread():
                        background_refill_thread = None

        background_refill_thread = threading.Thread(
            target=refill_worker,
            name="vpngate-node-refill",
            daemon=True,
        )
        background_refill_thread.start()
        return True

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        if schedule_background_refill():
            log_to_json("INFO", "Main", "连续自动切换失败，已启动唯一后台节点补齐任务")
        return
        
    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    # Find the next best available node
    with lock:
        nodes = read_nodes()
        candidates = [
            n for n in nodes 
            if n.get("probe_status") == "available" 
            and not n.get("active")
        ]
        candidates = apply_routing_filters(candidates, ui_cfg)
            
        if load_ui_config().get("speedtest", {}).get("auto_switch_fastest"):
            candidates.sort(
                key=lambda n: (
                    0 if node_speed(n) > 0 else 1,
                    -node_speed(n),
                    parse_int(n.get("latency_ms")) or 999999,
                    -parse_int(n.get("score")),
                )
            )
        else:
            candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score"))))
        
    if candidates:
        next_node = candidates[0]
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        if schedule_background_refill():
            log_to_json("INFO", "Main", "已启动唯一后台节点补齐任务")

def recover_after_manual_connect_failure(previous_node_id: str) -> None:
    if active_openvpn_running():
        return

    if previous_node_id:
        try:
            log_to_json("WARNING", "VPN", f"手动切换失败，正在恢复原节点: {previous_node_id}")
            connect_node(previous_node_id)
            return
        except Exception as exc:
            log_to_json("ERROR", "VPN", f"恢复原节点 {previous_node_id} 失败: {exc}")

    ui_cfg = load_ui_config()
    if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
        auto_switch_node()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id
    global last_active_ping_time, last_active_latency
    global consecutive_proxy_failures, last_proxy_failure_node_id
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")

    token, cancel_event = begin_connection_attempt()
    stopped_existing = False
    previous_node_id = ""
    try:
        set_state(
            is_connecting=True,
            pending_node_id=node_id,
            tunnel_ready=False,
            proxy_ready=False,
            proxy_ok=False,
            active_node_latency="正在连接",
            last_check_message=f"正在初始化连接配置: {node_id}",
        )
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        with lock:
            if active_openvpn_running():
                previous_node_id = active_openvpn_node_id
        
        ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, ui_cfg)
        ui_cfg["connection_enabled"] = True
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            write_json(auth_file, ui_cfg)

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        probed_at = float(node.get("probed_at", 0) or 0)
        should_preflight = (
            SWITCH_PREFLIGHT_MAX_AGE_SECONDS > 0
            and bool(previous_node_id)
            and previous_node_id != node_id
            and time.time() - probed_at > SWITCH_PREFLIGHT_MAX_AGE_SECONDS
        )
        if should_preflight:
            set_state(active_node_latency="切换预检", last_check_message="正在保持当前连接并预检目标节点...")
            test_index = None
            try:
                test_index = get_free_test_index()
                preflight_ok, preflight_message, _ = run_openvpn_until_ready(
                    str(config_path),
                    keep_alive=False,
                    route_nopull=True,
                    timeout=12,
                    dev=f"tun{test_index}",
                    cancel_event=cancel_event,
                    track_pending=True,
                )
            finally:
                if test_index is not None:
                    release_test_index(test_index)
            if not connection_attempt_is_current(token, cancel_event):
                raise ConnectionCancelled("连接操作已取消")
            if not preflight_ok:
                with lock:
                    current_nodes = read_nodes()
                    failed_node = next((item for item in current_nodes if item.get("id") == node_id), None)
                    if failed_node:
                        failed_node["probe_status"] = "unavailable"
                        failed_node["probe_message"] = preflight_message
                        failed_node["probed_at"] = time.time()
                        write_json(NODES_FILE, sort_all_nodes(current_nodes))
                raise RuntimeError(f"目标节点预检失败，已保留当前连接: {preflight_message}")

        if not connection_attempt_is_current(token, cancel_event):
            raise ConnectionCancelled("连接操作已取消")
        set_state(active_node_latency="清理连接", last_check_message="目标节点可用，正在关闭旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(
            str(config_path),
            keep_alive=True,
            route_nopull=True,
            cancel_event=cancel_event,
            track_pending=True,
        )
        if not connection_attempt_is_current(token, cancel_event):
            stop_process(process)
            raise ConnectionCancelled("连接操作已取消")
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, sort_all_nodes(nodes))
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            raise RuntimeError(message)
            
        with lock:
            if not connection_attempt_is_current(token, cancel_event):
                stop_process(process)
                raise ConnectionCancelled("连接操作已取消")
            active_openvpn_process = process
            active_openvpn_node_id = node_id
        set_state(tunnel_ready=True, proxy_ready=False)
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        routing_ready = setup_policy_routing("tun0")
        if not connection_attempt_is_current(token, cancel_event):
            raise ConnectionCancelled("连接操作已取消")
        
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if not connection_attempt_is_current(token, cancel_event):
            raise ConnectionCancelled("连接操作已取消")
        if not res["ok"]:
            route_note = "；策略路由配置失败" if not routing_ready else ""
            raise RuntimeError(f"VPN 隧道已建立但代理出口不可用{route_note}: {res.get('error', '未知错误')}")

        latest_ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, latest_ui_cfg)
        latest_ui_cfg["connection_enabled"] = True
        if latest_ui_cfg.get("routing_mode") == "fixed_ip":
            latest_ui_cfg["fixed_node_id"] = node_id

        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        with lock:
            if not connection_attempt_is_current(token, cancel_event):
                raise ConnectionCancelled("连接操作已取消")
            current_nodes = read_nodes()
            for item in current_nodes:
                item["active"] = item.get("id") == node_id
                if item["active"]:
                    item["probe_status"] = "available"
                    item["probed_at"] = time.time()
                    _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                    item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
            write_json(NODES_FILE, sort_all_nodes(current_nodes))
            write_json(auth_file, latest_ui_cfg)
            consecutive_proxy_failures = 0
            last_proxy_failure_node_id = node_id
            set_state(
                active_openvpn_node_id=node_id,
                is_connecting=False,
                pending_node_id="",
                last_check_message=f"Connected {node_id}",
                active_node_latency=latency_str,
                proxy_ok=True,
                tunnel_ready=True,
                proxy_ready=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error="",
            )
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        cancel_background_refill()
        return f"Connected {node_id}"
    except ConnectionCancelled:
        if stopped_existing:
            stop_active_openvpn()
        raise
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            with lock:
                current_nodes = read_nodes()
                failed_node = next((item for item in current_nodes if item.get("id") == node_id), None)
                if failed_node:
                    failed_node["probe_status"] = "unavailable"
                    failed_node["probe_message"] = str(exc)
                    failed_node["probed_at"] = time.time()
                    write_json(NODES_FILE, sort_all_nodes(current_nodes))
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, pending_node_id="", last_check_message=f"连接失败: {exc}")
        raise
    finally:
        finish_connection_attempt(token, cancel_event)
        set_state(pending_node_id="")

def parse_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number:
        return 0.0
    return number

def node_speed(node: dict[str, Any]) -> float:
    return parse_float(node.get("speed_mbps"))

def schedule_next_check(base: float | None = None) -> float:
    """Record when the next periodic pipeline run is due and wake the collector."""
    base_time = time.time() if base is None else float(base)
    next_at = base_time + check_interval_seconds()
    set_state(next_check_at=next_at)
    collector_wakeup.set()
    return next_at

def reschedule_after_interval_change() -> float:
    return schedule_next_check(last_pipeline_end or time.time())

def maintain_valid_nodes(force: bool = False) -> str:
    """Compatibility wrapper: fetch + probe without the speed-test stage."""
    return run_pipeline("forced" if force else "periodic", with_speedtest=False)

def run_pipeline(trigger: str, with_speedtest: bool) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting, last_pipeline_end
    ensure_dirs()
    if trigger not in PIPELINE_TRIGGERS:
        trigger = "periodic"
    if not maintenance_lock.acquire(blocking=False):
        msg = "任务进行中，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    with lock:
        if is_connecting:
            maintenance_lock.release()
            msg = "当前已有连接或节点测试任务正在运行，请稍后再试"
            set_state(last_check_message=msg)
            return msg
        is_connecting = True
    run_id = uuid.uuid4().hex[:12]
    pipeline_cancel_event.clear()
    with lock:
        pipeline_status.update(new_pipeline_status())
        pipeline_status.update(
            running=True,
            run_id=run_id,
            trigger=trigger,
            stage="fetch",
            with_speedtest=bool(with_speedtest),
            started_at=time.time(),
            message="正在获取节点列表...",
        )
    log_to_json("INFO", "Pipeline", f"管线开始: trigger={trigger} speedtest={'是' if with_speedtest else '否'} run_id={run_id}")
    speed_settings = speedtest.normalize_settings(load_ui_config().get("speedtest"))
    try:
        # A forced refresh must not tear down a healthy tunnel. It only forces
        # the node-pool maintenance path below.
        if not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    reconnect_fixed_node_if_needed(ui_cfg)
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        # ---- 阶段 1：获取 ------------------------------------------------
        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        if not candidates:
            pipeline_set(message="没有拉取到新节点")
            return "没有拉取到新节点"

        with lock:
            current_nodes = read_nodes()
            current_by_id = {
                str(n.get("id")): n
                for n in current_nodes
                if n.get("id")
            }
            active_node = None
            if active_openvpn_node_id:
                active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)

            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()

            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])

            for cand in candidates:
                if cand["id"] not in seen_ids:
                    previous = current_by_id.get(str(cand["id"]))
                    if previous:
                        for key in [
                            "probe_status",
                            "probe_message",
                            "latency_ms",
                            "probed_at",
                            "owner",
                            "asn",
                            "as_name",
                            "location",
                            "ip_type",
                            "quality",
                            "is_proxy",
                            "is_hosting",
                            "is_mobile",
                            "ip_type_reason",
                            "speed_mbps",
                            "speed_tested_at",
                            "speed_message",
                            "speed_run_id",
                        ]:
                            if previous.get(key) not in (None, ""):
                                cand[key] = previous.get(key)
                    merged.append(cand)
                    seen_ids.add(cand["id"])

            if len(merged) > 1000:
                merged = merged[:1000]

            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass

            write_json(NODES_FILE, merged)
            ip_enrichment_wakeup.set()

        if pipeline_cancel_event.is_set():
            pipeline_set(stopped_reason="manual", message="已手动停止")
            message = f"获取 {len(candidates)} 个节点，检测前已手动停止"
            set_state(last_check_at=time.time(), last_check_message="任务已手动停止")
            return message

        # ---- 阶段 2：检测 ------------------------------------------------
        ui_cfg = load_ui_config()
        with lock:
            probe_pool = [n for n in read_nodes() if not n.get("active")]
            probe_pool = apply_routing_filters(probe_pool, ui_cfg, include_unknown_ip_type=True)
        probe_total = len(probe_pool)
        probe_offset = 0
        pipeline_set(stage="probe", probe_total=probe_total, probe_done=0, message="正在检测节点可用性...")

        def probe_progress(done: int, total: int) -> None:
            pipeline_set(probe_done=min(probe_total, probe_offset + done))

        initial_tested_ids: set[str] = set()
        fast_results: list[dict[str, Any]] = []
        systemic_probe_failure = ""
        should_fast_connect = (
            ui_cfg.get("connection_enabled", True)
            and ui_cfg.get("routing_mode", "auto") != "fixed_ip"
            and not active_openvpn_running()
        )
        if should_fast_connect:
            with lock:
                current_nodes = read_nodes()
                fast_candidates = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("probe_status") != "unavailable"
                ]
                fast_candidates = apply_routing_filters(fast_candidates, ui_cfg, include_unknown_ip_type=True)
                fast_candidates.sort(key=probe_priority_key)
                fast_test_ids = [
                    n["id"] for n in fast_candidates
                    if n.get("id")
                ][:INITIAL_CONNECT_TEST_LIMIT]

            if fast_test_ids:
                msg = f"首次快速连接模式：优先测试 {len(fast_test_ids)} 个高优先级节点，发现可用节点后立即连接"
                print(f"[快速首连] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                set_state(is_connecting=True, last_check_message=msg)
                fast_results = test_multiple_nodes(
                    fast_test_ids,
                    target_available=TARGET_VALID_NODES,
                    cancel_event=pipeline_cancel_event,
                    progress_cb=probe_progress,
                )
                probe_offset = len(fast_results)
                pipeline_set(probe_done=min(probe_total, probe_offset))
                systemic_probe_failure = next(
                    (
                        str(result.get("probe_message") or "")
                        for result in fast_results
                        if is_systemic_probe_failure(result.get("probe_message"))
                    ),
                    "",
                )
                initial_tested_ids = {
                    str(result.get("id") or "")
                    for result in fast_results
                    if result.get("id")
                }

                with lock:
                    fast_nodes = read_nodes()
                    available_candidates = [
                        n for n in fast_nodes
                        if n.get("probe_status") == "available" and not n.get("active")
                    ]
                    available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                if available_candidates and not pipeline_cancel_event.is_set():
                    is_connecting = False
                    set_state(is_connecting=False, last_check_message="快速首连已找到可用节点，正在建立连接...")
                    auto_switch_node()
                    is_connecting = True

        tested_results: list[dict[str, Any]] = []
        if systemic_probe_failure:
            msg = f"已跳过本轮剩余节点检测，系统级故障需要先处理: {systemic_probe_failure}"
            print(f"[周期检测] {msg}", flush=True)
            log_to_json("ERROR", "VPN", msg)
            set_state(last_check_message=msg)
        elif pipeline_cancel_event.is_set():
            pass
        else:
            # Test every remaining non-active node in the list; no early stop.
            with lock:
                current_nodes = read_nodes()
                to_test = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("id") not in initial_tested_ids
                ]
                to_test = apply_routing_filters(to_test, ui_cfg, include_unknown_ip_type=True)
                to_test.sort(key=probe_priority_key)
                to_test_ids = [n["id"] for n in to_test]

            msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
            print(f"[周期检测] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)

            set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
            tested_results = test_multiple_nodes(
                to_test_ids,
                target_available=None,
                cancel_event=pipeline_cancel_event,
                progress_cb=probe_progress,
            )
        is_connecting = False

        with lock:
            merged = read_nodes()
            candidate_ids = {str(c.get("id")) for c in candidates}
            pruned = [
                n for n in merged
                if not (
                    n.get("id") not in candidate_ids
                    and n.get("probe_status") == "unavailable"
                    and not n.get("active")
                )
            ]
            if len(pruned) != len(merged):
                merged = pruned
                write_json(NODES_FILE, sort_all_nodes(merged))

            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")

            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)

            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)

            if not active_openvpn_running() and not pipeline_cancel_event.is_set():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")

                    if routing_mode != "fixed_ip":
                        available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                        available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                        if available_candidates:
                            auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        total_tested = len(fast_results) + len(tested_results)
        message = f"获取 {len(candidates)} 个节点，检测 {total_tested} 个"
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )

        if pipeline_cancel_event.is_set():
            pipeline_set(stopped_reason="manual", message="已手动停止")
            set_state(last_check_message="任务已手动停止")
            return message + "，已手动停止"

        # ---- 阶段 3 与 4：筛选、测速 ---------------------------------------
        stopped_reason = ""
        speed_ran = False
        if with_speedtest:
            set_state(is_connecting=False)
            ui_cfg = load_ui_config()
            active_id = active_openvpn_node_id if active_openvpn_running() else ""
            with lock:
                speed_candidates = speedtest.select_candidates(
                    read_nodes(),
                    speed_settings,
                    lambda items: apply_routing_filters(items, ui_cfg, include_unknown_ip_type=True),
                    active_id,
                    time.time(),
                )
            speed_ran = True
            stopped_reason = run_speed_stage(speed_candidates, speed_settings, run_id)
            message += f"，测速 {pipeline_snapshot().get('speed_done', 0)}/{len(speed_candidates)} 个"

        # ---- 阶段 5：切换判定 ----------------------------------------------
        if speed_ran and stopped_reason in ("", "threshold") and speed_settings.get("auto_switch_fastest"):
            pipeline_set(stage="switch", message="正在判定是否切换到最快节点...")
            try:
                if maybe_switch_to_fastest(run_id, speed_settings):
                    message += "，已切换到最快节点"
            except Exception as exc:
                log_to_json("ERROR", "Pipeline", f"最快节点切换判定异常: {exc}")

        if stopped_reason == "manual":
            set_state(last_check_message="任务已手动停止")
        else:
            set_state(last_check_message=message)
        pipeline_set(message=message)
        return message
    except Exception as e:
        pipeline_set(stopped_reason="error", message=str(e))
        log_to_json("ERROR", "Pipeline", f"管线异常终止: {e}")
        raise e
    finally:
        is_connecting = False
        last_pipeline_end = time.time()
        pipeline_set(running=False, stage="idle", current_node_id="", finished_at=last_pipeline_end)
        set_state(is_connecting=False)
        maintenance_lock.release()
        try:
            schedule_next_check(last_pipeline_end)
        except Exception as exc:
            log_to_json("WARNING", "Pipeline", f"安排下次检测失败: {exc}")

def measure_node_speed(node: dict[str, Any], settings: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Measure one node. The active node is measured over tun0; others get a temporary tunnel."""
    settings = speedtest.normalize_settings(settings)
    node_id = str(node.get("id") or "")
    max_bytes = int(settings["per_node_max_mb"]) * 1_000_000
    max_seconds = int(settings["per_node_seconds"])
    url = speedtest.build_url(settings["url"], max_bytes)
    result: dict[str, Any] = {
        "id": node_id,
        "speed_mbps": 0.0,
        "speed_tested_at": time.time(),
        "speed_message": "",
        "speed_run_id": run_id,
    }

    def apply_measurement(dev: str) -> None:
        measured = speedtest.measure_download(
            url,
            dev,
            max_seconds,
            max_bytes,
            pipeline_cancel_event,
            resolver=lambda host: proxy_server.resolve_dns_over_device(host, dev),
        )
        result["speed_tested_at"] = time.time()
        if measured.error:
            result["speed_mbps"] = 0.0
            result["speed_message"] = measured.error
            log_to_json("WARNING", "SpeedTest", f"节点 {node_id} 测速失败: {measured.error}")
        else:
            result["speed_mbps"] = round(measured.mbps, 3)
            result["speed_message"] = f"{measured.bytes / 1_000_000:.1f} MB / {measured.seconds:.1f} s"
            log_to_json("INFO", "SpeedTest", f"节点 {node_id} 实测 {speedtest.format_speed(measured.mbps)}（{result['speed_message']}）")

    is_active = bool(node_id) and active_openvpn_running() and node_id == active_openvpn_node_id
    if is_active:
        apply_measurement("tun0")
        return result

    idx: int | None = None
    process: subprocess.Popen[str] | None = None
    temp_path: Path | None = None
    dev = ""
    table = 0
    routing_ready = False
    try:
        idx = get_free_test_index()
        dev = f"tun{idx}"
        table = 100 + idx
        temp_path = test_config_path(node_id)
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(str(node.get("config_text") or ""), encoding="utf-8")
        ok, message, process = run_openvpn_until_ready(
            str(temp_path),
            keep_alive=True,
            route_nopull=True,
            timeout=12,
            dev=dev,
            cancel_event=pipeline_cancel_event,
            report_state=False,
            log_prefix=f"[SpeedTest {dev}]",
        )
        if not ok:
            result["speed_message"] = message
            if not pipeline_cancel_event.is_set():
                result["probe_status"] = "unavailable"
                result["probe_message"] = message
                result["probed_at"] = time.time()
                log_to_json("WARNING", "SpeedTest", f"节点 {node_id} 测速前连接失败，标记为不可用: {message}")
            return result
        result["probe_status"] = "available"
        if not setup_policy_routing(dev, table):
            result["speed_message"] = "测速隧道策略路由配置失败"
            return result
        routing_ready = True
        apply_measurement(dev)
    except Exception as exc:
        result["speed_message"] = str(exc)
        log_to_json("WARNING", "SpeedTest", f"节点 {node_id} 测速异常: {exc}")
    finally:
        if routing_ready:
            cleanup_policy_routing(dev, table)
        if process is not None:
            stop_process(process)
        if idx is not None:
            release_test_index(idx)
        if temp_path is not None:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
    return result

def run_speed_stage(candidates: list[dict[str, Any]], settings: dict[str, Any], run_id: str) -> str:
    """Measure candidates one by one. Returns the stopped_reason ("" / "manual" / "threshold")."""
    settings = speedtest.normalize_settings(settings)
    threshold = float(settings["stop_threshold_mbps"])
    pipeline_set(
        stage="speedtest",
        speed_total=len(candidates),
        speed_done=0,
        current_node_id="",
        best_node_id="",
        best_speed_mbps=0.0,
        message=f"开始逐个测速，共 {len(candidates)} 个节点",
    )
    log_to_json("INFO", "SpeedTest", f"开始逐个测速，共 {len(candidates)} 个节点，run_id={run_id}")
    done = 0
    best_id = ""
    best_speed = 0.0
    for node in candidates:
        if pipeline_cancel_event.is_set():
            pipeline_set(stopped_reason="manual", message="测速已手动停止")
            return "manual"
        node_id = str(node.get("id") or "")
        pipeline_set(current_node_id=node_id, message=f"正在测速 {node_id}")
        set_state(last_check_message=f"正在测速节点 {node_id}（{done + 1}/{len(candidates)}）")
        result = measure_node_speed(node, settings, run_id)
        with lock:
            nodes = read_nodes()
            for item in nodes:
                if item.get("id") == node_id:
                    item.update(result)
                    break
            write_json(NODES_FILE, sort_all_nodes(nodes))
            try:
                append_speed_history(node_id, {
                    "t": int(parse_float(result.get("speed_tested_at")) or time.time()),
                    "mbps": parse_float(result.get("speed_mbps")),
                    "msg": str(result.get("speed_message") or ""),
                    "run_id": str(result.get("speed_run_id") or run_id),
                })
            except Exception as exc:
                log_to_json("WARN", "SpeedHistory", f"测速历史写入失败（不影响测速）: {exc}")
        done += 1
        speed = parse_float(result.get("speed_mbps"))
        if speed > best_speed:
            best_speed = speed
            best_id = node_id
        pipeline_set(speed_done=done, current_node_id="", best_node_id=best_id, best_speed_mbps=best_speed)
        if threshold > 0 and speed >= threshold:
            msg = f"节点 {node_id} 达到阈值 {threshold} MB/s，停止本轮测速"
            log_to_json("INFO", "SpeedTest", msg)
            pipeline_set(stopped_reason="threshold", message=msg)
            return "threshold"
    if pipeline_cancel_event.is_set():
        pipeline_set(stopped_reason="manual", message="测速已手动停止")
        return "manual"
    pipeline_set(message=f"测速完成，共 {done} 个节点")
    return ""

def maybe_switch_to_fastest(run_id: str, settings: dict[str, Any]) -> bool:
    settings = speedtest.normalize_settings(settings)
    if not settings.get("auto_switch_fastest"):
        return False
    ui_cfg = load_ui_config()
    if not ui_cfg.get("connection_enabled", True):
        return False
    if ui_cfg.get("routing_mode", "auto") == "fixed_ip":
        return False
    with lock:
        nodes = read_nodes()
        current_id = active_openvpn_node_id if active_openvpn_running() else ""
        candidates = [
            n for n in nodes
            if n.get("speed_run_id") == run_id
            and node_speed(n) > 0
            and n.get("probe_status") == "available"
        ]
        candidates = apply_routing_filters(candidates, ui_cfg)
    current_speed: float | None = None
    if current_id:
        current = next((n for n in nodes if n.get("id") == current_id), None)
        if current and current.get("speed_run_id") == run_id and node_speed(current) > 0:
            current_speed = node_speed(current)
    candidates.sort(key=lambda n: -node_speed(n))
    margin = float(settings.get("switch_margin_percent", 20))
    for candidate in candidates[:3]:
        candidate_id = str(candidate.get("id") or "")
        candidate_speed = node_speed(candidate)
        if candidate_id == current_id:
            log_to_json("INFO", "Pipeline", f"当前节点 {current_id} 已是本轮最快，无需切换")
            return False
        if current_speed is not None and candidate_speed <= current_speed * (1 + margin / 100.0):
            log_to_json(
                "INFO",
                "Pipeline",
                f"最快节点 {candidate_id}（{speedtest.format_speed(candidate_speed)}）未超过当前 {speedtest.format_speed(current_speed)} 的 {margin:.0f}% 滞后，不切换",
            )
            return False
        try:
            log_to_json("INFO", "Pipeline", f"切换到本轮最快节点 {candidate_id}（{speedtest.format_speed(candidate_speed)}）")
            connect_node(candidate_id)
            return True
        except Exception as exc:
            log_to_json("WARNING", "Pipeline", f"切换到最快节点 {candidate_id} 失败: {exc}，尝试下一个")
    return False


_KEEP = object()

def ui_listen_port() -> int:
    return bounded_int(load_ui_config().get("port"), UI_PORT, 1, 65535)

def exit_status_copy(kind: str) -> dict[str, Any]:
    with lock:
        return json.loads(json.dumps(exit_status[kind]))

def refresh_exit_status(singbox_error: Any = _KEEP, global_error: Any = _KEEP, verified: Any = _KEEP) -> None:
    ui_cfg = load_ui_config()
    with lock:
        previous_singbox = dict(exit_status["singbox"])
        previous_global = dict(exit_status["global"])
    singbox_last_error = previous_singbox.get("last_error", "") if singbox_error is _KEEP else str(singbox_error or "")
    global_last_error = previous_global.get("last_error", "") if global_error is _KEEP else str(global_error or "")
    singbox_verified = previous_singbox.get("verified") if verified is _KEEP else verified
    singbox_snapshot = singbox_exit.status_snapshot(
        bool(ui_cfg.get("singbox_exit_enabled", True)),
        DEPLOYMENT_MODE,
        exit_runner,
        singbox_last_error,
        singbox_verified,
    )
    global_snapshot = global_exit.status_snapshot(
        bool(ui_cfg.get("global_exit_enabled", False)),
        DEPLOYMENT_MODE,
        exit_runner,
        global_last_error,
    )
    with lock:
        exit_status["singbox"] = singbox_snapshot
        exit_status["global"] = global_snapshot

def set_singbox_exit(enabled: bool) -> dict[str, Any]:
    enabled = bool(enabled)
    if enabled and load_ui_config().get("global_exit_enabled"):
        raise RuntimeError("全局出口开启期间 sing-box 出口由系统接管，请先关闭全局出口")
    update_ui_config(singbox_exit_enabled=enabled)
    supported, _reason = singbox_exit.is_supported(DEPLOYMENT_MODE)
    if not supported:
        refresh_exit_status(singbox_error="", verified=None)
        return exit_status_copy("singbox")
    try:
        if enabled:
            singbox_exit.enable(exit_runner)
        else:
            singbox_exit.disable(exit_runner)
    except Exception as exc:
        refresh_exit_status(singbox_error=str(exc), verified=None)
        raise RuntimeError(str(exc)) from exc
    verified = singbox_exit.verify_via_clash_api() if enabled else None
    refresh_exit_status(singbox_error="", verified=verified)
    return exit_status_copy("singbox")

def set_global_exit(enabled: bool) -> dict[str, Any]:
    enabled = bool(enabled)
    supported, reason = global_exit.is_supported(DEPLOYMENT_MODE)
    if enabled:
        if not supported:
            refresh_exit_status(global_error=reason)
            raise RuntimeError(reason)
        update_ui_config(global_exit_enabled=True)
        try:
            set_singbox_exit(False)
        except Exception as exc:
            log_to_json("ERROR", "GlobalExit", f"关闭 sing-box 出口失败（继续开启全局出口）: {exc}")
        try:
            context = global_exit.detect_context(ui_listen_port(), exit_runner)
            global_exit.enable(context, exit_runner)
        except Exception as exc:
            update_ui_config(global_exit_enabled=False)
            try:
                set_singbox_exit(True)
            except Exception as restore_exc:
                log_to_json("ERROR", "GlobalExit", f"回滚后重新打开 sing-box 出口失败: {restore_exc}")
            refresh_exit_status(global_error=str(exc))
            raise RuntimeError(str(exc)) from exc
        refresh_exit_status(global_error="")
        log_to_json("INFO", "GlobalExit", "全局出口已开启")
    else:
        update_ui_config(global_exit_enabled=False)
        error = ""
        if supported:
            try:
                global_exit.disable(exit_runner)
            except Exception as exc:
                error = str(exc)
                log_to_json("ERROR", "GlobalExit", f"关闭全局出口失败: {exc}")
        try:
            set_singbox_exit(True)
        except Exception as exc:
            log_to_json("ERROR", "GlobalExit", f"全局出口关闭后重新打开 sing-box 出口失败: {exc}")
        refresh_exit_status(global_error=error)
        if error:
            raise RuntimeError(error)
        log_to_json("INFO", "GlobalExit", "全局出口已关闭")
    return {"global": exit_status_copy("global"), "singbox": exit_status_copy("singbox")}

def reconcile_exits_once() -> None:
    """Make the sing-box file and the policy rules match the saved switches."""
    ui_cfg = load_ui_config()
    global_enabled = bool(ui_cfg.get("global_exit_enabled", False))
    singbox_enabled = bool(ui_cfg.get("singbox_exit_enabled", True))
    if global_enabled and singbox_enabled:
        # The global switch owns the sing-box switch while it is on.
        singbox_enabled = False
        update_ui_config(singbox_exit_enabled=False)
    global_error = ""
    singbox_error = ""
    if global_exit.is_supported(DEPLOYMENT_MODE)[0]:
        try:
            global_exit.reconcile(global_enabled, ui_listen_port(), exit_runner)
        except Exception as exc:
            global_error = str(exc)
            log_to_json("ERROR", "GlobalExit", f"全局出口核对失败: {exc}")
    if singbox_exit.is_supported(DEPLOYMENT_MODE)[0]:
        try:
            singbox_exit.reconcile(singbox_enabled, exit_runner)
        except Exception as exc:
            singbox_error = str(exc)
            log_to_json("ERROR", "SingBox", f"sing-box 出口核对失败: {exc}")
    refresh_exit_status(singbox_error=singbox_error, global_error=global_error)

def apply_exit_settings_on_startup() -> None:
    try:
        reconcile_exits_once()
    except Exception as exc:
        log_to_json("ERROR", "GlobalExit", f"启动时应用出口设置失败: {exc}")

EXIT_RECONCILE_INTERVAL_SECONDS = 60

def exit_reconcile_loop() -> None:
    while True:
        time.sleep(EXIT_RECONCILE_INTERVAL_SECONDS)
        try:
            reconcile_exits_once()
        except Exception as exc:
            log_to_json("ERROR", "GlobalExit", f"出口核对线程异常: {exc}")

def global_exit_teardown_for_restart() -> None:
    """Remove policy rules before the process exits; they are re-applied on startup."""
    try:
        if not global_exit.is_supported(DEPLOYMENT_MODE)[0]:
            return
        applied = global_exit.is_applied(exit_runner)
        flagged = bool(load_ui_config().get("global_exit_enabled"))
        if applied or flagged:
            global_exit.disable(exit_runner)
            print(f"[GlobalExit] 进程退出前已拆除全局出口规则（规则存在={applied}，开关={flagged}）", flush=True)
        else:
            print("[GlobalExit] 进程退出前无全局出口规则需要拆除", flush=True)
    except Exception as exc:
        print(f"[GlobalExit] 退出前拆除全局出口规则失败: {exc}", flush=True)

def graceful_shutdown(signum: int | None = None, frame: Any = None) -> None:
    print(f"[系统] 收到退出信号 {signum}，正在清理...", flush=True)
    global_exit_teardown_for_restart()
    os._exit(0)

def handle_disconnect_request() -> None:
    global last_active_ping_time, last_active_latency
    global consecutive_proxy_failures, last_proxy_failure_node_id
    if load_ui_config().get("global_exit_enabled"):
        try:
            set_global_exit(False)
        except Exception as exc:
            log_to_json("ERROR", "GlobalExit", f"断开连接前关闭全局出口失败: {exc}")
    cancel_background_refill()
    cancel_pending_connection_attempt()
    update_ui_config(connection_enabled=False)
    clear_active_connection_state("手动断开连接")
    last_active_ping_time = 0.0
    last_active_latency = 0
    consecutive_proxy_failures = 0
    last_proxy_failure_node_id = ""

def run_cli(argv: list[str]) -> int:
    usage = "用法: python3 vpngate_manager.py [--global-exit on|off] [--singbox-exit on|off]"
    if len(argv) != 2 or argv[0] not in ("--global-exit", "--singbox-exit") or argv[1] not in ("on", "off"):
        print(usage, flush=True)
        return 1
    ensure_dirs()
    enabled = argv[1] == "on"
    try:
        if argv[0] == "--global-exit":
            result = set_global_exit(enabled)
        else:
            result = set_singbox_exit(enabled)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2), flush=True)
        return 1
    print(json.dumps({"ok": True, "status": result}, ensure_ascii=False, indent=2), flush=True)
    return 0

def consume_skip_initial_run() -> bool:
    """一次性消费安装时记录的"跳过首次自动拉取"选择。

    install.sh 全新安装答 N 时在 ui_auth.json 写入 skip_initial_run=true；
    缺少该键、值非布尔 true 或文件损坏均返回 False（Docker/手动安装与
    历史升级没有记录，维持原有自动行为）。
    """
    auth_file = DATA_DIR / "ui_auth.json"
    with lock:
        try:
            data = json.loads(auth_file.read_text(encoding="utf-8"))
        except Exception:
            return False
        if not isinstance(data, dict) or data.get("skip_initial_run") is not True:
            return False
        data["skip_initial_run"] = False
        write_json(auth_file, data)
    return True


def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        if consume_skip_initial_run():
            msg = "已按安装时的选择跳过首次自动拉取，周期任务照常执行"
            print(f"[守护线程] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)
            # install.sh 重启前会在 state.json 预置 is_connecting=True 等待首连，
            # 首跑被跳过时必须纠正，否则面板卡在"正在连接"且前端会拦截所有操作按钮。
            set_state(is_connecting=False, last_check_message=msg)
            schedule_next_check()
            wait_for_next_check()
            continue
        success = False
        try:
            print("[守护线程] 开始执行节点拉取与可用性检测周期任务...", flush=True)
            log_to_json("INFO", "Main", "开始执行节点拉取与可用性检测周期任务...")
            with_speedtest = bool(speedtest.normalize_settings(load_ui_config().get("speedtest")).get("auto_after_check"))
            res = run_pipeline("periodic", with_speedtest=with_speedtest)
            if "没有拉取到新节点" not in res:
                success = True
            log_to_json("INFO", "Main", f"周期同步与检测任务完成，结果: {res}")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")

        if not active_openvpn_running() and not success:
            # Retry shortly when nothing was fetched and no tunnel is up.
            schedule_next_check(time.time() - check_interval_seconds() + 30)

        wait_for_next_check()

def wait_for_next_check() -> None:
    """Sleep until state.next_check_at; settings changes wake us up to recompute."""
    global last_collector_heartbeat
    while True:
        collector_wakeup.clear()
        remaining = float(get_state().get("next_check_at") or 0) - time.time()
        if remaining <= 0:
            return
        collector_wakeup.wait(min(remaining, 3600))
        last_collector_heartbeat = time.time()

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 安全登录</title>
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.96);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">AimiliVPN</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    function fetchWithTimeout(resource, options = {}, timeoutMs = 20000) {
      if (typeof AbortController === "undefined") return fetch(resource, options);
      const controller = new AbortController();
      const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
      return fetch(resource, Object.assign({}, options, { signal: controller.signal }))
        .then(
          response => { window.clearTimeout(timeoutId); return response; },
          error => { window.clearTimeout(timeoutId); throw error; }
        );
    }

    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value;
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";
      
      try {
        const response = await fetchWithTimeout("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        }, 20000);
        
        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = err && err.name === "AbortError"
          ? "登录请求超时，请检查网络后重试"
          : "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AimiliVPN 节点池管理系统</title>
  <style>
    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.94);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.97);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button, .btn-telegram {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      white-space: nowrap;
      text-decoration: none;
      box-sizing: border-box;
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-telegram {
      background: rgba(43, 162, 223, 0.15);
      border: 1px solid rgba(43, 162, 223, 0.3);
      color: #2ba2df;
    }

    .btn-telegram:hover {
      background: rgba(43, 162, 223, 0.25);
      border-color: rgba(43, 162, 223, 0.5);
      color: #2ba2df;
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
      min-height: 164px; /* 常态保持 164px 固定观感；内容装不下时自然增高，绝不裁剪 */
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: nowrap; /* 图标与信息始终同排，meta 在列内换行 */
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
      min-width: 0;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 2px 16px; /* 行距收紧，两行 meta 时保持紧凑 */
      font-size: 13px;
      line-height: 1.5;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    /* New style additions */
    .header-badge-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      height: 24px;
      box-sizing: border-box;
    }
    .header-badge-link:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--border-color-hover);
      color: var(--text-primary);
      transform: translateY(-1px);
    }
    .flex-row-container {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }
    .flex-row-container > * {
      flex: 1;
      min-width: 320px;
      margin-bottom: 0 !important;
    }

    
        
    
    
    
    
    
    
    
    
    
    

    .toolbar {
      position: relative;
      z-index: 50;
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .toolbar > input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar > input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .country-filter {
      position: relative;
      width: 220px;
      flex: 0 0 220px;
    }

    .country-filter-button {
      width: 100%;
      height: 42px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 0 12px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      color: var(--text-primary);
      font: inherit;
      font-size: 14px;
      cursor: pointer;
    }

    .country-filter-button:hover,
    .country-filter-button[aria-expanded="true"] {
      border-color: var(--primary);
      background: rgba(15, 23, 42, 0.8);
    }

    .country-filter-button:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: 2px;
    }

    .country-filter-chevron {
      width: 16px;
      height: 16px;
      flex: 0 0 16px;
      transition: transform 0.2s ease;
    }

    .country-filter-button[aria-expanded="true"] .country-filter-chevron {
      transform: rotate(180deg);
    }

    .country-filter-panel {
      position: absolute;
      top: calc(100% + 8px);
      left: 0;
      z-index: 1000;
      width: min(320px, calc(100vw - 40px));
      max-height: 360px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background: rgba(15, 23, 42, 0.98);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.45);
    }

    .country-filter-panel[hidden] {
      display: none;
    }

    .country-filter-options {
      padding: 6px;
      overflow-y: auto;
    }

    .country-option {
      position: relative;
      min-height: 40px;
      display: grid;
      grid-template-columns: 18px 24px minmax(0, 1fr) auto;
      align-items: center;
      gap: 8px;
      padding: 4px 8px;
      border-radius: 6px;
      color: var(--text-primary);
      cursor: pointer;
    }

    .country-option:hover {
      background: rgba(255, 255, 255, 0.06);
    }

    .country-option-input {
      position: absolute;
      width: 1px;
      height: 1px;
      margin: 0;
      opacity: 0;
      pointer-events: none;
    }

    .country-option-box {
      width: 18px;
      height: 18px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(148, 163, 184, 0.7);
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.03);
      color: white;
      font-size: 12px;
      line-height: 1;
    }

    .country-option-input:checked + .country-option-box {
      border-color: var(--primary);
      background: var(--primary);
    }

    .country-option-input:checked + .country-option-box::after {
      content: "✓";
    }

    .country-option-input:focus-visible + .country-option-box {
      outline: 2px solid #a5b4fc;
      outline-offset: 2px;
    }

    .country-option-flag {
      font-size: 18px;
      line-height: 1;
      text-align: center;
    }

    .country-option-name {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .country-option-count {
      color: var(--text-secondary);
      font-size: 12px;
      font-variant-numeric: tabular-nums;
    }

    .country-filter-footer {
      padding: 8px;
      border-top: 1px solid var(--border-color);
    }

    .country-filter-clear {
      width: 100%;
      min-height: 36px;
      border: 0;
      border-radius: 6px;
      background: transparent;
      color: #a5b4fc;
      font: inherit;
      font-size: 13px;
      cursor: pointer;
    }

    .country-filter-clear:hover,
    .country-filter-clear:focus-visible {
      background: rgba(99, 102, 241, 0.12);
      outline: none;
    }

    .table-wrapper {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }

    table {
      width: 100%;
      min-width: 1180px;
      border-collapse: collapse;
      text-align: left;
      table-layout: fixed;
    }

    th, td {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .testing {
      background: rgba(59, 130, 246, 0.12);
      color: #93c5fd;
      border-color: rgba(59, 130, 246, 0.24);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
      align-items: center;
      white-space: nowrap;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    .latency-estimated {
      background: rgba(148, 163, 184, 0.08);
      color: var(--text-secondary);
      border: 1px dashed rgba(148, 163, 184, 0.35);
      font-weight: 500;
    }

    .latency-source {
      margin-left: 4px;
      font-size: 10px;
      opacity: 0.8;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
        position: static;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
        gap: 8px;
        flex-wrap: wrap;
      }
      .btn-group > button,
      .btn-group > .btn-telegram,
      .btn-group > .dropdown {
        flex: 1 1 calc(50% - 4px);
        min-width: 0;
      }
      .btn-group .dropdown {
        display: flex;
      }
      .btn-group .dropdown button {
        width: 100%;
        flex: 1;
      }
      #github_dropdown {
        left: 0;
        right: auto;
        width: min(280px, calc(100vw - 40px));
        min-width: 0;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
      .active-card-title {
        flex-wrap: wrap;
      }
      .active-card .active-card-task {
        max-width: 100%;
        width: 100%;
        min-width: 0; /* 放开桌面保底宽度，小屏不横向溢出 */
        padding-left: 0;
        padding-top: 12px;
        border-left: none;
        border-top: 1px solid rgba(99, 102, 241, 0.18);
        text-align: left;
      }
      .active-card .active-card-task .pipeline-running,
      .active-card .active-card-task .pipeline-head,
      .active-card .active-card-task .pipeline-idle,
      .active-card .active-card-task .pipeline-stages {
        align-items: flex-start;
        justify-content: flex-start; /* 媒体块位于基础规则之前，需更高特异度才能覆盖 flex-end */
      }
      .active-card-meta {
        gap: 8px 16px;
      }
      button, .btn-telegram {
        min-height: 44px;
      }
      .input-field,
      .toolbar select,
      .toolbar > input {
        font-size: 16px;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.99);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
    }
    .dropdown-content a,
    .dropdown-content button {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      text-align: left;
      font-size: 13px;
      font-weight: 500;
      font-family: inherit;
      border: 0;
      background: transparent;
      box-sizing: border-box;
      cursor: pointer;
      transition: background 0.2s;
    }
    .dropdown-content a:hover,
    .dropdown-content button:hover:not(:disabled),
    .dropdown-content a:focus-visible,
    .dropdown-content button:focus-visible {
      background: rgba(255,255,255,0.08);
      outline: none;
    }
    .dropdown-content button:disabled {
      opacity: 0.55;
      cursor: wait;
    }
    .github-dropdown {
      min-width: 250px;
      padding: 6px;
    }
    .version-current {
      padding: 9px 10px 10px;
      margin-bottom: 4px;
      border-bottom: 1px solid var(--border-color);
    }
    .version-current-label {
      color: var(--text-primary);
      font-size: 13px;
      font-weight: 700;
    }
    .version-current-meta {
      margin-top: 3px;
      color: var(--text-secondary);
      font-size: 11px;
    }
    .update-check-status {
      min-height: 34px;
      margin: 6px 6px 0;
      padding: 8px 10px;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-secondary);
      font-size: 12px;
      line-height: 1.45;
      overflow-wrap: anywhere;
    }
    .update-check-status.available {
      border-color: rgba(245, 158, 11, 0.35);
      color: #fbbf24;
      background: rgba(245, 158, 11, 0.08);
    }
    .update-check-status.current {
      border-color: rgba(16, 185, 129, 0.3);
      color: #34d399;
      background: rgba(16, 185, 129, 0.08);
    }
    .update-check-status.error {
      border-color: rgba(244, 63, 94, 0.3);
      color: #fb7185;
      background: rgba(244, 63, 94, 0.08);
    }
    
    /* Themed scrollbars */
    * {
      scrollbar-width: thin;
      scrollbar-color: rgba(129, 140, 248, 0.35) transparent;
    }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb {
      background: rgba(129, 140, 248, 0.28);
      border-radius: 8px;
      border: 2px solid transparent;
      background-clip: padding-box;
    }
    ::-webkit-scrollbar-thumb:hover { background: rgba(129, 140, 248, 0.5); background-clip: padding-box; }
    ::-webkit-scrollbar-corner { background: transparent; }

    /* Hide native number spinners; themed steppers are added by JS */
    input[type="number"] { -moz-appearance: textfield; appearance: textfield; }
    input[type="number"]::-webkit-outer-spin-button,
    input[type="number"]::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
    .num-stepper { position: relative; display: block; }
    .num-stepper > input { padding-right: 34px; width: 100%; box-sizing: border-box; }
    .num-stepper-btns {
      position: absolute; top: 4px; right: 4px; bottom: 4px; width: 24px;
      display: flex; flex-direction: column; gap: 2px;
    }
    .num-stepper-btns button {
      flex: 1; border: none; padding: 0; cursor: pointer; border-radius: 4px;
      background: rgba(255, 255, 255, 0.05); color: var(--text-secondary);
      display: flex; align-items: center; justify-content: center;
      transition: background 0.15s, color 0.15s;
    }
    .num-stepper-btns button:hover { background: rgba(99, 102, 241, 0.3); color: #fff; }
    .num-stepper-btns svg { width: 10px; height: 10px; }

    @media (max-width: 720px) {
      .speedtest-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }

    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      right: 0;
      bottom: 0;
      overflow-y: auto;
      padding: 24px;
      box-sizing: border-box;
      background-color: rgba(9, 13, 22, 0.92);
      align-items: flex-start;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.99);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      margin: auto;
      max-height: calc(100vh - 48px);
      max-height: calc(100dvh - 48px);
      overflow-y: auto;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }
    select option {
      background-color: #0f172a;
      color: #f8fafc;
    }
    
    /* Option Card Styles for Proxy/Routing Settings */
    .option-group {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 6px;
    }
    
    @media (max-width: 480px) {
      .option-group {
        grid-template-columns: 1fr;
      }
    }
    
    .switch {
      position: relative;
      display: inline-block;
      width: 44px;
      height: 24px;
      flex-shrink: 0;
    }

    .switch-input {
      position: absolute;
      width: 1px;
      height: 1px;
      margin: 0;
      opacity: 0;
      pointer-events: none;
    }

    .switch-track {
      position: absolute;
      inset: 0;
      background: rgba(148, 163, 184, 0.35);
      border-radius: 999px;
      cursor: pointer;
      transition: background 0.2s;
    }

    .switch-track::after {
      content: "";
      position: absolute;
      top: 3px;
      left: 3px;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: white;
      transition: transform 0.2s;
    }

    .switch-input:checked + .switch-track {
      background: var(--primary);
    }

    .switch-input:checked + .switch-track::after {
      transform: translateX(20px);
    }

    .switch-input:disabled + .switch-track {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .switch-input:focus-visible + .switch-track {
      outline: 2px solid #a5b4fc;
      outline-offset: 2px;
    }

    .switch-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .exit-status {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
      margin-top: 8px;
      white-space: pre-line;
    }

    .speedtest-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px 16px;
    }

    .speedtest-countries {
      max-height: 180px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.02);
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .active-card-task {
      display: none;
      max-width: 44%;
      min-width: 360px; /* 保底宽度：桌面端文案行与进度行单行放下，卡片保底高度内完整显示 */
      box-sizing: border-box;
      padding-left: 24px;
      border-left: 1px solid rgba(99, 102, 241, 0.18);
      font-size: 13px;
      color: var(--text-secondary);
      text-align: right;
    }
    .active-card-task .pipeline-idle {
      justify-content: flex-end;
    }
    .active-card-task .pipeline-stages {
      margin: 0;
      justify-content: flex-end;
    }
    .pipeline-idle {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 6px;
      font-size: 13px;
      color: var(--text-secondary);
    }
    .pipeline-sep {
      margin: 0 4px;
      opacity: 0.5;
    }
    .pipeline-running {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 4px;
      width: 100%;
    }
    .pipeline-running > * {
      max-width: 100%;
    }
    .pipeline-head {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 8px;
      flex-wrap: wrap;
    }
    .pipeline-details {
      font-size: 13px;
      line-height: 1.5;
      color: var(--text-secondary);
    }

    .pipeline-stages {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 10px 0;
    }

    .pipeline-stage {
      padding: 4px 12px;
      border-radius: 999px;
      font-size: 12px;
      border: 1px solid var(--border-color);
      color: var(--text-secondary);
    }

    .pipeline-stage.done {
      border-color: rgba(16, 185, 129, 0.4);
      color: #34d399;
    }

    .pipeline-stage.current {
      border-color: var(--primary);
      background: rgba(99, 102, 241, 0.15);
      color: var(--text-primary);
    }

    .speed-testing {
      color: var(--warning);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .option-card {
      width: 100%;
      height: auto;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 12px 14px;
      cursor: pointer;
      color: var(--text-primary);
      font-family: inherit;
      text-align: left;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      user-select: none;
      position: relative;
      text-align: left;
    }
    
    .option-card:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(99, 102, 241, 0.25);
      transform: translateY(-1px);
    }
    
    .option-card.active {
      background: rgba(99, 102, 241, 0.08);
      border-color: var(--primary);
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.15);
    }
    
    .option-card-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 4px;
    }
    
    .option-card-desc {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.3;
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      AimiliVPN 节点管理系统
    </h1>
    <div id="status" class="status" role="status" aria-live="polite"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">

    <div class="dropdown">
      <button id="github_btn" class="btn-primary" type="button" aria-expanded="false" aria-controls="github_dropdown" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        <span id="github_version_label">V2.2.0 正式版</span>
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="github_dropdown" class="dropdown-content github-dropdown">
        <div class="version-current">
          <div id="current_version_label" class="version-current-label">V2.2.0 正式版</div>
          <div id="deployment_mode_label" class="version-current-meta">Python 源码部署 · 更新通道：main</div>
        </div>
        <button id="check_update_btn" type="button" onclick="checkForUpdate(event)">
          <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
          检测更新
        </button>
        <a href="https://github.com/kadidalax/aimili-vpngate/tree/main" target="_blank" rel="noopener noreferrer">GitHub main 主分支</a>
        <a id="latest_release_link" href="https://github.com/kadidalax/aimili-vpngate/releases/latest" target="_blank" rel="noopener noreferrer">下载最新正式版</a>
        <div id="update_check_status" class="update-check-status" role="status" aria-live="polite">点击“检测更新”查询 GitHub 最新正式版。</div>
      </div>
    </div>
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" type="button" aria-expanded="false" aria-controls="admin_dropdown" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>
  
    <!-- 当前连接活动节点卡片（含拉取/测速任务槽 pipeline_panel） -->
    <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
      <!-- Rendered dynamically by render() -->
    </section>



  <section class="toolbar">
    <select id="status_filter">
      <option value="all">全部节点</option>
      <option value="available">可用节点</option>
      <option value="testing">检测中</option>
      <option value="unavailable">失效节点</option>
    </select>
    <div class="country-filter" id="country_filter">
      <button
        id="country_filter_button"
        class="country-filter-button"
        type="button"
        aria-expanded="false"
        aria-controls="country_filter_panel"
      >
        <span id="country_filter_label">所有国家</span>
        <svg class="country-filter-chevron" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      <div id="country_filter_panel" class="country-filter-panel" role="group" aria-label="国家筛选" hidden>
        <div id="country_filter_options" class="country-filter-options"></div>
        <div class="country-filter-footer">
          <button class="country-filter-clear" type="button" onclick="clearDiscoveryCountries(event)">清空选择</button>
        </div>
      </div>
    </div>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
    </select>
    <select id="sort_mode" title="排序方式">
      <option value="default">默认排序</option>
      <option value="speed">按实测速度</option>
    </select>
    <button id="btn_speedtest_filtered" class="toolbar-btn" type="button" onclick="startFilteredSpeedtest()" style="margin-left: auto; height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
      测当前筛选
    </button>
    <button id="btn_speedtest" class="toolbar-btn" type="button" onclick="openSpeedtestModal()" style="height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
      测速
    </button>
    <button id="btn_favorites" class="toolbar-btn" type="button" onclick="toggleFavoritesView()" style="height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.907c.961 0 1.371 1.24.588 1.81l-3.97 2.883a1 1 0 00-.364 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.971-2.883a1 1 0 00-1.175 0l-3.97 2.883c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.364-1.118l-3.97-2.883c-.783-.57-.372-1.81.588-1.81h4.906a1 1 0 00.951-.69l1.519-4.674z" />
      </svg>
      收藏菜单
    </button>
  </section>
  <div id="favorites_panel" style="display: none; background: rgba(22, 30, 49, 0.97); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; margin-bottom: 20px; animation: modalFadeIn 0.25s ease-out;">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
            ⭐ 收藏专属管理面板
          </span>
          <span style="font-size: 13px; color: var(--text-secondary);">
            在这里管理您的收藏节点过滤，以及设置出站连接漂移策略。
          </span>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
          <button id="btn_toggle_fav_routing" type="button" class="toolbar-btn" style="height: 36px; padding: 0 14px; font-size: 13px; border-radius: 6px;" onclick="toggleFavRouting()">
            启用仅用收藏出站
          </button>
        </div>
      </div>
      
      <div style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
        <div style="padding: 10px 14px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 8px; font-size: 12px; color: var(--warning); line-height: 1.5;">
          <strong>仅用收藏是强锁定模式。</strong>开启后只会连接收藏节点；如果收藏节点全部不可用，系统不会切换到非收藏节点。
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 72px;">状态</th>
            <th style="width: 195px;">IP 地址 : 端口</th>
            <th style="width: 90px;">延迟</th>
            <th style="width: 90px;">实测速度</th>
            <th>物理位置</th>
            <th>运营主体 / ISP</th>
            <th style="width: 80px;">IP 类型</th>
            <th style="width: 270px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div id="pagination_container" class="pagination-container" style="padding: 16px; display: none; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="credentials_modal_title" aria-hidden="true">
    <div class="modal-content" tabindex="-1">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 id="credentials_modal_title" style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </h3>
        <button type="button" aria-label="关闭网页安全设置" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="credentials_error" role="alert" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" role="status" aria-live="polite" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号">
        </div>
        
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_port">网页管理端口</label>
          <input type="number" id="cred_port" class="input-field" required min="1" max="65535" placeholder="8787">
        </div>
        
        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="network_modal_title" aria-hidden="true">
    <div class="modal-content" tabindex="-1" style="max-width: 640px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 id="network_modal_title" style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </h3>
        <button type="button" aria-label="关闭代理设置" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="network_error" role="alert" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" role="status" aria-live="polite" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <div class="switch-row">
              <label class="form-label" for="net_global_exit" style="margin: 0;">全局出口（VPS 全部出站经 VPN）</label>
              <span class="switch">
                <input type="checkbox" id="net_global_exit" class="switch-input" onchange="toggleGlobalExit(this.checked)">
                <span class="switch-track" onclick="const i=$('net_global_exit'); if(!i.disabled){ i.checked=!i.checked; i.dispatchEvent(new Event('change')); }"></span>
              </span>
            </div>
            <div style="font-size: 12px; color: var(--danger); margin-top: 6px; line-height: 1.4;">⚠️ 开启后 VPS 所有出站流量经 VPN 节点；隧道断开时全部出站中断（SSH 与本面板不受影响）。</div>
            <div id="global_exit_status" class="exit-status"></div>
          </div>
          <div class="form-group" style="margin-bottom: 16px;">
            <div class="switch-row">
              <label class="form-label" for="net_singbox_exit" style="margin: 0;">sing-box 出口接管</label>
              <span class="switch">
                <input type="checkbox" id="net_singbox_exit" class="switch-input" onchange="toggleSingboxExit(this.checked)">
                <span class="switch-track" onclick="const i=$('net_singbox_exit'); if(!i.disabled){ i.checked=!i.checked; i.dispatchEvent(new Event('change')); }"></span>
              </span>
            </div>
            <div id="singbox_exit_status" class="exit-status"></div>
            <button type="button" id="btn_verify_singbox" class="test-btn" style="margin-top: 8px; height: 30px; padding: 0 12px;" onclick="verifySingboxExit()">验证出口</button>
          </div>
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站路由模式</label>
            <input type="hidden" id="net_routing_mode" value="auto">
            <div class="option-group" id="routing_mode_group">
              <button type="button" class="option-card active" data-value="auto" aria-pressed="true" onclick="setRoutingMode('auto')">
                <div class="option-card-title">自动配置</div>
                <div class="option-card-desc">智能切换，最稳定</div>
              </button>
              <button type="button" class="option-card" data-value="fixed_ip" aria-pressed="false" onclick="setRoutingMode('fixed_ip')">
                <div class="option-card-title">固定 IP</div>
                <div class="option-card-desc">锁定IP，不自动切换</div>
              </button>
              <button type="button" class="option-card" data-value="fixed_region" aria-pressed="false" onclick="setRoutingMode('fixed_region')">
                <div class="option-card-title">固定地区</div>
                <div class="option-card-desc">锁定特定国家地区</div>
              </button>
            </div>
          </div>
          
          <div id="net_force_country_group" class="form-group" style="margin-bottom: 16px; display: none;">
            <label class="form-label" for="net_force_country">锁定国家地区</label>
            <select id="net_force_country" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">正在加载节点国家...</option>
            </select>
          </div>
          
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站类型过滤</label>
            <input type="hidden" id="net_routing_ip_type" value="all">
            <div class="option-group" id="routing_ip_type_group">
              <button type="button" class="option-card active" data-value="all" aria-pressed="true" onclick="setRoutingIpType('all')">
                <div class="option-card-title">所有IP</div>
                <div class="option-card-desc">机房 + 住宅</div>
              </button>
              <button type="button" class="option-card" data-value="residential" aria-pressed="false" onclick="setRoutingIpType('residential')">
                <div class="option-card-title">住宅IP</div>
                <div class="option-card-desc">静态家宽</div>
              </button>
              <button type="button" class="option-card" data-value="hosting" aria-pressed="false" onclick="setRoutingIpType('hosting')">
                <div class="option-card-title">机房IP</div>
                <div class="option-card-desc">普通机房</div>
              </button>
            </div>
          </div>
          
          <div id="net_routing_warning" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>


  <div id="speedtest_modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="speedtest_modal_title" aria-hidden="true">
    <div class="modal-content" tabindex="-1" style="max-width: 820px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 id="speedtest_modal_title" style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          节点测速
        </h3>
        <button type="button" aria-label="关闭节点测速" onclick="closeSpeedtestModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div id="speedtest_error" role="alert" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="speedtest_success" role="status" aria-live="polite" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="speedtest_form" onsubmit="event.preventDefault(); saveSpeedtestSettings(false);">
        <div class="form-group" style="margin-bottom: 14px;">
          <label class="form-label" for="st_status">测速范围（节点状态）</label>
          <select id="st_status" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
            <option value="available">仅可用节点</option>
            <option value="unavailable">仅失效节点</option>
            <option value="all">全部节点</option>
          </select>
        </div>
        <div class="form-group" style="margin-bottom: 14px;">
          <label class="form-label">国家范围（不选则全部）</label>
          <div id="st_countries" class="country-filter-options speedtest-countries"></div>
        </div>
        <div class="form-group" style="margin-bottom: 14px;">
          <label class="form-label">IP 类型（不选则全部）</label>
          <div id="st_ip_types" style="display: flex; gap: 16px; flex-wrap: wrap; font-size: 13px; color: var(--text-primary);">
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;"><input type="checkbox" class="st-ip-type" value="residential"> 住宅</label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;"><input type="checkbox" class="st-ip-type" value="mobile"> 移动</label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;"><input type="checkbox" class="st-ip-type" value="hosting"> 机房</label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;"><input type="checkbox" class="st-ip-type" value="unknown"> 未知</label>
          </div>
        </div>
        <div class="speedtest-grid" style="margin-bottom: 14px;">
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="st_check_interval_hours">自动任务周期（小时，1 至 72）</label>
            <input type="number" id="st_check_interval_hours" class="input-field" min="1" max="72" step="1" placeholder="24">
            <div id="next_check_label" class="exit-status"></div>
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="st_retest_hours" title="这段时间内测过速的节点本轮不再测，0 表示全部重测">跳过 N 小时内已测过的节点</label>
            <input type="number" id="st_retest_hours" class="input-field" min="0" max="720" step="1">
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="st_seconds">单节点测速秒数</label>
            <input type="number" id="st_seconds" class="input-field" min="3" max="60" step="1">
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="st_max_mb">单节点最大流量（MB）</label>
            <input type="number" id="st_max_mb" class="input-field" min="1" max="500" step="1">
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="st_threshold">达标即停阈值（MB/s，0 不停）</label>
            <input type="number" id="st_threshold" class="input-field" min="0" max="1000" step="0.1">
            <div id="st_threshold_mbit" class="exit-status" style="margin-top: 4px;"></div>
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="st_margin">切换滞后（%）</label>
            <input type="number" id="st_margin" class="input-field" min="0" max="500" step="1">
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="st_url">测速地址</label>
            <input type="text" id="st_url" class="input-field" placeholder="https://...">
          </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 14px;">
          <div class="switch-row">
            <label class="form-label" for="st_auto" style="margin: 0;">每轮检测后自动测速</label>
            <span class="switch">
              <input type="checkbox" id="st_auto" class="switch-input">
              <span class="switch-track" onclick="const i=$('st_auto'); i.checked=!i.checked; i.dispatchEvent(new Event('input', {bubbles: true}));"></span>
            </span>
          </div>
          <div class="switch-row">
            <label class="form-label" for="st_auto_switch" style="margin: 0;">自动切换最快节点</label>
            <span class="switch">
              <input type="checkbox" id="st_auto_switch" class="switch-input">
              <span class="switch-track" onclick="const i=$('st_auto_switch'); i.checked=!i.checked; i.dispatchEvent(new Event('input', {bubbles: true}));"></span>
            </span>
          </div>
        </div>
        <div id="st_estimate" style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-bottom: 16px;">正在估算...</div>
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeSpeedtestModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="st_save" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-primary); cursor: pointer;">保存设置</button>
          <button type="button" id="st_save_start" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;" onclick="saveSpeedtestSettings(true)">保存并开始测速</button>
        </div>
      </form>
    </div>
  </div>


  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="gateway_modal_title" aria-hidden="true">
    <div class="modal-content" tabindex="-1" style="max-width: 600px; width: 90%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 id="gateway_modal_title" style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置与自检
        </h3>
        <button type="button" aria-label="关闭网关设置" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed rgba(255, 255, 255, 0.08); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>
        
        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>
      
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="logs_modal_title" aria-hidden="true">
    <div class="modal-content" tabindex="-1" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 id="logs_modal_title" style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>
        
        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: rgba(255, 255, 255, 0.03);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
        </div>
        
        <button type="button" aria-label="关闭日志" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #a5b4fc; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
          <button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
            一键复制
          </button>
          <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
const favoriteRequestIds = new Set();
let disconnectInFlight = false;
let currentPage = 1;
const pageSize = 50;
let currentPageNodes = [];
let selectedDiscoveryCountries = new Set();
let discoveryCountriesInitialized = false;
let discoveryCountriesDirty = false;
let countryFilterSignature = "";
let lastNodesSnapshotSignature = "";

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
function fetchWithTimeout(resource, options = {}, timeoutMs = 20000) {
  if (typeof AbortController === "undefined") return fetch(resource, options);
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
  return fetch(resource, Object.assign({}, options, { signal: controller.signal }))
    .then(
      response => { window.clearTimeout(timeoutId); return response; },
      error => { window.clearTimeout(timeoutId); throw error; }
    );
}
async function readJsonResponse(response, fallbackMessage) {
  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    if (response.ok) throw new Error("服务器返回了无效数据");
  }
  if (!response.ok) throw new Error(data.error || `${fallbackMessage} (${response.status})`);
  return data;
}
function formatUrlHost(hostname) {
  const host = String(hostname || "");
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

let activeModalId = "";
let modalReturnFocus = null;
let previousBodyOverflow = "";
function showModal(id, preferredFocusSelector) {
  const modal = $(id);
  if (!modal) return;
  modalReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  previousBodyOverflow = document.body.style.overflow;
  activeModalId = id;
  modal.style.display = "flex";
  modal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  window.setTimeout(() => {
    const preferred = preferredFocusSelector ? modal.querySelector(preferredFocusSelector) : null;
    const first = preferred || modal.querySelector('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])');
    const focusTarget = first || modal.querySelector(".modal-content");
    if (focusTarget) focusTarget.focus();
  }, 0);
}
function hideModal(id) {
  const modal = $(id);
  if (!modal) return;
  modal.style.display = "none";
  modal.setAttribute("aria-hidden", "true");
  if (activeModalId === id) {
    activeModalId = "";
    document.body.style.overflow = previousBodyOverflow;
    const returnTarget = modalReturnFocus;
    modalReturnFocus = null;
    if (returnTarget && document.contains(returnTarget)) returnTarget.focus();
  }
}
function closeActiveModal() {
  if (activeModalId === "credentials_modal") closeCredentialsModal();
  else if (activeModalId === "network_modal") closeNetworkModal();
  else if (activeModalId === "gateway_modal") closeGatewayModal();
  else if (activeModalId === "logs_modal") closeLogsModal();
}
document.querySelectorAll(".modal").forEach(modal => {
  modal.addEventListener("mousedown", event => {
    if (event.target === modal && activeModalId === modal.id) closeActiveModal();
  });
});
document.addEventListener("keydown", event => {
  if (!activeModalId) return;
  const modal = $(activeModalId);
  if (!modal) return;
  if (event.key === "Escape") {
    event.preventDefault();
    closeActiveModal();
    return;
  }
  if (event.key !== "Tab") return;
  const focusable = Array.from(modal.querySelectorAll('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'));
  if (!focusable.length) {
    event.preventDefault();
    modal.querySelector(".modal-content").focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
});
const renderedHtmlCache = new WeakMap();
function setHtmlIfChanged(element, html) {
  if (!element || renderedHtmlCache.get(element) === html) return false;
  element.innerHTML = html;
  renderedHtmlCache.set(element, html);
  return true;
}
function isPageVisible() {
  return typeof document.hidden !== "boolean" || !document.hidden;
}
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "unknown": "未知", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateConfidence = value => ({high: "高", medium: "中", low: "低"}[value] || "未知");

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "testing": "检测中", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function countryFlag(countryShort) {
  const code = String(countryShort || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return Array.from(code)
    .map(char => String.fromCodePoint(char.charCodeAt(0) + 127397))
    .join("");
}

function nodeLatencyHtml(node) {
  const measured = Number(node && node.latency_ms) || 0;
  if (measured > 0) {
    return `<span class="latency-val ${getLatencyClass(measured)}" title="本机实测延迟">${measured} ms</span>`;
  }
  const estimated = Number(node && node.ping) || 0;
  if (estimated > 0) {
    return `<span class="latency-val latency-estimated" title="VPNGate 官方公示值，仅供参考、非本机实测">~${estimated} ms<span class="latency-source">预估</span></span>`;
  }
  return "-";
}

function syncDiscoveryCountriesFromState() {
  if (discoveryCountriesInitialized && discoveryCountriesDirty) return;
  const saved = Array.isArray(state.discovery_countries) ? state.discovery_countries : [];
  selectedDiscoveryCountries = new Set(
    saved
      .map(code => String(code || "").trim().toUpperCase())
      .filter(code => /^[A-Z]{2}$/.test(code))
  );
  discoveryCountriesInitialized = true;
}

function updateCountryFilterLabel() {
  const label = $("country_filter_label");
  if (!label) return;
  const count = selectedDiscoveryCountries.size;
  label.textContent = count ? `已选 ${count} 个国家` : "所有国家";
}

function updateCountryFilter() {
  syncDiscoveryCountriesFromState();
  const countries = new Map();
  nodes.forEach(node => {
    if (!node) return;
    const code = String(node.country_short || "").trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return;
    const current = countries.get(code) || {
      code,
      name: translateCountry(node.country) || code,
      count: 0,
    };
    current.count += 1;
    countries.set(code, current);
  });
  selectedDiscoveryCountries.forEach(code => {
    if (!countries.has(code)) {
      countries.set(code, { code, name: code, count: 0 });
    }
  });
  const options = Array.from(countries.values()).sort((a, b) =>
    a.name.localeCompare(b.name, "zh-CN") || a.code.localeCompare(b.code)
  );
  const signature = JSON.stringify(options);
  if (signature !== countryFilterSignature) {
    const container = $("country_filter_options");
    container.innerHTML = options.length
      ? options.map(item => `
          <label class="country-option">
            <input
              class="country-option-input"
              type="checkbox"
              value="${esc(item.code)}"
              ${selectedDiscoveryCountries.has(item.code) ? "checked" : ""}
              onchange="toggleDiscoveryCountry(this)"
            >
            <span class="country-option-box" aria-hidden="true"></span>
            <span class="country-option-flag" aria-hidden="true">${esc(countryFlag(item.code))}</span>
            <span class="country-option-name">${esc(item.name)}</span>
            <span class="country-option-count">${item.count}</span>
          </label>
        `).join("")
      : '<div style="padding:12px; color:var(--text-secondary); font-size:13px;">暂无国家数据</div>';
    countryFilterSignature = signature;
  }
  document.querySelectorAll(".country-option-input").forEach(input => {
    input.checked = selectedDiscoveryCountries.has(input.value);
  });
  updateCountryFilterLabel();
}

function setCountryFilterOpen(open) {
  const button = $("country_filter_button");
  const panel = $("country_filter_panel");
  if (!button || !panel) return;
  button.setAttribute("aria-expanded", open ? "true" : "false");
  panel.hidden = !open;
}

function toggleDiscoveryCountry(input) {
  const code = String(input.value || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return;
  if (input.checked) selectedDiscoveryCountries.add(code);
  else selectedDiscoveryCountries.delete(code);
  discoveryCountriesDirty = true;
  currentPage = 1;
  updateCountryFilterLabel();
  render();
}

function clearDiscoveryCountries(event) {
  if (event) event.stopPropagation();
  selectedDiscoveryCountries.clear();
  discoveryCountriesDirty = true;
  document.querySelectorAll(".country-option-input").forEach(input => {
    input.checked = false;
  });
  currentPage = 1;
  updateCountryFilterLabel();
  render();
}

function nodeSpeedValue(n) {
  const value = Number(n && n.speed_mbps);
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function getFilteredNodes() {
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  const sortMode = $("sort_mode") ? $("sort_mode").value : "default";
  const filtered = nodes.filter(n => {
    if (!n) return false;
    const countryCode = String(n.country_short || "").trim().toUpperCase();
    if (selectedDiscoveryCountries.size && !selectedDiscoveryCountries.has(countryCode)) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
    }
    if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) {
      return false;
    }
    if (selectedStatus === "testing" && n.probe_status !== "testing") {
      return false;
    }
    if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) {
      return false;
    }
    const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
    if (showFavoritesOnly && !favoriteIds.includes(n.id)) {
      return false;
    }
    return true;
  });
  if (sortMode === "speed") {
    filtered.sort((a, b) => {
      const aSpeed = nodeSpeedValue(a);
      const bSpeed = nodeSpeedValue(b);
      if (bSpeed !== aSpeed) return bSpeed - aSpeed;
      return String(a.id || "").localeCompare(String(b.id || ""));
    });
  }
  return filtered;
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

// 连接状态只看隧道本身：后台检测/测速不改变它，只有切换节点时才是 connecting
function connectionPhase(activeNode) {
  if (activeNode) return "connected";
  if (state.pending_node_id) return "connecting";
  const exitHeld = Boolean((state.singbox_exit && state.singbox_exit.applied) || (state.global_exit && state.global_exit.applied));
  return exitHeld ? "blocked" : "disconnected";
}

function render(){
  const versionLabel = state.app_version_label || "V2.2.0 正式版";
  if ($("github_version_label")) $("github_version_label").textContent = versionLabel;
  if ($("current_version_label")) $("current_version_label").textContent = versionLabel;
  if ($("deployment_mode_label")) {
    const modeLabel = state.deployment_mode_label || "Python 源码";
    $("deployment_mode_label").textContent = `${modeLabel}部署 · 更新通道：main`;
  }

  const activeNode = nodes.find(n => n && n.active);
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  let activeCardHtml = "";
  const phase = connectionPhase(activeNode);
  if (phase === "connecting") {
    const busyMessage = state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...";
    activeCardHtml = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong class="mono">${esc(state.pending_node_id)}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(busyMessage)}
            </div>
          </div>
        </div>
        <div class="active-card-task" id="pipeline_panel" aria-live="polite"></div>
      </div>
    `;
  } else if (activeNode) {
    const latencyText = nodeLatencyHtml(activeNode);
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    const declaredFlag = countryFlag(activeNode.country_short);
    const locationFlag = countryFlag(activeNode.geo_country_short || activeNode.country_short);
    const ipTypeTitle = `${translateIpType(activeNode.ip_type)} · 置信度：${translateConfidence(activeNode.ip_type_confidence)} · 来源：${(activeNode.ip_type_sources || []).join(" + ") || "未知"}`;
    activeCardHtml = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${declaredFlag ? `${esc(declaredFlag)} ` : ""}${esc(translateCountry(activeNode.country))} 节点</strong>
              <button class="btn-danger" ${disconnectInFlight ? "disabled" : ""} style="height: 30px; padding: 0 12px; border-radius: 8px; font-size: 12px;" onclick="disconnectNode()">
                <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                断开连接
              </button>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span title="IP 情报源推测位置；节点申报国家见标题">物理位置: <strong>${locationFlag ? `${esc(locationFlag)} ` : ""}${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">实测速度: <strong>${speedCellHtml(activeNode)}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;" title="${esc(ipTypeTitle)}">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <div class="active-card-task" id="pipeline_panel" aria-live="polite"></div>
      </div>
    `;
  } else {
    activeCardHtml = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">${phase === "blocked" ? "出口已阻断" : "未连接"}</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${phase === "blocked"
                ? "出口接管已开启，隧道恢复前经 VPN 出口的流量会直接失败，不会回落到 VPS 直连。"
                : "在下方列表中选择一个可用节点并点击“切换”开始连接。"}
            </div>
          </div>
        </div>
        <div class="active-card-task" id="pipeline_panel" aria-live="polite"></div>
      </div>
    `;
  }
  setHtmlIfChanged(activeCardContainer, activeCardHtml);
  renderPipelinePanel();
  if ($("network_modal") && $("network_modal").getAttribute("aria-hidden") === "false") renderExitStatus();

  const shown = getFilteredNodes();
  
  if ($("total")) $("total").textContent = nodes.length; 
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0; 
  
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  const phaseBadge = {
    connected: activeNode ? `<span class="badge available" style="padding:2px 8px;">已连接 · ${esc(countryFlag(activeNode.country_short))} ${esc(translateCountry(activeNode.country))} ${esc(activeNode.ip || activeNode.remote_host || "")}</span>` : "",
    connecting: `<span class="badge" style="padding:2px 8px; background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);">正在连接</span>`,
    blocked: `<span class="badge unavailable" style="padding:2px 8px;">未连接 · 出口已阻断</span>`,
    disconnected: `<span class="badge unavailable" style="padding:2px 8px;">未连接</span>`,
  }[phase];
  const taskHint = state.pipeline && state.pipeline.running ? `<span style="color: var(--text-secondary);">· 后台任务进行中</span>` : "";
  if ($("status")) { setHtmlIfChanged($("status"), `<span class="status-dot"></span>本地代理 ${esc(localProxy)} · ${phaseBadge} ${taskHint}`); }
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (phase === "connecting") {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  const paginationContainer = $("pagination_container");
  if (paginationContainer) paginationContainer.style.display = totalPages > 1 ? "flex" : "none";
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  let rowsHtml = "";
  if (currentPageNodes.length === 0) {
    rowsHtml = `<tr><td colspan="8" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    rowsHtml = currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const isPending = Boolean(state.is_connecting && state.pending_node_id === n.id);
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (isPending ? 'testing' : (n.probe_status || 'not_checked'));
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : (isPending ? '<span class="badge-pulse"></span>切换中' : translateStatus(n.probe_status));
      const latencyText = nodeLatencyHtml(n);
      const displayLocation = n.location || translateCountry(n.country) || "-";
      const flag = countryFlag(n.geo_country_short || n.country_short);
      const locationTitle = n.location
        ? `IP 推测位置：${displayLocation}；节点申报国家：${translateCountry(n.country)}`
        : `节点申报国家：${translateCountry(n.country)}`;
      const ipTypeTitle = `${translateIpType(n.ip_type)} · 置信度：${translateConfidence(n.ip_type_confidence)} · 来源：${(n.ip_type_sources || []).join(" + ") || "未知"}`;
      
      const isTesting = testingNodeIds.has(n.id) || n.probe_status === "testing";
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || isTesting || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">${isPending ? '切换中' : '切换'}</button>`;
      
      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favoriteBusy = favoriteRequestIds.has(n.id);
      const favBtn = isFav 
        ? `<button class="test-btn" ${favoriteBusy ? "disabled" : ""} style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">${favoriteBusy ? "处理中" : "★ 已收藏"}</button>`
        : `<button class="test-btn" ${favoriteBusy ? "disabled" : ""} style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">${favoriteBusy ? "处理中" : "☆ 收藏"}</button>`;

      // 单节点测速：复用筛选测速端点，任务进行中由 speedtestNode 本地拦截提示
      const speedBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="speedtestNode('${esc(n.id)}', event)">测速</button>`;

      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="mono" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.ip||n.remote_host)}:${n.remote_port||""}">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td style="white-space: nowrap;">${latencyText}</td>
        <td style="white-space: nowrap;">${speedCellHtml(n)}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(locationTitle)}">${flag ? `<span aria-hidden="true">${esc(flag)}</span> ` : ""}${esc(displayLocation)}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.owner||n.as_name||"-")}">${esc(n.owner||n.as_name||"-")}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(ipTypeTitle)}">${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${testBtn}
            ${speedBtn}
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }
  setHtmlIfChanged($("rows"), rowsHtml);

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  if (testingNodeIds.has(id)) return;
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetchWithTimeout("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    }, 45000);
    const result = await readJsonResponse(response, "节点检测失败");
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
    alert("节点检测失败: " + (e.message || "未知错误"));
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  if (favoriteRequestIds.has(id)) return;
  favoriteRequestIds.add(id);
  render();
  try {
    const response = await fetchWithTimeout("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    }, 20000);
    const result = await readJsonResponse(response, "切换收藏失败");
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      render();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
    alert("切换收藏失败: " + (e.message || "未知错误"));
  } finally {
    favoriteRequestIds.delete(id);
    render();
  }
}

let pollInterval = null;
let refreshPollInterval = null;
let refreshPollInFlight = false;
let connectionPollInFlight = false;
let nodesRequestPromise = null;

async function fetchNodesSnapshot() {
  if (nodesRequestPromise) return nodesRequestPromise;
  const request = (async () => {
    const response = await fetchWithTimeout("./api/nodes", { cache: "no-store" }, 20000);
    if (!response.ok) throw new Error(`节点状态请求失败 (${response.status})`);
    return response.json();
  })();
  nodesRequestPromise = request;
  try {
    return await request;
  } finally {
    if (nodesRequestPromise === request) nodesRequestPromise = null;
  }
}

function applyNodesSnapshot(data) {
  const nextNodes = Array.isArray(data && data.nodes) ? data.nodes : [];
  const nextState = data && data.state ? data.state : {};
  const signature = JSON.stringify([nextNodes, nextState]);
  if (signature === lastNodesSnapshotSignature) return false;

  lastNodesSnapshotSignature = signature;
  nodes = nextNodes;
  state = nextState;
  stableSortNodes();
  updateCountryFilter();
  render();
  return true;
}

function refreshButtonBusy(message = "任务进行中...") {
  const btn = $("refresh");
  if (!btn) return;
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>${esc(message)}`;
}

function refreshButtonIdle() {
  const btn = $("refresh");
  if (!btn) return;
  btn.disabled = false;
  btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>更新节点`;
}

function startRefreshPolling() {
  if (refreshPollInterval) clearInterval(refreshPollInterval);
  refreshButtonBusy("任务进行中...");
  refreshPollInterval = setInterval(async () => {
    if (refreshPollInFlight || !isPageVisible()) return;
    refreshPollInFlight = true;
    try {
      const data = await fetchNodesSnapshot();
      applyNodesSnapshot(data);

      if (!state.maintenance_running) {
        clearInterval(refreshPollInterval);
        refreshPollInterval = null;
        refreshButtonIdle();
      }
    } catch (pe) {
      clearInterval(refreshPollInterval);
      refreshPollInterval = null;
      refreshButtonIdle();
    } finally {
      refreshPollInFlight = false;
    }
  }, 1000);
}

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    if (connectionPollInFlight || !isPageVisible()) return;
    connectionPollInFlight = true;
    try {
      const data = await fetchNodesSnapshot();
      applyNodesSnapshot(data);
      
      if (!state.is_connecting && !state.maintenance_running) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetchWithTimeout("./api/test_proxy", { method: "POST" }, 45000);
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    } finally {
      connectionPollInFlight = false;
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.pending_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  try {
    const request = fetchWithTimeout("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    }, 180000);
    startConnectionPolling();
    const r = await request;
    const result = await readJsonResponse(r, "连接请求失败");
    if (!result.ok) {
      if (!result.cancelled) {
        alert("连接失败: " + (result.error || "未知错误"));
      }
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      state.pending_node_id = "";
      await load();
      return;
    }
  } catch(e) {
    alert("连接请求错误: " + (e.message || "未知错误"));
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    state.pending_node_id = "";
    try {
      await load();
    } catch (loadError) {
      render();
    }
  }
}

async function disconnectNode(){
  if (disconnectInFlight) return;
  const globalExitOn = Boolean(state && state.global_exit && state.global_exit.enabled);
  const disconnectPrompt = globalExitOn
    ? "断开后将同时关闭全局出口开关，服务器恢复直连出站。确定断开？"
    : "确定要断开当前的 VPN 连接吗？";
  if (!confirm(disconnectPrompt)) return;
  disconnectInFlight = true;
  render();
  try {
    const response = await fetchWithTimeout("./api/disconnect", { method: "POST" }, 60000);
    const result = await readJsonResponse(response, "断开连接失败");
    if (result.ok) {
      try {
        await fetchWithTimeout("./api/test_proxy", { method: "POST" }, 45000);
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败: " + (e.message || "未知错误"));
  } finally {
    disconnectInFlight = false;
    render();
  }
}





async function load(){
  const d = await fetchNodesSnapshot();
  applyNodesSnapshot(d);

  if (state.maintenance_running) {
    startRefreshPolling();
  } else if (state.is_connecting) {
    startConnectionPolling();
  }
}
$("country_filter_button").onclick = event => {
  event.stopPropagation();
  const isOpen = $("country_filter_button").getAttribute("aria-expanded") === "true";
  setCountryFilterOpen(!isOpen);
};
$("country_filter_panel").onclick = event => event.stopPropagation();
document.addEventListener("click", () => setCountryFilterOpen(false));
document.addEventListener("keydown", event => {
  if (event.key === "Escape") {
    const wasOpen = $("country_filter_button").getAttribute("aria-expanded") === "true";
    setCountryFilterOpen(false);
    if (wasOpen) $("country_filter_button").focus();
  }
});
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };
$("status_filter").onchange=()=>{ currentPage = 1; render(); };
if ($("sort_mode")) $("sort_mode").onchange=()=>{ currentPage = 1; render(); };

$("refresh").onclick=async()=>{
  refreshButtonBusy("正在启动更新...");
  try{
    const response = await fetchWithTimeout("./api/refresh_nodes",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        discovery_countries: Array.from(selectedDiscoveryCountries).sort()
      })
    }, 25000);
    const result = await readJsonResponse(response, "节点更新启动失败");
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "节点更新启动失败");
    }
    state.discovery_countries = Array.isArray(result.discovery_countries)
      ? result.discovery_countries
      : Array.from(selectedDiscoveryCountries);
    discoveryCountriesDirty = false;
    await load();
    startRefreshPolling();
  }
  catch(e){
    refreshButtonIdle();
    alert("更新节点失败: " + (e.message || "未知错误"));
  }
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetchWithTimeout("./api/test_proxy", { method: "POST" }, 45000);
    const result = await readJsonResponse(response, "代理检测失败");
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle & GitHub dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
const githubBtn = $("github_btn");
const githubDropdown = $("github_dropdown");

async function checkForUpdate(event) {
  if (event) event.stopPropagation();
  const button = $("check_update_btn");
  const statusBox = $("update_check_status");
  const releaseLink = $("latest_release_link");
  if (!button || !statusBox) return;

  button.disabled = true;
  statusBox.className = "update-check-status";
  statusBox.textContent = "正在连接 GitHub 检查最新正式版...";
  try {
    const response = await fetchWithTimeout("./api/check_update", { cache: "no-store" }, 25000);
    const result = await readJsonResponse(response, "更新检查失败");
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "更新检查失败");
    }
    if (releaseLink && result.release_url) releaseLink.href = result.release_url;
    if (result.update_available) {
      statusBox.className = "update-check-status available";
      if (result.deployment_mode === "docker") {
        statusBox.textContent = `发现正式版 ${result.latest_tag}。请在 VPS 执行：${result.update_command}`;
      } else {
        statusBox.textContent = `发现正式版 ${result.latest_tag}。请执行：${result.update_command}`;
      }
    } else {
      statusBox.className = "update-check-status current";
      statusBox.textContent = `当前 ${result.current_version_label} 已是最新正式版。`;
    }
  } catch (error) {
    statusBox.className = "update-check-status error";
    statusBox.textContent = error.message || "无法连接 GitHub，请稍后重试。";
  } finally {
    button.disabled = false;
  }
}

if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
    adminBtn.setAttribute("aria-expanded", isShow ? "false" : "true");
    if (githubDropdown) {
      githubDropdown.style.display = "none";
      if (githubBtn) githubBtn.setAttribute("aria-expanded", "false");
    }
  };
}

if (githubBtn && githubDropdown) {
  githubBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = githubDropdown.style.display === "block";
    githubDropdown.style.display = isShow ? "none" : "block";
    githubBtn.setAttribute("aria-expanded", isShow ? "false" : "true");
    if (adminDropdown) {
      adminDropdown.style.display = "none";
      if (adminBtn) adminBtn.setAttribute("aria-expanded", "false");
    }
  };
  githubDropdown.onclick = event => event.stopPropagation();
}

document.addEventListener("click", () => {
  if (adminDropdown) adminDropdown.style.display = "none";
  if (githubDropdown) githubDropdown.style.display = "none";
  if (adminBtn) adminBtn.setAttribute("aria-expanded", "false");
  if (githubBtn) githubBtn.setAttribute("aria-expanded", "false");
});

document.addEventListener("keydown", event => {
  if (event.key !== "Escape") return;
  const githubWasOpen = githubBtn && githubBtn.getAttribute("aria-expanded") === "true";
  const adminWasOpen = adminBtn && adminBtn.getAttribute("aria-expanded") === "true";
  if (adminDropdown) adminDropdown.style.display = "none";
  if (githubDropdown) githubDropdown.style.display = "none";
  if (adminBtn) adminBtn.setAttribute("aria-expanded", "false");
  if (githubBtn) githubBtn.setAttribute("aria-expanded", "false");
  if (githubWasOpen && githubBtn) githubBtn.focus();
  else if (adminWasOpen && adminBtn) adminBtn.focus();
});

let showFavoritesOnly = false;

function toggleFavoritesView() {
  showFavoritesOnly = !showFavoritesOnly;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";
  
  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const favRoutingBtn = $("btn_toggle_fav_routing");
    if (favRoutingBtn) {
      if (state.routing_mode === "favorites") {
        favRoutingBtn.textContent = "禁用仅用收藏出站";
        favRoutingBtn.style.background = "var(--danger-gradient)";
        favRoutingBtn.style.borderColor = "transparent";
        favRoutingBtn.style.color = "#ffffff";
        favRoutingBtn.style.boxShadow = "0 0 12px rgba(244, 63, 94, 0.3)";
      } else {
        favRoutingBtn.textContent = "启用仅用收藏出站";
        favRoutingBtn.style.background = "rgba(255,255,255,0.03)";
        favRoutingBtn.style.borderColor = "var(--border-color)";
        favRoutingBtn.style.color = "var(--text-primary)";
        favRoutingBtn.style.boxShadow = "none";
      }
    }
  }
}

async function toggleFavRouting() {
  if (!state) return;
  const newMode = state.routing_mode === "favorites" ? "auto" : "favorites";
  
  state.routing_mode = newMode;
  updateFavPanelUI();
  
  try {
    const res = await fetchWithTimeout("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all"
      })
    }, 25000);
    const data = await readJsonResponse(res, "更新出站路由设置失败");
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新出站路由设置失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      const selected = card.getAttribute("data-value") === value;
      card.setAttribute("aria-pressed", selected ? "true" : "false");
      if (selected) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
    
    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      const selected = card.getAttribute("data-value") === value;
      card.setAttribute("aria-pressed", selected ? "true" : "false");
      if (selected) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");
  
  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定地区</strong>：限制仅连接选定国家的节点，且后台仅并发测速该国家的节点。如果该国的所有可用节点都失效，会造成代理中断且<strong>绝不自动切换到其他国家</strong>的节点。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>仅用收藏</strong>：只连接和切换您收藏的节点。如果所有收藏的节点均失效，系统不会自动切换到未收藏的节点。请确保收藏列表中有足够多且可用的节点。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "rgba(255, 255, 255, 0.02)";
    warningDiv.style.border = "1px solid rgba(255, 255, 255, 0.05)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    const code = String(n.country_short || "").trim().toUpperCase();
    const c = translateCountry(n.country);
    if (/^[A-Z]{2}$/.test(code) && c) {
      const current = countMap[code] || {name: c, count: 0};
      current.count += 1;
      countMap[code] = current;
    }
  });
  
  const countries = Object.keys(countMap).sort((a, b) => countMap[a].name.localeCompare(countMap[b].name, "zh-CN"));
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(code => {
    html += `<option value="${esc(code)}">${esc(countryFlag(code))} ${esc(countMap[code].name)} (${countMap[code].count}个节点)</option>`;
  });
  select.innerHTML = html;
  
  if (state) {
    const saved = String(state.force_country || "").trim();
    if (/^[A-Za-z]{2}$/.test(saved)) {
      select.value = saved.toUpperCase();
    } else {
      const legacy = countries.find(code => countMap[code].name === translateCountry(saved));
      select.value = legacy || "";
    }
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = state.port || 8787;
    $("cred_suffix").value = state.secret_path || "";
  }
  showModal("credentials_modal", "#cred_username");
  $("admin_dropdown").style.display = "none";
}

function closeCredentialsModal() {
  hideModal("credentials_modal");
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const username = $("cred_username").value.trim();
  const password = $("cred_password").value;
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();
  
  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetchWithTimeout("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix
      })
    }, 25000);
    const data = await readJsonResponse(res, "保存网页安全设置失败");
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";
        
        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = formatUrlHost(window.location.hostname);
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = data.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          if (data.reauth_required) {
            window.location.reload();
          } else {
            closeCredentialsModal();
            load();
          }
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();
  
  if (state) {
    $("net_proxy_port").value = state.proxy_port || 7928;
    const mode = state.routing_mode || "auto";
    const ipType = state.routing_ip_type || "all";
    
    selectOptionCard('routing_mode', mode);
    selectOptionCard('routing_ip_type', ipType);
  }
  renderExitStatus();

  populateRoutingCountries();
  showModal("network_modal", "#net_proxy_port");
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  hideModal("network_modal");
}

// ---- v2.2.0: exit switches, interval, speed test, pipeline ----
function formatDurationZh(totalSeconds) {
  const seconds = Math.max(0, Math.round(Number(totalSeconds) || 0));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `${hours} 小时 ${minutes} 分钟`;
  if (minutes > 0) return `${minutes} 分钟`;
  return `${seconds} 秒`;
}

function formatSpeed(mbps) {
  const value = Number(mbps);
  if (!Number.isFinite(value) || value <= 0) return "-";
  return `${value.toFixed(2)} MB/s`;
}

let toastTimer = null;
function showToast(msg) {
  const el = $("app_toast");
  if (!el) return;
  el.textContent = String(msg || "");
  el.style.display = "block";
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.style.display = "none"; toastTimer = null; }, 2400);
}

async function startFilteredSpeedtest() {
  const ids = getFilteredNodes().map(n => n && n.id).filter(Boolean);
  if (!ids.length) {
    showToast("当前筛选没有节点");
    return;
  }
  try {
    const response = await fetchWithTimeout("./api/pipeline/speedtest_filtered", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids })
    }, 15000);
    const result = await readJsonResponse(response, "启动测速失败");
    if (!response.ok || !result.ok) throw new Error(result.error || "启动测速失败");
    const total = Number(result.total) || ids.length;
    showToast(`开始测速 ${total} 个筛选节点`);
    startRefreshPolling();
  } catch (e) {
    showToast(e.message || "启动测速失败");
  }
}

async function speedtestNode(id, event) {
  if (event) event.stopPropagation();
  if (!id) return;
  const pipeline = (state && state.pipeline) || {};
  if (pipeline.running || (state && state.is_connecting)) {
    showToast("已有任务进行中，请稍后再试");
    return;
  }
  try {
    const response = await fetchWithTimeout("./api/pipeline/speedtest_filtered", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: [id] })
    }, 15000);
    const result = await readJsonResponse(response, "启动测速失败");
    if (!response.ok || !result.ok) throw new Error(result.error || "启动测速失败");
    showToast("开始测速该节点");
    startRefreshPolling();
  } catch (e) {
    showToast(e.message || "启动测速失败");
  }
}

function speedHistoryOf(id) {
  const history = (state && state.speed_history) || {};
  const rows = history[id];
  return Array.isArray(rows) ? rows : [];
}

function speedHistoryStats(rows) {
  const speeds = rows.map(r => Number(r && r.mbps)).filter(v => Number.isFinite(v) && v > 0);
  if (!speeds.length) return { best: 0, avg: 0 };
  const best = Math.max(...speeds);
  return { best, avg: speeds.reduce((a, b) => a + b, 0) / speeds.length };
}

function hideSpeedHistory() {
  const pop = $("speed_history_pop");
  if (pop) pop.style.display = "none";
}

function showSpeedHistory(anchor, id) {
  const pop = $("speed_history_pop");
  if (!pop || !anchor) return;
  const rows = speedHistoryOf(id);
  if (!rows.length) return;
  const { best, avg } = speedHistoryStats(rows);
  const newestFirst = rows.slice(-10).reverse();
  const pad = v => String(v).padStart(2, "0");
  const lines = newestFirst.map(r => {
    const when = r.t ? new Date(Number(r.t) * 1000) : null;
    const stamp = when && Number.isFinite(when.getTime())
      ? `${pad(when.getMonth() + 1)}-${pad(when.getDate())} ${pad(when.getHours())}:${pad(when.getMinutes())}`
      : "未知时间";
    const mbps = Number(r.mbps);
    const speed = Number.isFinite(mbps) && mbps > 0 ? `${mbps.toFixed(2)} MB/s` : "-";
    return `<div style="display:flex; justify-content:space-between; gap:14px; white-space:nowrap;"><span style="color: var(--text-secondary);">${stamp}</span><span class="mono">${speed}</span></div>`;
  }).join("");
  pop.innerHTML =
    `<div style="font-weight:600; margin-bottom:4px;">实测速度历史</div>` +
    `<div style="color: var(--text-secondary); margin-bottom:6px;">最好 ${best ? best.toFixed(2) + " MB/s" : "-"} · 平均 ${avg ? avg.toFixed(2) + " MB/s" : "-"} · 共 ${rows.length} 次</div>` +
    `<div style="border-top: 1px solid var(--border-color); padding-top: 6px; display:flex; flex-direction:column; gap:3px;">${lines}</div>`;
  pop.style.display = "block";
  const rect = anchor.getBoundingClientRect();
  const popRect = pop.getBoundingClientRect();
  let left = rect.right + 8;
  let top = rect.top;
  if (left + popRect.width > window.innerWidth - 8) left = Math.max(8, rect.left - popRect.width - 8);
  if (top + popRect.height > window.innerHeight - 8) top = Math.max(8, window.innerHeight - popRect.height - 8);
  pop.style.left = `${Math.max(8, left)}px`;
  pop.style.top = `${Math.max(8, top)}px`;
}

function speedCellHtml(n) {
  if (!n) return "-";
  const pipeline = state.pipeline || {};
  if (pipeline.running && pipeline.current_node_id && pipeline.current_node_id === n.id) {
    return '<span class="speed-testing"><span class="badge-pulse" style="background: var(--warning);"></span>测速中</span>';
  }
  const historyRows = speedHistoryOf(n.id);
  const historyAttrs = historyRows.length
    ? ` onmouseenter="showSpeedHistory(this, '${esc(n.id)}')" onmouseleave="hideSpeedHistory()"`
    : "";
  const historyText = historyRows.length
    ? (() => {
        const { best, avg } = speedHistoryStats(historyRows);
        return `历史最好 ${best ? best.toFixed(2) : "-"} MB/s / 平均 ${avg ? avg.toFixed(2) : "-"} MB/s（${historyRows.length} 次）`;
      })()
    : "";
  const value = Number(n.speed_mbps);
  if (!Number.isFinite(value) || value <= 0) {
    const parts = [];
    if (n.speed_message) parts.push(String(n.speed_message));
    if (historyText) parts.push(historyText);
    if (!parts.length) return "-";
    return `<span title="${esc(parts.join("；"))}"${historyAttrs}>-</span>`;
  }
  const parts = [`${(value * 8).toFixed(1)} Mbps`];
  if (n.speed_message) parts.push(String(n.speed_message));
  if (n.speed_tested_at) parts.push("测速时间：" + new Date(Number(n.speed_tested_at) * 1000).toLocaleString());
  if (historyText) parts.push(historyText);
  return `<span class="mono" title="${esc(parts.join("；"))}"${historyAttrs}>${esc(formatSpeed(value))}</span>`;
}

function renderExitStatus() {
  const sb = (state && state.singbox_exit) || {};
  const ge = (state && state.global_exit) || {};
  const activeNode = nodes.find(n => n && n.active);
  const sbInput = $("net_singbox_exit");
  const geInput = $("net_global_exit");
  if (!sbInput || !geInput) return;

  geInput.checked = Boolean(ge.enabled);
  geInput.disabled = !ge.supported || exitRequestInFlight;
  const geLines = [];
  if (!ge.supported) {
    geLines.push("当前环境不支持：" + (ge.unsupported_reason || "未知原因"));
  } else if (ge.applied) {
    geLines.push(`已接管：物理网卡 ${ge.physical_interface || "?"}，IP ${(ge.physical_ips || []).join(", ") || "?"}`);
    if (!activeNode) geLines.push("⚠️ 隧道未连接，服务器出站当前已中断（fail-closed）");
  } else if (ge.enabled) {
    geLines.push("已开启，规则尚未生效");
  } else {
    geLines.push("已关闭，服务器直连出站");
  }
  if (ge.last_error) geLines.push("错误：" + ge.last_error);
  $("global_exit_status").textContent = geLines.join("\n");

  sbInput.checked = Boolean(sb.enabled);
  sbInput.disabled = !sb.supported || Boolean(ge.enabled) || exitRequestInFlight;
  const sbLines = [];
  if (!sb.supported) {
    sbLines.push("当前环境不支持：" + (sb.unsupported_reason || "未知原因"));
  } else {
    if (ge.enabled) sbLines.push("全局出口开启期间由系统接管，无需单独配置");
    else sbLines.push(sb.applied ? "已接管 sing-box 出站" : (sb.enabled ? "已开启，配置尚未生效" : "已关闭，sing-box 直连出站"));
    if (sb.service_active === false) sbLines.push("sing-box 服务未运行");
    if (sb.verified && typeof sb.verified === "object") {
      sbLines.push(`验证：最近 ${sb.verified.total || 0} 条连接中 ${sb.verified.via_tunnel || 0} 条经隧道`);
    }
    if (sb.applied && !activeNode) sbLines.push("⚠️ 隧道未连接，sing-box 出站当前已中断（fail-closed）");
  }
  if (sb.last_error) sbLines.push("错误：" + sb.last_error);
  $("singbox_exit_status").textContent = sbLines.join("\n");
  $("btn_verify_singbox").disabled = !sb.supported || !sb.applied || exitRequestInFlight;

}

function nextCheckText() {
  const nextAt = Number(state && state.next_check_at) || 0;
  const remaining = nextAt - Date.now() / 1000;
  if (state && state.pipeline && state.pipeline.running) return "任务进行中，结束后重新计时";
  if (nextAt <= 0) return "";
  return remaining > 0 ? `下次自动任务：${formatDurationZh(remaining)}后` : "下次自动任务：即将开始";
}

let exitRequestInFlight = false;

function showNetworkError(message) {
  const el = $("network_error");
  el.textContent = message;
  el.style.display = "block";
}

async function postExitSwitch(url, enabled, failMessage) {
  const response = await fetchWithTimeout(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: Boolean(enabled) })
  }, 60000);
  const result = await readJsonResponse(response, failMessage);
  if (!response.ok || !result.ok) {
    throw new Error(result.error || failMessage);
  }
  return result;
}

async function toggleGlobalExit(enabled) {
  if (exitRequestInFlight) return;
  $("network_error").style.display = "none";
  if (enabled && !confirm("开启后 VPS 所有出站流量经 VPN 节点，隧道断开时全部出站中断（SSH 与面板不受影响）。确定开启？")) {
    $("net_global_exit").checked = false;
    return;
  }
  exitRequestInFlight = true;
  renderExitStatus();
  try {
    const result = await postExitSwitch("./api/global_exit", enabled, "切换全局出口失败");
    state.global_exit = result.status || state.global_exit;
    state.singbox_exit = result.singbox_exit || state.singbox_exit;
  } catch (e) {
    showNetworkError(e.message || "切换全局出口失败");
    $("net_global_exit").checked = !enabled;
  } finally {
    exitRequestInFlight = false;
    renderExitStatus();
    load().catch(() => {});
  }
}

async function toggleSingboxExit(enabled) {
  if (exitRequestInFlight) return;
  $("network_error").style.display = "none";
  exitRequestInFlight = true;
  renderExitStatus();
  try {
    const result = await postExitSwitch("./api/singbox_exit", enabled, "切换 sing-box 出口失败");
    state.singbox_exit = result.status || state.singbox_exit;
  } catch (e) {
    showNetworkError(e.message || "切换 sing-box 出口失败");
    $("net_singbox_exit").checked = !enabled;
  } finally {
    exitRequestInFlight = false;
    renderExitStatus();
    load().catch(() => {});
  }
}

async function verifySingboxExit() {
  if (exitRequestInFlight) return;
  $("network_error").style.display = "none";
  exitRequestInFlight = true;
  const btn = $("btn_verify_singbox");
  btn.textContent = "验证中...";
  renderExitStatus();
  try {
    const response = await fetchWithTimeout("./api/singbox_exit/verify", { method: "POST" }, 20000);
    const result = await readJsonResponse(response, "验证失败");
    if (!response.ok || !result.ok) throw new Error(result.error || "验证失败");
    if (result.status) state.singbox_exit = result.status;
    if (!result.verified) showNetworkError("无法读取 sing-box Clash API，请确认已开启 clash_api 且服务在运行");
  } catch (e) {
    showNetworkError(e.message || "验证失败");
  } finally {
    exitRequestInFlight = false;
    btn.textContent = "验证出口";
    renderExitStatus();
  }
}

function renderPipelinePanel() {
  const panel = $("pipeline_panel");
  if (!panel) return;
  const pipeline = (state && state.pipeline) || {};
  if (!pipeline.running) {
    // 空闲时只占一行：手动节点测试进度，或上一轮结果与下次自动任务时间
    const parts = [];
    if (state && state.is_connecting && !state.pending_node_id && state.last_check_message) {
      parts.push(`<span class="badge-pulse" style="background: var(--warning);"></span>${esc(state.last_check_message)}`);
    } else if (pipeline.finished_at) {
      const reason = {manual: "已手动停止", threshold: "达到阈值提前结束", error: "异常结束"}[pipeline.stopped_reason] || "";
      const summary = pipeline.stopped_reason === "error" ? `异常结束：${pipeline.message || "未知错误"}` : (pipeline.message || reason || "已完成");
      parts.push(`上一轮（${esc(formatDurationZh(Math.max(0, Date.now() / 1000 - pipeline.finished_at)))}前）：${esc(summary)}`);
    }
    const next = nextCheckText();
    if (next) parts.push(esc(next));
    if (!parts.length) {
      if (panel.style.display !== "none") { panel.style.display = "none"; panel.innerHTML = ""; }
      return;
    }
    panel.style.display = "block";
    setHtmlIfChanged(panel, `<div class="pipeline-idle">${parts.join('<span class="pipeline-sep">·</span>')}</div>`);
    return;
  }
  const stages = [["fetch", "获取"], ["probe", "检测"], ["speedtest", "测速"], ["switch", "切换"]];
  const activeStages = pipeline.with_speedtest ? stages : stages.slice(0, 2);
  const currentIndex = activeStages.findIndex(([key]) => key === pipeline.stage);
  const stageHtml = activeStages.map(([key, label], index) => {
    const cls = index < currentIndex ? "done" : (index === currentIndex ? "current" : "");
    return `<span class="pipeline-stage ${cls}">${esc(label)}</span>`;
  }).join("");
  const triggerLabel = {periodic: "周期任务", manual_update: "手动更新", manual_speedtest: "手动测速", forced: "强制检测"}[pipeline.trigger] || "任务";
  const details = [];
  if (pipeline.stage === "probe" || pipeline.probe_total) details.push(`检测 ${pipeline.probe_done || 0}/${pipeline.probe_total || 0}`);
  if (pipeline.with_speedtest && (pipeline.stage === "speedtest" || pipeline.speed_total)) details.push(`测速 ${pipeline.speed_done || 0}/${pipeline.speed_total || 0}`);
  if (pipeline.current_node_id) details.push(`当前节点 ${pipeline.current_node_id}`);
  if (pipeline.best_node_id) details.push(`最快 ${pipeline.best_node_id}（${formatSpeed(pipeline.best_speed_mbps)}）`);
  const stopLabel = pipeline.stop_requested ? "正在停止..." : "停止任务";
  const html = `
    <div class="pipeline-running">
      <div class="pipeline-head">
        <span style="font-size: 14px; font-weight: 600; color: var(--text-primary); display: inline-flex; align-items: center; gap: 6px;">
          <span class="badge-pulse" style="background: var(--primary);"></span>${esc(triggerLabel)}进行中
          <span style="font-size: 12px; font-weight: 400; color: var(--text-secondary);">当前连接保持不变</span>
        </span>
        <button type="button" class="btn-danger" ${pipeline.stop_requested ? "disabled" : ""} style="height: 30px; padding: 0 12px; border-radius: 8px; font-size: 12px;" onclick="stopPipeline()">${esc(stopLabel)}</button>
      </div>
      <div class="pipeline-stages">${stageHtml}</div>
      <div class="pipeline-details">${esc(details.join(" · ") || (pipeline.message || "正在获取节点列表..."))}</div>
    </div>`;
  panel.style.display = "block";
  setHtmlIfChanged(panel, html);
}

async function stopPipeline() {
  try {
    const response = await fetchWithTimeout("./api/pipeline/stop", { method: "POST" }, 15000);
    const result = await readJsonResponse(response, "停止任务失败");
    if (!response.ok || !result.ok) throw new Error(result.error || "停止任务失败");
    if (state.pipeline) state.pipeline.stop_requested = true;
    renderPipelinePanel();
  } catch (e) {
    alert("停止任务失败: " + (e.message || "未知错误"));
  }
}

let speedtestEstimateTimer = null;
let speedtestEstimateSeq = 0;

function populateSpeedtestCountries(selected) {
  const container = $("st_countries");
  if (!container) return;
  const selectedSet = new Set((selected || []).map(code => String(code).toUpperCase()));
  const countries = new Map();
  nodes.forEach(n => {
    const code = String(n && n.country_short || "").trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return;
    const entry = countries.get(code) || {code, name: translateCountry(n.country) || code, count: 0};
    entry.count += 1;
    countries.set(code, entry);
  });
  const options = Array.from(countries.values()).sort((a, b) => a.name.localeCompare(b.name, "zh-CN") || a.code.localeCompare(b.code));
  container.innerHTML = options.length
    ? options.map(item => `
        <label class="country-option">
          <input class="country-option-input st-country" type="checkbox" value="${esc(item.code)}" ${selectedSet.has(item.code) ? "checked" : ""}>
          <span class="country-option-box" aria-hidden="true"></span>
          <span class="country-option-flag" aria-hidden="true">${esc(countryFlag(item.code))}</span>
          <span class="country-option-name">${esc(item.name)}</span>
          <span class="country-option-count">${item.count}</span>
        </label>`).join("")
    : '<div style="padding:12px; color:var(--text-secondary); font-size:13px;">暂无国家数据</div>';
}

function readSpeedtestForm() {
  return {
    status: $("st_status").value,
    countries: Array.from(document.querySelectorAll(".st-country:checked")).map(el => el.value),
    ip_types: Array.from(document.querySelectorAll(".st-ip-type:checked")).map(el => el.value),
    retest_after_hours: Number($("st_retest_hours").value),
    per_node_seconds: Number($("st_seconds").value),
    per_node_max_mb: Number($("st_max_mb").value),
    stop_threshold_mbps: Number($("st_threshold").value),
    switch_margin_percent: Number($("st_margin").value),
    url: $("st_url").value.trim(),
    auto_after_check: $("st_auto").checked,
    auto_switch_fastest: $("st_auto_switch").checked,
  };
}

function updateThresholdMbit() {
  const value = Number($("st_threshold").value);
  $("st_threshold_mbit").textContent = Number.isFinite(value) && value > 0 ? `约 ${(value * 8).toFixed(1)} Mbps` : "0 表示测满设定时长或流量";
}

function scheduleSpeedtestEstimate() {
  updateThresholdMbit();
  if (speedtestEstimateTimer) clearTimeout(speedtestEstimateTimer);
  speedtestEstimateTimer = setTimeout(refreshSpeedtestEstimate, 500);
}

async function refreshSpeedtestEstimate() {
  const seq = ++speedtestEstimateSeq;
  const el = $("st_estimate");
  try {
    const response = await fetchWithTimeout("./api/speedtest/estimate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(readSpeedtestForm())
    }, 15000);
    const result = await readJsonResponse(response, "估算失败");
    if (seq !== speedtestEstimateSeq) return;
    if (!response.ok || !result.ok) throw new Error(result.error || "估算失败");
    el.textContent = `预计测 ${result.count} 个节点，最多约 ${result.max_mb} MB，约 ${formatDurationZh(result.est_seconds)}`;
  } catch (e) {
    if (seq !== speedtestEstimateSeq) return;
    el.textContent = "估算失败：" + (e.message || "未知错误");
  }
}

function openSpeedtestModal() {
  $("speedtest_error").style.display = "none";
  $("speedtest_success").style.display = "none";
  const settings = (state && state.speedtest_settings) || {};
  $("st_status").value = settings.status || "available";
  populateSpeedtestCountries(settings.countries || []);
  const ipTypes = new Set(settings.ip_types || []);
  document.querySelectorAll(".st-ip-type").forEach(el => { el.checked = ipTypes.has(el.value); });
  $("st_check_interval_hours").value = (state && state.check_interval_hours) || 24;
  $("next_check_label").textContent = nextCheckText();
  $("st_retest_hours").value = settings.retest_after_hours ?? 12;
  $("st_seconds").value = settings.per_node_seconds ?? 8;
  $("st_max_mb").value = settings.per_node_max_mb ?? 20;
  $("st_threshold").value = settings.stop_threshold_mbps ?? 0;
  $("st_margin").value = settings.switch_margin_percent ?? 20;
  $("st_url").value = settings.url || "";
  $("st_auto").checked = Boolean(settings.auto_after_check);
  $("st_auto_switch").checked = Boolean(settings.auto_switch_fastest);
  const running = Boolean(state && state.pipeline && state.pipeline.running);
  $("st_save_start").disabled = running;
  $("st_save_start").textContent = running ? "任务进行中..." : "保存并开始测速";
  updateThresholdMbit();
  $("st_estimate").textContent = "正在估算...";
  refreshSpeedtestEstimate();
  showModal("speedtest_modal", "#st_status");
}

function closeSpeedtestModal() {
  hideModal("speedtest_modal");
}

async function saveSpeedtestSettings(start) {
  const errorEl = $("speedtest_error");
  const successEl = $("speedtest_success");
  errorEl.style.display = "none";
  successEl.style.display = "none";
  const saveBtn = $("st_save");
  const startBtn = $("st_save_start");
  saveBtn.disabled = true;
  startBtn.disabled = true;
  try {
    const checkIntervalHours = parseInt($("st_check_interval_hours").value);
    if (isNaN(checkIntervalHours) || checkIntervalHours < 1 || checkIntervalHours > 72) {
      throw new Error("自动任务周期必须在 1 至 72 小时之间");
    }
    const response = await fetchWithTimeout("./api/speedtest/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...readSpeedtestForm(), check_interval_hours: checkIntervalHours })
    }, 15000);
    const result = await readJsonResponse(response, "保存测速设置失败");
    if (!response.ok || !result.ok) throw new Error(result.error || "保存测速设置失败");
    state.speedtest_settings = result.settings || state.speedtest_settings;
    if (result.check_interval_hours) state.check_interval_hours = result.check_interval_hours;
    if (start) {
      const startResponse = await fetchWithTimeout("./api/pipeline/speedtest", { method: "POST" }, 15000);
      const startResult = await readJsonResponse(startResponse, "启动测速失败");
      if (!startResponse.ok || !startResult.ok) throw new Error(startResult.error || "启动测速失败");
      closeSpeedtestModal();
      startRefreshPolling();
      return;
    }
    successEl.textContent = "测速设置已保存";
    successEl.style.display = "block";
    setTimeout(() => closeSpeedtestModal(), 1000);
  } catch (e) {
    errorEl.textContent = e.message || "保存失败";
    errorEl.style.display = "block";
  } finally {
    saveBtn.disabled = false;
    startBtn.disabled = Boolean(state && state.pipeline && state.pipeline.running);
  }
}

if ($("speedtest_form")) {
  $("speedtest_form").addEventListener("input", scheduleSpeedtestEstimate);
  $("speedtest_form").addEventListener("change", scheduleSpeedtestEstimate);
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const proxyPort = parseInt($("net_proxy_port").value);
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;
  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && proxyPort === state.port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }
  if (routingMode === "fixed_ip" && !(state && (state.active_openvpn_node_id || state.fixed_node_id))) {
    errorDivEl.textContent = "启用固定 IP 前，请先连接一个要锁定的节点";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetchWithTimeout("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType
      })
    }, 25000);
    const data = await readJsonResponse(res, "保存代理设置失败");
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！代理出站端口已变更，页面将在 4 秒内自动刷新...";
        successDiv.style.display = "block";
        
        const inputs = $("network_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          window.location.reload();
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}



async function logoutAdmin() {
  try {
    const res = await fetchWithTimeout("./api/logout", { method: "POST" }, 20000);
    if (res.ok) {
      window.location.reload();
    } else {
      alert("退出登录失败，请稍后重试");
    }
  } catch (err) {
    console.error("退出登录失败", err);
    alert("退出登录失败: " + (err.message || "网络错误"));
  }
}

// 页面加载时自动初始化数据
load().catch(error => console.error("初始化节点数据失败", error));

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
let backgroundPollInFlight = false;
setInterval(async () => {
  if (backgroundPollInFlight || !isPageVisible()) return;
  if (typeof state !== "undefined" && !state.is_connecting && !state.maintenance_running && (!testingNodeIds || !testingNodeIds.size)) {
    backgroundPollInFlight = true;
    try {
      const data = await fetchNodesSnapshot();
      applyNodesSnapshot(data);
    } catch(e) {
    } finally {
      backgroundPollInFlight = false;
    }
  }
}, 10000);
let gatewayPollInterval = null;
let gatewayRequestInFlight = false;

function openGatewayModal() {
  $("admin_dropdown").style.display = "none";
  showModal("gateway_modal", "#btn_test_proxy");
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  hideModal("gateway_modal");
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  if (gatewayRequestInFlight || !isPageVisible() || $("gateway_modal").style.display !== "flex") return;
  gatewayRequestInFlight = true;
  try {
    const res = await fetchWithTimeout("./api/gateway_status", { cache: "no-store" }, 20000);
    if (!res.ok) throw new Error(`网关状态请求失败 (${res.status})`);
    const data = await res.json();
    if (data.ok && data.services) {
      renderGatewayServices(data.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  } finally {
    gatewayRequestInFlight = false;
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';
    
    html += `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  setHtmlIfChanged(container, html);
}

let logsPollInterval = null;
let rawLogsCache = [];
let logsRequestInFlight = false;
const MAX_RENDERED_LOG_LINES = 300;

function openLogsModal() {
  $("admin_dropdown").style.display = "none";
  showModal("logs_modal", "#log_filter_select");
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 2500);
}

function closeLogsModal() {
  hideModal("logs_modal");
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  if (logsRequestInFlight || !isPageVisible() || $("logs_modal").style.display !== "flex") return;
  logsRequestInFlight = true;
  try {
    const res = await fetchWithTimeout("./api/logs", { cache: "no-store" }, 20000);
    if (!res.ok) throw new Error(`日志请求失败 (${res.status})`);
    const data = await res.json();
    if (Array.isArray(data.logs)) {
      rawLogsCache = data.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  } finally {
    logsRequestInFlight = false;
  }
}

function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;
  
  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }
  
  if (filtered.length === 0) {
    setHtmlIfChanged(term, `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`);
    return;
  }
  
  const linesHtml = filtered.slice(-MAX_RENDERED_LOG_LINES).map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";
    
    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");
  
  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;
  
  const changed = setHtmlIfChanged(term, linesHtml);
  
  if (changed && isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }
  
  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }
  
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
function enhanceNumberInputs(root) {
  const up = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M5 15l7-7 7 7"/></svg>';
  const down = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>';
  (root || document).querySelectorAll('input[type="number"]').forEach(input => {
    if (input.parentElement && input.parentElement.classList.contains("num-stepper")) return;
    const wrap = document.createElement("span");
    wrap.className = "num-stepper";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    const btns = document.createElement("span");
    btns.className = "num-stepper-btns";
    [["stepUp", up, "增加"], ["stepDown", down, "减少"]].forEach(([method, icon, label]) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.tabIndex = -1;
      btn.setAttribute("aria-label", label);
      btn.innerHTML = icon;
      btn.addEventListener("click", () => {
        if (input.disabled || input.readOnly) return;
        if (input.value === "" && input.placeholder) input.value = input.placeholder;
        else input[method]();
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
      btns.appendChild(btn);
    });
    wrap.appendChild(btns);
  });
}
enhanceNumberInputs();
</script>
<div id="app_toast" style="position: fixed; top: 18px; left: 50%; transform: translateX(-50%); background: rgba(22, 30, 49, 0.98); border: 1px solid var(--border-color); border-radius: 10px; padding: 10px 18px; color: var(--text-primary); font-size: 13px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35); display: none; z-index: 999; pointer-events: none; max-width: 80vw; text-align: center;"></div>
<div id="speed_history_pop" style="position: fixed; display: none; background: rgba(22, 30, 49, 0.98); border: 1px solid var(--border-color); border-radius: 12px; padding: 10px 12px; color: var(--text-primary); font-size: 12px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35); z-index: 998; pointer-events: none; min-width: 190px; max-width: 260px;"></div>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result
            
        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            
        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def reset_proxy_failure_counter(node_id: str = "") -> None:
    global consecutive_proxy_failures, last_proxy_failure_node_id
    with lock:
        consecutive_proxy_failures = 0
        last_proxy_failure_node_id = node_id

def record_proxy_failure(node_id: str) -> int:
    global consecutive_proxy_failures, last_proxy_failure_node_id
    with lock:
        if node_id != last_proxy_failure_node_id:
            consecutive_proxy_failures = 0
            last_proxy_failure_node_id = node_id
        consecutive_proxy_failures += 1
        return consecutive_proxy_failures

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            checked_node_id = active_openvpn_node_id
            res = check_proxy_health()
            if checked_node_id != active_openvpn_node_id:
                continue
            if res["ok"]:
                reset_proxy_failure_counter(checked_node_id)
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                failure_count = record_proxy_failure(checked_node_id) if checked_node_id else 0
                process_exited = bool(checked_node_id) and not active_openvpn_running()
                should_recover = process_exited or failure_count >= PROXY_FAILURE_THRESHOLD
                if checked_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json(
                        "WARNING",
                        "Proxy",
                        f"代理不可用 ({failure_count}/{PROXY_FAILURE_THRESHOLD}): {error_msg}",
                    )
                display_error = error_msg
                if checked_node_id and not process_exited and not should_recover:
                    display_error = f"{error_msg}（连续失败 {failure_count}/{PROXY_FAILURE_THRESHOLD}，暂不切换）"
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=display_error,
                )

                # A dead OpenVPN process is recovered immediately. Transient
                # external probe failures must cross the configured threshold.
                if checked_node_id and should_recover:
                    reset_proxy_failure_counter(checked_node_id)
                    ui_cfg = load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == checked_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {checked_node_id}", flush=True)
                        try:
                            connect_node(checked_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_nodes()
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


PIPELINE_BUSY_MESSAGE = "任务进行中，请稍后再试"


def parse_bool_field(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"字段 {key} 必须是布尔值")
    return value


def parse_check_interval_hours(value: Any) -> int:
    """Parse the pipeline interval field; raises ValueError when outside 1 to 72."""
    if isinstance(value, bool):
        raise ValueError("自动任务周期必须是 1 至 72 之间的整数小时")
    try:
        hours = int(value)
    except (TypeError, ValueError):
        raise ValueError("自动任务周期必须是 1 至 72 之间的整数小时") from None
    if isinstance(value, float) and value != hours:
        raise ValueError("自动任务周期必须是 1 至 72 之间的整数小时")
    if not (1 <= hours <= 72):
        raise ValueError("自动任务周期必须是 1 至 72 之间的整数小时")
    return hours


def handle_singbox_exit_request(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    try:
        enabled = parse_bool_field(payload, "enabled")
    except ValueError as exc:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
    try:
        status = set_singbox_exit(enabled)
    except Exception as exc:
        return HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc), "status": exit_status_copy("singbox")}
    return HTTPStatus.OK, {"ok": True, "status": status}


def handle_singbox_verify_request() -> tuple[int, dict[str, Any]]:
    try:
        verified = singbox_exit.verify_via_clash_api()
        refresh_exit_status(verified=verified)
    except Exception as exc:
        return HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)}
    return HTTPStatus.OK, {"ok": True, "verified": verified, "status": exit_status_copy("singbox")}


def handle_global_exit_request(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    try:
        enabled = parse_bool_field(payload, "enabled")
    except ValueError as exc:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
    try:
        result = set_global_exit(enabled)
    except Exception as exc:
        return HTTPStatus.INTERNAL_SERVER_ERROR, {
            "ok": False,
            "error": str(exc),
            "status": exit_status_copy("global"),
            "singbox_exit": exit_status_copy("singbox"),
        }
    return HTTPStatus.OK, {"ok": True, "status": result["global"], "singbox_exit": result["singbox"]}


def handle_speedtest_settings_request(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    raw = payload.get("speedtest") if isinstance(payload.get("speedtest"), dict) else payload
    settings = speedtest.normalize_settings(raw)
    updates: dict[str, Any] = {"speedtest": settings}
    interval_changed = False
    if payload.get("check_interval_hours") is not None:
        hours = parse_check_interval_hours(payload.get("check_interval_hours"))
        interval_changed = hours != bounded_int(load_ui_config().get("check_interval_hours"), 24, 1, 72)
        updates["check_interval_hours"] = hours
    ui_cfg = update_ui_config(**updates)
    if interval_changed:
        set_state(check_interval_hours=ui_cfg["check_interval_hours"])
        reschedule_after_interval_change()
    return HTTPStatus.OK, {"ok": True, "settings": settings, "check_interval_hours": bounded_int(ui_cfg.get("check_interval_hours"), 24, 1, 72)}


def speedtest_candidates_for(settings: dict[str, Any]) -> list[dict[str, Any]]:
    ui_cfg = load_ui_config()
    active_id = active_openvpn_node_id if active_openvpn_running() else ""
    with lock:
        return speedtest.select_candidates(
            read_nodes(),
            settings,
            lambda items: apply_routing_filters(items, ui_cfg, include_unknown_ip_type=True),
            active_id,
            time.time(),
        )


def handle_speedtest_estimate_request(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    raw = payload.get("speedtest") if isinstance(payload.get("speedtest"), dict) else payload
    if raw:
        settings = speedtest.normalize_settings(raw)
    else:
        settings = speedtest.normalize_settings(load_ui_config().get("speedtest"))
    candidates = speedtest_candidates_for(settings)
    active_id = active_openvpn_node_id if active_openvpn_running() else ""
    result = speedtest.estimate(candidates, settings, active_id)
    return HTTPStatus.OK, {"ok": True, **result}


def handle_pipeline_speedtest_request() -> tuple[int, dict[str, Any]]:
    if maintenance_lock.locked() or pipeline_snapshot().get("running"):
        return HTTPStatus.CONFLICT, {"ok": False, "error": PIPELINE_BUSY_MESSAGE, "running": True}
    threading.Thread(target=run_pipeline, args=("manual_speedtest", True), daemon=True).start()
    return HTTPStatus.OK, {"ok": True, "running": True}


FILTERED_SPEEDTEST_NODE_LIMIT = 500


def match_nodes_by_ids(raw_ids: Any) -> tuple[list[str], list[dict[str, Any]]]:
    """清洗传入的节点 id 列表，并按该顺序从 nodes.json 匹配出候选。返回 (清洗后 ids, 候选)。"""
    if not isinstance(raw_ids, list):
        raise ValueError("节点 ID 列表无效")
    ids: list[str] = []
    for node_id in raw_ids:
        node_id = str(node_id or "").strip()
        if node_id and node_id not in ids:
            ids.append(node_id)
    ids = ids[:FILTERED_SPEEDTEST_NODE_LIMIT]
    if not ids:
        raise ValueError("没有可测速的节点")
    with lock:
        found = {str(n.get("id") or ""): n for n in read_nodes()}
    candidates = [found[node_id] for node_id in ids if node_id in found]
    if not candidates:
        raise ValueError("指定的节点都不存在，请先刷新节点列表")
    return ids, candidates


def handle_pipeline_speedtest_filtered_request(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    if maintenance_lock.locked() or pipeline_snapshot().get("running"):
        return HTTPStatus.CONFLICT, {"ok": False, "error": PIPELINE_BUSY_MESSAGE, "running": True}
    try:
        ids, candidates = match_nodes_by_ids(payload.get("ids"))
    except ValueError as exc:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
    threading.Thread(target=run_filtered_speedtest, args=(ids, candidates), daemon=True).start()
    return HTTPStatus.OK, {"ok": True, "running": True, "total": len(candidates)}


def run_filtered_speedtest(ids: list[str], candidates: list[dict[str, Any]]) -> None:
    """只测调用方指定的筛选节点：不 fetch、不 select、不切换，只跑 run_speed_stage。"""
    global is_connecting, last_pipeline_end
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        set_state(last_check_message="任务进行中，请稍后再试")
        return
    with lock:
        if is_connecting:
            maintenance_lock.release()
            set_state(last_check_message="当前已有连接或节点测试任务正在运行，请稍后再试")
            return
        is_connecting = True
    run_id = "filtered_speedtest"
    pipeline_cancel_event.clear()
    with lock:
        pipeline_status.update(new_pipeline_status())
        pipeline_status.update(
            running=True,
            run_id=run_id,
            trigger="manual_speedtest",
            stage="speedtest",
            with_speedtest=True,
            started_at=time.time(),
            message=f"准备测速 {len(candidates)} 个筛选节点...",
        )
    log_to_json("INFO", "SpeedTest", f"筛选测速开始: {len(candidates)} 个节点 run_id={run_id}")
    settings = speedtest.normalize_settings(load_ui_config().get("speedtest"))
    try:
        with lock:
            current = {str(n.get("id") or ""): n for n in read_nodes()}
        live = [current[node_id] for node_id in ids if node_id in current] or candidates
        set_state(is_connecting=True, last_check_message=f"正在测速 {len(live)} 个筛选节点...")
        stopped = run_speed_stage(live, settings, run_id)
        if stopped == "manual":
            set_state(last_check_message="任务已手动停止")
        else:
            done = pipeline_snapshot().get("speed_done", 0)
            suffix = "，达到阈值提前停止" if stopped == "threshold" else ""
            set_state(last_check_message=f"筛选测速完成，共 {done} 个节点{suffix}")
    except Exception as exc:
        pipeline_set(stopped_reason="error", message=str(exc))
        log_to_json("ERROR", "SpeedTest", f"筛选测速异常终止: {exc}")
    finally:
        is_connecting = False
        last_pipeline_end = time.time()
        pipeline_set(running=False, stage="idle", current_node_id="", finished_at=last_pipeline_end)
        set_state(is_connecting=False)
        maintenance_lock.release()


def handle_pipeline_stop_request() -> tuple[int, dict[str, Any]]:
    pipeline_cancel_event.set()
    if pipeline_snapshot().get("running"):
        pipeline_set(stop_requested=True)
    return HTTPStatus.OK, {"ok": True}


def exit_service_statuses() -> list[dict[str, Any]]:
    singbox = exit_status_copy("singbox")
    global_ = exit_status_copy("global")
    if singbox.get("supported"):
        singbox_details = "已接管" if singbox.get("applied") else ("已开启但未生效" if singbox.get("enabled") else "已关闭")
        if singbox.get("service_active") is False:
            singbox_details += "，sing-box 服务未运行"
    else:
        singbox_details = singbox.get("unsupported_reason") or "当前环境不支持"
    if global_.get("supported"):
        if global_.get("applied"):
            iface = global_.get("physical_interface") or "?"
            ips = ", ".join(global_.get("physical_ips") or []) or "?"
            global_details = f"已接管（物理网卡 {iface}，IP {ips}）"
        else:
            global_details = "已开启但未生效" if global_.get("enabled") else "已关闭（服务器直连出站）"
    else:
        global_details = global_.get("unsupported_reason") or "当前环境不支持"
    return [
        {
            "name": "sing-box 出口接管",
            "status": "running" if singbox.get("applied") else "stopped",
            "details": singbox_details,
            "error": singbox.get("last_error") or "",
        },
        {
            "name": "全局出口接管",
            "status": "running" if global_.get("applied") else "stopped",
            "details": global_details,
            "error": global_.get("last_error") or "",
        },
    ]


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        purge_expired_sessions()
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_nodes()
            connection_state = get_state()
            connection_ready = connection_ready_for_ui(connection_state)
            active_node = next((n for n in nodes if connection_ready and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = bool(connection_ready and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path == "/api/check_update":
            try:
                self.send_json(check_latest_release())
            except Exception as exc:
                self.send_json(
                    {"ok": False, "error": f"无法检查 GitHub 正式版更新: {exc}"},
                    HTTPStatus.BAD_GATEWAY,
                )
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < max(check_interval_seconds() * 1.5, 5400)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status,
                    *exit_service_statuses(),
                ]
            })
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries: list[dict[str, Any]] = []
            if log_file.exists():
                try:
                    with lock:
                        entries = read_recent_log_entries(log_file)
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": entries})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        global is_connecting
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                password_matches = bool(expected_pwd) and secrets.compare_digest(input_pwd, str(expected_pwd))
                username_matches = secrets.compare_digest(input_uname, str(expected_uname))
                if password_matches and username_matches:
                    token = uuid.uuid4().hex
                    purge_expired_sessions()
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "")
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                
                ui_cfg = load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                if ports_conflict(new_port_int, ui_cfg.get("proxy_port", 7928)):
                    self.send_json({"ok": False, "error": "网页管理端口不能与代理出站端口相同"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                
                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                    if reauth_required:
                        active_sessions.clear()
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        global_exit_teardown_for_restart()
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()
                
                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = normalize_routing_country(payload.get("force_country"), read_nodes())
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用固定地区前，请先选择一个要锁定的国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                check_interval_hours = None
                if payload.get("check_interval_hours") is not None:
                    try:
                        check_interval_hours = parse_check_interval_hours(payload.get("check_interval_hours"))
                    except ValueError as exc:
                        self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                        return

                ui_cfg = load_ui_config()
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""
                
                if ports_conflict(ui_cfg.get("port", 8787), new_proxy_port_int):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                if routing_mode == "favorites":
                    ui_cfg["fav_fail_fallback"] = False
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id
                interval_changed = False
                if check_interval_hours is not None:
                    interval_changed = check_interval_hours != bounded_int(ui_cfg.get("check_interval_hours"), 24, 1, 72)
                    ui_cfg["check_interval_hours"] = check_interval_hours

                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                if interval_changed:
                    reschedule_after_interval_change()

                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "路由设置已更新")
                
                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        global_exit_teardown_for_restart()
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    message = policy_message or "配置更新成功，已即时生效！"
                    self.send_json({"ok": True, "restart_needed": False, "message": message})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = normalize_routing_country(payload.get("force_country"), read_nodes())
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                fav_fail_fallback = False
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用固定地区前，请先选择一个要锁定的国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "出站路由配置已更新")
                
                self.send_json({"ok": True, "message": policy_message or "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                if not node_id:
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []
                
                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)
                
                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = None
                if ui_cfg.get("routing_mode") == "favorites":
                    policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "收藏列表已更新")
                
                self.send_json({"ok": True, "favorite_node_ids": fav_ids, "message": policy_message or ""})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                payload = self.read_json_body()
                if "discovery_countries" in payload:
                    discovery_countries = persist_discovery_countries(
                        payload.get("discovery_countries")
                    )
                else:
                    discovery_countries = normalize_discovery_countries(
                        load_ui_config().get("discovery_countries")
                    )
                if maintenance_lock.locked():
                    self.send_json({
                        "ok": True,
                        "message": "节点维护任务正在运行，国家范围已保存并将在下一轮生效",
                        "running": True,
                        "discovery_countries": discovery_countries,
                    })
                else:
                    threading.Thread(target=run_pipeline, args=("manual_update", False), daemon=True).start()
                    self.send_json({
                        "ok": True,
                        "message": "已在后台启动节点更新流程",
                        "running": True,
                        "discovery_countries": discovery_countries,
                    })
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                if not isinstance(node_ids, list):
                    self.send_json({"ok": False, "error": "节点 ID 列表无效"}, HTTPStatus.BAD_REQUEST)
                    return
                node_ids = [str(node_id or "").strip() for node_id in node_ids]
                node_ids = [node_id for node_id in node_ids if node_id]
                if len(node_ids) > MANUAL_TEST_NODE_LIMIT:
                    self.send_json({"ok": False, "error": f"单次最多测试 {MANUAL_TEST_NODE_LIMIT} 个节点"}, HTTPStatus.BAD_REQUEST)
                    return
                if pipeline_snapshot().get("running"):
                    self.send_json({"ok": False, "error": PIPELINE_BUSY_MESSAGE}, HTTPStatus.CONFLICT)
                    return
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message="正在手动测试节点可用性...")
                    tested_nodes = test_multiple_nodes(node_ids)
                    self.send_json({"ok": True, "nodes": tested_nodes})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/singbox_exit":
            try:
                status_code, body = handle_singbox_exit_request(self.read_json_body())
                self.send_json(body, HTTPStatus(status_code))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/singbox_exit/verify":
            try:
                self.read_request_body()
                status_code, body = handle_singbox_verify_request()
                self.send_json(body, HTTPStatus(status_code))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/global_exit":
            try:
                status_code, body = handle_global_exit_request(self.read_json_body())
                self.send_json(body, HTTPStatus(status_code))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/speedtest/settings":
            try:
                status_code, body = handle_speedtest_settings_request(self.read_json_body())
                self.send_json(body, HTTPStatus(status_code))
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/speedtest/estimate":
            try:
                status_code, body = handle_speedtest_estimate_request(self.read_json_body())
                self.send_json(body, HTTPStatus(status_code))
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/pipeline/speedtest":
            try:
                self.read_request_body()
                status_code, body = handle_pipeline_speedtest_request()
                self.send_json(body, HTTPStatus(status_code))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/pipeline/speedtest_filtered":
            try:
                payload = self.read_json_body()
                status_code, body = handle_pipeline_speedtest_filtered_request(payload)
                self.send_json(body, HTTPStatus(status_code))
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/pipeline/stop":
            try:
                self.read_request_body()
                status_code, body = handle_pipeline_stop_request()
                self.send_json(body, HTTPStatus(status_code))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                handle_disconnect_request()
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            previous_node_id = active_openvpn_node_id if active_openvpn_running() else ""
            try:
                payload = self.read_json_body()
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except ConnectionCancelled as exc:
                self.send_json({"ok": False, "cancelled": True, "error": str(exc)}, HTTPStatus.CONFLICT)
            except RuntimeError as exc:
                if str(exc).startswith("当前已有"):
                    self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.CONFLICT)
                    return
                threading.Thread(
                    target=recover_after_manual_connect_failure,
                    args=(previous_node_id,),
                    daemon=True,
                ).start()
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            except Exception as exc:
                threading.Thread(
                    target=recover_after_manual_connect_failure,
                    args=(previous_node_id,),
                    daemon=True,
                ).start()
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                if not node_id.strip():
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                if pipeline_snapshot().get("running"):
                    self.send_json({"ok": False, "error": PIPELINE_BUSY_MESSAGE}, HTTPStatus.CONFLICT)
                    return
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message="正在手动测试节点可用性...")
                    updated_node = test_node_by_id(node_id)
                    self.send_json({"ok": True, "node": updated_node})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        tunnel_ready=active_openvpn_running(),
                        proxy_ready=active_openvpn_running(),
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ready=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    cleanup_stale_speedtest_routes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "mirror_url": MIRROR_HTTPS_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_fetch_source": "",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "tunnel_ready": False,
            "proxy_ready": False,
            "proxy_ok": False,
            "pending_node_id": "",
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    if sys.platform.startswith("linux"):
        try:
            signal.signal(signal.SIGTERM, graceful_shutdown)
            signal.signal(signal.SIGINT, graceful_shutdown)
        except (ValueError, OSError) as exc:
            print(f"[系统] 注册退出信号失败: {exc}", flush=True)
    apply_exit_settings_on_startup()
    threading.Thread(target=exit_reconcile_loop, daemon=True).start()
    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=ip_enrichment_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(run_cli(sys.argv[1:]))
    main()
