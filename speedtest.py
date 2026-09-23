"""Speed test helpers for AimiliVPN.

Pure logic module: candidate selection, estimation, a device-bound HTTP
download measurement and speed formatting. It must not import the manager.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

DEFAULT_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"
DEFAULT_SETTINGS: dict[str, Any] = {
    "auto_after_check": False,
    "status": "available",
    "countries": [],
    "ip_types": [],
    "retest_after_hours": 12,
    "per_node_seconds": 8,
    "per_node_max_mb": 20,
    "stop_threshold_mbps": 0.0,
    "url": DEFAULT_URL,
    "auto_switch_fastest": False,
    "switch_margin_percent": 20,
}
IP_TYPES = ("residential", "mobile", "hosting", "unknown")
STATUS_CHOICES = ("available", "unavailable", "all")
USER_AGENT = "AimiliVPN-SpeedTest/2.2.0"
RECV_CHUNK = 65536
MIN_TIMING_SECONDS = 0.2


def _clamp_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        number = default
    return max(low, min(high, number))


def _clamp_float(value: Any, default: float, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    if number != number:  # NaN
        number = default
    return max(low, min(high, number))


def normalize_settings(value: Any) -> dict[str, Any]:
    """Return a fully populated, range-clamped copy of speed test settings."""
    raw = value if isinstance(value, dict) else {}
    result: dict[str, Any] = dict(DEFAULT_SETTINGS)
    result["countries"] = []
    result["ip_types"] = []

    result["auto_after_check"] = bool(raw.get("auto_after_check", DEFAULT_SETTINGS["auto_after_check"]))
    result["auto_switch_fastest"] = bool(raw.get("auto_switch_fastest", DEFAULT_SETTINGS["auto_switch_fastest"]))

    status = str(raw.get("status") or DEFAULT_SETTINGS["status"]).strip().lower()
    result["status"] = status if status in STATUS_CHOICES else DEFAULT_SETTINGS["status"]

    countries: list[str] = []
    raw_countries = raw.get("countries")
    if isinstance(raw_countries, (list, tuple, set)):
        for item in raw_countries:
            code = str(item or "").strip().upper()
            if len(code) == 2 and code.isalpha() and code not in countries:
                countries.append(code)
    result["countries"] = countries

    ip_types: list[str] = []
    raw_ip_types = raw.get("ip_types")
    if isinstance(raw_ip_types, (list, tuple, set)):
        for item in raw_ip_types:
            kind = str(item or "").strip().lower()
            if kind in IP_TYPES and kind not in ip_types:
                ip_types.append(kind)
    result["ip_types"] = ip_types

    result["retest_after_hours"] = _clamp_int(raw.get("retest_after_hours"), 12, 0, 720)
    result["per_node_seconds"] = _clamp_int(raw.get("per_node_seconds"), 8, 3, 60)
    result["per_node_max_mb"] = _clamp_int(raw.get("per_node_max_mb"), 20, 1, 500)
    result["stop_threshold_mbps"] = _clamp_float(raw.get("stop_threshold_mbps"), 0.0, 0.0, 10000.0)
    result["switch_margin_percent"] = _clamp_int(raw.get("switch_margin_percent"), 20, 0, 100)

    url = str(raw.get("url") or "").strip()
    parts = urlsplit(url) if url else None
    if parts and parts.scheme in ("http", "https") and parts.hostname:
        result["url"] = url
    else:
        result["url"] = DEFAULT_URL
    return result


def classify_ip_type(node: dict[str, Any]) -> str:
    kind = str((node or {}).get("ip_type") or "").strip().lower()
    if kind in ("residential", "mobile", "hosting"):
        return kind
    return "unknown"


def _latency_key(node: dict[str, Any]) -> int:
    for key in ("latency_ms", "ping"):
        try:
            value = int(node.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return 999999


def _score_key(node: dict[str, Any]) -> int:
    try:
        return int(node.get("score") or 0)
    except (TypeError, ValueError):
        return 0


def select_candidates(
    nodes: Iterable[dict[str, Any]],
    settings: dict[str, Any],
    routing_filter: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None,
    active_node_id: str,
    now: float,
) -> list[dict[str, Any]]:
    """Apply spec 8.1 filters and ordering; the active node always leads."""
    settings = normalize_settings(settings)
    all_nodes = [n for n in nodes if isinstance(n, dict) and n.get("id")]
    active_id = str(active_node_id or "")
    active_node = next((n for n in all_nodes if n.get("id") == active_id), None) if active_id else None

    status = settings["status"]
    if status == "available":
        pool = [n for n in all_nodes if n.get("probe_status") == "available"]
    elif status == "unavailable":
        pool = [n for n in all_nodes if n.get("probe_status") == "unavailable"]
    else:
        pool = [n for n in all_nodes if n.get("probe_status") in ("available", "unavailable")]

    if settings["countries"]:
        wanted = set(settings["countries"])
        pool = [n for n in pool if str(n.get("country_short") or "").upper() in wanted]

    if settings["ip_types"]:
        wanted_types = set(settings["ip_types"])
        pool = [n for n in pool if classify_ip_type(n) in wanted_types]

    if routing_filter is not None:
        allowed_ids = {n.get("id") for n in routing_filter(list(pool)) if isinstance(n, dict)}
        pool = [n for n in pool if n.get("id") in allowed_ids]

    window = settings["retest_after_hours"] * 3600
    if window > 0:
        kept = []
        for n in pool:
            try:
                tested_at = float(n.get("speed_tested_at") or 0)
            except (TypeError, ValueError):
                tested_at = 0.0
            if tested_at > 0 and now - tested_at < window:
                continue
            kept.append(n)
        pool = kept

    others = [n for n in pool if n.get("id") != active_id]
    others.sort(key=lambda n: (_latency_key(n), -_score_key(n)))
    if active_node is not None:
        return [active_node] + others
    return others


def estimate(candidates: list[dict[str, Any]], settings: dict[str, Any], active_node_id: str = "") -> dict[str, Any]:
    settings = normalize_settings(settings)
    count = len(candidates)
    seconds = 0
    for node in candidates:
        if active_node_id and node.get("id") == active_node_id:
            seconds += settings["per_node_seconds"] + 2
        else:
            seconds += settings["per_node_seconds"] + 16
    return {
        "count": count,
        "max_mb": count * settings["per_node_max_mb"],
        "est_seconds": seconds,
    }


def build_url(template: str, max_bytes: int) -> str:
    return str(template or DEFAULT_URL).replace("{bytes}", str(int(max_bytes)))


@dataclass
class MeasureResult:
    bytes: int = 0
    seconds: float = 0.0
    mbps: float = 0.0
    error: str = ""


def bind_device(sock: socket.socket, dev: str | None) -> None:
    if not dev:
        return
    option = getattr(socket, "SO_BINDTODEVICE", None)
    if option is None:
        return
    sock.setsockopt(socket.SOL_SOCKET, option, dev.encode())


def _resolve_ipv4(host: str, port: int, resolver: Callable[[str], str | None] | None) -> str:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    if resolver is not None:
        try:
            resolved = resolver(host)
        except Exception:
            resolved = None
        if resolved:
            try:
                socket.inet_aton(resolved)
                return resolved
            except OSError:
                pass
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"无法解析 {host}")
    return infos[0][4][0]


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read until end of HTTP headers; return (header_bytes, leftover_body)."""
    buffer = b""
    while True:
        chunk = sock.recv(RECV_CHUNK)
        if not chunk:
            raise OSError("连接在响应头结束前关闭")
        buffer += chunk
        marker = buffer.find(b"\r\n\r\n")
        if marker >= 0:
            return buffer[:marker], buffer[marker + 4:]
        if len(buffer) > 65536:
            raise OSError("响应头过大")


def measure_download(
    url: str,
    dev: str | None,
    max_seconds: float,
    max_bytes: int,
    cancel_event: threading.Event | None = None,
    resolver: Callable[[str], str | None] | None = None,
    connect_timeout: float = 10.0,
) -> MeasureResult:
    result = MeasureResult()
    sock: socket.socket | None = None
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            result.error = "测速地址必须是 http 或 https"
            return result
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        ip = _resolve_ipv4(host, port, resolver)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = raw_sock
        bind_device(raw_sock, dev)
        raw_sock.settimeout(connect_timeout)
        raw_sock.connect((ip, port))
        if parts.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(raw_sock, server_hostname=host)

        host_header = host if port in (80, 443) else f"{host}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(request)

        headers, leftover = _read_headers(sock)
        status_line = headers.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        status_parts = status_line.split()
        status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
        if status_code not in (200, 206):
            result.error = f"HTTP {status_code or status_line}"
            return result

        total = 0
        t_first = 0.0
        t_end = 0.0
        read_timeout = max(1.0, float(max_seconds))
        sock.settimeout(read_timeout)
        chunk = leftover
        while True:
            if chunk:
                if t_first == 0.0:
                    t_first = time.monotonic()
                total += len(chunk)
                t_end = time.monotonic()
                if total >= max_bytes:
                    break
                if t_end - t_first >= max_seconds:
                    break
            if cancel_event is not None and cancel_event.is_set():
                break
            if t_first and time.monotonic() - t_first >= max_seconds:
                break
            try:
                chunk = sock.recv(RECV_CHUNK)
            except socket.timeout:
                break
            if not chunk:
                break

        if total <= 0:
            result.error = "未收到正文"
            return result
        seconds = max(MIN_TIMING_SECONDS, t_end - t_first)
        result.bytes = total
        result.seconds = seconds
        result.mbps = total / seconds / 1_000_000
        return result
    except Exception as exc:  # noqa: BLE001 - every failure becomes a message
        result.error = str(exc) or exc.__class__.__name__
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def format_speed(mbps: Any) -> str:
    try:
        value = float(mbps)
    except (TypeError, ValueError):
        return "-"
    if value <= 0:
        return "-"
    return f"{value:.2f} MB/s ({value * 8:.1f} Mbps)"
