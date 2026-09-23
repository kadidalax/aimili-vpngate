"""Global exit takeover for AimiliVPN.

Policy routing that sends every locally originated IPv4 flow through the
AimiliVPN tunnel table while exempting inbound-reply, private-network and
manager-own traffic. Standard library only; never imports the manager.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

FWMARK = 0x1A
TABLE = 100
PREF_MARK = 30000
PREF_FROM_BASE = 30001
PREF_SPORT_BASE = 30010
PREF_TO_BASE = 30020
PREF_MAIN_SUPPRESS = 30030
PREF_TUNNEL = 30031
PREF_RANGE = range(30000, 30040)
PRIVATE_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")
STATE_NAME = "global_exit_state.json"
LOG_MODULE = "GlobalExit"
FALLBACK_ROUTE = ["unreachable", "default", "table", str(TABLE), "metric", "1000"]

_logger: Callable[[str, str, str], None] | None = None
_mark_permission_warned = False


def set_logger(func: Callable[[str, str, str], None] | None) -> None:
    global _logger
    _logger = func


def _log(level: str, message: str) -> None:
    print(f"[{LOG_MODULE}] {message}", flush=True)
    if _logger is not None:
        try:
            _logger(level, LOG_MODULE, message)
        except Exception:
            pass


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def state_file() -> Path:
    base = os.environ.get("VPNGATE_DATA_DIR")
    root = Path(base).resolve() if base else Path.cwd() / "vpngate_data"
    return root / STATE_NAME


@dataclass
class Context:
    interface: str = ""
    gateway: str = ""
    ips: list[str] = field(default_factory=list)
    ssh_ports: list[int] = field(default_factory=list)
    ui_port: int = 0
    private_resolvers: list[str] = field(default_factory=list)

    def signature(self) -> dict[str, Any]:
        data = asdict(self)
        data["ips"] = sorted(set(data["ips"]))
        data["ssh_ports"] = sorted(set(data["ssh_ports"]))
        data["private_resolvers"] = sorted(set(data["private_resolvers"]))
        return data


class CommandRunner:
    def run(self, args: list[str], timeout: float = 15) -> tuple[int, str]:
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return 127, str(exc)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output.strip()


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def detect_default_route(runner: CommandRunner) -> tuple[str, str]:
    rc, out = runner.run(["ip", "route", "show", "default"], timeout=5)
    if rc != 0:
        return "", ""
    routes: list[tuple[int, str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        try:
            dev = parts[parts.index("dev") + 1]
        except (ValueError, IndexError):
            continue
        if dev.startswith(("tun", "tap", "wg", "ppp")):
            continue
        gateway = parts[parts.index("via") + 1] if "via" in parts else ""
        metric = 0
        if "metric" in parts:
            try:
                metric = int(parts[parts.index("metric") + 1])
            except (ValueError, IndexError):
                metric = 0
        routes.append((metric, dev, gateway))
    if not routes:
        return "", ""
    routes.sort(key=lambda item: item[0])
    return routes[0][1], routes[0][2]


def detect_interface_ips(interface: str, runner: CommandRunner) -> list[str]:
    if not interface:
        return []
    rc, out = runner.run(["ip", "-4", "-o", "addr", "show", "dev", interface], timeout=5)
    if rc != 0:
        return []
    ips: list[str] = []
    for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?", out):
        ip = match.group(1)
        if ip not in ips:
            ips.append(ip)
    return ips


def _ports_from_config_text(text: str) -> list[int]:
    ports: list[int] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        match = re.match(r"(?i)^port\s+(\d+)\s*$", stripped)
        if match:
            port = int(match.group(1))
            if 0 < port < 65536 and port not in ports:
                ports.append(port)
    return ports


def detect_ssh_ports(runner: CommandRunner, config_paths: list[str] | None = None) -> list[int]:
    rc, out = runner.run(["sshd", "-T"], timeout=10)
    if rc == 0:
        ports = _ports_from_config_text(out)
        if ports:
            return ports
    paths: list[Path] = []
    if config_paths is None:
        paths.append(Path("/etc/ssh/sshd_config"))
        paths.extend(sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")))
    else:
        paths = [Path(p) for p in config_paths]
    ports: list[int] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for port in _ports_from_config_text(text):
            if port not in ports:
                ports.append(port)
    return ports or [22]


def is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return any(address in ipaddress.ip_network(cidr) for cidr in PRIVATE_CIDRS)


def detect_private_resolvers(resolv_path: str = "/etc/resolv.conf") -> list[str]:
    try:
        text = Path(resolv_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    resolvers: list[str] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        match = re.match(r"^nameserver\s+(\S+)", stripped)
        if not match:
            continue
        ip = match.group(1)
        if is_private_ip(ip) and not ip.startswith("127.") and ip not in resolvers:
            resolvers.append(ip)
    return resolvers


def detect_context(ui_port: int, runner: CommandRunner) -> Context:
    interface, gateway = detect_default_route(runner)
    return Context(
        interface=interface,
        gateway=gateway,
        ips=detect_interface_ips(interface, runner),
        ssh_ports=detect_ssh_ports(runner),
        ui_port=int(ui_port or 0),
        private_resolvers=detect_private_resolvers(),
    )


# --------------------------------------------------------------------------
# Rule set
# --------------------------------------------------------------------------

def desired_rules(ctx: Context) -> list[tuple[int, list[str]]]:
    rules: list[tuple[int, list[str]]] = [(PREF_MARK, ["fwmark", hex(FWMARK), "lookup", "main"])]
    for offset, ip in enumerate(sorted(set(ctx.ips))):
        pref = PREF_FROM_BASE + offset
        if pref >= PREF_SPORT_BASE:
            break
        rules.append((pref, ["from", ip, "lookup", "main"]))
    ports: list[int] = []
    for port in list(ctx.ssh_ports) + ([ctx.ui_port] if ctx.ui_port else []):
        if port and port not in ports:
            ports.append(port)
    for offset, port in enumerate(ports):
        pref = PREF_SPORT_BASE + offset
        if pref >= PREF_TO_BASE:
            break
        rules.append((pref, ["sport", str(port), "lookup", "main"]))
    for offset, cidr in enumerate(PRIVATE_CIDRS):
        rules.append((PREF_TO_BASE + offset, ["to", cidr, "lookup", "main"]))
    rules.append((PREF_MAIN_SUPPRESS, ["lookup", "main", "suppress_prefixlength", "0"]))
    rules.append((PREF_TUNNEL, ["lookup", str(TABLE)]))
    return rules


def is_supported(deployment_mode: str) -> tuple[bool, str]:
    if not is_linux():
        return False, "仅支持 Linux"
    if str(deployment_mode or "").lower() == "docker":
        return False, "Docker 部署模式不支持全局出口接管"
    if shutil.which("ip") is None:
        return False, "未找到 ip 命令（iproute2）"
    return True, ""


def existing_prefs(runner: CommandRunner) -> set[int]:
    rc, out = runner.run(["ip", "rule", "show"], timeout=5)
    if rc != 0:
        # A transient failure here would make the caller believe nothing is applied
        # and skip teardown, leaving the box fail-closed after the process exits.
        rc, out = runner.run(["ip", "rule", "show"], timeout=5)
        if rc != 0:
            _log("WARNING", f"读取 ip rule 失败：{out}")
            return set()
    prefs: set[int] = set()
    for line in out.splitlines():
        match = re.match(r"^\s*(\d+):", line)
        if match:
            prefs.add(int(match.group(1)))
    return prefs


def is_applied(runner: CommandRunner) -> bool:
    return PREF_TUNNEL in existing_prefs(runner)


def delete_pref(pref: int, runner: CommandRunner) -> None:
    for _ in range(50):
        rc, _out = runner.run(["ip", "rule", "del", "pref", str(pref)], timeout=5)
        if rc != 0:
            break


def delete_all_prefs(runner: CommandRunner) -> None:
    present = existing_prefs(runner)
    # Delete the catch-all (highest pref) first so exemption rules never vanish
    # while "lookup 100" is still in place, which would blackhole live SSH replies.
    for pref in reversed(PREF_RANGE):
        if pref in present:
            delete_pref(pref, runner)


def ensure_table_fallback(runner: CommandRunner) -> None:
    rc, out = runner.run(["ip", "route", "replace"] + FALLBACK_ROUTE, timeout=5)
    if rc != 0:
        raise RuntimeError(f"写入表 {TABLE} 兜底路由失败：{out}")


def remove_table_fallback(runner: CommandRunner) -> None:
    runner.run(["ip", "route", "del"] + FALLBACK_ROUTE, timeout=5)


def _host_route_args(ip: str, ctx: Context) -> list[str]:
    args = [f"{ip}/32"]
    if ctx.gateway:
        args += ["via", ctx.gateway]
    if ctx.interface:
        args += ["dev", ctx.interface]
    return args


def _read_state() -> dict[str, Any]:
    try:
        data = json.loads(state_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_state(data: dict[str, Any]) -> None:
    path = state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def enable(ctx: Context, runner: CommandRunner) -> dict[str, Any]:
    if not ctx.interface:
        raise RuntimeError("未检测到物理网卡默认路由，无法开启全局出口")
    sport_supported = True
    host_routes: list[str] = []
    try:
        delete_all_prefs(runner)
        for pref, args in desired_rules(ctx):
            rc, out = runner.run(["ip", "rule", "add", "pref", str(pref)] + args, timeout=5)
            if rc == 0:
                continue
            if args and args[0] == "sport":
                if sport_supported:
                    _log("WARNING", f"当前内核或 iproute2 不支持 sport 规则，跳过：{out}")
                sport_supported = False
                continue
            raise RuntimeError(f"添加规则 pref {pref} {' '.join(args)} 失败：{out}")
        for ip in ctx.private_resolvers:
            rc, out = runner.run(["ip", "route", "replace"] + _host_route_args(ip, ctx), timeout=5)
            if rc != 0:
                raise RuntimeError(f"写入私网解析器主机路由 {ip} 失败：{out}")
            host_routes.append(ip)
        ensure_table_fallback(runner)
        state = {
            "context": ctx.signature(),
            "host_routes": host_routes,
            "sport_supported": sport_supported,
        }
        _write_state(state)
    except Exception as exc:
        _log("ERROR", f"开启全局出口失败，回滚：{exc}")
        try:
            _rollback(runner, host_routes, ctx)
        except Exception as rollback_exc:  # noqa: BLE001
            _log("ERROR", f"回滚时出错：{rollback_exc}")
        raise
    _log("INFO", f"全局出口已开启：{ctx.interface} {', '.join(ctx.ips) or '无 IPv4'}，SSH 端口 {ctx.ssh_ports}")
    return {"applied": True, "sport_supported": sport_supported, "host_routes": host_routes, "context": ctx.signature()}


def _rollback(runner: CommandRunner, host_routes: list[str], ctx: Context) -> None:
    delete_all_prefs(runner)
    for ip in host_routes:
        runner.run(["ip", "route", "del"] + _host_route_args(ip, ctx), timeout=5)
    remove_table_fallback(runner)
    try:
        state_file().unlink()
    except OSError:
        pass


def disable(runner: CommandRunner) -> dict[str, Any]:
    state = _read_state()
    delete_all_prefs(runner)
    recorded = state.get("context") if isinstance(state.get("context"), dict) else {}
    ctx = Context(interface=str(recorded.get("interface") or ""), gateway=str(recorded.get("gateway") or ""))
    removed: list[str] = []
    for ip in state.get("host_routes") or []:
        runner.run(["ip", "route", "del"] + _host_route_args(str(ip), ctx), timeout=5)
        removed.append(str(ip))
    remove_table_fallback(runner)
    try:
        state_file().unlink()
    except OSError:
        pass
    _log("INFO", "全局出口已关闭")
    return {"applied": False, "host_routes": removed}


def reconcile(enabled: bool, ui_port: int, runner: CommandRunner) -> dict[str, Any] | None:
    applied = is_applied(runner)
    if enabled:
        ctx = detect_context(ui_port, runner)
        recorded = _read_state().get("context")
        if applied and recorded == ctx.signature():
            return None
        if applied:
            _log("WARNING", "网络环境变化，重新应用全局出口规则")
        else:
            _log("WARNING", "全局出口规则缺失，重新应用")
        return enable(ctx, runner)
    if applied or state_file().exists():
        _log("WARNING", "开关已关闭但规则仍存在，清理")
        return disable(runner)
    return None


# --------------------------------------------------------------------------
# Socket marking helpers
# --------------------------------------------------------------------------

def mark_socket(sock: socket.socket) -> bool:
    global _mark_permission_warned
    if not is_linux():
        return False
    option = getattr(socket, "SO_MARK", None)
    if option is None:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, option, FWMARK)
        return True
    except PermissionError:
        if not _mark_permission_warned:
            _mark_permission_warned = True
            _log("WARNING", "设置 SO_MARK 权限不足（需要 CAP_NET_ADMIN），面板自身流量将不豁免")
        return False
    except OSError as exc:
        _log("WARNING", f"设置 SO_MARK 失败：{exc}")
        return False


def openvpn_mark_args() -> list[str]:
    return ["--mark", str(FWMARK)] if is_linux() else []


def _marked_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):  # type: ignore[attr-defined]
    sock = socket.create_connection(address, timeout, source_address)
    mark_socket(sock)
    return sock


class MarkedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _marked_create_connection


class MarkedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _marked_create_connection


class MarkedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(MarkedHTTPConnection, req)


class MarkedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(MarkedHTTPSConnection, req, context=self._context)


def install_marked_urllib_opener() -> None:
    opener = urllib.request.build_opener(MarkedHTTPHandler(), MarkedHTTPSHandler())
    urllib.request.install_opener(opener)


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------

def status_snapshot(enabled: bool, deployment_mode: str, runner: CommandRunner, last_error: str = "") -> dict[str, Any]:
    supported, reason = is_supported(deployment_mode)
    snapshot: dict[str, Any] = {
        "supported": supported,
        "unsupported_reason": reason,
        "enabled": bool(enabled),
        "applied": False,
        "last_error": last_error or "",
        "physical_interface": "",
        "physical_ips": [],
        "ssh_ports": [],
        "gateway": "",
        "sport_supported": None,
    }
    if not supported:
        return snapshot
    snapshot["applied"] = is_applied(runner)
    state = _read_state()
    recorded = state.get("context") if isinstance(state.get("context"), dict) else None
    if snapshot["applied"] and recorded:
        snapshot["physical_interface"] = str(recorded.get("interface") or "")
        snapshot["physical_ips"] = list(recorded.get("ips") or [])
        snapshot["ssh_ports"] = list(recorded.get("ssh_ports") or [])
        snapshot["gateway"] = str(recorded.get("gateway") or "")
        snapshot["sport_supported"] = state.get("sport_supported")
    else:
        interface, gateway = detect_default_route(runner)
        snapshot["physical_interface"] = interface
        snapshot["gateway"] = gateway
        snapshot["physical_ips"] = detect_interface_ips(interface, runner)
    return snapshot
