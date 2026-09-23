"""sing-box exit takeover for AimiliVPN.

Writes a single extra config file into the sing-box conf directory so that
sing-box's default outbound binds to the AimiliVPN tunnel interface. The
module only uses the standard library and never imports the manager.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

OUTBOUND_TAG = "aimili-vpngate"
DNS_TAG = "aimili-vpngate-dns"
CONFIG_NAME = "90_aimili_vpngate.json"
DEFAULT_WORK_DIR = "/etc/sing-box"
LOG_MODULE = "SingBox"

_logger: Callable[[str, str, str], None] | None = None


def set_logger(func: Callable[[str, str, str], None] | None) -> None:
    """Install a ``(level, module, message)`` callback used for log lines."""
    global _logger
    _logger = func


def _log(level: str, message: str) -> None:
    print(f"[{LOG_MODULE}] {message}", flush=True)
    if _logger is not None:
        try:
            _logger(level, LOG_MODULE, message)
        except Exception:
            pass


def work_dir() -> Path:
    return Path(os.environ.get("SINGBOX_WORK_DIR") or DEFAULT_WORK_DIR)


def conf_dir() -> Path:
    return work_dir() / "conf"


def binary_path() -> Path:
    return work_dir() / "sing-box"


def config_path() -> Path:
    return conf_dir() / CONFIG_NAME


def render_config(interface: str = "tun0", dns_server: str = "8.8.8.8") -> dict[str, Any]:
    return {
        "outbounds": [
            {
                "type": "direct",
                "tag": OUTBOUND_TAG,
                "bind_interface": interface,
                "domain_resolver": {"server": DNS_TAG, "strategy": "ipv4_only"},
            }
        ],
        "route": {"final": OUTBOUND_TAG},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": DNS_TAG,
                    "server": dns_server,
                    "server_port": 53,
                    "detour": OUTBOUND_TAG,
                }
            ],
            "final": DNS_TAG,
        },
    }


def render_text(interface: str = "tun0", dns_server: str = "8.8.8.8") -> str:
    return json.dumps(render_config(interface, dns_server), indent=4, ensure_ascii=False) + "\n"


class CommandRunner:
    """Thin subprocess wrapper so tests can substitute a fake."""

    def run(self, args: list[str], timeout: float = 15) -> tuple[int, str]:
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - missing binary, timeout, etc.
            return 127, str(exc)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output.strip()


def is_supported(deployment_mode: str) -> tuple[bool, str]:
    if str(deployment_mode or "").lower() == "docker":
        return False, "Docker 部署模式不支持 sing-box 出口接管"
    if not conf_dir().is_dir():
        return False, f"未找到 sing-box 配置目录 {conf_dir()}"
    if not binary_path().is_file():
        return False, f"未找到 sing-box 可执行文件 {binary_path()}"
    return True, ""


def is_alpine() -> bool:
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return bool(re.search(r"^ID=\"?alpine\"?", text, re.MULTILINE))


def _service_commands() -> tuple[list[str], list[str], list[str]]:
    """Return (status, reload, restart) commands for the platform."""
    if is_alpine():
        return (
            ["rc-service", "sing-box", "status"],
            ["rc-service", "sing-box", "reload"],
            ["rc-service", "sing-box", "restart"],
        )
    return (
        ["systemctl", "is-active", "sing-box"],
        ["systemctl", "reload", "sing-box"],
        ["systemctl", "restart", "sing-box"],
    )


def service_active(runner: CommandRunner) -> bool | None:
    """True/False for the service state, None when the service manager is unavailable."""
    status_cmd, _, _ = _service_commands()
    rc, _out = runner.run(status_cmd, timeout=10)
    if rc == 127:
        return None
    return rc == 0


def check_config(runner: CommandRunner) -> tuple[bool, str]:
    rc, out = runner.run([str(binary_path()), "check", "-C", str(conf_dir())], timeout=30)
    return rc == 0, out


def reload_service(runner: CommandRunner) -> tuple[bool, str]:
    _, reload_cmd, restart_cmd = _service_commands()
    rc, out = runner.run(reload_cmd, timeout=20)
    if rc == 0:
        return True, "reload"
    _log("WARNING", f"sing-box reload 失败（{out or rc}），改为 restart")
    rc2, out2 = runner.run(restart_cmd, timeout=30)
    if rc2 == 0:
        return True, "restart"
    return False, out2 or out or f"退出码 {rc2}"


def is_applied() -> bool:
    path = config_path()
    try:
        return path.is_file() and path.read_text(encoding="utf-8") == render_text()
    except OSError:
        return False


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".aimili_", suffix=".json.tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def enable(runner: CommandRunner) -> dict[str, Any]:
    path = config_path()
    previous = None
    if path.is_file():
        try:
            previous = path.read_text(encoding="utf-8")
        except OSError:
            previous = None
    _write_atomic(path, render_text())
    ok, output = check_config(runner)
    if not ok:
        try:
            if previous is None:
                path.unlink()
            else:
                _write_atomic(path, previous)
        except OSError:
            pass
        message = f"sing-box check 未通过：{output or '无输出'}"
        _log("ERROR", message)
        raise RuntimeError(message)
    active = service_active(runner)
    reloaded = False
    if active:
        reloaded, how = reload_service(runner)
        if not reloaded:
            message = f"sing-box 重载失败：{how}"
            _log("ERROR", message)
            raise RuntimeError(message)
        message = f"已写入 {path.name} 并 {how} sing-box"
    elif active is None:
        message = f"已写入 {path.name}，无法确认 sing-box 服务状态"
    else:
        message = f"已写入 {path.name}；sing-box 未运行，启动后自动生效"
    _log("INFO", message)
    return {"applied": True, "service_active": active, "reloaded": reloaded, "message": message}


def disable(runner: CommandRunner) -> dict[str, Any]:
    path = config_path()
    existed = path.is_file()
    if existed:
        path.unlink()
    active = service_active(runner)
    reloaded = False
    if existed and active:
        reloaded, how = reload_service(runner)
        if not reloaded:
            message = f"已删除 {path.name}，但 sing-box 重载失败：{how}"
            _log("ERROR", message)
            raise RuntimeError(message)
        message = f"已删除 {path.name} 并 {how} sing-box"
    elif existed:
        message = f"已删除 {path.name}"
    else:
        message = "接管配置不存在，无需删除"
    _log("INFO", message)
    return {"applied": False, "service_active": active, "reloaded": reloaded, "message": message}


def reconcile(enabled: bool, runner: CommandRunner) -> dict[str, Any] | None:
    applied = is_applied()
    if enabled and not applied:
        _log("WARNING", "接管配置缺失或内容不符，重新写入")
        return enable(runner)
    if not enabled and config_path().is_file():
        _log("WARNING", "开关已关闭但接管配置仍存在，删除")
        return disable(runner)
    return None


def clash_api_port() -> int | None:
    path = conf_dir() / "04_experimental.json"
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for line in text.splitlines():
        if line.strip().startswith("//"):
            continue
        match = re.search(r'"external_controller"\s*:\s*"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::\]|::)?:?(\d+)"', line)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
    return None


def verify_via_clash_api(timeout: float = 3.0) -> dict[str, Any] | None:
    port = clash_api_port()
    if not port:
        return None
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/connections", headers={"User-Agent": "AimiliVPN"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        _log("WARNING", f"读取 Clash API 失败：{exc}")
        return None
    connections = payload.get("connections") if isinstance(payload, dict) else None
    if not isinstance(connections, list):
        return None
    via = 0
    for item in connections:
        chains = item.get("chains") if isinstance(item, dict) else None
        if isinstance(chains, list) and OUTBOUND_TAG in chains:
            via += 1
    return {"total": len(connections), "via_tunnel": via, "checked_at": time.time()}


def status_snapshot(
    enabled: bool,
    deployment_mode: str,
    runner: CommandRunner,
    last_error: str = "",
    verified: dict[str, Any] | None = None,
) -> dict[str, Any]:
    supported, reason = is_supported(deployment_mode)
    snapshot: dict[str, Any] = {
        "supported": supported,
        "unsupported_reason": reason,
        "enabled": bool(enabled),
        "applied": False,
        "service_active": None,
        "last_error": last_error or "",
        "config_path": str(config_path()),
        "verified": verified,
    }
    if supported:
        snapshot["applied"] = is_applied()
        snapshot["service_active"] = service_active(runner)
    return snapshot
