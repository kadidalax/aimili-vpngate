from __future__ import annotations

import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import global_exit


class FakeRunner:
    """Records ip commands; `ip rule show` reflects rules added so far."""

    def __init__(self, failures: dict[str, tuple[int, str]] | None = None, outputs: dict[str, str] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.failures = failures or {}
        self.outputs = outputs or {}
        self.rules: dict[int, list[str]] = {}

    def run(self, args, timeout=15):
        args = list(args)
        self.calls.append(args)
        joined = " ".join(args)
        for prefix, response in self.failures.items():
            if joined.startswith(prefix):
                return response
        if args[:3] == ["ip", "rule", "add"]:
            pref = int(args[4])
            self.rules[pref] = args[5:]
            return 0, ""
        if args[:3] == ["ip", "rule", "del"]:
            pref = int(args[4])
            if pref in self.rules:
                del self.rules[pref]
                return 0, ""
            return 2, "RTNETLINK answers: No such file or directory"
        if args[:3] == ["ip", "rule", "show"]:
            lines = [f"{pref}:\t{' '.join(rule)}" for pref, rule in sorted(self.rules.items())]
            return 0, "\n".join(["0:\tfrom all lookup local"] + lines + ["32766:\tfrom all lookup main"])
        for prefix, output in self.outputs.items():
            if joined.startswith(prefix):
                return 0, output
        if args[:2] == ["ip", "route"] and args[2] == "show":
            return 0, ""
        return 0, ""

    def commands(self, *prefixes: str) -> list[str]:
        result = []
        for call in self.calls:
            joined = " ".join(call)
            if not prefixes or any(joined.startswith(p) for p in prefixes):
                result.append(joined)
        return result


def make_context(**overrides) -> global_exit.Context:
    base = dict(
        interface="eth0",
        gateway="203.0.113.1",
        ips=["203.0.113.10"],
        ssh_ports=[3222],
        ui_port=8080,
        private_resolvers=["10.0.0.2"],
    )
    base.update(overrides)
    return global_exit.Context(**base)


class GlobalExitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"VPNGATE_DATA_DIR": self.tmp.name})
        self.env.start()
        self.stdout = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout.start()

    def tearDown(self) -> None:
        self.stdout.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_desired_rules_cover_mark_from_sport_private_suppress_and_tunnel(self) -> None:
        ctx = make_context(ips=["203.0.113.10", "198.51.100.5"], ssh_ports=[22, 3222], ui_port=8080)
        rules = global_exit.desired_rules(ctx)
        self.assertEqual((30000, ["fwmark", "0x1a", "lookup", "main"]), rules[0])
        self.assertEqual((30001, ["from", "198.51.100.5", "lookup", "main"]), rules[1])
        self.assertEqual((30002, ["from", "203.0.113.10", "lookup", "main"]), rules[2])
        self.assertEqual((30010, ["sport", "22", "lookup", "main"]), rules[3])
        self.assertEqual((30011, ["sport", "3222", "lookup", "main"]), rules[4])
        self.assertEqual((30012, ["sport", "8080", "lookup", "main"]), rules[5])
        self.assertEqual((30020, ["to", "10.0.0.0/8", "lookup", "main"]), rules[6])
        self.assertEqual((30024, ["to", "100.64.0.0/10", "lookup", "main"]), rules[10])
        self.assertEqual((30030, ["lookup", "main", "suppress_prefixlength", "0"]), rules[11])
        self.assertEqual((30031, ["lookup", "100"]), rules[12])
        self.assertEqual(13, len(rules))
        prefs = [pref for pref, _ in rules]
        self.assertEqual(prefs, sorted(prefs))
        self.assertTrue(all(pref in global_exit.PREF_RANGE for pref in prefs))

    def test_enable_applies_rules_routes_and_fallback_then_records_state(self) -> None:
        runner = FakeRunner()
        ctx = make_context()
        result = global_exit.enable(ctx, runner)
        self.assertTrue(result["applied"])
        self.assertTrue(result["sport_supported"])
        adds = runner.commands("ip rule add")
        self.assertEqual("ip rule add pref 30000 fwmark 0x1a lookup main", adds[0])
        self.assertEqual("ip rule add pref 30031 lookup 100", adds[-1])
        self.assertIn("ip route replace 10.0.0.2/32 via 203.0.113.1 dev eth0", runner.commands("ip route replace"))
        self.assertIn("ip route replace unreachable default table 100 metric 1000", runner.commands("ip route replace"))
        # rules are added only after the pre-clean and route steps come after rules
        first_add = runner.calls.index(["ip", "rule", "add", "pref", "30000", "fwmark", "0x1a", "lookup", "main"])
        first_route = next(i for i, c in enumerate(runner.calls) if c[:3] == ["ip", "route", "replace"])
        self.assertLess(first_add, first_route)
        state = json.loads(global_exit.state_file().read_text(encoding="utf-8"))
        self.assertEqual(["10.0.0.2"], state["host_routes"])
        self.assertEqual("eth0", state["context"]["interface"])
        self.assertEqual([3222], state["context"]["ssh_ports"])
        self.assertTrue(global_exit.is_applied(runner))

    def test_enable_rolls_back_on_failure(self) -> None:
        runner = FakeRunner(failures={"ip rule add pref 30020": (2, "RTNETLINK answers: Invalid argument")})
        with self.assertRaises(RuntimeError) as ctx:
            global_exit.enable(make_context(), runner)
        self.assertIn("30020", str(ctx.exception))
        self.assertEqual({}, runner.rules)
        deletes = runner.commands("ip rule del pref")
        self.assertIn("ip rule del pref 30000", deletes)
        self.assertIn("ip rule del pref 30010", deletes)
        self.assertIn("ip route del unreachable default table 100 metric 1000", runner.commands("ip route del"))
        self.assertFalse(global_exit.state_file().exists())
        self.assertFalse(global_exit.is_applied(runner))

    def test_enable_rolls_back_when_fallback_route_fails(self) -> None:
        runner = FakeRunner(failures={"ip route replace unreachable": (2, "boom")})
        with self.assertRaises(RuntimeError):
            global_exit.enable(make_context(), runner)
        self.assertEqual({}, runner.rules)
        self.assertIn("ip route del 10.0.0.2/32 via 203.0.113.1 dev eth0", runner.commands("ip route del"))

    def test_enable_skips_sport_when_unsupported(self) -> None:
        runner = FakeRunner(failures={"ip rule add pref 3001": (255, 'Error: argument "sport" is wrong')})
        result = global_exit.enable(make_context(), runner)
        self.assertTrue(result["applied"])
        self.assertFalse(result["sport_supported"])
        self.assertNotIn(30010, runner.rules)
        self.assertIn(30031, runner.rules)
        state = json.loads(global_exit.state_file().read_text(encoding="utf-8"))
        self.assertFalse(state["sport_supported"])

    def test_enable_requires_physical_interface(self) -> None:
        with self.assertRaises(RuntimeError):
            global_exit.enable(make_context(interface=""), FakeRunner())

    def test_existing_prefs_retries_transient_show_failure(self) -> None:
        runner = FakeRunner()
        global_exit.enable(make_context(), runner)
        calls = {"n": 0}
        original = runner.run

        def flaky(args, timeout=15):
            if list(args)[:3] == ["ip", "rule", "show"] and calls["n"] == 0:
                calls["n"] += 1
                return 127, "Interrupted system call"
            return original(args, timeout)

        runner.run = flaky
        self.assertIn(30031, global_exit.existing_prefs(runner))
        self.assertTrue(global_exit.is_applied(runner))

    def test_disable_removes_everything_from_state(self) -> None:
        runner = FakeRunner()
        global_exit.enable(make_context(), runner)
        runner.calls.clear()
        result = global_exit.disable(runner)
        self.assertFalse(result["applied"])
        self.assertEqual(["10.0.0.2"], result["host_routes"])
        self.assertEqual({}, runner.rules)
        self.assertIn("ip route del 10.0.0.2/32 via 203.0.113.1 dev eth0", runner.commands("ip route del"))
        self.assertIn("ip route del unreachable default table 100 metric 1000", runner.commands("ip route del"))
        self.assertFalse(global_exit.state_file().exists())
        # prefs that were never added are not attempted
        self.assertNotIn("ip rule del pref 30039", runner.commands("ip rule del"))
        # catch-all 30031 goes first so exemptions never disappear while "lookup 100" remains
        deletes = runner.commands("ip rule del pref")
        self.assertLess(deletes.index("ip rule del pref 30031"), deletes.index("ip rule del pref 30000"))

    def test_reconcile_reapplies_when_ips_change(self) -> None:
        runner = FakeRunner()
        ctx = make_context()
        with mock.patch.object(global_exit, "detect_context", return_value=ctx):
            self.assertIsNotNone(global_exit.reconcile(True, 8080, runner))
            runner.calls.clear()
            self.assertIsNone(global_exit.reconcile(True, 8080, runner))
            self.assertEqual([], runner.commands("ip rule add"))
        changed = make_context(ips=["203.0.113.99"])
        with mock.patch.object(global_exit, "detect_context", return_value=changed):
            result = global_exit.reconcile(True, 8080, runner)
        self.assertIsNotNone(result)
        self.assertEqual(["from", "203.0.113.99", "lookup", "main"], runner.rules[30001])
        # Missing rules are re-applied even when the context did not change.
        del runner.rules[30031]
        with mock.patch.object(global_exit, "detect_context", return_value=changed):
            self.assertIsNotNone(global_exit.reconcile(True, 8080, runner))
        self.assertIn(30031, runner.rules)
        # Disabled switch with leftover rules cleans up.
        runner.calls.clear()
        self.assertIsNotNone(global_exit.reconcile(False, 8080, runner))
        self.assertEqual({}, runner.rules)
        self.assertIsNone(global_exit.reconcile(False, 8080, runner))

    def test_detect_ssh_ports_from_sshd_T_then_config_files(self) -> None:
        runner = FakeRunner(outputs={"sshd -T": "port 3222\nport 22\naddressfamily any"})
        self.assertEqual([3222, 22], global_exit.detect_ssh_ports(runner))

        runner = FakeRunner(failures={"sshd -T": (127, "not found")})
        cfg_dir = Path(self.tmp.name)
        main_cfg = cfg_dir / "sshd_config"
        main_cfg.write_text("# Port 9\nPort 2200\n", encoding="utf-8")
        extra = cfg_dir / "10-extra.conf"
        extra.write_text("Port 2201\n", encoding="utf-8")
        self.assertEqual([2200, 2201], global_exit.detect_ssh_ports(runner, [str(main_cfg), str(extra), str(cfg_dir / "missing")]))
        self.assertEqual([22], global_exit.detect_ssh_ports(runner, [str(cfg_dir / "missing")]))

    def test_private_resolver_detection(self) -> None:
        resolv = Path(self.tmp.name) / "resolv.conf"
        resolv.write_text("nameserver 127.0.0.53\nnameserver 10.0.0.2 # local\nnameserver 8.8.8.8\nnameserver 100.100.2.136\nnameserver fe80::1\n", encoding="utf-8")
        self.assertEqual(["10.0.0.2", "100.100.2.136"], global_exit.detect_private_resolvers(str(resolv)))
        self.assertEqual([], global_exit.detect_private_resolvers(str(resolv) + ".missing"))
        self.assertTrue(global_exit.is_private_ip("192.168.1.1"))
        self.assertTrue(global_exit.is_private_ip("169.254.10.1"))
        self.assertFalse(global_exit.is_private_ip("1.1.1.1"))
        self.assertFalse(global_exit.is_private_ip("bad"))

    def test_detect_default_route_and_interface_ips(self) -> None:
        runner = FakeRunner(
            outputs={
                "ip route show default": "default via 10.8.0.1 dev tun0 metric 50\ndefault via 203.0.113.1 dev eth0 proto dhcp metric 100\ndefault via 198.51.100.1 dev eth1 metric 200",
                "ip -4 -o addr show dev eth0": "2: eth0    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0\n2: eth0    inet 203.0.113.11/24 scope global secondary eth0",
            }
        )
        self.assertEqual(("eth0", "203.0.113.1"), global_exit.detect_default_route(runner))
        self.assertEqual(["203.0.113.10", "203.0.113.11"], global_exit.detect_interface_ips("eth0", runner))
        self.assertEqual([], global_exit.detect_interface_ips("", runner))
        ctx = global_exit.detect_context(8080, FakeRunner(outputs={"ip route show default": "default via 203.0.113.1 dev eth0"}))
        self.assertEqual("eth0", ctx.interface)
        self.assertEqual(8080, ctx.ui_port)

    def test_mark_socket_noop_off_linux(self) -> None:
        sock = mock.Mock()
        with mock.patch.object(global_exit, "is_linux", return_value=False):
            self.assertFalse(global_exit.mark_socket(sock))
        sock.setsockopt.assert_not_called()

        with (
            mock.patch.object(global_exit, "is_linux", return_value=True),
            mock.patch.object(global_exit.socket, "SO_MARK", 36, create=True),
        ):
            self.assertTrue(global_exit.mark_socket(sock))
            sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, 36, global_exit.FWMARK)
            sock.setsockopt.side_effect = PermissionError("no cap")
            global_exit._mark_permission_warned = False
            self.assertFalse(global_exit.mark_socket(sock))
            self.assertFalse(global_exit.mark_socket(sock))
            self.assertEqual(1, sys.stdout.getvalue().count("CAP_NET_ADMIN"))

    def test_openvpn_mark_args_platform(self) -> None:
        with mock.patch.object(global_exit, "is_linux", return_value=True):
            self.assertEqual(["--mark", "26"], global_exit.openvpn_mark_args())
        with mock.patch.object(global_exit, "is_linux", return_value=False):
            self.assertEqual([], global_exit.openvpn_mark_args())

    def test_marked_opener_marks_connection(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_GET(self):
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        previous_opener = urllib.request._opener
        try:
            with mock.patch.object(global_exit, "mark_socket", return_value=True) as marker:
                global_exit.install_marked_urllib_opener()
                with urllib.request.urlopen(f"http://127.0.0.1:{server.server_address[1]}/", timeout=5) as response:
                    self.assertEqual(200, response.status)
                    self.assertEqual(b"ok", response.read())
            marker.assert_called_once()
            self.assertIsInstance(marker.call_args.args[0], socket.socket)
        finally:
            urllib.request.install_opener(previous_opener) if previous_opener else setattr(urllib.request, "_opener", None)
            server.shutdown()
            server.server_close()

    def test_is_supported_requires_linux_non_docker_and_ip(self) -> None:
        with mock.patch.object(global_exit, "is_linux", return_value=False):
            ok, reason = global_exit.is_supported("source")
        self.assertFalse(ok)
        self.assertIn("Linux", reason)
        with mock.patch.object(global_exit, "is_linux", return_value=True):
            ok, reason = global_exit.is_supported("docker")
            self.assertFalse(ok)
            self.assertIn("Docker", reason)
            with mock.patch.object(global_exit.shutil, "which", return_value=None):
                ok, reason = global_exit.is_supported("source")
                self.assertFalse(ok)
                self.assertIn("ip", reason)
            with mock.patch.object(global_exit.shutil, "which", return_value="/sbin/ip"):
                self.assertEqual((True, ""), global_exit.is_supported("source"))

    def test_status_snapshot_reports_applied_context(self) -> None:
        runner = FakeRunner()
        with mock.patch.object(global_exit, "is_supported", return_value=(True, "")):
            before = global_exit.status_snapshot(False, "source", runner)
            self.assertFalse(before["applied"])
            global_exit.enable(make_context(), runner)
            after = global_exit.status_snapshot(True, "source", runner, last_error="")
        self.assertTrue(after["applied"])
        self.assertEqual("eth0", after["physical_interface"])
        self.assertEqual(["203.0.113.10"], after["physical_ips"])
        self.assertEqual([3222], after["ssh_ports"])
        self.assertEqual("203.0.113.1", after["gateway"])
        with mock.patch.object(global_exit, "is_supported", return_value=(False, "nope")):
            unsupported = global_exit.status_snapshot(True, "docker", runner)
        self.assertFalse(unsupported["supported"])
        self.assertEqual("nope", unsupported["unsupported_reason"])


if __name__ == "__main__":
    unittest.main()
