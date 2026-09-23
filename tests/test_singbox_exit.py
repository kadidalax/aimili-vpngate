from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import singbox_exit


class FakeRunner:
    def __init__(self, responses: dict[str, tuple[int, str]] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.responses = responses or {}

    def run(self, args, timeout=15):
        self.calls.append(list(args))
        for prefix, response in self.responses.items():
            if " ".join(args).startswith(prefix) or " ".join(args[1:]).startswith(prefix):
                return response
        return 0, ""

    def names(self) -> list[str]:
        result = []
        for call in self.calls:
            if call[0].endswith("sing-box") and len(call) > 1 and call[1] == "check":
                result.append("check")
            else:
                result.append(" ".join(call[1:]))
        return result


class SingboxExitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        (self.work / "conf").mkdir()
        (self.work / "sing-box").write_text("#!/bin/sh\n", encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {"SINGBOX_WORK_DIR": str(self.work)})
        self.env.start()
        self.alpine = mock.patch.object(singbox_exit, "is_alpine", return_value=False)
        self.alpine.start()
        self.stdout = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout.start()

    def tearDown(self) -> None:
        self.stdout.stop()
        self.alpine.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_render_config_matches_spec(self) -> None:
        cfg = singbox_exit.render_config()
        outbound = cfg["outbounds"][0]
        self.assertEqual("direct", outbound["type"])
        self.assertEqual("aimili-vpngate", outbound["tag"])
        self.assertEqual("tun0", outbound["bind_interface"])
        self.assertEqual({"server": "aimili-vpngate-dns", "strategy": "ipv4_only"}, outbound["domain_resolver"])
        self.assertEqual("aimili-vpngate", cfg["route"]["final"])
        server = cfg["dns"]["servers"][0]
        self.assertEqual("udp", server["type"])
        self.assertEqual("aimili-vpngate-dns", server["tag"])
        self.assertEqual("8.8.8.8", server["server"])
        self.assertEqual(53, server["server_port"])
        self.assertEqual("aimili-vpngate", server["detour"])
        self.assertEqual("aimili-vpngate-dns", cfg["dns"]["final"])
        self.assertEqual(cfg, json.loads(singbox_exit.render_text()))
        self.assertTrue(singbox_exit.render_text().endswith("\n"))
        self.assertEqual(self.work / "conf" / "90_aimili_vpngate.json", singbox_exit.config_path())

    def test_enable_writes_file_checks_and_reloads(self) -> None:
        runner = FakeRunner({"is-active": (0, "active")})
        result = singbox_exit.enable(runner)
        self.assertTrue(result["applied"])
        self.assertTrue(result["reloaded"])
        self.assertTrue(result["service_active"])
        self.assertEqual(["check", "is-active sing-box", "reload sing-box"], runner.names())
        self.assertEqual(runner.calls[0][:2], [str(self.work / "sing-box"), "check"])
        self.assertEqual(runner.calls[0][2:], ["-C", str(self.work / "conf")])
        self.assertEqual(singbox_exit.render_text(), singbox_exit.config_path().read_text(encoding="utf-8"))
        self.assertTrue(singbox_exit.is_applied())
        if os.name != "nt":
            self.assertEqual(0o644, singbox_exit.config_path().stat().st_mode & 0o777)

    def test_enable_rolls_back_when_check_fails(self) -> None:
        runner = FakeRunner({"check": (1, "FATAL[0000] decode config: unknown field")})
        with self.assertRaises(RuntimeError) as ctx:
            singbox_exit.enable(runner)
        self.assertIn("unknown field", str(ctx.exception))
        self.assertFalse(singbox_exit.config_path().exists())
        self.assertEqual(["check"], runner.names())

    def test_enable_restores_previous_content_when_check_fails(self) -> None:
        singbox_exit.config_path().write_text("{\"old\": true}\n", encoding="utf-8")
        runner = FakeRunner({"check": (1, "bad")})
        with self.assertRaises(RuntimeError):
            singbox_exit.enable(runner)
        self.assertEqual("{\"old\": true}\n", singbox_exit.config_path().read_text(encoding="utf-8"))

    def test_enable_skips_reload_when_service_inactive(self) -> None:
        runner = FakeRunner({"is-active": (3, "inactive")})
        result = singbox_exit.enable(runner)
        self.assertTrue(result["applied"])
        self.assertFalse(result["reloaded"])
        self.assertFalse(result["service_active"])
        self.assertIn("未运行", result["message"])
        self.assertEqual(["check", "is-active sing-box"], runner.names())

    def test_enable_reports_unknown_service_state_when_systemctl_missing(self) -> None:
        runner = FakeRunner({"is-active": (127, "No such file")})
        result = singbox_exit.enable(runner)
        self.assertIsNone(result["service_active"])
        self.assertFalse(result["reloaded"])

    def test_disable_removes_file_and_reloads(self) -> None:
        singbox_exit.config_path().write_text(singbox_exit.render_text(), encoding="utf-8")
        runner = FakeRunner({"is-active": (0, "active")})
        result = singbox_exit.disable(runner)
        self.assertFalse(result["applied"])
        self.assertTrue(result["reloaded"])
        self.assertFalse(singbox_exit.config_path().exists())
        self.assertEqual(["is-active sing-box", "reload sing-box"], runner.names())

        # Second call is a no-op without reload.
        runner2 = FakeRunner({"is-active": (0, "active")})
        result2 = singbox_exit.disable(runner2)
        self.assertFalse(result2["reloaded"])
        self.assertEqual(["is-active sing-box"], runner2.names())

    def test_reload_falls_back_to_restart(self) -> None:
        runner = FakeRunner({"reload": (1, "Job for sing-box.service failed")})
        ok, how = singbox_exit.reload_service(runner)
        self.assertTrue(ok)
        self.assertEqual("restart", how)
        self.assertEqual(["reload sing-box", "restart sing-box"], runner.names())

        runner = FakeRunner({"reload": (1, "x"), "restart": (1, "y")})
        ok, how = singbox_exit.reload_service(runner)
        self.assertFalse(ok)
        self.assertEqual("y", how)

    def test_alpine_uses_rc_service(self) -> None:
        with mock.patch.object(singbox_exit, "is_alpine", return_value=True):
            runner = FakeRunner({"status": (0, "started")})
            singbox_exit.enable(runner)
        self.assertEqual(["rc-service", "sing-box", "status"], runner.calls[1])
        self.assertEqual(["rc-service", "sing-box", "reload"], runner.calls[2])

    def test_reconcile_rewrites_missing_file(self) -> None:
        runner = FakeRunner({"is-active": (0, "active")})
        result = singbox_exit.reconcile(True, runner)
        self.assertIsNotNone(result)
        self.assertTrue(singbox_exit.is_applied())

        singbox_exit.config_path().write_text("{}\n", encoding="utf-8")
        runner = FakeRunner({"is-active": (0, "active")})
        result = singbox_exit.reconcile(True, runner)
        self.assertTrue(result["applied"])
        self.assertTrue(singbox_exit.is_applied())

        runner = FakeRunner({"is-active": (0, "active")})
        result = singbox_exit.reconcile(False, runner)
        self.assertFalse(result["applied"])
        self.assertFalse(singbox_exit.config_path().exists())

    def test_reconcile_noop_when_consistent(self) -> None:
        runner = FakeRunner()
        self.assertIsNone(singbox_exit.reconcile(False, runner))
        singbox_exit.config_path().write_text(singbox_exit.render_text(), encoding="utf-8")
        self.assertIsNone(singbox_exit.reconcile(True, runner))
        self.assertEqual([], runner.calls)

    def test_unsupported_in_docker_or_without_conf_dir(self) -> None:
        self.assertEqual((True, ""), singbox_exit.is_supported("source"))
        ok, reason = singbox_exit.is_supported("docker")
        self.assertFalse(ok)
        self.assertIn("Docker", reason)
        (self.work / "sing-box").unlink()
        ok, reason = singbox_exit.is_supported("source")
        self.assertFalse(ok)
        self.assertIn("sing-box", reason)
        with mock.patch.dict(os.environ, {"SINGBOX_WORK_DIR": str(self.work / "missing")}):
            ok, reason = singbox_exit.is_supported("source")
        self.assertFalse(ok)
        self.assertIn("配置目录", reason)

    def test_clash_api_port_parses_experimental_file(self) -> None:
        self.assertIsNone(singbox_exit.clash_api_port())
        (self.work / "conf" / "04_experimental.json").write_text(
            '{\n  // "external_controller": "127.0.0.1:1111",\n  "experimental": {"clash_api": {"external_controller": "127.0.0.1:9095"}}\n}\n',
            encoding="utf-8",
        )
        self.assertEqual(9095, singbox_exit.clash_api_port())

    def test_verify_counts_connections_via_tunnel(self) -> None:
        (self.work / "conf" / "04_experimental.json").write_text(
            '{"experimental": {"clash_api": {"external_controller": "127.0.0.1:9095"}}}', encoding="utf-8"
        )
        payload = {
            "connections": [
                {"chains": ["aimili-vpngate"]},
                {"chains": ["direct"]},
                {"chains": ["aimili-vpngate", "selector"]},
                {"nochains": True},
            ]
        }

        class FakeResponse(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        with mock.patch.object(singbox_exit.urllib.request, "urlopen", return_value=FakeResponse(json.dumps(payload).encode())) as urlopen:
            result = singbox_exit.verify_via_clash_api()
        self.assertEqual(4, result["total"])
        self.assertEqual(2, result["via_tunnel"])
        self.assertGreater(result["checked_at"], 0)
        request = urlopen.call_args.args[0]
        self.assertEqual("http://127.0.0.1:9095/connections", request.full_url)

        with mock.patch.object(singbox_exit.urllib.request, "urlopen", side_effect=OSError("refused")):
            self.assertIsNone(singbox_exit.verify_via_clash_api())

    def test_status_snapshot_reports_fields(self) -> None:
        runner = FakeRunner({"is-active": (0, "active")})
        snapshot = singbox_exit.status_snapshot(True, "source", runner, last_error="x", verified={"total": 1, "via_tunnel": 1, "checked_at": 1.0})
        self.assertTrue(snapshot["supported"])
        self.assertTrue(snapshot["enabled"])
        self.assertFalse(snapshot["applied"])
        self.assertTrue(snapshot["service_active"])
        self.assertEqual("x", snapshot["last_error"])
        self.assertEqual(str(singbox_exit.config_path()), snapshot["config_path"])
        self.assertEqual(1, snapshot["verified"]["via_tunnel"])

        docker = singbox_exit.status_snapshot(True, "docker", runner)
        self.assertFalse(docker["supported"])
        self.assertIsNone(docker["service_active"])

    def test_logger_hook_receives_messages(self) -> None:
        received = []
        singbox_exit.set_logger(lambda level, module, message: received.append((level, module, message)))
        try:
            singbox_exit.disable(FakeRunner())
        finally:
            singbox_exit.set_logger(None)
        self.assertEqual("SingBox", received[0][1])
        self.assertEqual("INFO", received[0][0])


if __name__ == "__main__":
    unittest.main()
