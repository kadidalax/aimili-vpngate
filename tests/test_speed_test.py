import json
import inspect
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class SpeedConfigTests(unittest.TestCase):
    app = None

    def setUp(self):
        tmp_path = Path(tempfile.mkdtemp())
        os.environ["VPNGATE_DATA_DIR"] = str(tmp_path)
        if self.__class__.app is None:
            import vpngate_manager
            self.__class__.app = vpngate_manager
        self.app = self.__class__.app
        self.app.DATA_DIR = tmp_path
        self.app.CONFIG_DIR = tmp_path / "configs"
        self.app.STATE_FILE = tmp_path / "state.json"
        self.app.NODES_FILE = tmp_path / "nodes.json"

    def write_config(self, **updates):
        config = {"username": "user", "password": "pass"}
        config.update(updates)
        (self.app.DATA_DIR / "ui_auth.json").write_text(json.dumps(config), encoding="utf-8")

    def test_speed_config_defaults(self):
        cfg = self.app.load_ui_config()
        self.assertIs(cfg["speed_test_enabled"], False)
        self.assertEqual(cfg["speed_test_interval"], 3600)
        self.assertEqual(cfg["speed_test_min_bytes"], 10 * 1024 * 1024)
        self.assertEqual(cfg["speed_test_url"], self.app.DEFAULT_SPEED_TEST_URL)
        self.assertEqual(cfg["speed_test_country"], "")
        self.assertEqual(cfg["speed_test_ip_type"], "all")
        self.assertEqual(cfg["speed_test_status"], "all")
        self.assertIs(cfg["speed_test_favorites_only"], False)

    def test_speed_state_defaults(self):
        state = self.app.get_state()
        self.assertIs(state["speed_test_running"], False)
        self.assertEqual(state["speed_test_completed"], 0)
        self.assertEqual(state["speed_test_total"], 0)

    def test_speed_config_normalizes_invalid_values(self):
        self.write_config(
            speed_test_enabled="yes",
            speed_test_interval=10,
            speed_test_min_bytes=1,
            speed_test_url=123,
            speed_test_country=123,
            speed_test_ip_type="invalid",
            speed_test_status="invalid",
            speed_test_favorites_only="yes",
        )
        cfg = self.app.load_ui_config()
        self.assertIs(cfg["speed_test_enabled"], False)
        self.assertEqual(cfg["speed_test_interval"], 3600)
        self.assertEqual(cfg["speed_test_min_bytes"], 10 * 1024 * 1024)
        self.assertEqual(cfg["speed_test_url"], self.app.DEFAULT_SPEED_TEST_URL)
        self.assertEqual(cfg["speed_test_country"], "")
        self.assertEqual(cfg["speed_test_ip_type"], "all")
        self.assertEqual(cfg["speed_test_status"], "all")
        self.assertIs(cfg["speed_test_favorites_only"], False)

    def test_stop_speed_test_marks_running_job_for_cancellation(self):
        self.app.speed_test_cancel.clear()
        self.app.speed_test_lock.acquire()
        try:
            self.assertIs(self.app.stop_speed_test(), True)
            self.assertTrue(self.app.speed_test_cancel.is_set())
        finally:
            self.app.speed_test_lock.release()

    def test_speed_config_normalizes_country_and_url(self):
        self.write_config(
            speed_test_country="  日本  ",
            speed_test_url=" https://example.test/file.bin ",
        )
        cfg = self.app.load_ui_config()
        self.assertEqual(cfg["speed_test_country"], "日本")
        self.assertEqual(cfg["speed_test_url"], "https://example.test/file.bin")

    def test_speed_config_rejects_non_https_or_unparseable_url(self):
        for url in ("http://example.test/file.bin", "ftp://example.test/file.bin", "https:///missing-host", "https://"):
            with self.subTest(url=url):
                self.write_config(speed_test_url=url)
                cfg = self.app.load_ui_config()
                self.assertEqual(cfg["speed_test_url"], self.app.DEFAULT_SPEED_TEST_URL)

    def test_legacy_speed_url_migrates_to_cloudflare(self):
        self.write_config(speed_test_url="https://speed.hetzner.de/100MB.bin")
        cfg = self.app.load_ui_config()
        self.assertEqual(cfg["speed_test_url"], self.app.DEFAULT_SPEED_TEST_URL)

    def test_preserve_node_runtime_fields_keeps_speed_results(self):
        candidate = {"id": "node-1", "probe_status": "available"}
        previous = {
            "speed_test_bps": 1048576,
            "speed_test_at": 123,
            "speed_test_bytes": 10485760,
            "speed_test_status": "ok",
            "speed_test_error": "",
        }
        self.app.preserve_node_runtime_fields(candidate, previous)
        for key, value in previous.items():
            self.assertEqual(candidate[key], value)

    def test_state_exposes_real_node_refresh_status(self):
        self.app.node_refresh_running = True
        try:
            self.assertIs(self.app.get_state()["node_refresh_running"], True)
        finally:
            self.app.node_refresh_running = False

    def test_speed_config_preserves_valid_values(self):
        ip_types = ("all", "residential", "hosting")
        statuses = ("all", "available", "testing", "unavailable")
        for ip_type in ip_types:
            for status in statuses:
                with self.subTest(ip_type=ip_type, status=status):
                    self.write_config(
                        speed_test_enabled=False,
                        speed_test_interval=3600,
                        speed_test_min_bytes=10 * 1024 * 1024,
                        speed_test_ip_type=ip_type,
                        speed_test_status=status,
                        speed_test_favorites_only=True,
                    )
                    cfg = self.app.load_ui_config()
                    self.assertIs(cfg["speed_test_enabled"], False)
                    self.assertEqual(cfg["speed_test_interval"], 3600)
                    self.assertEqual(cfg["speed_test_min_bytes"], 10 * 1024 * 1024)
                    self.assertEqual(cfg["speed_test_ip_type"], ip_type)
                    self.assertEqual(cfg["speed_test_status"], status)
                    self.assertIs(cfg["speed_test_favorites_only"], True)

    def test_filter_speed_nodes_uses_only_speed_settings(self):
        nodes = [
            {"id": "jp-home", "country": "Japan", "ip_type": "residential", "probe_status": "available"},
            {"id": "us-host", "country": "United States", "ip_type": "hosting", "probe_status": "available"},
            {"id": "jp-active", "country": "Japan", "ip_type": "mobile", "probe_status": "available", "active": True},
        ]
        cfg = {
            "routing_mode": "favorites",
            "force_country": "美国",
            "routing_ip_type": "hosting",
            "speed_test_country": "日本",
            "speed_test_ip_type": "residential",
            "speed_test_status": "available",
            "speed_test_favorites_only": False,
            "favorite_node_ids": [],
        }
        result = self.app.filter_speed_nodes(nodes, cfg)
        self.assertEqual([node["id"] for node in result], ["jp-home", "jp-active"])

    def test_filter_speed_nodes_supports_status_and_favorites(self):
        nodes = [
            {"id": "favorite", "probe_status": "unavailable"},
            {"id": "other", "probe_status": "unavailable"},
            {"id": "available", "probe_status": "available"},
        ]
        cfg = {
            "speed_test_country": "",
            "speed_test_ip_type": "all",
            "speed_test_status": "unavailable",
            "speed_test_favorites_only": True,
            "favorite_node_ids": ["favorite", "available"],
        }
        result = self.app.filter_speed_nodes(nodes, cfg)
        self.assertEqual([node["id"] for node in result], ["favorite"])

    def test_residential_filter_includes_every_non_hosting_type(self):
        nodes = [
            {"id": "home", "ip_type": "residential"},
            {"id": "mobile", "ip_type": "mobile"},
            {"id": "unknown", "ip_type": ""},
            {"id": "host", "ip_type": "hosting"},
        ]
        cfg = {
            "speed_test_country": "",
            "speed_test_ip_type": "residential",
            "speed_test_status": "all",
            "speed_test_favorites_only": False,
        }
        self.assertEqual(
            [node["id"] for node in self.app.filter_speed_nodes(nodes, cfg)],
            ["home", "mobile", "unknown"],
        )

    def test_format_speed_uses_megabytes_per_second(self):
        self.assertEqual(self.app.format_speed(1024 * 1024), "1.00 MB/s")
        self.assertEqual(self.app.format_speed(0), "-")

    def test_openvpn_command_marks_linux_control_traffic(self):
        config_path = self.app.DATA_DIR / "node.ovpn"
        config_path.write_text("client\nproto udp\n", encoding="utf-8")
        with (
            patch.object(self.app, "split_openvpn_command", return_value=["openvpn"]),
            patch.object(self.app, "get_openvpn_version", return_value=2.6),
            patch.object(self.app.sys, "platform", "linux"),
        ):
            command = self.app.openvpn_command(str(config_path), True, "tun0")
        self.assertEqual(command[command.index("--mark") + 1], "51820")

    def test_main_policy_cleanup_is_exact(self):
        with patch.object(self.app.subprocess, "run") as run:
            self.app.cleanup_policy_routing("tun0", 100, 32765)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(
            ["ip", "rule", "del", "priority", "32765", "oif", "tun0", "lookup", "100"],
            commands,
        )
        self.assertNotIn(["ip", "rule", "del", "table", "100"], commands)

    def test_main_route_setup_refreshes_jkw_global_route(self):
        fake_jkw = self.app.DATA_DIR / "jkw"
        fake_jkw.write_text("", encoding="utf-8")
        with (
            patch.object(self.app, "JKW_COMMAND", fake_jkw, create=True),
            patch.object(self.app.subprocess, "run") as run,
        ):
            self.app.refresh_global_residential_route()
        self.assertIn(
            [str(fake_jkw), "--刷新整机路由"],
            [call.args[0] for call in run.call_args_list],
        )

    def test_resolve_speed_target_uses_marked_public_interface_dns(self):
        with (
            patch.object(self.app, "main_route_interface", return_value="ens18"),
            patch.object(
                self.app.proxy_server,
                "dns_query_over_interface",
                return_value="203.0.113.8",
                create=True,
            ) as query,
        ):
            result = self.app.resolve_speed_target("https://example.test/file.bin")
        self.assertEqual(result, "203.0.113.8")
        query.assert_called_once_with("example.test", 1, "1.1.1.1", 4.0, "ens18", 51820)

    def test_direct_socket_is_bound_and_marked(self):
        sock = Mock()
        with (
            patch.object(self.app.sys, "platform", "linux"),
            patch.object(self.app.socket, "SO_MARK", 36, create=True),
            patch.object(self.app.socket, "SO_BINDTODEVICE", 25, create=True),
        ):
            self.app.prepare_direct_socket(sock, "ens18")
        sock.setsockopt.assert_any_call(self.app.socket.SOL_SOCKET, 36, 51820)
        sock.setsockopt.assert_any_call(
            self.app.socket.SOL_SOCKET,
            25,
            b"ens18\0",
        )

    def test_global_mode_api_fetch_uses_direct_control_plane(self):
        with (
            patch.object(self.app, "global_residential_mode_enabled", return_value=True),
            patch.object(self.app, "fetch_api_text_direct", return_value="api-data") as direct,
        ):
            result = self.app.fetch_api_text("https://api.example.test/list")
        self.assertEqual(result, "api-data")
        direct.assert_called_once_with("https://api.example.test/list", True)

    def test_main_connect_disables_upstream_proxy_in_global_mode(self):
        source = inspect.getsource(self.app.connect_node)
        self.assertIn("use_upstream_proxy=not global_residential_mode_enabled()", source)

    def test_download_speed_via_interface_caps_and_calculates_download(self):
        class FakeResult:
            returncode = 0
            stdout = "10485760 2.0"
            stderr = ""

        with patch.object(self.app.subprocess, "run", return_value=FakeResult()) as run:
            result = self.app.download_speed_via_interface(
                "tun2", "https://example.test/file.bin", 10 * 1024 * 1024, "203.0.113.8"
            )

        self.assertIs(result["ok"], True)
        self.assertEqual(result["bytes"], 10 * 1024 * 1024)
        self.assertEqual(result["bps"], 5 * 1024 * 1024)
        command = run.call_args.args[0]
        self.assertIn("--interface", command)
        self.assertEqual(command[command.index("--interface") + 1], "if!tun2")
        self.assertEqual(command[command.index("--resolve") + 1], "example.test:443:203.0.113.8")
        self.assertEqual(command[command.index("--proto") + 1], "=https")
        self.assertNotIn("--location", command)
        self.assertIn("--range", command)
        self.assertIn("0-10485759", command)
        self.assertIn("--max-filesize", command)
        self.assertIn("10485760", command)
        self.assertIn("--connect-timeout", command)
        self.assertIn("--max-time", command)

    def test_download_speed_via_interface_rejects_unsafe_inputs(self):
        for interface, url, size in (
            ("tun2", "http://example.test/file.bin", 10 * 1024 * 1024),
            ("tun2", "https://example.test/file.bin", 1024),
            ("tun2;reboot", "https://example.test/file.bin", 10 * 1024 * 1024),
        ):
            with self.subTest(interface=interface, url=url, size=size):
                result = self.app.download_speed_via_interface(interface, url, size, "203.0.113.8")
                self.assertIs(result["ok"], False)

    def test_download_speed_via_interface_caps_requested_bytes_at_10_mib(self):
        class FakeResult:
            returncode = 0
            stdout = "10485760 2.0"
            stderr = ""

        with patch.object(self.app.subprocess, "run", return_value=FakeResult()) as run:
            result = self.app.download_speed_via_interface(
                "tun2", "https://example.test/file.bin", 20 * 1024 * 1024, "203.0.113.8"
            )

        self.assertIs(result["ok"], True)
        self.assertEqual(result["bytes"], 10 * 1024 * 1024)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--range") + 1], "0-10485759")
        self.assertEqual(command[command.index("--max-filesize") + 1], "10485760")

    def test_speed_test_worker_records_success(self):
        node = {
            "id": "n1",
            "config_text": "client",
            "remote_host": "1.2.3.4",
            "remote_port": 1194,
            "active": False,
        }
        with (
            patch.object(self.app, "run_openvpn_until_ready", return_value=(True, "ok", object())) as openvpn,
            patch.object(self.app, "setup_policy_routing") as setup,
            patch.object(self.app, "cleanup_policy_routing") as cleanup,
            patch.object(self.app, "resolve_speed_target", return_value="203.0.113.8"),
            patch.object(
                self.app,
                "download_speed_via_interface",
                return_value={"ok": True, "bytes": 10 * 1024 * 1024, "bps": 2 * 1024 * 1024},
            ),
            patch.object(self.app, "stop_process"),
        ):
            result = self.app.speed_test_node(node, "https://example.test/10MB.bin")

        self.assertEqual(result["speed_test_status"], "ok")
        self.assertEqual(result["speed_test_bytes"], 10 * 1024 * 1024)
        self.assertEqual(result["speed_test_bps"], 2 * 1024 * 1024)
        self.assertFalse(openvpn.call_args.kwargs["report_status"])
        self.assertFalse(openvpn.call_args.kwargs["use_upstream_proxy"])
        setup.assert_called_once_with("tun2", 202, 31002)
        cleanup.assert_called_once_with("tun2", 202, 31002)

    def test_speed_test_worker_does_not_skip_active_node(self):
        node = {"id": "active", "active": True, "config_text": "client"}
        with (
            patch.object(self.app, "get_free_test_index", return_value=2),
            patch.object(self.app, "resolve_speed_target", return_value="203.0.113.8"),
            patch.object(self.app, "run_openvpn_until_ready", return_value=(True, "ok", object())),
            patch.object(self.app, "setup_policy_routing"),
            patch.object(self.app, "cleanup_policy_routing"),
            patch.object(self.app, "download_speed_via_interface", return_value={"ok": True, "bytes": 10485760, "bps": 1}),
            patch.object(self.app, "stop_process"),
        ):
            result = self.app.speed_test_node(node, "https://example.test/10MB.bin")
        self.assertEqual(result["speed_test_status"], "ok")

    def test_speed_test_once_writes_each_result(self):
        nodes = [{"id": "n1", "config_text": "client", "probe_status": "available"}]
        self.app.NODES_FILE.write_text(json.dumps(nodes), encoding="utf-8")
        with patch.object(
            self.app,
            "speed_test_node",
            return_value={
                "speed_test_status": "ok",
                "speed_test_bytes": 10 * 1024 * 1024,
                "speed_test_bps": 2 * 1024 * 1024,
                "speed_test_at": 123,
                "speed_test_error": "",
            },
        ), patch.object(self.app, "connect_node"):
            result = self.app.speed_test_once()

        saved = json.loads(self.app.NODES_FILE.read_text(encoding="utf-8"))
        self.assertIs(result["ok"], True)
        self.assertEqual(saved[0]["speed_test_status"], "ok")
        self.assertEqual(self.app.get_state()["speed_test_completed"], 1)

    def test_speed_round_clears_old_results_and_connects_fastest(self):
        nodes = [
            {"id": "slow", "config_text": "a", "speed_test_bps": 999, "speed_test_status": "ok"},
            {"id": "fast", "config_text": "b", "speed_test_bps": 1, "speed_test_status": "error"},
        ]
        self.app.NODES_FILE.write_text(json.dumps(nodes), encoding="utf-8")
        results = {
            "slow": {"speed_test_status": "ok", "speed_test_bps": 1048576, "speed_test_bytes": 10485760, "speed_test_at": 1, "speed_test_error": ""},
            "fast": {"speed_test_status": "ok", "speed_test_bps": 4194304, "speed_test_bytes": 10485760, "speed_test_at": 2, "speed_test_error": ""},
        }
        observed_clear = []

        def run_test(node, url):
            saved = json.loads(self.app.NODES_FILE.read_text(encoding="utf-8"))
            observed_clear.append(all("speed_test_bps" not in item for item in saved))
            return results[node["id"]]

        self.write_config(
            speed_test_url="https://example.test/file",
            speed_test_country="",
            speed_test_ip_type="all",
            speed_test_status="all",
            speed_test_favorites_only=False,
            connection_enabled=True,
        )
        with (
            patch.object(self.app, "speed_test_node", side_effect=run_test),
            patch.object(self.app, "connect_node") as connect,
        ):
            result = self.app.speed_test_once()
        self.assertEqual(result["ok"], True)
        self.assertEqual(result["fastest_node_id"], "fast")
        self.assertEqual(result["succeeded"], 2)
        self.assertIs(observed_clear[0], True)
        connect.assert_called_once_with("fast", user_initiated=False)

    def test_all_failed_round_returns_failure_and_keeps_connection(self):
        self.app.NODES_FILE.write_text(json.dumps([{"id": "n1", "config_text": "a"}]), encoding="utf-8")
        failed = {"speed_test_status": "error", "speed_test_bps": 0, "speed_test_bytes": 0, "speed_test_at": 1, "speed_test_error": "测速失败"}
        self.write_config(speed_test_url="https://example.test/file", connection_enabled=True)
        with (
            patch.object(self.app, "speed_test_node", return_value=failed),
            patch.object(self.app, "connect_node") as connect,
        ):
            result = self.app.speed_test_once()
        self.assertIs(result["ok"], False)
        self.assertEqual(result["failed"], 1)
        connect.assert_not_called()

    def test_speed_round_does_not_reconnect_after_manual_disconnect(self):
        self.app.NODES_FILE.write_text(json.dumps([{"id": "n1", "config_text": "a"}]), encoding="utf-8")
        success = {"speed_test_status": "ok", "speed_test_bps": 4194304, "speed_test_bytes": 10485760, "speed_test_at": 1, "speed_test_error": ""}
        self.write_config(speed_test_url="https://example.test/file", connection_enabled=False)
        with (
            patch.object(self.app, "speed_test_node", return_value=success),
            patch.object(self.app, "connect_node") as connect,
        ):
            result = self.app.speed_test_once()
        self.assertIs(result["ok"], True)
        connect.assert_not_called()

    def test_manual_connection_api_marks_user_operation(self):
        source = inspect.getsource(self.app.Handler.do_POST)
        self.assertIn('connect_node(str(payload.get("id") or ""), user_initiated=True)', source)
        disconnect_block = source[source.index('effective_path == "/api/disconnect"'):source.index('effective_path == "/api/connect"')]
        self.assertIn("note_user_connection_operation()", disconnect_block)

    def test_empty_speed_round_is_success_without_retry_error(self):
        self.app.NODES_FILE.write_text("[]", encoding="utf-8")
        result = self.app.speed_test_once()
        self.assertEqual(result["ok"], True)
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["succeeded"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["skipped"], 0)

    def test_speed_settings_payload_rejects_short_interval(self):
        result = self.app.validate_speed_settings(
            {
                "enabled": True,
                "country": "日本",
                "ip_type": "residential",
                "status": "available",
                "favorites_only": True,
                "interval": 3599,
            }
        )
        self.assertIs(result["ok"], False)
        self.assertIn("3600", result["error"])

    def test_speed_settings_payload_accepts_minimum_interval(self):
        result = self.app.validate_speed_settings(
            {
                "enabled": False,
                "country": "",
                "ip_type": "all",
                "status": "all",
                "favorites_only": False,
                "interval": 3600,
            }
        )
        self.assertIs(result["ok"], True)

    def test_speed_ui_strings_present(self):
        self.assertIn("测速设置", self.app.INDEX_HTML)
        self.assertIn("按当前筛选测速", self.app.INDEX_HTML)
        self.assertIn("检测可用性", self.app.INDEX_HTML)
        self.assertIn("下载速度", self.app.INDEX_HTML)
        self.assertIn("测速时间", self.app.INDEX_HTML)

    def test_manual_availability_check_uses_current_non_active_nodes(self):
        self.app.NODES_FILE.write_text(json.dumps([
            {"id": "active", "active": True},
            {"id": "candidate", "active": False},
        ]), encoding="utf-8")
        with patch.object(self.app, "test_multiple_nodes") as check:
            result = self.app.check_current_nodes()
        self.assertIn("1 个", result)
        check.assert_called_once_with(["candidate"])

    def test_residential_ui_explains_mobile_is_included(self):
        self.assertIn("住宅 IP（含移动网络）", self.app.INDEX_HTML)

    def test_compact_speed_settings_ui_present(self):
        html = self.app.INDEX_HTML
        self.assertLess(html.index('id="speed_settings_top"'), html.index('id="admin_btn"'))
        self.assertIn('class="speed-switch-row"', html)
        self.assertEqual(html.count('class="speed-switch"'), 2)
        self.assertIn('max-width: 480px', html)
        self.assertIn('class="speed-modal-close"', html)
        self.assertIn('<div id="speed_modal" class="modal">', html)

    def test_mobile_header_buttons_wrap_without_page_overflow(self):
        html = self.app.INDEX_HTML
        self.assertIn("flex-wrap: wrap;", html)
        self.assertIn("flex: 1 1 calc(50% - 4px);", html)
        self.assertIn("min-width: 150px;", html)

    def test_speed_test_loop_is_started_by_main(self):
        self.assertTrue(callable(self.app.speed_test_loop))
        self.assertTrue(hasattr(self.app, "speed_test_trigger"))
        self.assertIn("target=speed_test_loop", inspect.getsource(self.app.main))

    def test_speed_test_loop_retries_soon_when_node_maintenance_is_busy(self):
        class FakeTrigger:
            def __init__(self):
                self.timeouts = []

            def wait(self, timeout):
                self.timeouts.append(timeout)
                if len(self.timeouts) == 3:
                    raise StopIteration
                return False

            def clear(self):
                pass

        trigger = FakeTrigger()
        results = [
            {"ok": False, "error": "节点维护任务正在运行，请稍后再试"},
            {"ok": True, "total": 0},
        ]
        with (
            patch.object(self.app, "speed_test_trigger", trigger),
            patch.object(
                self.app,
                "load_ui_config",
                return_value={"speed_test_enabled": True, "speed_test_interval": 3600},
            ),
            patch.object(self.app, "speed_test_once", side_effect=results),
            self.assertRaises(StopIteration),
        ):
            self.app.speed_test_loop()

        self.assertEqual(trigger.timeouts, [30, 30, 3600])

    def test_config_wakeup_recalculates_without_running_speed_test(self):
        class FakeTrigger:
            def __init__(self):
                self.calls = 0

            def wait(self, timeout):
                self.calls += 1
                if self.calls == 1:
                    return True
                raise StopIteration

            def clear(self):
                pass

        trigger = FakeTrigger()
        with (
            patch.object(self.app, "speed_test_trigger", trigger),
            patch.object(self.app, "consume_speed_test_request", return_value=False, create=True),
            patch.object(
                self.app,
                "load_ui_config",
                return_value={"speed_test_enabled": True, "speed_test_interval": 3600},
            ),
            patch.object(self.app, "speed_test_once") as run,
            self.assertRaises(StopIteration),
        ):
            self.app.speed_test_loop()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
