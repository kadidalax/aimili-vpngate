from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import proxy_server
import snapshot_utils

REPO_ROOT = Path(__file__).resolve().parent.parent

_import_data_dir = tempfile.TemporaryDirectory()
_original_data_dir = os.environ.get("VPNGATE_DATA_DIR")
os.environ["VPNGATE_DATA_DIR"] = _import_data_dir.name
try:
    import vpngate_manager as manager
finally:
    if _original_data_dir is None:
        os.environ.pop("VPNGATE_DATA_DIR", None)
    else:
        os.environ["VPNGATE_DATA_DIR"] = _original_data_dir


class FakeProcess:
    def __init__(self) -> None:
        self.running = True
        self.terminated = False

    def poll(self):
        return None if self.running else 0

    def terminate(self) -> None:
        self.terminated = True
        self.running = False

    def wait(self, timeout=None):
        self.running = False
        return 0

    def kill(self) -> None:
        self.running = False


def valid_snapshot_rows(rows: list[tuple[str, str, str]]) -> str:
    csv_rows = [
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
    ]
    for index, (ip, country_long, country_short) in enumerate(rows):
        config_text = (
            "client\n"
            "dev tun\n"
            "proto udp\n"
            f"remote {ip} 1194 udp\n"
            "resolv-retry infinite\n"
            "nobind\n"
            "<ca>\nCA\n</ca>\n"
            "<cert>\nCERT\n</cert>\n"
            "<key>\nKEY\n</key>\n"
        )
        config = base64.b64encode(config_text.encode("utf-8")).decode("ascii")
        csv_rows.append(
            f"vpn{index}.example,{ip},100,20,1000,{country_long},{country_short},1,{config}"
        )
    return "\n".join(csv_rows) + "\n"


def valid_snapshot(ip: str = "198.51.100.10") -> str:
    return valid_snapshot_rows([(ip, "Japan", "JP")])


class ManagerLogicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
            mock.patch.object(manager, "SPEED_HISTORY_FILE", root / "speed_history.json"),
            mock.patch.object(manager.vpn_utils, "DATA_DIR", root),
            mock.patch.object(manager.vpn_utils, "IP_CACHE_FILE", root / "ip_cache.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager.active_openvpn_process = None
        manager.pending_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.active_connection_cancel_event = None
        manager.is_connecting = False
        manager.consecutive_proxy_failures = 0
        manager.last_proxy_failure_node_id = ""
        manager.background_refill_thread = None
        manager.background_refill_cancel_event.clear()
        manager.active_sessions.clear()

    def tearDown(self) -> None:
        if manager.connection_attempt_lock.locked():
            manager.connection_attempt_lock.release()
        manager.background_refill_cancel_event.set()
        manager.background_refill_thread = None
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    def write_nodes(self, count: int) -> list[dict]:
        nodes = []
        for index in range(count):
            node_id = f"node-{index}"
            nodes.append(
                {
                    "id": node_id,
                    "ip": f"192.0.2.{index + 1}",
                    "remote_host": f"192.0.2.{index + 1}",
                    "remote_port": 1194,
                    "ping": index + 1,
                    "score": 1000 - index,
                    "config_text": "client\nremote 192.0.2.1 1194 udp\n",
                    "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
                    "probe_status": "not_checked",
                    "probed_at": 0,
                    "active": False,
                }
            )
        manager.write_json(manager.NODES_FILE, nodes)
        return nodes

    def test_node_probe_stops_after_target_batch(self) -> None:
        nodes = self.write_nodes(12)
        calls = []

        def fake_openvpn(config_file, **kwargs):
            calls.append(config_file)
            return True, "ready", None

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=3,
            )

        self.assertEqual(5, len(calls))
        self.assertEqual(5, len(results))
        stored = manager.read_nodes()
        self.assertEqual(5, sum(node.get("probe_status") == "available" for node in stored))
        self.assertEqual(7, sum(node.get("probe_status") == "not_checked" for node in stored))

    def test_ip_classification_separates_proxy_use_from_network_type(self) -> None:
        residential, residential_reason = manager.vpn_utils.classify_ip_type(
            {
                "isp": "Sony Network Communications Inc.",
                "org": "Sony Network Communications Inc.",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        )
        softether, softether_reason = manager.vpn_utils.classify_ip_type(
            {
                "isp": "SoftEther",
                "org": "SoftEther Corporation",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        )
        hosting, hosting_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": True, "hosting": True, "mobile": False}
        )
        mobile, mobile_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": False, "hosting": False, "mobile": True}
        )
        unknown, unknown_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": True, "hosting": False, "mobile": False}
        )

        self.assertEqual(("residential", "consumer_or_unclassified_network"), (residential, residential_reason))
        self.assertEqual(("hosting", "proxy_provider_datacenter"), (softether, softether_reason))
        self.assertEqual(("hosting", "hosting_flag"), (hosting, hosting_reason))
        self.assertEqual(("mobile", "mobile_flag"), (mobile, mobile_reason))
        self.assertEqual(("unknown", "missing_provider_data"), (unknown, unknown_reason))
        self.assertEqual("low", manager.vpn_utils.classification_confidence(unknown_reason))

    def test_ip_enrichment_reclassifies_legacy_cache_and_keeps_proxy_quality(self) -> None:
        ip = "118.240.250.95"
        manager.vpn_utils.IP_CACHE_FILE.write_text(
            json.dumps(
                {
                    ip: {
                        "ip_type": "hosting",
                        "quality": "proxy",
                        "cached_at": 9999999999,
                        "classification_version": 1,
                    }
                }
            ),
            encoding="utf-8",
        )
        api_result = [
            {
                "status": "success",
                "query": ip,
                "country": "Japan",
                "regionName": "Tokyo",
                "city": "Tokyo",
                "isp": "Sony Network Communications Inc.",
                "org": "Sony Network Communications Inc.",
                "as": "AS2527 Sony Network Communications Inc.",
                "asname": "Sony Network Communications Inc.",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        ]
        response = mock.MagicMock()
        response.read.return_value = json.dumps(api_result).encode("utf-8")
        response.__enter__.return_value = response
        node = {"id": "sony", "ip": ip}

        with mock.patch.object(manager.vpn_utils.urllib.request, "urlopen", return_value=response) as urlopen_mock:
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("residential", node["ip_type"])
        self.assertEqual("proxy", node["quality"])
        self.assertTrue(node["is_proxy"])
        self.assertFalse(node["is_hosting"])
        urlopen_mock.assert_called_once()
        cache = json.loads(manager.vpn_utils.IP_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual(manager.vpn_utils.IP_CLASSIFICATION_VERSION, cache[ip]["classification_version"])

    def test_ambiguous_datacenter_uses_secondary_source_and_geo_country(self) -> None:
        ip = "219.100.37.98"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Chiyoda",
            "isp": "SoftEther",
            "org": "SoftEther Corporation",
            "as": "AS36599 SoftEther",
            "asname": "SOFTETHER",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        secondary = mock.MagicMock()
        secondary.read.return_value = json.dumps({"is_datacenter": True, "is_vpn": True}).encode("utf-8")
        secondary.__enter__.return_value = secondary
        node = {"id": "softether", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, secondary],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("hosting", node["ip_type"])
        self.assertEqual("high", node["ip_type_confidence"])
        self.assertEqual("datacenter", node["quality"])
        self.assertTrue(node["is_hosting"])
        self.assertEqual(["ip-api.com", "ipapi.is"], node["ip_type_sources"])
        self.assertEqual("JP", node["geo_country_short"])

    def test_unverified_datacenter_conflict_becomes_unknown(self) -> None:
        ip = "203.0.113.10"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Tokyo",
            "isp": "Example VPS",
            "org": "Example VPS Hosting",
            "as": "AS64500 Example",
            "asname": "EXAMPLE",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        node = {"id": "ambiguous", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, TimeoutError("secondary unavailable")],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("unknown", node["ip_type"])
        self.assertEqual("low", node["ip_type_confidence"])
        strict = manager.apply_routing_filters([node], {"routing_mode": "auto", "routing_ip_type": "residential"})
        self.assertEqual([], strict)

    def test_missing_provider_data_uses_secondary_source_or_stays_unknown(self) -> None:
        ip = "203.0.113.11"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Tokyo",
            "isp": "",
            "org": "",
            "as": "",
            "asname": "",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        node = {"id": "missing-provider", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, TimeoutError("secondary unavailable")],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("unknown", node["ip_type"])
        self.assertEqual("provider_data_unverified", node["ip_type_reason"])
        self.assertEqual("low", node["ip_type_confidence"])
        strict = manager.apply_routing_filters(
            [node],
            {"routing_mode": "auto", "routing_ip_type": "residential"},
        )
        self.assertEqual([], strict)

    def test_strict_residential_filter_requires_medium_or_high_confidence(self) -> None:
        nodes = [
            {"id": "low", "ip_type": "residential", "ip_type_confidence": "low"},
            {"id": "medium", "ip_type": "residential", "ip_type_confidence": "medium"},
            {"id": "mobile", "ip_type": "mobile", "ip_type_confidence": "high"},
            {"id": "hosting", "ip_type": "hosting", "ip_type_confidence": "high"},
        ]

        strict = manager.apply_routing_filters(
            nodes,
            {"routing_mode": "auto", "routing_ip_type": "residential"},
        )

        self.assertEqual(["medium", "mobile"], [node["id"] for node in strict])

    def test_background_ip_enrichment_merges_metadata_without_replacing_status(self) -> None:
        nodes = self.write_nodes(2)
        nodes[0]["probe_status"] = "available"
        manager.write_json(manager.NODES_FILE, nodes)

        def fake_enrich(items):
            for item in items:
                item["ip_type"] = "residential"
                item["quality"] = "proxy"
                item["owner"] = "Consumer ISP"
                item["is_proxy"] = True

        with mock.patch.object(manager.vpn_utils, "enrich_ip_info", side_effect=fake_enrich):
            changed = manager.enrich_stored_nodes()

        stored = manager.read_nodes()
        self.assertGreater(changed, 0)
        self.assertEqual("available", next(node for node in stored if node["id"] == "node-0")["probe_status"])
        self.assertTrue(all(node["ip_type"] == "residential" for node in stored))

    def test_source_deadline_still_tries_official_http(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl=True, deadline_seconds=None):
            if url == manager.API_HTTPS_URL:
                raise manager.SourceDeadlineExceeded("slow official source")
            if url == manager.API_HTTP_URL:
                return csv_text
            raise AssertionError(f"unexpected source: {url}")

        with (
            mock.patch.object(manager, "fetch_api_text_with_deadline", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [manager.API_HTTPS_URL, manager.API_HTTP_URL],
            [call.args[0] for call in fetch_mock.call_args_list],
        )

    def test_probe_failure_preserves_existing_ip_metadata(self) -> None:
        nodes = self.write_nodes(1)
        nodes[0].update(
            {
                "owner": "Existing ISP",
                "location": "日本 东京",
                "ip_type": "residential",
                "ip_type_confidence": "medium",
            }
        )
        manager.write_json(manager.NODES_FILE, nodes)

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=0),
            mock.patch.object(manager, "run_openvpn_until_ready", return_value=(False, "offline", None)),
        ):
            manager.test_multiple_nodes([nodes[0]["id"]])

        stored = manager.read_nodes()[0]
        self.assertEqual("unavailable", stored["probe_status"])
        self.assertEqual("Existing ISP", stored["owner"])
        self.assertEqual("日本 东京", stored["location"])
        self.assertEqual("residential", stored["ip_type"])
        self.assertEqual("medium", stored["ip_type_confidence"])

    def test_country_matching_accepts_iso_and_legacy_name(self) -> None:
        node = {"country": "日本", "country_short": "JP"}
        self.assertTrue(manager.country_matches(node["country"], "JP", node["country_short"]))
        self.assertTrue(manager.country_matches(node["country"], "日本", node["country_short"]))
        self.assertFalse(manager.country_matches(node["country"], "KR", node["country_short"]))
        self.assertEqual("JP", manager.normalize_routing_country("日本", [node]))

    def test_web_and_proxy_ports_must_be_distinct(self) -> None:
        self.assertTrue(manager.ports_conflict(8787, "8787"))
        self.assertFalse(manager.ports_conflict(8787, 7928))

    def test_ui_connection_requires_tunnel_and_proxy_readiness(self) -> None:
        manager.active_openvpn_node_id = "node-1"
        manager.active_openvpn_process = FakeProcess()
        base_state = {"is_connecting": False, "tunnel_ready": True, "proxy_ready": False, "proxy_ok": False}
        self.assertFalse(manager.connection_ready_for_ui(base_state))
        ready_state = {**base_state, "proxy_ready": True, "proxy_ok": True}
        self.assertTrue(manager.connection_ready_for_ui(ready_state))
        # Background maintenance keeps the tunnel up, so it must not hide the active node.
        self.assertTrue(manager.connection_ready_for_ui({**ready_state, "is_connecting": True}))
        self.assertFalse(manager.connection_ready_for_ui({**ready_state, "pending_node_id": "node-2"}))

    def test_manual_disconnect_state_clears_all_readiness_flags(self) -> None:
        nodes = self.write_nodes(1)
        nodes[0]["active"] = True
        manager.write_json(manager.NODES_FILE, nodes)
        manager.set_state(
            is_connecting=True,
            tunnel_ready=True,
            proxy_ready=True,
            proxy_ok=True,
            proxy_ip="198.51.100.20",
        )

        with mock.patch.object(manager, "stop_active_openvpn") as stop_mock:
            manager.clear_active_connection_state("手动断开连接")

        stop_mock.assert_called_once_with()
        state = manager.get_state()
        self.assertFalse(state["is_connecting"])
        self.assertFalse(state["tunnel_ready"])
        self.assertFalse(state["proxy_ready"])
        self.assertFalse(state["proxy_ok"])
        self.assertEqual("-", state["proxy_ip"])
        self.assertFalse(any(node.get("active") for node in manager.read_nodes()))

    def test_ui_config_has_v220_defaults(self) -> None:
        cfg = manager.load_ui_config()
        self.assertEqual(24, cfg["check_interval_hours"])
        self.assertTrue(cfg["singbox_exit_enabled"])
        self.assertFalse(cfg["global_exit_enabled"])
        self.assertEqual(manager.speedtest.DEFAULT_SETTINGS, cfg["speedtest"])

        auth_file = manager.DATA_DIR / "ui_auth.json"
        stored = json.loads(auth_file.read_text(encoding="utf-8"))
        stored["check_interval_hours"] = 999
        stored["singbox_exit_enabled"] = "yes"
        stored["speedtest"] = {"per_node_seconds": 1, "url": "ftp://x"}
        manager.write_json(auth_file, stored)
        cfg = manager.load_ui_config()
        self.assertEqual(24, cfg["check_interval_hours"])  # out-of-range falls back to default
        self.assertTrue(cfg["singbox_exit_enabled"])
        self.assertEqual(3, cfg["speedtest"]["per_node_seconds"])
        self.assertEqual(manager.speedtest.DEFAULT_URL, cfg["speedtest"]["url"])
        persisted = json.loads(auth_file.read_text(encoding="utf-8"))
        self.assertEqual(24, persisted["check_interval_hours"])

    def test_check_interval_seconds_uses_hours(self) -> None:
        manager.update_ui_config(check_interval_hours=2)
        self.assertEqual(7200, manager.check_interval_seconds())
        manager.update_ui_config(check_interval_hours=0)
        self.assertEqual(86400, manager.check_interval_seconds())

    def test_state_exposes_pipeline_exit_and_speedtest_settings(self) -> None:
        manager.pipeline_set(running=True, stage="probe", probe_total=7)
        try:
            with manager.lock:
                manager.exit_status["global"]["applied"] = True
            state = manager.get_state()
        finally:
            manager.pipeline_status.update(manager.new_pipeline_status())
            with manager.lock:
                manager.exit_status["global"]["applied"] = False
        self.assertEqual("probe", state["pipeline"]["stage"])
        self.assertEqual(7, state["pipeline"]["probe_total"])
        self.assertTrue(state["global_exit"]["applied"])
        self.assertIn("supported", state["singbox_exit"])
        self.assertEqual(24, state["check_interval_hours"])
        self.assertEqual(0, state["next_check_at"])
        self.assertEqual(manager.speedtest.DEFAULT_SETTINGS, state["speedtest_settings"])

        manager.set_state(next_check_at=123)
        persisted = json.loads(manager.STATE_FILE.read_text(encoding="utf-8"))
        self.assertEqual(123, persisted["next_check_at"])
        for key in manager.RUNTIME_STATE_KEYS:
            self.assertNotIn(key, persisted)
        self.assertEqual(123, manager.get_state()["next_check_at"])

    def _record_ip_commands(self, rc_for=None):
        """Return (patcher, calls) where calls collects subprocess.run argv lists."""
        calls: list[list[str]] = []
        rule_del_seen = {"count": 0}

        def fake_run(args, *a, **kw):
            argv = list(args)
            calls.append(argv)
            rc = 0
            if argv[:3] == ["ip", "rule", "del"]:
                rule_del_seen["count"] += 1
                rc = 0 if rule_del_seen["count"] % 2 == 1 else 2
            if rc_for is not None:
                rc = rc_for(argv, rc)
            if kw.get("check") and rc != 0:
                raise subprocess.CalledProcessError(rc, argv)
            return subprocess.CompletedProcess(argv, rc, stdout="", stderr="")

        return mock.patch.object(manager.subprocess, "run", side_effect=fake_run), calls

    def test_cleanup_policy_routing_only_removes_tun0_route_from_table_100(self) -> None:
        patcher, calls = self._record_ip_commands()
        with patcher:
            manager.cleanup_policy_routing("tun0", 100)
        joined = [" ".join(c) for c in calls]
        self.assertIn("ip rule del oif tun0 table 100", joined)
        self.assertIn("ip route del default dev tun0 table 100", joined)
        self.assertFalse(any("flush" in c for c in joined))
        self.assertFalse(any(c == "ip rule del table 100" for c in joined))

        patcher, calls = self._record_ip_commands()
        with patcher:
            manager.cleanup_policy_routing("tun5", 105)
        joined = [" ".join(c) for c in calls]
        self.assertIn("ip rule del oif tun5 table 105", joined)
        self.assertIn("ip route flush table 105", joined)

    def test_setup_policy_routing_uses_table_argument_and_fallback_hook(self) -> None:
        manager.update_ui_config(global_exit_enabled=True)
        patcher, calls = self._record_ip_commands()
        with patcher, mock.patch.object(manager.global_exit, "ensure_table_fallback") as fallback:
            self.assertTrue(manager.setup_policy_routing("tun5", 105))
            fallback.assert_not_called()
            calls.clear()
            self.assertTrue(manager.setup_policy_routing("tun0", 100))
            fallback.assert_called_once_with(manager.exit_runner)
        joined = [" ".join(c) for c in calls]
        self.assertIn("ip route replace default dev tun0 table 100", joined)
        self.assertIn("ip rule add oif tun0 table 100", joined)

        manager.update_ui_config(global_exit_enabled=False)
        patcher, calls = self._record_ip_commands()
        with patcher, mock.patch.object(manager.global_exit, "ensure_table_fallback") as fallback:
            self.assertTrue(manager.setup_policy_routing("tun0", 100))
            fallback.assert_not_called()

        def fail_route(argv, rc):
            return 2 if argv[:3] == ["ip", "route", "replace"] else rc

        patcher, calls = self._record_ip_commands(rc_for=fail_route)
        with patcher, mock.patch.object(manager.time, "sleep"):
            self.assertFalse(manager.setup_policy_routing("tun5", 105))

    def test_openvpn_command_includes_mark_on_linux(self) -> None:
        with (
            mock.patch.object(manager.global_exit, "openvpn_mark_args", return_value=["--mark", "26"]),
            mock.patch.object(manager, "get_openvpn_version", return_value=2.6),
        ):
            command = manager.openvpn_command("missing.ovpn", route_nopull=True, dev="tun7")
        self.assertIn("--mark", command)
        self.assertEqual("26", command[command.index("--mark") + 1])
        self.assertLess(command.index("--mark"), command.index("--verb"))
        self.assertEqual("tun7", command[command.index("--dev") + 1])
        self.assertEqual("--route-nopull", command[-1])

        with (
            mock.patch.object(manager.global_exit, "openvpn_mark_args", return_value=[]),
            mock.patch.object(manager, "get_openvpn_version", return_value=2.6),
        ):
            command = manager.openvpn_command("missing.ovpn", route_nopull=False)
        self.assertNotIn("--mark", command)

    def test_run_openvpn_report_state_false_does_not_touch_state(self) -> None:
        class FakePopen:
            def __init__(self, *args, **kwargs):
                self.stdout = iter(
                    [
                        "Mon PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0'\n",
                        "Mon TUN/TAP device tun5 opened\n",
                        "Mon Initialization Sequence Completed\n",
                    ]
                )
                self.running = True

            def poll(self):
                return None if self.running else 0

            def terminate(self):
                self.running = False

            def wait(self, timeout=None):
                self.running = False
                return 0

            def kill(self):
                self.running = False

        with (
            mock.patch.object(manager.subprocess, "Popen", FakePopen),
            mock.patch.object(manager, "openvpn_command", return_value=["openvpn"]),
            mock.patch.object(manager, "set_state") as set_state,
            mock.patch("sys.stdout", new_callable=lambda: __import__("io").StringIO()) as out,
        ):
            ok, message, process = manager.run_openvpn_until_ready(
                "x.ovpn", keep_alive=True, route_nopull=True, timeout=5, dev="tun5",
                report_state=False, log_prefix="[SpeedTest tun5]",
            )
        self.assertTrue(ok, message)
        self.assertIsNotNone(process)
        set_state.assert_not_called()
        self.assertIn("[SpeedTest tun5]", out.getvalue())
        self.assertNotIn("[OpenVPN]", out.getvalue())

        with (
            mock.patch.object(manager.subprocess, "Popen", FakePopen),
            mock.patch.object(manager, "openvpn_command", return_value=["openvpn"]),
            mock.patch.object(manager, "set_state") as set_state,
            mock.patch("sys.stdout", new_callable=lambda: __import__("io").StringIO()),
        ):
            ok, _message, _process = manager.run_openvpn_until_ready("x.ovpn", keep_alive=True, route_nopull=True, timeout=5)
        self.assertTrue(ok)
        self.assertTrue(set_state.called)

    def test_multiple_nodes_honours_cancel_event_and_progress(self) -> None:
        nodes = self.write_nodes(12)
        cancel = threading.Event()
        calls = []
        progress = []

        def fake_openvpn(config_file, **kwargs):
            calls.append(config_file)
            self.assertIs(cancel, kwargs.get("cancel_event"))
            cancel.set()
            return True, "ready", None

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 4),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=None,
                cancel_event=cancel,
                progress_cb=lambda done, total: progress.append((done, total)),
            )

        self.assertEqual(4, len(calls))
        self.assertEqual(4, len(results))
        self.assertEqual([(1, 12), (2, 12), (3, 12), (4, 12)], progress)

    def test_multiple_nodes_without_target_probes_everything(self) -> None:
        nodes = self.write_nodes(12)
        calls = []

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=lambda cf, **kw: (calls.append(cf) or (True, "ready", None))),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
        ):
            results = manager.test_multiple_nodes([node["id"] for node in nodes], target_available=None)
        self.assertEqual(12, len(calls))
        self.assertEqual(12, len(results))

    def test_stale_speedtest_routes_cleanup_parses_rules(self) -> None:
        rules = (
            "0:\tfrom all lookup local\n"
            "32765:\tfrom all oif tun0 lookup 100\n"
            "32764:\tfrom all oif tun5 lookup 105\n"
            "32763:\tfrom all oif tun7 lookup 107\n"
            "32762:\tfrom all oif tun9 lookup 250\n"
            "32766:\tfrom all lookup main\n"
        )

        def rc_for(argv, rc):
            return rc

        calls: list[list[str]] = []
        del_count = {"n": 0}

        def fake_run(args, *a, **kw):
            argv = list(args)
            calls.append(argv)
            if argv == ["ip", "rule", "show"]:
                return subprocess.CompletedProcess(argv, 0, stdout=rules, stderr="")
            if argv[:3] == ["ip", "rule", "del"]:
                del_count["n"] += 1
                return subprocess.CompletedProcess(argv, 0 if del_count["n"] % 2 else 2, stdout="", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch.object(manager.subprocess, "run", side_effect=fake_run):
            manager.cleanup_stale_speedtest_routes()
        joined = [" ".join(c) for c in calls]
        self.assertIn("ip rule del oif tun5 table 105", joined)
        self.assertIn("ip route flush table 105", joined)
        self.assertIn("ip rule del oif tun7 table 107", joined)
        self.assertIn("ip route flush table 107", joined)
        self.assertFalse(any("tun0" in c for c in joined))
        self.assertFalse(any("250" in c for c in joined))

    def test_dns_query_over_device_binds_requested_device(self) -> None:
        class FakeSock:
            def __init__(self, *args, **kwargs):
                self.options = []

            def settimeout(self, value):
                pass

            def setsockopt(self, level, option, value):
                self.options.append((level, option, value))

            def sendto(self, packet, address):
                raise OSError("stop here")

            def close(self):
                pass

        created = []

        def factory(*args, **kwargs):
            sock = FakeSock()
            created.append(sock)
            return sock

        with (
            mock.patch.object(proxy_server.socket, "socket", side_effect=factory),
            mock.patch.object(proxy_server.socket, "SO_BINDTODEVICE", 25, create=True),
        ):
            self.assertIsNone(proxy_server.dns_query_over_device("example.com", 1, "8.8.8.8", 1.0, dev="tun9"))
            self.assertIsNone(proxy_server.dns_query_over_tun0("example.com", 1, "8.8.8.8", 1.0))
            self.assertEqual("1.2.3.4", proxy_server.resolve_dns_over_device("1.2.3.4", "tun9"))
        self.assertEqual((proxy_server.socket.SOL_SOCKET, 25, b"tun9"), created[0].options[0])
        self.assertEqual((proxy_server.socket.SOL_SOCKET, 25, b"tun0"), created[1].options[0])

    # ---- v2.2.0 pipeline -------------------------------------------------

    def _pipeline_patches(self, openvpn_result=(True, "ready", None)):
        return [
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", return_value=openvpn_result),
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
        ]

    def test_pipeline_probes_all_nodes_without_target_limit(self) -> None:
        candidates = self.write_nodes(12)
        manager.update_ui_config(connection_enabled=False)
        patches = self._pipeline_patches()
        with mock.patch.object(manager, "fetch_candidates", return_value=candidates):
            started = [patcher.start() for patcher in patches]
            try:
                result = manager.run_pipeline("manual_update", with_speedtest=False)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        self.assertIn("检测 12 个", result)
        self.assertEqual(12, started[2].call_count)
        stored = manager.read_nodes()
        self.assertEqual(12, sum(node.get("probe_status") == "available" for node in stored))
        snapshot = manager.pipeline_snapshot()
        self.assertFalse(snapshot["running"])
        self.assertEqual("idle", snapshot["stage"])
        self.assertEqual("manual_update", snapshot["trigger"])
        self.assertEqual(12, snapshot["probe_total"])
        self.assertEqual(12, snapshot["probe_done"])
        self.assertEqual("", snapshot["stopped_reason"])
        self.assertGreater(manager.get_state()["next_check_at"], manager.time.time() + 3600)

    def test_pipeline_prunes_unavailable_nodes_missing_from_fetch(self) -> None:
        nodes = self.write_nodes(4)
        stale = dict(nodes[0], id="stale-node", probe_status="unavailable")
        keep = dict(nodes[1], id="known-node", probe_status="available", speed_mbps=3.5, speed_run_id="old", speed_tested_at=1.0, speed_message="x")
        manager.write_json(manager.NODES_FILE, [stale, keep] + nodes[2:])
        candidates = [dict(keep, probe_status="not_checked", speed_mbps=0)] + nodes[2:]
        manager.update_ui_config(connection_enabled=False)
        patches = self._pipeline_patches()
        with mock.patch.object(manager, "fetch_candidates", return_value=candidates):
            for patcher in patches:
                patcher.start()
            try:
                manager.run_pipeline("periodic", with_speedtest=False)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertNotIn("stale-node", stored)
        self.assertIn("known-node", stored)
        self.assertEqual(3.5, stored["known-node"]["speed_mbps"])
        self.assertEqual("old", stored["known-node"]["speed_run_id"])

    def test_pipeline_manual_update_never_speedtests(self) -> None:
        candidates = self.write_nodes(3)
        manager.update_ui_config(connection_enabled=False, speedtest={"auto_after_check": True, "auto_switch_fastest": True})
        patches = self._pipeline_patches()
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "run_speed_stage", return_value="") as speed_stage,
            mock.patch.object(manager, "maybe_switch_to_fastest") as switch,
        ):
            for patcher in patches:
                patcher.start()
            try:
                manager.run_pipeline("manual_update", with_speedtest=False)
                manager.run_pipeline("forced", with_speedtest=False)
                manager.maintain_valid_nodes(force=False)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        speed_stage.assert_not_called()
        switch.assert_not_called()

    def test_pipeline_speedtest_trigger_runs_speed_stage(self) -> None:
        candidates = self.write_nodes(3)
        manager.update_ui_config(connection_enabled=False, speedtest={"retest_after_hours": 0, "auto_switch_fastest": True})
        speeds = {"node-0": 1.5, "node-1": 4.0, "node-2": 2.0}

        def fake_measure(node, settings, run_id):
            return {
                "id": node["id"],
                "speed_mbps": speeds[node["id"]],
                "speed_tested_at": 123.0,
                "speed_message": "ok",
                "speed_run_id": run_id,
                "probe_status": "available",
            }

        patches = self._pipeline_patches()
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "measure_node_speed", side_effect=fake_measure) as measure,
            mock.patch.object(manager, "maybe_switch_to_fastest", return_value=False) as switch,
        ):
            for patcher in patches:
                patcher.start()
            try:
                result = manager.run_pipeline("manual_speedtest", with_speedtest=True)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        self.assertIn("测速 3/3 个", result)
        self.assertEqual(3, measure.call_count)
        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertEqual(4.0, stored["node-1"]["speed_mbps"])
        run_id = stored["node-1"]["speed_run_id"]
        switch.assert_called_once()
        self.assertEqual(run_id, switch.call_args.args[0])
        snapshot = manager.pipeline_snapshot()
        self.assertEqual(3, snapshot["speed_done"])
        self.assertEqual("node-1", snapshot["best_node_id"])
        self.assertEqual(4.0, snapshot["best_speed_mbps"])
        self.assertTrue(snapshot["with_speedtest"])

    def test_pipeline_returns_busy_when_locked(self) -> None:
        self.assertTrue(manager.maintenance_lock.acquire(blocking=False))
        try:
            with mock.patch.object(manager, "fetch_candidates") as fetch:
                result = manager.run_pipeline("manual_speedtest", with_speedtest=True)
        finally:
            manager.maintenance_lock.release()
        self.assertEqual("任务进行中，请稍后再试", result)
        fetch.assert_not_called()

    def test_speed_stage_stops_at_threshold(self) -> None:
        self.write_nodes(3)
        candidates = [{"id": "node-0", "config_text": ""}, {"id": "node-1", "config_text": ""}, {"id": "node-2", "config_text": ""}]
        speeds = iter([1.0, 5.0, 9.0])

        def fake_measure(node, settings, run_id):
            return {"id": node["id"], "speed_mbps": next(speeds), "speed_tested_at": 1.0, "speed_message": "", "speed_run_id": run_id}

        manager.pipeline_cancel_event.clear()
        with mock.patch.object(manager, "measure_node_speed", side_effect=fake_measure) as measure, mock.patch.object(manager, "log_to_json"):
            reason = manager.run_speed_stage(candidates, {"stop_threshold_mbps": 4}, "run-x")
        self.assertEqual("threshold", reason)
        self.assertEqual(2, measure.call_count)
        snapshot = manager.pipeline_snapshot()
        self.assertEqual("threshold", snapshot["stopped_reason"])
        self.assertEqual(2, snapshot["speed_done"])
        self.assertEqual("node-1", snapshot["best_node_id"])
        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertEqual(5.0, stored["node-1"]["speed_mbps"])
        self.assertNotIn("speed_mbps", stored["node-2"])

    # ---- 测速历史写入钩子（spec 5.1） ----

    def test_speed_stage_appends_history_for_each_node(self) -> None:
        candidates = self.write_nodes(3)

        def fake_measure(node, settings, run_id):
            return {"id": node["id"], "speed_mbps": 3.5, "speed_tested_at": 1700000000.0,
                    "speed_message": "ok", "speed_run_id": run_id}

        manager.pipeline_cancel_event.clear()
        with mock.patch.object(manager, "measure_node_speed", side_effect=fake_measure), \
                mock.patch.object(manager, "log_to_json"):
            reason = manager.run_speed_stage(candidates, {"stop_threshold_mbps": 0}, "run-hist")

        self.assertEqual("", reason)
        history = manager.read_speed_history()
        self.assertEqual(3, len(history))
        for node in candidates:
            records = history[node["id"]]
            self.assertEqual(1, len(records))
            self.assertEqual(1700000000, records[0]["t"])
            self.assertEqual(3.5, records[0]["mbps"])
            self.assertEqual("ok", records[0]["msg"])
            self.assertEqual("run-hist", records[0]["run_id"])

    def test_speed_stage_survives_history_write_failure(self) -> None:
        candidates = self.write_nodes(3)

        def fake_measure(node, settings, run_id):
            return {"id": node["id"], "speed_mbps": 2.0, "speed_tested_at": 1700000000.0,
                    "speed_message": "", "speed_run_id": run_id}

        manager.pipeline_cancel_event.clear()
        with mock.patch.object(manager, "measure_node_speed", side_effect=fake_measure), \
                mock.patch.object(manager, "append_speed_history", side_effect=OSError("disk full")), \
                mock.patch.object(manager, "log_to_json"):
            reason = manager.run_speed_stage(candidates, {"stop_threshold_mbps": 0}, "run-broken")

        # 测速不中断：3 个节点全部测完，nodes.json 正常写回
        self.assertEqual("", reason)
        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertEqual(3, sum(1 for n in stored.values() if n.get("speed_mbps") == 2.0))
        self.assertEqual({}, manager.read_speed_history())

    def test_speed_stage_cancel_keeps_results_and_skips_switch(self) -> None:
        candidates = self.write_nodes(3)
        manager.update_ui_config(connection_enabled=False, speedtest={"retest_after_hours": 0, "auto_switch_fastest": True})

        def fake_measure(node, settings, run_id):
            manager.pipeline_cancel_event.set()
            return {"id": node["id"], "speed_mbps": 7.0, "speed_tested_at": 1.0, "speed_message": "ok", "speed_run_id": run_id}

        patches = self._pipeline_patches()
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "measure_node_speed", side_effect=fake_measure) as measure,
            mock.patch.object(manager, "maybe_switch_to_fastest") as switch,
        ):
            for patcher in patches:
                patcher.start()
            try:
                manager.run_pipeline("manual_speedtest", with_speedtest=True)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        self.assertEqual(1, measure.call_count)
        switch.assert_not_called()
        snapshot = manager.pipeline_snapshot()
        self.assertEqual("manual", snapshot["stopped_reason"])
        self.assertFalse(snapshot["running"])
        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertEqual(1, sum(1 for n in stored.values() if n.get("speed_mbps") == 7.0))
        self.assertFalse(manager.pipeline_cancel_event.is_set() and manager.maintenance_lock.locked())

    def test_measure_node_speed_marks_unreachable_node_unavailable(self) -> None:
        manager.pipeline_cancel_event.clear()
        node = {"id": "node-x", "config_text": "client\n"}
        with (
            mock.patch.object(manager, "run_openvpn_until_ready", return_value=(False, "[错误代码 2101] timeout", None)) as openvpn,
            mock.patch.object(manager, "setup_policy_routing") as routing,
            mock.patch.object(manager.speedtest, "measure_download") as download,
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.measure_node_speed(node, manager.speedtest.DEFAULT_SETTINGS, "run-1")
        self.assertEqual("unavailable", result["probe_status"])
        self.assertEqual("[错误代码 2101] timeout", result["speed_message"])
        self.assertEqual(0.0, result["speed_mbps"])
        self.assertEqual("run-1", result["speed_run_id"])
        routing.assert_not_called()
        download.assert_not_called()
        kwargs = openvpn.call_args.kwargs
        self.assertFalse(kwargs["report_state"])
        self.assertTrue(kwargs["keep_alive"])
        self.assertTrue(kwargs["route_nopull"])
        self.assertEqual("tun2", kwargs["dev"])
        self.assertIn("[SpeedTest tun2]", kwargs["log_prefix"])
        self.assertEqual(set(), manager.active_test_indexes)
        self.assertEqual([], list(manager.CONFIG_DIR.glob(".test_*")))

        # A cancelled connection attempt must not mark the node unavailable.
        manager.pipeline_cancel_event.set()
        try:
            with (
                mock.patch.object(manager, "run_openvpn_until_ready", return_value=(False, "连接操作已取消", None)),
                mock.patch.object(manager, "log_to_json"),
            ):
                result = manager.measure_node_speed(node, manager.speedtest.DEFAULT_SETTINGS, "run-1")
        finally:
            manager.pipeline_cancel_event.clear()
        self.assertNotIn("probe_status", result)

    def test_measure_node_speed_cleans_up_on_failure(self) -> None:
        manager.pipeline_cancel_event.clear()
        process = FakeProcess()
        node = {"id": "node-y", "config_text": "client\n"}
        with (
            mock.patch.object(manager, "run_openvpn_until_ready", return_value=(True, "ok", process)),
            mock.patch.object(manager, "setup_policy_routing", return_value=True) as setup,
            mock.patch.object(manager, "cleanup_policy_routing") as cleanup,
            mock.patch.object(manager.speedtest, "measure_download", side_effect=RuntimeError("boom")),
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.measure_node_speed(node, {"per_node_max_mb": 5, "per_node_seconds": 4}, "run-2")
        self.assertEqual("boom", result["speed_message"])
        self.assertEqual("available", result["probe_status"])
        setup.assert_called_once_with("tun2", 102)
        cleanup.assert_called_once_with("tun2", 102)
        self.assertTrue(process.terminated)
        self.assertEqual(set(), manager.active_test_indexes)
        self.assertEqual([], list(manager.CONFIG_DIR.glob(".test_*")))

        # Successful measurement fills the speed fields and the URL carries the byte limit.
        process = FakeProcess()
        measured = manager.speedtest.MeasureResult(bytes=5_000_000, seconds=2.0, mbps=2.5)
        with (
            mock.patch.object(manager, "run_openvpn_until_ready", return_value=(True, "ok", process)),
            mock.patch.object(manager, "setup_policy_routing", return_value=True),
            mock.patch.object(manager, "cleanup_policy_routing"),
            mock.patch.object(manager.speedtest, "measure_download", return_value=measured) as download,
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.measure_node_speed(node, {"per_node_max_mb": 5, "per_node_seconds": 4, "url": "http://x/{bytes}"}, "run-3")
        self.assertEqual(2.5, result["speed_mbps"])
        self.assertEqual("5.0 MB / 2.0 s", result["speed_message"])
        self.assertEqual("http://x/5000000", download.call_args.args[0])
        self.assertEqual("tun2", download.call_args.args[1])
        self.assertEqual(4, download.call_args.args[2])
        self.assertEqual(5_000_000, download.call_args.args[3])
        self.assertTrue(process.terminated)

    def test_measure_node_speed_active_node_uses_tun0(self) -> None:
        manager.pipeline_cancel_event.clear()
        manager.active_openvpn_process = FakeProcess()
        manager.active_openvpn_node_id = "active-node"
        measured = manager.speedtest.MeasureResult(bytes=1_000_000, seconds=1.0, mbps=1.0)
        with (
            mock.patch.object(manager, "run_openvpn_until_ready") as openvpn,
            mock.patch.object(manager, "setup_policy_routing") as setup,
            mock.patch.object(manager.speedtest, "measure_download", return_value=measured) as download,
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.measure_node_speed({"id": "active-node", "config_text": ""}, manager.speedtest.DEFAULT_SETTINGS, "run-4")
        openvpn.assert_not_called()
        setup.assert_not_called()
        self.assertEqual("tun0", download.call_args.args[1])
        self.assertEqual(1.0, result["speed_mbps"])
        self.assertNotIn("probe_status", result)

    def _speed_nodes(self):
        nodes = self.write_nodes(4)
        for index, node in enumerate(nodes):
            node["probe_status"] = "available"
            node["country_short"] = "JP" if index < 3 else "US"
            node["speed_run_id"] = "run-9"
        nodes[0]["speed_mbps"] = 10.0
        nodes[0]["active"] = True
        nodes[1]["speed_mbps"] = 11.0
        nodes[2]["speed_mbps"] = 13.0
        nodes[3]["speed_mbps"] = 50.0
        manager.write_json(manager.NODES_FILE, nodes)
        return nodes

    def test_switch_to_fastest_respects_margin_fixed_ip_and_routing(self) -> None:
        self._speed_nodes()
        manager.active_openvpn_process = FakeProcess()
        manager.active_openvpn_node_id = "node-0"
        settings = {"auto_switch_fastest": True, "switch_margin_percent": 20}
        manager.update_ui_config(routing_mode="fixed_region", force_country="JP")

        with mock.patch.object(manager, "connect_node") as connect, mock.patch.object(manager, "log_to_json"):
            self.assertTrue(manager.maybe_switch_to_fastest("run-9", settings))
        connect.assert_called_once_with("node-2")  # node-3 is US and filtered out; 13 > 10 * 1.2

        with mock.patch.object(manager, "connect_node") as connect, mock.patch.object(manager, "log_to_json"):
            self.assertFalse(manager.maybe_switch_to_fastest("run-9", dict(settings, switch_margin_percent=40)))
        connect.assert_not_called()

        with mock.patch.object(manager, "connect_node") as connect, mock.patch.object(manager, "log_to_json"):
            self.assertFalse(manager.maybe_switch_to_fastest("run-9", dict(settings, auto_switch_fastest=False)))
            manager.update_ui_config(routing_mode="fixed_ip")
            self.assertFalse(manager.maybe_switch_to_fastest("run-9", settings))
            manager.update_ui_config(routing_mode="auto", connection_enabled=False)
            self.assertFalse(manager.maybe_switch_to_fastest("run-9", settings))
        connect.assert_not_called()

        # Records from another run are ignored; the current node being fastest ends the check.
        manager.update_ui_config(connection_enabled=True)
        with mock.patch.object(manager, "connect_node") as connect, mock.patch.object(manager, "log_to_json"):
            self.assertFalse(manager.maybe_switch_to_fastest("other-run", settings))
        connect.assert_not_called()

        # Unknown current speed: the fastest candidate wins outright.
        manager.active_openvpn_node_id = "node-unknown"
        manager.update_ui_config(routing_mode="auto", force_country="")
        with mock.patch.object(manager, "connect_node") as connect, mock.patch.object(manager, "log_to_json"):
            self.assertTrue(manager.maybe_switch_to_fastest("run-9", settings))
        connect.assert_called_once_with("node-3")

    def test_switch_to_fastest_tries_next_on_failure(self) -> None:
        self._speed_nodes()
        manager.active_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.update_ui_config(routing_mode="auto", force_country="")
        attempts = []

        def fake_connect(node_id):
            attempts.append(node_id)
            if len(attempts) < 3:
                raise RuntimeError("fail")
            return "ok"

        with mock.patch.object(manager, "connect_node", side_effect=fake_connect), mock.patch.object(manager, "log_to_json"):
            self.assertTrue(manager.maybe_switch_to_fastest("run-9", {"auto_switch_fastest": True}))
        self.assertEqual(["node-3", "node-2", "node-1"], attempts)

        with mock.patch.object(manager, "connect_node", side_effect=RuntimeError("fail")) as connect, mock.patch.object(manager, "log_to_json"):
            self.assertFalse(manager.maybe_switch_to_fastest("run-9", {"auto_switch_fastest": True}))
        self.assertEqual(3, connect.call_count)

    def test_auto_switch_prefers_measured_speed_when_enabled(self) -> None:
        nodes = self.write_nodes(3)
        for node in nodes:
            node["probe_status"] = "available"
        nodes[0]["latency_ms"] = 10
        nodes[1]["latency_ms"] = 50
        nodes[1]["speed_mbps"] = 8.0
        nodes[2]["latency_ms"] = 30
        nodes[2]["speed_mbps"] = 3.0
        manager.write_json(manager.NODES_FILE, nodes)
        manager.update_ui_config(routing_mode="auto", connection_enabled=True, speedtest={"auto_switch_fastest": True})
        with mock.patch.object(manager, "connect_node") as connect, mock.patch.object(manager, "log_to_json"):
            manager.auto_switch_node()
        connect.assert_called_once_with("node-1")

        manager.update_ui_config(speedtest={"auto_switch_fastest": False})
        with mock.patch.object(manager, "connect_node") as connect, mock.patch.object(manager, "log_to_json"):
            manager.auto_switch_node()
        connect.assert_called_once_with("node-0")

    def test_schedule_next_check_uses_interval_and_wakes_collector(self) -> None:
        manager.update_ui_config(check_interval_hours=2)
        manager.collector_wakeup.clear()
        next_at = manager.schedule_next_check(1000.0)
        self.assertEqual(1000.0 + 7200, next_at)
        self.assertEqual(next_at, manager.get_state()["next_check_at"])
        self.assertTrue(manager.collector_wakeup.is_set())
        manager.collector_wakeup.clear()

        manager.last_pipeline_end = 500.0
        self.assertEqual(500.0 + 7200, manager.reschedule_after_interval_change())
        manager.last_pipeline_end = 0.0
        with mock.patch.object(manager.time, "time", return_value=42.0):
            self.assertEqual(42.0 + 7200, manager.reschedule_after_interval_change())
        manager.collector_wakeup.clear()

    def test_interval_change_reschedules_from_last_end_without_running(self) -> None:
        manager.update_ui_config(check_interval_hours=2)
        manager.last_pipeline_end = 1000.0
        manager.schedule_next_check(1000.0)
        clock = {"now": 1500.0}
        waits = []

        def fake_wait(timeout=None):
            waits.append(timeout)
            if len(waits) == 1:
                # A settings change shrinks the interval to one hour: still not due.
                manager.update_ui_config(check_interval_hours=1)
                manager.reschedule_after_interval_change()
                clock["now"] = 2000.0
                return True
            if len(waits) == 2:
                clock["now"] = 1000.0 + 3600 + 1
                return False
            raise AssertionError("waited too often")

        with (
            mock.patch.object(manager.time, "time", side_effect=lambda: clock["now"]),
            mock.patch.object(manager.collector_wakeup, "wait", side_effect=fake_wait),
        ):
            manager.wait_for_next_check()

        self.assertEqual(2, len(waits))
        self.assertEqual(3600, waits[0])  # min(remaining 6700, 3600)
        self.assertAlmostEqual(1000.0 + 3600 - 2000.0, waits[1])
        self.assertEqual(1000.0 + 3600, manager.get_state()["next_check_at"])

    def test_collector_loop_runs_pipeline_with_auto_speedtest_setting(self) -> None:
        manager.update_ui_config(speedtest={"auto_after_check": True})
        calls = []

        def fake_pipeline(trigger, with_speedtest):
            calls.append((trigger, with_speedtest))
            return "Fetched 3 nodes."

        with (
            mock.patch.object(manager, "run_pipeline", side_effect=fake_pipeline),
            mock.patch.object(manager, "wait_for_next_check", side_effect=KeyboardInterrupt),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaises(KeyboardInterrupt):
                manager.collector_loop()
        self.assertEqual([("periodic", True)], calls)

        manager.update_ui_config(speedtest={"auto_after_check": False})
        manager.active_openvpn_process = None
        with (
            mock.patch.object(manager, "run_pipeline", return_value="没有拉取到新节点"),
            mock.patch.object(manager, "wait_for_next_check", side_effect=KeyboardInterrupt),
            mock.patch.object(manager, "schedule_next_check") as schedule,
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager.time, "time", return_value=10000.0),
        ):
            with self.assertRaises(KeyboardInterrupt):
                manager.collector_loop()
        schedule.assert_called_once_with(10000.0 - manager.check_interval_seconds() + 30)

    # ---- v2.2.0 exit switches --------------------------------------------

    def _exit_patches(self):
        fake_singbox_status = lambda enabled, mode, runner, last_error="", verified=None: {
            "supported": True, "unsupported_reason": "", "enabled": enabled, "applied": enabled,
            "service_active": True, "last_error": last_error, "config_path": "/x", "verified": verified,
        }
        fake_global_status = lambda enabled, mode, runner, last_error="": {
            "supported": True, "unsupported_reason": "", "enabled": enabled, "applied": enabled,
            "last_error": last_error, "physical_interface": "eth0", "physical_ips": ["203.0.113.10"],
            "ssh_ports": [22], "gateway": "203.0.113.1",
        }
        return [
            mock.patch.object(manager.singbox_exit, "is_supported", return_value=(True, "")),
            mock.patch.object(manager.global_exit, "is_supported", return_value=(True, "")),
            mock.patch.object(manager.singbox_exit, "status_snapshot", side_effect=fake_singbox_status),
            mock.patch.object(manager.global_exit, "status_snapshot", side_effect=fake_global_status),
            mock.patch.object(manager.singbox_exit, "verify_via_clash_api", return_value={"total": 2, "via_tunnel": 2, "checked_at": 1.0}),
            mock.patch.object(manager.global_exit, "detect_context", return_value=manager.global_exit.Context(interface="eth0")),
            mock.patch.object(manager, "log_to_json"),
        ]

    def test_set_global_exit_disables_singbox_and_reenables_on_off(self) -> None:
        patches = self._exit_patches()
        for patcher in patches:
            patcher.start()
        try:
            with (
                mock.patch.object(manager.singbox_exit, "enable", return_value={"applied": True}) as sb_enable,
                mock.patch.object(manager.singbox_exit, "disable", return_value={"applied": False}) as sb_disable,
                mock.patch.object(manager.global_exit, "enable", return_value={"applied": True}) as g_enable,
                mock.patch.object(manager.global_exit, "disable", return_value={"applied": False}) as g_disable,
            ):
                result = manager.set_global_exit(True)
                sb_disable.assert_called_once_with(manager.exit_runner)
                g_enable.assert_called_once()
                self.assertEqual("eth0", g_enable.call_args.args[0].interface)
                cfg = manager.load_ui_config()
                self.assertTrue(cfg["global_exit_enabled"])
                self.assertFalse(cfg["singbox_exit_enabled"])
                self.assertTrue(result["global"]["applied"])
                self.assertFalse(result["singbox"]["enabled"])
                self.assertTrue(manager.get_state()["global_exit"]["applied"])

                with self.assertRaises(RuntimeError):
                    manager.set_singbox_exit(True)
                sb_enable.assert_not_called()

                result = manager.set_global_exit(False)
                g_disable.assert_called_once_with(manager.exit_runner)
                sb_enable.assert_called_once_with(manager.exit_runner)
                cfg = manager.load_ui_config()
                self.assertFalse(cfg["global_exit_enabled"])
                self.assertTrue(cfg["singbox_exit_enabled"])
                self.assertFalse(result["global"]["enabled"])
                self.assertEqual(2, result["singbox"]["verified"]["via_tunnel"])
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    def test_set_global_exit_rollback_on_failure(self) -> None:
        patches = self._exit_patches()
        for patcher in patches:
            patcher.start()
        try:
            with (
                mock.patch.object(manager.singbox_exit, "enable", return_value={"applied": True}) as sb_enable,
                mock.patch.object(manager.singbox_exit, "disable", return_value={"applied": False}) as sb_disable,
                mock.patch.object(manager.global_exit, "enable", side_effect=RuntimeError("添加规则 pref 30020 失败")),
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    manager.set_global_exit(True)
            self.assertIn("30020", str(ctx.exception))
            sb_disable.assert_called_once()
            sb_enable.assert_called_once()
            cfg = manager.load_ui_config()
            self.assertFalse(cfg["global_exit_enabled"])
            self.assertTrue(cfg["singbox_exit_enabled"])
            self.assertIn("30020", manager.get_state()["global_exit"]["last_error"])

            # Unsupported platforms refuse to enable and keep the setting off.
            with mock.patch.object(manager.global_exit, "is_supported", return_value=(False, "仅支持 Linux")):
                with self.assertRaises(RuntimeError):
                    manager.set_global_exit(True)
            self.assertFalse(manager.load_ui_config()["global_exit_enabled"])
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    def test_set_singbox_exit_records_error_and_unsupported_only_saves(self) -> None:
        patches = self._exit_patches()
        for patcher in patches:
            patcher.start()
        try:
            with mock.patch.object(manager.singbox_exit, "enable", side_effect=RuntimeError("sing-box check 未通过：bad")):
                with self.assertRaises(RuntimeError):
                    manager.set_singbox_exit(True)
            self.assertIn("check", manager.get_state()["singbox_exit"]["last_error"])
            with mock.patch.object(manager.singbox_exit, "is_supported", return_value=(False, "Docker")):
                with mock.patch.object(manager.singbox_exit, "disable") as sb_disable:
                    status = manager.set_singbox_exit(False)
            sb_disable.assert_not_called()
            self.assertFalse(manager.load_ui_config()["singbox_exit_enabled"])
            self.assertFalse(status["enabled"])
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    def test_disconnect_turns_off_global_exit(self) -> None:
        manager.update_ui_config(global_exit_enabled=True, connection_enabled=True)
        with (
            mock.patch.object(manager, "set_global_exit") as set_global,
            mock.patch.object(manager, "clear_active_connection_state") as clear_state,
            mock.patch.object(manager, "log_to_json"),
        ):
            manager.handle_disconnect_request()
        set_global.assert_called_once_with(False)
        clear_state.assert_called_once_with("手动断开连接")
        self.assertFalse(manager.load_ui_config()["connection_enabled"])

        manager.update_ui_config(global_exit_enabled=False, connection_enabled=True)
        with (
            mock.patch.object(manager, "set_global_exit") as set_global,
            mock.patch.object(manager, "clear_active_connection_state"),
        ):
            manager.handle_disconnect_request()
        set_global.assert_not_called()

    def test_cli_flags_dispatch_and_exit_codes(self) -> None:
        with (
            mock.patch.object(manager, "set_global_exit", return_value={"global": {"applied": False}}) as set_global,
            mock.patch.object(manager, "set_singbox_exit", return_value={"applied": True}) as set_singbox,
            mock.patch("sys.stdout", new_callable=lambda: __import__("io").StringIO()) as out,
        ):
            self.assertEqual(0, manager.run_cli(["--global-exit", "off"]))
            set_global.assert_called_once_with(False)
            self.assertEqual(0, manager.run_cli(["--singbox-exit", "on"]))
            set_singbox.assert_called_once_with(True)
            self.assertEqual(1, manager.run_cli(["--global-exit", "maybe"]))
            self.assertEqual(1, manager.run_cli(["--bogus"]))
            self.assertEqual(1, manager.run_cli([]))
        self.assertIn('"ok": true', out.getvalue())
        self.assertIn("用法", out.getvalue())

        with (
            mock.patch.object(manager, "set_global_exit", side_effect=RuntimeError("boom")),
            mock.patch("sys.stdout", new_callable=lambda: __import__("io").StringIO()) as out,
        ):
            self.assertEqual(1, manager.run_cli(["--global-exit", "on"]))
        self.assertIn("boom", out.getvalue())

    def test_startup_applies_exit_settings(self) -> None:
        manager.update_ui_config(global_exit_enabled=True, singbox_exit_enabled=True, port=8123)
        patches = self._exit_patches()
        for patcher in patches:
            patcher.start()
        try:
            with (
                mock.patch.object(manager.global_exit, "reconcile", return_value=None) as g_reconcile,
                mock.patch.object(manager.singbox_exit, "reconcile", return_value=None) as sb_reconcile,
            ):
                manager.apply_exit_settings_on_startup()
            g_reconcile.assert_called_once_with(True, 8123, manager.exit_runner)
            sb_reconcile.assert_called_once_with(False, manager.exit_runner)
            self.assertFalse(manager.load_ui_config()["singbox_exit_enabled"])
            self.assertTrue(manager.get_state()["global_exit"]["enabled"])

            manager.update_ui_config(global_exit_enabled=False, singbox_exit_enabled=True)
            with (
                mock.patch.object(manager.global_exit, "reconcile", side_effect=RuntimeError("rules broken")),
                mock.patch.object(manager.singbox_exit, "reconcile", return_value={"applied": True}) as sb_reconcile,
            ):
                manager.reconcile_exits_once()
            sb_reconcile.assert_called_once_with(True, manager.exit_runner)
            self.assertEqual("rules broken", manager.get_state()["global_exit"]["last_error"])
            self.assertEqual("", manager.get_state()["singbox_exit"]["last_error"])
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    def test_teardown_for_restart_disables_applied_rules(self) -> None:
        with (
            mock.patch.object(manager.global_exit, "is_supported", return_value=(True, "")),
            mock.patch.object(manager.global_exit, "is_applied", return_value=True),
            mock.patch.object(manager.global_exit, "disable") as disable,
        ):
            manager.global_exit_teardown_for_restart()
        disable.assert_called_once_with(manager.exit_runner)
        with (
            mock.patch.object(manager.global_exit, "is_supported", return_value=(True, "")),
            mock.patch.object(manager.global_exit, "is_applied", return_value=False),
            mock.patch.object(manager.global_exit, "disable") as disable,
        ):
            manager.global_exit_teardown_for_restart()
        disable.assert_not_called()

    def _post(self, path: str, payload: dict | None = None) -> tuple[int, dict]:
        """Drive Handler.do_POST without sockets; returns (status, body)."""
        handler = manager.Handler.__new__(manager.Handler)
        captured: list[tuple[int, dict]] = []

        def fake_send_json(data, status=manager.HTTPStatus.OK):
            captured.append((int(status), data))

        handler.send_json = fake_send_json
        handler.read_json_body = lambda max_bytes=65536: dict(payload or {})
        handler.read_request_body = lambda max_bytes=65536: b""
        handler.validate_path = lambda: path
        handler.is_authorized = lambda: True
        handler.do_POST()
        self.assertEqual(1, len(captured), f"expected one response for {path}, got {captured}")
        return captured[0]

    def _get_gateway_status(self) -> dict:
        handler = manager.Handler.__new__(manager.Handler)
        captured: list = []
        handler.send_json = lambda data, status=manager.HTTPStatus.OK: captured.append(data)
        handler.validate_path = lambda: "/api/gateway_status"
        handler.is_authorized = lambda: True
        with mock.patch.object(manager.vpn_utils, "diagnose_local_obstructions", return_value=None):
            handler.do_GET()
        self.assertEqual(1, len(captured))
        return captured[0]

    def test_api_speedtest_settings_roundtrip(self) -> None:
        status, body = self._post("/api/speedtest/settings", {
            "status": "all", "countries": ["jp", "US"], "per_node_seconds": 5,
            "per_node_max_mb": 10, "stop_threshold_mbps": 4.5, "auto_switch_fastest": True,
        })
        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual("all", body["settings"]["status"])
        self.assertEqual(["JP", "US"], body["settings"]["countries"])
        self.assertEqual(5, body["settings"]["per_node_seconds"])
        self.assertTrue(body["settings"]["auto_switch_fastest"])
        self.assertEqual(body["settings"], manager.load_ui_config()["speedtest"])
        self.assertEqual(body["settings"], manager.get_state()["speedtest_settings"])
        # nested "speedtest" object is accepted as well
        status, body = self._post("/api/speedtest/settings", {"speedtest": {"per_node_seconds": 3}})
        self.assertEqual(200, status)
        self.assertEqual(3, manager.load_ui_config()["speedtest"]["per_node_seconds"])

    def test_api_speedtest_estimate_uses_saved_or_payload_settings(self) -> None:
        nodes = self.write_nodes(3)
        for node in nodes:
            node["probe_status"] = "available"
        manager.write_json(manager.NODES_FILE, nodes)
        manager.update_ui_config(speedtest=manager.speedtest.normalize_settings({"per_node_seconds": 4, "per_node_max_mb": 10}))
        status, body = self._post("/api/speedtest/estimate", {})
        self.assertEqual(200, status)
        self.assertEqual(3, body["count"])
        self.assertEqual(30, body["max_mb"])
        self.assertEqual(3 * (4 + 16), body["est_seconds"])
        status, body = self._post("/api/speedtest/estimate", {"per_node_seconds": 4, "per_node_max_mb": 10, "status": "unavailable"})
        self.assertEqual(200, status)
        self.assertEqual(0, body["count"])

    def test_api_pipeline_speedtest_conflicts_when_running(self) -> None:
        with mock.patch.object(manager.threading, "Thread") as thread_cls:
            status, body = self._post("/api/pipeline/speedtest")
            self.assertEqual(200, status)
            self.assertTrue(body["running"])
            thread_cls.assert_called_once()
            self.assertEqual(("manual_speedtest", True), thread_cls.call_args.kwargs["args"])
            self.assertIs(manager.run_pipeline, thread_cls.call_args.kwargs["target"])
        manager.pipeline_set(running=True)
        try:
            with mock.patch.object(manager.threading, "Thread") as thread_cls:
                status, body = self._post("/api/pipeline/speedtest")
                self.assertEqual(409, status)
                self.assertFalse(body["ok"])
                thread_cls.assert_not_called()
            status, body = self._post("/api/test_node", {"id": "node-1"})
            self.assertEqual(409, status)
            self.assertIn("任务进行中", body["error"])
            status, body = self._post("/api/test_nodes", {"ids": ["node-1"]})
            self.assertEqual(409, status)
            self.assertIn("任务进行中", body["error"])
            manager.pipeline_cancel_event.clear()
            status, body = self._post("/api/pipeline/stop")
            self.assertEqual(200, status)
            self.assertTrue(manager.pipeline_cancel_event.is_set())
            self.assertTrue(manager.pipeline_snapshot()["stop_requested"])
        finally:
            manager.pipeline_cancel_event.clear()
            manager.pipeline_set(**manager.new_pipeline_status())

    def test_api_refresh_nodes_starts_manual_update_pipeline(self) -> None:
        with mock.patch.object(manager.threading, "Thread") as thread_cls:
            status, body = self._post("/api/refresh_nodes", {})
        self.assertEqual(200, status)
        self.assertTrue(body["running"])
        self.assertIs(manager.run_pipeline, thread_cls.call_args.kwargs["target"])
        self.assertEqual(("manual_update", False), thread_cls.call_args.kwargs["args"])

    def test_api_update_settings_validates_interval(self) -> None:
        base = {"proxy_port": 7928, "routing_mode": "auto", "routing_ip_type": "all"}
        for bad in (0, 73, "abc", 1.5, True):
            status, body = self._post("/api/update_settings", {**base, "check_interval_hours": bad})
            self.assertEqual(400, status, f"value {bad!r} should be rejected")
            self.assertIn("1 至 72", body["error"])
        self.assertEqual(24, manager.load_ui_config()["check_interval_hours"])
        with mock.patch.object(manager, "reschedule_after_interval_change") as resched:
            status, body = self._post("/api/update_settings", {**base, "check_interval_hours": "6"})
            self.assertEqual(200, status, body)
            resched.assert_called_once()
            self.assertEqual(6, manager.load_ui_config()["check_interval_hours"])
            # unchanged value does not reschedule again
            status, _ = self._post("/api/update_settings", {**base, "check_interval_hours": 6})
            self.assertEqual(200, status)
            resched.assert_called_once()
            # omitted field keeps the saved interval
            status, _ = self._post("/api/update_settings", base)
            self.assertEqual(200, status)
            self.assertEqual(6, manager.load_ui_config()["check_interval_hours"])

    def test_api_exit_switches_validate_and_apply(self) -> None:
        status, body = self._post("/api/singbox_exit", {"enabled": "yes"})
        self.assertEqual(400, status)
        status, body = self._post("/api/global_exit", {})
        self.assertEqual(400, status)
        patches = self._exit_patches()
        for patcher in patches:
            patcher.start()
        try:
            with (
                mock.patch.object(manager.singbox_exit, "enable"),
                mock.patch.object(manager.singbox_exit, "disable"),
                mock.patch.object(manager.global_exit, "enable"),
                mock.patch.object(manager.global_exit, "disable"),
            ):
                status, body = self._post("/api/global_exit", {"enabled": True})
                self.assertEqual(200, status, body)
                self.assertTrue(body["status"]["applied"])
                self.assertFalse(body["singbox_exit"]["enabled"])
                status, body = self._post("/api/singbox_exit", {"enabled": True})
                self.assertEqual(500, status)
                self.assertIn("全局出口", body["error"])
                status, body = self._post("/api/global_exit", {"enabled": False})
                self.assertEqual(200, status, body)
                self.assertFalse(body["status"]["enabled"])
                self.assertTrue(body["singbox_exit"]["applied"])
                status, body = self._post("/api/singbox_exit/verify")
                self.assertEqual(200, status)
                self.assertEqual(2, body["verified"]["via_tunnel"])
                self.assertEqual(2, manager.get_state()["singbox_exit"]["verified"]["total"])
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    def test_gateway_status_lists_exit_services(self) -> None:
        with manager.lock:
            manager.exit_status["singbox"].update({"supported": True, "enabled": True, "applied": True, "service_active": True, "last_error": ""})
            manager.exit_status["global"].update({
                "supported": True, "enabled": True, "applied": True, "physical_interface": "eth0",
                "physical_ips": ["203.0.113.10"], "last_error": "boom",
            })
        try:
            body = self._get_gateway_status()
        finally:
            with manager.lock:
                manager.exit_status["singbox"].update({"supported": False, "enabled": True, "applied": False, "service_active": None})
                manager.exit_status["global"].update({"supported": False, "enabled": False, "applied": False, "physical_interface": "", "physical_ips": [], "last_error": ""})
        services = {item["name"]: item for item in body["services"]}
        self.assertIn("sing-box 出口接管", services)
        self.assertIn("全局出口接管", services)
        self.assertEqual("running", services["sing-box 出口接管"]["status"])
        self.assertEqual("running", services["全局出口接管"]["status"])
        self.assertIn("eth0", services["全局出口接管"]["details"])
        self.assertEqual("boom", services["全局出口接管"]["error"])

    def test_release_archive_includes_new_modules(self) -> None:
        text = (REPO_ROOT / "scripts" / "build_release_archives.py").read_text(encoding="utf-8")
        for name in ("speedtest.py", "singbox_exit.py", "global_exit.py"):
            self.assertIn(f'"{name}"', text)

    def test_dockerfile_copies_new_modules(self) -> None:
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        copy_lines = [line for line in text.splitlines() if line.startswith("COPY ") and "vpngate_manager.py" in line]
        compile_lines = [line for line in text.splitlines() if "py_compile" in line]
        self.assertEqual(1, len(copy_lines))
        self.assertEqual(1, len(compile_lines))
        for name in ("speedtest.py", "singbox_exit.py", "global_exit.py"):
            self.assertIn(name, copy_lines[0])
            self.assertIn(name, compile_lines[0])

    def test_readme_documents_exit_takeover(self) -> None:
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("## 出口接管与节点测速", text)
        for phrase in (
            "fail-closed", "IPv6 不经隧道", "--global-exit off", "--singbox-exit off",
            "ip rule del pref", "ip route del unreachable default table 100",
            "数秒直连窗口", "Docker 模式限制", "kadidalax/aimili-vpngate",
        ):
            self.assertIn(phrase, text, phrase)

    def test_ui_auth_json_is_written_private(self) -> None:
        auth_file = manager.DATA_DIR / "ui_auth.json"
        manager.write_json(auth_file, {"username": "test", "password": "secret"})
        if os.name != "nt":
            self.assertEqual(0o600, stat.S_IMODE(auth_file.stat().st_mode))

    def test_source_deadline_limits_total_fetch_time(self) -> None:
        def slow_fetch(url, verify_ssl=True):
            threading.Event().wait(0.1)
            return valid_snapshot()

        with mock.patch.object(manager, "fetch_api_text", side_effect=slow_fetch):
            started = manager.time.monotonic()
            with self.assertRaises(manager.SourceDeadlineExceeded):
                manager.fetch_api_text_with_deadline(
                    manager.API_HTTPS_URL,
                    deadline_seconds=0.01,
                )

        self.assertLess(manager.time.monotonic() - started, 0.08)

    def test_node_probe_stops_after_systemic_openvpn_failure(self) -> None:
        nodes = self.write_nodes(12)

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "[ERR_OVPN_TUN_NOT_AVAILABLE] missing TUN", None),
            ) as openvpn_mock,
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
            mock.patch.object(manager, "log_to_json"),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=3,
            )

        self.assertEqual(5, openvpn_mock.call_count)
        self.assertEqual(5, len(results))
        stored = manager.read_nodes()
        self.assertEqual(5, sum(node.get("probe_status") == "unavailable" for node in stored))
        self.assertEqual(7, sum(node.get("probe_status") == "not_checked" for node in stored))

    def test_maintenance_does_not_start_second_batch_after_systemic_failure(self) -> None:
        candidates = self.write_nodes(12)

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "[ERR_OVPN_CMD_NOT_FOUND] openvpn missing", None),
            ) as openvpn_mock,
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.maintain_valid_nodes()

        self.assertEqual(5, openvpn_mock.call_count)
        self.assertIn("检测 5 个", result)

    def test_cancel_pending_connection_stops_handshake_process(self) -> None:
        process = FakeProcess()
        event = threading.Event()
        manager.pending_openvpn_process = process
        manager.active_connection_cancel_event = event
        manager.is_connecting = True
        previous_epoch = manager.connection_epoch

        manager.cancel_pending_connection_attempt()

        self.assertTrue(event.is_set())
        self.assertTrue(process.terminated)
        self.assertIsNone(manager.pending_openvpn_process)
        self.assertFalse(manager.is_connecting)
        self.assertEqual(previous_epoch + 1, manager.connection_epoch)

    def test_proxy_failures_reset_when_node_changes(self) -> None:
        self.assertEqual(1, manager.record_proxy_failure("node-a"))
        self.assertEqual(2, manager.record_proxy_failure("node-a"))
        self.assertEqual(1, manager.record_proxy_failure("node-b"))
        manager.reset_proxy_failure_counter("node-b")
        self.assertEqual(1, manager.record_proxy_failure("node-b"))

    def test_failed_switch_preflight_keeps_current_connection(self) -> None:
        nodes = self.write_nodes(2)
        nodes[0]["active"] = True
        manager.write_json(manager.NODES_FILE, nodes)
        current_process = FakeProcess()
        manager.active_openvpn_process = current_process
        manager.active_openvpn_node_id = nodes[0]["id"]

        with (
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "preflight failed", None),
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "已保留当前连接"):
                manager.connect_node(nodes[1]["id"])

        self.assertIs(manager.active_openvpn_process, current_process)
        self.assertEqual(nodes[0]["id"], manager.active_openvpn_node_id)
        self.assertTrue(current_process.running)
        stored = {node["id"]: node for node in manager.read_nodes()}
        self.assertEqual("unavailable", stored[nodes[1]["id"]]["probe_status"])

    def test_proxy_failure_does_not_report_connection_success(self) -> None:
        nodes = self.write_nodes(1)
        process = FakeProcess()

        with (
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(True, "ready", process),
            ),
            mock.patch.object(manager, "setup_policy_routing", return_value=False),
            mock.patch.object(manager, "cleanup_policy_routing"),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager, "check_proxy_health", return_value={"ok": False, "error": "no route"}),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "代理出口不可用"):
                manager.connect_node(nodes[0]["id"])

        self.assertFalse(process.running)
        self.assertIsNone(manager.active_openvpn_process)
        self.assertEqual("", manager.active_openvpn_node_id)
        stored = manager.read_nodes()
        self.assertEqual("unavailable", stored[0]["probe_status"])

    def test_manual_failure_recovery_prefers_previous_node(self) -> None:
        with (
            mock.patch.object(manager, "active_openvpn_running", return_value=False),
            mock.patch.object(manager, "connect_node", return_value="connected") as connect_mock,
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "auto_switch_node") as auto_switch_mock,
        ):
            manager.recover_after_manual_connect_failure("old-node")

        connect_mock.assert_called_once_with("old-node")
        auto_switch_mock.assert_not_called()

    def test_auto_switch_exhaustion_schedules_background_refill(self) -> None:
        with (
            mock.patch.object(manager, "schedule_background_refill", return_value=True) as schedule_mock,
            mock.patch.object(manager, "log_to_json") as log_mock,
        ):
            manager.auto_switch_node(attempt=3)

        schedule_mock.assert_called_once_with()
        log_mock.assert_called_once_with("INFO", "Main", "连续自动切换失败，已启动唯一后台节点补齐任务")

    def test_physical_interface_detection_is_cached(self) -> None:
        original_cache = manager.vpn_utils.physical_interface_cache
        manager.vpn_utils.physical_interface_cache = (None, 0.0)
        try:
            with mock.patch.object(
                manager.vpn_utils,
                "_detect_physical_interface",
                return_value="eth0",
            ) as detect_mock:
                self.assertEqual("eth0", manager.vpn_utils.get_physical_interface())
                self.assertEqual("eth0", manager.vpn_utils.get_physical_interface())
            detect_mock.assert_called_once_with()
        finally:
            manager.vpn_utils.physical_interface_cache = original_cache

    def test_forced_refresh_keeps_healthy_active_connection(self) -> None:
        process = FakeProcess()
        manager.active_openvpn_process = process
        manager.active_openvpn_node_id = "active-node"

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=[]),
            mock.patch.object(manager, "stop_active_openvpn") as stop_mock,
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.maintain_valid_nodes(force=True)

        self.assertEqual("没有拉取到新节点", result)
        self.assertTrue(process.running)
        stop_mock.assert_not_called()

    def test_fetch_timeout_skips_insecure_https_retry(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl):
            if url.startswith("https://"):
                raise TimeoutError("timed out")
            return csv_text

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "set_state"),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [mock.call(manager.API_HTTPS_URL, True), mock.call(manager.API_HTTP_URL, True)],
            fetch_mock.call_args_list,
        )

    def test_discovery_countries_are_normalized_and_persisted(self) -> None:
        countries = manager.persist_discovery_countries(["jp", "US", "JP", "bad", ""])

        self.assertEqual(["JP", "US"], countries)
        self.assertEqual(["JP", "US"], manager.load_ui_config()["discovery_countries"])
        self.assertEqual(["JP", "US"], manager.get_state()["discovery_countries"])

    def test_fetch_filters_country_after_source_is_accepted(self) -> None:
        csv_text = valid_snapshot_rows(
            [
                ("198.51.100.60", "Japan", "JP"),
                ("198.51.100.61", "United States", "US"),
            ]
        )
        manager.persist_discovery_countries(["JP"])

        with (
            mock.patch.object(manager, "fetch_api_text", return_value=csv_text) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(["JP"], [node["country_short"] for node in nodes])
        fetch_mock.assert_called_once_with(manager.API_HTTPS_URL, True)
        self.assertEqual(csv_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertIn("成功获取 2 个", manager.get_state()["last_fetch_message"])
        self.assertIn("保留 1 个", manager.get_state()["last_fetch_message"])

    def test_empty_country_result_does_not_fall_through_to_next_source(self) -> None:
        csv_text = valid_snapshot_rows(
            [
                ("198.51.100.70", "Japan", "JP"),
                ("198.51.100.71", "United States", "US"),
            ]
        )
        manager.persist_discovery_countries(["DE"])

        with (
            mock.patch.object(manager, "fetch_api_text", return_value=csv_text) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual([], nodes)
        fetch_mock.assert_called_once_with(manager.API_HTTPS_URL, True)
        state = manager.get_state()
        self.assertEqual("ok", state["last_fetch_status"])
        self.assertEqual("official_https", state["last_fetch_source"])
        self.assertIn("保留 0 个", state["last_fetch_message"])

    def test_node_table_contains_latency_country_panel_and_test_action(self) -> None:
        self.assertIn('<th style="width: 125px;">延迟</th>', manager.INDEX_HTML)
        self.assertIn('<th style="width: 130px;">实测速度</th>', manager.INDEX_HTML)
        self.assertIn('colspan="8"', manager.INDEX_HTML)
        self.assertNotIn('colspan="7"', manager.INDEX_HTML)
        self.assertIn('class="country-option-input"', manager.INDEX_HTML)
        self.assertIn('${testBtn}', manager.INDEX_HTML)
        self.assertIn('${speedCellHtml(n)}', manager.INDEX_HTML)

    def test_dashboard_contains_filtered_speedtest_and_history_popover(self) -> None:
        html = manager.INDEX_HTML
        for element_id in ("btn_speedtest_filtered", "app_toast", "speed_history_pop"):
            self.assertIn(f'id="{element_id}"', html, element_id)
        for text in (
            "startFilteredSpeedtest", "showSpeedHistory", "hideSpeedHistory",
            "speedHistoryOf", "speedHistoryStats", "showToast",
            "./api/pipeline/speedtest_filtered", "实测速度历史",
        ):
            self.assertIn(text, html, text)
        # 右对齐分组：margin-left:auto 从 #btn_speedtest 挪到新按钮
        self.assertIn('id="btn_speedtest_filtered" class="toolbar-btn" type="button" onclick="startFilteredSpeedtest()" style="margin-left: auto;', html)
        self.assertNotIn('id="btn_speedtest" class="toolbar-btn" type="button" onclick="openSpeedtestModal()" style="margin-left: auto;', html)
        # 浮层不占文档流
        self.assertIn('id="speed_history_pop" style="position: fixed; display: none;', html)

    def test_speed_cell_shows_history_popover_without_current_speed(self) -> None:
        html = manager.INDEX_HTML
        cell_body = html[html.index("function speedCellHtml"):html.index("function renderExitStatus")]
        # 最近一次测速失败（speed_mbps<=0）但留有历史的节点也必须能悬浮出历史
        self.assertLess(cell_body.index("speedHistoryOf"), cell_body.index("value <= 0"))
        self.assertIn('${historyAttrs}>-</span>', cell_body)
        # toast 数使用服务端返回的 total（服务端按 500 截断，前端 ids 可能更长）
        fn_body = html[html.index("async function startFilteredSpeedtest"):html.index("function speedHistoryOf")]
        self.assertIn("Number(result.total)", fn_body)

    def test_dashboard_contains_v220_controls(self) -> None:
        html = manager.INDEX_HTML
        for element_id in (
            "net_global_exit", "global_exit_status", "net_singbox_exit", "singbox_exit_status",
            "btn_verify_singbox", "st_check_interval_hours", "next_check_label",
            "btn_speedtest", "sort_mode", "speedtest_modal", "st_status", "st_countries", "st_ip_types",
            "st_retest_hours", "st_seconds", "st_max_mb", "st_threshold", "st_threshold_mbit", "st_margin",
            "st_url", "st_auto", "st_auto_switch", "st_estimate", "st_save", "st_save_start", "pipeline_panel",
        ):
            self.assertIn(f'id="{element_id}"', html, element_id)
        for text in (
            "隧道断开时全部出站中断", "断开后将同时关闭全局出口开关", "任务进行中...", "测速中", "停止任务",
            "./api/global_exit", "./api/singbox_exit", "./api/singbox_exit/verify", "./api/speedtest/settings",
            "./api/speedtest/estimate", "./api/pipeline/speedtest", "./api/pipeline/stop",
            "check_interval_hours: checkIntervalHours", 'sortMode === "speed"', "class=\"switch-input\"",
        ):
            self.assertIn(text, html, text)

    def test_web_dashboard_has_browser_freeze_safeguards(self) -> None:
        self.assertNotIn("backdrop-filter", manager.LOGIN_HTML)
        self.assertNotIn("backdrop-filter", manager.INDEX_HTML)
        self.assertNotIn("background-attachment: fixed", manager.INDEX_HTML)
        self.assertIn("@media (prefers-reduced-motion: reduce)", manager.LOGIN_HTML)
        self.assertIn("@media (prefers-reduced-motion: reduce)", manager.INDEX_HTML)
        self.assertIn("const pageSize = 50;", manager.INDEX_HTML)
        self.assertIn('id="pagination_container"', manager.INDEX_HTML)
        self.assertIn('paginationContainer.style.display = totalPages > 1 ? "flex" : "none";', manager.INDEX_HTML)
        self.assertIn("const MAX_RENDERED_LOG_LINES = 300;", manager.INDEX_HTML)
        self.assertIn("nodesRequestPromise", manager.INDEX_HTML)
        self.assertIn("backgroundPollInFlight", manager.INDEX_HTML)
        self.assertIn('let lastNodesSnapshotSignature = "";', manager.INDEX_HTML)
        self.assertIn("if (signature === lastNodesSnapshotSignature) return false;", manager.INDEX_HTML)
        self.assertIn('typeof document.hidden !== "boolean" || !document.hidden', manager.INDEX_HTML)
        self.assertEqual(500, manager.WEB_LOG_MAX_ENTRIES)

    def test_web_dashboard_has_cross_browser_interaction_safeguards(self) -> None:
        self.assertNotIn("fonts.googleapis.com", manager.LOGIN_HTML)
        self.assertNotIn("fonts.googleapis.com", manager.INDEX_HTML)
        self.assertIn('const pwd = document.getElementById("password").value;', manager.LOGIN_HTML)
        self.assertIn('const password = $("cred_password").value;', manager.INDEX_HTML)
        self.assertIn("function fetchWithTimeout", manager.LOGIN_HTML)
        self.assertIn("function fetchWithTimeout", manager.INDEX_HTML)
        self.assertNotIn("await fetch(", manager.INDEX_HTML)
        self.assertIn('role="dialog" aria-modal="true"', manager.INDEX_HTML)
        self.assertIn('aria-label="关闭网页安全设置"', manager.INDEX_HTML)
        self.assertIn('class="option-card active" data-value="auto" aria-pressed="true"', manager.INDEX_HTML)
        self.assertIn('position: static;', manager.INDEX_HTML)
        self.assertIn('-webkit-overflow-scrolling: touch;', manager.INDEX_HTML)
        self.assertIn('formatUrlHost(window.location.hostname)', manager.INDEX_HTML)
        self.assertNotIn('id="status" class="status" style="display: none;"', manager.INDEX_HTML)
        self.assertIn('${esc(localProxy)}', manager.INDEX_HTML)
        self.assertIn('${esc(state.last_check_message)}', manager.INDEX_HTML)

    def test_dashboard_javascript_is_valid(self) -> None:
        if not shutil.which("node"):
            self.skipTest("Node.js is not installed; JavaScript syntax check skipped")
        scripts = re.findall(r"<script>(.*?)</script>", manager.INDEX_HTML, re.DOTALL)
        self.assertTrue(scripts)
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as handle:
            handle.write("\n".join(scripts))
            script_path = handle.name
        try:
            result = subprocess.run(
                ["node", "--check", script_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
        finally:
            Path(script_path).unlink(missing_ok=True)

    def test_random_password_uses_cryptographic_randomness(self) -> None:
        with mock.patch.object(manager.secrets, "choice", side_effect=list("aA0aA0aA0aA0")) as choice:
            password = manager.generate_random_password()

        self.assertEqual("aA0aA0aA0aA0", password)
        self.assertEqual(12, choice.call_count)

    def test_expired_sessions_are_removed(self) -> None:
        manager.active_sessions.update({"expired": 99.0, "active": 101.0})

        removed = manager.purge_expired_sessions(now=100.0)

        self.assertEqual(1, removed)
        self.assertEqual({"active": 101.0}, manager.active_sessions)

    def test_web_log_reader_only_returns_recent_valid_entries(self) -> None:
        log_file = manager.DATA_DIR / "logs" / "current.json"
        log_file.parent.mkdir(parents=True)
        with log_file.open("w", encoding="utf-8") as f:
            for index in range(520):
                f.write(json.dumps({"index": index}) + "\n")
            f.write("not-json\n")

        entries = manager.read_recent_log_entries(log_file)

        self.assertEqual(500, len(entries))
        self.assertEqual(20, entries[0]["index"])
        self.assertEqual(519, entries[-1]["index"])

    def test_web_update_controls_only_expose_stable_main_channel(self) -> None:
        self.assertEqual("2.2.0", manager.APP_VERSION)
        self.assertEqual("V2.2.0 正式版", manager.APP_VERSION_LABEL)
        self.assertIn("检测更新", manager.INDEX_HTML)
        self.assertIn("/api/check_update", manager.INDEX_HTML)
        self.assertIn("/tree/main", manager.INDEX_HTML)
        self.assertIn("/releases/latest", manager.INDEX_HTML)
        self.assertNotIn("/tree/bate", manager.INDEX_HTML)
        self.assertNotIn(">测试版<", manager.INDEX_HTML)
        self.assertIn('id="deployment_mode_label"', manager.INDEX_HTML)

    def test_installer_updates_only_from_main(self) -> None:
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")

        self.assertIn('DEPLOY_BRANCH="main"', install_text)
        self.assertIn('branch = "main"', install_text)
        self.assertNotIn("CURRENT_BRANCH", install_text)
        self.assertNotIn("origin/master", install_text)
        self.assertNotIn("bate", install_text.lower())
        self.assertIn('DEFAULT_USER="kadidalax"', install_text)
        self.assertNotIn("baoweise-bot", install_text)

    def test_installer_uses_secure_credentials_and_current_version(self) -> None:
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")

        self.assertNotIn("random.choices", install_text)
        self.assertIn("secrets.choice", install_text)
        self.assertIn('get_app_version()', install_text)
        self.assertNotIn("管理终端 v2.0", install_text)
        self.assertIn("5-90 秒", install_text)
        self.assertIn('new_pwd = input("请输入新管理密码 (不能为空): ")', install_text)
        self.assertIn('state["active_openvpn_node_id"] = ""', install_text)
        self.assertIn("ip link show dev tun0", install_text)
        self.assertIn("pidof openvpn", install_text)
        self.assertIn('chmod 600 "$AUTH_FILE"', install_text)
        self.assertIn("AIMILIVPN_NONINTERACTIVE", install_text)
        self.assertIn('["ip", "rule", "del", "table", "100"]', install_text)
        self.assertIn('/etc/sysctl.d/99-aimilivpn.conf', install_text)
        self.assertNotIn('http://[::1]:${PROXY_PORT}', install_text)

    def test_openvpn_command_requires_server_certificate_usage(self) -> None:
        with mock.patch.object(manager, "get_openvpn_version", return_value=2.5):
            command = manager.openvpn_command("node.ovpn", route_nopull=True)
        index = command.index("--remote-cert-tls")
        self.assertEqual("server", command[index + 1])

    def test_release_workflow_uses_full_patch_version(self) -> None:
        workflow_text = (manager.ROOT_DIR / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

        self.assertIn("default: v2.2.0", workflow_text)
        self.assertIn("AimiliVPN V$(tr -d '\\r\\n' < VERSION) 正式版", workflow_text)
        self.assertNotIn("cut -d. -f1,2 VERSION", workflow_text)

    def test_latest_release_check_ignores_non_version_name_text(self) -> None:
        release = {
            "tag_name": "v2.3.0",
            "name": "AimiliVPN V2.3 正式版",
            "published_at": "2026-09-01T00:00:00Z",
            "draft": False,
            "prerelease": False,
        }
        with mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)) as fetch_mock:
            result = manager.check_latest_release()

        self.assertTrue(result["ok"])
        self.assertTrue(result["update_available"])
        self.assertEqual("2.3.0", result["latest_version"])
        self.assertEqual("v2.3.0", result["latest_tag"])
        self.assertEqual(
            "https://github.com/kadidalax/aimili-vpngate/releases/tag/v2.3.0",
            result["release_url"],
        )
        fetch_mock.assert_called_once_with(manager.GITHUB_LATEST_RELEASE_API, True)

    def test_latest_release_check_reports_current_formal_version(self) -> None:
        release = {
            "tag_name": "v2.2.0",
            "name": "AimiliVPN V2.2.0 正式版",
            "draft": False,
            "prerelease": False,
        }
        with mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)):
            result = manager.check_latest_release()

        self.assertFalse(result["update_available"])
        self.assertEqual("V2.2.0 正式版", result["current_version_label"])

    def test_latest_release_check_reports_source_update_command(self) -> None:
        release = {"tag_name": "v2.3.0", "draft": False, "prerelease": False}
        with (
            mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)),
            mock.patch.object(manager, "DEPLOYMENT_MODE", "source"),
            mock.patch.object(manager, "DEPLOYMENT_MODE_LABEL", "Python 源码"),
            mock.patch.object(manager, "UPDATE_COMMAND", "ml update"),
        ):
            result = manager.check_latest_release()

        self.assertEqual("source", result["deployment_mode"])
        self.assertEqual("ml update", result["update_command"])

    def test_latest_release_check_reports_docker_update_command(self) -> None:
        release = {"tag_name": "v2.3.0", "draft": False, "prerelease": False}
        with (
            mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)),
            mock.patch.object(manager, "DEPLOYMENT_MODE", "docker"),
            mock.patch.object(manager, "DEPLOYMENT_MODE_LABEL", "Docker 容器"),
            mock.patch.object(
                manager,
                "UPDATE_COMMAND",
                "docker compose pull && docker compose up -d",
            ),
        ):
            result = manager.check_latest_release()

        self.assertEqual("docker", result["deployment_mode"])
        self.assertEqual(
            "docker compose pull && docker compose up -d",
            result["update_command"],
        )

    def test_fetch_uses_github_mirror_after_official_sources(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl):
            if url == manager.MIRROR_HTTPS_URL:
                return csv_text
            raise TimeoutError("blocked")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "read_mirror_freshness", return_value=(0.0, "")),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [manager.API_HTTPS_URL, manager.API_HTTP_URL, manager.MIRROR_HTTPS_URL],
            [call.args[0] for call in fetch_mock.call_args_list],
        )
        self.assertEqual(csv_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("github_pages_https", manager.get_state()["last_fetch_source"])

    def test_http_source_does_not_replace_trusted_cache(self) -> None:
        cached_text = valid_snapshot("198.51.100.20")
        http_text = valid_snapshot("198.51.100.21")
        manager.API_CACHE_FILE.write_text(cached_text, encoding="utf-8")

        def fake_fetch(url, verify_ssl):
            if url == manager.API_HTTP_URL:
                return http_text
            raise TimeoutError("TLS unavailable")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.21", nodes[0]["ip"])
        self.assertEqual(cached_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))

    def test_fetch_falls_back_to_local_cache(self) -> None:
        cached_text = valid_snapshot("198.51.100.30")
        manager.API_CACHE_FILE.write_text(cached_text, encoding="utf-8")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=TimeoutError("all blocked")),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.30", nodes[0]["ip"])
        self.assertEqual("local_cache", manager.get_state()["last_fetch_source"])

    def test_bundled_snapshot_seeds_local_cache(self) -> None:
        bundled_text = valid_snapshot("198.51.100.40")
        manager.BUNDLED_SNAPSHOT_FILE.write_text(bundled_text, encoding="utf-8")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=TimeoutError("all blocked")),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.40", nodes[0]["ip"])
        self.assertEqual(bundled_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("bundled_initial", manager.get_state()["last_fetch_source"])

    def test_snapshot_rejects_executable_openvpn_directive(self) -> None:
        unsafe_config = (
            "client\ndev tun\nproto udp\nremote 198.51.100.50 1194 udp\n"
            "script-security 2\nup /tmp/payload\n"
            "<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
        )
        encoded = base64.b64encode(unsafe_config.encode("utf-8")).decode("ascii")
        csv_text = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n"
            f"vpn.example,198.51.100.50,100,20,1000,Japan,JP,1,{encoded}\n"
        )

        with self.assertRaisesRegex(ValueError, "no valid nodes"):
            snapshot_utils.parse_and_validate_snapshot(csv_text)

    # ---- 测速历史存储（spec 3.1 / 3.2） ----

    def test_append_speed_history_keeps_latest_ten_records(self) -> None:
        for index in range(12):
            manager.append_speed_history("node-a", {"t": 1700000000 + index, "mbps": index, "msg": "", "run_id": "r"})

        history = manager.read_speed_history()
        self.assertEqual(1, len(history))
        records = history["node-a"]
        self.assertEqual(10, len(records))
        self.assertEqual(2, records[0]["t"] - 1700000000)
        self.assertEqual(11, records[-1]["t"] - 1700000000)
        on_disk = manager.read_json(manager.SPEED_HISTORY_FILE, {})
        self.assertEqual(1, on_disk.get("version"))
        self.assertEqual(10, len(on_disk["nodes"]["node-a"]))

    def test_append_speed_history_prunes_oldest_node_entries(self) -> None:
        total = manager.SPEED_HISTORY_MAX_NODES + 1
        for index in range(total):
            # node-0 最新记录最旧，应最先被淘汰
            manager.append_speed_history(f"node-{index}", {"t": 1700000000 + index, "mbps": 1.0, "msg": "", "run_id": "r"})

        history = manager.read_speed_history()
        self.assertEqual(manager.SPEED_HISTORY_MAX_NODES, len(history))
        self.assertNotIn("node-0", history)
        self.assertIn(f"node-{total - 1}", history)

    def test_append_speed_history_ignores_empty_node_id(self) -> None:
        manager.append_speed_history("", {"t": 1, "mbps": 1.0, "msg": "", "run_id": "r"})
        self.assertEqual({}, manager.read_speed_history())

    def test_read_speed_history_tolerates_corrupt_file(self) -> None:
        manager.SPEED_HISTORY_FILE.write_text("{not json", encoding="utf-8")
        with mock.patch.object(manager, "log_to_json") as log_mock:
            history = manager.read_speed_history()
        self.assertEqual({}, history)
        self.assertTrue(log_mock.called)

        # 结构不对（根不是对象）同样当空记录
        manager.SPEED_HISTORY_FILE.write_text("[1, 2, 3]", encoding="utf-8")
        with mock.patch.object(manager, "log_to_json"):
            self.assertEqual({}, manager.read_speed_history())

    def test_append_speed_history_survives_write_failure(self) -> None:
        with mock.patch.object(manager, "write_json", side_effect=OSError("disk full")), \
                mock.patch.object(manager, "log_to_json") as log_mock:
            manager.append_speed_history("node-a", {"t": 1, "mbps": 1.0, "msg": "", "run_id": "r"})
        self.assertTrue(log_mock.called)
        self.assertEqual({}, manager.read_speed_history())

    def test_get_state_includes_speed_history(self) -> None:
        manager.append_speed_history("node-a", {"t": 1700000000, "mbps": 42.5, "msg": "", "run_id": "r"})

        state = manager.get_state()

        self.assertIn("speed_history", state)
        self.assertEqual(42.5, state["speed_history"]["node-a"][0]["mbps"])

    def test_set_state_does_not_persist_speed_history(self) -> None:
        # 历史只存在 speed_history.json；state.json 不得复制一份（否则每次 set_state 都写几百 KB）
        manager.append_speed_history("node-a", {"t": 1700000000, "mbps": 42.5, "msg": "", "run_id": "r"})

        manager.set_state(last_check_message="ping")

        self.assertIn("speed_history", manager.RUNTIME_STATE_KEYS)
        persisted = json.loads(manager.STATE_FILE.read_text(encoding="utf-8"))
        self.assertNotIn("speed_history", persisted)
        # 前端仍能从 get_state 拿到历史
        self.assertIn("speed_history", manager.get_state())

    def test_append_speed_history_truncates_long_msg(self) -> None:
        long_msg = "x" * (manager.SPEED_HISTORY_MSG_LIMIT + 100)
        manager.append_speed_history("node-a", {"t": 1, "mbps": 1.0, "msg": long_msg, "run_id": "r"})

        records = manager.read_speed_history()["node-a"]
        self.assertEqual(manager.SPEED_HISTORY_MSG_LIMIT + 3, len(records[0]["msg"]))
        self.assertTrue(records[0]["msg"].endswith("..."))

        # 短消息原样保留
        manager.append_speed_history("node-a", {"t": 2, "mbps": 1.0, "msg": "ok", "run_id": "r"})
        self.assertEqual("ok", manager.read_speed_history()["node-a"][1]["msg"])

    # ---- 独立筛选测速（spec 4.1） ----

    def test_filtered_speedtest_returns_409_when_busy(self) -> None:
        with mock.patch.object(manager, "pipeline_snapshot", return_value={"running": True}):
            status, body = manager.handle_pipeline_speedtest_filtered_request({"ids": ["node-0"]})
        self.assertEqual(409, status)
        self.assertFalse(body["ok"])
        self.assertTrue(body["running"])

        with mock.patch.object(manager, "pipeline_snapshot", return_value={"running": False}):
            self.assertTrue(manager.maintenance_lock.acquire(blocking=False))
            try:
                status, body = manager.handle_pipeline_speedtest_filtered_request({"ids": ["node-0"]})
            finally:
                manager.maintenance_lock.release()
        self.assertEqual(409, status)

    def test_filtered_speedtest_rejects_bad_ids(self) -> None:
        self.write_nodes(2)
        for bad_ids in ([], ["ghost-1", "ghost-2"], "node-0", None, [""], 42):
            with self.subTest(ids=bad_ids):
                status, body = manager.handle_pipeline_speedtest_filtered_request({"ids": bad_ids})
                self.assertEqual(400, status)
                self.assertFalse(body["ok"])

    def test_filtered_speedtest_builds_candidates_from_ids_without_fetch(self) -> None:
        self.write_nodes(4)

        with (
            mock.patch.object(manager, "fetch_candidates") as fetch,
            mock.patch.object(manager.speedtest, "select_candidates") as select,
            mock.patch.object(manager, "run_filtered_speedtest") as runner,
        ):
            status, body = manager.handle_pipeline_speedtest_filtered_request(
                {"ids": ["node-3", "node-0", "node-0"]}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        fetch.assert_not_called()
        select.assert_not_called()
        runner.assert_called_once()
        ids, candidates = runner.call_args.args
        self.assertEqual(["node-3", "node-0"], ids)
        self.assertEqual(["node-3", "node-0"], [c["id"] for c in candidates])

    def test_run_filtered_speedtest_runs_speed_stage_only(self) -> None:
        self.write_nodes(3)
        candidates = manager.read_nodes()
        manager.pipeline_cancel_event.clear()

        with (
            mock.patch.object(manager, "run_speed_stage", return_value="") as stage,
            mock.patch.object(manager, "fetch_candidates") as fetch,
            mock.patch.object(manager.speedtest, "select_candidates") as select,
            mock.patch.object(manager, "maybe_switch_to_fastest") as switch,
            mock.patch.object(manager, "run_pipeline") as pipeline,
            mock.patch.object(manager, "log_to_json"),
        ):
            manager.run_filtered_speedtest(["node-0", "node-1"], candidates[:2])

        stage.assert_called_once()
        staged_ids = [c["id"] for c in stage.call_args.args[0]]
        self.assertEqual(["node-0", "node-1"], staged_ids)
        self.assertEqual("filtered_speedtest", stage.call_args.args[2])
        fetch.assert_not_called()
        select.assert_not_called()
        switch.assert_not_called()
        pipeline.assert_not_called()
        snapshot = manager.pipeline_snapshot()
        self.assertFalse(snapshot["running"])
        self.assertEqual("idle", snapshot["stage"])
        self.assertFalse(manager.is_connecting)
        self.assertFalse(manager.maintenance_lock.locked())

    def test_run_filtered_speedtest_releases_lock_on_stage_error(self) -> None:
        candidates = self.write_nodes(1)

        with (
            mock.patch.object(manager, "run_speed_stage", side_effect=RuntimeError("boom")),
            mock.patch.object(manager, "log_to_json"),
        ):
            manager.run_filtered_speedtest(["node-0"], candidates)

        snapshot = manager.pipeline_snapshot()
        self.assertFalse(snapshot["running"])
        self.assertEqual("error", snapshot["stopped_reason"])
        self.assertFalse(manager.is_connecting)
        self.assertFalse(manager.maintenance_lock.locked())

    def test_run_filtered_speedtest_returns_busy_without_leaking_lock(self) -> None:
        self.assertTrue(manager.maintenance_lock.acquire(blocking=False))
        try:
            with mock.patch.object(manager, "run_speed_stage") as stage:
                manager.run_filtered_speedtest(["node-0"], [])
        finally:
            manager.maintenance_lock.release()
        stage.assert_not_called()
        self.assertFalse(manager.is_connecting)


class ProxyServerConcurrencyTests(unittest.TestCase):
    def test_socks5_rejects_client_without_no_auth_method(self) -> None:
        class Client:
            def __init__(self):
                self.incoming = bytearray(b"\x01\x02")
                self.sent = bytearray()
                self.closed = False

            def recv(self, size):
                chunk = self.incoming[:size]
                del self.incoming[:size]
                return bytes(chunk)

            def sendall(self, data):
                self.sent.extend(data)

            def close(self):
                self.closed = True

        client = Client()
        with mock.patch.object(proxy_server, "proxy_auth_enabled", return_value=False):
            proxy_server.socks5_client(client, b"\x05")

        self.assertEqual(b"\x05\xff", bytes(client.sent))
        self.assertTrue(client.closed)

    def test_each_proxy_worker_keeps_its_accepted_socket(self) -> None:
        class Client:
            def __init__(self, name):
                self.name = name

            def close(self):
                pass

        class FakeServer:
            def __init__(self):
                self.items = [(Client("first"), ("first", 1)), (Client("second"), ("second", 2))]

            def setsockopt(self, *args):
                pass

            def bind(self, *args):
                pass

            def listen(self, *args):
                pass

            def accept(self):
                if self.items:
                    return self.items.pop(0)
                raise KeyboardInterrupt()

        class DeferredThread:
            targets = []

            def __init__(self, target, daemon=True):
                self.target = target
                self.targets.append(target)

            def start(self):
                pass

        seen = []
        semaphore = mock.Mock()
        semaphore.acquire.return_value = True
        with (
            mock.patch.object(proxy_server.socket, "socket", return_value=FakeServer()),
            mock.patch.object(proxy_server.threading, "Thread", DeferredThread),
            mock.patch.object(
                proxy_server,
                "proxy_client",
                side_effect=lambda client, address: seen.append((client.name, address[0])),
            ),
            mock.patch.object(proxy_server, "proxy_connection_sem", semaphore),
        ):
            with self.assertRaises(KeyboardInterrupt):
                proxy_server.start_proxy_server("127.0.0.1", 7928)
            for target in DeferredThread.targets:
                target()

        self.assertEqual([("first", "first"), ("second", "second")], seen)


if __name__ == "__main__":
    unittest.main()
