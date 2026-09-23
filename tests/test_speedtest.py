from __future__ import annotations

import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import speedtest


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D401 - silence
        return

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/bytes/"):
            size = int(self.path.rsplit("/", 1)[1])
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            remaining = size
            block = b"x" * 65536
            try:
                while remaining > 0:
                    piece = block[:remaining]
                    self.wfile.write(piece)
                    remaining -= len(piece)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            return
        if self.path == "/slow":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            block = b"y" * 65536
            deadline = time.monotonic() + 5
            try:
                while time.monotonic() < deadline:
                    self.wfile.write(block)
                    self.wfile.flush()
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            self.close_connection = True
            return
        if self.path == "/404":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()


class SpeedtestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    # ---- settings -------------------------------------------------------

    def test_normalize_clamps_and_defaults(self) -> None:
        settings = speedtest.normalize_settings(
            {
                "status": "weird",
                "countries": ["jp", "us", "x", "JP"],
                "ip_types": ["residential", "alien", "HOSTING"],
                "retest_after_hours": 9999,
                "per_node_seconds": 1,
                "per_node_max_mb": 0,
                "stop_threshold_mbps": -5,
                "switch_margin_percent": 500,
                "url": "ftp://example.com/x",
                "auto_after_check": 1,
            }
        )
        self.assertEqual("available", settings["status"])
        self.assertEqual(["JP", "US"], settings["countries"])
        self.assertEqual(["residential", "hosting"], settings["ip_types"])
        self.assertEqual(720, settings["retest_after_hours"])
        self.assertEqual(3, settings["per_node_seconds"])
        self.assertEqual(1, settings["per_node_max_mb"])
        self.assertEqual(0.0, settings["stop_threshold_mbps"])
        self.assertEqual(100, settings["switch_margin_percent"])
        self.assertEqual(speedtest.DEFAULT_URL, settings["url"])
        self.assertTrue(settings["auto_after_check"])
        self.assertFalse(settings["auto_switch_fastest"])

        empty = speedtest.normalize_settings(None)
        self.assertEqual(speedtest.DEFAULT_SETTINGS, empty)
        self.assertIsNot(speedtest.DEFAULT_SETTINGS["countries"], empty["countries"])

    # ---- candidate selection ------------------------------------------

    def _nodes(self):
        return [
            {"id": "a", "probe_status": "available", "country_short": "JP", "ip_type": "residential", "latency_ms": 50, "score": 10},
            {"id": "b", "probe_status": "available", "country_short": "US", "ip_type": "hosting", "latency_ms": 20, "score": 5},
            {"id": "c", "probe_status": "unavailable", "country_short": "JP", "ip_type": "", "latency_ms": 0, "ping": 30, "score": 8},
            {"id": "d", "probe_status": "available", "country_short": "JP", "ip_type": "mobile", "latency_ms": 50, "score": 99, "speed_tested_at": 1000.0},
            {"id": "e", "probe_status": "not_checked", "country_short": "JP", "ip_type": "residential"},
        ]

    def test_select_filters_status_country_iptype_routing_and_window(self) -> None:
        nodes = self._nodes()
        settings = {"status": "available", "countries": ["JP"], "ip_types": ["residential", "mobile"], "retest_after_hours": 1}
        # Routing filter drops nothing here but must be invoked with the pool.
        seen = {}

        def routing(items):
            seen["ids"] = [n["id"] for n in items]
            return items

        result = speedtest.select_candidates(nodes, settings, routing, "", now=1000.0 + 1800)
        self.assertEqual(["a"], [n["id"] for n in result])  # d skipped by window, b wrong country, c unavailable, e not checked
        self.assertEqual(["a", "d"], seen["ids"])

        settings["retest_after_hours"] = 0
        result = speedtest.select_candidates(nodes, settings, routing, "", now=1000.0 + 1800)
        self.assertEqual(["d", "a"], [n["id"] for n in result])

        settings.update({"status": "unavailable", "countries": [], "ip_types": ["unknown"]})
        result = speedtest.select_candidates(nodes, settings, lambda items: items, "", now=0)
        self.assertEqual(["c"], [n["id"] for n in result])

        settings.update({"status": "all", "ip_types": []})
        result = speedtest.select_candidates(nodes, settings, lambda items: [n for n in items if n["id"] != "b"], "", now=0)
        self.assertEqual(["c", "d", "a"], [n["id"] for n in result])

    def test_select_active_node_is_baseline_regardless_of_filters(self) -> None:
        nodes = self._nodes()
        settings = {"status": "available", "countries": ["US"], "ip_types": ["hosting"], "retest_after_hours": 12}
        result = speedtest.select_candidates(nodes, settings, lambda items: [], "d", now=1000.0 + 60)
        self.assertEqual(["d"], [n["id"] for n in result])

        result = speedtest.select_candidates(nodes, settings, lambda items: items, "a", now=0)
        self.assertEqual(["a", "b"], [n["id"] for n in result])

        result = speedtest.select_candidates(nodes, settings, lambda items: items, "missing", now=0)
        self.assertEqual(["b"], [n["id"] for n in result])

    def test_select_orders_by_latency_then_score(self) -> None:
        nodes = self._nodes()
        settings = {"status": "all", "retest_after_hours": 0}
        result = speedtest.select_candidates(nodes, settings, None, "", now=0)
        self.assertEqual(["b", "c", "d", "a"], [n["id"] for n in result])

    def test_estimate_counts_active_node_cheaper(self) -> None:
        settings = {"per_node_seconds": 8, "per_node_max_mb": 20}
        candidates = [{"id": "act"}, {"id": "x"}, {"id": "y"}]
        result = speedtest.estimate(candidates, settings, "act")
        self.assertEqual({"count": 3, "max_mb": 60, "est_seconds": 10 + 24 + 24}, result)
        self.assertEqual({"count": 0, "max_mb": 0, "est_seconds": 0}, speedtest.estimate([], settings, ""))

    def test_build_url_replaces_bytes(self) -> None:
        self.assertEqual("https://x/?bytes=1000", speedtest.build_url("https://x/?bytes={bytes}", 1000))
        self.assertEqual("https://x/file", speedtest.build_url("https://x/file", 1000))

    # ---- download measurement ----------------------------------------

    def test_measure_stops_at_byte_limit(self) -> None:
        result = speedtest.measure_download(self.url("/bytes/5000000"), None, 30, 1_000_000)
        self.assertEqual("", result.error)
        self.assertGreaterEqual(result.bytes, 1_000_000)
        self.assertLessEqual(result.bytes, 1_000_000 + 65536 * 2)
        self.assertGreater(result.mbps, 0)
        self.assertGreaterEqual(result.seconds, speedtest.MIN_TIMING_SECONDS)

    def test_measure_stops_at_time_limit(self) -> None:
        started = time.monotonic()
        result = speedtest.measure_download(self.url("/slow"), None, 1, 10 ** 9)
        elapsed = time.monotonic() - started
        self.assertEqual("", result.error)
        self.assertGreater(result.bytes, 0)
        self.assertLess(elapsed, 3.0)
        self.assertGreaterEqual(result.seconds, 0.9)
        self.assertLessEqual(result.seconds, 1.6)

    def test_measure_cancel_stops_early(self) -> None:
        cancel = threading.Event()
        timer = threading.Timer(0.3, cancel.set)
        timer.start()
        started = time.monotonic()
        result = speedtest.measure_download(self.url("/slow"), None, 10, 10 ** 9, cancel_event=cancel)
        elapsed = time.monotonic() - started
        timer.cancel()
        self.assertEqual("", result.error)
        self.assertLess(elapsed, 2.5)
        self.assertGreater(result.bytes, 0)

    def test_measure_non_200_is_error(self) -> None:
        result = speedtest.measure_download(self.url("/404"), None, 5, 1000)
        self.assertIn("404", result.error)
        self.assertEqual(0, result.bytes)

    def test_measure_rejects_non_http_and_reports_connect_failure(self) -> None:
        self.assertIn("http", speedtest.measure_download("ftp://127.0.0.1/x", None, 1, 1).error)
        # A closed port must produce an error string rather than raising.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()
        result = speedtest.measure_download(f"http://127.0.0.1:{free_port}/x", None, 1, 1, connect_timeout=1)
        self.assertNotEqual("", result.error)

    def test_measure_without_device_does_not_bind(self) -> None:
        with mock.patch.object(socket.socket, "setsockopt", autospec=True) as setsockopt:
            result = speedtest.measure_download(self.url("/bytes/1000"), None, 5, 1000)
        self.assertEqual("", result.error)
        bind_calls = [c for c in setsockopt.call_args_list if getattr(socket, "SO_BINDTODEVICE", -1) in c.args]
        self.assertEqual([], bind_calls)

    def test_bind_device_uses_so_bindtodevice_when_available(self) -> None:
        sock = mock.Mock()
        with mock.patch.object(speedtest.socket, "SO_BINDTODEVICE", 25, create=True):
            speedtest.bind_device(sock, "tun5")
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, 25, b"tun5")
        sock.reset_mock()
        speedtest.bind_device(sock, "")
        sock.setsockopt.assert_not_called()

    def test_measure_uses_resolver_before_system_dns(self) -> None:
        calls = []

        def resolver(host):
            calls.append(host)
            return "127.0.0.1"

        result = speedtest.measure_download(f"http://localhost:{self.port}/bytes/1000", None, 5, 1000, resolver=resolver)
        self.assertEqual("", result.error)
        self.assertEqual(["localhost"], calls)

    def test_format_speed(self) -> None:
        self.assertEqual("2.41 MB/s (19.3 Mbps)", speedtest.format_speed(2.41))
        self.assertEqual("-", speedtest.format_speed(0))
        self.assertEqual("-", speedtest.format_speed(-1))
        self.assertEqual("-", speedtest.format_speed(None))


if __name__ == "__main__":
    unittest.main()
