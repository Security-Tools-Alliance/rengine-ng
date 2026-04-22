"""
Tests for CIDR discovery and ping_hosts_v2 APIs (Secator fping + PTR).
"""

from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.urls import reverse
from rest_framework import status

import api.views_ip_discovery as views_ip_discovery
from api.views_ip_discovery import PING_CACHE_KEY
from reNgine.services import ip_discovery_secator as ipd
from utils.test_base import BaseTestCase


class _SyncThread(threading.Thread):
    """Runs ping worker on the caller thread so tests see cache updates immediately."""

    def start(self) -> None:
        self.run()


class TestCidrDiscoveryApi(BaseTestCase):
    # Lexicographic default order would run test_get_discovery_* before test_get_requires_*.
    sortTestMethodsUsing = None  # noqa: N815

    def setUp(self) -> None:
        super().setUp()

    def test_get_requires_ip_address(self) -> None:
        url = reverse("api:cidr_discovery")
        response = self.client.get(url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("status"))

    def test_get_rejects_invalid_notation(self) -> None:
        url = reverse("api:cidr_discovery")
        response = self.client.get(url, {"ip_address": "not-an-ip", "format": "json"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_rejects_oversized_network(self) -> None:
        url = reverse("api:cidr_discovery")
        response = self.client.get(url, {"ip_address": "10.0.0.0/8", "format": "json"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("large", (response.data.get("message") or "").lower())

    def test_post_discovery_requires_body_ip(self) -> None:
        url = reverse("api:cidr_discovery")
        response = self.client.post(
            url,
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("api.views_ip_discovery.ipd.run_cidr_discovery")
    def test_get_discovery_response_shape(self, mock_run: MagicMock) -> None:
        mock_run.return_value = {
            "status": True,
            "ip_address": [
                {
                    "ip": "203.0.113.10",
                    "domain": "host.example.test",
                    "domains": ["host.example.test"],
                    "resolved_by": "PTR (fping ICMP)",
                    "is_alive": True,
                }
            ],
            "total_hosts": 1,
            "hostname_count": 1,
            "discovered_domains": ["example.test"],
            "current_dns_servers": ["8.8.8.8"],
            "used_dns_servers": ["8.8.8.8"],
            "ping_required": False,
            "range_warning": False,
        }
        url = reverse("api:cidr_discovery")
        response = self.client.get(
            url,
            {"ip_address": "203.0.113.10", "format": "json"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("status"))
        self.assertIn("range_warning", response.data)
        mock_run.assert_called_once()

    def test_probe_current_dns_returns_status_and_servers(self) -> None:
        url = reverse("api:cidr_discovery")
        response = self.client.get(url, {"probe": "current_dns", "format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("status"))
        self.assertIsInstance(response.data.get("current_dns_servers"), list)
        self.assertGreater(len(response.data["current_dns_servers"]), 0)


class TestIpDiscoveryServiceHelpers(BaseTestCase):
    def test_parse_ip_or_cidr_single_host(self) -> None:
        net, text = ipd.parse_ip_or_cidr("203.0.113.55")
        self.assertEqual(text, "203.0.113.55")
        self.assertEqual(net.num_addresses, 1)

    def test_normalize_ip_list_for_ping_dedupes_and_caps(self) -> None:
        ips = ["203.0.113.1", "  203.0.113.1 ", "203.0.113.2"]
        out = ipd.normalize_ip_list_for_ping(ips)
        self.assertEqual(out, ["203.0.113.1", "203.0.113.2"])

    def test_normalize_ip_list_rejects_overflow(self) -> None:
        ips = ["10.0.%d.%d" % (n // 256, n % 256) for n in range(ipd.MAX_PING_TARGETS + 1)]
        with self.assertRaises(ValueError):
            ipd.normalize_ip_list_for_ping(ips)

    def test_parse_dns_servers_option_skips_invalid_tokens(self) -> None:
        raw = "203.0.113.53,;../../etc,ns1.example.test"
        out = ipd.parse_dns_servers_option(raw)
        self.assertIn("203.0.113.53", out)
        self.assertIn("ns1.example.test", out)
        self.assertNotIn("../..", "".join(out))

    def test_split_network_into_chunks_caps_to_four(self) -> None:
        net, _ = ipd.parse_ip_or_cidr("203.0.113.0/24")
        chunks = ipd._split_network_into_chunks(net)
        self.assertEqual(len(chunks), 4)
        self.assertEqual(sum(len(chunk) for chunk in chunks), 256)

    @patch("reNgine.services.ip_discovery_secator.emit_ip_scan_progress")
    @patch("reNgine.services.ip_discovery_secator.ptr_lookup", return_value=(None, None))
    @patch("reNgine.services.ip_discovery_secator.run_fping_sync")
    def test_run_cidr_discovery_chunks_fping_calls_for_large_range(
        self,
        mock_fping: MagicMock,
        mock_ptr: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        mock_fping.return_value = []
        out = ipd.run_cidr_discovery(
            "203.0.113.0/24",
            dns_servers_raw=None,
            use_system_fallback=True,
            scan_id=None,
        )
        self.assertFalse(out.get("status"))
        self.assertEqual(mock_fping.call_count, 4)
        workspace_names = {call.kwargs.get("workspace_name") for call in mock_fping.call_args_list}
        self.assertEqual(len(workspace_names), 4)
        self.assertTrue(all(name and name.startswith("rengine-ephemeral-ip-discovery-c") for name in workspace_names))
        self.assertEqual(mock_ptr.call_count, 0)

    @patch("reNgine.services.ip_discovery_secator.emit_ip_scan_progress")
    @patch("reNgine.services.ip_discovery_secator.ptr_lookup", return_value=(None, None))
    @patch("reNgine.services.ip_discovery_secator.run_fping_sync")
    def test_run_cidr_discovery_calls_fping_without_live_dns_flags(
        self,
        mock_fping: MagicMock,
        mock_ptr: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        from secator.output_types import Ip as SecatorIp

        mock_fping.return_value = [
            SecatorIp(ip="203.0.113.10", host="host.example.test", alive=True),
        ]
        out = ipd.run_cidr_discovery(
            "203.0.113.10",
            dns_servers_raw=None,
            use_system_fallback=True,
            scan_id=None,
        )
        self.assertTrue(out.get("status"))
        self.assertEqual(out.get("total_hosts"), 1)
        mock_fping.assert_called_once()
        _args, kwargs = mock_fping.call_args
        self.assertEqual(_args[0], ["203.0.113.10"])
        self.assertFalse(kwargs.get("use_dns"))
        self.assertFalse(kwargs.get("show_name"))

    @patch("reNgine.services.ip_discovery_secator.emit_ip_scan_progress")
    @patch("reNgine.services.ip_discovery_secator.ptr_lookup", return_value=(None, None))
    @patch("reNgine.services.ip_discovery_secator.run_fping_sync")
    def test_run_cidr_discovery_sets_large_range_warning_for_more_than_slash24(
        self,
        mock_fping: MagicMock,
        mock_ptr: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        mock_fping.return_value = []
        out = ipd.run_cidr_discovery(
            "203.0.112.0/23",
            dns_servers_raw=None,
            use_system_fallback=True,
            scan_id=None,
        )
        self.assertTrue(out.get("range_warning"))

    @patch("reNgine.services.ip_discovery_secator.emit_ip_scan_progress")
    @patch("reNgine.services.ip_discovery_secator.run_fping_sync")
    @patch("reNgine.services.ip_discovery_secator.ptr_lookup")
    def test_run_cidr_discovery_attempts_ptr_for_each_unresolved_ip(
        self,
        mock_ptr: MagicMock,
        mock_fping: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        from secator.output_types import Ip as SecatorIp

        mock_fping.return_value = [
            SecatorIp(ip="203.0.113.1", host="", alive=True),
            SecatorIp(ip="203.0.113.2", host="", alive=True),
            SecatorIp(ip="203.0.113.3", host="", alive=False),
            SecatorIp(ip="203.0.113.4", host="", alive=False),
            SecatorIp(ip="203.0.113.5", host="", alive=False),
        ]
        mock_ptr.return_value = (None, None)
        out = ipd.run_cidr_discovery(
            "203.0.113.0/29",
            dns_servers_raw=None,
            use_system_fallback=True,
            scan_id=None,
        )
        self.assertEqual(out.get("total_hosts"), 5)
        self.assertEqual(mock_ptr.call_count, 5)


class TestPingHostsV2Api(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()

    def tearDown(self) -> None:
        cache.clear()
        super().tearDown()

    def test_post_rejects_non_list(self) -> None:
        url = reverse("api:ping_hosts_v2")
        response = self.client.post(
            url,
            data=json.dumps({"ip_list": "203.0.113.1"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_rejects_empty_valid_ips(self) -> None:
        url = reverse("api:ping_hosts_v2")
        response = self.client.post(
            url,
            data=json.dumps({"ip_list": ["not-ip"]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("reNgine.services.ip_discovery_secator.emit_ip_scan_progress")
    @patch("reNgine.services.ip_discovery_secator.run_ping_for_ips")
    def test_ping_worker_writes_cache_and_result_shape(
        self,
        mock_ping: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        mock_ping.return_value = {"203.0.113.20": True, "203.0.113.21": False}
        key = PING_CACHE_KEY % ("test-task-id",)
        cache.set(key, {"status": True, "task_status": "running", "result": None}, timeout=600)
        views_ip_discovery._ping_worker(key, ["203.0.113.20", "203.0.113.21"], None)
        mock_emit.assert_called()
        entry = cache.get(key)
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.get("task_status"), "completed")
        result = entry.get("result") or {}
        self.assertEqual(result.get("alive_count"), 1)
        self.assertEqual(result.get("total_count"), 2)
        self.assertIn("ping_results", result)

    @patch("reNgine.services.ip_discovery_secator.emit_ip_scan_progress")
    @patch("api.views_ip_discovery.threading.Thread", _SyncThread)
    @patch("reNgine.services.ip_discovery_secator.run_ping_for_ips")
    def test_post_then_get_returns_completed_when_worker_finishes(
        self,
        mock_ping: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        mock_ping.return_value = {"203.0.113.30": True}
        url_post = reverse("api:ping_hosts_v2")
        response = self.client.post(
            url_post,
            data=json.dumps({"ip_list": ["203.0.113.30"], "scan_id": "scan-test"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        task_id = response.data.get("task_id")
        self.assertIsNotNone(task_id)

        url_get = reverse("api:ping_hosts_v2")
        r2 = self.client.get(url_get, {"task_id": task_id})
        self.assertEqual(r2.status_code, status.HTTP_200_OK)
        self.assertEqual(r2.data.get("task_status"), "completed")
        self.assertTrue(r2.data.get("status"))
        result = r2.data.get("result") or {}
        self.assertTrue(result.get("ping_results", {}).get("203.0.113.30"))
        mock_emit.assert_called()

    def test_get_unknown_task_returns_404(self) -> None:
        url = reverse("api:ping_hosts_v2")
        response = self.client.get(url, {"task_id": "00000000-0000-0000-0000-000000000000"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
