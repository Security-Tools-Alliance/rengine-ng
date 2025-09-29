"""
Tests for DNS-related Celery tasks.
"""

from unittest.mock import MagicMock, patch

from utils.test_base import BaseTestCase


class TestIPRangeDiscovery(BaseTestCase):
    """Tests for the ip_range_discovery Celery task."""

    @patch("reNgine.utilities.dns.resolve_ip_with_dns")
    def test_ip_range_discovery_single_ip(self, mock_resolve_ip):
        """Test IP range discovery for a single IP address."""
        from reNgine.tasks.dns import ip_range_discovery

        # Mock DNS resolution result
        mock_resolve_ip.return_value = {
            "ip": "8.8.8.8",
            "domain": "dns.google",
            "domains": ["dns.google"],
            "ips": ["8.8.8.8"],
            "resolved_by": "8.8.8.8",
            "is_alive": False,
        }

        # Test single IP
        result = ip_range_discovery("8.8.8.8", scan_id="test-scan-id")

        # Verify result structure
        self.assertTrue(result["status"])
        self.assertEqual(result["orig"], "8.8.8.8")
        self.assertEqual(len(result["ip_address"]), 1)
        self.assertEqual(result["ip_address"][0]["ip"], "8.8.8.8")
        self.assertEqual(result["ip_address"][0]["domain"], "dns.google")
        self.assertIn("dns.google", result["discovered_domains"])
        self.assertTrue(result["ping_required"])
        self.assertEqual(result["total_hosts"], 1)

    @patch("reNgine.utilities.dns.resolve_ip_with_dns")
    def test_ip_range_discovery_cidr_range(self, mock_resolve_ip):
        """Test IP range discovery for a CIDR range."""
        from reNgine.tasks.dns import ip_range_discovery

        # Mock DNS resolution results
        def mock_resolve_side_effect(ip, dns_servers, use_system_fallback=False):
            if ip == "192.168.1.1":
                return {
                    "ip": "192.168.1.1",
                    "domain": "router.local",
                    "domains": ["local"],
                    "ips": ["192.168.1.1"],
                    "resolved_by": "192.168.1.1",
                    "is_alive": False,
                }
            else:
                return {"ip": ip, "domain": ip, "domains": [], "ips": [ip], "resolved_by": None, "is_alive": False}

        mock_resolve_ip.side_effect = mock_resolve_side_effect

        # Test small CIDR range
        result = ip_range_discovery("192.168.1.0/30", scan_id="test-scan-id")

        # Verify result structure
        self.assertTrue(result["status"])
        self.assertEqual(result["orig"], "192.168.1.0/30")
        self.assertEqual(len(result["ip_address"]), 4)  # /30 = 4 IPs
        self.assertTrue(result["ping_required"])
        self.assertEqual(result["total_hosts"], 4)

    @patch("reNgine.utilities.dns.resolve_ip_with_dns")
    def test_ip_range_discovery_with_custom_dns(self, mock_resolve_ip):
        """Test IP range discovery with custom DNS servers."""
        from reNgine.tasks.dns import ip_range_discovery

        # Mock DNS resolution result
        mock_resolve_ip.return_value = {
            "ip": "8.8.8.8",
            "domain": "dns.google",
            "domains": ["dns.google"],
            "ips": ["8.8.8.8"],
            "resolved_by": "8.8.8.8",
            "is_alive": False,
        }

        # Test with custom DNS
        custom_dns = "8.8.8.8,1.1.1.1"
        result = ip_range_discovery("8.8.8.8", scan_id="test-scan-id", custom_dns=custom_dns)

        # Verify custom DNS was used
        self.assertTrue(result["status"])
        self.assertEqual(result["used_dns_servers"], ["8.8.8.8", "1.1.1.1"])

    @patch("reNgine.utilities.dns.resolve_ip_with_dns")
    def test_ip_range_discovery_websocket_progress(self, mock_resolve_ip):
        """Test that IP range discovery completes successfully."""
        from reNgine.tasks.dns import ip_range_discovery

        # Mock DNS resolution result
        mock_resolve_ip.return_value = {
            "ip": "8.8.8.8",
            "domain": "dns.google",
            "domains": ["dns.google"],
            "ips": ["8.8.8.8"],
            "resolved_by": "8.8.8.8",
            "is_alive": False,
        }

        # Test IP range discovery
        result = ip_range_discovery("8.8.8.8", scan_id="test-scan-id")

        # Verify task completed successfully
        self.assertTrue(result["status"])
        self.assertEqual(result["orig"], "8.8.8.8")
        self.assertEqual(len(result["ip_address"]), 1)
        self.assertTrue(result["ping_required"])

    def test_ip_range_discovery_invalid_ip(self):
        """Test IP range discovery with invalid IP format."""
        from reNgine.tasks.dns import ip_range_discovery

        # Test invalid IP
        result = ip_range_discovery("invalid-ip", scan_id="test-scan-id")

        # Verify error handling
        self.assertFalse(result["status"])
        self.assertIn("message", result)


class TestPingHostsTask(BaseTestCase):
    """Tests for the ping_hosts_task Celery task."""

    @patch("reNgine.utilities.dns.check_host_alive")
    @patch("reNgine.tasks.dns.get_channel_layer")
    def test_ping_hosts_task_success(self, mock_get_channel_layer, mock_check_alive):
        """Test successful ping hosts task execution."""
        from reNgine.tasks.dns import ping_hosts_task

        # Mock ping results
        def mock_ping_side_effect(ip):
            return ip in ["8.8.8.8", "1.1.1.1"]  # Only these IPs are alive

        mock_check_alive.side_effect = mock_ping_side_effect

        # Mock WebSocket channel layer
        mock_channel_layer = MagicMock()
        mock_get_channel_layer.return_value = mock_channel_layer

        # Test ping task
        ip_list = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
        result = ping_hosts_task(ip_list, scan_id="test-scan-id")

        # Verify result structure
        self.assertTrue(result["status"])
        self.assertIn("ping_results", result)
        self.assertEqual(result["alive_count"], 2)
        self.assertEqual(result["total_count"], 3)

        # Verify ping results
        self.assertTrue(result["ping_results"]["8.8.8.8"])
        self.assertTrue(result["ping_results"]["1.1.1.1"])
        self.assertFalse(result["ping_results"]["192.168.1.1"])

    @patch("reNgine.utilities.dns.check_host_alive")
    def test_ping_hosts_task_websocket_progress(self, mock_check_alive):
        """Test that ping task executes successfully with multiple IPs."""
        from reNgine.tasks.dns import ping_hosts_task

        # Mock ping results
        mock_check_alive.return_value = True

        # Test ping task with multiple IPs
        ip_list = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"]
        result = ping_hosts_task(ip_list, scan_id="test-scan-id")

        # Verify task completed successfully
        self.assertTrue(result["status"])
        self.assertEqual(result["alive_count"], 5)
        self.assertEqual(result["total_count"], 5)
        self.assertEqual(len(result["ping_results"]), 5)

        # Verify all IPs are marked as alive
        for ip in ip_list:
            self.assertTrue(result["ping_results"][ip])

    @patch("reNgine.utilities.dns.check_host_alive")
    def test_ping_hosts_task_no_scan_id(self, mock_check_alive):
        """Test ping hosts task without scan_id (no WebSocket)."""
        from reNgine.tasks.dns import ping_hosts_task

        # Mock ping results
        mock_check_alive.return_value = True

        # Test ping task without scan_id
        ip_list = ["8.8.8.8", "1.1.1.1"]
        result = ping_hosts_task(ip_list)

        # Verify result structure
        self.assertTrue(result["status"])
        self.assertEqual(result["alive_count"], 2)
        self.assertEqual(result["total_count"], 2)

    @patch("reNgine.utilities.dns.check_host_alive")
    def test_ping_hosts_task_ping_failure(self, mock_check_alive):
        """Test ping hosts task when ping checks fail."""
        from reNgine.tasks.dns import ping_hosts_task

        # Mock ping failure
        mock_check_alive.side_effect = Exception("Ping failed")

        # Test ping task
        ip_list = ["8.8.8.8"]
        result = ping_hosts_task(ip_list, scan_id="test-scan-id")

        # Verify result structure
        self.assertTrue(result["status"])
        self.assertEqual(result["alive_count"], 0)
        self.assertEqual(result["total_count"], 1)
        self.assertFalse(result["ping_results"]["8.8.8.8"])

    def test_ping_hosts_task_empty_ip_list(self):
        """Test ping hosts task with empty IP list."""
        from reNgine.tasks.dns import ping_hosts_task

        # Test with empty list
        result = ping_hosts_task([], scan_id="test-scan-id")

        # Verify result structure
        self.assertTrue(result["status"])
        self.assertEqual(result["alive_count"], 0)
        self.assertEqual(result["total_count"], 0)
        self.assertEqual(len(result["ping_results"]), 0)
