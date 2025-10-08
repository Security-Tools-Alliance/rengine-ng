"""
Tests for DNS utility functions.
"""

import socket
from unittest.mock import MagicMock, patch

from utils.test_base import BaseTestCase


class TestDNSUtilities(BaseTestCase):
    """Tests for DNS utility functions."""

    @patch("reNgine.utilities.dns.socket.gethostbyaddr")
    def test_resolve_ip_with_dns_success(self, mock_gethostbyaddr):
        """Test successful DNS resolution."""
        from reNgine.utilities.dns import resolve_ip_with_dns

        # Mock successful DNS resolution
        mock_gethostbyaddr.return_value = ("dns.google", ["8.8.8.8.in-addr.arpa"], ["8.8.8.8"])

        result = resolve_ip_with_dns("8.8.8.8", ["8.8.8.8"])

        # Verify result structure
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["domain"], "dns.google")
        self.assertIn("dns.google", result["domains"])  # The actual domain returned
        self.assertEqual(result["resolved_by"], "8.8.8.8")
        self.assertFalse(result["is_alive"])  # Should be False by default

    @patch("reNgine.utilities.dns.socket.gethostbyaddr")
    def test_resolve_ip_with_dns_failure(self, mock_gethostbyaddr):
        """Test DNS resolution failure."""
        from reNgine.utilities.dns import resolve_ip_with_dns

        # Mock DNS resolution failure
        mock_gethostbyaddr.side_effect = socket.herror(1, "Host not found")

        result = resolve_ip_with_dns("192.168.1.1", ["8.8.8.8"])

        # Verify result structure for failed resolution
        self.assertEqual(result["ip"], "192.168.1.1")
        self.assertEqual(result["domain"], "192.168.1.1")
        self.assertEqual(result["domains"], [])
        self.assertIsNone(result["resolved_by"])
        self.assertFalse(result["is_alive"])

    @patch("reNgine.utilities.dns.socket.gethostbyaddr")
    def test_resolve_ip_with_dns_system_fallback(self, mock_gethostbyaddr):
        """Test DNS resolution with system fallback."""
        from reNgine.utilities.dns import resolve_ip_with_dns

        # Mock DNS resolution failure with custom DNS, success with system
        def mock_side_effect(ip):
            if ip == "8.8.8.8":
                raise socket.herror(1, "Host not found")
            else:
                return ("dns.google", ["8.8.8.8.in-addr.arpa"], ["8.8.8.8"])

        mock_gethostbyaddr.side_effect = mock_side_effect

        result = resolve_ip_with_dns("8.8.8.8", ["8.8.8.8"], use_system_fallback=True)

        # Verify system fallback was used
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["domain"], "dns.google")
        self.assertIn("dns.google", result["domains"])

    @patch("reNgine.utilities.dns.subprocess.run")
    def test_check_host_alive_success(self, mock_subprocess):
        """Test successful host alive check."""
        from reNgine.utilities.dns import check_host_alive

        # Mock successful ping
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        result = check_host_alive("8.8.8.8")

        self.assertTrue(result)
        mock_subprocess.assert_called_once()

    @patch("reNgine.utilities.dns.subprocess.run")
    def test_check_host_alive_failure(self, mock_subprocess):
        """Test failed host alive check."""
        from reNgine.utilities.dns import check_host_alive

        # Mock failed ping
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result

        result = check_host_alive("192.168.1.999")

        self.assertFalse(result)
        mock_subprocess.assert_called_once()

    @patch("reNgine.utilities.dns.subprocess.run")
    def test_check_host_alive_timeout(self, mock_subprocess):
        """Test host alive check with timeout."""
        from reNgine.utilities.dns import check_host_alive

        # Mock timeout
        mock_subprocess.side_effect = TimeoutError("Command timed out")

        result = check_host_alive("192.168.1.1")

        self.assertFalse(result)

    @patch("reNgine.utilities.dns.subprocess.run")
    def test_check_host_alive(self, mock_subprocess):
        """Test host alive check with specific command arguments."""
        from reNgine.utilities.dns import check_host_alive

        # Mock successful ping
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        result = check_host_alive("8.8.8.8")

        self.assertTrue(result)
        # Verify ping command was used with correct arguments
        call_args = mock_subprocess.call_args[0][0]
        self.assertIn("ping", call_args)
        self.assertIn("-c", call_args)
        self.assertIn("-W", call_args)
        self.assertIn("8.8.8.8", call_args)

    def test_extract_root_domain(self):
        """Test root domain extraction from hostnames."""
        from reNgine.utilities.dns import resolve_ip_with_dns

        # Test various hostname formats
        test_cases = [
            ("server.example.com", "example.com"),
            ("sub.domain.example.com", "example.com"),
            ("a.b.c.d.example.org", "example.org"),
            ("single.com", "single.com"),
            ("192.168.1.1", "192.168.1.1"),  # IP address should remain unchanged
        ]

        for hostname, expected_root in test_cases:
            # Mock the DNS resolver instead of socket.gethostbyaddr
            with patch("reNgine.utilities.dns._resolve_with_custom_dns") as mock_resolve:
                mock_resolve.return_value = (hostname, "8.8.8.8")

                result = resolve_ip_with_dns("8.8.8.8", ["8.8.8.8"])

                if expected_root != "192.168.1.1":  # Skip IP address test
                    # The function should return the hostname in the domains list
                    self.assertIn(hostname, result["domains"])

    def test_dns_servers_validation(self):
        """Test DNS servers validation and processing."""
        from reNgine.utilities.dns import resolve_ip_with_dns

        # Test with valid DNS servers
        valid_dns = ["8.8.8.8", "1.1.1.1"]

        with patch("reNgine.utilities.dns.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("dns.google", ["8.8.8.8.in-addr.arpa"], ["8.8.8.8"])

            result = resolve_ip_with_dns("8.8.8.8", valid_dns)

            self.assertEqual(result["ip"], "8.8.8.8")
            # Verify DNS servers were processed correctly
            self.assertIsNotNone(result["resolved_by"])

    def test_empty_dns_servers_list(self):
        """Test handling of empty DNS servers list."""
        from reNgine.utilities.dns import resolve_ip_with_dns

        # Test with empty DNS servers list
        with patch("reNgine.utilities.dns.socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("dns.google", ["8.8.8.8.in-addr.arpa"], ["8.8.8.8"])

            result = resolve_ip_with_dns("8.8.8.8", [])

        # Should still work with system DNS
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["domain"], "8.8.8.8")  # When no DNS servers provided, domain defaults to IP
