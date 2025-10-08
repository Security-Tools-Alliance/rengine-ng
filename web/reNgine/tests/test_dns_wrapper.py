"""
Unit tests for DNS wrapper functionality.

Tests the DNS argument injection for various reconnaissance tools.
"""

from unittest.mock import MagicMock

from reNgine.utilities.dns_wrapper import (
    build_command_with_dns,
    get_dns_args,
    get_domain_dns_servers,
    tool_supports_custom_dns,
)
from utils.test_base import BaseTestCase


class TestDNSWrapper(BaseTestCase):
    """Test DNS wrapper utility functions."""

    def test_get_dns_args_subfinder(self):
        """Test DNS arguments for subfinder."""
        args = get_dns_args("subfinder", ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(args, ["-r", "8.8.8.8,1.1.1.1"])

    def test_get_dns_args_nmap(self):
        """Test DNS arguments for nmap."""
        args = get_dns_args("nmap", ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(args, ["--dns-servers", "8.8.8.8,1.1.1.1"])

    def test_get_dns_args_massdns(self):
        """Test DNS arguments for massdns (space-separated)."""
        args = get_dns_args("massdns", ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(args, ["-r", "8.8.8.8", "-r", "1.1.1.1"])

    def test_get_dns_args_dig(self):
        """Test DNS arguments for dig (@ format, first only)."""
        args = get_dns_args("dig", ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(args, ["@8.8.8.8"])

    def test_get_dns_args_no_support(self):
        """Test tool without DNS support returns empty list."""
        args = get_dns_args("assetfinder", ["8.8.8.8"])
        self.assertEqual(args, [])

    def test_get_dns_args_empty_servers(self):
        """Test empty DNS servers list returns empty args."""
        args = get_dns_args("subfinder", [])
        self.assertEqual(args, [])

    def test_tool_supports_custom_dns_true(self):
        """Test tool support check for supported tools."""
        self.assertTrue(tool_supports_custom_dns("subfinder"))
        self.assertTrue(tool_supports_custom_dns("nmap"))
        self.assertTrue(tool_supports_custom_dns("dnsx"))

    def test_tool_supports_custom_dns_false(self):
        """Test tool support check for unsupported tools."""
        self.assertFalse(tool_supports_custom_dns("assetfinder"))
        self.assertFalse(tool_supports_custom_dns("gospider"))
        self.assertFalse(tool_supports_custom_dns("unknown_tool"))

    def test_build_command_with_dns_explicit(self):
        """Test building command with explicit DNS servers."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["8.8.8.8"])
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8", "-d", "example.com"])

    def test_build_command_with_dns_domain_object(self):
        """Test building command with domain object."""
        # Create mock domain with custom DNS
        mock_domain = MagicMock()
        mock_domain.get_dns_servers.return_value = ["172.16.0.1", "192.168.1.2"]

        command = build_command_with_dns("nmap", ["-sS", "192.168.1.1"], domain=mock_domain)

        self.assertEqual(command, ["nmap", "--dns-servers", "172.16.0.1,192.168.1.2", "-sS", "192.168.1.1"])

    def test_build_command_with_dns_no_dns(self):
        """Test building command without DNS (should be unchanged)."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"])
        self.assertEqual(command, ["subfinder", "-d", "example.com"])

    def test_build_command_with_dns_tool_no_support(self):
        """Test building command for tool without DNS support."""
        command = build_command_with_dns("assetfinder", ["--subs-only", "example.com"], dns_servers=["8.8.8.8"])
        # DNS args should not be added for unsupported tools
        self.assertEqual(command, ["assetfinder", "--subs-only", "example.com"])

    def test_get_domain_dns_servers_with_dns(self):
        """Test getting DNS servers from domain object."""
        mock_domain = MagicMock()
        mock_domain.get_dns_servers.return_value = ["172.16.0.1"]

        dns_servers = get_domain_dns_servers(mock_domain)
        self.assertEqual(dns_servers, ["172.16.0.1"])

    def test_get_domain_dns_servers_no_method(self):
        """Test getting DNS servers from object without method."""
        mock_domain = MagicMock(spec=[])  # No get_dns_servers method

        dns_servers = get_domain_dns_servers(mock_domain)
        self.assertEqual(dns_servers, [])

    def test_get_domain_dns_servers_none(self):
        """Test getting DNS servers with None object."""
        dns_servers = get_domain_dns_servers(None)
        self.assertEqual(dns_servers, [])


class TestDNSWrapperIntegration(BaseTestCase):
    """Integration tests using actual Domain model."""

    def test_domain_with_custom_dns(self):
        """Test building command with actual Domain object with custom DNS."""
        from targetApp.models import Domain

        # Create test domain with custom DNS
        domain = Domain.objects.create(
            name="test-internal.local", project=self.data_generator.project, custom_dns_servers="172.16.0.1,192.168.1.2"
        )

        # Build command
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)

        # Verify DNS was added
        self.assertIn("-r", command)
        self.assertIn("172.16.0.1,192.168.1.2", command)

    def test_domain_without_custom_dns(self):
        """Test building command with Domain object without custom DNS."""
        from targetApp.models import Domain

        # Create test domain without custom DNS
        domain = Domain.objects.create(name="test-public.com", project=self.data_generator.project)

        # Build command
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)

        # Verify no DNS was added
        self.assertNotIn("-r", command)
        self.assertEqual(command, ["subfinder", "-d", domain.name])
