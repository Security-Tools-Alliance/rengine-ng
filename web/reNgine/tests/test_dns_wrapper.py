"""
Unit tests for DNS wrapper functionality.

Tests the DNS argument injection for various reconnaissance tools.
"""

from unittest.mock import MagicMock, patch

from reNgine.utilities.command import get_dns_command
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
        self.assertTrue(tool_supports_custom_dns("httpx"))
        self.assertTrue(tool_supports_custom_dns("nuclei"))
        self.assertTrue(tool_supports_custom_dns("katana"))
        self.assertTrue(tool_supports_custom_dns("tlsx"))

    def test_tool_supports_custom_dns_false(self):
        """Test tool support check for unsupported tools."""
        self.assertFalse(tool_supports_custom_dns("gospider"))
        self.assertFalse(tool_supports_custom_dns("unknown_tool"))

    def test_build_command_with_dns_explicit(self):
        """Test building command with explicit DNS servers."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["8.8.8.8"])
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8", "-d", "example.com"])

    def test_build_command_with_dns_domain_object(self):
        """Test building command with domain object."""
        from unittest.mock import MagicMock

        # Create mock domain with custom DNS
        mock_domain = MagicMock()
        mock_domain.get_dns_servers.return_value = ["172.16.0.1", "192.168.1.2"]

        command = build_command_with_dns("nmap", ["-sS", "192.168.1.1"], domain=mock_domain)

        self.assertEqual(command, ["nmap", "--dns-servers", "172.16.0.1,192.168.1.2", "-sS", "192.168.1.1"])

    def test_build_command_with_dns_domain_object_empty_dns(self):
        """Test building command with domain object returning empty DNS list."""
        from unittest.mock import MagicMock

        mock_domain = MagicMock()
        mock_domain.get_dns_servers.return_value = []

        command = build_command_with_dns("nmap", ["-sS", "192.168.1.1"], domain=mock_domain)

        # Should not add any --dns-servers argument if list is empty
        self.assertEqual(command, ["nmap", "-sS", "192.168.1.1"])

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

    def test_build_command_with_existing_dns_args(self):
        """Test that existing DNS arguments are not duplicated."""
        # Test with subfinder that uses -r flag
        command = build_command_with_dns("subfinder", ["-r", "9.9.9.9", "-d", "example.com"], dns_servers=["8.8.8.8"])
        # Should detect existing -r flag and not add new DNS
        self.assertIn("-r", command)
        self.assertIn("9.9.9.9", command)
        # Should not have duplicate DNS injection
        dns_flag_count = command.count("-r")
        self.assertEqual(dns_flag_count, 1, "DNS flag should appear only once")

    def test_build_command_with_existing_dns_args_nmap(self):
        """Test that existing DNS arguments are not duplicated for nmap."""
        command = build_command_with_dns(
            "nmap", ["--dns-servers", "9.9.9.9", "-sS", "192.168.1.1"], dns_servers=["8.8.8.8"]
        )
        # Should detect existing --dns-servers flag and not add new DNS
        self.assertIn("--dns-servers", command)
        self.assertIn("9.9.9.9", command)
        # Should not have duplicate DNS injection
        dns_flag_count = command.count("--dns-servers")
        self.assertEqual(dns_flag_count, 1, "DNS flag should appear only once")


class TestDNSWrapperInvalidInput(BaseTestCase):
    """Test DNS wrapper with invalid or malformed inputs."""

    def test_build_command_with_empty_string_in_dns_list(self):
        """Test building command with empty string in DNS server list."""
        # Empty strings are now filtered out by build_command_with_dns
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["8.8.8.8", "", "1.1.1.1"])
        # Should only include non-empty DNS servers
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8,1.1.1.1", "-d", "example.com"])

    def test_build_command_with_none_in_dns_list(self):
        """Test building command with None value in DNS server list."""
        # None values are now filtered out by build_command_with_dns
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["8.8.8.8", None, "1.1.1.1"])
        # Should only include non-None DNS servers
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8,1.1.1.1", "-d", "example.com"])

    def test_get_dns_args_with_invalid_ip_format(self):
        """Test DNS arguments with non-IP string values."""
        # Non-IP strings should still be passed through (no IP validation in get_dns_args)
        args = get_dns_args("subfinder", ["notanip", "invalid.server", "999.999.999.999"])
        self.assertEqual(args, ["-r", "notanip,invalid.server,999.999.999.999"])

    def test_get_dns_args_with_special_characters(self):
        """Test DNS arguments with special characters."""
        args = get_dns_args("subfinder", ["8.8.8.8;rm -rf", "1.1.1.1 && echo"])
        # Should pass through as-is (command injection protection is elsewhere)
        self.assertIsInstance(args, list)
        self.assertEqual(len(args), 2)

    def test_build_command_with_dns_none_servers(self):
        """Test building command with None as dns_servers."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=None)
        # Should return command without DNS args
        self.assertEqual(command, ["subfinder", "-d", "example.com"])

    def test_build_command_with_dns_empty_string_server(self):
        """Test building command with only empty string as DNS server."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=[""])
        # Should filter out empty strings and not add DNS args
        self.assertEqual(command, ["subfinder", "-d", "example.com"])

    def test_build_command_with_dns_single_string(self):
        """Test building command with single string instead of list."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers="8.8.8.8")
        # Function should convert string to list
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8", "-d", "example.com"])

    def test_build_command_with_dns_mixed_valid_invalid(self):
        """Test building command with mixed valid and invalid DNS values."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["8.8.8.8", "", "1.1.1.1"])
        # Should filter out empty strings and keep valid ones
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8,1.1.1.1", "-d", "example.com"])

    def test_build_command_with_dns_whitespace_only(self):
        """Test building command with whitespace-only DNS servers."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["   ", "\t", "\n"])
        # Should filter out whitespace-only strings and not add DNS args
        self.assertEqual(command, ["subfinder", "-d", "example.com"])

    def test_build_command_with_dns_numeric_port(self):
        """Test building command with DNS server including port."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["8.8.8.8:53"])
        # Should pass through (port validation is tool-specific)
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8:53", "-d", "example.com"])

    def test_build_command_with_base_args_none(self):
        """Test building command with None as base_args."""
        command = build_command_with_dns("subfinder", None, dns_servers=["8.8.8.8"])
        # Should handle None base_args gracefully
        self.assertIsInstance(command, list)
        self.assertIn("subfinder", command)
        self.assertIn("-r", command)
        self.assertIn("8.8.8.8", command)

    def test_build_command_with_base_args_empty_list(self):
        """Test building command with empty base_args list."""
        command = build_command_with_dns("subfinder", [], dns_servers=["8.8.8.8"])
        # Should build command with only tool name and DNS args
        self.assertEqual(command, ["subfinder", "-r", "8.8.8.8"])

    def test_build_command_with_ipv6_dns(self):
        """Test building command with IPv6 DNS servers."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["2001:4860:4860::8888"])
        # Should handle IPv6 addresses
        self.assertEqual(command, ["subfinder", "-r", "2001:4860:4860::8888", "-d", "example.com"])

    def test_build_command_with_localhost_dns(self):
        """Test building command with localhost DNS servers."""
        command = build_command_with_dns("subfinder", ["-d", "example.com"], dns_servers=["127.0.0.1", "localhost"])
        # Should handle localhost addresses
        self.assertIn("-r", command)
        self.assertIn("127.0.0.1,localhost", command)

    def test_get_dns_args_with_very_long_list(self):
        """Test DNS arguments with very long list of servers."""
        dns_servers = [f"8.8.8.{i}" for i in range(100)]
        args = get_dns_args("subfinder", dns_servers)
        # Should handle large lists
        self.assertIsInstance(args, list)
        self.assertEqual(len(args), 2)  # ["-r", "comma-separated-list"]
        self.assertIn("-r", args)

    def test_build_command_domain_with_none_dns_method(self):
        """Test building command when domain.get_dns_servers() returns None."""
        mock_domain = MagicMock()
        mock_domain.get_dns_servers.return_value = None

        command = build_command_with_dns("subfinder", ["-d", "example.com"], domain=mock_domain)
        # Should handle None return gracefully
        self.assertEqual(command, ["subfinder", "-d", "example.com"])


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

    def test_domain_with_malformed_dns_extra_commas(self):
        """Test Domain with extra commas in custom_dns_servers."""
        from targetApp.models import Domain

        # Create domain with extra commas
        domain = Domain.objects.create(
            name="test-malformed1.local",
            project=self.data_generator.project,
            custom_dns_servers="8.8.8.8,,1.1.1.1,,,9.9.9.9",
        )

        # get_dns_servers should filter out empty strings from extra commas
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])

        # Build command should work correctly
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        self.assertIn("8.8.8.8,1.1.1.1,9.9.9.9", command)

    def test_domain_with_malformed_dns_extra_whitespace(self):
        """Test Domain with extra whitespace in custom_dns_servers."""
        from targetApp.models import Domain

        # Create domain with extra whitespace
        domain = Domain.objects.create(
            name="test-malformed2.local",
            project=self.data_generator.project,
            custom_dns_servers="  8.8.8.8  ,  1.1.1.1  , 9.9.9.9  ",
        )

        # get_dns_servers should strip whitespace
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])

        # Build command should work correctly
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        self.assertIn("8.8.8.8,1.1.1.1,9.9.9.9", command)

    def test_domain_with_malformed_dns_leading_trailing_commas(self):
        """Test Domain with leading/trailing commas in custom_dns_servers."""
        from targetApp.models import Domain

        # Create domain with leading/trailing commas
        domain = Domain.objects.create(
            name="test-malformed3.local", project=self.data_generator.project, custom_dns_servers=",8.8.8.8,1.1.1.1,"
        )

        # get_dns_servers should handle leading/trailing commas
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, ["8.8.8.8", "1.1.1.1"])

        # Build command should work correctly
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        self.assertIn("8.8.8.8,1.1.1.1", command)

    def test_domain_with_malformed_dns_whitespace_only(self):
        """Test Domain with whitespace-only custom_dns_servers."""
        from targetApp.models import Domain

        # Create domain with only whitespace
        domain = Domain.objects.create(
            name="test-malformed4.local", project=self.data_generator.project, custom_dns_servers="   ,  ,   "
        )

        # get_dns_servers should return empty list
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, [])

        # Build command should not add DNS args
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertNotIn("-r", command)
        self.assertEqual(command, ["subfinder", "-d", domain.name])

    def test_domain_with_malformed_dns_empty_string(self):
        """Test Domain with empty string as custom_dns_servers."""
        from targetApp.models import Domain

        # Create domain with empty string
        domain = Domain.objects.create(
            name="test-malformed5.local", project=self.data_generator.project, custom_dns_servers=""
        )

        # get_dns_servers should return empty list
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, [])

        # Build command should not add DNS args
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertNotIn("-r", command)
        self.assertEqual(command, ["subfinder", "-d", domain.name])

    def test_domain_with_invalid_ip_formats(self):
        """Test Domain with invalid IP formats in custom_dns_servers."""
        from targetApp.models import Domain

        # Create domain with invalid IP formats (no validation in model)
        domain = Domain.objects.create(
            name="test-malformed6.local",
            project=self.data_generator.project,
            custom_dns_servers="999.999.999.999,notanip,256.256.256.256",
        )

        # get_dns_servers should return the values as-is (no IP validation)
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, ["999.999.999.999", "notanip", "256.256.256.256"])

        # Build command should pass them through (validation is tool-specific)
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        self.assertIn("999.999.999.999,notanip,256.256.256.256", command)

    def test_domain_with_mixed_valid_invalid_dns(self):
        """Test Domain with mixed valid and invalid DNS entries."""
        from targetApp.models import Domain

        # Create domain with mix of valid IPs and invalid entries
        domain = Domain.objects.create(
            name="test-malformed7.local",
            project=self.data_generator.project,
            custom_dns_servers="8.8.8.8,,notanip,  ,1.1.1.1, , invalid.server,  9.9.9.9  ",
        )

        # get_dns_servers should filter empty entries but keep invalid IPs
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, ["8.8.8.8", "notanip", "1.1.1.1", "invalid.server", "9.9.9.9"])

        # Build command should work with the filtered list
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        # Note: build_command_with_dns will rejoin with commas
        self.assertIn("8.8.8.8,notanip,1.1.1.1,invalid.server,9.9.9.9", command)

    def test_domain_with_ipv6_addresses(self):
        """Test Domain with IPv6 addresses in custom_dns_servers."""
        from targetApp.models import Domain

        # Create domain with IPv6 addresses
        domain = Domain.objects.create(
            name="test-ipv6.local",
            project=self.data_generator.project,
            custom_dns_servers="2001:4860:4860::8888,2001:4860:4860::8844",
        )

        # get_dns_servers should handle IPv6
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, ["2001:4860:4860::8888", "2001:4860:4860::8844"])

        # Build command should work with IPv6
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        self.assertIn("2001:4860:4860::8888,2001:4860:4860::8844", command)

    def test_domain_with_dns_ports(self):
        """Test Domain with DNS servers including ports."""
        from targetApp.models import Domain

        # Create domain with DNS servers including ports
        domain = Domain.objects.create(
            name="test-ports.local", project=self.data_generator.project, custom_dns_servers="8.8.8.8:53,1.1.1.1:5353"
        )

        # get_dns_servers should keep port information
        dns_servers = domain.get_dns_servers()
        self.assertEqual(dns_servers, ["8.8.8.8:53", "1.1.1.1:5353"])

        # Build command should pass through ports
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        self.assertIn("8.8.8.8:53,1.1.1.1:5353", command)

    def test_domain_with_very_long_dns_list(self):
        """Test Domain with very long list of DNS servers."""
        from targetApp.models import Domain

        # Create domain with many DNS servers
        dns_list = ",".join([f"10.0.0.{i}" for i in range(1, 51)])
        domain = Domain.objects.create(
            name="test-long-list.local", project=self.data_generator.project, custom_dns_servers=dns_list
        )

        # get_dns_servers should handle large lists
        dns_servers = domain.get_dns_servers()
        self.assertEqual(len(dns_servers), 50)

        # Build command should work with large lists
        command = build_command_with_dns("subfinder", ["-d", domain.name], domain=domain)
        self.assertIn("-r", command)
        # Verify command is constructed properly
        self.assertIsInstance(command, list)
        self.assertIn("subfinder", command)


class TestGetDNSCommand(BaseTestCase):
    """Test get_dns_command function with error handling."""

    def test_get_dns_command_with_valid_scan(self):
        """Test get_dns_command with valid scan ID and custom DNS."""
        from django.utils import timezone

        from startScan.models import ScanHistory
        from targetApp.models import Domain

        # Create domain with custom DNS
        domain = Domain.objects.create(
            name="test.local", project=self.data_generator.project, custom_dns_servers="8.8.8.8,1.1.1.1"
        )

        # Create scan
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=self.data_generator.default_engine, celery_ids=[], start_scan_date=timezone.now()
        )

        # Test command injection
        original_cmd = "subfinder -d test.local"
        modified_cmd = get_dns_command(scan.id, original_cmd)

        # Should have DNS args added
        self.assertIn("-r", modified_cmd)
        self.assertIn("8.8.8.8,1.1.1.1", modified_cmd)

    def test_get_dns_command_with_invalid_scan_id(self):
        """Test get_dns_command with non-existent scan ID."""
        # Use a scan ID that doesn't exist
        original_cmd = "subfinder -d test.local"
        result_cmd = get_dns_command(99999, original_cmd)

        # Should return original command unchanged
        self.assertEqual(result_cmd, original_cmd)

    def test_get_dns_command_with_none_scan_id(self):
        """Test get_dns_command with None as scan_id."""
        original_cmd = "subfinder -d test.local"
        result_cmd = get_dns_command(None, original_cmd)

        # Should return original command unchanged
        self.assertEqual(result_cmd, original_cmd)

    def test_get_dns_command_with_scan_without_domain(self):
        """Test get_dns_command when domain is not set (edge case)."""
        # Note: In practice, ScanHistory requires a domain (NOT NULL constraint)
        # This tests the error handling when scan_id is valid but scan.domain is somehow None
        # We use a mock instead of creating an invalid DB object
        from unittest.mock import MagicMock, patch

        # Mock a scan with no domain
        with patch("reNgine.utilities.command.ScanHistory.objects.get") as mock_get:
            mock_scan = MagicMock()
            mock_scan.domain = None
            mock_get.return_value = mock_scan

            original_cmd = "subfinder -d test.local"
            result_cmd = get_dns_command(999, original_cmd)

            # Should return original command unchanged (no domain)
            self.assertEqual(result_cmd, original_cmd)

    def test_get_dns_command_with_domain_without_dns(self):
        """Test get_dns_command with domain that has no custom DNS."""
        from django.utils import timezone

        from startScan.models import ScanHistory
        from targetApp.models import Domain

        # Create domain without custom DNS
        domain = Domain.objects.create(name="test-no-dns.local", project=self.data_generator.project)

        # Create scan
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=self.data_generator.default_engine, celery_ids=[], start_scan_date=timezone.now()
        )

        original_cmd = "subfinder -d test.local"
        result_cmd = get_dns_command(scan.id, original_cmd)

        # Should return original command (no custom DNS)
        self.assertEqual(result_cmd, original_cmd)

    def test_get_dns_command_with_complex_command(self):
        """Test get_dns_command with complex command containing quotes and arguments."""
        from django.utils import timezone

        from startScan.models import ScanHistory
        from targetApp.models import Domain

        # Create domain with custom DNS
        domain = Domain.objects.create(
            name="test-complex.local", project=self.data_generator.project, custom_dns_servers="9.9.9.9"
        )

        # Create scan
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=self.data_generator.default_engine, celery_ids=[], start_scan_date=timezone.now()
        )

        # Test with complex command
        original_cmd = 'subfinder -d "test.local" -o output.txt'
        modified_cmd = get_dns_command(scan.id, original_cmd)

        # Should have DNS args added
        self.assertIn("-r", modified_cmd)
        self.assertIn("9.9.9.9", modified_cmd)

    def test_get_dns_command_preserves_tool_path(self):
        """Test that get_dns_command preserves full tool path."""
        from django.utils import timezone

        from startScan.models import ScanHistory
        from targetApp.models import Domain

        # Create domain with custom DNS
        domain = Domain.objects.create(
            name="test-path.local", project=self.data_generator.project, custom_dns_servers="8.8.8.8"
        )

        # Create scan
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=self.data_generator.default_engine, celery_ids=[], start_scan_date=timezone.now()
        )

        # Test with full path to tool
        original_cmd = "/usr/local/bin/subfinder -d test.local"
        modified_cmd = get_dns_command(scan.id, original_cmd)

        # Should preserve the full path
        self.assertIn("/usr/local/bin/subfinder", modified_cmd)
        # Should have DNS args added
        self.assertIn("-r", modified_cmd)
        self.assertIn("8.8.8.8", modified_cmd)

    @patch("reNgine.utilities.command.build_command_with_dns")
    def test_get_dns_command_handles_build_error(self, mock_build):
        """Test get_dns_command handles errors from build_command_with_dns."""
        from django.utils import timezone

        from startScan.models import ScanHistory
        from targetApp.models import Domain

        # Create domain with custom DNS
        domain = Domain.objects.create(
            name="test-error.local", project=self.data_generator.project, custom_dns_servers="8.8.8.8"
        )

        # Create scan
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=self.data_generator.default_engine, celery_ids=[], start_scan_date=timezone.now()
        )

        # Mock build_command_with_dns to raise an exception
        mock_build.side_effect = Exception("Test error")

        original_cmd = "subfinder -d test.local"
        result_cmd = get_dns_command(scan.id, original_cmd)

        # Should return original command on error
        self.assertEqual(result_cmd, original_cmd)

    def test_get_dns_command_with_malformed_command(self):
        """Test get_dns_command with malformed command string."""
        from django.utils import timezone

        from startScan.models import ScanHistory
        from targetApp.models import Domain

        # Create domain with custom DNS
        domain = Domain.objects.create(
            name="test-malformed.local", project=self.data_generator.project, custom_dns_servers="8.8.8.8"
        )

        # Create scan
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=self.data_generator.default_engine, celery_ids=[], start_scan_date=timezone.now()
        )

        # Test with malformed command (unmatched quotes)
        original_cmd = 'subfinder -d "test.local'
        result_cmd = get_dns_command(scan.id, original_cmd)

        # Should handle gracefully and attempt to process
        self.assertIsInstance(result_cmd, str)
