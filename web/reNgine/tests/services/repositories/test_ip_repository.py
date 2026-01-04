"""
Tests for IP repository functionality.
"""

from reNgine.services.repositories.ip_repository import IpRepository
from utils.test_base import BaseTestCase


class TestIpRepository(BaseTestCase):
    """Test cases for IpRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.ip_repo = IpRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def test_save_from_secator_valid_ipv4(self):
        """Test saving valid IPv4 address from Secator."""
        item = {
            "_type": "ip",
            "ip": "192.168.1.1",
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.168.1.1")
        self.assertEqual(result.version, 4)
        self.assertTrue(result.is_private)

    def test_save_from_secator_valid_ipv6(self):
        """Test saving valid IPv6 address from Secator."""
        item = {
            "_type": "ip",
            "ip": "2001:4860:4860::8888",  # Google DNS IPv6 (public)
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "2001:4860:4860::8888")
        self.assertEqual(result.version, 6)
        self.assertFalse(result.is_private)

    def test_save_from_secator_invalid_ip(self):
        """Test handling invalid IP address."""
        item = {
            "_type": "ip",
            "ip": "invalid-ip",
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_ip(self):
        """Test handling missing IP field."""
        item = {
            "_type": "ip",
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_get_or_create_valid_ip(self):
        """Test get_or_create with valid IP."""
        ip_address = "10.0.0.1"

        result, created = self.ip_repo.get_or_create(ip_address)

        self.assertIsNotNone(result)
        self.assertTrue(created)
        self.assertEqual(result.address, ip_address)
        self.assertTrue(result.is_private)

    def test_get_or_create_invalid_ip(self):
        """Test get_or_create with invalid IP."""
        ip_address = "invalid-ip"

        result, created = self.ip_repo.get_or_create(ip_address)

        self.assertIsNone(result)
        self.assertFalse(created)

    def test_bulk_create_valid_ips(self):
        """Test bulk creation of valid IPs."""
        ip_addresses = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]

        result = self.ip_repo.bulk_create(ip_addresses, self.scan_history.id, self.domain.id)

        self.assertEqual(len(result), 3)
        for ip_obj in result:
            self.assertIn(ip_obj.address, ip_addresses)

    def test_bulk_create_mixed_ips(self):
        """Test bulk creation with mixed valid/invalid IPs."""
        ip_addresses = ["192.168.1.1", "invalid-ip", "10.0.0.1"]

        result = self.ip_repo.bulk_create(ip_addresses, self.scan_history.id, self.domain.id)

        # Should only create valid IPs
        self.assertEqual(len(result), 2)
        valid_ips = [ip_obj.address for ip_obj in result]
        self.assertIn("192.168.1.1", valid_ips)
        self.assertIn("10.0.0.1", valid_ips)

    def test_update_geolocation(self):
        """Test updating geolocation data."""
        # First create an IP
        ip_obj, _ = self.ip_repo.get_or_create("8.8.8.8")
        self.assertIsNotNone(ip_obj)

        geo_data = {
            "country_iso": "US",
            "country_name": "United States",
        }

        result = self.ip_repo.update_geolocation(ip_obj.id, geo_data)

        self.assertTrue(result)

    def test_update_geolocation_nonexistent_ip(self):
        """Test updating geolocation for non-existent IP."""
        geo_data = {
            "country_iso": "US",
            "country_name": "United States",
        }

        result = self.ip_repo.update_geolocation(99999, geo_data)

        self.assertFalse(result)

    def test_is_private_ip_private(self):
        """Test private IP detection."""
        self.assertTrue(self.ip_repo._is_private_ip("192.168.1.1"))
        self.assertTrue(self.ip_repo._is_private_ip("10.0.0.1"))
        self.assertTrue(self.ip_repo._is_private_ip("172.16.0.1"))

    def test_is_private_ip_public(self):
        """Test public IP detection."""
        self.assertFalse(self.ip_repo._is_private_ip("8.8.8.8"))
        self.assertFalse(self.ip_repo._is_private_ip("1.1.1.1"))

    def test_get_ip_version_ipv4(self):
        """Test IPv4 version detection."""
        self.assertEqual(self.ip_repo._get_ip_version("192.168.1.1"), 4)

    def test_get_ip_version_ipv6(self):
        """Test IPv6 version detection."""
        self.assertEqual(self.ip_repo._get_ip_version("2001:db8::1"), 6)

    def test_get_ip_version_invalid(self):
        """Test version detection for invalid IP."""
        self.assertEqual(self.ip_repo._get_ip_version("invalid"), 4)  # Default

    def test_associate_with_subdomain(self):
        """Test IP association with subdomain."""
        # Create a subdomain first
        subdomain = self.data_generator.create_subdomain(
            name="test.example.com",
            scan_history=self.scan_history,
            target_domain=self.domain,
        )

        # Create IP
        ip_obj, _ = self.ip_repo.get_or_create("192.168.1.1")

        # Test association
        self.ip_repo._associate_with_subdomain(ip_obj, "test.example.com", self.scan_history.id)

        # Verify association
        subdomain.refresh_from_db()
        self.assertIn(ip_obj, subdomain.ip_addresses.all())

    def test_associate_with_subdomain_nonexistent(self):
        """Test IP association with non-existent subdomain."""
        ip_obj, _ = self.ip_repo.get_or_create("192.168.1.1")

        # Should not raise exception
        self.ip_repo._associate_with_subdomain(ip_obj, "nonexistent.com", self.scan_history.id)

    def test_save_from_secator_with_hostname_association(self):
        """Test saving IP with hostname for subdomain association."""
        # Create subdomain first
        subdomain = self.data_generator.create_subdomain(
            name="test.example.com",
            scan_history=self.scan_history,
            target_domain=self.domain,
        )

        item = {
            "_type": "ip",
            "ip": "192.168.1.1",
            "host": "test.example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)

        # Verify association was made
        subdomain.refresh_from_db()
        self.assertIn(result, subdomain.ip_addresses.all())

    def test_process_secator_ip_item_valid(self):
        """Test _process_secator_ip_item with valid data."""
        item = {
            "ip": "192.168.1.1",
            "host": "test.example.com",
            "alive": True,
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.168.1.1")
        self.assertTrue(result.alive)
        self.assertTrue(result.is_private)

    def test_process_secator_ip_item_missing_ip(self):
        """Test _process_secator_ip_item with missing IP."""
        item = {
            "host": "test.example.com",
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_process_secator_ip_item_invalid_ip(self):
        """Test _process_secator_ip_item with invalid IP."""
        item = {
            "ip": "invalid-ip",
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_with_protocol(self):
        """Test saving IP with protocol field."""
        item = {
            "_type": "ip",
            "ip": "2001:db8::1",
            "protocol": "IPv6",
            "alive": True,
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "2001:db8::1")
        self.assertEqual(result.protocol, "IPv6")
        self.assertEqual(result.version, 6)

    def test_save_from_secator_protocol_derived_from_version(self):
        """Test that protocol is derived from version if not provided."""
        item = {
            "_type": "ip",
            "ip": "192.168.1.1",
            "alive": True,
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.168.1.1")
        self.assertEqual(result.protocol, "IPv4")  # Should be derived from version
        self.assertEqual(result.version, 4)

    def test_process_secator_ip_item_with_hostname(self):
        """Test _process_secator_ip_item with hostname for subdomain association."""
        subdomain = self.data_generator.create_subdomain(
            name="test.example.com",
            scan_history=self.scan_history,
            target_domain=self.domain,
        )

        item = {
            "ip": "192.168.1.1",
            "host": "test.example.com",
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        subdomain.refresh_from_db()
        self.assertIn(result, subdomain.ip_addresses.all())
