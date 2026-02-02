"""
Tests for Port repository functionality.
"""

from reNgine.services.repositories.port_repository import PortRepository
from utils.test_base import BaseTestCase


class TestPortRepository(BaseTestCase):
    """Test cases for PortRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.port_repo = PortRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def test_save_from_secator_valid_port(self):
        """Test saving valid port from Secator."""
        # First create an IP
        self.data_generator.create_ip_address()

        item = {
            "_type": "port",
            "port": 80,
            "ip": "192.168.1.1",
            "service_name": "http",
            "description": "HTTP service",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.number, 80)
        self.assertEqual(result.ip_address.address, "192.168.1.1")
        self.assertEqual(result.service_name, "http")
        self.assertEqual(result.description, "HTTP service")

    def test_save_from_secator_invalid_port(self):
        """Test handling invalid port number."""
        item = {
            "_type": "port",
            "port": 99999,  # Invalid port
            "ip": "192.168.1.1",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_port(self):
        """Test handling missing port field."""
        item = {
            "_type": "port",
            "ip": "192.168.1.1",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_ip(self):
        """Test handling missing IP field."""
        item = {
            "_type": "port",
            "port": 80,
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_creates_ip_if_not_exists(self):
        """Test that port creation creates IP if it doesn't exist."""
        item = {
            "_type": "port",
            "port": 443,
            "ip": "10.0.0.1",
            "service_name": "https",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.number, 443)
        self.assertEqual(result.ip_address.address, "10.0.0.1")
        self.assertTrue(result.ip_address.is_private)

    def test_get_or_create_valid_port(self):
        """Test get_or_create with valid port."""
        # FIX: Pass IP address as STRING, not object
        # IP will be created automatically by get_or_create if it doesn't exist
        result, created = self.port_repo.get_or_create(
            port_number=80,
            ip_address="192.168.1.1",  # ← STRING au lieu de ip_obj
        )

        self.assertIsNotNone(result)
        self.assertTrue(created)
        self.assertEqual(result.number, 80)
        self.assertEqual(result.ip_address.address, "192.168.1.1")  # Vérifier via address

    def test_get_or_create_invalid_port(self):
        """Test get_or_create with invalid port."""
        # FIX: Pass IP as string
        # IP will be created automatically by get_or_create if it doesn't exist
        result, created = self.port_repo.get_or_create(
            port_number=99999,  # Invalid port
            ip_address="192.168.1.1",
        )

        self.assertIsNone(result)
        self.assertFalse(created)

    def test_bulk_create_valid_ports(self):
        """Test bulk creation of valid ports."""
        # IP will be created automatically by bulk_create if it doesn't exist
        ports_data = [
            {"port": 80, "ip": "192.168.1.1", "service_name": "http"},  # ← Ajouter "ip"
            {"port": 443, "ip": "192.168.1.1", "service_name": "https"},
            {"port": 22, "ip": "192.168.1.1", "service_name": "ssh"},
        ]

        result = self.port_repo.bulk_create(ports_data, self.scan_history.id, self.domain.id)

        self.assertEqual(len(result), 3)
        port_numbers = [port.number for port in result]
        self.assertIn(80, port_numbers)
        self.assertIn(443, port_numbers)
        self.assertIn(22, port_numbers)

    def test_bulk_create_mixed_ports(self):
        """Test bulk creation with mixed valid/invalid ports."""
        # IP will be created automatically by bulk_create if it doesn't exist
        ports_data = [
            {"port": 80, "ip": "192.168.1.1", "service_name": "http"},  # ← Ajouter "ip"
            {"port": 99999, "ip": "192.168.1.1", "service_name": "invalid"},  # Invalid port
            {"port": 443, "ip": "192.168.1.1", "service_name": "https"},
        ]

        result = self.port_repo.bulk_create(ports_data, self.scan_history.id, self.domain.id)

        # Should only create valid ports
        self.assertEqual(len(result), 2)
        port_numbers = [port.number for port in result]
        self.assertIn(80, port_numbers)
        self.assertIn(443, port_numbers)

    def test_is_uncommon_port_common(self):
        """Test detection of common ports."""
        self.assertFalse(self.port_repo._is_uncommon_port(80))  # HTTP
        self.assertFalse(self.port_repo._is_uncommon_port(443))  # HTTPS
        self.assertFalse(self.port_repo._is_uncommon_port(22))  # SSH
        self.assertFalse(self.port_repo._is_uncommon_port(21))  # FTP
        self.assertFalse(self.port_repo._is_uncommon_port(25))  # SMTP

    def test_is_uncommon_port_uncommon(self):
        """Test detection of uncommon ports."""
        self.assertTrue(self.port_repo._is_uncommon_port(8080))  # Alternative HTTP
        self.assertTrue(self.port_repo._is_uncommon_port(8443))  # Alternative HTTPS
        self.assertTrue(self.port_repo._is_uncommon_port(9999))  # Custom port

    def test_is_private_ip_private(self):
        """Test private IP detection."""
        self.assertTrue(self.port_repo._is_private_ip("192.168.1.1"))
        self.assertTrue(self.port_repo._is_private_ip("10.0.0.1"))
        self.assertTrue(self.port_repo._is_private_ip("172.16.0.1"))

    def test_is_private_ip_public(self):
        """Test public IP detection."""
        self.assertFalse(self.port_repo._is_private_ip("8.8.8.8"))
        self.assertFalse(self.port_repo._is_private_ip("1.1.1.1"))

    def test_get_ip_version_ipv4(self):
        """Test IPv4 version detection."""
        self.assertEqual(self.port_repo._get_ip_version("192.168.1.1"), 4)

    def test_get_ip_version_ipv6(self):
        """Test IPv6 version detection."""
        self.assertEqual(self.port_repo._get_ip_version("2001:db8::1"), 6)

    def test_get_ip_version_invalid(self):
        """Test version detection for invalid IP."""
        self.assertEqual(self.port_repo._get_ip_version("invalid"), 4)  # Default

    def test_save_from_secator_with_extra_data(self):
        """Test saving port with extra data."""
        item = {
            "_type": "port",
            "port": 8080,
            "ip": "192.168.1.1",
            "service_name": "http-alt",
            "description": "Alternative HTTP service",
            "extra_data": {
                "banner": "Apache/2.4.41",
                "version": "2.4.41",
            },
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.number, 8080)
        self.assertEqual(result.service_name, "http-alt")
        self.assertEqual(result.description, "Alternative HTTP service")
        self.assertTrue(result.is_uncommon)  # 8080 is uncommon

    def test_save_from_secator_duplicate_port(self):
        """Test handling duplicate port creation."""
        # Create first port
        item1 = {
            "_type": "port",
            "port": 80,
            "ip": "192.168.1.1",
            "service_name": "http",
        }

        result1 = self.port_repo.save_from_secator(item1, self.scan_history.id, self.domain.id)

        # Try to create same port again
        item2 = {
            "_type": "port",
            "port": 80,
            "ip": "192.168.1.1",
            "service_name": "http",
        }

        result2 = self.port_repo.save_from_secator(item2, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)  # Should be same object

    def test_process_secator_port_item_valid(self):
        """Test _process_secator_port_item with valid data."""
        item = {
            "port": 80,
            "ip": "192.168.1.1",
            "service_name": "http",
            "description": "HTTP service",
        }

        result = self.port_repo._process_secator_port_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.number, 80)
        self.assertEqual(result.ip_address.address, "192.168.1.1")
        self.assertEqual(result.service_name, "http")

    def test_process_secator_port_item_missing_port(self):
        """Test _process_secator_port_item with missing port."""
        item = {
            "ip": "192.168.1.1",
        }

        result = self.port_repo._process_secator_port_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_process_secator_port_item_missing_ip(self):
        """Test _process_secator_port_item with missing IP."""
        item = {
            "port": 80,
        }

        result = self.port_repo._process_secator_port_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_create_ports_in_bulk_valid(self):
        """Test _create_ports_in_bulk with valid data."""
        ports_data = [
            {"port": 80, "ip": "192.168.1.1", "service_name": "http"},
            {"port": 443, "ip": "192.168.1.1", "service_name": "https"},
        ]

        result = self.port_repo._create_ports_in_bulk(self.scan_history.id, self.domain.id, ports_data)

        self.assertEqual(len(result), 2)
        port_numbers = [port.number for port in result]
        self.assertIn(80, port_numbers)
        self.assertIn(443, port_numbers)

    def test_create_ports_in_bulk_empty_list(self):
        """Test _create_ports_in_bulk with empty list."""
        result = self.port_repo._create_ports_in_bulk(self.scan_history.id, self.domain.id, [])

        self.assertEqual(result, [])

    def test_create_ports_in_bulk_invalid_ports(self):
        """Test _create_ports_in_bulk with invalid ports."""
        ports_data = [
            {"port": 99999, "ip": "192.168.1.1"},  # Invalid port
            {"port": 80, "ip": "invalid-ip"},  # Invalid IP
        ]

        result = self.port_repo._create_ports_in_bulk(self.scan_history.id, self.domain.id, ports_data)

        self.assertEqual(result, [])

    def test_save_from_secator_with_confidence(self):
        """Test saving port with confidence field."""
        item = {
            "_type": "port",
            "port": 80,
            "ip": "192.168.1.1",
            "service_name": "http",
            "confidence": "high",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.number, 80)
        self.assertEqual(result.confidence, "high")

    def test_save_from_secator_port_as_string(self):
        """Test saving port when port is provided as string (e.g. from JSON)."""
        item = {
            "_type": "port",
            "port": "80",
            "ip": "192.168.1.1",
            "service_name": "http",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.number, 80)
        self.assertEqual(result.ip_address.address, "192.168.1.1")

    def test_save_from_secator_uses_host_when_ip_missing(self):
        """Test that host is used as IP when ip field is missing but host is valid IP."""
        item = {
            "_type": "port",
            "port": 443,
            "host": "10.0.0.2",
            "service_name": "https",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.number, 443)
        self.assertEqual(result.ip_address.address, "10.0.0.2")

    def test_save_from_secator_rejects_hostname_only(self):
        """Test that port is rejected when only hostname is provided (no valid IP in ip or host)."""
        item = {
            "_type": "port",
            "port": 80,
            "host": "example.local",
        }

        result = self.port_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_process_secator_port_item_invalid_port_type(self):
        """Test _process_secator_port_item rejects non-numeric port."""
        item = {
            "port": "not-a-number",
            "ip": "192.168.1.1",
        }

        result = self.port_repo._process_secator_port_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)
