"""
Tests for IP repository functionality.
"""

import json

from django.utils import timezone

from reNgine.services.repositories.ip_repository import IpRepository
from startScan.models import EndPoint
from utils.test_base import BaseTestCase


class TestIpRepository(BaseTestCase):
    """Test cases for IpRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.ip_repo = IpRepository()
        # Scan history first (needs target), then domain linked to that scan
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

    def test_save_from_secator_valid_ipv4(self):
        """Test saving valid IPv4 address from Secator."""
        item = {
            "_type": "ip",
            "ip": "192.168.1.1",
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.168.1.1")
        self.assertEqual(result.version, 4)
        self.assertTrue(result.is_private)
        self.assertEqual(result.reverse_pointer, "example.com")

    def test_save_from_secator_persists_root_source(self) -> None:
        item = {
            "_type": "ip",
            "ip": "192.168.1.50",
            "host": "host-src.example.com",
            "_source": "nmap",
        }
        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        result.refresh_from_db()
        self.assertEqual(result.source, "nmap")

    def test_save_from_secator_valid_ipv6(self):
        """Test saving valid IPv6 address from Secator."""
        item = {
            "_type": "ip",
            "ip": "2001:4860:4860::8888",  # Google DNS IPv6 (public)
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "2001:4860:4860::8888")
        self.assertEqual(result.version, 6)
        self.assertFalse(result.is_private)
        self.assertEqual(result.reverse_pointer, "example.com")

    def test_save_from_secator_invalid_ip(self):
        """Test handling invalid IP address."""
        item = {
            "_type": "ip",
            "ip": "invalid-ip",
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_ip(self):
        """Test handling missing IP field."""
        item = {
            "_type": "ip",
            "host": "example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_uses_host_when_ip_is_hostname(self):
        """When ip is hostname (e.g. PTR result) and host is valid IP, use host as the IP."""
        item = {
            "_type": "ip",
            "ip": "ptr-result.example.com",
            "host": "192.0.2.1",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.0.2.1")
        self.assertEqual(result.reverse_pointer, "ptr-result.example.com")

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

        result = self.ip_repo.bulk_create(ip_addresses, self.scan_history.id, self.data_generator.domain.id)

        self.assertEqual(len(result), 3)
        for ip_obj in result:
            self.assertIn(ip_obj.address, ip_addresses)

    def test_bulk_create_mixed_ips(self):
        """Test bulk creation with mixed valid/invalid IPs."""
        ip_addresses = ["192.168.1.1", "invalid-ip", "10.0.0.1"]

        result = self.ip_repo.bulk_create(ip_addresses, self.scan_history.id, self.data_generator.domain.id)

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
            domain=self.domain,
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
            domain=self.domain,
        )

        item = {
            "_type": "ip",
            "ip": "192.168.1.1",
            "host": "test.example.com",
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.reverse_pointer, "test.example.com")

        # Verify association was made
        subdomain.refresh_from_db()
        self.assertIn(result, subdomain.ip_addresses.all())

    def test_save_from_secator_dnsx_a_does_not_set_reverse_pointer(self):
        """Forward dnsx A record: host is the subdomain, not rDNS — leave reverse_pointer empty."""
        item = {
            "_type": "ip",
            "ip": "192.0.2.10",
            "host": "www.example.com",
            "tags": ["dns", "a"],
        }
        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.0.2.10")
        self.assertIsNone(result.reverse_pointer)

    def test_save_from_secator_dnsx_ptr_tag_sets_reverse_pointer(self):
        item = {
            "_type": "ip",
            "ip": "ptr-target.example.com",
            "host": "192.0.2.11",
            "tags": ["dns", "ptr"],
        }
        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.0.2.11")
        self.assertEqual(result.reverse_pointer, "ptr-target.example.com")

    def test_save_from_secator_reverse_pointer_hostname_lowercased(self):
        item = {
            "_type": "ip",
            "ip": "HoSt.EXAMPLE.CoM",
            "host": "192.0.2.19",
            "tags": ["dns", "ptr"],
        }
        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.reverse_pointer, "host.example.com")

    def test_save_from_secator_ptr_overwrites_existing_reverse_pointer(self):
        item_nmap = {
            "_type": "ip",
            "ip": "192.0.2.12",
            "host": "nmap-name.example.com",
        }
        first = self.ip_repo.save_from_secator(item_nmap, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(first)
        self.assertEqual(first.reverse_pointer, "nmap-name.example.com")

        item_ptr = {
            "_type": "ip",
            "ip": "ptr-authoritative.example.com",
            "host": "192.0.2.12",
            "tags": ["dns", "ptr"],
        }
        second = self.ip_repo.save_from_secator(item_ptr, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(second)
        self.assertEqual(second.id, first.id)
        second.refresh_from_db()
        self.assertEqual(second.reverse_pointer, "ptr-authoritative.example.com")

    def test_save_from_secator_heuristic_does_not_overwrite_existing_reverse_pointer(self):
        item_first = {
            "_type": "ip",
            "ip": "192.0.2.13",
            "host": "first-name.example.com",
        }
        ip_row = self.ip_repo.save_from_secator(item_first, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(ip_row)

        item_second = {
            "_type": "ip",
            "ip": "192.0.2.13",
            "host": "second-name.example.com",
        }
        again = self.ip_repo.save_from_secator(item_second, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(again)
        again.refresh_from_db()
        self.assertEqual(again.reverse_pointer, "first-name.example.com")

    def test_save_from_secator_reverse_pointer_truncated_to_max_length(self):
        long_host = "a" * 120
        item = {
            "_type": "ip",
            "ip": "192.0.2.14",
            "host": long_host,
        }
        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.reverse_pointer or ""), 100)
        self.assertEqual(result.reverse_pointer, long_host[:100])

    def test_process_secator_ip_item_valid(self):
        """Test _process_secator_ip_item with valid data."""
        item = {
            "ip": "192.168.1.1",
            "host": "test.example.com",
            "alive": True,
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.168.1.1")
        self.assertTrue(result.alive)
        self.assertTrue(result.is_private)
        self.assertEqual(result.reverse_pointer, "test.example.com")

    def test_process_secator_ip_item_missing_ip(self):
        """Test _process_secator_ip_item with missing IP."""
        item = {
            "host": "test.example.com",
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_process_secator_ip_item_invalid_ip(self):
        """Test _process_secator_ip_item with invalid IP."""
        item = {
            "ip": "invalid-ip",
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_with_protocol(self):
        """Test saving IP with protocol field."""
        item = {
            "_type": "ip",
            "ip": "2001:db8::1",
            "protocol": "IPv6",
            "alive": True,
        }

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

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

        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "192.168.1.1")
        self.assertEqual(result.protocol, "IPv4")  # Should be derived from version
        self.assertEqual(result.version, 4)

    def test_process_secator_ip_item_with_hostname(self):
        """Test _process_secator_ip_item with hostname for subdomain association."""
        subdomain = self.data_generator.create_subdomain(
            name="test.example.com",
            scan_history=self.scan_history,
            domain=self.domain,
        )

        item = {
            "ip": "192.168.1.1",
            "host": "test.example.com",
        }

        result = self.ip_repo._process_secator_ip_item(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.reverse_pointer, "test.example.com")
        subdomain.refresh_from_db()
        self.assertIn(result, subdomain.ip_addresses.all())

    def test_save_from_secator_merges_extra_data(self):
        """Secator Ip.extra_data is merged into IpAddress.extra_data on repeat ingestion."""
        item = {
            "_type": "ip",
            "ip": "192.0.2.88",
            "host": "host.example.com",
            "extra_data": {"mac": "00:11:22:33:44:55", "vendor": "TestCo"},
        }
        first = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(first)
        first.refresh_from_db()
        self.assertEqual(first.extra_data.get("mac"), "00:11:22:33:44:55")

        item2 = {
            "_type": "ip",
            "ip": "192.0.2.88",
            "host": "host.example.com",
            "extra_data": {"asn": "AS64496"},
        }
        second = self.ip_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(second)
        second.refresh_from_db()
        self.assertEqual(second.id, first.id)
        self.assertEqual(second.extra_data.get("mac"), "00:11:22:33:44:55")
        self.assertEqual(second.extra_data.get("asn"), "AS64496")

    def test_sync_alive_from_http_subdomain_http_status(self):
        """Subdomain with http_status > 0 promotes linked IP alive."""
        subdomain = self.data_generator.create_subdomain(
            name="sync.example.com",
            scan_history=self.scan_history,
            domain=self.domain,
        )
        ip_obj, _ = self.ip_repo.get_or_create_for_scan(
            self.scan_history.id,
            self.data_generator.target.id,
            "203.0.113.20",
            alive=False,
        )
        self.assertIsNotNone(ip_obj)
        self.assertFalse(ip_obj.alive)
        subdomain.ip_addresses.add(ip_obj)
        subdomain.http_status = 200
        subdomain.save(update_fields=["http_status"])
        self.assertTrue(self.ip_repo.sync_alive_from_http_evidence(ip_obj.id, self.scan_history.id))
        ip_obj.refresh_from_db()
        self.assertTrue(ip_obj.alive)

    def test_sync_alive_from_http_endpoint_on_subdomain(self):
        """EndPoint with http_status > 0 for linked subdomain promotes IP alive."""
        subdomain = self.data_generator.create_subdomain(
            name="ep.example.com",
            scan_history=self.scan_history,
            domain=self.domain,
        )
        ip_obj, _ = self.ip_repo.get_or_create_for_scan(
            self.scan_history.id,
            self.data_generator.target.id,
            "203.0.113.21",
            alive=False,
        )
        subdomain.ip_addresses.add(ip_obj)
        subdomain.http_status = 0
        subdomain.save(update_fields=["http_status"])
        self.data_generator.create_endpoint(
            subdomain=subdomain,
            scan_history=self.scan_history,
            domain=self.domain,
            http_status=200,
        )
        self.assertTrue(self.ip_repo.sync_alive_from_http_evidence(ip_obj.id, self.scan_history.id))
        ip_obj.refresh_from_db()
        self.assertTrue(ip_obj.alive)

    def test_sync_alive_from_http_direct_ip_endpoint(self):
        """EndPoint linked to IpAddress (literal host) with http_status > 0 promotes alive."""
        ip_obj, _ = self.ip_repo.get_or_create_for_scan(
            self.scan_history.id,
            self.data_generator.target.id,
            "203.0.113.22",
            alive=False,
        )
        EndPoint.objects.create(
            domain=self.domain,
            scan_history=self.scan_history,
            subdomain=None,
            ip_address=ip_obj,
            http_url="http://203.0.113.22",
            http_status=200,
            discovered_date=timezone.now(),
        )
        self.assertTrue(self.ip_repo.sync_alive_from_http_evidence(ip_obj.id, self.scan_history.id))
        ip_obj.refresh_from_db()
        self.assertTrue(ip_obj.alive)

    def test_save_from_secator_preserves_alive_from_json_bool(self):
        """JSON-style dict (e.g. API body) keeps boolean alive for Secator IP items."""
        raw = '{"_type": "ip", "ip": "192.0.2.60", "alive": true}'
        item = json.loads(raw)
        result = self.ip_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertTrue(result.alive)
