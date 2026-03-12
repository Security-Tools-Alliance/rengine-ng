"""
Tests for scan_lookups module.

Asserts the ORM relations required by scan_lookups (Subdomain, EndPoint, IpAddress, Port)
exist so that model changes break these tests and are noticed. See scan_lookups module
docstring for the documented relations.
"""

from django.db import models

from startScan.models import EndPoint, IpAddress, Port, Subdomain
from utils.test_base import BaseTestCase


class TestScanLookupsModelRelations(BaseTestCase):
    """Assert model relations required by scan_lookups exist."""

    def test_subdomain_has_scan_history_id(self):
        """Subdomain must have scan_history_id for scan-scoped lookups."""
        self.assertTrue(Subdomain._meta.get_field("scan_history_id").is_relation)

    def test_subdomain_has_ip_addresses_m2m(self):
        """Subdomain must have ip_addresses M2M to IpAddress (related_name on IpAddress)."""
        field = Subdomain._meta.get_field("ip_addresses")
        self.assertIsInstance(field, models.ManyToManyField)
        self.assertEqual(field.related_model, IpAddress)
        self.assertEqual(field.remote_field.related_name, "ip_addresses")

    def test_endpoint_has_scan_history_id(self):
        """EndPoint must have scan_history_id for get_endpoint_in_scan."""
        self.assertTrue(EndPoint._meta.get_field("scan_history_id").is_relation)

    def test_ip_address_reverse_m2m_from_subdomain(self):
        """IpAddress must have reverse relation ip_addresses from Subdomain M2M for ip_addresses__scan_history_id."""
        fields = [f for f in IpAddress._meta.get_fields() if f.name == "ip_addresses"]
        self.assertEqual(
            len(fields), 1, "IpAddress must have relation 'ip_addresses' (reverse of Subdomain.ip_addresses)"
        )
        self.assertEqual(fields[0].related_model, Subdomain)

    def test_port_has_ip_address_fk(self):
        """Port must have ip_address FK for get_port_for_ip and port_exists_in_scan."""
        field = Port._meta.get_field("ip_address")
        self.assertTrue(field.is_relation)
        self.assertEqual(field.related_model, IpAddress)
