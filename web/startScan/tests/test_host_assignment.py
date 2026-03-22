"""Tests for exclusive host assignment helpers (EndPoint / SubScan)."""

from django.utils import timezone

from startScan.models import EndPoint, IpAddress, SubScan
from startScan.services.host_assignment import apply_endpoint_host, apply_subscan_host
from utils.test_base import BaseTestCase


class HostAssignmentTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.scan = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan)
        self.sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        self.ip = IpAddress.objects.create(address="192.0.2.50", version=4, alive=True)

    def test_apply_endpoint_host_subdomain_clears_ip(self) -> None:
        ep = EndPoint(
            scan_history=self.scan,
            domain=self.domain,
            ip_address=self.ip,
            http_url="http://192.0.2.50/",
            discovered_date=timezone.now(),
        )
        apply_endpoint_host(ep, subdomain=self.sub)
        self.assertEqual(ep.subdomain_id, self.sub.id)
        self.assertIsNone(ep.ip_address_id)

    def test_apply_endpoint_host_ip_clears_subdomain(self) -> None:
        ep = EndPoint(
            scan_history=self.scan,
            domain=self.domain,
            subdomain=self.sub,
            http_url="http://example.invalid/",
            discovered_date=timezone.now(),
        )
        apply_endpoint_host(ep, ip_address=self.ip)
        self.assertEqual(ep.ip_address_id, self.ip.id)
        self.assertIsNone(ep.subdomain_id)

    def test_apply_endpoint_host_rejects_both_or_neither(self) -> None:
        ep = EndPoint(scan_history=self.scan, domain=self.domain, http_url="http://x/", discovered_date=timezone.now())
        with self.assertRaises(ValueError):
            apply_endpoint_host(ep)
        with self.assertRaises(ValueError):
            apply_endpoint_host(ep, subdomain=self.sub, ip_address=self.ip)

    def test_apply_subscan_host_rejects_both(self) -> None:
        ss = SubScan(
            type="t",
            start_scan_date=timezone.now(),
            status=0,
            scan_history=self.scan,
        )
        with self.assertRaises(ValueError):
            apply_subscan_host(ss, subdomain=self.sub, ip_address=self.ip)

    def test_apply_subscan_host_ip_clears_subdomain(self) -> None:
        ss = SubScan(
            type="t",
            start_scan_date=timezone.now(),
            status=0,
            scan_history=self.scan,
            subdomain=self.sub,
        )
        apply_subscan_host(ss, ip_address=self.ip)
        self.assertEqual(ss.ip_address_id, self.ip.id)
        self.assertIsNone(ss.subdomain_id)
