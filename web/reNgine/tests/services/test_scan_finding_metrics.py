"""Tests for centralized scan finding counts (including IP metrics)."""

from django.utils import timezone

from reNgine.services.scan_finding_metrics import (
    SCAN_FINDING_IP_ALIVE_KEY,
    SCAN_FINDING_IP_COUNT_KEY,
    attach_ip_metrics_to_scans,
    bulk_ip_metrics_for_scans,
    bulk_ip_metrics_for_targets,
    get_ip_address_metrics_for_scan,
    get_ip_address_total_for_scan,
    get_ip_metrics_for_project,
    get_ip_metrics_for_target,
    get_scan_finding_counts,
    ip_address_id_linked_to_scan,
    partition_ip_address_ids_for_scan_history,
)
from reNgine.utilities.websocket import build_light_scan_status_message
from startScan.models import EndPoint, IpAddress, ScanHistory
from utils.test_base import BaseTestCase


class ScanFindingMetricsTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.scan = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan)

    def test_get_ip_address_metrics_empty_scan(self) -> None:
        total, alive = get_ip_address_metrics_for_scan(self.scan.id)
        self.assertEqual(total, 0)
        self.assertEqual(alive, 0)

    def test_get_ip_address_metrics_via_subdomain_m2m(self) -> None:
        sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        ip = IpAddress.objects.create(address="192.0.2.1", version=4, alive=True)
        sub.ip_addresses.add(ip)
        total, alive = get_ip_address_metrics_for_scan(self.scan.id)
        self.assertEqual(total, 1)
        self.assertEqual(alive, 1)
        self.assertEqual(get_ip_address_total_for_scan(self.scan.id), total)

    def test_get_ip_address_metrics_dedupes_same_ip_m2m_and_endpoint(self) -> None:
        sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        ip = IpAddress.objects.create(address="192.0.2.2", version=4, alive=True)
        sub.ip_addresses.add(ip)
        EndPoint.objects.create(
            scan_history=self.scan,
            domain=self.domain,
            subdomain=None,
            ip_address=ip,
            http_url="http://192.0.2.2/",
            discovered_date=timezone.now(),
        )
        total, alive = get_ip_address_metrics_for_scan(self.scan.id)
        self.assertEqual(total, 1)
        self.assertEqual(alive, 1)

    def test_ip_address_id_linked_to_scan_matches_partition(self) -> None:
        sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        ip_in = IpAddress.objects.create(address="192.0.2.40", version=4, alive=True)
        ip_out = IpAddress.objects.create(address="192.0.2.41", version=4, alive=True)
        sub.ip_addresses.add(ip_in)
        self.assertTrue(ip_address_id_linked_to_scan(ip_in.id, self.scan.id))
        self.assertFalse(ip_address_id_linked_to_scan(ip_out.id, self.scan.id))
        self.assertFalse(ip_address_id_linked_to_scan(ip_in.id, 0))

    def test_partition_ip_address_ids_for_scan_history(self) -> None:
        sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        ip_in = IpAddress.objects.create(address="192.0.2.30", version=4, alive=True)
        ip_out = IpAddress.objects.create(address="192.0.2.31", version=4, alive=True)
        sub.ip_addresses.add(ip_in)
        valid, invalid = partition_ip_address_ids_for_scan_history(
            [ip_in.id, ip_out.id, ip_in.id],
            self.scan.id,
        )
        self.assertEqual(valid, [ip_in.id, ip_in.id])
        self.assertEqual(invalid, [ip_out.id])

    def test_bulk_ip_metrics_for_scans(self) -> None:
        scan_b = self.data_generator.create_scan_history()
        domain_b = self.data_generator.create_domain(scan_history=scan_b)
        sub_a = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        sub_b = self.data_generator.create_subdomain(scan_history=scan_b, domain=domain_b)
        ip_a = IpAddress.objects.create(address="192.0.2.10", version=4, alive=False)
        ip_b = IpAddress.objects.create(address="192.0.2.11", version=4, alive=True)
        sub_a.ip_addresses.add(ip_a)
        sub_b.ip_addresses.add(ip_b)
        out = bulk_ip_metrics_for_scans([self.scan.id, scan_b.id])
        self.assertEqual(out[self.scan.id], (1, 0))
        self.assertEqual(out[scan_b.id], (1, 1))

    def test_attach_ip_metrics_to_scans(self) -> None:
        sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        ip = IpAddress.objects.create(address="192.0.2.20", version=4, alive=True)
        sub.ip_addresses.add(ip)
        scans = [self.scan]
        attach_ip_metrics_to_scans(scans)
        self.assertEqual(getattr(self.scan, "ip_address_count"), 1)
        self.assertEqual(getattr(self.scan, "ip_alive_count"), 1)

    def test_bulk_ip_metrics_for_targets_matches_union_across_scans(self) -> None:
        target = self.data_generator.target
        scan_a = self.scan
        sub_a = self.data_generator.create_subdomain(scan_history=scan_a, domain=self.domain)
        ip_a = IpAddress.objects.create(address="192.0.2.50", version=4, alive=True)
        sub_a.ip_addresses.add(ip_a)

        scan_b = ScanHistory.objects.create(
            target=target,
            start_scan_date=timezone.now(),
            scan_status=2,
            is_legacy_scan=False,
            tasks=["httpx"],
        )
        domain_b = self.data_generator.create_domain(scan_history=scan_b)
        sub_b = self.data_generator.create_subdomain(scan_history=scan_b, domain=domain_b)
        ip_b = IpAddress.objects.create(address="192.0.2.51", version=4, alive=False)
        sub_b.ip_addresses.add(ip_b)

        bulk = bulk_ip_metrics_for_targets([target.id])
        legacy = IpAddress.get_counts_for_scan_histories([scan_a.id, scan_b.id])
        self.assertEqual(bulk[target.id], (legacy["total"], legacy["alive"]))
        self.assertEqual(get_ip_metrics_for_target(target.id), bulk[target.id])

    def test_ip_address_get_project_counts_matches_service(self) -> None:
        project = self.data_generator.project
        before = IpAddress.get_project_counts(project)
        sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        ip_dead = IpAddress.objects.create(address="192.0.2.100", version=4, alive=False)
        ip_alive = IpAddress.objects.create(address="192.0.2.101", version=4, alive=True)
        sub.ip_addresses.add(ip_dead, ip_alive)
        after = IpAddress.get_project_counts(project)
        self.assertEqual(after["total"], before["total"] + 2)
        self.assertEqual(after["alive"], before["alive"] + 1)
        total, alive = get_ip_metrics_for_project(project)
        self.assertEqual(total, after["total"])
        self.assertEqual(alive, after["alive"])

    def test_light_websocket_payload_ip_counts_match_get_scan_finding_counts(self) -> None:
        """WebSocket light status uses the same IP count semantics as get_scan_finding_counts (anti-drift)."""
        sub = self.data_generator.create_subdomain(scan_history=self.scan, domain=self.domain)
        ip = IpAddress.objects.create(address="192.0.2.77", version=4, alive=True)
        sub.ip_addresses.add(ip)
        counts = get_scan_finding_counts(self.scan.id)
        light = build_light_scan_status_message(self.scan.id)
        self.assertEqual(light[SCAN_FINDING_IP_COUNT_KEY], counts[SCAN_FINDING_IP_COUNT_KEY])
        self.assertEqual(light[SCAN_FINDING_IP_ALIVE_KEY], counts[SCAN_FINDING_IP_ALIVE_KEY])
