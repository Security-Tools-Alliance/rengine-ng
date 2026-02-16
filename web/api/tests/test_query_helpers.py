"""
Unit tests for api.helpers.query (get_scan_status_querysets, build_subdomain_datatable_queryset).
"""

from django.utils import timezone

from api.helpers.query import build_subdomain_datatable_queryset, get_scan_status_querysets
from reNgine.definitions import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
)
from startScan.models import ScanHistory
from utils.test_base import BaseTestCase


class GetScanStatusQuerysetsTestCase(BaseTestCase):
    """Tests for get_scan_status_querysets."""

    def test_returns_expected_keys(self):
        """Result dict contains all expected queryset keys."""
        slug = self.data_generator.project.slug
        result = get_scan_status_querysets(slug)
        expected_keys = {
            "pending_scans",
            "current_scans",
            "recently_completed_scans",
            "pending_tasks",
            "current_tasks",
            "recently_completed_tasks",
        }
        self.assertEqual(set(result.keys()), expected_keys)

    def test_custom_limits_applied(self):
        """Custom limits cap the size of returned slices."""
        slug = self.data_generator.project.slug
        result = get_scan_status_querysets(
            slug,
            max_running_tasks=5,
            recently_completed_scans_limit=3,
            recently_completed_tasks_limit=7,
        )
        self.assertLessEqual(len(list(result["recently_completed_scans"])), 3)
        self.assertLessEqual(len(list(result["recently_completed_tasks"])), 7)
        self.assertLessEqual(len(list(result["current_tasks"])), 5)

    def test_pending_scan_in_pending_scans_bucket(self):
        """Scan with scan_status=SCAN_STATUS_PENDING appears in pending_scans."""
        slug = self.data_generator.project.slug
        domain = self.data_generator.domain
        scan = ScanHistory.objects.create(
            domain=domain,
            start_scan_date=timezone.now(),
            scan_status=SCAN_STATUS_PENDING,
            is_legacy_scan=False,
            tasks=[],
        )
        result = get_scan_status_querysets(slug)
        pending_ids = [s.id for s in result["pending_scans"]]
        self.assertIn(scan.id, pending_ids)

    def test_running_scan_in_current_scans_bucket(self):
        """Scan with scan_status=SCAN_STATUS_RUNNING appears in current_scans."""
        slug = self.data_generator.project.slug
        domain = self.data_generator.domain
        scan = ScanHistory.objects.create(
            domain=domain,
            start_scan_date=timezone.now(),
            scan_status=SCAN_STATUS_RUNNING,
            is_legacy_scan=False,
            tasks=[],
        )
        result = get_scan_status_querysets(slug)
        current_ids = [s.id for s in result["current_scans"]]
        self.assertIn(scan.id, current_ids)

    def test_completed_scan_in_recently_completed_bucket(self):
        """Scan with scan_status=SCAN_STATUS_COMPLETED appears in recently_completed_scans."""
        slug = self.data_generator.project.slug
        domain = self.data_generator.domain
        scan = ScanHistory.objects.create(
            domain=domain,
            start_scan_date=timezone.now(),
            scan_status=SCAN_STATUS_COMPLETED,
            is_legacy_scan=False,
            tasks=[],
        )
        result = get_scan_status_querysets(slug, recently_completed_scans_limit=20)
        completed_ids = [s.id for s in result["recently_completed_scans"]]
        self.assertIn(scan.id, completed_ids)

    def test_failed_scan_in_recently_completed_bucket(self):
        """Scan with scan_status=SCAN_STATUS_FAILED appears in recently_completed_scans."""
        slug = self.data_generator.project.slug
        domain = self.data_generator.domain
        scan = ScanHistory.objects.create(
            domain=domain,
            start_scan_date=timezone.now(),
            scan_status=SCAN_STATUS_FAILED,
            is_legacy_scan=False,
            tasks=[],
        )
        result = get_scan_status_querysets(slug, recently_completed_scans_limit=20)
        completed_ids = [s.id for s in result["recently_completed_scans"]]
        self.assertIn(scan.id, completed_ids)

    def test_scan_querysets_have_count_annotations(self):
        """Scans in returned querysets have subdomain_count, endpoint_count, vulnerability_count."""
        slug = self.data_generator.project.slug
        result = get_scan_status_querysets(slug)
        for key in ("pending_scans", "current_scans", "recently_completed_scans"):
            for scan in list(result[key])[:1]:
                self.assertIsInstance(getattr(scan, "subdomain_count", None), int)
                self.assertIsInstance(getattr(scan, "endpoint_count", None), int)
                self.assertIsInstance(getattr(scan, "vulnerability_count", None), int)
                break


class BuildSubdomainDatatableQuerysetTestCase(BaseTestCase):
    """Tests for build_subdomain_datatable_queryset."""

    def test_returns_queryset_and_interesting_names(self):
        """Returns (queryset, datatable_interesting_names); interesting_names None when scan_id is None."""
        slug = self.data_generator.project.slug
        queryset, interesting_names = build_subdomain_datatable_queryset(slug)
        self.assertIsNone(interesting_names)
        self.assertEqual(queryset.model.__name__, "Subdomain")

    def test_with_scan_id_returns_interesting_names_set(self):
        """When scan_id is set, second return value is a set of subdomain names."""
        slug = self.data_generator.project.slug
        scan_id = self.data_generator.scan_history.id
        _, interesting_names = build_subdomain_datatable_queryset(slug, scan_id=scan_id)
        self.assertIsInstance(interesting_names, set)

    def test_subdomain_queryset_has_count_annotations(self):
        """Queryset rows have endpoint_count, vuln_count, subscan_count, todos_count, etc."""
        slug = self.data_generator.project.slug
        queryset, _ = build_subdomain_datatable_queryset(slug)
        first = next(iter(queryset), None)
        if first is None:
            return
        self.assertIsInstance(getattr(first, "endpoint_count", None), int)
        self.assertIsInstance(getattr(first, "vuln_count", None), int)
        self.assertIsInstance(getattr(first, "subscan_count", None), int)
        self.assertIsInstance(getattr(first, "todos_count", None), int)
