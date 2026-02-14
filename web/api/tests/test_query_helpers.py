"""
Unit tests for api.query_helpers (get_scan_status_querysets, build_subdomain_datatable_queryset).
"""

from api.query_helpers import build_subdomain_datatable_queryset, get_scan_status_querysets
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
