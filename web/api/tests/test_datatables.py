"""
Tests for api.helpers.datatables (ordering helpers and DataTables action URL wiring).
"""

from django.test import RequestFactory
from django.urls import reverse

from utils.test_base import BaseTestCase


class TestGetDatatablesOrderColumn(BaseTestCase):
    """Tests for get_datatables_order_column direction handling."""

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()
        self.column_map = {"0": "name", "1": "severity"}

    def _order_column(self, column: str | None = None, dir: str | None = None, default_order: str = "id") -> str:
        from api.helpers.datatables import get_datatables_order_column

        params = {}
        if column is not None:
            params["order[0][column]"] = column
        if dir is not None:
            params["order[0][dir]"] = dir
        request = self.factory.get("/", params)
        return get_datatables_order_column(request, self.column_map, default_order=default_order)

    def test_mapped_column_asc_uses_request_direction(self):
        """Mapped column with dir=asc returns bare field."""
        self.assertEqual(self._order_column(column="0", dir="asc"), "name")
        self.assertEqual(self._order_column(column="1", dir="asc"), "severity")

    def test_mapped_column_desc_uses_request_direction(self):
        """Mapped column with dir=desc returns prefixed field."""
        self.assertEqual(self._order_column(column="0", dir="desc"), "-name")
        self.assertEqual(self._order_column(column="1", dir="desc"), "-severity")

    def test_fallback_default_order_no_dir_uses_default_direction(self):
        """When column is unmapped and no dir, default_order direction is used."""
        self.assertEqual(self._order_column(column="99", dir=None, default_order="-severity"), "-severity")
        self.assertEqual(self._order_column(column="99", dir=None, default_order="id"), "id")

    def test_fallback_default_order_asc_overrides_default_direction(self):
        """When fallback and dir=asc, result is ascending even if default_order is descending."""
        self.assertEqual(self._order_column(column="99", dir="asc", default_order="-severity"), "severity")

    def test_fallback_default_order_desc_overrides_default_direction(self):
        """When fallback and dir=desc, result is descending."""
        self.assertEqual(self._order_column(column="99", dir="desc", default_order="id"), "-id")


class TestGetDatatableActionUrls(BaseTestCase):
    """Tests for get_datatable_action_urls."""

    def setUp(self):
        super().setUp()

    def test_returns_subdomain_vulnerability_target_keys(self):
        """get_datatable_action_urls returns dict with subdomain, vulnerability, target."""
        from api.helpers.datatables import get_datatable_action_urls

        slug = self.data_generator.project.slug
        urls = get_datatable_action_urls(slug)
        self.assertIn("subdomain", urls)
        self.assertIn("vulnerability", urls)
        self.assertIn("target", urls)

    def test_subdomain_urls_are_absolute_paths(self):
        """Subdomain action URLs are non-empty paths."""
        from api.helpers.datatables import get_datatable_action_urls

        urls = get_datatable_action_urls(self.data_generator.project.slug)
        sub = urls["subdomain"]
        self.assertIn("attackSurface", sub)
        self.assertIn("toggleSubdomain", sub)
        self.assertIn("cmsDetector", sub)
        for key, path in sub.items():
            self.assertTrue(path.startswith("/"), msg=f"subdomain.{key} should be absolute path")

    def test_vulnerability_urls_are_absolute_paths(self):
        """Vulnerability action URLs are non-empty paths."""
        from api.helpers.datatables import get_datatable_action_urls

        urls = get_datatable_action_urls(self.data_generator.project.slug)
        vuln = urls["vulnerability"]
        self.assertIn("llmReport", vuln)
        self.assertIn("hackeroneReport", vuln)
        self.assertIn("deleteVulnerability", vuln)
        for key, path in vuln.items():
            self.assertTrue(path.startswith("/"), msg=f"vulnerability.{key} should be absolute path")

    def test_target_urls_are_base_without_trailing_id(self):
        """Target URLs are base paths (no trailing /0) so frontend can append row id."""
        from api.helpers.datatables import get_datatable_action_urls

        slug = self.data_generator.project.slug
        urls = get_datatable_action_urls(slug)
        target = urls["target"]
        self.assertIn("targetSummaryBase", target)
        self.assertIn("startScanBase", target)
        self.assertIn("scheduleScanBase", target)
        self.assertIn("updateTargetBase", target)
        self.assertIn("deleteTargetBase", target)
        for key, path in target.items():
            self.assertFalse(path.endswith("/0") or path.endswith("/0/"), msg=f"target.{key} must be base path")
            self.assertTrue(path.startswith("/"), msg=f"target.{key} must be absolute path for href")
            self.assertTrue(path.endswith("/"), msg=f"target.{key} must end with / so that base+id yields base/id")
        expected_summary = reverse("target_summary", args=[slug, 0])
        expected_full = expected_summary.rstrip("/")
        if not expected_full.startswith("/"):
            expected_full = f"/{expected_full}"
        self.assertEqual(target["targetSummaryBase"] + "0", expected_full)
