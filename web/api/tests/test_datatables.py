"""
Tests for api.helpers.datatables (ordering helpers, column maps, and DataTables action URL wiring).
"""

import re

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

    def test_returns_subdomain_ip_vulnerability_target_keys(self):
        """get_datatable_action_urls returns dict with subdomain, ip, vulnerability, target."""
        from api.helpers.datatables import get_datatable_action_urls

        slug = self.data_generator.project.slug
        urls = get_datatable_action_urls(slug)
        self.assertIn("subdomain", urls)
        self.assertIn("ip", urls)
        self.assertIn("vulnerability", urls)
        self.assertIn("target", urls)

    def test_ip_urls_are_absolute_paths(self):
        """IP action URLs are non-empty absolute paths."""
        from api.helpers.datatables import get_datatable_action_urls

        urls = get_datatable_action_urls(self.data_generator.project.slug)
        ip_urls = urls["ip"]
        self.assertIn("attackSurface", ip_urls)
        self.assertIn("toggleIpImportant", ip_urls)
        self.assertIn("unlinkScanIps", ip_urls)
        self.assertIn("unlinkTargetIps", ip_urls)
        self.assertIn("getIpDetails", ip_urls)
        self.assertIn("querySubdomains", ip_urls)
        for key, path in ip_urls.items():
            self.assertTrue(path.startswith("/"), msg=f"ip.{key} should be absolute path")

    def test_subdomain_urls_are_absolute_paths(self):
        """Subdomain action URLs are non-empty paths."""
        from api.helpers.datatables import get_datatable_action_urls

        urls = get_datatable_action_urls(self.data_generator.project.slug)
        sub = urls["subdomain"]
        self.assertIn("attackSurface", sub)
        self.assertIn("toggleSubdomain", sub)
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
        self.assertIn("attackSurface", target)
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


def _get_all_column_maps():
    """Return all DATATABLE_COLUMN_MAP_* dicts from api.helpers.datatables."""
    from api.helpers import datatables as datatables_module

    return [
        (name, getattr(datatables_module, name))
        for name in dir(datatables_module)
        if name.startswith("DATATABLE_COLUMN_MAP_") and isinstance(getattr(datatables_module, name), dict)
    ]


class TestDatatableColumnMaps(BaseTestCase):
    """Tests for DATATABLE_COLUMN_MAP_* contract: keys, values, no duplicates."""

    def test_every_column_map_has_string_keys_and_non_empty_string_values(self):
        """All column map keys are strings; all values are non-empty strings (field or lookup names)."""
        for name, column_map in _get_all_column_maps():
            self.assertIsInstance(column_map, dict, msg=f"{name} must be a dict")
            for key, value in column_map.items():
                self.assertIsInstance(key, str, msg=f"{name}: key {key!r} must be str")
                self.assertIsInstance(value, str, msg=f"{name}: value for key {key!r} must be str")
                self.assertTrue(len(value) > 0, msg=f"{name}: value for key {key!r} must be non-empty")
                self.assertFalse(
                    value.startswith("-"),
                    msg=f"{name}: column_map must use bare field names (no leading '-'); got {value!r}",
                )

    def test_column_map_keys_are_numeric_string_indices(self):
        """Column map keys are numeric strings (DataTables column index as string)."""
        numeric = re.compile(r"^\d+$")
        for name, column_map in _get_all_column_maps():
            for key in column_map:
                self.assertRegex(key, numeric, msg=f"{name}: key {key!r} must be a numeric string index")

    def test_column_map_has_no_duplicate_keys(self):
        """Each column map has unique keys (no duplicate column index)."""
        for name, column_map in _get_all_column_maps():
            keys = list(column_map.keys())
            self.assertEqual(len(keys), len(set(keys)), msg=f"{name}: duplicate keys in column map")


class TestGetRequestFilterList(BaseTestCase):
    """Tests for get_request_filter_list (DataTables multi-value filter param)."""

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()

    def test_returns_empty_list_when_param_missing(self):
        """When param_key is absent, returns empty list."""
        from api.helpers.datatables import get_request_filter_list

        request = self.factory.get("/")
        self.assertEqual(get_request_filter_list(request, "filter_scope"), [])

    def test_returns_list_when_param_key_used(self):
        """When values are sent as param_key (multiple), returns list of values."""
        from api.helpers.datatables import get_request_filter_list

        request = self.factory.get("/", [("filter_scope", "scope-a"), ("filter_scope", "scope-b")])
        result = get_request_filter_list(request, "filter_scope")
        self.assertIsInstance(result, list)
        self.assertIn("scope-a", result)
        self.assertIn("scope-b", result)

    def test_returns_list_when_param_key_bracket_used(self):
        """When values are sent as param_key[], returns list of values."""
        from api.helpers.datatables import get_request_filter_list

        request = self.factory.get("/", [("filter_scope[]", "scope-1"), ("filter_scope[]", "scope-2")])
        result = get_request_filter_list(request, "filter_scope")
        self.assertEqual(len(result), 2)
        self.assertIn("scope-1", result)
        self.assertIn("scope-2", result)

    def test_param_key_takes_precedence_over_bracket(self):
        """When both param_key and param_key[] exist, getlist(param_key) is used first."""
        from api.helpers.datatables import get_request_filter_list

        request = self.factory.get("/", [("filter_x", "a"), ("filter_x[]", "b"), ("filter_x[]", "c")])
        result = get_request_filter_list(request, "filter_x")
        self.assertEqual(result, ["a"])


class TestApplyFilterListIn(BaseTestCase):
    """Tests for apply_filter_list_in (__in filter with optional value_mapper and distinct)."""

    def test_returns_queryset_unchanged_when_values_empty(self):
        """When values is empty, queryset is returned unchanged."""
        from api.helpers.datatables import apply_filter_list_in

        qs = self.data_generator.project.target_set.all()
        initial_count = qs.count()
        result = apply_filter_list_in(qs, "id__in", [])
        self.assertEqual(result.count(), initial_count)

    def test_applies_filter_when_values_non_empty(self):
        """When values is non-empty, __in filter is applied."""
        from api.helpers.datatables import apply_filter_list_in

        target = self.data_generator.target
        qs = self.data_generator.project.target_set.all()
        result = apply_filter_list_in(qs, "id__in", [target.id])
        self.assertEqual(result.count(), 1)
        self.assertEqual(result.first().id, target.id)

    def test_value_mapper_filters_none(self):
        """value_mapper that returns None for some values excludes them."""
        from api.helpers.datatables import apply_filter_list_in

        target = self.data_generator.target
        qs = self.data_generator.project.target_set.all()

        def map_only_first(v):
            return v if v == target.id else None

        result = apply_filter_list_in(qs, "id__in", [target.id, 99999], value_mapper=map_only_first)
        self.assertEqual(result.count(), 1)
        self.assertEqual(result.first().id, target.id)

    def test_distinct_called_when_true(self):
        """When distinct=True, resulting queryset has distinct() applied."""
        from api.helpers.datatables import apply_filter_list_in

        qs = self.data_generator.project.target_set.all()
        result = apply_filter_list_in(qs, "id__in", [self.data_generator.target.id], distinct=True)
        self.assertTrue(result.query.distinct)

    def test_all_mapped_to_none_returns_empty_queryset_by_default(self):
        """When value_mapper maps all values to None, return empty queryset (explicit no match)."""
        from api.helpers.datatables import apply_filter_list_in

        qs = self.data_generator.project.target_set.all()
        result = apply_filter_list_in(qs, "id__in", [1, 2, 3], value_mapper=lambda v: None)
        self.assertEqual(result.count(), 0)

    def test_all_mapped_to_none_returns_queryset_unchanged_when_opt_out(self):
        """When value_mapper maps all to None and empty_when_no_valid_values=False, queryset unchanged."""
        from api.helpers.datatables import apply_filter_list_in

        qs = self.data_generator.project.target_set.all()
        initial_count = qs.count()
        result = apply_filter_list_in(
            qs, "id__in", [1, 2], value_mapper=lambda v: None, empty_when_no_valid_values=False
        )
        self.assertEqual(result.count(), initial_count)


class TestApplyFilterListInByParam(BaseTestCase):
    """Tests for apply_filter_list_in_by_param (request param -> __in filter)."""

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()

    def test_returns_queryset_unchanged_when_param_missing(self):
        """When param is absent, queryset is returned unchanged."""
        from api.helpers.datatables import FILTER_PARAM_ORGANIZATION, apply_filter_list_in_by_param

        qs = self.data_generator.project.target_set.all()
        request = self.factory.get("/")
        result = apply_filter_list_in_by_param(
            qs, request, FILTER_PARAM_ORGANIZATION, "organizations__name__in", distinct=True
        )
        self.assertEqual(list(result), list(qs))

    def test_applies_filter_when_param_present(self):
        """When param has values, __in filter is applied (strip_empty=True drops empty strings)."""
        from api.helpers.datatables import FILTER_PARAM_ORGANIZATION, apply_filter_list_in_by_param

        org = self.data_generator.organization
        qs = self.data_generator.project.target_set.all()
        request = self.factory.get("/", {FILTER_PARAM_ORGANIZATION: org.name})
        result = apply_filter_list_in_by_param(
            qs, request, FILTER_PARAM_ORGANIZATION, "organizations__name__in", distinct=True
        )
        self.assertGreaterEqual(result.count(), 0)
        for t in result:
            self.assertIn(org, t.organizations.all())


class TestGetScanStatusCodesForLabels(BaseTestCase):
    """Tests for get_scan_status_codes_for_labels (scan history filter)."""

    def test_returns_codes_for_known_labels(self):
        """Known SCAN_STATUSES labels return corresponding codes."""
        from api.helpers.datatables import get_scan_status_codes_for_labels

        result = get_scan_status_codes_for_labels(["Completed", "Running"])
        self.assertEqual(len(result), 2)
        self.assertIn(2, result)
        self.assertIn(1, result)

    def test_uses_default_aliases(self):
        """Default aliases (e.g. Successful -> Completed) are applied."""
        from api.helpers.datatables import get_scan_status_codes_for_labels

        result = get_scan_status_codes_for_labels(["Successful"])
        self.assertEqual(result, [2])

    def test_unknown_labels_excluded(self):
        """Unknown labels are excluded from the result."""
        from api.helpers.datatables import get_scan_status_codes_for_labels

        result = get_scan_status_codes_for_labels(["Completed", "UnknownLabel"])
        self.assertEqual(result, [2])

    def test_empty_list_returns_empty(self):
        """Empty labels list returns empty list."""
        from api.helpers.datatables import get_scan_status_codes_for_labels

        self.assertEqual(get_scan_status_codes_for_labels([]), [])

    def test_filter_labels_resolve_to_codes(self):
        """All labels from get_scan_status_filter_labels resolve to valid codes."""
        from api.helpers.datatables import (
            get_scan_status_codes_for_labels,
            get_scan_status_filter_labels,
        )

        labels = get_scan_status_filter_labels()
        self.assertIsInstance(labels, list)
        self.assertGreater(len(labels), 0)
        codes = get_scan_status_codes_for_labels(labels)
        self.assertEqual(len(codes), len(labels))


class TestGetTaskStatusCodesForLabels(BaseTestCase):
    """Tests for get_task_status_codes_for_labels (subscan/task filter)."""

    def test_returns_codes_for_known_display_labels(self):
        """Known TASK_STATUS_MAP display values return corresponding codes."""
        from api.helpers.datatables import get_task_status_codes_for_labels

        result = get_task_status_codes_for_labels(["RUNNING", "SUCCESS"])
        self.assertEqual(len(result), 2)
        self.assertIn(1, result)
        self.assertIn(2, result)

    def test_uses_default_aliases(self):
        """Default aliases (e.g. In Progress -> RUNNING) are applied."""
        from api.helpers.datatables import get_task_status_codes_for_labels

        result = get_task_status_codes_for_labels(["In Progress"])
        self.assertEqual(result, [1])

    def test_unknown_labels_excluded(self):
        """Unknown labels are excluded."""
        from api.helpers.datatables import get_task_status_codes_for_labels

        result = get_task_status_codes_for_labels(["SUCCESS", "UnknownTask"])
        self.assertEqual(result, [2])

    def test_empty_list_returns_empty(self):
        """Empty labels list returns empty list."""
        from api.helpers.datatables import get_task_status_codes_for_labels

        self.assertEqual(get_task_status_codes_for_labels([]), [])

    def test_filter_labels_resolve_to_codes(self):
        """All labels from get_task_status_filter_labels resolve to valid codes."""
        from api.helpers.datatables import (
            get_task_status_codes_for_labels,
            get_task_status_filter_labels,
        )

        labels = get_task_status_filter_labels()
        self.assertIsInstance(labels, list)
        self.assertGreater(len(labels), 0)
        codes = get_task_status_codes_for_labels(labels)
        self.assertEqual(len(codes), len(labels))


class TestGetNucleiSeverityCodesForLabels(BaseTestCase):
    """Tests for get_nuclei_severity_codes_for_labels (vulnerability filter)."""

    def test_returns_codes_for_known_severities(self):
        """Known severity labels return NUCLEI_SEVERITY_MAP codes."""
        from api.helpers.datatables import get_nuclei_severity_codes_for_labels

        result = get_nuclei_severity_codes_for_labels(["info", "high", "critical"])
        self.assertEqual(len(result), 3)
        self.assertIn(0, result)
        self.assertIn(3, result)
        self.assertIn(4, result)

    def test_case_insensitive(self):
        """Severity lookup is case-insensitive."""
        from api.helpers.datatables import get_nuclei_severity_codes_for_labels

        result = get_nuclei_severity_codes_for_labels(["INFO", "Medium"])
        self.assertIn(0, result)
        self.assertIn(2, result)

    def test_unknown_severities_excluded(self):
        """Unknown labels (mapped to -2) are excluded."""
        from api.helpers.datatables import get_nuclei_severity_codes_for_labels

        result = get_nuclei_severity_codes_for_labels(["high", "unknown_severity_xyz"])
        self.assertEqual(result, [3])

    def test_empty_list_returns_empty(self):
        """Empty labels list returns empty list."""
        from api.helpers.datatables import get_nuclei_severity_codes_for_labels

        self.assertEqual(get_nuclei_severity_codes_for_labels([]), [])


class TestGetScopeTypeValuesForLabels(BaseTestCase):
    """Tests for get_scope_type_values_for_labels (scope type filter)."""

    def test_returns_values_for_known_scope_type_labels(self):
        """Known SCOPE_TYPE_CHOICES labels return corresponding values."""
        from api.helpers.datatables import get_scope_type_values_for_labels

        result = get_scope_type_values_for_labels(["Bug Bounty Program", "Internal Engagement"])
        self.assertEqual(len(result), 2)
        self.assertIn("program_bug_bounty", result)
        self.assertIn("engagement_internal", result)

    def test_unknown_label_passed_through(self):
        """Unknown labels are passed through as-is (per implementation)."""
        from api.helpers.datatables import get_scope_type_values_for_labels

        result = get_scope_type_values_for_labels(["Bug Bounty Program", "CustomType"])
        self.assertIn("program_bug_bounty", result)
        self.assertIn("CustomType", result)

    def test_empty_list_returns_empty(self):
        """Empty labels list returns empty list."""
        from api.helpers.datatables import get_scope_type_values_for_labels

        self.assertEqual(get_scope_type_values_for_labels([]), [])


class TestDatatableFilterContextMapping(BaseTestCase):
    """
    Assert each table's filter_context (select id -> query param name) matches expected mapping.
    Uses validate_datatable_filter_config() in api.helpers.datatables to catch drift between
    backend FILTER_CONTEXT_* and frontend filter partials (select ids must match).
    """

    def test_validate_datatable_filter_config_passes(self):
        """Central validation: select IDs and param names match EXPECTED_* in datatables.py."""
        from api.helpers.datatables import validate_datatable_filter_config

        errors = validate_datatable_filter_config()
        self.assertEqual(errors, [], msg="Filter config drift: " + "; ".join(errors))

    def test_get_datatable_table_config_returns_expected_filter_context(self):
        """get_datatable_table_config(table_id) returns filter_context consistent with DATATABLE_TABLE_CONFIGS."""
        from api.helpers.datatables import (
            EXPECTED_FILTER_PARAM_NAMES,
            EXPECTED_FILTER_SELECT_IDS,
            TABLE_ID_SCAN_HISTORY,
            TABLE_ID_TARGET_LIST,
            get_datatable_table_config,
        )

        config = get_datatable_table_config(TABLE_ID_SCAN_HISTORY)
        self.assertIn("filter_context", config)
        self.assertEqual(set(config["filter_context"].keys()), EXPECTED_FILTER_SELECT_IDS[TABLE_ID_SCAN_HISTORY])

        config = get_datatable_table_config(TABLE_ID_TARGET_LIST)
        self.assertEqual(set(config["filter_context"].values()), EXPECTED_FILTER_PARAM_NAMES[TABLE_ID_TARGET_LIST])
