"""
Unit tests for Secator AJAX helpers (selection, id_prefix normalization, cache).
"""

import json
from unittest.mock import patch

from django.http import HttpRequest

from startScan.secator.ajax import (
    _secator_selection_cache_key,
    get_secator_selection_template_and_context,
    normalize_secator_id_prefix,
    render_secator_selection_json,
)
from utils.test_base import BaseTestCase


class TestNormalizeSecatorIdPrefix(BaseTestCase):
    """Tests for normalize_secator_id_prefix."""

    def test_normalize_strips_whitespace(self):
        """Leading/trailing whitespace is stripped."""
        self.assertEqual(normalize_secator_id_prefix("  start_scan  "), "start_scan")

    def test_normalize_replaces_dashes_with_underscores(self):
        """Dashes are normalized to underscores for consistent DOM IDs."""
        self.assertEqual(normalize_secator_id_prefix("start-scan"), "start_scan")

    def test_normalize_empty_returns_empty(self):
        """Empty or None returns empty string."""
        self.assertEqual(normalize_secator_id_prefix(""), "")
        self.assertEqual(normalize_secator_id_prefix(None), "")

    def test_normalize_preserves_underscores(self):
        """Already-underscore prefix is unchanged."""
        self.assertEqual(normalize_secator_id_prefix("start_multi_scan"), "start_multi_scan")


class TestGetSecatorSelectionContextScan(BaseTestCase):
    """Tests for get_secator_selection_template_and_context in scan mode."""

    def test_scan_mode_returns_secator_scan_select_template(self):
        """Scan mode returns secator_scan_select template."""
        template_name, context = get_secator_selection_template_and_context("scan")
        self.assertEqual(template_name, "startScan/_items/secator_scan_select.html")

    def test_scan_mode_context_has_scans_and_tasks_dict(self):
        """Scan mode context has 'scans' (list) and 'tasks_dict', not 'scan_types'."""
        _template_name, context = get_secator_selection_template_and_context("scan")
        self.assertIn("scans", context)
        self.assertIn("tasks_dict", context)
        self.assertNotIn("scan_types", context)
        self.assertIsInstance(context["scans"], list)
        self.assertIsInstance(context["tasks_dict"], dict)

    def test_scan_mode_each_scan_has_workflows_context(self):
        """Each scan in context is a dict with 'scan' and 'workflows' (list of workflow context dicts)."""
        _template_name, context = get_secator_selection_template_and_context("scan")
        for scan_ctx in context["scans"]:
            self.assertIsInstance(scan_ctx, dict)
            self.assertIn("scan", scan_ctx)
            self.assertIn("workflows", scan_ctx)
            self.assertIsInstance(scan_ctx["workflows"], list)
            for wf_ctx in scan_ctx["workflows"]:
                self.assertIn("workflow", wf_ctx)
                self.assertIn("structured_tasks", wf_ctx)
                self.assertIn("tasks_count", wf_ctx)


class TestSecatorSelectionCacheKey(BaseTestCase):
    """Tests for _secator_selection_cache_key."""

    def test_key_includes_mode_and_normalized_prefix(self):
        """Cache key is built from execution_mode and normalized id_prefix."""
        self.assertEqual(
            _secator_selection_cache_key("workflow", "subscan_"),
            "secator_selection:workflow:subscan_",
        )
        self.assertEqual(
            _secator_selection_cache_key("tasks", "id-prefix"),
            "secator_selection:tasks:id_prefix",
        )

    def test_key_handles_empty_prefix(self):
        """Empty id_prefix yields key with empty suffix."""
        self.assertEqual(
            _secator_selection_cache_key("scan", ""),
            "secator_selection:scan:",
        )


class TestRenderSecatorSelectionJson(BaseTestCase):
    """Tests for render_secator_selection_json (cache hit and miss)."""

    def test_cache_hit_returns_cached_payload(self):
        """When cache has a value, response is the cached payload without building template."""
        request = HttpRequest()
        request.GET = request.GET.copy()
        request.GET["execution_mode"] = "workflow"
        request.GET["id_prefix"] = "subscan_"
        request.user = self.user
        cached = {"html": '<div class="cached">cached</div>'}
        with patch("startScan.secator.ajax.cache.get", return_value=cached):
            response = render_secator_selection_json(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), cached)

    def test_cache_miss_returns_fresh_html_and_stores_in_cache(self):
        """When cache misses, response is built and stored in cache."""
        request = HttpRequest()
        request.GET = request.GET.copy()
        request.GET["execution_mode"] = "workflow"
        request.GET["id_prefix"] = ""
        request.user = self.user
        with (
            patch("startScan.secator.ajax.cache.get", return_value=None),
            patch("startScan.secator.ajax.cache.set") as mock_set,
        ):
            response = render_secator_selection_json(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("html", data)
        self.assertIsInstance(data["html"], str)
        secator_calls = [c for c in mock_set.call_args_list if c[0][0].startswith("secator_selection:")]
        self.assertEqual(len(secator_calls), 1)
        self.assertEqual(secator_calls[0][0][1], {"html": data["html"]})
        self.assertEqual(secator_calls[0][0][2], 300)
