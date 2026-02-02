"""
Unit tests for Secator AJAX helpers (selection, id_prefix normalization).
"""

from startScan.secator_ajax import (
    get_secator_selection_template_and_context,
    normalize_secator_id_prefix,
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
