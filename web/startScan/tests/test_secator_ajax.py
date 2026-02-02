"""
Unit tests for Secator AJAX helpers (selection, id_prefix normalization).
"""

from startScan.secator_ajax import normalize_secator_id_prefix
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
