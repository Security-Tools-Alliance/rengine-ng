"""
Unit tests for Secator template tags (secator_extras).
"""

from startScan.templatetags.secator_extras import (
    category_display_label,
    category_icon,
    scan_icon,
    slice_from,
    subtract,
)
from utils.test_base import BaseTestCase


class TestCategoryDisplayLabel(BaseTestCase):
    """Tests for category_display_label filter."""

    def test_unknown_returns_untagged(self):
        """'unknown' (any case) displays as 'Untagged'."""
        self.assertEqual(category_display_label("unknown"), "Untagged")
        self.assertEqual(category_display_label("Unknown"), "Untagged")

    def test_empty_returns_untagged(self):
        """Empty or None returns 'Untagged'."""
        self.assertEqual(category_display_label(""), "Untagged")
        self.assertEqual(category_display_label(None), "Untagged")

    def test_other_categories_unchanged(self):
        """Other categories are returned as-is."""
        self.assertEqual(category_display_label("url"), "url")
        self.assertEqual(category_display_label("dns"), "dns")


class TestScanIcon(BaseTestCase):
    """Tests for scan_icon filter."""

    def test_known_scan_names_return_mapped_icons(self):
        """Known scan names return the same icons as previously hardcoded in template."""
        self.assertEqual(scan_icon("subdomain"), "sitemap")
        self.assertEqual(scan_icon("domain"), "globe")
        self.assertEqual(scan_icon("host"), "server")
        self.assertEqual(scan_icon("network"), "network-wired")
        self.assertEqual(scan_icon("url"), "link")

    def test_scan_icon_case_insensitive(self):
        """Scan name matching is case-insensitive."""
        self.assertEqual(scan_icon("Subdomain"), "sitemap")
        self.assertEqual(scan_icon("HOST"), "server")

    def test_empty_or_none_returns_radar(self):
        """Empty or None returns default 'radar' icon."""
        self.assertEqual(scan_icon(""), "radar")
        self.assertEqual(scan_icon(None), "radar")

    def test_unknown_scan_name_falls_back_to_workflow_icon(self):
        """Unknown scan name uses workflow_icon fallback (project-diagram or partial match)."""
        result = scan_icon("custom_scan")
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_scan_icon_non_string_coerced(self):
        """Non-string scan_name (e.g. from template) is coerced with str() to avoid AttributeError."""
        result = scan_icon(123)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)
        result2 = scan_icon(42)
        self.assertIsInstance(result2, str)
        self.assertGreater(len(result2), 0)


class TestSliceFrom(BaseTestCase):
    """Tests for slice_from filter."""

    def test_returns_tail_from_index(self):
        """Returns list[start_index:] so limit is respected for remaining items."""
        self.assertEqual(slice_from([1, 2, 3, 4, 5], 2), [3, 4, 5])
        self.assertEqual(slice_from([1, 2], 4), [])

    def test_none_returns_empty_list(self):
        """None value returns empty list."""
        self.assertEqual(slice_from(None, 2), [])

    def test_invalid_start_returns_full_list(self):
        """Invalid start_index falls back to full list."""
        self.assertEqual(slice_from([1, 2, 3], "x"), [1, 2, 3])


class TestSubtract(BaseTestCase):
    """Tests for subtract filter (for '+N more' count)."""

    def test_subtracts_integers(self):
        """Returns value - arg."""
        self.assertEqual(subtract(10, 4), 6)
        self.assertEqual(subtract(5, 5), 0)

    def test_coerces_strings_to_int(self):
        """Coerces string numbers to int."""
        self.assertEqual(subtract("10", "4"), 6)

    def test_invalid_returns_zero(self):
        """Invalid values return 0."""
        self.assertEqual(subtract("x", 4), 0)
        self.assertEqual(subtract(10, "y"), 0)


class TestCategoryIconUnknown(BaseTestCase):
    """Tests for category_icon when category is unknown."""

    def test_unknown_returns_tag(self):
        """'unknown' category uses 'tag' icon for untagged tasks."""
        self.assertEqual(category_icon("unknown"), "tag")

    def test_empty_returns_tag(self):
        """Empty category returns 'tag' icon."""
        self.assertEqual(category_icon(""), "tag")
        self.assertEqual(category_icon(None), "tag")
