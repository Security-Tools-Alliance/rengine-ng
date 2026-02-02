"""
Unit tests for Secator template tags (secator_extras).
"""

from startScan.templatetags.secator_extras import category_display_label, category_icon
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


class TestCategoryIconUnknown(BaseTestCase):
    """Tests for category_icon when category is unknown."""

    def test_unknown_returns_tag(self):
        """'unknown' category uses 'tag' icon for untagged tasks."""
        self.assertEqual(category_icon("unknown"), "tag")

    def test_empty_returns_tag(self):
        """Empty category returns 'tag' icon."""
        self.assertEqual(category_icon(""), "tag")
        self.assertEqual(category_icon(None), "tag")
