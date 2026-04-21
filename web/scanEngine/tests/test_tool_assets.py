"""
Unit tests for scanEngine.tool_assets (asset filename normalization and upload).
"""

from scanEngine.tool_assets import _normalize_asset_filename
from utils.test_base import BaseTestCase


class TestNormalizeAssetFilename(BaseTestCase):
    """Tests for _normalize_asset_filename."""

    def setUp(self):
        super().setUp()

    def test_normal_name_unchanged(self):
        self.assertEqual(_normalize_asset_filename("my-pattern"), "my-pattern")

    def test_strips_invalid_chars(self):
        self.assertEqual(
            _normalize_asset_filename('foo/\\*?:"<>|bar'),
            "foobar",
        )

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(_normalize_asset_filename("  my_asset  "), "my_asset")

    def test_removes_leading_dots(self):
        self.assertEqual(_normalize_asset_filename(".env"), "env")
        self.assertEqual(_normalize_asset_filename("..hidden"), "hidden")

    def test_empty_after_sanitization_returns_none(self):
        self.assertIsNone(_normalize_asset_filename(""))
        self.assertIsNone(_normalize_asset_filename("   "))
        self.assertIsNone(_normalize_asset_filename("..."))
        self.assertIsNone(_normalize_asset_filename(".*?:<>|"))

    def test_truncates_to_max_length(self):
        long_name = "a" * 150
        result = _normalize_asset_filename(long_name, max_length=100)
        self.assertEqual(len(result), 100)
        self.assertEqual(result, "a" * 100)

    def test_only_dots_and_spaces_returns_none(self):
        self.assertIsNone(_normalize_asset_filename("." * 101))
