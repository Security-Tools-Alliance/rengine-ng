"""
Tests for Secator path utilities: to_relative_scan_path and strip_secator_reports_prefix.
"""

from unittest.mock import patch

from reNgine.secator.path_utils import strip_secator_reports_prefix, to_relative_scan_path
from utils.test_base import BaseTestCase


class ToRelativeScanPathTestCase(BaseTestCase):
    """Unit tests for to_relative_scan_path."""

    def test_returns_none_for_empty_or_none(self):
        self.assertIsNone(to_relative_scan_path(""))
        self.assertIsNone(to_relative_scan_path(None))
        self.assertIsNone(to_relative_scan_path("   "))

    def test_returns_path_unchanged_when_already_relative(self):
        path = "example/domain/tasks/44/screenshot.png"
        self.assertEqual(to_relative_scan_path(path), path)
        self.assertEqual(to_relative_scan_path("workspace/file.txt"), "workspace/file.txt")

    def test_strips_secator_reports_prefix_when_matching(self):
        with patch("reNgine.secator.path_utils.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = "/home/secator/.secator/reports"
            mock_settings.RENGINE_RESULTS = "/data/rengine/results"
            path = "/home/secator/.secator/reports/example/domain/screenshot.png"
            self.assertEqual(
                to_relative_scan_path(path),
                "example/domain/screenshot.png",
            )

    def test_strips_rengine_results_when_matching(self):
        with patch("reNgine.secator.path_utils.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = ""
            mock_settings.RENGINE_RESULTS = "/data/rengine/results"
            path = "/data/rengine/results/workspace/domain/file.png"
            self.assertEqual(
                to_relative_scan_path(path),
                "workspace/domain/file.png",
            )

    def test_strips_secator_reports_marker_when_prefix_does_not_match(self):
        with patch("reNgine.secator.path_utils.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = "/home/webuser/.secator/reports"
            mock_settings.RENGINE_RESULTS = "/data/results"
            path = "/home/secator/.secator/reports/example/example.com/tasks/44/file.png"
            self.assertEqual(
                to_relative_scan_path(path),
                "example/example.com/tasks/44/file.png",
            )

    def test_returns_none_for_absolute_path_with_no_known_prefix(self):
        with patch("reNgine.secator.path_utils.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = "/home/x/.secator/reports"
            mock_settings.RENGINE_RESULTS = "/data"
            self.assertIsNone(to_relative_scan_path("/etc/passwd"))
            self.assertIsNone(to_relative_scan_path("/tmp/other/file.png"))

    def test_normalizes_backslashes(self):
        with patch("reNgine.secator.path_utils.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = ""
            mock_settings.RENGINE_RESULTS = ""
            path = "/home/secator/.secator/reports/a/b.png"
            self.assertEqual(to_relative_scan_path(path), "a/b.png")


class StripSecatorReportsPrefixTestCase(BaseTestCase):
    """Unit tests for strip_secator_reports_prefix (including to_relative_scan_path fallback)."""

    def test_returns_path_unchanged_for_empty(self):
        self.assertEqual(strip_secator_reports_prefix(""), "")
        self.assertEqual(strip_secator_reports_prefix(None), None)

    def test_strips_prefix_and_respects_max_length(self):
        with patch("reNgine.secator.path_utils.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = "/home/secator/.secator/reports"
            mock_settings.RENGINE_RESULTS = ""
            mock_settings.SECATOR_RESULTS = ""
            path = "/home/secator/.secator/reports/example/domain/file.png"
            self.assertEqual(
                strip_secator_reports_prefix(path),
                "example/domain/file.png",
            )

    def test_strips_via_marker_when_prefix_does_not_match(self):
        with patch("reNgine.secator.path_utils.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = "/home/webuser/.secator/reports"
            mock_settings.RENGINE_RESULTS = ""
            mock_settings.SECATOR_RESULTS = "/home/secator/.secator/reports"
            path = "/home/secator/.secator/reports/example/ws/file.png"
            result = strip_secator_reports_prefix(path)
            self.assertEqual(result, "example/ws/file.png")
