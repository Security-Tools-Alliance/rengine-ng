"""
Tests for Secator path configuration diagnostic (get_secator_prefix_diagnostic).
"""

from pathlib import Path
import tempfile
from unittest.mock import patch

from reNgine.secator.diagnostic import get_secator_prefix_diagnostic
from utils.test_base import BaseTestCase


class GetSecatorPrefixDiagnosticTestCase(BaseTestCase):
    """Tests for get_secator_prefix_diagnostic."""

    def test_returns_dict_with_expected_keys(self):
        with patch("reNgine.secator.diagnostic.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = "/home/secator/.secator/reports"
            mock_settings.RENGINE_RESULTS = str(Path.home() / "scan_results")
            diag = get_secator_prefix_diagnostic(sample_size=5)
        self.assertIn("prefix_configured", diag)
        self.assertIn("rengine_results", diag)
        self.assertIn("rengine_results_exists", diag)
        self.assertIn("rengine_results_readable", diag)
        self.assertIn("paths_still_with_prefix", diag)
        self.assertIn("count_paths_still_with_prefix", diag)
        self.assertIn("count_total_with_path", diag)
        self.assertIn("ok", diag)
        self.assertIsInstance(diag["paths_still_with_prefix"], list)

    def test_prefix_configured_reflects_settings(self):
        with patch("reNgine.secator.diagnostic.settings") as mock_settings:
            mock_settings.SECATOR_REPORTS_PREFIX = "/custom/prefix"
            mock_settings.RENGINE_RESULTS = "/tmp/results"
            diag = get_secator_prefix_diagnostic(sample_size=5)
        self.assertEqual(diag["prefix_configured"], "/custom/prefix")
        self.assertEqual(diag["rengine_results"], "/tmp/results")

    def test_ok_true_when_results_dir_readable_and_no_legacy_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("reNgine.secator.diagnostic.settings") as mock_settings:
                mock_settings.SECATOR_REPORTS_PREFIX = "/home/secator/.secator/reports"
                mock_settings.RENGINE_RESULTS = tmpdir
                diag = get_secator_prefix_diagnostic(sample_size=5)
        self.assertTrue(diag["rengine_results_exists"])
        self.assertTrue(diag["rengine_results_readable"])
        self.assertEqual(diag["count_paths_still_with_prefix"], 0)
        self.assertTrue(diag["ok"])

    def test_detects_stored_paths_still_with_prefix(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        legacy_path = "/home/secator/.secator/reports/workspace/screenshot.png"
        self.data_generator.create_endpoint(screenshot_path=legacy_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("reNgine.secator.diagnostic.settings") as mock_settings:
                mock_settings.SECATOR_REPORTS_PREFIX = "/home/secator/.secator/reports"
                mock_settings.RENGINE_RESULTS = tmpdir
                diag = get_secator_prefix_diagnostic(sample_size=10)
        self.assertEqual(diag["count_paths_still_with_prefix"], 1)
        self.assertGreaterEqual(len(diag["paths_still_with_prefix"]), 1)
        self.assertFalse(diag["ok"])

    def test_relative_paths_not_counted_as_still_with_prefix(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        relative_path = "workspace/domain/screenshot.png"
        self.data_generator.create_endpoint(screenshot_path=relative_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("reNgine.secator.diagnostic.settings") as mock_settings:
                mock_settings.SECATOR_REPORTS_PREFIX = "/home/secator/.secator/reports"
                mock_settings.RENGINE_RESULTS = tmpdir
                diag = get_secator_prefix_diagnostic(sample_size=10)
        self.assertEqual(diag["count_paths_still_with_prefix"], 0)
        self.assertEqual(len(diag["paths_still_with_prefix"]), 0)
