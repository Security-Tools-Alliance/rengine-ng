"""
Tests for SecatorRunner scan execution.
"""

from unittest.mock import MagicMock, patch

from django.utils import timezone

from reNgine.secator.runner import SecatorRunner
from scanEngine.models import SecatorScan
from startScan.models import Domain, ScanHistory
from utils.test_base import BaseTestCase


class TestSecatorRunnerScans(BaseTestCase):
    """Test cases for SecatorRunner scan execution."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.runner = SecatorRunner()
        self.data_generator.create_target()
        scan_history = ScanHistory.objects.create(
            target=self.data_generator.target,
            start_scan_date=timezone.now(),
            scan_status=2,
        )
        self.domain = Domain.objects.create(
            name="testdomain.com",
            insert_date=timezone.now(),
            scan_history=scan_history,
        )

        self.builtin_scan = SecatorScan.objects.create(
            name="domain",
            description="Test domain scan",
            scan_config_type="builtin",
            yaml_configuration="",
            is_active=True,
            scan_type="internet",
        )

        self.custom_scan = SecatorScan.objects.create(
            name="custom_test",
            description="Custom test scan",
            scan_config_type="custom",
            yaml_configuration="""
name: custom_test
description: Custom test scan
type: scan
workflows:
  subdomain_enum:
    - subfinder
    - dnsx
""",
            is_active=True,
            scan_type="internet",
        )

    def tearDown(self):
        """Clean up test data."""
        SecatorScan.objects.all().delete()
        Domain.objects.all().delete()
        super().tearDown()

    @patch("reNgine.secator.runner.os.makedirs")
    @patch("reNgine.secator.runner.Scan")
    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_scan_builtin_success(self, mock_template_loader, mock_scan_class, mock_makedirs):
        """Test successful execution of builtin scan."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        mock_scan_instance = MagicMock()
        mock_scan_instance.run.return_value = {"items": [], "stats": {}}
        mock_scan_class.return_value = mock_scan_instance
        mock_scan_class.__name__ = "Scan"

        result = self.runner.run_scan(
            scan_type="domain",
            targets=["testdomain.com"],
            scan_history_id=1,
            target_id=self.domain.scan_history.target_id,
            config={},
            profiles={},
        )

        if result["status"] != "success":
            print(f"Error in test: {result.get('error', 'Unknown error')}")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["targets"], ["testdomain.com"])
        mock_template_loader.assert_called_once_with(name="scan/domain")
        mock_scan_instance.run.assert_called_once()

    @patch("reNgine.secator.runner.os.makedirs")
    @patch("reNgine.secator.runner.Scan")
    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_scan_custom_success(self, mock_template_loader, mock_scan_class, mock_makedirs):
        """Test successful execution of custom scan."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        mock_scan_instance = MagicMock()
        mock_scan_instance.run.return_value = {"items": [], "stats": {}}
        mock_scan_class.return_value = mock_scan_instance
        mock_scan_class.__name__ = "Scan"

        result = self.runner.run_scan(
            scan_type="custom_test",
            targets=["testdomain.com"],
            scan_history_id=1,
            target_id=self.domain.scan_history.target_id,
            config={},
            profiles={},
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["targets"], ["testdomain.com"])
        self.assertTrue(mock_template_loader.called)
        yaml_arg = mock_template_loader.call_args[0][0]
        self.assertIn("custom_test", yaml_arg)
        mock_scan_instance.run.assert_called_once()

    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_scan_nonexistent_scan(self, mock_template_loader):
        """Test error handling when scan doesn't exist."""
        mock_template_loader.side_effect = Exception("Scan not found")

        result = self.runner.run_scan(
            scan_type="nonexistent",
            targets=["testdomain.com"],
            scan_history_id=1,
            target_id=self.domain.scan_history.target_id,
            config={},
            profiles={},
        )

        self.assertEqual(result["status"], "error")
        self.assertIn("error", result)

    @patch("reNgine.secator.runner.Scan")
    @patch("reNgine.secator.runner.TemplateLoader")
    def test_load_scan_template_builtin(self, mock_template_loader, mock_scan_class):
        """Test loading builtin scan template."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        template = self.runner._load_scan_template("domain")

        mock_template_loader.assert_called_once_with(name="scan/domain")
        self.assertEqual(template, mock_template)

    @patch("reNgine.secator.runner.TemplateLoader")
    def test_load_scan_template_custom(self, mock_template_loader):
        """Test loading custom scan template."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        template = self.runner._load_scan_template("custom_test")

        self.assertTrue(mock_template_loader.called)
        yaml_arg = mock_template_loader.call_args[0][0]
        self.assertIn("custom_test", yaml_arg)
        self.assertEqual(template, mock_template)
