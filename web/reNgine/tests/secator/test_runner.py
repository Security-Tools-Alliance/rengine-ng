"""
Tests for SecatorRunner to ensure workflow loading works correctly.
"""

from unittest.mock import MagicMock, patch

from django.test import TestCase

from reNgine.secator.runner import SecatorRunner
from scanEngine.models import SecatorWorkflow


class TestSecatorRunner(TestCase):
    """Test cases for SecatorRunner workflow loading."""

    def setUp(self):
        """Set up test data."""
        self.runner = SecatorRunner()

        # Create a test workflow
        self.workflow = SecatorWorkflow.objects.create(
            name="Test Subdomain Recon",
            alias="test_subdomain_recon",
            description="Test subdomain discovery workflow",
            workflow_type="builtin",
            yaml_configuration="""
name: test_subdomain_recon
description: Test subdomain discovery
tasks:
  - subfinder
  - dnsx
""",
            is_active=True,
            scan_type="internet",
        )

    def tearDown(self):
        """Clean up test data."""
        SecatorWorkflow.objects.all().delete()

    def _assert_workflow_config(self, config_obj):
        """Helper method to assert workflow configuration."""
        self.assertEqual(config_obj.name, "test_subdomain_recon")
        # Tasks should be converted from list to TaskDict format
        self.assertEqual(dict(config_obj.tasks), {"subfinder": {}, "dnsx": {}})
        self.assertTrue(hasattr(config_obj.tasks, "toDict"))
        self.assertTrue(callable(config_obj.tasks.toDict))

    def test_run_workflow_with_database_template_success(self):
        """Test workflow execution when loading template from database succeeds."""
        # Mock the _load_workflow_template and _execute_runner methods
        with (
            patch.object(self.runner, "_load_workflow_template") as mock_load_template,
            patch.object(self.runner, "_execute_runner") as mock_execute,
        ):
            mock_template = MagicMock()
            mock_load_template.return_value = mock_template
            mock_execute.return_value = {"status": "success", "result": "test_result"}

            result = self.runner.run_workflow(
                workflow_name="test_subdomain_recon", targets=["example.com"], scan_history_id=1, domain_id=1
            )

            # Verify template was loaded
            mock_load_template.assert_called_once_with("test_subdomain_recon")

            # Verify _execute_runner was called with template
            mock_execute.assert_called_once()
            call_args = mock_execute.call_args
            config_obj = call_args[1]["config"]
            self.assertEqual(config_obj, mock_template)

            # Verify result
            self.assertEqual(result["status"], "success")

    def test_run_workflow_with_database_template_detailed(self):
        """Test workflow execution with detailed template validation from database."""
        # Mock the _load_workflow_template and _execute_runner methods
        with (
            patch.object(self.runner, "_load_workflow_template") as mock_load_template,
            patch.object(self.runner, "_execute_runner") as mock_execute,
        ):
            mock_template = MagicMock()
            mock_load_template.return_value = mock_template
            mock_execute.return_value = {"status": "success", "result": "test_result"}

            result = self.runner.run_workflow(
                workflow_name="test_subdomain_recon", targets=["example.com"], scan_history_id=1, domain_id=1
            )

            # Verify template was loaded
            mock_load_template.assert_called_once_with("test_subdomain_recon")

            # Verify _execute_runner was called with template
            mock_execute.assert_called_once()
            call_args = mock_execute.call_args
            config_obj = call_args[1]["config"]
            self.assertEqual(config_obj, mock_template)

            # Verify result
            self.assertEqual(result["status"], "success")

    def test_run_workflow_with_nonexistent_workflow(self):
        """Test workflow execution with non-existent workflow."""
        result = self.runner.run_workflow(
            workflow_name="nonexistent_workflow", targets=["example.com"], scan_history_id=1, domain_id=1
        )

        # Should return error status
        self.assertEqual(result["status"], "error")
        self.assertIn("Could not load workflow template", result["error"])

    def test_run_workflow_with_workflow_no_alias(self):
        """Test workflow execution with workflow that has no alias."""
        # Create workflow without alias
        SecatorWorkflow.objects.create(
            name="Workflow Without Alias",
            alias=None,
            description="Test workflow without alias",
            workflow_type="custom",
            yaml_configuration="name: test\ntasks: []",
            is_active=True,
            scan_type="internet",
        )

        # Mock _execute_runner to avoid domain/scan_history lookup errors
        with patch.object(self.runner, "_execute_runner") as mock_execute:
            # The workflow should load successfully, but we mock execution
            # to test that workflows without alias can still be loaded by name
            mock_execute.return_value = {"status": "success", "result": "test_result"}

            result = self.runner.run_workflow(
                workflow_name="Workflow Without Alias", targets=["example.com"], scan_history_id=1, domain_id=1
            )

            # Should succeed since workflow can be loaded by name (alias is optional)
            self.assertEqual(result["status"], "success")
            mock_execute.assert_called_once()
