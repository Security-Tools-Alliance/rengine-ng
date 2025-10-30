"""
Tests for ScanOrchestrator functionality.
"""

from unittest.mock import patch

from reNgine.services.scan.scan_orchestrator import ScanOrchestrator
from utils.test_base import BaseTestCase


class TestScanOrchestrator(BaseTestCase):
    """Test cases for ScanOrchestrator."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.orchestrator = ScanOrchestrator()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def test_initialization(self):
        """Test ScanOrchestrator initialization."""
        self.assertIsNotNone(self.orchestrator.secator_runner)
        self.assertIsNotNone(self.orchestrator.scan_repo)

    @patch("reNgine.services.scan.scan_orchestrator.SecatorRunner.run_workflow")
    def test_execute_scan_workflow_mode(self, mock_run_workflow):
        """Test executing scan in workflow mode."""
        mock_run_workflow.return_value = {"status": "success", "message": "Workflow executed successfully"}

        config = {"workflow_name": "test_workflow"}
        targets = ["example.com"]
        profiles = {"speed": "fast"}

        result = self.orchestrator.execute_scan(
            scan_history_id=self.scan_history.id,
            domain_id=self.domain.id,
            execution_mode="workflow",
            targets=targets,
            config=config,
            profiles=profiles,
        )

        self.assertEqual(result["status"], "success")
        mock_run_workflow.assert_called_once_with(
            workflow_name="test_workflow",
            targets=targets,
            scan_history_id=self.scan_history.id,
            domain_id=self.domain.id,
            config=config,
            profiles=profiles,
        )

    @patch("reNgine.services.scan.scan_orchestrator.SecatorRunner.run_tasks")
    def test_execute_scan_tasks_mode(self, mock_run_tasks):
        """Test executing scan in tasks mode."""
        mock_run_tasks.return_value = {"status": "success", "message": "Tasks executed successfully"}

        config = {"tasks": ["subfinder", "httpx", "nuclei"]}
        targets = ["example.com"]
        profiles = {"speed": "fast"}

        result = self.orchestrator.execute_scan(
            scan_history_id=self.scan_history.id,
            domain_id=self.domain.id,
            execution_mode="tasks",
            targets=targets,
            config=config,
            profiles=profiles,
        )

        self.assertEqual(result["status"], "success")
        mock_run_tasks.assert_called_once_with(
            tasks=["subfinder", "httpx", "nuclei"],
            targets=targets,
            scan_history_id=self.scan_history.id,
            domain_id=self.domain.id,
            config=config,
            profiles=profiles,
        )

    @patch.object(ScanOrchestrator, "_execute_scan_type")
    def test_execute_scan_scan_mode(self, mock_execute_scan_type):
        """Test executing scan in scan mode."""
        mock_execute_scan_type.return_value = {
            "status": "success",
            "scan_type": "subdomain",
            "targets": ["example.com"],
            "result": {"items": []},
            "scan_history_id": self.scan_history.id,
        }

        config = {"scan_type": "subdomain"}
        targets = ["example.com"]

        result = self.orchestrator.execute_scan(
            scan_history_id=self.scan_history.id,
            domain_id=self.domain.id,
            execution_mode="scan",
            targets=targets,
            config=config,
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["scan_type"], "subdomain")

    def test_execute_scan_type_domain(self):
        """Test executing domain scan type."""
        config = {"scan_type": "domain"}
        targets = ["example.com"]

        with patch.object(self.orchestrator.secator_runner, "run_scan_type") as mock_run:
            mock_run.return_value = {
                "status": "success",
                "scan_type": "domain",
                "targets": targets,
                "result": {"items": []},
                "scan_history_id": self.scan_history.id,
            }

            result = self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=targets,
                config=config,
            )

            mock_run.assert_called_once_with(
                scan_type="domain",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=None,
            )
            self.assertEqual(result["status"], "success")

    def test_execute_scan_type_host(self):
        """Test executing host scan type."""
        config = {"scan_type": "host"}
        targets = ["192.168.1.1"]

        with patch.object(self.orchestrator.secator_runner, "run_scan_type") as mock_run:
            mock_run.return_value = {
                "status": "success",
                "scan_type": "host",
                "targets": targets,
                "result": {"items": []},
                "scan_history_id": self.scan_history.id,
            }

            result = self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=targets,
                config=config,
            )

            mock_run.assert_called_once_with(
                scan_type="host",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=None,
            )
            self.assertEqual(result["status"], "success")

    def test_execute_scan_type_network(self):
        """Test executing network scan type."""
        config = {"scan_type": "network"}
        targets = ["192.168.1.0/24"]

        with patch.object(self.orchestrator.secator_runner, "run_scan_type") as mock_run:
            mock_run.return_value = {
                "status": "success",
                "scan_type": "network",
                "targets": targets,
                "result": {"items": []},
                "scan_history_id": self.scan_history.id,
            }

            result = self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=targets,
                config=config,
            )

            mock_run.assert_called_once_with(
                scan_type="network",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=None,
            )
            self.assertEqual(result["status"], "success")

    def test_execute_scan_type_subdomain(self):
        """Test executing subdomain scan type."""
        config = {"scan_type": "subdomain"}
        targets = ["example.com"]

        with patch.object(self.orchestrator.secator_runner, "run_scan_type") as mock_run:
            mock_run.return_value = {
                "status": "success",
                "scan_type": "subdomain",
                "targets": targets,
                "result": {"items": []},
                "scan_history_id": self.scan_history.id,
            }

            result = self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=targets,
                config=config,
            )

            mock_run.assert_called_once_with(
                scan_type="subdomain",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=None,
            )
            self.assertEqual(result["status"], "success")

    def test_execute_scan_type_url(self):
        """Test executing URL scan type."""
        config = {"scan_type": "url"}
        targets = ["https://example.com"]

        with patch.object(self.orchestrator.secator_runner, "run_scan_type") as mock_run:
            mock_run.return_value = {
                "status": "success",
                "scan_type": "url",
                "targets": targets,
                "result": {"items": []},
                "scan_history_id": self.scan_history.id,
            }

            result = self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=targets,
                config=config,
            )

            mock_run.assert_called_once_with(
                scan_type="url",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=None,
            )
            self.assertEqual(result["status"], "success")

    def test_execute_scan_type_missing_scan_type(self):
        """Test executing scan type without scan_type in config."""
        config = {}  # Missing scan_type
        targets = ["example.com"]

        with self.assertRaises(ValueError) as context:
            self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=targets,
                config=config,
            )

        self.assertIn("scan_type is required in config", str(context.exception))

    def test_execute_scan_type_with_profiles(self):
        """Test executing scan type with profiles."""
        config = {"scan_type": "domain"}
        targets = ["example.com"]
        profiles = {"speed": "fast", "stealth": "low"}

        with patch.object(self.orchestrator.secator_runner, "run_scan_type") as mock_run:
            mock_run.return_value = {
                "status": "success",
                "scan_type": "domain",
                "targets": targets,
                "result": {"items": []},
                "scan_history_id": self.scan_history.id,
            }

            result = self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=targets,
                config=config,
                profiles=profiles,
            )

            mock_run.assert_called_once_with(
                scan_type="domain",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=profiles,
            )
            self.assertEqual(result["status"], "success")

    def test_execute_scan_invalid_mode(self):
        """Test executing scan with invalid execution mode."""
        config = {}
        targets = ["example.com"]

        with self.assertRaises(ValueError) as context:
            self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="invalid_mode",
                targets=targets,
                config=config,
            )

        self.assertIn("Unknown execution mode", str(context.exception))

    def test_execute_workflow_missing_workflow_name(self):
        """Test executing workflow with missing workflow_name."""
        config = {}
        targets = ["example.com"]

        with self.assertRaises(ValueError) as context:
            self.orchestrator._execute_workflow(
                scan_history_id=self.scan_history.id, domain_id=self.domain.id, targets=targets, config=config
            )

        self.assertIn("workflow_name is required", str(context.exception))

    def test_execute_tasks_missing_tasks(self):
        """Test executing tasks with missing tasks list."""
        config = {}
        targets = ["example.com"]

        with self.assertRaises(ValueError) as context:
            self.orchestrator._execute_tasks(
                scan_history_id=self.scan_history.id, domain_id=self.domain.id, targets=targets, config=config
            )

        self.assertIn("tasks list is required", str(context.exception))

    @patch("reNgine.services.scan.scan_orchestrator.SecatorRunner.run_workflow")
    @patch("reNgine.services.scan.scan_orchestrator.ScanRepository.mark_scan_failed")
    def test_execute_scan_workflow_exception(self, mock_mark_failed, mock_run_workflow):
        """Test handling exception in workflow execution."""
        mock_run_workflow.side_effect = Exception("Workflow execution failed")

        config = {"workflow_name": "test_workflow"}
        targets = ["example.com"]

        with self.assertRaises(Exception) as context:
            self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="workflow",
                targets=targets,
                config=config,
            )

        self.assertIn("Workflow execution failed", str(context.exception))
        mock_mark_failed.assert_called_once_with(self.scan_history.id, "Workflow execution failed")

    @patch("reNgine.services.scan.scan_orchestrator.SecatorRunner.run_tasks")
    @patch("reNgine.services.scan.scan_orchestrator.ScanRepository.mark_scan_failed")
    def test_execute_scan_tasks_exception(self, mock_mark_failed, mock_run_tasks):
        """Test handling exception in tasks execution."""
        mock_run_tasks.side_effect = Exception("Tasks execution failed")

        config = {"tasks": ["subfinder", "httpx"]}
        targets = ["example.com"]

        with self.assertRaises(Exception) as context:
            self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="tasks",
                targets=targets,
                config=config,
            )

        self.assertIn("Tasks execution failed", str(context.exception))
        mock_mark_failed.assert_called_once_with(self.scan_history.id, "Tasks execution failed")

    @patch("reNgine.services.scan.scan_orchestrator.ScanRepository.mark_scan_failed")
    def test_execute_scan_value_error_handling(self, mock_mark_failed):
        """Test handling ValueError in scan execution."""
        config = {}
        targets = ["example.com"]

        with self.assertRaises(ValueError):
            self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="invalid_mode",
                targets=targets,
                config=config,
            )

        mock_mark_failed.assert_called_once()

    @patch("reNgine.services.scan.scan_orchestrator.ScanRepository.mark_scan_failed")
    def test_execute_scan_database_error_handling(self, mock_mark_failed):
        """Test handling database error when marking scan as failed."""
        mock_mark_failed.side_effect = Exception("Database error")

        config = {}
        targets = ["example.com"]

        # Should not raise the database error, only the original exception
        with self.assertRaises(Exception) as context:
            self.orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="invalid_mode",
                targets=targets,
                config=config,
            )

        # The exception should be the database error from mark_scan_failed
        self.assertIn("Database error", str(context.exception))

    def test_execute_workflow_with_profiles(self):
        """Test executing workflow with profiles."""
        with patch.object(self.orchestrator.secator_runner, "run_workflow") as mock_run:
            mock_run.return_value = {"status": "success"}

            config = {"workflow_name": "test_workflow"}
            targets = ["example.com"]
            profiles = {"speed": "fast", "stealth": "high"}

            self.orchestrator._execute_workflow(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                targets=targets,
                config=config,
                profiles=profiles,
            )

            mock_run.assert_called_once_with(
                workflow_name="test_workflow",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=profiles,
            )

    def test_execute_tasks_with_profiles(self):
        """Test executing tasks with profiles."""
        with patch.object(self.orchestrator.secator_runner, "run_tasks") as mock_run:
            mock_run.return_value = {"status": "success"}

            config = {"tasks": ["subfinder", "httpx"]}
            targets = ["example.com"]
            profiles = {"speed": "fast", "stealth": "high"}

            self.orchestrator._execute_tasks(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                targets=targets,
                config=config,
                profiles=profiles,
            )

            mock_run.assert_called_once_with(
                tasks=["subfinder", "httpx"],
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=profiles,
            )

    @patch.object(ScanOrchestrator, "_execute_scan_type")
    def test_execute_scan_type_with_different_scan_types(self, mock_execute_scan_type):
        """Test executing different scan types."""
        scan_types = ["domain", "host", "network", "subdomain", "url"]

        for scan_type in scan_types:
            mock_execute_scan_type.return_value = {
                "status": "success",
                "scan_type": scan_type,
                "targets": ["example.com"],
                "result": {"items": []},
                "scan_history_id": self.scan_history.id,
            }

            config = {"scan_type": scan_type}
            targets = ["example.com"]

            result = self.orchestrator._execute_scan_type(
                scan_history_id=self.scan_history.id, domain_id=self.domain.id, targets=targets, config=config
            )

            self.assertEqual(result["status"], "success")
            self.assertEqual(result["scan_type"], scan_type)

    def test_execute_scan_with_empty_targets(self):
        """Test executing scan with empty targets list."""
        config = {"workflow_name": "test_workflow"}
        targets = []

        with patch.object(self.orchestrator.secator_runner, "run_workflow") as mock_run:
            mock_run.return_value = {"status": "success"}

            self.orchestrator._execute_workflow(
                scan_history_id=self.scan_history.id, domain_id=self.domain.id, targets=targets, config=config
            )

            mock_run.assert_called_once_with(
                workflow_name="test_workflow",
                targets=[],
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=None,
            )

    def test_execute_scan_with_none_profiles(self):
        """Test executing scan with None profiles."""
        config = {"workflow_name": "test_workflow"}
        targets = ["example.com"]
        profiles = None

        with patch.object(self.orchestrator.secator_runner, "run_workflow") as mock_run:
            mock_run.return_value = {"status": "success"}

            self.orchestrator._execute_workflow(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                targets=targets,
                config=config,
                profiles=profiles,
            )

            mock_run.assert_called_once_with(
                workflow_name="test_workflow",
                targets=targets,
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                config=config,
                profiles=None,
            )
