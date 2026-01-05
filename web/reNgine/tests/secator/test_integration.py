"""
Integration tests for Secator components.
"""

from reNgine.services.scan.scan_orchestrator import ScanOrchestrator
from utils.test_base import BaseTestCase


class TestSecatorIntegration(BaseTestCase):
    """Integration tests for Secator components."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()

        from targetApp.models import Domain

        self.domain, _ = Domain.objects.get_or_create(
            name="test-secator.com", defaults={"project": self.data_generator.project}
        )

    def test_scan_orchestrator_initialization(self):
        """Test ScanOrchestrator initialization."""
        orchestrator = ScanOrchestrator()

        self.assertIsNotNone(orchestrator.secator_runner)
        self.assertIsNotNone(orchestrator.scan_repo)

    def test_scan_orchestrator_invalid_execution_mode(self):
        """Test ScanOrchestrator with invalid execution mode."""
        orchestrator = ScanOrchestrator()

        with self.assertRaises(ValueError) as context:
            orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="invalid_mode",
                targets=["example.com"],
                config={},
            )

        self.assertIn("Unknown execution mode", str(context.exception))

    def test_scan_orchestrator_workflow_missing_name(self):
        """Test ScanOrchestrator workflow execution with missing workflow name."""
        orchestrator = ScanOrchestrator()

        with self.assertRaises(ValueError) as context:
            orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="workflow",
                targets=["example.com"],
                config={},
            )

        self.assertIn("workflow_name is required", str(context.exception))

    def test_scan_orchestrator_tasks_missing_list(self):
        """Test ScanOrchestrator tasks execution with missing tasks list."""
        orchestrator = ScanOrchestrator()

        with self.assertRaises(ValueError) as context:
            orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="tasks",
                targets=["example.com"],
                config={},
            )

        self.assertIn("tasks list is required", str(context.exception))

    def test_scan_orchestrator_scan_missing_scan_type(self):
        """Test ScanOrchestrator scan execution with missing scan_type."""
        orchestrator = ScanOrchestrator()

        with self.assertRaises(ValueError) as context:
            orchestrator.execute_scan(
                scan_history_id=self.scan_history.id,
                domain_id=self.domain.id,
                execution_mode="scan",
                targets=["example.com"],
                config={},
            )

        self.assertIn("scan_type is required", str(context.exception))
