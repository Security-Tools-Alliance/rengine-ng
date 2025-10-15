"""
Integration tests for Secator components.
"""

from unittest.mock import call, patch

from reNgine.secator.drivers.rengine_driver import ReNgineDriver
from reNgine.secator.hooks.database_hooks import DatabaseHooks
from reNgine.secator.hooks.progress_hooks import ProgressHooks
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

    def test_database_hooks_initialization(self):
        """Test DatabaseHooks initialization."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        self.assertEqual(hooks.scan_history_id, self.scan_history.id)
        self.assertEqual(hooks.domain_id, self.domain.id)
        self.assertIsNotNone(hooks.subdomain_repo)
        self.assertIsNotNone(hooks.endpoint_repo)
        self.assertIsNotNone(hooks.vulnerability_repo)

    def test_database_hooks_on_item_subdomain(self):
        """Test DatabaseHooks on_item with subdomain item."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        # Mock the repository method
        with patch(
            "reNgine.services.repositories.subdomain_repository.SubdomainRepository.save_from_secator"
        ) as mock_save:
            item = {"_type": "subdomain", "target": "subdomain.example.com", "ip": "192.168.1.1"}

            result = hooks.on_item(item)

            # Verify the item is returned unchanged
            self.assertEqual(result, item)
            # Verify the repository method was called with correct parameters
            mock_save.assert_called_once_with(item, self.scan_history.id, self.domain.id)

    def test_database_hooks_on_item_url(self):
        """Test DatabaseHooks on_item with URL item."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        # Mock the repository method
        with patch(
            "reNgine.services.repositories.endpoint_repository.EndpointRepository.save_from_secator"
        ) as mock_save:
            item = {"_type": "url", "target": "https://example.com/path", "status_code": 200}

            result = hooks.on_item(item)

            # Verify the item is returned unchanged
            self.assertEqual(result, item)
            # Verify the repository method was called with correct parameters
            mock_save.assert_called_once_with(item, self.scan_history.id, self.domain.id)

    def test_database_hooks_on_item_vulnerability(self):
        """Test DatabaseHooks on_item with vulnerability item."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        # Mock the repository method
        with patch(
            "reNgine.services.repositories.vulnerability_repository.VulnerabilityRepository.save_from_secator"
        ) as mock_save:
            item = {
                "_type": "vulnerability",
                "name": "SQL Injection",
                "severity": "high",
                "target": "https://example.com",
            }

            result = hooks.on_item(item)

            # Verify the item is returned unchanged
            self.assertEqual(result, item)
            # Verify the repository method was called with correct parameters
            mock_save.assert_called_once_with(item, self.scan_history.id, self.domain.id)

    def test_database_hooks_on_item_unknown_type(self):
        """Test DatabaseHooks on_item with unknown item type."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        # Mock logger to verify debug message
        with patch("reNgine.secator.hooks.database_hooks.logger") as mock_logger:
            item = {"_type": "unknown_type", "data": "some data"}

            result = hooks.on_item(item)

            # Verify the item is returned unchanged
            self.assertEqual(result, item)
            # Verify debug message was logged
            mock_logger.debug.assert_called_once_with("Unhandled item type: unknown_type")

    def test_database_hooks_on_item_repository_error(self):
        """Test DatabaseHooks on_item with repository error."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        # Mock repository to raise an exception
        with patch(
            "reNgine.services.repositories.subdomain_repository.SubdomainRepository.save_from_secator"
        ) as mock_save:
            mock_save.side_effect = Exception("Database connection failed")

            # Mock logger to verify error message
            with patch("reNgine.secator.hooks.database_hooks.logger") as mock_logger:
                item = {"_type": "subdomain", "target": "subdomain.example.com"}

                result = hooks.on_item(item)

                # Verify the item is still returned unchanged
                self.assertEqual(result, item)
                # Verify error was logged
                mock_logger.error.assert_called_once_with("Error saving item to database: Database connection failed")

    def test_database_hooks_on_duplicate(self):
        """Test DatabaseHooks on_duplicate method."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        # Mock logger to verify debug message
        with patch("reNgine.secator.hooks.database_hooks.logger") as mock_logger:
            item = {"_type": "subdomain", "target": "duplicate.example.com"}

            result = hooks.on_duplicate(item)

            # Verify the item is returned unchanged
            self.assertEqual(result, item)
            # Verify debug message was logged
            mock_logger.debug.assert_called_once_with("Duplicate item detected: subdomain - duplicate.example.com")

    def test_database_hooks_on_error(self):
        """Test DatabaseHooks on_error method."""
        hooks = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        # Mock logger to verify error message
        with patch("reNgine.secator.hooks.database_hooks.logger") as mock_logger:
            item = {"_type": "error", "message": "Connection timeout", "target": "example.com"}

            result = hooks.on_error(item)

            # Verify the item is returned unchanged
            self.assertEqual(result, item)
            # Verify error was logged
            mock_logger.error.assert_called_once_with(f"Error item received: {item}")

    def test_progress_hooks_initialization(self):
        """Test ProgressHooks initialization."""
        hooks = ProgressHooks(scan_history_id=self.scan_history.id)

        self.assertEqual(hooks.scan_history_id, self.scan_history.id)
        self.assertIsNotNone(hooks.scan_repo)
        self.assertEqual(hooks.item_count, 0)

    def test_progress_hooks_on_init(self):
        """Test ProgressHooks on_init lifecycle method."""
        hooks = ProgressHooks(scan_history_id=self.scan_history.id)

        # Mock logger to verify info message
        with patch("reNgine.secator.hooks.progress_hooks.logger") as mock_logger:
            hooks.on_init()

            # Verify info message was logged
            mock_logger.info.assert_called_once_with(f"Scan {self.scan_history.id} initialized")

    def test_progress_hooks_on_start(self):
        """Test ProgressHooks on_start lifecycle method."""
        hooks = ProgressHooks(scan_history_id=self.scan_history.id)

        # Mock the repository methods
        with (
            patch.object(hooks.scan_repo, "update_status") as mock_update_status,
            patch.object(hooks.scan_repo, "create_scan_activity") as mock_create_activity,
            patch("reNgine.secator.hooks.progress_hooks.logger") as mock_logger,
        ):
            from reNgine.definitions import RUNNING_TASK

            hooks.on_start()

            # Verify repository methods were called with correct parameters
            mock_update_status.assert_called_once_with(self.scan_history.id, status=RUNNING_TASK)
            mock_create_activity.assert_called_once_with(self.scan_history.id, "Secator scan started", RUNNING_TASK)
            # Verify info message was logged
            mock_logger.info.assert_called_once_with(f"Scan {self.scan_history.id} started")

    def test_progress_hooks_on_iter(self):
        """Test ProgressHooks on_iter lifecycle method increments item_count."""
        hooks = ProgressHooks(scan_history_id=self.scan_history.id)
        initial_count = hooks.item_count

        # Mock logger to verify debug message
        with patch("reNgine.secator.hooks.progress_hooks.logger") as mock_logger:
            # Test first iteration (should not log)
            hooks.on_iter()
            self.assertEqual(hooks.item_count, initial_count + 1)
            mock_logger.debug.assert_not_called()

            # Test multiple iterations to trigger logging (every 10 items)
            for _ in range(9):  # 9 more iterations to reach 10 total
                hooks.on_iter()

            # Verify item count is now 10
            self.assertEqual(hooks.item_count, 10)
            # Verify debug message was logged
            mock_logger.debug.assert_called_once_with(f"Scan {self.scan_history.id} - 10 items processed")

    def test_progress_hooks_on_iter_multiple_logging(self):
        """Test ProgressHooks on_iter logs every 10 items."""
        hooks = ProgressHooks(scan_history_id=self.scan_history.id)

        with patch("reNgine.secator.hooks.progress_hooks.logger") as mock_logger:
            # Test 25 iterations to trigger logging at 10 and 20
            for _ in range(25):
                hooks.on_iter()

            # Verify item count is 25
            self.assertEqual(hooks.item_count, 25)
            # Verify debug messages were logged at 10 and 20
            expected_calls = [
                call(f"Scan {self.scan_history.id} - 10 items processed"),
                call(f"Scan {self.scan_history.id} - 20 items processed"),
            ]
            mock_logger.debug.assert_has_calls(expected_calls, any_order=False)

    def test_progress_hooks_on_end(self):
        """Test ProgressHooks on_end lifecycle method."""
        hooks = ProgressHooks(scan_history_id=self.scan_history.id)
        # Set some item count to test the completion message
        hooks.item_count = 42

        # Mock the repository methods
        with (
            patch.object(hooks.scan_repo, "mark_scan_complete") as mock_mark_complete,
            patch.object(hooks.scan_repo, "create_scan_activity") as mock_create_activity,
            patch("reNgine.secator.hooks.progress_hooks.logger") as mock_logger,
        ):
            from reNgine.definitions import SUCCESS_TASK

            hooks.on_end()

            # Verify repository methods were called with correct parameters
            mock_mark_complete.assert_called_once_with(self.scan_history.id)
            mock_create_activity.assert_called_once_with(
                self.scan_history.id, "Secator scan completed - 42 items processed", SUCCESS_TASK
            )
            # Verify info message was logged
            mock_logger.info.assert_called_once_with(f"Scan {self.scan_history.id} completed with 42 items")

    def test_progress_hooks_on_end_zero_items(self):
        """Test ProgressHooks on_end with zero items processed."""
        hooks = ProgressHooks(scan_history_id=self.scan_history.id)
        # Ensure item_count is 0
        hooks.item_count = 0

        # Mock the repository methods
        with (
            patch.object(hooks.scan_repo, "mark_scan_complete") as mock_mark_complete,
            patch.object(hooks.scan_repo, "create_scan_activity") as mock_create_activity,
            patch("reNgine.secator.hooks.progress_hooks.logger") as mock_logger,
        ):
            from reNgine.definitions import SUCCESS_TASK

            hooks.on_end()

            # Verify completion message includes zero items
            mock_create_activity.assert_called_once_with(
                self.scan_history.id, "Secator scan completed - 0 items processed", SUCCESS_TASK
            )
            mock_logger.info.assert_called_once_with(f"Scan {self.scan_history.id} completed with 0 items")

    def test_rengine_driver_initialization(self):
        """Test ReNgineDriver initialization."""
        driver = ReNgineDriver(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        self.assertEqual(driver.scan_history_id, self.scan_history.id)
        self.assertEqual(driver.domain_id, self.domain.id)
        self.assertIsNotNone(driver.db_hooks)
        self.assertIsNotNone(driver.progress_hooks)

    def test_rengine_driver_hooks_config(self):
        """Test ReNgineDriver hooks configuration."""
        driver = ReNgineDriver(scan_history_id=self.scan_history.id, domain_id=self.domain.id)

        hooks_config = driver.get_hooks_config()

        self.assertIsInstance(hooks_config, dict)
        self.assertIn("Task", str(hooks_config) if hooks_config else "")

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
