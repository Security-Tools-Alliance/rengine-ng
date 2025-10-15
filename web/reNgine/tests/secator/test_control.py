"""
Tests for SecatorScanController functionality.
"""

import unittest
from unittest.mock import Mock, call, patch

from reNgine.secator.control import SecatorScanController


class TestSecatorScanController(unittest.TestCase):
    """Test cases for SecatorScanController."""

    def setUp(self):
        """Set up test fixtures."""
        self.scan_history_id = 123
        self.controller = SecatorScanController(self.scan_history_id)

    @patch("reNgine.secator.control.ScanRepository")
    def test_init(self, mock_scan_repo_class):
        """Test SecatorScanController initialization."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo

        controller = SecatorScanController(456)

        self.assertEqual(controller.scan_history_id, 456)
        self.assertEqual(controller.scan_repo, mock_scan_repo)
        mock_scan_repo_class.assert_called_once()

    @patch("reNgine.secator.control.ScanRepository")
    @patch("reNgine.celery.app")
    def test_stop_scan_single_task(self, mock_app, mock_scan_repo_class):
        """Test stopping a scan with a single Celery task."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan.celery_ids = ["task-123"]
        mock_scan_repo.get_by_id.return_value = mock_scan

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        # Execute
        result = controller.stop_scan()

        # Verify
        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        mock_app.control.revoke.assert_called_once_with("task-123", terminate=True)
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_called_once()

    @patch("reNgine.secator.control.ScanRepository")
    @patch("reNgine.celery.app")
    def test_stop_scan_multiple_tasks(self, mock_app, mock_scan_repo_class):
        """Test stopping a scan with multiple Celery tasks."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan.celery_ids = ["task-123", "task-456", "task-789"]
        mock_scan_repo.get_by_id.return_value = mock_scan

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        # Execute
        result = controller.stop_scan()

        # Verify
        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        self.assertEqual(mock_app.control.revoke.call_count, 3)
        mock_app.control.revoke.assert_has_calls(
            [call("task-123", terminate=True), call("task-456", terminate=True), call("task-789", terminate=True)]
        )
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_called_once()

    @patch("reNgine.secator.control.ScanRepository")
    @patch("reNgine.celery.app")
    def test_stop_scan_partial_revocation_failure(self, mock_app, mock_scan_repo_class):
        """Test stopping a scan when some task revocations fail."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan.celery_ids = ["task-123", "task-456"]
        mock_scan_repo.get_by_id.return_value = mock_scan

        # Make one revocation fail
        def side_effect(task_id, terminate):
            if task_id == "task-456":
                raise Exception("Revocation failed")

        mock_app.control.revoke.side_effect = side_effect

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        # Execute
        result = controller.stop_scan()

        # Verify
        self.assertTrue(result)
        self.assertEqual(mock_app.control.revoke.call_count, 2)
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_called_once()

    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_no_tasks(self, mock_scan_repo_class):
        """Test stopping a scan with no Celery tasks."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan.celery_ids = []
        mock_scan_repo.get_by_id.return_value = mock_scan

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        # Execute
        result = controller.stop_scan()

        # Verify
        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        mock_scan_repo.update_status.assert_called_once()
        # When no tasks, create_scan_activity is not called
        mock_scan_repo.create_scan_activity.assert_not_called()

    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_none_tasks(self, mock_scan_repo_class):
        """Test stopping a scan with None Celery tasks."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan.celery_ids = None
        mock_scan_repo.get_by_id.return_value = mock_scan

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        # Execute
        result = controller.stop_scan()

        # Verify
        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        mock_scan_repo.update_status.assert_called_once()
        # When no tasks, create_scan_activity is not called
        mock_scan_repo.create_scan_activity.assert_not_called()

    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_not_found(self, mock_scan_repo_class):
        """Test stopping a scan that doesn't exist."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan_repo.get_by_id.return_value = None

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        # Execute
        result = controller.stop_scan()

        # Verify
        self.assertFalse(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)

    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_repository_error(self, mock_scan_repo_class):
        """Test stopping a scan when repository raises an error."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan_repo.get_by_id.side_effect = Exception("Database error")

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        # Execute
        result = controller.stop_scan()

        # Verify
        self.assertFalse(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)


if __name__ == "__main__":
    unittest.main()
