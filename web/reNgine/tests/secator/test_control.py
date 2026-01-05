"""
Tests for SecatorScanController functionality.
"""

import unittest
from unittest.mock import Mock, patch

from reNgine.secator.control import SecatorScanController
from startScan.models import SecatorRunner


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

    @patch("reNgine.secator.control.SecatorRunner")
    @patch("reNgine.secator.control.ScanRepository")
    @patch("secator.celery.revoke_task")
    def test_stop_scan_single_task(self, mock_revoke_task, mock_scan_repo_class, mock_secator_runner_class):
        """Test stopping a scan with a single Celery task."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan_repo.get_by_id.return_value = mock_scan

        # Create mock runner with celery_id
        mock_runner = Mock()
        mock_runner.celery_id = "task-123"
        mock_secator_runner_class.objects.filter.return_value = [mock_runner]

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        result = controller.stop_scan()

        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        mock_secator_runner_class.objects.filter.assert_called_once_with(scan_history_id=self.scan_history_id)
        mock_revoke_task.assert_called_once_with("task-123", task_name=f"scan_{self.scan_history_id}")
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_called_once()

    @patch("reNgine.secator.control.SecatorRunner")
    @patch("reNgine.secator.control.ScanRepository")
    @patch("secator.celery.revoke_task")
    def test_stop_scan_multiple_tasks(self, mock_revoke_task, mock_scan_repo_class, mock_secator_runner_class):
        """Test stopping a scan with multiple Celery tasks."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan_repo.get_by_id.return_value = mock_scan

        # Create mock runners with celery_ids
        mock_runner1 = Mock()
        mock_runner1.celery_id = "task-123"
        mock_runner2 = Mock()
        mock_runner2.celery_id = "task-456"
        mock_runner3 = Mock()
        mock_runner3.celery_id = "task-789"
        mock_secator_runner_class.objects.filter.return_value = [mock_runner1, mock_runner2, mock_runner3]

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        result = controller.stop_scan()

        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        mock_secator_runner_class.objects.filter.assert_called_once_with(scan_history_id=self.scan_history_id)
        self.assertEqual(mock_revoke_task.call_count, 3)
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_called_once()

    @patch("reNgine.secator.control.SecatorRunner")
    @patch("reNgine.secator.control.ScanRepository")
    @patch("secator.celery.revoke_task")
    def test_stop_scan_partial_revocation_failure(self, mock_revoke_task, mock_scan_repo_class, mock_secator_runner_class):
        """Test stopping a scan when some task revocations fail."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan_repo.get_by_id.return_value = mock_scan

        # Create mock runners with celery_ids
        mock_runner1 = Mock()
        mock_runner1.celery_id = "task-123"
        mock_runner2 = Mock()
        mock_runner2.celery_id = "task-456"
        mock_secator_runner_class.objects.filter.return_value = [mock_runner1, mock_runner2]

        def side_effect(task_id, task_name=None):
            if task_id == "task-456":
                raise Exception("Revocation failed")

        mock_revoke_task.side_effect = side_effect

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        result = controller.stop_scan()

        self.assertTrue(result)
        mock_secator_runner_class.objects.filter.assert_called_once_with(scan_history_id=self.scan_history_id)
        self.assertEqual(mock_revoke_task.call_count, 2)
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_called_once()

    @patch("reNgine.secator.control.SecatorRunner")
    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_no_tasks(self, mock_scan_repo_class, mock_secator_runner_class):
        """Test stopping a scan with no Celery tasks."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan_repo.get_by_id.return_value = mock_scan

        # No runners found
        mock_secator_runner_class.objects.filter.return_value = []

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        result = controller.stop_scan()

        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        mock_secator_runner_class.objects.filter.assert_called_once_with(scan_history_id=self.scan_history_id)
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_not_called()

    @patch("reNgine.secator.control.SecatorRunner")
    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_none_tasks(self, mock_scan_repo_class, mock_secator_runner_class):
        """Test stopping a scan with no runners."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan = Mock()
        mock_scan_repo.get_by_id.return_value = mock_scan

        # No runners found
        mock_secator_runner_class.objects.filter.return_value = []

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        result = controller.stop_scan()

        self.assertTrue(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)
        mock_secator_runner_class.objects.filter.assert_called_once_with(scan_history_id=self.scan_history_id)
        mock_scan_repo.update_status.assert_called_once()
        mock_scan_repo.create_scan_activity.assert_not_called()

    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_not_found(self, mock_scan_repo_class):
        """Test stopping a scan that doesn't exist."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan_repo.get_by_id.return_value = None

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        result = controller.stop_scan()

        self.assertFalse(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)

    @patch("reNgine.secator.control.ScanRepository")
    def test_stop_scan_repository_error(self, mock_scan_repo_class):
        """Test stopping a scan when repository raises an error."""
        mock_scan_repo = Mock()
        mock_scan_repo_class.return_value = mock_scan_repo
        mock_scan_repo.get_by_id.side_effect = Exception("Database error")

        controller = SecatorScanController(self.scan_history_id)
        controller.scan_repo = mock_scan_repo

        result = controller.stop_scan()

        self.assertFalse(result)
        mock_scan_repo.get_by_id.assert_called_once_with(self.scan_history_id)

    def test_pause_scan_not_implemented(self):
        """Test that pause_scan returns False (not implemented)."""
        result = self.controller.pause_scan()
        self.assertFalse(result)

    def test_resume_scan_not_implemented(self):
        """Test that resume_scan returns False (not implemented)."""
        result = self.controller.resume_scan()
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
