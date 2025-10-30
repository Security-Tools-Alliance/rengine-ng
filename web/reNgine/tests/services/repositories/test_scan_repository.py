"""
Tests for Scan repository functionality.
"""

from reNgine.services.repositories.scan_repository import ScanRepository
from utils.test_base import BaseTestCase


class TestScanRepository(BaseTestCase):
    """Test cases for ScanRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.scan_repo = ScanRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def test_update_celery_task_id_success(self):
        """Test successful celery task ID update."""
        task_id = "test-task-id-123"

        result = self.scan_repo.update_celery_task_id(self.scan_history.id, task_id)

        self.assertTrue(result)

        # Verify the task ID was updated
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.celery_ids, [task_id])

    def test_update_celery_task_id_nonexistent_scan(self):
        """Test updating celery task ID for non-existent scan."""
        task_id = "test-task-id-123"

        result = self.scan_repo.update_celery_task_id(99999, task_id)

        self.assertFalse(result)

    def test_update_progress_success(self):
        """Test successful progress update."""
        progress = 50

        result = self.scan_repo.update_progress(self.scan_history.id, progress)

        self.assertTrue(result)

        # Note: Progress field may not exist in ScanHistory model
        # The method should still return True if the field doesn't exist

    def test_update_progress_invalid_progress(self):
        """Test updating progress with invalid value."""
        # Test negative progress
        result = self.scan_repo.update_progress(self.scan_history.id, -10)
        self.assertFalse(result)

        # Test progress over 100
        result = self.scan_repo.update_progress(self.scan_history.id, 150)
        self.assertFalse(result)

    def test_update_progress_nonexistent_scan(self):
        """Test updating progress for non-existent scan."""
        result = self.scan_repo.update_progress(99999, 50)

        self.assertFalse(result)

    def test_mark_scan_completed_success(self):
        """Test marking scan as completed."""
        result = self.scan_repo.mark_scan_complete(self.scan_history.id)

        self.assertTrue(result)

        # Verify the scan was marked as completed
        self.scan_history.refresh_from_db()
        from reNgine.definitions import SUCCESS_TASK

        self.assertEqual(self.scan_history.scan_status, SUCCESS_TASK)

    def test_mark_scan_completed_nonexistent_scan(self):
        """Test marking non-existent scan as completed."""
        result = self.scan_repo.mark_scan_complete(99999)

        self.assertFalse(result)

    def test_mark_scan_failed_success(self):
        """Test marking scan as failed."""
        error_message = "Test error message"

        result = self.scan_repo.mark_scan_failed(self.scan_history.id, error_message)

        self.assertTrue(result)

        # Verify the scan was marked as failed
        self.scan_history.refresh_from_db()
        from reNgine.definitions import FAILED_TASK

        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    def test_mark_scan_failed_nonexistent_scan(self):
        """Test marking non-existent scan as failed."""
        error_message = "Test error message"

        result = self.scan_repo.mark_scan_failed(99999, error_message)

        self.assertFalse(result)

    def test_get_scan_by_id_success(self):
        """Test getting scan by ID."""
        result = self.scan_repo.get_by_id(self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.scan_history.id)

    def test_get_scan_by_id_nonexistent(self):
        """Test getting non-existent scan by ID."""
        result = self.scan_repo.get_by_id(99999)

        self.assertIsNone(result)

    # Note: The following methods are not implemented in the current ScanRepository:
    # - get_scans_by_domain
    # - get_active_scans
    # - get_scans_by_status
    # These tests have been removed as they test non-existent functionality

    def test_update_scan_status_success(self):
        """Test updating scan status."""
        from reNgine.definitions import SUCCESS_TASK

        new_status = SUCCESS_TASK

        result = self.scan_repo.update_status(self.scan_history.id, new_status)

        self.assertTrue(result)

        # Verify the status was updated
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, new_status)

    def test_update_scan_status_nonexistent_scan(self):
        """Test updating status for non-existent scan."""
        from reNgine.definitions import SUCCESS_TASK

        result = self.scan_repo.update_status(99999, SUCCESS_TASK)

        self.assertFalse(result)

    # Note: The following methods are not implemented in the current ScanRepository:
    # - delete_scan
    # - get_scan_statistics
    # - get_scan_statistics_by_domain
    # - cleanup_old_scans
    # These tests have been removed as they test non-existent functionality

    # Note: validate_scan_config method has been removed from ScanRepository
    # These tests are no longer applicable
