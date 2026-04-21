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
        # Scan history first (needs target), then domain linked to that scan
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

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

    def test_create_scan_activity_success(self):
        """Test creating scan activity."""
        message = "Test activity message"
        status = 1

        result = self.scan_repo.create_scan_activity(self.scan_history.id, message, status)

        self.assertIsNotNone(result)
        from startScan.models import ScanActivity

        activity = ScanActivity.objects.get(id=result)
        self.assertEqual(activity.title, message)
        self.assertEqual(activity.status, status)

    def test_create_scan_activity_nonexistent_scan(self):
        """Test creating scan activity for non-existent scan."""
        # create_scan_activity catches ObjectDoesNotExist and returns None
        result = self.scan_repo.create_scan_activity(99999, "Test message", 1)
        self.assertIsNone(result)

    def test_create_activity_success(self):
        """Test creating activity (raises on error)."""
        message = "Test activity"
        status = 1

        result = self.scan_repo.create_activity(self.scan_history.id, message, status)

        self.assertIsNotNone(result)
        from startScan.models import ScanActivity

        activity = ScanActivity.objects.get(id=result)
        self.assertEqual(activity.title, message)
        self.assertEqual(activity.status, status)

    def test_create_activity_nonexistent_scan(self):
        """Test creating activity for non-existent scan (should raise)."""
        from django.core.exceptions import ObjectDoesNotExist

        with self.assertRaises(ObjectDoesNotExist):
            self.scan_repo.create_activity(99999, "Test message", 1)

    def test_create_scan_success(self):
        """Test creating a new scan with target_id."""
        engine = self.data_generator.engine_type
        target = self.data_generator.target

        result = self.scan_repo.create_scan(engine_id=engine.id, target_id=target.id)

        self.assertIsNotNone(result)
        from startScan.models import ScanHistory

        scan = ScanHistory.objects.get(id=result)
        self.assertEqual(scan.target_id, target.id)
        self.assertIsNone(scan.scan_type)
        self.assertFalse(scan.is_legacy_scan)
        from reNgine.definitions import INITIATED_TASK

        self.assertEqual(scan.scan_status, INITIATED_TASK)

    def test_create_scan_with_initiated_by(self):
        """Test creating scan with initiated_by user."""
        from dashboard.models import User

        engine = self.data_generator.engine_type
        target = self.data_generator.target
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
        )

        result = self.scan_repo.create_scan(engine_id=engine.id, target_id=target.id, initiated_by_id=user.id)

        self.assertIsNotNone(result)
        from startScan.models import ScanHistory

        scan = ScanHistory.objects.get(id=result)
        self.assertEqual(scan.initiated_by.id, user.id)

    def test_update_scan_status_and_notify(self):
        """Test _update_scan_status_and_notify method."""
        from unittest.mock import patch

        from reNgine.definitions import SUCCESS_TASK

        with patch("reNgine.utilities.websocket.send_scan_status_update") as mock_notify:
            result = self.scan_repo._update_scan_status_and_notify(self.scan_history.id, SUCCESS_TASK)

            self.assertTrue(result)
            self.scan_history.refresh_from_db()
            self.assertEqual(self.scan_history.scan_status, SUCCESS_TASK)
            mock_notify.assert_called_once_with(self.scan_history.id, force=True)

    def test_create_scan_activity_entry(self):
        """Test _create_scan_activity_entry method."""
        message = "Test activity"
        status = 1

        result = self.scan_repo._create_scan_activity_entry(self.scan_history.id, message, status)

        self.assertIsNotNone(result)
        from startScan.models import ScanActivity

        activity = ScanActivity.objects.get(id=result)
        self.assertEqual(activity.title, message)
        self.assertEqual(activity.status, status)
        self.assertEqual(activity.scan_of.id, self.scan_history.id)

    def test_build_scan_activity_entry(self):
        """Test _build_scan_activity_entry method."""
        message = "Test activity"
        status = 1

        result = self.scan_repo._build_scan_activity_entry(self.scan_history.id, message, status)

        self.assertIsNotNone(result)
        from startScan.models import ScanActivity

        activity = ScanActivity.objects.get(id=result)
        self.assertEqual(activity.title, message)
        self.assertEqual(activity.status, status)

    def test_create_scan_history_entry(self):
        """Test _create_scan_history_entry method."""
        engine = self.data_generator.engine_type
        target = self.data_generator.target

        result = self.scan_repo._create_scan_history_entry(engine.id, target_id=target.id)

        self.assertIsNotNone(result)
        from startScan.models import ScanHistory

        scan = ScanHistory.objects.get(id=result)
        self.assertEqual(scan.target_id, target.id)
        self.assertIsNone(scan.scan_type)
        self.assertFalse(scan.is_legacy_scan)

    def test_create_scan_history_entry_with_user(self):
        """Test _create_scan_history_entry with initiated_by user."""
        from dashboard.models import User

        engine = self.data_generator.engine_type
        target = self.data_generator.target
        user = User.objects.create_user(
            username="testuser2",
            email="test2@example.com",
            password="testpass123",
        )

        result = self.scan_repo._create_scan_history_entry(engine.id, initiated_by_id=user.id, target_id=target.id)

        self.assertIsNotNone(result)
        from startScan.models import ScanHistory

        scan = ScanHistory.objects.get(id=result)
        self.assertEqual(scan.initiated_by.id, user.id)

    def test_mark_scan_failed_and_notify(self):
        """Test _mark_scan_failed_and_notify method."""
        error_message = "Test error"
        from unittest.mock import patch

        from reNgine.definitions import FAILED_TASK

        with patch("reNgine.utilities.websocket.send_scan_status_update") as mock_notify:
            result = self.scan_repo._mark_scan_failed_and_notify(self.scan_history.id, error_message)

            self.assertTrue(result)
            self.scan_history.refresh_from_db()
            self.assertEqual(self.scan_history.scan_status, FAILED_TASK)
            self.assertEqual(self.scan_history.error_message, error_message)
            self.assertIsNotNone(self.scan_history.stop_scan_date)
            mock_notify.assert_called_once_with(self.scan_history.id, force=True)

    def test_mark_scan_failed_and_notify_no_error_message(self):
        """Test _mark_scan_failed_and_notify without error message."""
        from unittest.mock import patch

        from reNgine.definitions import FAILED_TASK

        with patch("reNgine.utilities.websocket.send_scan_status_update") as mock_notify:
            result = self.scan_repo._mark_scan_failed_and_notify(self.scan_history.id, None)

            self.assertTrue(result)
            self.scan_history.refresh_from_db()
            self.assertEqual(self.scan_history.scan_status, FAILED_TASK)
            mock_notify.assert_called_once_with(self.scan_history.id, force=True)

    # Note: The following methods are not implemented in the current ScanRepository:
    # - delete_scan
    # - get_scan_statistics
    # - get_scan_statistics_by_domain
    # - cleanup_old_scans
    # These tests have been removed as they test non-existent functionality

    # Note: validate_scan_config method has been removed from ScanRepository
    # These tests are no longer applicable
