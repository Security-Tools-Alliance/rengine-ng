"""
Tests for Secator service functionality.
"""

from unittest.mock import patch

from reNgine.definitions import ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.secator.service import handle_scan_error
from utils.test_base import BaseTestCase


class TestSecatorService(BaseTestCase):
    """Test cases for Secator service."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()

    def test_handle_scan_error_sets_failed_status(self):
        """Test that handle_scan_error sets scan status to FAILED_TASK."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    def test_handle_scan_error_skips_when_already_success(self):
        """Test that handle_scan_error skips update when scan is already SUCCESS."""
        self.scan_history.scan_status = SUCCESS_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SUCCESS_TASK)

    def test_handle_scan_error_skips_when_already_failed(self):
        """Test that handle_scan_error skips update when scan is already FAILED."""
        self.scan_history.scan_status = FAILED_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    def test_handle_scan_error_skips_when_already_aborted(self):
        """Test that handle_scan_error skips update when scan is already ABORTED."""
        self.scan_history.scan_status = ABORTED_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, ABORTED_TASK)

    def test_handle_scan_error_updates_from_initiated(self):
        """Test that handle_scan_error updates scan from INITIATED status."""
        self.scan_history.scan_status = INITIATED_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    def test_handle_scan_error_updates_from_running(self):
        """Test that handle_scan_error updates scan from RUNNING status."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    @patch("reNgine.secator.service.logger")
    def test_handle_scan_error_logs_error(self, mock_logger):
        """Test that handle_scan_error logs the error."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        error = Exception("Test error message")
        handle_scan_error(self.scan_history, error)

        mock_logger.error.assert_called_once()
        self.assertIn("Test error message", str(mock_logger.error.call_args))

    @patch("reNgine.secator.service.logger")
    def test_handle_scan_error_logs_debug_when_terminal(self, mock_logger):
        """Test that handle_scan_error logs debug when scan is already in terminal state."""
        self.scan_history.scan_status = SUCCESS_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        mock_logger.debug.assert_called_once()
        self.assertIn("already in terminal state", str(mock_logger.debug.call_args).lower())

    def test_handle_scan_error_refreshes_from_db(self):
        """Test that handle_scan_error refreshes scan from database before checking status."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        # Manually change status in DB to simulate race condition
        from startScan.models import ScanHistory

        ScanHistory.objects.filter(id=self.scan_history.id).update(scan_status=SUCCESS_TASK)

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        # Should skip update because refresh_from_db detected SUCCESS status
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SUCCESS_TASK)
