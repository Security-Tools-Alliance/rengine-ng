"""
Tests for SecatorProgressSync and map_secator_status_to_rengine.
"""

import unittest
from unittest.mock import patch

from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    RUNNING_TASK,
    SKIPPED_TASK,
    SUCCESS_TASK,
)
from reNgine.secator.progress import (
    UNKNOWN_SECATOR_STATUS_FALLBACK,
    SecatorProgressSync,
)


class TestMapSecatorStatusToRengine(unittest.TestCase):
    """Test cases for map_secator_status_to_rengine."""

    def test_known_statuses_mapped_correctly(self):
        """Known Secator statuses return the expected reNgine code."""
        cases = [
            ("RUNNING", RUNNING_TASK),
            ("running", RUNNING_TASK),
            ("SUCCESS", SUCCESS_TASK),
            ("FAILURE", FAILED_TASK),
            ("FAILED", FAILED_TASK),
            ("PENDING", INITIATED_TASK),
            ("REVOKED", ABORTED_TASK),
            ("SKIPPED", SKIPPED_TASK),
        ]
        for secator_status, expected in cases:
            with self.subTest(secator_status=secator_status):
                self.assertEqual(
                    SecatorProgressSync.map_secator_status_to_rengine(secator_status),
                    expected,
                )

    def test_none_and_empty_status_return_fallback(self):
        """None and empty-string status map to UNKNOWN_SECATOR_STATUS_FALLBACK."""
        self.assertEqual(
            SecatorProgressSync.map_secator_status_to_rengine(None),
            UNKNOWN_SECATOR_STATUS_FALLBACK,
        )
        self.assertEqual(
            SecatorProgressSync.map_secator_status_to_rengine(""),
            UNKNOWN_SECATOR_STATUS_FALLBACK,
        )
        self.assertEqual(
            SecatorProgressSync.map_secator_status_to_rengine("   "),
            UNKNOWN_SECATOR_STATUS_FALLBACK,
        )

    def test_unknown_status_returns_fallback(self):
        """Unknown Secator status returns UNKNOWN_SECATOR_STATUS_FALLBACK."""
        self.assertEqual(
            SecatorProgressSync.map_secator_status_to_rengine("UNKNOWN_STATUS"),
            UNKNOWN_SECATOR_STATUS_FALLBACK,
        )
        self.assertEqual(
            SecatorProgressSync.map_secator_status_to_rengine("CUSTOM"),
            UNKNOWN_SECATOR_STATUS_FALLBACK,
        )

    def test_unknown_status_fallback_equals_initiated_task(self):
        """Fallback for unknown status is INITIATED_TASK."""
        self.assertEqual(UNKNOWN_SECATOR_STATUS_FALLBACK, INITIATED_TASK)

    @patch("reNgine.secator.progress.logger")
    def test_unknown_status_logs_warning(self, mock_logger):
        """Unknown Secator status logs a warning via log_line."""
        SecatorProgressSync.map_secator_status_to_rengine("UNKNOWN_STATUS")
        mock_logger.log_line.assert_called_once()
        call_args = mock_logger.log_line.call_args
        self.assertEqual(call_args[1].get("level"), "warning")
        self.assertIn("UNKNOWN_STATUS", str(call_args[0]))
        self.assertIn(str(UNKNOWN_SECATOR_STATUS_FALLBACK), str(call_args[0]))
