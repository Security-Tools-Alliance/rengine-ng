"""
Tests for reNgine.utilities.status: assert_scan_status, assert_task_status,
is_scan_status_pending, is_scan_status_current, is_scan_status_recently_completed.
"""

from reNgine.definitions import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_VALUES,
    SCAN_STATUSES_CURRENT,
    SCAN_STATUSES_RECENTLY_COMPLETED,
    TASK_STATUS_VALUES,
)
from reNgine.utilities.status import (
    assert_scan_status,
    assert_task_status,
    is_scan_status_current,
    is_scan_status_pending,
    is_scan_status_recently_completed,
)
from utils.test_base import BaseTestCase


class AssertScanStatusTestCase(BaseTestCase):
    """Tests for assert_scan_status."""

    def test_accepts_all_scan_status_values(self):
        for code in SCAN_STATUS_VALUES:
            assert_scan_status(code)

    def test_raises_for_invalid_scan_status(self):
        with self.assertRaises(ValueError) as ctx:
            assert_scan_status(99)
        self.assertIn("Invalid scan status", str(ctx.exception))
        self.assertIn("99", str(ctx.exception))

    def test_raises_for_task_status_value_when_semantically_wrong(self):
        with self.assertRaises(ValueError):
            assert_scan_status(99)


class AssertTaskStatusTestCase(BaseTestCase):
    """Tests for assert_task_status."""

    def test_accepts_all_task_status_values(self):
        for code in TASK_STATUS_VALUES:
            assert_task_status(code)

    def test_raises_for_invalid_task_status(self):
        with self.assertRaises(ValueError) as ctx:
            assert_task_status(100)
        self.assertIn("Invalid task status", str(ctx.exception))
        self.assertIn("100", str(ctx.exception))


class IsScanStatusPendingTestCase(BaseTestCase):
    """Tests for is_scan_status_pending."""

    def test_pending_returns_true(self):
        self.assertTrue(is_scan_status_pending(SCAN_STATUS_PENDING))

    def test_non_pending_returns_false(self):
        self.assertFalse(is_scan_status_pending(SCAN_STATUS_QUEUED))


class IsScanStatusCurrentTestCase(BaseTestCase):
    """Tests for is_scan_status_current."""

    def test_current_statuses_return_true(self):
        for code in SCAN_STATUSES_CURRENT:
            self.assertTrue(is_scan_status_current(code))

    def test_non_current_returns_false(self):
        self.assertFalse(is_scan_status_current(SCAN_STATUS_COMPLETED))


class IsScanStatusRecentlyCompletedTestCase(BaseTestCase):
    """Tests for is_scan_status_recently_completed."""

    def test_recently_completed_return_true(self):
        for code in SCAN_STATUSES_RECENTLY_COMPLETED:
            self.assertTrue(is_scan_status_recently_completed(code))

    def test_running_returns_false(self):
        for code in SCAN_STATUSES_CURRENT:
            self.assertFalse(is_scan_status_recently_completed(code))
