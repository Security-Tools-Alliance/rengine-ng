"""
Scan and task status helpers.

Validation and predicate functions for ScanHistory.scan_status and for
ScanActivity/SubScan/Command task status. Constants and value sets remain
in reNgine.definitions.
"""

from reNgine.definitions import (
    SCAN_STATUS_PENDING,
    SCAN_STATUS_VALUES,
    SCAN_STATUSES_CURRENT,
    SCAN_STATUSES_RECENTLY_COMPLETED,
    TASK_STATUS_VALUES,
)


def assert_scan_status(code: int) -> None:
    """
    Raise ValueError if code is not a valid ScanHistory.scan_status value.

    Use when accepting or storing a scan status to avoid accidentally using a
    task status constant (e.g. FAILED_TASK vs SCAN_STATUS_FAILED).
    """
    if code not in SCAN_STATUS_VALUES:
        raise ValueError(f"Invalid scan status: {code} (expected one of {sorted(SCAN_STATUS_VALUES)})")


def assert_task_status(code: int) -> None:
    """
    Raise ValueError if code is not a valid task status (ScanActivity, SubScan, Command).

    Use when accepting or storing a task status to avoid accidentally using a
    scan status constant.
    """
    if code not in TASK_STATUS_VALUES:
        raise ValueError(f"Invalid task status: {code} (expected one of {sorted(TASK_STATUS_VALUES)})")


def is_scan_status_pending(scan_status: int) -> bool:
    """Return True if scan_status is Pending (ScanHistory.scan_status)."""
    return scan_status == SCAN_STATUS_PENDING


def is_scan_status_current(scan_status: int) -> bool:
    """Return True if scan_status is Running or Running Background (ScanHistory.scan_status)."""
    return scan_status in SCAN_STATUSES_CURRENT


def is_scan_status_recently_completed(scan_status: int) -> bool:
    """Return True if scan_status is Queued, Completed, or Failed (ScanHistory.scan_status)."""
    return scan_status in SCAN_STATUSES_RECENTLY_COMPLETED
