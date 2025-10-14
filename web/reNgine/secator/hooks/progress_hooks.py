"""
Progress tracking hooks for Secator scans.
Updates scan status and progress in database.
"""

from celery.utils.log import get_task_logger

from reNgine.definitions import RUNNING_TASK, SUCCESS_TASK
from reNgine.secator.hooks.base import SecatorHooks
from reNgine.services.repositories.scan_repository import ScanRepository


logger = get_task_logger(__name__)


class ProgressHooks(SecatorHooks):
    """Hooks for tracking scan progress."""

    def __init__(self, scan_history_id):
        """
        Initialize progress hooks.

        Args:
            scan_history_id: ID of the scan history
        """
        self.scan_history_id = scan_history_id
        self.scan_repo = ScanRepository()
        self.item_count = 0

    def on_init(self):
        """Execute when runner init is completed."""
        logger.info(f"Scan {self.scan_history_id} initialized")

    def on_start(self):
        """Mark scan as started."""
        self.scan_repo.update_status(self.scan_history_id, status=RUNNING_TASK)
        self.scan_repo.create_scan_activity(self.scan_history_id, "Secator scan started", RUNNING_TASK)
        logger.info(f"Scan {self.scan_history_id} started")

    def on_iter(self):
        """Update scan progress on each iteration."""
        self.item_count += 1
        if self.item_count % 10 == 0:
            logger.debug(f"Scan {self.scan_history_id} - {self.item_count} items processed")

    def on_end(self):
        """Mark scan as completed."""
        self.scan_repo.mark_scan_complete(self.scan_history_id)
        self.scan_repo.create_scan_activity(
            self.scan_history_id, f"Secator scan completed - {self.item_count} items processed", SUCCESS_TASK
        )
        logger.info(f"Scan {self.scan_history_id} completed with {self.item_count} items")
