"""
Scan control operations for Secator scans.
Provides start, stop, pause functionality.
"""

from celery.utils.log import get_task_logger

from reNgine.definitions import ABORTED_TASK
from reNgine.services.repositories.scan_repository import ScanRepository


logger = get_task_logger(__name__)


class SecatorScanController:
    """Controls Secator scan lifecycle."""

    def __init__(self, scan_history_id):
        """
        Initialize scan controller.

        Args:
            scan_history_id: ID of the scan history
        """
        self.scan_history_id = scan_history_id
        self.scan_repo = ScanRepository()

    def stop_scan(self):
        """
        Stop a running Secator scan.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            scan = self.scan_repo.get_by_id(self.scan_history_id)
            if not scan:
                logger.error(f"Scan {self.scan_history_id} not found")
                return False

            celery_task_ids = scan.celery_ids
            if not celery_task_ids:
                logger.warning(f"No Celery task IDs found for scan {self.scan_history_id}")
                self.scan_repo.update_status(self.scan_history_id, ABORTED_TASK)
                return True

            from reNgine.celery import app

            # Revoke all Celery tasks associated with this scan
            revoked_count = 0
            failed_count = 0

            for celery_task_id in celery_task_ids:
                try:
                    app.control.revoke(celery_task_id, terminate=True)
                    revoked_count += 1
                    logger.debug(f"Successfully revoked Celery task {celery_task_id} for scan {self.scan_history_id}")
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Failed to revoke Celery task {celery_task_id} for scan {self.scan_history_id}: {e}")

            # Log summary of revocation results
            if revoked_count > 0:
                logger.info(f"Revoked {revoked_count} Celery task(s) for scan {self.scan_history_id}")
            if failed_count > 0:
                logger.warning(f"Failed to revoke {failed_count} Celery task(s) for scan {self.scan_history_id}")

            # Update scan status regardless of individual task revocation results
            # The scan should be marked as aborted even if some tasks couldn't be revoked
            self.scan_repo.update_status(self.scan_history_id, ABORTED_TASK)
            self.scan_repo.create_scan_activity(self.scan_history_id, "Scan stopped by user", ABORTED_TASK)

            logger.info(f"Stopped scan {self.scan_history_id} (revoked {revoked_count}/{len(celery_task_ids)} tasks)")
            return True

        except Exception as e:
            logger.error(f"Error stopping scan {self.scan_history_id}: {e}")
            return False

    def pause_scan(self):
        """
        Pause a running Secator scan.

        Note: This requires Secator support for pausing.

        Returns:
            bool: True if successful, False otherwise
        """
        logger.warning("Pause functionality not yet implemented for Secator scans")
        return False

    def resume_scan(self):
        """
        Resume a paused Secator scan.

        Note: This requires Secator support for resuming.

        Returns:
            bool: True if successful, False otherwise
        """
        logger.warning("Resume functionality not yet implemented for Secator scans")
        return False
