"""
Scan Repository - Data access for scan-related operations.
Handles ScanHistory and ScanActivity database operations.
"""

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from dashboard.models import User
from reNgine.definitions import INITIATED_TASK
from scanEngine.models import EngineType
from startScan.models import Domain, ScanActivity, ScanHistory


logger = get_task_logger(__name__)


class ScanRepository:
    """Repository for scan-related database operations."""

    def get_by_id(self, scan_history_id):
        """
        Get scan history by ID.

        Args:
            scan_history_id: ID of the scan history

        Returns:
            ScanHistory: Scan history object or None
        """
        try:
            return ScanHistory.objects.get(id=scan_history_id)
        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return None

    def update_status(self, scan_history_id, status):
        """
        Update scan status.

        Args:
            scan_history_id: ID of the scan history
            status: New status value

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            scan = ScanHistory.objects.get(id=scan_history_id)
            scan.scan_status = status
            scan.save()
            logger.info(f"Updated scan {scan_history_id} status to {status}")
            return True
        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating scan status: {e}")
            return False

    def update_progress(self, scan_history_id, progress):
        """
        Update scan progress.

        Args:
            scan_history_id: ID of the scan history
            progress: Progress value (0-100)

        Returns:
            bool: True if successful, False otherwise
        """
        # Validate progress range
        if not isinstance(progress, (int, float)):
            logger.error(f"Progress must be a number, got: {type(progress).__name__}")
            return False

        if progress < 0 or progress > 100:
            logger.error(f"Progress must be between 0 and 100, got: {progress}")
            return False

        try:
            scan = ScanHistory.objects.get(id=scan_history_id)
            if hasattr(scan, "progress"):
                scan.progress = progress
                scan.save(update_fields=["progress"])
                logger.debug(f"Updated scan {scan_history_id} progress to {progress}%")
            else:
                logger.warning("ScanHistory model does not have a 'progress' field. Progress update ignored.")
            return True
        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating scan progress: {e}")
            return False

    def create_scan_activity(self, scan_history_id, message, status):
        """
        Create a scan activity log entry.

        Args:
            scan_history_id: ID of the scan history
            message: Activity message
            status: Activity status

        Returns:
            int: Activity ID or None
        """
        try:
            scan_activity = ScanActivity()
            scan_activity.scan_of = ScanHistory.objects.get(id=scan_history_id)
            scan_activity.title = message
            scan_activity.time = timezone.now()
            scan_activity.status = status
            scan_activity.save()
            return scan_activity.id
        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error creating scan activity: {e}")
            return None

    def update_celery_task_id(self, scan_history_id, celery_task_id):
        """
        Update Celery task ID for a scan.

        Args:
            scan_history_id: ID of the scan history
            celery_task_id: Celery task ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            scan = ScanHistory.objects.get(id=scan_history_id)
            scan.celery_ids = [celery_task_id]
            scan.save(update_fields=["celery_ids"])
            logger.debug(f"Updated scan {scan_history_id} celery task ID to {celery_task_id}")
            return True
        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating celery task ID: {e}")
            return False

    def update_error_message(self, scan_history_id, error_message):
        """
        Update error message for a scan.

        Args:
            scan_history_id: ID of the scan history
            error_message: Error message

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            scan = ScanHistory.objects.get(id=scan_history_id)
            scan.error_message = error_message
            scan.save(update_fields=["error_message"])
            logger.info(f"Updated scan {scan_history_id} error message")
            return True
        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating error message: {e}")
            return False

    def mark_scan_complete(self, scan_history_id):
        """
        Mark scan as complete with end date.

        Args:
            scan_history_id: ID of the scan history

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from reNgine.definitions import SUCCESS_TASK

            scan = ScanHistory.objects.get(id=scan_history_id)
            scan.scan_status = SUCCESS_TASK
            scan.stop_scan_date = timezone.now()
            scan.save()
            logger.info(f"Marked scan {scan_history_id} as complete")
            return True
        except Exception as e:
            logger.error(f"Error marking scan {scan_history_id} as complete: {e}")
            return False

    def create_scan(self, host_id, engine_id, initiated_by_id=None):
        """
        Create a new scan object with pending status.

        Args:
            host_id: ID of Domain model
            engine_id: ID of EngineType model
            initiated_by_id: ID of User model (Optional)

        Returns:
            int: ID of the created scan history
        """
        try:
            # Get current time
            current_scan_time = timezone.now()

            # Fetch engine and domain objects
            engine = EngineType.objects.get(pk=engine_id)
            domain = Domain.objects.get(pk=host_id)

            # Create scan history
            scan = ScanHistory()
            scan.scan_status = INITIATED_TASK
            scan.domain = domain
            scan.scan_type = engine
            scan.start_scan_date = current_scan_time

            if initiated_by_id:
                user = User.objects.get(pk=initiated_by_id)
                scan.initiated_by = user

            scan.save()

            # Update domain's last scan date
            domain.start_scan_date = current_scan_time
            domain.save()

            logger.info(f"Created scan {scan.id} for domain {domain.name} with engine {engine.engine_name}")
            return scan.id

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when creating scan: {e}")
            raise
        except Exception as e:
            logger.error(f"Error creating scan: {e}")
            raise

    def create_activity(self, scan_history_id, message, status):
        """
        Create a new scan activity.

        Args:
            scan_history_id: ID of the scan history
            message: Activity message
            status: Activity status

        Returns:
            int: ID of the created scan activity
        """
        try:
            scan = ScanHistory.objects.get(pk=scan_history_id)

            scan_activity = ScanActivity()
            scan_activity.scan_of = scan
            scan_activity.title = message
            scan_activity.time = timezone.now()
            scan_activity.status = status
            scan_activity.save()

            logger.info(f"Created scan activity {scan_activity.id} for scan {scan_history_id}: {message}")
            return scan_activity.id

        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            raise
        except Exception as e:
            logger.error(f"Error creating scan activity: {e}")
            raise

    def mark_scan_failed(self, scan_history_id, error_message=None):
        """
        Mark scan as failed with optional error message.

        Args:
            scan_history_id: ID of the scan history
            error_message: Optional error message

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from reNgine.definitions import FAILED_TASK

            scan = ScanHistory.objects.get(id=scan_history_id)
            scan.scan_status = FAILED_TASK
            scan.stop_scan_date = timezone.now()
            if error_message:
                scan.error_message = error_message
            scan.save()
            logger.info(f"Marked scan {scan_history_id} as failed")
            return True
        except ObjectDoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error marking scan failed: {e}")
            return False
