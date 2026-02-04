from django.utils import timezone

from reNgine.definitions import (
    FAILED_TASK,
    SUCCESS_TASK,
)
from reNgine.utilities.logger import get_module_logger
from startScan.models import ScanActivity, ScanHistory, SubScan


logger = get_module_logger(__name__)


# TODO Use secator to launch this task
# @app.task(name="report", bind=False, queue="report_queue")
def report(ctx=None, description=None):
    """Report task running after all other tasks.
    Mark ScanHistory or SubScan object as completed and update with final
    status, log run details and send notification.

    Args:
        description (str, optional): Task description shown in UI.
    """
    if ctx is None:
        ctx = {}
    # Get objects
    subscan_id = ctx.get("subscan_id")
    scan_id = ctx.get("scan_history_id")
    # engine_id = ctx.get("engine_id")  # Temporarily unused due to notification commenting
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    subscan = SubScan.objects.filter(pk=subscan_id).first()

    # Check if scan exists
    if not scan:
        logger.error(f"ScanHistory with ID {scan_id} not found")
        return

    # Get failed tasks
    tasks = ScanActivity.objects.filter(scan_of=scan).all()
    if subscan:
        # For subscans, filter tasks by checking if they belong to the subscan's scan
        # Note: Subscans don't have direct runners, so we filter by scan
        pass
    failed_tasks = tasks.filter(status=FAILED_TASK)

    # Get task status - since report is a callback, all tasks are completed
    failed_count = failed_tasks.count()

    # Determine status based on failures only
    if failed_count > 0:
        status = FAILED_TASK
        status_h = "FAILED"
        logger.info(f"Scan {scan_id}: Completed with {failed_count} failed tasks")
    else:
        status = SUCCESS_TASK
        status_h = "SUCCESS"
        logger.info(f"Scan {scan_id}: Completed successfully")

    # Update scan / subscan status
    if subscan:
        subscan.stop_scan_date = timezone.now()
        subscan.status = status
        subscan.save()
    else:
        scan.scan_status = status

    # Always set stop_scan_date since workflow is completed
    scan.stop_scan_date = timezone.now()
    scan.save()

    # Send scan status notif
    # TODO: Temporarily commented out due to Celery worker queue issue
    # The send_scan_notif task is not registered in the Secator worker
    # send_scan_notif.delay(scan_history_id=scan_id, subscan_id=subscan_id, engine_id=engine_id, status=status_h)
    logger.info(f"Scan notification temporarily disabled - report completed for scan {scan_id} with status {status_h}")

    logger.info(f"Report completed for scan {scan_id} with status {status_h}")
