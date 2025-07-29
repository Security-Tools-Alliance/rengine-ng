from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.celery import app
from reNgine.definitions import (
    FAILED_TASK,
    SUCCESS_TASK,
)
from reNgine.tasks.notification import send_scan_notif
from startScan.models import ScanActivity, ScanHistory, SubScan

logger = get_task_logger(__name__)


@app.task(name='report', bind=False, queue='report_queue')
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
    subscan_id = ctx.get('subscan_id')
    scan_id = ctx.get('scan_history_id')
    engine_id = ctx.get('engine_id')
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    subscan = SubScan.objects.filter(pk=subscan_id).first()

    # Check if scan exists
    if not scan:
        logger.error(f'ScanHistory with ID {scan_id} not found')
        return

    # Get failed tasks
    tasks = ScanActivity.objects.filter(scan_of=scan).all()
    if subscan:
        tasks = tasks.filter(celery_id__in=subscan.celery_ids)
    failed_tasks = tasks.filter(status=FAILED_TASK)

    # Get task status - since report is a callback, all tasks are completed
    failed_count = failed_tasks.count()
    
    # Determine status based on failures only
    if failed_count > 0:
        status = FAILED_TASK
        status_h = 'FAILED'
        logger.info(f'Scan {scan_id}: Completed with {failed_count} failed tasks')
    else:
        status = SUCCESS_TASK
        status_h = 'SUCCESS'
        logger.info(f'Scan {scan_id}: Completed successfully')

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
    send_scan_notif.delay(
        scan_history_id=scan_id,
        subscan_id=subscan_id,
        engine_id=engine_id,
        status=status_h)
    
    logger.info(f'Report completed for scan {scan_id} with status {status_h}') 