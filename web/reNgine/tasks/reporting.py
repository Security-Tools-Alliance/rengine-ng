from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.celery import app
from reNgine.definitions import (
    FAILED_TASK,
    RUNNING_BACKGROUND,
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

    # Get task status
    failed_count = failed_tasks.count()
    
    # Check if there are async tasks still running
    has_async_tasks = False
    running_async_count = 0
    
    # Simple check for async tasks by looking at scan metadata
    # This is a simplified version - in a full implementation you'd want to
    # properly track task IDs and check their status via Celery
    try:
        # Check if we have any recently started async tasks
        recent_activities = ScanActivity.objects.filter(
            scan_of=scan,
            time__gte=timezone.now() - timezone.timedelta(minutes=5)  # Started in last 5 minutes
        ).filter(
            name__in=['http_crawl', 'nuclei_scan', 'vulnerability_scan', 'dalfox_xss_scan', 'crlfuzz_scan']
        )
        
        if recent_activities.exists():
            has_async_tasks = True
            running_async_count = recent_activities.count()
            logger.info(f'Found {running_async_count} recent async tasks for scan {scan_id}')
    except Exception as e:
        logger.debug(f'Error checking async tasks: {e}')
        has_async_tasks = False
    
    # Determine status based on failures and async tasks
    if failed_count > 0:
        status = FAILED_TASK
        status_h = 'FAILED'
    elif has_async_tasks:
        status = RUNNING_BACKGROUND
        status_h = 'RUNNING_BACKGROUND'
        logger.info(f'Scan {scan_id}: Main tasks completed but {running_async_count} async tasks still running')
    else:
        status = SUCCESS_TASK
        status_h = 'SUCCESS'

    # Update scan / subscan status
    if subscan:
        subscan.stop_scan_date = timezone.now()
        subscan.status = status
        subscan.save()
    else:
        scan.scan_status = status
    
    # Only set stop_scan_date if fully completed (not for RUNNING_BACKGROUND)
    if status != RUNNING_BACKGROUND:
        scan.stop_scan_date = timezone.now()
    scan.save()

    # Send scan status notif
    send_scan_notif.delay(
        scan_history_id=scan_id,
        subscan_id=subscan_id,
        engine_id=engine_id,
        status=status_h)
    
    # For RUNNING_BACKGROUND status, schedule a check later to finalize
    if status == RUNNING_BACKGROUND:
        from reNgine.tasks.scan import check_and_finalize_scan
        logger.info(f'Scheduling status check in 2 minutes for scan {scan_id}')
        # Use a simple delayed task to check again later
        check_and_finalize_scan.apply_async(args=[scan_id, subscan_id], countdown=120)  # Check again in 2 minutes 