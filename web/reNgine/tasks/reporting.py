from django.utils import timezone

from reNgine.definitions import (
    SUCCESS_TASK,
    FAILED_TASK,
)

from reNgine.celery import app
from reNgine.utils.logger import Logger
from startScan.models import (
    ScanActivity,
    ScanHistory,
    SubScan,
)
from reNgine.tasks.notification import send_scan_notif

logger = Logger(True)

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

    # Get failed tasks
    tasks = ScanActivity.objects.filter(scan_of=scan).all()
    if subscan:
        tasks = tasks.filter(celery_id__in=subscan.celery_ids)
    failed_tasks = tasks.filter(status=FAILED_TASK)

    # Get task status
    failed_count = failed_tasks.count()
    status = SUCCESS_TASK if failed_count == 0 else FAILED_TASK
    status_h = 'SUCCESS' if failed_count == 0 else 'FAILED'

    # Update scan / subscan status
    if subscan:
        subscan.stop_scan_date = timezone.now()
        subscan.status = status
        subscan.save()
    else:
        scan.scan_status = status
    scan.stop_scan_date = timezone.now()
    scan.save()

    # Send scan status notif
    send_scan_notif.delay(
        scan_history_id=scan_id,
        subscan_id=subscan_id,
        engine_id=engine_id,
        status=status_h) 