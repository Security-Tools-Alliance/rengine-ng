"""
Standalone logic to sync SecatorRunner data with ScanHistory and ScanActivity.

Used by the API view (inline or from request thread) and by the background sync
service (startScan.secator.sync_service) so the sync is independent of the view layer.
"""

from typing import Any

from django.utils import timezone

from reNgine.definitions import ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.services.repositories.scan_repository import ScanRepository
from reNgine.utilities.websocket import send_scan_status_update
from startScan.models import ScanActivity, SecatorRunner


def is_all_runners_completed(scan_history_id: int, logger: Any) -> bool:
    """
    Check if all runners for this scan are completed.
    Works for both workflow scans (checks all runners) and task-only scans.

    Args:
        scan_history_id: ID of the scan history
        logger: Logger with PREFIX_SYNC, log_debug

    Returns:
        True if all runners are done, False otherwise
    """
    runners_list = list(
        SecatorRunner.objects.filter(scan_history_id=scan_history_id).only("runner_name", "runner_type", "runner_data")
    )
    if not runners_list:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "CHECK",
            "is_all_runners_completed: No runners found for scan %s" % (scan_history_id,),
        )
        return False

    incomplete_runners = []
    for runner in runners_list:
        if runner.runner_data:
            done = runner.runner_data.get("done", False)
            status = runner.runner_data.get("status", "").upper()
            runner_name = runner.runner_name or runner.runner_data.get("name", "Unknown")
            runner_type = runner.runner_type or runner.runner_data.get("config", {}).get("type", "unknown")
            if not done or status == "RUNNING":
                incomplete_runners.append(f"{runner_name} (type={runner_type}, status={status}, done={done})")

    if incomplete_runners:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "CHECK",
            "is_all_runners_completed: Scan %s NOT completed. Incomplete runners: %s"
            % (scan_history_id, ", ".join(incomplete_runners)),
        )
        return False

    logger.log_debug(
        logger.PREFIX_SYNC,
        "CHECK",
        "is_all_runners_completed: Scan %s is fully completed. Total runners checked: %s"
        % (scan_history_id, len(runners_list)),
    )
    return True


def sync_runner_with_scan_history(secator_runner: SecatorRunner, runner_data: dict, logger: Any) -> None:
    """
    Synchronize runner data with ScanHistory and create/update ScanActivity.

    Args:
        secator_runner: SecatorRunner instance (must have scan_history loaded)
        runner_data: Runner data from Secator hook
        logger: Logger with PREFIX_SYNC, log_debug, log_warning, log_runner_sync
    """
    scan_history = secator_runner.scan_history
    scan_repo = ScanRepository()

    runner_status = runner_data.get("status", "").upper()
    runner_done = runner_data.get("done", False)
    runner_name = runner_data.get("name") or secator_runner.runner_name or "Unknown"
    runner_type = runner_data.get("config", {}).get("type", "") or secator_runner.runner_type

    status_map = {
        "RUNNING": RUNNING_TASK,
        "SUCCESS": SUCCESS_TASK,
        "FAILURE": FAILED_TASK,
        "FAILED": FAILED_TASK,
        "PENDING": INITIATED_TASK,
        "REVOKED": ABORTED_TASK,
    }
    rengine_status = status_map.get(runner_status, INITIATED_TASK)

    logger.log_debug(
        logger.PREFIX_SYNC,
        "SYNC",
        "Runner update request - Runner: %s (type=%s, id=%s), Secator status: %s, done: %s, "
        "ScanHistory current status: %s, Proposed reNgine status: %s"
        % (
            runner_name,
            runner_type,
            secator_runner.id,
            runner_status,
            runner_done,
            scan_history.scan_status,
            rengine_status,
        ),
    )

    has_workflow_or_scan_runner = SecatorRunner.objects.filter(
        scan_history_id=scan_history.id, runner_type__in=["workflow", "scan"]
    ).exists()
    can_update_status = runner_type in ["workflow", "scan"] or (
        runner_type == "task" and not has_workflow_or_scan_runner
    )

    logger.log_debug(
        logger.PREFIX_SYNC,
        "SYNC",
        "Permission check - has_workflow_or_scan_runner: %s, can_update_status: %s"
        % (has_workflow_or_scan_runner, can_update_status),
    )

    if can_update_status:
        if runner_status == "PENDING" and scan_history.scan_status in [RUNNING_TASK, SUCCESS_TASK]:
            logger.log_debug(
                logger.PREFIX_SYNC,
                "BLOCKED",
                "Ignoring PENDING status for runner %s (type=%s) - scan already in progress. "
                "Current ScanHistory status: %s, Would set to: %s"
                % (runner_name, runner_type, scan_history.scan_status, rengine_status),
            )
        elif runner_status == "SUCCESS":
            logger.log_debug(
                logger.PREFIX_SYNC,
                "SUCCESS",
                "Processing SUCCESS status - Runner: %s (type=%s), done: %s, Current ScanHistory status: %s"
                % (runner_name, runner_type, runner_done, scan_history.scan_status),
            )
            if runner_done:
                all_completed = is_all_runners_completed(scan_history.id, logger)
                logger.log_debug(
                    logger.PREFIX_SYNC,
                    "CHECK",
                    "All runners completed check: %s for scan %s" % (all_completed, scan_history.id),
                )
                if all_completed:
                    old_status = scan_history.scan_status
                    scan_history.scan_status = rengine_status
                    if not scan_history.stop_scan_date:
                        scan_history.stop_scan_date = timezone.now()
                    scan_history.save(update_fields=["scan_status", "stop_scan_date"])
                    logger.log_runner_sync(
                        "SUCCESS",
                        runner_name,
                        runner_type,
                        runner_status,
                        scan_history.id,
                        {
                            "old_status": old_status,
                            "new_status": rengine_status,
                            "stop_scan_date": scan_history.stop_scan_date,
                        },
                    )
                    send_scan_status_update(scan_history.id)
                else:
                    old_status = scan_history.scan_status
                    scan_history.scan_status = RUNNING_TASK
                    scan_history.save(update_fields=["scan_status"])
                    logger.log_debug(
                        logger.PREFIX_SYNC,
                        "KEEP_RUNNING",
                        "Scan %s not fully completed yet. Status changed from %s to %s by runner %s (type=%s)"
                        % (scan_history.id, old_status, RUNNING_TASK, runner_name, runner_type),
                    )
                    send_scan_status_update(scan_history.id)
            else:
                old_status = scan_history.scan_status
                scan_history.scan_status = RUNNING_TASK
                scan_history.save(update_fields=["scan_status"])
                logger.log_debug(
                    logger.PREFIX_SYNC,
                    "KEEP_RUNNING",
                    "Runner %s (type=%s) in SUCCESS but not done. Status changed from %s to %s"
                    % (runner_name, runner_type, old_status, RUNNING_TASK),
                )
                send_scan_status_update(scan_history.id)
        elif runner_status in ["RUNNING", "FAILURE", "FAILED"]:
            old_status = scan_history.scan_status
            scan_history.scan_status = rengine_status
            if runner_done and runner_status in ["FAILURE", "FAILED"] and not scan_history.stop_scan_date:
                scan_history.stop_scan_date = timezone.now()
            scan_history.save(update_fields=["scan_status", "stop_scan_date"])
            logger.log_runner_sync(
                "UPDATED",
                runner_name,
                runner_type,
                runner_status,
                scan_history.id,
                {
                    "old_status": old_status,
                    "new_status": rengine_status,
                    "done": runner_done,
                    "stop_scan_date": scan_history.stop_scan_date,
                },
            )
            send_scan_status_update(scan_history.id)
    else:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "SKIPPED",
            "Runner %s (type=%s) cannot update global status. Current ScanHistory status: %s"
            % (runner_name, runner_type, scan_history.scan_status),
        )

    run_opts = runner_data.get("run_opts", {})
    reports_folder = run_opts.get("reports_folder")
    activity_title = f"{runner_type.title()}: {runner_name}"

    existing_activity = (
        ScanActivity.objects.filter(scan_of=scan_history, name=runner_name, runner_id=secator_runner)
        .order_by("-time")
        .first()
    )
    activity_id_for_command = None

    if existing_activity:
        existing_activity.status = rengine_status
        existing_activity.time = timezone.now()
        if runner_done and runner_status in ["SUCCESS", "FAILURE", "FAILED"]:
            existing_activity.title = f"{activity_title} - Completed"
        if reports_folder:
            existing_activity.results_dir = reports_folder
        update_fields = ["status", "time", "title"]
        if reports_folder:
            update_fields.append("results_dir")
        existing_activity.save(update_fields=update_fields)
        activity_id_for_command = existing_activity.id
        logger.log_debug(
            logger.PREFIX_SYNC,
            "ACTIVITY",
            "Updated ScanActivity %s for runner %s" % (existing_activity.id, runner_name),
        )
    else:
        activity_id_for_command = scan_repo.create_activity(scan_history.id, activity_title, rengine_status)
        try:
            new_activity = ScanActivity.objects.get(id=activity_id_for_command)
            new_activity.runner_id = secator_runner
            new_activity.name = runner_name
            if reports_folder:
                new_activity.results_dir = reports_folder
            update_fields = ["runner_id", "name"]
            if reports_folder:
                update_fields.append("results_dir")
            new_activity.save(update_fields=update_fields)
            logger.log_debug(
                logger.PREFIX_SYNC,
                "ACTIVITY",
                "Created ScanActivity %s for runner %s" % (activity_id_for_command, runner_name),
            )
        except ScanActivity.DoesNotExist:
            logger.log_warning(
                "Could not find newly created ScanActivity %s" % (activity_id_for_command,),
                {"prefix": logger.PREFIX_SYNC, "action": "SYNC", "runner": runner_name},
            )

    from reNgine.secator import SecatorProgressSync

    SecatorProgressSync._sync_subscans_if_terminal(secator_runner.id, runner_status, rengine_status)

    logger.log_runner_sync("SYNC", runner_name, runner_type, runner_status, scan_history.id, {})

    try:
        from reNgine.services.repositories.command_repository import CommandRepository

        command_repo = CommandRepository()
        if activity_id_for_command is not None:
            command_repo.save_from_secator(runner_data, scan_history.id, activity_id_for_command)
    except Exception as e:
        logger.log_warning(
            "Error saving command log for runner %s: %s" % (runner_name, e),
            {"prefix": logger.PREFIX_SYNC, "action": "SYNC", "runner": runner_name},
        )

    runner_progress = runner_data.get("progress")
    if isinstance(runner_progress, (int, float)) and runner_progress >= 0:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "WEBSOCKET",
            "Sending progress update for scan %s - Runner: %s, Progress: %s%%, Status: %s"
            % (scan_history.id, runner_name, runner_progress, runner_status),
        )
    else:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "WEBSOCKET",
            "Sending runner update for scan %s - Runner: %s, Status: %s (no progress data)"
            % (scan_history.id, runner_name, runner_status),
        )
    send_scan_status_update(scan_history.id)
