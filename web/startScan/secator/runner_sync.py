"""
Standalone logic to sync SecatorRunner data with ScanHistory and ScanActivity.

Used by the API view (inline or from request thread) and by the background sync
service (startScan.secator.sync_service) so the sync is independent of the view layer.
"""

from typing import Any

from django.utils import timezone

from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    RUNNING_TASK,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    SUCCESS_TASK,
)
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
            f"is_all_runners_completed: No runners found for scan {scan_history_id}",
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
            f"is_all_runners_completed: Scan {scan_history_id} NOT completed. Incomplete runners: {', '.join(incomplete_runners)}",
        )
        return False

    logger.log_debug(
        logger.PREFIX_SYNC,
        "CHECK",
        f"is_all_runners_completed: Scan {scan_history_id} is fully completed. Total runners checked: {len(runners_list)}",
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
        f"Runner update request - Runner: {runner_name} (type={runner_type}, id={secator_runner.id}), "
        f"Secator status: {runner_status}, done: {runner_done}, "
        f"ScanHistory current status: {scan_history.scan_status}, Proposed reNgine status: {rengine_status}",
    )

    can_update_status = _runner_can_update_scan_status(scan_history.id, runner_type)
    logger.log_debug(
        logger.PREFIX_SYNC,
        "SYNC",
        f"Permission check - can_update_status: {can_update_status}",
    )

    runner_status_to_scan_status = {
        "RUNNING": SCAN_STATUS_RUNNING,
        "FAILURE": SCAN_STATUS_FAILED,
        "FAILED": SCAN_STATUS_FAILED,
        "REVOKED": SCAN_STATUS_FAILED,
        "PENDING": SCAN_STATUS_PENDING,
    }
    _apply_scan_history_status(
        scan_history,
        can_update_status,
        runner_status,
        runner_done,
        runner_name,
        runner_type,
        runner_status_to_scan_status,
        logger,
    )

    activity_id_for_command = _sync_scan_activity(
        scan_history,
        secator_runner,
        runner_data,
        runner_name,
        runner_type,
        runner_status,
        runner_done,
        rengine_status,
        logger,
    )

    _finalize_runner_sync(
        secator_runner,
        scan_history,
        runner_data,
        runner_name,
        runner_type,
        runner_status,
        rengine_status,
        activity_id_for_command,
        logger,
    )
    send_scan_status_update(scan_history.id)


def _runner_can_update_scan_status(scan_history_id: int, runner_type: str) -> bool:
    """True if this runner type is allowed to update ScanHistory.scan_status."""
    has_workflow_or_scan = SecatorRunner.objects.filter(
        scan_history_id=scan_history_id, runner_type__in=["workflow", "scan"]
    ).exists()
    return runner_type in {"workflow", "scan"} or (runner_type == "task" and not has_workflow_or_scan)


def _apply_scan_history_status(
    scan_history,
    can_update_status: bool,
    runner_status: str,
    runner_done: bool,
    runner_name: str,
    runner_type: str,
    runner_status_to_scan_status: dict,
    logger: Any,
) -> None:
    """Update ScanHistory.scan_status when the runner is allowed to drive it."""
    if not can_update_status:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "SKIPPED",
            f"Runner {runner_name} (type={runner_type}) cannot update global status. Current ScanHistory status: {scan_history.scan_status}",
        )
        return

    if runner_status == "PENDING" and scan_history.scan_status in {
        SCAN_STATUS_RUNNING,
        SCAN_STATUS_COMPLETED,
    }:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "BLOCKED",
            f"Ignoring PENDING status for runner {runner_name} (type={runner_type}) - scan already in progress. "
            f"Current ScanHistory status: {scan_history.scan_status}, Would set to: {SCAN_STATUS_PENDING}",
        )
        return

    if runner_status == "SUCCESS":
        _apply_success_status(scan_history, runner_done, runner_name, runner_type, runner_status, logger)
    elif runner_status in {"RUNNING", "FAILURE", "FAILED", "REVOKED"}:
        _apply_terminal_or_running_status(
            scan_history,
            runner_status,
            runner_done,
            runner_name,
            runner_type,
            runner_status_to_scan_status,
            logger,
        )


def _apply_success_status(
    scan_history, runner_done: bool, runner_name: str, runner_type: str, runner_status: str, logger: Any
) -> None:
    """Apply SUCCESS runner status to ScanHistory (completed or keep running)."""
    logger.log_debug(
        logger.PREFIX_SYNC,
        "SUCCESS",
        f"Processing SUCCESS status - Runner: {runner_name} (type={runner_type}), done: {runner_done}, Current ScanHistory status: {scan_history.scan_status}",
    )
    if runner_done:
        all_completed = is_all_runners_completed(scan_history.id, logger)
        logger.log_debug(
            logger.PREFIX_SYNC,
            "CHECK",
            f"All runners completed check: {all_completed} for scan {scan_history.id}",
        )
        old_status = scan_history.scan_status
        if all_completed:
            scan_history.scan_status = SCAN_STATUS_COMPLETED
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
                    "new_status": SCAN_STATUS_COMPLETED,
                    "stop_scan_date": scan_history.stop_scan_date,
                },
            )
        else:
            scan_history.scan_status = SCAN_STATUS_RUNNING
            scan_history.save(update_fields=["scan_status"])
            logger.log_debug(
                logger.PREFIX_SYNC,
                "KEEP_RUNNING",
                f"Scan {scan_history.id} not fully completed yet. Status changed from {old_status} to {SCAN_STATUS_RUNNING} by runner {runner_name} (type={runner_type})",
            )
    else:
        old_status = scan_history.scan_status
        scan_history.scan_status = SCAN_STATUS_RUNNING
        scan_history.save(update_fields=["scan_status"])
        logger.log_debug(
            logger.PREFIX_SYNC,
            "KEEP_RUNNING",
            f"Runner {runner_name} (type={runner_type}) in SUCCESS but not done. Status changed from {old_status} to {SCAN_STATUS_RUNNING}",
        )


def _apply_terminal_or_running_status(
    scan_history,
    runner_status: str,
    runner_done: bool,
    runner_name: str,
    runner_type: str,
    runner_status_to_scan_status: dict,
    logger: Any,
) -> None:
    """Apply RUNNING/FAILURE/FAILED/REVOKED to ScanHistory."""
    old_status = scan_history.scan_status
    if runner_status not in runner_status_to_scan_status:
        logger.log_warning(
            f"Unexpected runner status {runner_status} for runner {runner_name} (type={runner_type}), scan_id={scan_history.id}; mapping to FAILED",
            {"prefix": logger.PREFIX_SYNC, "action": "UPDATED"},
        )
    scan_status_value = runner_status_to_scan_status.get(runner_status, SCAN_STATUS_FAILED)
    scan_history.scan_status = scan_status_value
    if runner_done and runner_status in {"FAILURE", "FAILED"} and not scan_history.stop_scan_date:
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
            "new_status": scan_status_value,
            "done": runner_done,
            "stop_scan_date": scan_history.stop_scan_date,
        },
    )


def _sync_scan_activity(
    scan_history,
    secator_runner: SecatorRunner,
    runner_data: dict,
    runner_name: str,
    runner_type: str,
    runner_status: str,
    runner_done: bool,
    rengine_status: int,
    logger: Any,
) -> int | None:
    """Create or update ScanActivity for this runner; return activity id for command log."""
    scan_repo = ScanRepository()
    reports_folder = runner_data.get("run_opts", {}).get("reports_folder")
    activity_title = f"{runner_type.title()}: {runner_name}"

    existing_activity = (
        ScanActivity.objects.filter(scan_of=scan_history, name=runner_name, runner_id=secator_runner)
        .order_by("-time")
        .first()
    )
    if existing_activity:
        existing_activity.status = rengine_status
        existing_activity.time = timezone.now()
        if runner_done and runner_status in {"SUCCESS", "FAILURE", "FAILED"}:
            existing_activity.title = f"{activity_title} - Completed"
        if reports_folder:
            existing_activity.results_dir = reports_folder
        update_fields = ["status", "time", "title"]
        if reports_folder:
            update_fields.append("results_dir")
        existing_activity.save(update_fields=update_fields)
        logger.log_debug(
            logger.PREFIX_SYNC,
            "ACTIVITY",
            f"Updated ScanActivity {existing_activity.id} for runner {runner_name}",
        )
        return existing_activity.id

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
            f"Created ScanActivity {activity_id_for_command} for runner {runner_name}",
        )
    except ScanActivity.DoesNotExist:
        logger.log_warning(
            f"Could not find newly created ScanActivity {activity_id_for_command}",
            {"prefix": logger.PREFIX_SYNC, "action": "SYNC", "runner": runner_name},
        )
    return activity_id_for_command


def _finalize_runner_sync(
    secator_runner: SecatorRunner,
    scan_history,
    runner_data: dict,
    runner_name: str,
    runner_type: str,
    runner_status: str,
    rengine_status: int,
    activity_id_for_command: int | None,
    logger: Any,
) -> None:
    """Sync subscans, log sync, save command, and log websocket send."""
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
            f"Error saving command log for runner {runner_name}: {e}",
            {"prefix": logger.PREFIX_SYNC, "action": "SYNC", "runner": runner_name},
        )

    runner_progress = runner_data.get("progress")
    if isinstance(runner_progress, (int, float)) and runner_progress >= 0:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "WEBSOCKET",
            f"Sending progress update for scan {scan_history.id} - Runner: {runner_name}, Progress: {runner_progress}%, Status: {runner_status}",
        )
    else:
        logger.log_debug(
            logger.PREFIX_SYNC,
            "WEBSOCKET",
            f"Sending runner update for scan {scan_history.id} - Runner: {runner_name}, Status: {runner_status} (no progress data)",
        )
