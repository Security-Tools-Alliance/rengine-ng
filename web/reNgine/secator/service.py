"""
Secator scan service - Business logic for starting Secator scans.

This service provides the core logic for starting scans, decoupled from
API and UI layers for better reusability and testability.
"""

from __future__ import annotations

import logging
import threading
from typing import TypedDict

from django.utils import timezone

from reNgine.definitions import ABORTED_TASK, FAILED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.secator.selected_targets import (
    PerTaskValidationError,
    validate_per_task_targets,
)
from reNgine.secator.tasks import initiate_secator_scan
from reNgine.services.repositories.scan_repository import ScanRepository
from reNgine.utilities.websocket import send_scan_status_update
from scanEngine.models import SecatorScan, SecatorTask
from startScan.models import ScanHistory, Subdomain, SubScan
from targetApp.models import Domain


logger = logging.getLogger(__name__)


class PerTaskRunResult(TypedDict):
    """Result of run_per_task_secator_scans: validation errors and run results."""

    validation_errors: list[PerTaskValidationError]
    results: list[dict]
    success_count: int
    failed_count: int
    scan_id: int | None


def handle_scan_error(scan: ScanHistory, error: Exception) -> None:
    """
    Handle scan error by marking scan as failed if not already in terminal state.

    This function prevents race conditions with hooks that may have updated
    the scan status to a terminal state (SUCCESS, FAILED, or ABORTED).

    Args:
        scan: ScanHistory instance to update
        error: Exception that occurred during scan execution
    """
    logger.exception("Error in scan thread: %s", error)
    # Refresh from DB to get current state before modifying
    scan.refresh_from_db()
    # Only mark as failed if scan is not already in a terminal state
    # to avoid race conditions with hooks that may have updated the status
    terminal_statuses = [SUCCESS_TASK, FAILED_TASK, ABORTED_TASK]
    if scan.scan_status not in terminal_statuses:
        scan.scan_status = FAILED_TASK
        scan.save()
    else:
        logger.debug(f"Scan {scan.id} already in terminal state {scan.scan_status}, skipping error status update")


def start_secator_scan(
    domain_id: int,
    user_id: int,
    execution_mode: str = None,
    workflow_id: int = None,
    task_ids: list = None,
    secator_scan_type: str = None,
    secator_scan_id: int = None,
    imported_subdomains: list = None,
    out_of_scope_subdomains: list = None,
    url_filter: str = "",
    subdomain_ids: list = None,
    secator_config: dict = None,
    targets_override: list = None,
    scan_history_id: int = None,
    subscan_id: int = None,
    worker_id: int = None,
) -> dict:
    """
    Start a Secator scan with the given parameters.

    This is a shared service function that can be called from both API and UI layers
    without coupling them together.

    When scan_history_id is provided with execution_mode, no new ScanHistory is created;
    the existing one is reused (used by run_per_task_secator_scans to share one scan).
    When subscan_id is provided, it is passed to the runner context so findings can link to the SubScan.

    Args:
        domain_id: ID of the target domain
        user_id: ID of the user initiating the scan
        execution_mode: workflow|tasks|scan
        workflow_id: Required for workflow mode
        task_ids: Required for tasks mode
        secator_scan_type: Required for scan mode
        secator_scan_id: ID of existing SecatorScan configuration
        imported_subdomains: List of subdomains to import
        out_of_scope_subdomains: List of subdomains to exclude
        url_filter: URL filter/path to scan
        secator_config: Configuration parameters (proxy, delay, profiles array)
        targets_override: Optional list of target strings; when set, used instead of DB-built targets
        scan_history_id: Optional existing ScanHistory id; when set with execution_mode, reuse it instead of creating
        subscan_id: Optional SubScan id; when set, passed to runner context for findings linking
        worker_id: Optional SecatorWorker id; when set, run the scan on that remote worker via SSH

    Returns:
        dict: Result with 'status' (bool), 'scan_id' (int), 'error' (str), 'http_status' (int), etc.
    """
    if task_ids is None:
        task_ids = []
    if imported_subdomains is None:
        imported_subdomains = []
    if out_of_scope_subdomains is None:
        out_of_scope_subdomains = []
    if secator_config is None:
        secator_config = {}
    if subdomain_ids is None:
        subdomain_ids = []
    if targets_override is None:
        targets_override = []

    # Handle random proxy if proxy is None
    if secator_config.get("proxy") is None:
        from reNgine.utilities.proxy import get_random_proxy

        random_proxy = get_random_proxy()
        if random_proxy:
            secator_config["proxy"] = random_proxy

    # Validate required parameters
    if not domain_id:
        return {"status": False, "error": "domain_id is required", "http_status": 400}

    # Verify domain exists
    try:
        domain = Domain.objects.get(id=domain_id)
    except Domain.DoesNotExist:
        return {"status": False, "error": f"Domain with ID {domain_id} not found", "http_status": 404}

    if worker_id is not None:
        from scanEngine.models import SecatorWorker

        if not SecatorWorker.objects.filter(id=worker_id, is_active=True).exists():
            return {"status": False, "error": "Worker not found or not active", "http_status": 400}

    # Ensure lists are properly formatted
    if isinstance(imported_subdomains, str):
        imported_subdomains = [s.strip() for s in imported_subdomains.split("\n") if s.strip()]
    if isinstance(out_of_scope_subdomains, str):
        out_of_scope_subdomains = [s.strip() for s in out_of_scope_subdomains.split("\n") if s.strip()]

    try:
        # Handle existing SecatorScan ID
        if secator_scan_id:
            # Use existing SecatorScan - this is a special case for API
            try:
                secator_scan = SecatorScan.objects.get(id=secator_scan_id)
            except SecatorScan.DoesNotExist:
                return {
                    "status": False,
                    "error": f"SecatorScan with ID {secator_scan_id} not found",
                    "http_status": 404,
                }

            # Use the existing scan configuration
            scan_repo = ScanRepository()
            scan_history_id = scan_repo.create_scan(
                host_id=domain_id,
                engine_id=1,
                initiated_by_id=user_id,
            )
            scan = ScanHistory.objects.get(pk=scan_history_id)

            secator_scan_type = secator_scan.name

            # Copy user ID to local variable for thread safety
            initiated_by_id = user_id

            # Launch scan asynchronously in a separate thread
            def launch_scan():
                try:
                    initiate_secator_scan(
                        scan_history_id=scan.id,
                        domain_id=domain_id,
                        execution_mode="scan",
                        secator_scan_type=secator_scan_type,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        subdomain_ids=subdomain_ids or [],
                        secator_config=secator_config,
                        initiated_by_id=initiated_by_id,
                        worker_id=worker_id,
                    )
                    # Do not save scan here - status is managed by Secator hooks via SecatorRunnerUpdate API
                    # Saving would overwrite the status updated by the hooks
                except Exception as e:
                    handle_scan_error(scan, e)

            scan_thread = threading.Thread(target=launch_scan, daemon=True)
            scan_thread.start()

            # Return immediately without waiting for scan completion
            return {
                "status": True,
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "domain_id": domain.id,
                "domain_name": domain.name,
                "secator_scan_id": secator_scan.id,
                "execution_mode": "scan",
                "message": f"Scan started successfully for {domain.name}",
                "http_status": 200,
            }

        if scan_history_id is not None and execution_mode:
            try:
                scan = ScanHistory.objects.get(pk=scan_history_id)
            except ScanHistory.DoesNotExist:
                return {
                    "status": False,
                    "error": f"ScanHistory with ID {scan_history_id} not found",
                    "http_status": 404,
                }
            if scan.domain_id != domain_id:
                return {
                    "status": False,
                    "error": f"ScanHistory {scan_history_id} does not belong to domain {domain_id}",
                    "http_status": 400,
                }
            initiated_by_id = user_id

            def launch_scan():
                try:
                    initiate_secator_scan(
                        scan_history_id=scan.id,
                        domain_id=domain_id,
                        execution_mode=execution_mode,
                        workflow_id=workflow_id,
                        task_ids=task_ids,
                        secator_scan_type=secator_scan_type,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        subdomain_ids=subdomain_ids or [],
                        secator_config=secator_config,
                        initiated_by_id=initiated_by_id,
                        targets_override=targets_override or None,
                        subscan_id=subscan_id,
                        worker_id=worker_id,
                    )
                except Exception as e:
                    handle_scan_error(scan, e)

            threading.Thread(target=launch_scan, daemon=True).start()
            return {
                "status": True,
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "domain_id": domain.id,
                "domain_name": domain.name,
                "execution_mode": execution_mode,
                "message": f"Scan task started for {domain.name}",
                "http_status": 200,
            }

        if execution_mode:
            # Create scan object first (synchronously)
            scan_repo = ScanRepository()
            new_scan_history_id = scan_repo.create_scan(
                host_id=domain_id,
                engine_id=1,  # Fixed engine ID for all Secator scans
                initiated_by_id=user_id,
            )
            scan = ScanHistory.objects.get(pk=new_scan_history_id)

            # Copy user ID to local variable for thread safety
            initiated_by_id = user_id

            # Launch scan asynchronously in a separate thread
            # Secator will handle Celery tasks internally
            def launch_scan():
                try:
                    initiate_secator_scan(
                        scan_history_id=scan.id,
                        domain_id=domain_id,
                        execution_mode=execution_mode,
                        workflow_id=workflow_id,
                        task_ids=task_ids,
                        secator_scan_type=secator_scan_type,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        subdomain_ids=subdomain_ids or [],
                        secator_config=secator_config,
                        initiated_by_id=initiated_by_id,
                        targets_override=targets_override or None,
                        worker_id=worker_id,
                    )
                    # Do not save scan here - status is managed by Secator hooks via SecatorRunnerUpdate API
                    # Saving would overwrite the status updated by the hooks
                except Exception as e:
                    handle_scan_error(scan, e)

            scan_thread = threading.Thread(target=launch_scan, daemon=True)
            scan_thread.start()

            # Return immediately without waiting for scan completion
            return {
                "status": True,
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "domain_id": domain.id,
                "domain_name": domain.name,
                "execution_mode": execution_mode,
                "message": f"Scan started successfully for {domain.name}",
                "http_status": 200,
            }
        else:
            return {
                "status": False,
                "error": "Must provide either secator_scan_id or execution_mode with parameters",
                "http_status": 400,
            }

    except Exception:
        logger.exception("Error starting scan")
        return {"status": False, "error": "Failed to start scan due to a server error.", "http_status": 500}


def _run_one_per_task_entry(
    task_type: str,
    targets: list[str],
    task_id: int,
    shared_scan_id: int,
    subdomains: list,
    scan: ScanHistory | None,
    domain_id: int,
    user_id: int,
    imported_subdomains: list,
    out_of_scope_subdomains: list,
    url_filter: str,
    secator_config: dict,
    *,
    worker_id: int | None = None,
) -> tuple[dict, bool]:
    """Run one per-task (task_type, targets) and return (result_dict, success)."""
    subscan = None
    if subdomains and scan:
        subscan = SubScan.objects.create(
            scan_history=scan,
            subdomain=subdomains[0],
            type=task_type,
            start_scan_date=timezone.now(),
            status=RUNNING_TASK,
        )
        send_scan_status_update(scan.id)

    try:
        result = start_secator_scan(
            domain_id=domain_id,
            user_id=user_id,
            execution_mode="tasks",
            task_ids=[task_id],
            targets_override=targets,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=out_of_scope_subdomains,
            url_filter=url_filter,
            secator_config=secator_config,
            scan_history_id=shared_scan_id,
            subscan_id=subscan.id if subscan else None,
            worker_id=worker_id,
        )
        if result.get("status"):
            return ({"task_type": task_type, "status": "success", "scan_id": shared_scan_id}, True)
        err_msg = result.get("error", "Unknown error")
        logger.warning("Per-task scan failed for task_type=%s: %s", task_type, err_msg)
        return (
            {"task_type": task_type, "status": "error", "error": err_msg, "detail": err_msg},
            False,
        )
    except ValueError as exc:
        logger.warning("Per-task start failed for task_type=%s: %s", task_type, exc)
        return (
            {
                "task_type": task_type,
                "status": "error",
                "error": str(exc),
                "detail": "Failed to start scan for this task",
            },
            False,
        )
    except Exception as e:
        logger.exception("Per-task error for task_type=%s: %s", task_type, e)
        return (
            {
                "task_type": task_type,
                "status": "error",
                "error": str(e),
                "detail": "Unexpected error starting scan for this task",
            },
            False,
        )


def run_per_task_secator_scans(
    domain_id: int,
    user_id: int,
    selected_targets_per_task: dict[str, list[str]],
    *,
    task_type_to_id: dict[str, int] | None = None,
    imported_subdomains: list | None = None,
    out_of_scope_subdomains: list | None = None,
    url_filter: str = "",
    secator_config: dict | None = None,
    subdomain_ids: list[int] | None = None,
    scan_history_id: int | None = None,
    worker_id: int | None = None,
) -> PerTaskRunResult:
    """
    Validate per-task targets and run one scan per (task_type, targets) under a single ScanHistory.

    High-level: This is used when resolve_selected_targets returned use_per_task=True (execution_mode
    "tasks" with per-task targets). It uses one ScanHistory (reused if scan_history_id is provided
    and valid for the domain, otherwise creates a new one) and one SubScan/Celery task per
    (task_type, targets) so each task type runs with its own targets while sharing the same scan.

    When scan_history_id is provided and exists for the given domain_id, that ScanHistory is
    reused; otherwise a new one is created (e.g. when launching from target summary where there
    is no single scan). When subdomain_ids is provided, only the first ID is used: one SubScan
    per task is created and linked to that single subdomain; any additional subdomain_ids are
    ignored. When task_type_to_id is None, it is loaded from SecatorTask.
    Validation errors (unknown_task_type, no_targets) are returned in validation_errors.
    """
    if task_type_to_id is None:
        task_types = list(selected_targets_per_task.keys())
        tasks = SecatorTask.objects.filter(task_type__in=task_types, is_active=True)
        task_type_to_id = dict(tasks.values_list("task_type", "id"))

    validation_errors = validate_per_task_targets(selected_targets_per_task, task_type_to_id)
    error_task_types = {e["task_type"] for e in validation_errors}
    imported_subdomains = imported_subdomains or []
    out_of_scope_subdomains = out_of_scope_subdomains or []
    secator_config = secator_config or {}
    subdomain_ids = subdomain_ids or []
    if len(subdomain_ids) > 1:
        logger.warning(
            "run_per_task_secator_scans: only the first subdomain_id is used for SubScan linkage; %d provided, rest ignored",
            len(subdomain_ids),
        )
    subdomain_ids_for_subscan = subdomain_ids[:1] if subdomain_ids else []

    valid_entries = [
        (task_type, targets, task_type_to_id[task_type])
        for task_type, targets in selected_targets_per_task.items()
        if task_type not in error_task_types and task_type in task_type_to_id and targets
    ]
    if not valid_entries:
        return {
            "validation_errors": validation_errors,
            "results": [],
            "success_count": 0,
            "failed_count": 0,
            "scan_id": None,
        }

    scan = None
    if scan_history_id is not None:
        scan = ScanHistory.objects.filter(id=scan_history_id, domain_id=domain_id).first()
    if scan is None:
        scan_repo = ScanRepository()
        shared_scan_id = scan_repo.create_scan(
            host_id=domain_id,
            engine_id=1,
            initiated_by_id=user_id,
        )
        scan = ScanHistory.objects.get(pk=shared_scan_id)
    shared_scan_id = scan.id
    subdomains = list(Subdomain.objects.filter(id__in=subdomain_ids_for_subscan)) if subdomain_ids_for_subscan else []
    scan_for_subscans = scan if subdomains else None

    results: list[dict] = []
    success_count = 0
    failed_count = 0

    for task_type, targets, task_id in valid_entries:
        result_dict, success = _run_one_per_task_entry(
            task_type,
            targets,
            task_id,
            shared_scan_id,
            subdomains,
            scan_for_subscans,
            domain_id,
            user_id,
            imported_subdomains,
            out_of_scope_subdomains,
            url_filter,
            secator_config,
            worker_id=worker_id,
        )
        results.append(result_dict)
        if success:
            success_count += 1
        else:
            failed_count += 1

    return {
        "validation_errors": validation_errors,
        "results": results,
        "success_count": success_count,
        "failed_count": failed_count,
        "scan_id": shared_scan_id,
    }
