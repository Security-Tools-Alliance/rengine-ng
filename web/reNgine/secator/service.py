"""
Secator scan service - Business logic for starting Secator scans.

This service provides the core logic for starting scans, decoupled from
API and UI layers for better reusability and testability.
"""

from __future__ import annotations

import copy
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
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.websocket import send_scan_status_update
from scanEngine.models import SecatorScan, SecatorTask
from startScan.models import ScanHistory, Subdomain, SubScan
from targetApp.models import Target
from targetApp.services.scope_params import (
    apply_resolved_to_secator_config,
    flatten_profile_opts_into_config,
    get_scope_for_target,
    resolve_scan_params,
)


PREFIX_SECATOR_SERVICE = "[SECATOR_SERVICE]"
logger = get_module_logger(__name__)


class PerTaskRunResult(TypedDict):
    """Result of run_per_task_secator_scans: validation errors and run results."""

    validation_errors: list[PerTaskValidationError]
    results: list[dict]
    success_count: int
    failed_count: int
    scan_id: int | None


def _persist_scan_config_on_history(scan: ScanHistory, secator_config: dict | None) -> None:
    """Persist the effective scan_config snapshot on a ScanHistory after creation."""
    if secator_config:
        scan.scan_config = secator_config
        scan.save(update_fields=["scan_config"])


def _apply_effective_scan_params(target: Target, secator_config: dict) -> None:
    """
    Resolve and merge effective scan params from the target/scope/org chain into secator_config.

    Treats the current values in secator_config as the user override (highest priority).
    Missing values are filled from scope, organization, then settings defaults.
    Mutates secator_config in place.
    """
    scope = get_scope_for_target(target)
    organization = None
    if scope is not None:
        organization = getattr(scope, "organization", None)
    elif target is not None:
        orgs = getattr(target, "organizations", None)
        if orgs is not None:
            organization = orgs.first()
    resolved = resolve_scan_params(target, scope=scope, organization=organization, user_override=secator_config)
    apply_resolved_to_secator_config(secator_config, resolved)


def handle_scan_error(scan: ScanHistory, error: Exception) -> None:
    """
    Handle scan error by marking scan as failed if not already in terminal state.

    This function prevents race conditions with hooks that may have updated
    the scan status to a terminal state (SUCCESS, FAILED, or ABORTED).

    Args:
        scan: ScanHistory instance to update
        error: Exception that occurred during scan execution
    """
    logger.log_line(
        PREFIX_SECATOR_SERVICE,
        "SCAN_THREAD",
        "Error in scan thread: %s" % (error,),
        level="error",
        exc_info=True,
    )
    # Refresh from DB to get current state before modifying
    scan.refresh_from_db()
    # Only mark as failed if scan is not already in a terminal state
    # to avoid race conditions with hooks that may have updated the status
    terminal_statuses = [SUCCESS_TASK, FAILED_TASK, ABORTED_TASK]
    if scan.scan_status not in terminal_statuses:
        scan.scan_status = FAILED_TASK
        scan.save()
    else:
        logger.log_line(
            PREFIX_SECATOR_SERVICE,
            "SCAN_THREAD",
            "Scan %s already in terminal state %s, skipping error status update" % (scan.id, scan.scan_status),
            level="debug",
        )


def start_secator_scan(
    user_id: int,
    target_id: int = None,
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
        user_id: ID of the user initiating the scan
        target_id: ID of the target (required). Scan is always launched from a target.
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

    if target_id is None:
        return {"status": False, "error": "target_id is required", "http_status": 400}
    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return {"status": False, "error": "Target with ID %s not found" % (target_id,), "http_status": 404}

    # Merge effective params from target/scope/org chain; secator_config values act as user overrides.
    # Resolution happens here so both UI and API paths benefit consistently.
    _apply_effective_scan_params(target, secator_config)

    # Apply random proxy only after scope/org resolution: proxy from scope takes precedence
    # and random proxy is the last fallback when still unset.
    if secator_config.get("proxy") is None:
        from reNgine.utilities.proxy import get_random_proxy

        random_proxy = get_random_proxy()
        if random_proxy:
            secator_config["proxy"] = random_proxy

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

            scan_repo = ScanRepository()
            create_kw = {"engine_id": 1, "initiated_by_id": user_id, "target_id": target.id}
            scan_history_id = scan_repo.create_scan(**create_kw)
            scan = ScanHistory.objects.get(pk=scan_history_id)
            effective_snapshot = copy.deepcopy(secator_config)
            flatten_profile_opts_into_config(effective_snapshot)
            _persist_scan_config_on_history(scan, effective_snapshot)

            secator_scan_type = secator_scan.name
            initiated_by_id = user_id

            def launch_scan():
                try:
                    init_kw = {
                        "scan_history_id": scan.id,
                        "execution_mode": "scan",
                        "target_id": target.id,
                    }
                    initiate_secator_scan(
                        **init_kw,
                        secator_scan_type=secator_scan_type,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        subdomain_ids=subdomain_ids or [],
                        secator_config=secator_config,
                        initiated_by_id=initiated_by_id,
                        worker_id=worker_id,
                    )
                except Exception as e:
                    handle_scan_error(scan, e)

            scan_thread = threading.Thread(target=launch_scan, daemon=True)
            scan_thread.start()

            return {
                "status": True,
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "target_id": target.id,
                "target_name": target.value,
                "secator_scan_id": secator_scan.id,
                "execution_mode": "scan",
                "message": "Scan started successfully for %s" % (target.value,),
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
            if scan.target_id != target.id:
                return {
                    "status": False,
                    "error": "ScanHistory %s does not belong to target %s" % (scan_history_id, target_id),
                    "http_status": 400,
                }
            initiated_by_id = user_id

            def launch_scan():
                try:
                    init_kw = {"scan_history_id": scan.id, "execution_mode": execution_mode, "target_id": target.id}
                    initiate_secator_scan(
                        **init_kw,
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
                "target_id": target.id,
                "target_name": target.value,
                "execution_mode": execution_mode,
                "message": "Scan task started for %s" % (target.value,),
                "http_status": 200,
            }

        if execution_mode:
            scan_repo = ScanRepository()
            create_kw = {"engine_id": 1, "initiated_by_id": user_id, "target_id": target.id}
            new_scan_history_id = scan_repo.create_scan(**create_kw)
            scan = ScanHistory.objects.get(pk=new_scan_history_id)
            effective_snapshot = copy.deepcopy(secator_config)
            flatten_profile_opts_into_config(effective_snapshot)
            _persist_scan_config_on_history(scan, effective_snapshot)
            initiated_by_id = user_id

            def launch_scan():
                try:
                    init_kw = {"scan_history_id": scan.id, "execution_mode": execution_mode, "target_id": target.id}
                    initiate_secator_scan(
                        **init_kw,
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
                except Exception as e:
                    handle_scan_error(scan, e)

            scan_thread = threading.Thread(target=launch_scan, daemon=True)
            scan_thread.start()

            return {
                "status": True,
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "target_id": target.id,
                "target_name": target.value,
                "execution_mode": execution_mode,
                "message": "Scan started successfully for %s" % (target.value,),
                "http_status": 200,
            }
        else:
            return {
                "status": False,
                "error": "Must provide either secator_scan_id or execution_mode with parameters",
                "http_status": 400,
            }

    except Exception:
        logger.log_line(
            PREFIX_SECATOR_SERVICE,
            "START_SCAN",
            "Error starting scan",
            level="error",
            exc_info=True,
        )
        return {"status": False, "error": "Failed to start scan due to a server error.", "http_status": 500}


def _run_one_per_task_entry(
    task_type: str,
    targets: list[str],
    task_id: int,
    shared_scan_id: int,
    subdomains: list,
    scan: ScanHistory | None,
    target_id: int,
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
            target_id=target_id,
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
        logger.log_line(
            PREFIX_SECATOR_SERVICE,
            "PER_TASK",
            "Per-task scan failed for task_type=%s: %s" % (task_type, err_msg),
            level="warning",
        )
        return (
            {"task_type": task_type, "status": "error", "error": err_msg, "detail": err_msg},
            False,
        )
    except ValueError as exc:
        logger.log_line(
            PREFIX_SECATOR_SERVICE,
            "PER_TASK",
            "Per-task start failed for task_type=%s: %s" % (task_type, exc),
            level="warning",
        )
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
        logger.log_line(
            PREFIX_SECATOR_SERVICE,
            "PER_TASK",
            "Per-task error for task_type=%s: %s" % (task_type, e),
            level="error",
            exc_info=True,
        )
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
    user_id: int,
    selected_targets_per_task: dict[str, list[str]],
    *,
    target_id: int | None = None,
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

    When scan_history_id is provided and exists for the given target_id/domain_id, that ScanHistory is
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
        logger.log_line(
            PREFIX_SECATOR_SERVICE,
            "PER_TASK",
            "run_per_task_secator_scans: only the first subdomain_id is used for SubScan linkage; %s provided, rest ignored"
            % (len(subdomain_ids),),
            level="warning",
        )
    subdomain_ids_for_subscan = subdomain_ids[:1] if subdomain_ids else []

    if target_id is None:
        return {
            "validation_errors": validation_errors,
            "results": [],
            "success_count": 0,
            "failed_count": 0,
            "scan_id": None,
        }
    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return {
            "validation_errors": validation_errors,
            "results": [],
            "success_count": 0,
            "failed_count": 0,
            "scan_id": None,
        }

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
        scan = ScanHistory.objects.filter(id=scan_history_id, target_id=target.id).first()
    if scan is None:
        scan_repo = ScanRepository()
        create_kw = {"engine_id": 1, "initiated_by_id": user_id, "target_id": target.id}
        shared_scan_id = scan_repo.create_scan(**create_kw)
        scan = ScanHistory.objects.get(pk=shared_scan_id)
        # Resolve effective params before persisting so the DB snapshot reflects the
        # full resolved config including profile opts, not just the raw user override.
        _apply_effective_scan_params(target, secator_config)
        effective_snapshot = copy.deepcopy(secator_config)
        flatten_profile_opts_into_config(effective_snapshot)
        _persist_scan_config_on_history(scan, effective_snapshot)
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
            target.id,
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
