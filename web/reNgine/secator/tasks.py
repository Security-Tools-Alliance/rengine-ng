from django.core.exceptions import ObjectDoesNotExist

from reNgine.core.path import is_safe_path
from reNgine.core.validators import sanitize_path_component
from reNgine.utilities.error import get_safe_user_message
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import get_subdomain_from_url
from startScan.models import ScanHistory
from targetApp.models import Target


PREFIX_SECATOR_TASKS = "[SECATOR_TASKS]"
logger = get_module_logger(__name__)


def _workspace_for_target(target: Target) -> str:
    """
    Return workspace string for target.
    When a project is associated, include project slug or id to avoid workspace
    collision for identical target values across projects.
    """
    if target.project_id is not None:
        try:
            project = target.project
            slug = getattr(project, "slug", None) if project else None
            if slug:
                return f"{sanitize_path_component(slug)}/{sanitize_path_component(target.value)}"
            return f"{target.project_id}/{sanitize_path_component(target.value)}"
        except Exception:
            return f"{target.project_id}/{sanitize_path_component(target.value)}"
    return sanitize_path_component(target.value)


def initiate_secator_scan(
    scan_history_id,
    target_id=None,
    execution_mode=None,
    workflow_id=None,
    task_ids=None,
    secator_scan_type=None,
    imported_subdomains=None,
    out_of_scope_subdomains=None,
    initiated_by_id=None,
    url_filter="",
    subdomain_ids=None,
    secator_config=None,
    targets_override=None,
    subscan_id=None,
    worker_id=None,
):
    """Initiate a new Secator scan.

    Args:
        scan_history_id (int): ScanHistory id.
        target_id (int): Target id (required).
        execution_mode (str): workflow|tasks|scan
        workflow_id (int): Required for workflow mode
        task_ids (list): Required for tasks mode
        secator_scan_type (str): Required for scan mode
        imported_subdomains (list): Imported subdomains.
        out_of_scope_subdomains (list): Out-of-scope subdomains.
        url_filter (str): URL path. Default: ''.
        initiated_by_id (int): User ID initiating the scan.
        subdomain_ids (list): Optional; for subscan, list of subdomain IDs to restrict targets.
        secator_config (dict): Secator configuration (proxy, delay, profiles). Default: None.
        targets_override (list): Optional; explicit target strings. When set, used instead of DB-built targets.
        subscan_id (int): Optional SubScan id; when set, passed in config so runner context includes it for findings.
    """
    try:
        import os

        from secator.utils import autodetect_type

        from reNgine.secator.orchestrator import ScanOrchestrator
        from reNgine.secator.services.input_type_service import InputTypeService
        from reNgine.settings import SECATOR_RESULTS

        if target_id is None:
            raise ValueError("target_id is required for Secator scan")

        target = Target.objects.get(id=target_id)
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.is_legacy_scan = False
        scan_history.save()

        if execution_mode == "workflow" and not workflow_id:
            raise ValueError("workflow_id required for workflow mode")
        if execution_mode == "tasks" and not task_ids:
            raise ValueError("task_ids required for tasks mode")
        if execution_mode == "scan" and not secator_scan_type:
            raise ValueError("secator_scan_type required for scan mode")
        if execution_mode not in ["workflow", "tasks", "scan"]:
            raise ValueError("Invalid execution_mode: %s" % (execution_mode,))

        if execution_mode == "workflow":
            input_types = InputTypeService.get_input_types(workflow_id=workflow_id)
        elif execution_mode == "scan":
            input_types = InputTypeService.get_input_types(scan_name=secator_scan_type)
        else:
            from scanEngine.models import SecatorTask

            tasks_qs = SecatorTask.objects.filter(id__in=task_ids)
            if not tasks_qs.exists():
                raise ValueError("No active tasks found for IDs %s" % (list(task_ids),))
            task_types = list(tasks_qs.values_list("task_type", flat=True))
            input_types_set = set()
            for task_type in task_types:
                input_types_set.update(InputTypeService.get_input_types_for_task(task_type))
            input_types = list(input_types_set)

        if not input_types:
            raise ValueError("Could not resolve input_types for the selected workflow/scan/task")

        if targets_override is not None:
            raw_targets = [str(t).strip() for t in targets_override if t is not None and str(t).strip()]
        else:
            raw_targets = build_enriched_targets(
                input_types=input_types,
                target_id=target_id,
                subdomain_ids=subdomain_ids or [],
                out_of_scope_subdomains=out_of_scope_subdomains or [],
                url_filter=url_filter,
            )

        def _safe_target_repr(target: str, max_len: int = 32) -> str:
            """
            Return a safe string representation of a target for logging.

            Keeps only a small prefix and redacts the rest to avoid leaking
            potentially sensitive data (full hostnames, URLs, IPs, etc.).
            """
            if target is None:
                return "<none>"
            target_str = target
            if len(target_str) <= max_len:
                return target_str
            return f"{target_str[:max_len]}...[redacted]"

        validated_targets = []
        for t in raw_targets:
            detected = autodetect_type(t)
            if detected in input_types:
                validated_targets.append(t)
            else:
                logger.log_line(
                    PREFIX_SECATOR_TASKS,
                    "TARGETS",
                    "Target skipped (detected type %s not in %s, value_prefix=%s)"
                    % (detected, input_types, _safe_target_repr(t)),
                    level="debug",
                )
        if not validated_targets:
            raise ValueError(
                "No valid targets for input_types %s. "
                "Ensure discovery data (endpoints, subdomains, IPs) exists for this target." % (input_types,)
            )
        targets = validated_targets

        target_value_sanitized = sanitize_path_component(target.value)
        target_results_dir = os.path.abspath(os.path.join(SECATOR_RESULTS, target_value_sanitized))
        if not is_safe_path(SECATOR_RESULTS, target_results_dir):
            raise ValueError(
                "Target results path would escape SECATOR_RESULTS base; target.value may be invalid: %s"
                % (target.value,)
            )
        os.makedirs(target_results_dir, exist_ok=True)
        logger.log_line(
            PREFIX_SECATOR_TASKS,
            "TARGETS",
            "Built targets list: %s targets (input_types=%s)" % (len(targets), input_types),
            level="info",
        )

        config = {}
        if secator_config:
            if "proxy" in secator_config:
                config["proxy"] = secator_config["proxy"]
            if "delay" in secator_config:
                config["delay"] = secator_config["delay"]

        profiles = []
        if secator_config and "profiles" in secator_config:
            profile_list = secator_config.get("profiles", [])
            if isinstance(profile_list, list):
                profiles = [str(p) for p in profile_list if p is not None]
                logger.log_line(
                    PREFIX_SECATOR_TASKS,
                    "CONFIG",
                    "Using %s profile(s): %s" % (len(profiles), ", ".join(profiles) if profiles else "none"),
                    level="info",
                )

        if execution_mode == "workflow":
            from scanEngine.models import SecatorWorkflow

            workflow = SecatorWorkflow.objects.get(id=workflow_id)
            config["workflow_name"] = workflow.name
        elif execution_mode == "tasks":
            from scanEngine.models import SecatorTask

            tasks = SecatorTask.objects.filter(id__in=task_ids)
            if len(tasks) != len(task_ids):
                raise ValueError("Invalid task IDs")

            # Ensure deterministic ordering: preserve the original task_ids order
            tasks_by_id = {task.id: task for task in tasks}
            ordered_tasks = [tasks_by_id[task_id] for task_id in task_ids]

            config["tasks"] = [task.task_type for task in ordered_tasks]
        elif execution_mode == "scan":
            config["scan_type"] = secator_scan_type

        if subscan_id is not None:
            config["subscan_id"] = subscan_id

        if worker_id:
            from reNgine.secator.remote_runner import run_scan_on_worker
            from reNgine.secator.service import handle_scan_error
            from scanEngine.models import SecatorWorker

            worker = SecatorWorker.objects.get(id=worker_id)
            if not worker.is_active:
                raise ValueError("Worker is not active")
            workspace = _workspace_for_target(target)
            remote_config = {"proxy": config.get("proxy"), "delay": config.get("delay"), "profiles": profiles}
            try:
                run_scan_on_worker(
                    worker,
                    scan_history_id=scan_history_id,
                    target_id=target_id,
                    workspace_name=workspace,
                    execution_mode=execution_mode,
                    targets=targets,
                    workflow_name=config.get("workflow_name"),
                    scan_type=config.get("scan_type"),
                    task_names=config.get("tasks"),
                    secator_config=remote_config,
                    subscan_id=subscan_id,
                )
            except Exception as e:
                handle_scan_error(scan_history, e)
                return {
                    "status": "error",
                    "error": get_safe_user_message(e, logger),
                    "scan_type": "secator",
                    "result": {"worker_id": worker.id, "mode": "remote"},
                }
            result = {
                "scan_history_id": scan_history_id,
                "worker_id": worker.id,
                "mode": "remote",
            }
            if subscan_id is not None:
                result["subscan_id"] = subscan_id
            return {"status": "success", "result": result, "scan_type": "secator"}

        orchestrator = ScanOrchestrator()
        result = orchestrator.execute_scan(
            scan_history_id=scan_history_id,
            target_id=target_id,
            execution_mode=execution_mode,
            targets=targets,
            config=config,
            profiles=profiles,
        )

        return {
            "status": "success",
            "result": result,
            "scan_type": "secator",
        }

    except ObjectDoesNotExist as e:
        logger.log_line(
            PREFIX_SECATOR_TASKS,
            "INIT",
            "Invalid reference for Secator scan: %s" % (e,),
            level="warning",
        )
        return {"status": "error", "error": "Invalid scan, target, or workflow ID"}
    except ValueError as e:
        logger.log_line(
            PREFIX_SECATOR_TASKS,
            "INIT",
            "Validation error initiating Secator scan: %s" % (e,),
            level="warning",
        )
        return {"status": "error", "error": str(e)}
    except Exception:
        logger.log_line(
            PREFIX_SECATOR_TASKS,
            "INIT",
            "Error initiating Secator scan",
            level="error",
            exc_info=True,
        )
        return {"status": "error", "error": "Failed to start scan due to a server error."}


def build_enriched_targets(
    input_types: list,
    target_id: int = None,
    subdomain_ids: list = None,
    out_of_scope_subdomains=None,
    url_filter: str = "",
):
    """Build enriched targets list for Secator scan from input_types and Target/domain data.

    Uses TargetBuilderService to build targets per input_type (url, host, host:port, ip, etc.),
    then optionally applies out-of-scope filter and URL path filter.

    Args:
        input_types: List of Secator input type strings (e.g. ['url'], ['host', 'ip'])
        target_id: Target ID (required).
        subdomain_ids: Optional list of subdomain IDs (for subscan; restricts to these subdomains)
        out_of_scope_subdomains: Optional list of hostnames to exclude from targets
        url_filter: Optional URL path to append to targets (e.g. '/api'). Applied only when
            input_types includes 'url'; ignored for host, ip, host:port to avoid invalid values.

    Returns:
        List of target strings for Secator
    """
    if subdomain_ids is None:
        subdomain_ids = []
    if out_of_scope_subdomains is None:
        out_of_scope_subdomains = []

    if target_id is None:
        raise ValueError("target_id is required")

    from reNgine.secator.services.target_builder_service import TargetBuilderService

    builder = TargetBuilderService(target_id=target_id, subdomain_ids=subdomain_ids)
    targets = builder.build_flat_targets(input_types)

    if out_of_scope_subdomains:
        out_of_scope_clean = {s.strip().lower() for s in out_of_scope_subdomains if s and s.strip()}
        original_count = len(targets)
        targets = [t for t in targets if get_subdomain_from_url(t).lower() not in out_of_scope_clean]
        if original_count > len(targets):
            logger.log_line(
                PREFIX_SECATOR_TASKS,
                "TARGETS",
                "Removed %s out-of-scope targets" % (original_count - len(targets),),
                level="info",
            )

    if url_filter and url_filter.strip() and "url" in input_types:
        url_filter_clean = url_filter.strip()
        if not url_filter_clean.startswith("/"):
            url_filter_clean = f"/{url_filter_clean}"
        logger.log_line(
            PREFIX_SECATOR_TASKS,
            "TARGETS",
            "Applying URL filter: %s" % (url_filter_clean,),
            level="info",
        )
        targets = [f"{t}{url_filter_clean}" for t in targets]
    elif url_filter and url_filter.strip():
        logger.log_line(
            PREFIX_SECATOR_TASKS,
            "TARGETS",
            "URL filter not applied: path appending only applies when input_types include 'url'",
            level="debug",
        )

    logger.log_line(
        PREFIX_SECATOR_TASKS,
        "TARGETS",
        "Final targets list: %s targets (input_types=%s)" % (len(targets), input_types),
        level="info",
    )
    return targets
