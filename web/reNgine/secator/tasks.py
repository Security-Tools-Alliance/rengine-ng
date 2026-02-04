from django.core.exceptions import ObjectDoesNotExist

from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import get_subdomain_from_url
from startScan.models import ScanHistory
from targetApp.models import Domain


logger = get_module_logger(__name__)


def initiate_secator_scan(
    scan_history_id,
    domain_id,
    execution_mode,
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
):
    """Initiate a new Secator scan.

    Args:
        scan_history_id (int): ScanHistory id.
        domain_id (int): Domain id.
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

        domain = Domain.objects.get(id=domain_id)
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
            raise ValueError(f"Invalid execution_mode: {execution_mode}")

        if execution_mode == "workflow":
            input_types = InputTypeService.get_input_types(workflow_id=workflow_id)
        elif execution_mode == "scan":
            input_types = InputTypeService.get_input_types(scan_name=secator_scan_type)
        else:
            from scanEngine.models import SecatorTask

            tasks_qs = SecatorTask.objects.filter(id__in=task_ids)
            if not tasks_qs.exists():
                raise ValueError(f"No active tasks found for IDs {list(task_ids)}")
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
                domain_id=domain_id,
                input_types=input_types,
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
                logger.debug(
                    "Target skipped (detected type %s not in %s, value_prefix=%s)",
                    detected,
                    input_types,
                    _safe_target_repr(t),
                )
        if not validated_targets:
            raise ValueError(
                f"No valid targets for input_types {input_types}. "
                "Ensure discovery data (endpoints, subdomains, IPs) exists for this domain."
            )
        targets = validated_targets

        domain_results_dir = os.path.join(SECATOR_RESULTS, domain.name)
        os.makedirs(domain_results_dir, exist_ok=True)
        logger.info(f"Built targets list: {len(targets)} targets (input_types={input_types})")

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
                logger.info(f"Using {len(profiles)} profile(s): {', '.join(profiles) if profiles else 'none'}")

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

        orchestrator = ScanOrchestrator()
        result = orchestrator.execute_scan(
            scan_history_id=scan_history_id,
            domain_id=domain_id,
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
        logger.warning("Invalid reference for Secator scan: %s", e)
        return {"status": "error", "error": "Invalid scan, domain, or workflow ID"}
    except ValueError as e:
        logger.warning("Validation error initiating Secator scan: %s", e)
        return {"status": "error", "error": str(e)}
    except Exception:
        logger.exception("Error initiating Secator scan")
        return {"status": "error", "error": "Failed to start scan due to a server error."}


def build_enriched_targets(
    domain_id: int,
    input_types: list,
    subdomain_ids: list = None,
    out_of_scope_subdomains=None,
    url_filter: str = "",
):
    """Build enriched targets list for Secator scan from input_types and domain/subdomain data.

    Uses TargetBuilderService to build targets per input_type (url, host, host:port, ip),
    then optionally applies out-of-scope filter and URL path filter.

    Args:
        domain_id: Domain ID
        input_types: List of Secator input type strings (e.g. ['url'], ['host', 'ip'])
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

    from reNgine.secator.services.target_builder_service import TargetBuilderService

    builder = TargetBuilderService(domain_id=domain_id, subdomain_ids=subdomain_ids)
    targets = builder.build_flat_targets(input_types)

    if out_of_scope_subdomains:
        out_of_scope_clean = {s.strip().lower() for s in out_of_scope_subdomains if s and s.strip()}
        original_count = len(targets)
        targets = [t for t in targets if get_subdomain_from_url(t).lower() not in out_of_scope_clean]
        if original_count > len(targets):
            logger.info(f"Removed {original_count - len(targets)} out-of-scope targets")

    if url_filter and url_filter.strip() and "url" in input_types:
        url_filter_clean = url_filter.strip()
        if not url_filter_clean.startswith("/"):
            url_filter_clean = f"/{url_filter_clean}"
        logger.info(f"Applying URL filter: {url_filter_clean}")
        targets = [f"{t}{url_filter_clean}" for t in targets]
    elif url_filter and url_filter.strip():
        logger.debug("URL filter not applied: path appending only applies when input_types include 'url'")

    logger.info(f"Final targets list: {len(targets)} targets (input_types={input_types})")
    return targets
