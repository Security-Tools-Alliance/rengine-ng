from celery.utils.log import get_task_logger

from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


logger = get_task_logger(__name__)


def start_secator_scan(
    domain_id,
    execution_mode,
    user_id,
    workflow_id=None,
    task_ids=None,
    secator_scan_type=None,
    imported_subdomains=None,
    out_of_scope_subdomains=None,
    url_filter="",
    scan_existing_elements=False,
    secator_config=None,
    speed_profile=None,
    stealth_profile=None,
    expert_mode=False,
    scan_type="internet",
):
    """Start a Secator scan with common logic for both UI and API.

    Args:
        domain_id (int): ID of the target domain
        execution_mode (str): workflow|tasks|scan
        user_id (int): ID of the user initiating the scan
        workflow_id (int): Required for workflow mode
        task_ids (list): Required for tasks mode
        secator_scan_type (str): Required for scan mode
        imported_subdomains (list): List of subdomains to import
        out_of_scope_subdomains (list): List of subdomains to exclude
        url_filter (str): URL filter/path to scan
        scan_existing_elements (bool): Whether to scan existing elements
        secator_config (dict): Configuration parameters
        speed_profile (str): Speed profile
        stealth_profile (str): Stealth profile
        expert_mode (bool): Enable expert mode
        scan_type (str): Scan type

    Returns:
        dict: Result with status, scan_id, and error message if any
    """
    try:
        from reNgine.services.repositories.scan_repository import ScanRepository

        # Validate domain exists
        try:
            domain = Domain.objects.get(id=domain_id)
        except Domain.DoesNotExist:
            return {"status": "error", "error": f"Domain with ID {domain_id} not found"}

        # Ensure lists are properly formatted
        if imported_subdomains is None:
            imported_subdomains = []
        if out_of_scope_subdomains is None:
            out_of_scope_subdomains = []
        if secator_config is None:
            secator_config = {}

        # Create scan object (always use engine_id=1 for Secator)
        scan_repo = ScanRepository()
        scan_history_id = scan_repo.create_scan(
            host_id=domain_id,
            engine_id=1,  # Fixed engine ID for all Secator scans
            initiated_by_id=user_id,
        )
        scan = ScanHistory.objects.get(pk=scan_history_id)

        # Start the scan directly with parameters
        result = initiate_secator_scan(
            scan_history_id=scan.id,
            domain_id=domain_id,
            execution_mode=execution_mode,
            workflow_id=workflow_id,
            task_ids=task_ids,
            secator_scan_type=secator_scan_type,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=out_of_scope_subdomains,
            url_filter=url_filter,
            scan_existing_elements=scan_existing_elements,
            secator_config=secator_config,
            speed_profile=speed_profile,
            stealth_profile=stealth_profile,
            expert_mode=expert_mode,
        )
        scan.save()

        # Check result
        if result.get("status") == "success":
            return {
                "status": "success",
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "domain_id": domain.id,
                "domain_name": domain.name,
                "secator_scan_id": None,
                "execution_mode": execution_mode,
                "message": f"Scan started successfully for {domain.name}",
            }
        else:
            return {"status": "error", "error": result.get("error", "Unknown error")}

    except Exception as e:
        logger.error(f"Error starting Secator scan: {str(e)}")
        return {"status": "error", "error": str(e)}


def initiate_secator_scan(
    scan_history_id,
    domain_id,
    execution_mode,
    workflow_id=None,
    task_ids=None,
    secator_scan_type=None,
    imported_subdomains=[],
    out_of_scope_subdomains=[],
    initiated_by_id=None,
    url_filter="",
    scan_existing_elements=False,
    # Secator parameters
    secator_config=None,
    speed_profile=None,
    stealth_profile=None,
    expert_mode=False,
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
        initiated_by (int): User ID initiating the scan.
        scan_existing_elements (bool): Whether to scan existing hostnames and IPs in the target. Default: False.
        secator_config (dict): Secator configuration parameters. Default: None.
        speed_profile (str): Speed profile (jaguar, rabbit, turtle). Default: None.
        stealth_profile (str): Stealth profile (ninja, chameleon, mouse). Default: None.
        expert_mode (bool): Enable expert mode. Default: False.
    """
    try:
        from reNgine.services.scan.scan_orchestrator import ScanOrchestrator

        domain = Domain.objects.get(id=domain_id)
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.is_legacy_scan = False
        scan_history.save()

        # Build enriched targets list
        targets = _build_enriched_targets(
            domain=domain,
            imported_subdomains=imported_subdomains or [],
            out_of_scope_subdomains=out_of_scope_subdomains or [],
            url_filter=url_filter,
            scan_existing_elements=scan_existing_elements,
        )

        # Create domain-specific results directory
        import os

        from reNgine.settings import SECATOR_RESULTS

        domain_results_dir = os.path.join(SECATOR_RESULTS, domain.name)
        os.makedirs(domain_results_dir, exist_ok=True)

        logger.info(f"Built targets list: {len(targets)} targets (domain + imported + existing)")

        # Validate execution mode parameters
        if execution_mode == "workflow" and not workflow_id:
            raise ValueError("workflow_id required for workflow mode")
        elif execution_mode == "tasks" and not task_ids:
            raise ValueError("task_ids required for tasks mode")
        elif execution_mode == "scan" and not secator_scan_type:
            raise ValueError("secator_scan_type required for scan mode")
        elif execution_mode not in ["workflow", "tasks", "scan"]:
            raise ValueError(f"Invalid execution_mode: {execution_mode}")

        # Build configuration from secator_config and profiles
        config = secator_config or {}
        profiles = {}

        # Apply speed profile
        if speed_profile:
            profiles["speed"] = speed_profile
            logger.info(f"Applied speed profile: {speed_profile}")

        # Apply stealth profile
        if stealth_profile:
            profiles["stealth"] = stealth_profile
            logger.info(f"Applied stealth profile: {stealth_profile}")

        # Apply expert mode settings
        if expert_mode:
            config["expert_mode"] = True
            logger.info("Expert mode enabled")

        # Set execution mode and configuration based on parameters
        if execution_mode == "workflow":
            # Get workflow alias/name from database
            from scanEngine.models import SecatorWorkflow

            try:
                workflow = SecatorWorkflow.objects.get(id=workflow_id)
                config["workflow_name"] = workflow.name
            except SecatorWorkflow.DoesNotExist:
                raise ValueError(f"SecatorWorkflow with ID {workflow_id} not found")
        elif execution_mode == "tasks":
            # Get task types from database
            from scanEngine.models import SecatorTask

            tasks = SecatorTask.objects.filter(id__in=task_ids)
            if len(tasks) != len(task_ids):
                raise ValueError("Invalid task IDs")
            config["tasks"] = [task.task_type for task in tasks]
        elif execution_mode == "scan":
            config["scan_type"] = secator_scan_type

        # Add reNgine context to config for hooks
        config["rengine_context"] = {
            "imported_subdomains": imported_subdomains or [],
            "out_of_scope_subdomains": out_of_scope_subdomains or [],
            "url_filter": url_filter,
            "scan_existing_elements": scan_existing_elements,
            "initiated_by_id": initiated_by_id,
        }

        # Add output directory to config
        config["output_dir"] = domain_results_dir

        # Call ScanOrchestrator directly
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

    except Exception as e:
        logger.error(f"Error initiating Secator scan: {e}")
        return {"status": "error", "error": str(e)}


def _build_enriched_targets(
    domain,
    imported_subdomains=None,
    out_of_scope_subdomains=None,
    url_filter="",
    scan_existing_elements=False,
):
    """Build enriched targets list for Secator scan.

    Args:
        domain: Domain object
        imported_subdomains: List of imported subdomains
        out_of_scope_subdomains: List of out-of-scope subdomains to exclude
        url_filter: URL filter to append to targets
        scan_existing_elements: Whether to include existing subdomains

    Returns:
        List of target strings for Secator
    """
    if imported_subdomains is None:
        imported_subdomains = []
    if out_of_scope_subdomains is None:
        out_of_scope_subdomains = []

    # Start with main domain
    targets = [domain.name]
    logger.info(f"Added main domain to targets: {domain.name}")

    # Add imported subdomains
    if imported_subdomains:
        logger.info(f"Adding {len(imported_subdomains)} imported subdomains to targets")
        for subdomain in imported_subdomains:
            if subdomain and subdomain.strip():
                clean_subdomain = subdomain.strip().lower()
                # Validate that it's a subdomain of the main domain
                if clean_subdomain.endswith(f".{domain.name}") or clean_subdomain == domain.name:
                    targets.append(clean_subdomain)
                    logger.debug(f"Added imported subdomain: {clean_subdomain}")
                else:
                    logger.warning(
                        f"Skipping invalid imported subdomain: {clean_subdomain} (not a subdomain of {domain.name})"
                    )

    # Add existing subdomains if requested
    if scan_existing_elements:
        existing_subdomains = Subdomain.objects.filter(target_domain=domain).values_list("name", flat=True).distinct()

        logger.info(f"Adding {len(existing_subdomains)} existing subdomains to targets")
        for subdomain in existing_subdomains:
            if subdomain and subdomain not in targets:
                targets.append(subdomain)
                logger.debug(f"Added existing subdomain: {subdomain}")

    # Remove out-of-scope subdomains
    if out_of_scope_subdomains:
        out_of_scope_clean = [s.strip().lower() for s in out_of_scope_subdomains if s and s.strip()]
        original_count = len(targets)
        targets = [t for t in targets if t not in out_of_scope_clean]
        removed_count = original_count - len(targets)
        if removed_count > 0:
            logger.info(f"Removed {removed_count} out-of-scope subdomains from targets")

    # Apply URL filter if specified
    if url_filter and url_filter.strip():
        url_filter_clean = url_filter.strip()
        # Ensure URL filter starts with /
        if not url_filter_clean.startswith("/"):
            url_filter_clean = f"/{url_filter_clean}"

        logger.info(f"Applying URL filter: {url_filter_clean}")
        targets = [f"{target}{url_filter_clean}" for target in targets]
        logger.info(f"Applied URL filter to {len(targets)} targets")

    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)

    logger.info(f"Final targets list: {len(unique_targets)} unique targets")
    return unique_targets
