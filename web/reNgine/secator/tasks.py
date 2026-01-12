from celery.utils.log import get_task_logger

from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


logger = get_task_logger(__name__)


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
    general_profile=None,
    network_profile=None,
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
        speed_profile (str): Speed profile (aggressive, insane, polite, paranoid). Default: None.
        stealth_profile (str): Evasion profile (sneaky, stealth, tor). Default: None.
        general_profile (str): General profile (active, passive, full). Default: None.
        network_profile (str): Network profile (all_ports, http_headless, http_record). Default: None.
        expert_mode (bool): Enable expert mode. Default: False.
    """
    try:
        from reNgine.secator.orchestrator import ScanOrchestrator

        domain = Domain.objects.get(id=domain_id)
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.is_legacy_scan = False
        scan_history.save()

        # Build enriched targets list
        targets = build_enriched_targets(
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

        # Apply general profile
        if general_profile:
            profiles["general"] = general_profile
            logger.info(f"Applied general profile: {general_profile}")

        # Apply network profile
        if network_profile:
            profiles["network"] = network_profile
            logger.info(f"Applied network profile: {network_profile}")

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
            "expert_mode": expert_mode,
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


def build_enriched_targets(
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
