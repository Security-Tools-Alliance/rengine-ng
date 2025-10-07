import json
import uuid

from celery import chain
from celery.utils.log import get_task_logger
from django.utils import timezone
import yaml

from reNgine.celery import app
from reNgine.definitions import (
    CELERY_TASK_STATUS_MAP,
    FAILED_TASK,
    GF_PATTERNS,
    LIVE_SCAN,
    RUNNING_TASK,
    SCHEDULED_SCAN,
)
from reNgine.settings import (
    RENGINE_RESULTS,
)
from reNgine.tasks.notification import send_scan_notif
from reNgine.tasks.reporting import report
from reNgine.utilities.data import is_iterable
from reNgine.utilities.database import (
    create_default_endpoint_for_subdomain,
    create_scan_object,
    save_imported_subdomains,
    validate_and_save_subdomain,
)
from reNgine.utilities.misc import determine_target_type
from reNgine.utilities.path import SafePath
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, SubScan
from targetApp.models import Domain


logger = get_task_logger(__name__)


@app.task(name="initiate_scan", bind=False, queue="orchestrator_queue")
def initiate_scan(
    scan_history_id,
    domain_id,
    engine_id=None,
    scan_type=LIVE_SCAN,
    results_dir=RENGINE_RESULTS,
    imported_subdomains=[],
    out_of_scope_subdomains=[],
    initiated_by_id=None,
    url_filter="",
    scan_existing_elements=False,
):
    """Initiate a new scan.

    Args:
        scan_history_id (int): ScanHistory id.
        domain_id (int): Domain id.
        engine_id (int): Engine ID.
        scan_type (int): Scan type (periodic, live).
        results_dir (str): Results directory.
        imported_subdomains (list): Imported subdomains.
        out_of_scope_subdomains (list): Out-of-scope subdomains.
        url_filter (str): URL path. Default: ''.
        initiated_by (int): User ID initiating the scan.
        scan_existing_elements (bool): Whether to scan existing hostnames and IPs in the target. Default: False.
    """
    # Get all available tasks dynamically from the tasks module
    from reNgine.tasks import get_scan_tasks

    # Get all tasks
    available_tasks = get_scan_tasks()

    scan = None
    try:
        # Get scan engine
        engine_id = engine_id or scan.scan_type.id  # scan history engine_id
        logger.info(f"Engine ID: {engine_id}")
        engine = EngineType.objects.get(pk=engine_id)

        # Get YAML config
        config = yaml.safe_load(engine.yaml_configuration)
        gf_patterns = config.get(GF_PATTERNS, [])

        # Get domain and set last_scan_date
        domain = Domain.objects.get(pk=domain_id)
        domain.last_scan_date = timezone.now()
        domain.save()

        # Determine target type and adapt tasks accordingly
        target_type = determine_target_type(domain.name)
        logger.info(f"Target type detected: {target_type} for {domain.name}")

        if target_type == "ip_address":
            # Filter out irrelevant tasks for an IP
            allowed_tasks = [
                "port_scan",
                "fetch_url",
                "dir_file_fuzz",
                "vulnerability_scan",
                "screenshot",
                "waf_detection",
            ]
            engine.tasks = [task for task in engine.tasks if task in allowed_tasks]
            logger.info(f"IP scan detected - Limited available tasks to: {engine.tasks}")
        elif target_type == "ip_range":
            # For IP ranges, focus on network scanning tasks
            allowed_tasks = [
                "port_scan",
                "vulnerability_scan",
            ]
            engine.tasks = [task for task in engine.tasks if task in allowed_tasks]
            logger.info(f"IP range scan detected - Limited available tasks to: {engine.tasks}")
        elif target_type == "custom_text":
            # For custom text targets, use all available tasks
            logger.info(f"Custom text target detected - Using all available tasks: {engine.tasks}")
        else:  # domain or subdomain
            # Standard domain/subdomain scanning
            logger.info(f"Domain/Subdomain target detected - Using all available tasks: {engine.tasks}")

        logger.warning(f"Initiating scan for {target_type} target '{domain.name}' on celery")

        # for live scan scan history id is passed as scan_history_id
        # and no need to create scan_history object

        if scan_type == SCHEDULED_SCAN:  # scheduled
            # we need to create scan_history object for each scheduled scan
            scan_history_id = create_scan_object(
                host_id=domain_id,
                engine_id=engine_id,
                initiated_by_id=initiated_by_id,
            )
        scan = ScanHistory.objects.get(pk=scan_history_id)
        scan.scan_status = RUNNING_TASK

        scan.scan_type = engine
        scan.celery_ids = [initiate_scan.request.id]
        scan.domain = domain
        scan.start_scan_date = timezone.now()
        scan.tasks = engine.tasks

        # Create results directory
        try:
            uuid_scan = uuid.uuid1()
            scan.results_dir = SafePath.create_safe_path(
                base_dir=RENGINE_RESULTS, components=[domain.name, "scans", str(uuid_scan)]
            )
        except (ValueError, OSError) as e:
            logger.error(f"Failed to create results directory: {str(e)}")
            scan.scan_status = FAILED_TASK
            scan.error_message = "Failed to create results directory, scan failed"
            scan.save()
            return {"success": False, "error": scan.error_message}

        add_gf_patterns = gf_patterns and "fetch_url" in engine.tasks
        if add_gf_patterns and is_iterable(gf_patterns):
            scan.used_gf_patterns = ",".join(gf_patterns)
        scan.save()

        # Build task context
        ctx = {
            "scan_history_id": scan_history_id,
            "engine_id": engine_id,
            "domain_id": domain.id,
            "results_dir": scan.results_dir,
            "url_filter": url_filter,
            "yaml_configuration": config,
            "out_of_scope_subdomains": out_of_scope_subdomains,
        }
        ctx_str = json.dumps(ctx, indent=2)

        # Send start notif
        logger.warning(f"Starting scan {scan_history_id} with context:\n{ctx_str}")
        send_scan_notif.delay(
            scan_history_id, subscan_id=None, engine_id=engine_id, status=CELERY_TASK_STATUS_MAP[scan.scan_status]
        )

        # Save imported subdomains in DB
        save_imported_subdomains(imported_subdomains, ctx=ctx)

        # Create initial subdomain in DB based on target type
        subdomain_name = domain.name
        subdomain = None

        # Create subdomain and endpoints based on target type
        if target_type in ["domain", "subdomain"]:
            # For domains/subdomains, create subdomain and default HTTP/HTTPS endpoints
            subdomain, _ = validate_and_save_subdomain(subdomain_name, ctx=ctx)
            if subdomain is not None:
                create_default_endpoint_for_subdomain(subdomain, ctx)
                logger.info(f"Created default endpoints for domain/subdomain: {subdomain_name}")
            else:
                logger.warning(f"Failed to create subdomain for domain/subdomain: {subdomain_name}")
        elif target_type == "ip_address":
            # For IP addresses, create subdomain and default endpoints
            subdomain, _ = validate_and_save_subdomain(subdomain_name, ctx=ctx)
            if subdomain is not None:
                create_default_endpoint_for_subdomain(subdomain, ctx)
                logger.info(f"Created default endpoints for IP address: {subdomain_name}")
            else:
                logger.warning(f"Failed to create subdomain for IP address: {subdomain_name}")
        elif target_type == "ip_range":
            # For IP ranges, we'll handle this differently - no subdomain creation
            logger.info(f"IP range target detected: {subdomain_name} - No subdomain created")
        elif target_type == "custom_text":
            # For custom text, don't create subdomain as it's not a valid domain
            logger.info(f"Custom text target detected: {subdomain_name} - No subdomain created (custom text)")
        else:
            # Fallback - try to create subdomain and endpoints
            subdomain, _ = validate_and_save_subdomain(subdomain_name, ctx=ctx)
            if subdomain is not None:
                create_default_endpoint_for_subdomain(subdomain, ctx)
                logger.info(f"Created default endpoints for unknown target type: {subdomain_name}")
            else:
                logger.warning(f"Failed to create subdomain for unknown target type: {subdomain_name}")

        # Handle scanning of existing elements if requested
        if scan_existing_elements:
            logger.info(f"Scan existing elements enabled for {target_type} target: {domain.name}")

            # Get existing hostnames and IPs for this domain
            existing_subdomains = Subdomain.objects.filter(target_domain=domain)
            existing_ips = IpAddress.objects.filter(ip_addresses__target_domain=domain)

            logger.info(
                f"Found {existing_subdomains.count()} existing hostnames and {existing_ips.count()} existing IPs"
            )

            # Track processed subdomains to avoid duplicates
            processed_subdomains = set()

            # Create subdomains for existing hostnames
            for existing_subdomain in existing_subdomains:
                if existing_subdomain.name != domain.name:  # Skip the main target
                    # Check if we've already processed this subdomain
                    if existing_subdomain.name in processed_subdomains:
                        logger.info(f"Skipping duplicate subdomain: {existing_subdomain.name}")
                        continue

                    processed_subdomains.add(existing_subdomain.name)
                    subdomain_obj, _ = validate_and_save_subdomain(existing_subdomain.name, ctx=ctx)

                    if subdomain_obj is not None:
                        create_default_endpoint_for_subdomain(subdomain_obj, ctx)
                        logger.info(f"Added existing hostname to scan: {existing_subdomain.name}")
                    else:
                        logger.warning(f"Failed to create subdomain for existing hostname: {existing_subdomain.name}")

            # Create subdomains for existing IPs
            for existing_ip in existing_ips:
                if existing_ip.address != domain.name:  # Skip if IP is the main target
                    # Check if we've already processed this IP
                    if existing_ip.address in processed_subdomains:
                        logger.info(f"Skipping duplicate IP: {existing_ip.address}")
                        continue

                    processed_subdomains.add(existing_ip.address)
                    subdomain_obj, _ = validate_and_save_subdomain(existing_ip.address, ctx=ctx)

                    if subdomain_obj is not None:
                        # Create endpoints for IP addresses
                        create_default_endpoint_for_subdomain(subdomain_obj, ctx)
                        logger.info(f"Added existing IP to scan: {existing_ip.address}")
                    else:
                        logger.warning(f"Failed to create subdomain for existing IP: {existing_ip.address}")
        else:
            logger.info(f"Scan existing elements disabled for {target_type} target: {domain.name}")

        # Create initial host
        host = domain.name
        logger.info(f"Creating scan for {host} - web service detection will be handled by port_scan or pre_crawl")

        # Build new workflow structure based on enabled tasks:
        # 1. Initial discovery (subdomain_discovery, osint)
        # 2. pre_crawl (crawl existing subdomains)
        # 3. port_scan (if enabled)
        # 4. fetch_url (discover new endpoints)
        # 5. intermediate_crawl (crawl new endpoints)
        # 6. Final tasks (dir_file_fuzz, vulnerability_scan, screenshot, waf_detection)
        # 7. post_crawl (final endpoint verification)

        workflow_tasks = []

        # Phase 1: Initial discovery - Use chord to wait for all tasks
        from celery import chord, group

        initial_tasks = []

        if "subdomain_discovery" in engine.tasks and "subdomain_discovery" in available_tasks:
            initial_tasks.append(available_tasks["subdomain_discovery"].si(ctx=ctx, description="Subdomain discovery"))
        if "osint" in engine.tasks and "osint" in available_tasks:
            initial_tasks.append(available_tasks["osint"].si(ctx=ctx, description="OS Intelligence"))

        if initial_tasks:
            # Create a chord: run initial_tasks in parallel, then execute pre_crawl when all are done
            if "pre_crawl" in available_tasks:
                initial_chord = chord(
                    initial_tasks, available_tasks["pre_crawl"].si(ctx=ctx, description="Pre-crawl endpoints")
                )
                workflow_tasks.append(initial_chord)
            else:
                # If no pre_crawl, just use group
                workflow_tasks.append(group(initial_tasks))
        elif "pre_crawl" in available_tasks:
            # Only pre_crawl, no initial tasks
            workflow_tasks.append(available_tasks["pre_crawl"].si(ctx=ctx, description="Pre-crawl endpoints"))

        # Phase 2: Port scan (if enabled)
        reconnaissance_tasks = []
        if "port_scan" in engine.tasks and "port_scan" in available_tasks:
            reconnaissance_tasks.append("port_scan")
            workflow_tasks.append(available_tasks["port_scan"].si(ctx=ctx, description="Port scan"))

        # Phase 3: Fetch URLs (if enabled)
        if "fetch_url" in engine.tasks and "fetch_url" in available_tasks:
            reconnaissance_tasks.append("fetch_url")
            workflow_tasks.append(available_tasks["fetch_url"].si(ctx=ctx, description="Fetch URLs"))

        if reconnaissance_tasks and "intermediate_crawl" in available_tasks:
            workflow_tasks.append(available_tasks["intermediate_crawl"].si(ctx=ctx, description="Intermediate crawl"))

        # Phase 4: Final tasks
        final_tasks = []
        if "dir_file_fuzz" in engine.tasks and "dir_file_fuzz" in available_tasks:
            final_tasks.append(available_tasks["dir_file_fuzz"].si(ctx=ctx, description="Directory & file fuzzing"))
        if "vulnerability_scan" in engine.tasks and "vulnerability_scan" in available_tasks:
            final_tasks.append(available_tasks["vulnerability_scan"].si(ctx=ctx, description="Vulnerability scan"))
        if "screenshot" in engine.tasks and "screenshot" in available_tasks:
            final_tasks.append(available_tasks["screenshot"].si(ctx=ctx, description="Screenshot"))
        if "waf_detection" in engine.tasks and "waf_detection" in available_tasks:
            final_tasks.append(available_tasks["waf_detection"].si(ctx=ctx, description="WAF detection"))

        if final_tasks:
            workflow_tasks.append(group(final_tasks))

        # Add post_crawl after all final tasks (including vulnerability scans) are completed
        if "post_crawl" in available_tasks:
            workflow_tasks.append(available_tasks["post_crawl"].si(ctx=ctx, description="Post-crawl verification"))

        # Create workflow chain
        workflow = chain(*workflow_tasks) if workflow_tasks else None

        if not workflow:
            logger.error("No tasks to execute in workflow")
            scan.scan_status = FAILED_TASK
            scan.error_message = "No tasks configured for this engine"
            scan.save()
            return {"success": False, "error": scan.error_message}

        # Build callback
        callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

        # Run Celery chord
        logger.info(f"Running Celery workflow with {len(workflow.tasks) + 1} tasks")
        task = chain(workflow, callback).on_error(callback).delay()
        scan.celery_ids.append(task.id)
        scan.save()

        return {"success": True, "task_id": task.id}

    except Exception as e:
        logger.exception(e)
        if scan:
            scan.scan_status = FAILED_TASK
            scan.error_message = str(e)
            scan.save()
        return {"success": False, "error": str(e)}


@app.task(name="initiate_subscan", bind=False, queue="orchestrator_queue")
def initiate_subscan(subdomain_id, engine_id=None, scan_type=None, results_dir=RENGINE_RESULTS, url_filter=""):
    """Initiate a new subscan.

    Args:
        subdomain_id (int): Subdomain id.
        engine_id (int): Engine ID.
        scan_type (int): Scan type (port_scan, subdomain_discovery, vulnerability_scan...).
        results_dir (str): Results directory.
        url_filter (str): URL path. Default: ''
    """
    from reNgine.tasks import get_scan_tasks
    from reNgine.tasks.reporting import report

    # Get all available tasks
    available_tasks = get_scan_tasks()

    subscan = None
    try:
        # Get Subdomain, Domain and ScanHistory
        subdomain = Subdomain.objects.get(pk=subdomain_id)
        scan = ScanHistory.objects.get(pk=subdomain.scan_history.id)
        domain = Domain.objects.get(pk=subdomain.target_domain.id)

        logger.info(f"Initiating subscan for subdomain {subdomain.name} on celery")

        # Get EngineType
        engine_id = engine_id or scan.scan_type.id
        engine = EngineType.objects.get(pk=engine_id)

        # Get YAML config
        config = yaml.safe_load(engine.yaml_configuration)
        config_subscan = config.get(scan_type)

        # Create scan activity of SubScan Model
        subscan = SubScan(
            start_scan_date=timezone.now(),
            celery_ids=[initiate_subscan.request.id],
            scan_history=scan,
            subdomain=subdomain,
            type=scan_type,
            status=RUNNING_TASK,
            engine=engine,
        )
        subscan.save()

        # Create results directory
        try:
            uuid_scan = uuid.uuid1()
            results_dir = SafePath.create_safe_path(
                base_dir=RENGINE_RESULTS, components=[domain.name, "subscans", str(uuid_scan)]
            )
        except (ValueError, OSError) as e:
            logger.error(f"Failed to create results directory: {str(e)}")
            subscan.scan_status = FAILED_TASK
            subscan.error_message = "Failed to create results directory, scan failed"
            subscan.save()
            return {"success": False, "error": subscan.error_message}

        # Get task method from available tasks
        method = available_tasks.get(scan_type)
        if not method:
            logger.warning(
                f"Task {scan_type} is not supported by reNgine-ng. Available tasks: {list(available_tasks.keys())}"
            )
            subscan.status = FAILED_TASK
            subscan.error_message = f"Unsupported task type: {scan_type}"
            subscan.save()
            return {"success": False, "error": f"Task {scan_type} is not supported by reNgine-ng"}

        # Add task to scan history
        if scan_type not in scan.tasks:
            scan.tasks.append(scan_type)
            scan.save()

        # Send start notif
        send_scan_notif.delay(scan.id, subscan_id=subscan.id, engine_id=engine_id, status="RUNNING")

        # Build context
        ctx = {
            "scan_history_id": scan.id,
            "subscan_id": subscan.id,
            "engine_id": engine_id,
            "domain_id": domain.id,
            "subdomain_id": subdomain.id,
            "yaml_configuration": config,
            "yaml_configuration_subscan": config_subscan,
            "results_dir": results_dir,
            "url_filter": url_filter,
        }

        ctx_str = json.dumps(ctx, indent=2)
        logger.warning(f"Starting subscan {subscan.id} with context:\n{ctx_str}")

        # Build header + callback
        workflow = method.si(ctx=ctx)
        callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

        # Run Celery tasks
        task = chain(workflow, callback).on_error(callback).delay()
        subscan.celery_ids.append(task.id)
        subscan.save()

        return {"success": True, "task_id": task.id}
    except Exception as e:
        logger.exception(e)
        if subscan:
            subscan.scan_status = FAILED_TASK
            subscan.error_message = str(e)
            subscan.save()
        return {"success": False, "error": str(e)}
