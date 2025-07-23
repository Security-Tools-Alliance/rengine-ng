import json
import uuid
import validators
import yaml

from celery import chain
from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.celery import app
from reNgine.definitions import (
    GF_PATTERNS,
    LIVE_SCAN,
    SCHEDULED_SCAN,
    RUNNING_TASK,
    FAILED_TASK,
    SUCCESS_TASK,
    RUNNING_BACKGROUND,
    CELERY_TASK_STATUS_MAP
)
from reNgine.settings import (
    RENGINE_RESULTS,
)
from reNgine.tasks.notification import send_scan_notif
from reNgine.tasks.reporting import report
from reNgine.utilities import SafePath
from reNgine.common_func import create_scan_object, is_iterable, save_imported_subdomains, save_subdomain
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, SubScan
from targetApp.models import Domain

logger = get_task_logger(__name__)


@app.task(name='initiate_scan', bind=False, queue='orchestrator_queue')
def initiate_scan(
        scan_history_id,
        domain_id,
        engine_id=None,
        scan_type=LIVE_SCAN,
        results_dir=RENGINE_RESULTS,
        imported_subdomains=[],
        out_of_scope_subdomains=[],
        initiated_by_id=None,
        url_filter=''):
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
    """
    # Import all necessary modules
    from reNgine.tasks.subdomain import subdomain_discovery
    from reNgine.tasks.osint import osint
    from reNgine.tasks.http import pre_crawl, intermediate_crawl, post_crawl
    from reNgine.tasks.port_scan import port_scan
    from reNgine.tasks.url import fetch_url
    from reNgine.tasks.fuzzing import dir_file_fuzz
    from reNgine.tasks.vulnerability import vulnerability_scan
    from reNgine.tasks.screenshot import screenshot
    from reNgine.tasks.detect import waf_detection

    scan = None
    try:
        # Get scan engine
        engine_id = engine_id or scan.scan_type.id # scan history engine_id
        logger.info(f'Engine ID: {engine_id}')
        engine = EngineType.objects.get(pk=engine_id)

        # Get YAML config
        config = yaml.safe_load(engine.yaml_configuration)
        gf_patterns = config.get(GF_PATTERNS, [])

        # Get domain and set last_scan_date
        domain = Domain.objects.get(pk=domain_id)
        domain.last_scan_date = timezone.now()
        domain.save()

        if validators.ip_address.ipv4(
            domain.name
        ) or validators.ip_address.ipv6(domain.name):
            # Filter out irrelevant tasks for an IP
            allowed_tasks = ['port_scan', 'fetch_url', 'dir_file_fuzz', 'vulnerability_scan', 'screenshot', 'waf_detection']
            engine.tasks = [task for task in engine.tasks if task in allowed_tasks]
            logger.info(f'IP scan detected - Limited available tasks to: {engine.tasks}')

        logger.warning(f'Initiating scan for domain {domain.name} on celery')

        # for live scan scan history id is passed as scan_history_id 
        # and no need to create scan_history object

        if scan_type == SCHEDULED_SCAN: # scheduled
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
                base_dir=RENGINE_RESULTS,
                components=[domain.name, 'scans', str(uuid_scan)]
            )
        except (ValueError, OSError) as e:
            logger.error(f"Failed to create results directory: {str(e)}")
            scan.scan_status = FAILED_TASK
            scan.error_message = "Failed to create results directory, scan failed"
            scan.save()
            return {'success': False, 'error': scan.error_message}

        add_gf_patterns = gf_patterns and 'fetch_url' in engine.tasks
        if add_gf_patterns and is_iterable(gf_patterns):
            scan.used_gf_patterns = ','.join(gf_patterns)
        scan.save()

        # Build task context
        ctx = {
            'scan_history_id': scan_history_id,
            'engine_id': engine_id,
            'domain_id': domain.id,
            'results_dir': scan.results_dir,
            'url_filter': url_filter,
            'yaml_configuration': config,
            'out_of_scope_subdomains': out_of_scope_subdomains
        }
        ctx_str = json.dumps(ctx, indent=2)

        # Send start notif
        logger.warning(f'Starting scan {scan_history_id} with context:\n{ctx_str}')
        send_scan_notif.delay(
            scan_history_id,
            subscan_id=None,
            engine_id=engine_id,
            status=CELERY_TASK_STATUS_MAP[scan.scan_status])

        # Save imported subdomains in DB
        save_imported_subdomains(imported_subdomains, ctx=ctx)

        # Create initial subdomain in DB: make a copy of domain as a subdomain so
        # that other tasks using subdomains can use it.
        subdomain_name = domain.name
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

        # Create initial host - no more initial web service detection
        host = domain.name
        logger.info(f'Creating scan for {host} - web service detection will be handled by port_scan or pre_crawl')

        # Build new workflow structure based on enabled tasks:
        # 1. Initial discovery (subdomain_discovery, osint)
        # 2. pre_crawl (crawl existing subdomains)
        # 3. port_scan (if enabled)
        # 4. fetch_url (discover new endpoints)
        # 5. intermediate_crawl (crawl new endpoints)
        # 6. Final tasks (dir_file_fuzz, vulnerability_scan, screenshot, waf_detection)
        # 7. post_crawl (final endpoint verification)

        workflow_tasks = []

        # Phase 1: Initial discovery
        from celery import group
        initial_tasks = []
        if 'subdomain_discovery' in engine.tasks:
            initial_tasks.append(subdomain_discovery.si(ctx=ctx, description='Subdomain discovery'))
        if 'osint' in engine.tasks:
            initial_tasks.append(osint.si(ctx=ctx, description='OS Intelligence'))

        if initial_tasks:
            workflow_tasks.extend(
                (
                    group(initial_tasks),
                    pre_crawl.si(ctx=ctx, description='Pre-crawl endpoints'),
                )
            )
        # Phase 2: Port scan (if enabled)
        reconnaissance_tasks = []
        if 'port_scan' in engine.tasks:
            reconnaissance_tasks.append('port_scan')
            workflow_tasks.append(port_scan.si(ctx=ctx, description='Port scan'))

        # Phase 3: Fetch URLs (if enabled)
        if 'fetch_url' in engine.tasks:
            reconnaissance_tasks.append('fetch_url')
            workflow_tasks.append(fetch_url.si(ctx=ctx, description='Fetch URLs'))

        if reconnaissance_tasks:
            # Intermediate crawl of discovered endpoints
            workflow_tasks.append(intermediate_crawl.si(ctx=ctx, description='Intermediate crawl'))

        # Phase 4: Final tasks
        final_tasks = []
        if 'dir_file_fuzz' in engine.tasks:
            final_tasks.append(dir_file_fuzz.si(ctx=ctx, description='Directory & file fuzzing'))
        if 'vulnerability_scan' in engine.tasks:
            final_tasks.append(vulnerability_scan.si(ctx=ctx, description='Vulnerability scan'))
        if 'screenshot' in engine.tasks:
            final_tasks.append(screenshot.si(ctx=ctx, description='Screenshot'))
        if 'waf_detection' in engine.tasks:
            final_tasks.append(waf_detection.si(ctx=ctx, description='WAF detection'))

        if final_tasks:
            workflow_tasks.extend(
                (
                    group(final_tasks),
                    post_crawl.si(
                        ctx=ctx, description='Post-crawl verification'
                    ),
                )
            )
        # Create workflow chain
        workflow = chain(*workflow_tasks) if workflow_tasks else None

        if not workflow:
            logger.error('No tasks to execute in workflow')
            scan.scan_status = FAILED_TASK
            scan.error_message = "No tasks configured for this engine"
            scan.save()
            return {'success': False, 'error': scan.error_message}

        # Build callback
        callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

        # Run Celery chord
        logger.info(f'Running Celery workflow with {len(workflow.tasks) + 1} tasks')
        task = chain(workflow, callback).on_error(callback).delay()
        scan.celery_ids.append(task.id)
        scan.save()

        return {
            'success': True,
            'task_id': task.id
        }

    except Exception as e:
        logger.exception(e)
        if scan:
            scan.scan_status = FAILED_TASK
            scan.error_message = str(e)
            scan.save()
        return {
            'success': False,
            'error': str(e)
        }


@app.task(name='initiate_subscan', bind=False, queue='orchestrator_queue')
def initiate_subscan(
        scan_history_id,
        subdomain_id,
        engine_id=None,
        scan_type=None,
        results_dir=RENGINE_RESULTS,
        url_filter=''):
    """Initiate a new subscan.

    Args:
        scan_history_id (int): ScanHistory id.
        subdomain_id (int): Subdomain id.
        engine_id (int): Engine ID.
        scan_type (int): Scan type (port_scan, subdomain_discovery, vulnerability_scan...).
        results_dir (str): Results directory.
        url_filter (str): URL path. Default: ''
    """
    from reNgine.tasks.reporting import report

    subscan = None
    try:
        # Get Subdomain, Domain and ScanHistory
        from startScan.models import Subdomain
        subdomain = Subdomain.objects.get(pk=subdomain_id)
        scan = ScanHistory.objects.get(pk=subdomain.scan_history.id)
        domain = Domain.objects.get(pk=subdomain.target_domain.id)

        logger.info(f'Initiating subscan for subdomain {subdomain.name} on celery')

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
            engine=engine)
        subscan.save()

        # Create results directory
        try:
            uuid_scan = uuid.uuid1()
            results_dir = SafePath.create_safe_path(
                base_dir=RENGINE_RESULTS,
                components=[domain.name, 'subscans', str(uuid_scan)]
            )
        except (ValueError, OSError) as e:
            logger.error(f"Failed to create results directory: {str(e)}")
            subscan.scan_status = FAILED_TASK
            subscan.error_message = "Failed to create results directory, scan failed"
            subscan.save()
            return {
                'success': False,
                'error': subscan.error_message
            }

        # Run task
        method = globals().get(scan_type)
        if not method:
            logger.warning(f'Task {scan_type} is not supported by reNgine. Skipping')
            return
        scan.tasks.append(scan_type)
        scan.save()

        # Send start notif
        send_scan_notif.delay(
            scan.id,
            subscan_id=subscan.id,
            engine_id=engine_id,
            status='RUNNING')

        # Build context
        ctx = {
            'scan_history_id': scan.id,
            'subscan_id': subscan.id,
            'engine_id': engine_id,
            'domain_id': domain.id,
            'subdomain_id': subdomain.id,
            'yaml_configuration': config,
            'yaml_configuration_subscan': config_subscan,
            'results_dir': results_dir,
            'url_filter': url_filter
        }

        ctx_str = json.dumps(ctx, indent=2)
        logger.warning(f'Starting subscan {subscan.id} with context:\n{ctx_str}')

        # HTTP crawling is now handled by dedicated crawl tasks

        # Build header + callback
        workflow = method.si(ctx=ctx)
        callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

        # Run Celery tasks
        task = chain(workflow, callback).on_error(callback).delay()
        subscan.celery_ids.append(task.id)
        subscan.save()

        return {
            'success': True,
            'task_id': task.id
        }
    except Exception as e:
        logger.exception(e)
        if subscan:
            subscan.scan_status = FAILED_TASK
            subscan.error_message = str(e)
            subscan.save()
        return {
            'success': False,
            'error': str(e)
        }    


@app.task(name='check_and_finalize_scan', bind=False, queue='orchestrator_queue')
def check_and_finalize_scan(scan_id, subscan_id=None):
    """Check if async tasks are done and finalize scan status.
    
    Args:
        scan_id (int): Scan history ID
        subscan_id (int, optional): SubScan ID
    """
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if not scan:
        return

    # Check if we're dealing with a subscan
    subscan = None
    if subscan_id:
        subscan = SubScan.objects.filter(pk=subscan_id).first()
        if not subscan:
            logger.warning(f'SubScan {subscan_id} not found, skipping finalization')
            return

        # Check if subscan status is not RUNNING_BACKGROUND anymore
        if subscan.status != RUNNING_BACKGROUND:
            logger.info(f'SubScan {subscan_id} status is no longer RUNNING_BACKGROUND, skipping finalization')
            return
    elif scan.scan_status != RUNNING_BACKGROUND:
        logger.info(f'Scan {scan_id} status is no longer RUNNING_BACKGROUND, skipping finalization')
        return

    # Check for recent async task activities (simplified approach)
    recent_activities = ScanActivity.objects.filter(
        scan_of=scan,
        time__gte=timezone.now() - timezone.timedelta(minutes=10),  # Active in last 10 minutes
        name__in=['http_crawl', 'nuclei_scan', 'vulnerability_scan', 'dalfox_xss_scan', 'crlfuzz_scan']
    ).filter(status=RUNNING_TASK)

    # If checking a subscan, filter activities by subscan's celery_ids
    if subscan_id and subscan:
        recent_activities = recent_activities.filter(celery_id__in=subscan.celery_ids)

    if recent_activities.exists():
        # Still have running async tasks, check again later
        running_count = recent_activities.count()
        scan_or_subscan = f'SubScan {subscan_id}' if subscan_id else f'Scan {scan_id}'
        logger.info(f'{scan_or_subscan}: {running_count} async tasks still running, will check again in 2 minutes')
        check_and_finalize_scan.apply_async(args=[scan_id, subscan_id], countdown=120)
        return

    # No more running async tasks, finalize the scan
    scan_or_subscan = f'SubScan {subscan_id}' if subscan_id else f'Scan {scan_id}'
    logger.info(f'{scan_or_subscan}: All async tasks completed, finalizing status')

    # Check for failures in all tasks
    all_tasks = ScanActivity.objects.filter(scan_of=scan)
    if subscan_id and subscan:
        all_tasks = all_tasks.filter(celery_id__in=subscan.celery_ids)

    failed_tasks = all_tasks.filter(status=FAILED_TASK)
    failed_count = failed_tasks.count()
    final_status = SUCCESS_TASK if failed_count == 0 else FAILED_TASK
    final_status_h = 'SUCCESS' if failed_count == 0 else 'FAILED'

    # Update scan/subscan status
    if subscan_id and subscan:
        subscan.status = final_status
        subscan.stop_scan_date = timezone.now()
        subscan.save()
    else:
        scan.scan_status = final_status
        scan.stop_scan_date = timezone.now()
        scan.save()

    # Send final notification
    send_scan_notif.delay(
        scan_history_id=scan_id,
        subscan_id=subscan_id,
        engine_id=scan.scan_type.id if scan.scan_type else None,
        status=final_status_h
    )

    logger.info(f'{scan_or_subscan} finalized with status: {final_status_h}') 