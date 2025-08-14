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
    CELERY_TASK_STATUS_MAP
)
from reNgine.settings import (
    RENGINE_RESULTS,
)
from reNgine.tasks.notification import send_scan_notif
from reNgine.tasks.reporting import report
from reNgine.utilities.path import SafePath, get_scan_results_dir, get_subscan_results_dir
from reNgine.utilities.database import create_scan_object, save_imported_subdomains, save_subdomain, create_default_endpoint_for_subdomain
from reNgine.utilities.data import is_iterable
from scanEngine.models import EngineType
from startScan.models import ScanHistory, SubScan, Subdomain
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
    # Get all available tasks dynamically from the tasks module
    from reNgine.tasks import get_scan_tasks

    # Get all tasks
    available_tasks = get_scan_tasks()

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
        # Fix for issue #1519: Use domain ID instead of domain name to avoid
        # database field length limits with long domain names
        try:
            scan.results_dir = get_scan_results_dir(RENGINE_RESULTS, domain.id, scan.id)
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

        # Create default endpoint for the TLD subdomain
        create_default_endpoint_for_subdomain(subdomain, ctx)

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

        # Phase 1: Initial discovery - Use chord to wait for all tasks
        from celery import group, chord
        initial_tasks = []

        if 'subdomain_discovery' in engine.tasks and 'subdomain_discovery' in available_tasks:
            initial_tasks.append(available_tasks['subdomain_discovery'].si(ctx=ctx, description='Subdomain discovery'))
        if 'osint' in engine.tasks and 'osint' in available_tasks:
            initial_tasks.append(available_tasks['osint'].si(ctx=ctx, description='OS Intelligence'))

        if initial_tasks:
            # Create a chord: run initial_tasks in parallel, then execute pre_crawl when all are done
            if 'pre_crawl' in available_tasks:
                initial_chord = chord(
                    initial_tasks,
                    available_tasks['pre_crawl'].si(ctx=ctx, description='Pre-crawl endpoints')
                )
                workflow_tasks.append(initial_chord)
            else:
                # If no pre_crawl, just use group
                workflow_tasks.append(group(initial_tasks))
        elif 'pre_crawl' in available_tasks:
            # Only pre_crawl, no initial tasks
            workflow_tasks.append(available_tasks['pre_crawl'].si(ctx=ctx, description='Pre-crawl endpoints'))

        # Phase 2: Port scan (if enabled)
        reconnaissance_tasks = []
        if 'port_scan' in engine.tasks and 'port_scan' in available_tasks:
            reconnaissance_tasks.append('port_scan')
            workflow_tasks.append(available_tasks['port_scan'].si(ctx=ctx, description='Port scan'))

        # Phase 3: Fetch URLs (if enabled)
        if 'fetch_url' in engine.tasks and 'fetch_url' in available_tasks:
            reconnaissance_tasks.append('fetch_url')
            workflow_tasks.append(available_tasks['fetch_url'].si(ctx=ctx, description='Fetch URLs'))

        if reconnaissance_tasks and 'intermediate_crawl' in available_tasks:
            workflow_tasks.append(available_tasks['intermediate_crawl'].si(ctx=ctx, description='Intermediate crawl'))

        # Phase 4: Final tasks
        final_tasks = []
        if 'dir_file_fuzz' in engine.tasks and 'dir_file_fuzz' in available_tasks:
            final_tasks.append(available_tasks['dir_file_fuzz'].si(ctx=ctx, description='Directory & file fuzzing'))
        if 'vulnerability_scan' in engine.tasks and 'vulnerability_scan' in available_tasks:
            final_tasks.append(available_tasks['vulnerability_scan'].si(ctx=ctx, description='Vulnerability scan'))
        if 'screenshot' in engine.tasks and 'screenshot' in available_tasks:
            final_tasks.append(available_tasks['screenshot'].si(ctx=ctx, description='Screenshot'))
        if 'waf_detection' in engine.tasks and 'waf_detection' in available_tasks:
            final_tasks.append(available_tasks['waf_detection'].si(ctx=ctx, description='WAF detection'))

        if final_tasks:
            workflow_tasks.append(group(final_tasks))

        # Add post_crawl after all final tasks (including vulnerability scans) are completed
        if 'post_crawl' in available_tasks:
            workflow_tasks.append(available_tasks['post_crawl'].si(ctx=ctx, description='Post-crawl verification'))

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
        subdomain_id,
        engine_id=None,
        scan_type=None,
        results_dir=RENGINE_RESULTS,
        url_filter=''):
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
        # Fix for issue #1519: Use domain ID for subscan paths too
        try:
            results_dir = get_subscan_results_dir(RENGINE_RESULTS, domain.id, subscan.id)
        except (ValueError, OSError) as e:
            logger.error(f"Failed to create results directory: {str(e)}")
            subscan.scan_status = FAILED_TASK
            subscan.error_message = "Failed to create results directory, scan failed"
            subscan.save()
            return {
                'success': False,
                'error': subscan.error_message
            }

        # Get task method from available tasks
        method = available_tasks.get(scan_type)
        if not method:
            logger.warning(f'Task {scan_type} is not supported by reNgine-ng. Available tasks: {list(available_tasks.keys())}')
            subscan.status = FAILED_TASK
            subscan.error_message = f"Unsupported task type: {scan_type}"
            subscan.save()
            return {
                'success': False,
                'error': f'Task {scan_type} is not supported by reNgine-ng'
            }

        # Add task to scan history
        if scan_type not in scan.tasks:
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