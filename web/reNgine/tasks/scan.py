import json
import yaml
import uuid

from celery import chain
from django.utils import timezone

from reNgine.definitions import (
    RUNNING_TASK,
    FAILED_TASK,
    LIVE_SCAN,
)
from reNgine.settings import RENGINE_RESULTS
from reNgine.celery import app
from reNgine.utils.logger import Logger
from reNgine.utils.formatters import SafePath
from reNgine.utils.http import get_http_crawl_value
from scanEngine.models import EngineType
from startScan.models import (
    ScanHistory,
    Subdomain,
    SubScan,
)
from targetApp.models import Domain
from reNgine.tasks.notification import send_scan_notif
from reNgine.tasks.reporting import report
from reNgine.tasks.http import http_crawl
from reNgine.utils.scan_helpers import (
    get_scan_engine,
    handle_ip_scan,
    initialize_scan_history,
    validate_scan_inputs,
    build_scan_workflow,
)
from django.core.exceptions import ValidationError

"""
Celery tasks.
"""

logger = Logger(is_task_logger=True)  # Use task logger for Celery tasks


@app.task(name='initiate_scan', bind=True, queue='main_scan_queue')
def initiate_scan(self, scan_history_id, domain_id, engine_id=None, scan_type=LIVE_SCAN,
                 results_dir=RENGINE_RESULTS, imported_subdomains=None,
                 out_of_scope_subdomains=None, initiated_by_id=None, url_filter=''):
    """Initiate a new scan workflow."""
    scan = None

    try:
        # Validate and initialize scan
        validate_scan_inputs(domain_id, engine_id, scan_type, scan_history_id)
        scan = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)

        # Setup scan configuration
        engine = get_scan_engine(engine_id, scan)
        engine = handle_ip_scan(domain, engine)

        # Initialize scan
        domain.last_scan_date = timezone.now()
        domain.save()

        scan, ctx = initialize_scan_history(
            scan=scan,
            domain=domain,
            engine=engine,
            scan_type=scan_type,
            initiated_by_id=initiated_by_id,
            results_dir=results_dir,
            celery_ids=[self.request.id],
            out_of_scope_subdomains=out_of_scope_subdomains,
            url_filter=url_filter
        )

        if not scan or not ctx:
            raise ValueError("Failed to initialize scan")

        # Send start notification
        ctx_str = json.dumps(ctx, indent=2)
        logger.warning(f'Starting scan {scan_history_id} with context:\n{ctx_str}')
        send_scan_notif.apply_async(
            kwargs={
                'scan_history_id': scan.id,
                'subscan_id': None,
                'engine_id': engine.id,
                'status': 'RUNNING'
            }
        )

        # Build and execute workflow
        workflow, task_ids = build_scan_workflow(domain, engine, ctx)
        task = workflow.apply_async()
        
        # Update scan with all task IDs
        scan.celery_ids.extend([self.request.id] + task_ids)
        scan.save()

        return {
            'success': True,
            'task_id': task.id,
            'scan_history_id': scan.id
        }

    except Exception as e:
        error_msg = str(e)
        logger.error(f"{'Validation/DB error' if isinstance(e, (ValidationError, ScanHistory.DoesNotExist, Domain.DoesNotExist)) else 'Unexpected error'}: {error_msg}")
        
        if scan:
            scan.scan_status = FAILED_TASK
            scan.error_message = error_msg
            scan.save()
            
        if isinstance(e, (ValidationError, ScanHistory.DoesNotExist, Domain.DoesNotExist)):
            return {'success': False, 'error': error_msg}
        else:
            raise self.retry(exc=e, countdown=60) from e

@app.task(name='initiate_subscan', bind=False, queue='subscan_queue')
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

    # if CELERY_REMOTE_DEBUG:
    #     debug()

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
        enable_http_crawl = get_http_crawl_value(engine, config_subscan)

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

        if enable_http_crawl:
            results = http_crawl(
                urls=[subdomain.http_url],
                ctx=ctx)
            if not results:
                subscan.scan_status = FAILED_TASK
                subscan.error_message = "Sorry, host does not seems to have any web service"
                subscan.save()
                return {
                    'success': False,
                    'error': subscan.error_message
                }

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
