import json
import yaml
import uuid

from celery import chain
from django.core.exceptions import ValidationError
from django.utils import timezone

from reNgine.definitions import RUNNING_TASK, FAILED_TASK, LIVE_SCAN
from reNgine.settings import RENGINE_RESULTS
from reNgine.celery import app
from reNgine.utils.debug import debug
from reNgine.utils.formatters import SafePath, fmt_traceback
from reNgine.utils.logger import default_logger as logger
from reNgine.utils.scan_helpers import (
    get_scan_engine,
    handle_ip_scan,
    initialize_scan_history,
    validate_scan_inputs,
    build_scan_workflow,
    set_cache_for_task,
)
from reNgine.tasks.http import http_crawl
from reNgine.tasks.notification import send_scan_notif
from reNgine.tasks.reporting import report
from reNgine.tasks.port_scan import process_nmap_results

from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, SubScan
from targetApp.models import Domain

"""
Celery tasks.
"""

@app.task(name='initiate_scan', queue='orchestrator_queue', bind=True)
def initiate_scan(self, scan_history_id, domain_id, engine_id=None, scan_type=LIVE_SCAN,
                 results_dir=RENGINE_RESULTS, imported_subdomains=None,
                 out_of_scope_subdomains=None, initiated_by_id=None, url_filter=''):
    """Initiate a new scan workflow."""
    from reNgine.utils.db import save_imported_subdomains
    
    #debug()

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

        save_imported_subdomains(imported_subdomains, ctx)

        if not scan or not ctx:
            raise ValueError("🚫 Failed to initialize scan")

        # Send start notification
        logger.info(f'🚀 Starting scan {scan_history_id}')
        send_scan_notif.apply_async(
            kwargs={
                'scan_history_id': scan.id,
                'subscan_id': None,
                'engine_id': engine.id,
                'status': 'RUNNING'
            }
        )

        # Build and execute workflow
        workflow, task_ids = build_scan_workflow(domain, engine, ctx, True)
        task = workflow.delay()

        # Update scan with all task IDs
        scan.celery_ids.extend([self.request.id] + task_ids)
        scan.save()

        return {
            'success': True,
            'task_id': task.id,
            'scan_history_id': scan.id
        }

    except (ValidationError, ScanHistory.DoesNotExist, Domain.DoesNotExist) as e:
        # Manage expected errors
        error_msg = str(e)
        logger.exception(f"🚫 Validation/DB error: {error_msg}")

        if scan:
            scan.scan_status = FAILED_TASK
            scan.error_message = error_msg
            scan.save()

        return {'success': False, 'error': error_msg}

    except Exception as e:
        # Manage unexpected errors
        error_msg = str(e)
        logger.exception(f"🚫 Unexpected error: {error_msg} {fmt_traceback(e)}")

        if scan:
            scan.scan_status = FAILED_TASK
            scan.error_message = error_msg
            scan.save()

        raise self.retry(exc=e, countdown=60) from e

@app.task(name='initiate_subscan', queue='orchestrator_queue', bind=False)
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

    #debug()

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
        config_subscan = config.get_value(scan_type)

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
            logger.exception(f"Failed to create results directory: {str(e)}")
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
        logger.info(f'Starting subscan {subscan.id} with context:\n{ctx_str}')

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

@app.task(name='post_process', queue='orchestrator_queue', bind=True)
def post_process(self, results=None, source_task=None, cached_results=None, cache_keys=None, **kwargs):
    """
    Process results from a group of tasks and handle caching.
    
    Args:
        results: Results from the group of tasks
        source_task: Name of the parent task
        cached_results: Dictionary of results retrieved from cache
        cache_keys: Dictionary of cache keys by host/key parameter
        **kwargs: Additional parameters
    """
    #debug()
    logger.info(f"📊 Processing results from {source_task} task group")

    # Initialize combined results
    combined_results = {}

    # Add cached results if any
    if cached_results:
        combined_results |= cached_results
        logger.info(f"📋 Added {len(cached_results)} cached results")

    # Process new results
    if results:
        for i, result in enumerate(results):
            if result:
                # Try to find a key parameter in the result
                key_param = None
                if isinstance(result, dict) and 'host' in result:
                    key_param = result['host']
                elif isinstance(result, dict) and 'url' in result:
                    key_param = result['url']

                # Store result
                if key_param:
                    combined_results[key_param] = result

                    # Cache the new result if we have a cache key
                    if cache_keys and key_param in cache_keys:
                        set_cache_for_task(cache_keys[key_param], result)
                else:
                    # No specific key, just add to combined results with index
                    combined_results[f"result_{i}"] = result

    if source_task == 'nmap_scan':
        try:
            process_nmap_results(ctx=kwargs['scan_ctx'], combined_results=combined_results)
        except Exception as e:
            logger.exception(f"Error processing nmap results: {e}\n{fmt_traceback(e)}")

    logger.info(f"✅ Processed {len(combined_results)} total results")

    return combined_results
