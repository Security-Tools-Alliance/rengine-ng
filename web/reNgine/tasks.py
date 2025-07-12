import csv
import json
import os
import pprint
import subprocess
import time
import validators
import xmltodict
import yaml
import tldextract
import concurrent.futures
import base64
import uuid
import shutil
import glob
import select
from pathlib import Path
from copy import deepcopy

from urllib.parse import urlparse
from api.serializers import SubdomainSerializer
from celery import chain, chord, group
from celery.result import allow_join_result
from celery.utils.log import get_task_logger
from django.db import transaction
from django.db.models import Count
from dotted_dict import DottedDict
from django.utils import timezone, html
from pycvesearch import CVESearch
from metafinder.extractor import extract_metadata_from_google_search
import xml.etree.ElementTree as ET

from reNgine.celery import app
from reNgine.llm.llm import LLMVulnerabilityReportGenerator
from reNgine.llm.utils import get_llm_vuln_input_description, convert_markdown_to_html
from reNgine.celery_custom_task import RengineTask
from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.settings import *
from reNgine.utilities import *
from scanEngine.models import (EngineType, InstalledExternalTool, Notification, Proxy)
from startScan.models import *
from startScan.models import EndPoint, Subdomain, Vulnerability
from targetApp.models import Domain
if CELERY_REMOTE_DEBUG:
    import debugpy

"""
Celery tasks.
"""

logger = get_task_logger(__name__)


#----------------------#
# Scan / Subscan tasks #
#----------------------#

#-------------------------#
# Async Task Tracking     #
#-------------------------#

@app.task(name='initiate_scan', bind=False, queue='initiate_scan_queue')
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

    #debug()

    scan = None
    try:
        # Get scan engine
        engine_id = engine_id or scan.scan_type.id # scan history engine_id
        logger.info(f'Engine ID: {engine_id}')
        engines = EngineType.objects.all()
        for engine in engines:
            logger.info(f'Engine: {engine.id} - {engine.engine_name}')
        engine = EngineType.objects.get(pk=engine_id)

        # Get YAML config
        config = yaml.safe_load(engine.yaml_configuration)
        gf_patterns = config.get(GF_PATTERNS, [])

        # Get domain and set last_scan_date
        domain = Domain.objects.get(pk=domain_id)
        domain.last_scan_date = timezone.now()
        domain.save()

        # Check if scanning an IP address
        is_ip_scan = validators.ip_address.ipv4(domain.name) or validators.ip_address.ipv6(domain.name)

        if is_ip_scan:
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
        return {
            'success': False,
            'error': str(e)
        }

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


@app.task(name='report', bind=False, queue='report_queue')
def report(ctx={}, description=None):
    """Report task running after all other tasks.
    Mark ScanHistory or SubScan object as completed and update with final
    status, log run details and send notification.

    Args:
        description (str, optional): Task description shown in UI.
    """
    # Get objects
    subscan_id = ctx.get('subscan_id')
    scan_id = ctx.get('scan_history_id')
    engine_id = ctx.get('engine_id')
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    subscan = SubScan.objects.filter(pk=subscan_id).first()

    # Check if scan exists
    if not scan:
        logger.error(f'ScanHistory with ID {scan_id} not found')
        return

    # Get failed tasks
    tasks = ScanActivity.objects.filter(scan_of=scan).all()
    if subscan:
        tasks = tasks.filter(celery_id__in=subscan.celery_ids)
    failed_tasks = tasks.filter(status=FAILED_TASK)

    # Get task status
    failed_count = failed_tasks.count()
    
    # Check if there are async tasks still running
    has_async_tasks = False
    running_async_count = 0
    
    # Simple check for async tasks by looking at scan metadata
    # This is a simplified version - in a full implementation you'd want to
    # properly track task IDs and check their status via Celery
    try:
        # Check if we have any recently started async tasks
        recent_activities = ScanActivity.objects.filter(
            scan_of=scan,
            time__gte=timezone.now() - timezone.timedelta(minutes=5)  # Started in last 5 minutes
        ).filter(
            name__in=['http_crawl', 'nuclei_scan', 'vulnerability_scan', 'dalfox_xss_scan', 'crlfuzz_scan']
        )
        
        if recent_activities.exists():
            has_async_tasks = True
            running_async_count = recent_activities.count()
            logger.info(f'Found {running_async_count} recent async tasks for scan {scan_id}')
    except Exception as e:
        logger.debug(f'Error checking async tasks: {e}')
        has_async_tasks = False
    
    # Determine status based on failures and async tasks
    if failed_count > 0:
        status = FAILED_TASK
        status_h = 'FAILED'
    elif has_async_tasks:
        status = RUNNING_BACKGROUND
        status_h = 'RUNNING_BACKGROUND'
        logger.info(f'Scan {scan_id}: Main tasks completed but {running_async_count} async tasks still running')
    else:
        status = SUCCESS_TASK
        status_h = 'SUCCESS'

    # Update scan / subscan status
    if subscan:
        subscan.stop_scan_date = timezone.now()
        subscan.status = status
        subscan.save()
    else:
        scan.scan_status = status
    
    # Only set stop_scan_date if fully completed (not for RUNNING_BACKGROUND)
    if status != RUNNING_BACKGROUND:
        scan.stop_scan_date = timezone.now()
    scan.save()

    # Send scan status notif
    send_scan_notif.delay(
        scan_history_id=scan_id,
        subscan_id=subscan_id,
        engine_id=engine_id,
        status=status_h)
    
    # For RUNNING_BACKGROUND status, schedule a check later to finalize
    if status == RUNNING_BACKGROUND:
        logger.info(f'Scheduling status check in 2 minutes for scan {scan_id}')
        # Use a simple delayed task to check again later
        check_and_finalize_scan.apply_async(args=[scan_id, subscan_id], countdown=120)  # Check again in 2 minutes


@app.task(name='check_and_finalize_scan', bind=False, queue='report_queue')
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
    else:
        # Check if main scan status is not RUNNING_BACKGROUND anymore
        if scan.scan_status != RUNNING_BACKGROUND:
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


#------------------------- #
# Tracked reNgine tasks    #
#--------------------------#

@app.task(name='subdomain_discovery', queue='main_scan_queue', base=RengineTask, bind=True)
def subdomain_discovery(
        self,
        host=None,
        ctx=None,
        description=None):
    """Uses a set of tools (see SUBDOMAIN_SCAN_DEFAULT_TOOLS) to scan all
    subdomains associated with a domain.

    Args:
        host (str): Hostname to scan.

    Returns:
        subdomains (list): List of subdomain names.
    """
    if not host:
        host = self.subdomain.name if self.subdomain else self.domain.name

    if self.url_filter:
        logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.url_filter}).')
        return

    # Config
    config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
    tools = config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
    default_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)]
    custom_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)]
    send_subdomain_changes, send_interesting = False, False
    notif = Notification.objects.first()
    if notif:
        send_subdomain_changes = notif.send_subdomain_changes_notif
        send_interesting = notif.send_interesting_notif

    # Gather tools to run for subdomain scan
    if ALL in tools:
        tools = SUBDOMAIN_SCAN_DEFAULT_TOOLS + custom_subdomain_tools
    tools = [t.lower() for t in tools]

    # Make exception for amass since tool name is amass, but command is amass-active/passive
    default_subdomain_tools.append('amass-passive')
    default_subdomain_tools.append('amass-active')

    # Run tools
    for tool in tools:
        cmd = None
        logger.info(f'Scanning subdomains for {host} with {tool}')
        proxy = get_random_proxy()
        if tool in default_subdomain_tools:
            if tool == 'amass-passive':
                use_amass_config = config.get(USE_AMASS_CONFIG, False)
                cmd = f'amass enum -passive -d {host} -o ' + str(Path(self.results_dir) / 'subdomains_amass.txt')
                cmd += (' -config ' + str(Path.home() / '.config' / 'amass' / 'config.ini')) if use_amass_config else ''

            elif tool == 'amass-active':
                use_amass_config = config.get(USE_AMASS_CONFIG, False)
                amass_wordlist_name = config.get(AMASS_WORDLIST, AMASS_DEFAULT_WORDLIST_NAME)
                wordlist_path = str(Path(AMASS_DEFAULT_WORDLIST_PATH) / f'{amass_wordlist_name}.txt')
                cmd = f'amass enum -active -d {host} -o ' + str(Path(self.results_dir) / 'subdomains_amass_active.txt')
                cmd += (' -config ' + str(Path.home() / '.config' / 'amass' / 'config.ini')) if use_amass_config else ''
                cmd += f' -brute -w {wordlist_path}'

            elif tool == 'sublist3r':
                cmd = f'sublist3r -d {host} -t {threads} -o ' + str(Path(self.results_dir) / 'subdomains_sublister.txt')

            elif tool == 'subfinder':
                cmd = f'subfinder -d {host} -o ' + str(Path(self.results_dir) / 'subdomains_subfinder.txt')
                use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
                cmd += (' -config ' + str(Path.home() / '.config' / 'subfinder' / 'config.yaml')) if use_subfinder_config else ''
                cmd += f' -proxy {proxy}' if proxy else ''
                cmd += f' -timeout {timeout}' if timeout else ''
                cmd += f' -t {threads}' if threads else ''
                cmd += f' -silent'

            elif tool == 'oneforall':
                cmd = f'oneforall --target {host} run'
                cmd_extract = f'cut -d\',\' -f6 ' + str(Path(RENGINE_TOOL_GITHUB_PATH) / 'OneForAll' / 'results' / f'{host}.csv') + ' | tail -n +2 > ' + str(Path(self.results_dir) / 'subdomains_oneforall.txt')
                cmd_rm = f'rm -rf ' + str(Path(RENGINE_TOOL_GITHUB_PATH) / 'OneForAll' / 'results'/ f'{host}.csv')
                cmd += f' && {cmd_extract} && {cmd_rm}'

            elif tool == 'ctfr':
                results_file = str(Path(self.results_dir) / 'subdomains_ctfr.txt')
                cmd = f'ctfr -d {host} -o {results_file}'
                cmd_extract = f"cat {results_file} | sed 's/\*.//g' | tail -n +12 | uniq | sort > {results_file}"
                cmd += f' && {cmd_extract}'

            elif tool == 'tlsx':
                results_file = str(Path(self.results_dir) / 'subdomains_tlsx.txt')
                cmd = f'tlsx -san -cn -silent -ro -host {host}'
                cmd += f" | sed -n '/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+{host}$/p' | uniq | sort"
                cmd += f' > {results_file}'

            elif tool == 'netlas':
                results_file = str(Path(self.results_dir) / 'subdomains_netlas.txt')
                cmd = f'netlas search -d domain -i domain domain:"*.{host}" -f json'
                netlas_key = get_netlas_key()
                cmd += f' -a {netlas_key}' if netlas_key else ''
                cmd_extract = f"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+{host}'"
                cmd += f' | {cmd_extract} > {results_file}'

        elif tool in custom_subdomain_tools:
            tool_query = InstalledExternalTool.objects.filter(name__icontains=tool.lower())
            if not tool_query.exists():
                logger.error(f'{tool} configuration does not exists. Skipping.')
                continue
            custom_tool = tool_query.first()
            cmd = custom_tool.subdomain_gathering_command
            if '{TARGET}' not in cmd:
                logger.error(f'Missing {{TARGET}} placeholders in {tool} configuration. Skipping.')
                continue
            if '{OUTPUT}' not in cmd:
                logger.error(f'Missing {{OUTPUT}} placeholders in {tool} configuration. Skipping.')
                continue

            
            cmd = cmd.replace('{TARGET}', host)
            cmd = cmd.replace('{OUTPUT}', str(Path(self.results_dir) / f'subdomains_{tool}.txt'))
            cmd = cmd.replace('{PATH}', custom_tool.github_clone_path) if '{PATH}' in cmd else cmd
        else:
            logger.warning(
                f'Subdomain discovery tool "{tool}" is not supported by reNgine. Skipping.')
            continue

        # Run tool
        try:
            run_command(
                cmd,
                shell=True,
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id)
        except Exception as e:
            logger.error(
                f'Subdomain discovery tool "{tool}" raised an exception')
            logger.exception(e)

    # Gather all the tools' results in one single file. Write subdomains into
    # separate files, and sort all subdomains.
    run_command(
        f'cat ' + str(Path(self.results_dir) / 'subdomains_*.txt') + f' > {self.output_path}',
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)
    run_command(
        f'sort -u {self.output_path} -o {self.output_path}',
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)

    with open(self.output_path) as f:
        lines = f.readlines()

    # Parse the output_file file and store Subdomain and EndPoint objects found
    # in db.
    subdomain_count = 0
    subdomains = []
    urls = []
    for line in lines:
        subdomain_name = line.strip()
        valid_url = bool(validators.url(subdomain_name))
        valid_domain = (
            bool(validators.domain(subdomain_name)) or
            bool(validators.ipv4(subdomain_name)) or
            bool(validators.ipv6(subdomain_name)) or
            valid_url
        )
        if not valid_domain:
            logger.error(f'Subdomain {subdomain_name} is not a valid domain, IP or URL. Skipping.')
            continue

        if valid_url:
            subdomain_name = urlparse(subdomain_name).netloc

        if subdomain_name in self.out_of_scope_subdomains:
            logger.error(f'Subdomain {subdomain_name} is out of scope. Skipping.')
            continue

        # Add subdomain
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        if not isinstance(subdomain, Subdomain):
            logger.error(f"Invalid subdomain encountered: {subdomain}")
            continue
        subdomain_count += 1
        subdomains.append(subdomain)
        urls.append(subdomain.name)

    url_filter = ctx.get('url_filter')
    # Find root subdomain endpoints
    for subdomain in subdomains:
        # Create base endpoint (for scan)
        http_url = f'{subdomain.name}{url_filter}' if url_filter else subdomain.name
        endpoint, _ = save_endpoint(
            http_url,
            ctx=ctx,
            is_default=True,
            subdomain=subdomain
        )
        save_subdomain_metadata(subdomain, endpoint)

    # Send notifications
    subdomains_str = '\n'.join([f'• `{subdomain.name}`' for subdomain in subdomains])
    self.notify(fields={
        'Subdomain count': len(subdomains),
        'Subdomains': subdomains_str,
    })
    if send_subdomain_changes and self.scan_id and self.domain_id:
        added = get_new_added_subdomain(self.scan_id, self.domain_id)
        removed = get_removed_subdomain(self.scan_id, self.domain_id)

        if added:
            subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in added])
            self.notify(fields={'Added subdomains': subdomains_str})

        if removed:
            subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in removed])
            self.notify(fields={'Removed subdomains': subdomains_str})

    if send_interesting and self.scan_id and self.domain_id:
        interesting_subdomains = get_interesting_subdomains(self.scan_id, self.domain_id)
        if interesting_subdomains:
            subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in interesting_subdomains])
            self.notify(fields={'Interesting subdomains': subdomains_str})

    return SubdomainSerializer(subdomains, many=True).data

@app.task(name='osint', queue='main_scan_queue', base=RengineTask, bind=True)
def osint(self, host=None, ctx={}, description=None):
    """Run Open-Source Intelligence tools on selected domain.

    Args:
        host (str): Hostname to scan.

    Returns:
        dict: Results from osint discovery and dorking.
    """
    config = self.yaml_configuration.get(OSINT) or OSINT_DEFAULT_CONFIG
    results = {}

    grouped_tasks = []

    if 'discover' in config:
        logger.info('Starting OSINT Discovery')
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        _task = osint_discovery.si(
            config=config,
            host=self.scan.domain.name,
            scan_history_id=self.scan.id,
            activity_id=self.activity_id,
            results_dir=self.results_dir,
            ctx=custom_ctx
        )
        grouped_tasks.append(_task)

    if OSINT_DORK in config or OSINT_CUSTOM_DORK in config:
        logger.info('Starting OSINT Dorking')
        _task = dorking.si(
            config=config,
            host=self.scan.domain.name,
            scan_history_id=self.scan.id,
            results_dir=self.results_dir
        )
        grouped_tasks.append(_task)

    # Launch OSINT tasks asynchronously without waiting for completion
    # This avoids Celery deadlock by not blocking the worker
    if grouped_tasks:
        celery_group = group(grouped_tasks)
        job = celery_group.apply_async()
        logger.info(f'Started {len(grouped_tasks)} OSINT tasks asynchronously')
    else:
        logger.info('No OSINT tasks to run')

@app.task(name='osint_discovery', queue='osint_discovery_queue', bind=False)
def osint_discovery(config, host, scan_history_id, activity_id, results_dir, ctx={}):
    """Run OSINT discovery.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results

    Returns:
        dict: osint metadat and theHarvester and h8mail results.
    """
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    osint_lookup = config.get(OSINT_DISCOVER, [])
    osint_intensity = config.get(INTENSITY, 'normal')
    documents_limit = config.get(OSINT_DOCUMENTS_LIMIT, 50)
    results = {}
    meta_info = []
    emails = []
    creds = []

    # Get and save meta info
    if 'metainfo' in osint_lookup:
        logger.info('Saving Metainfo')
        if osint_intensity == 'normal':
            meta_dict = DottedDict({
                'osint_target': host,
                'domain': host,
                'scan_id': scan_history_id,
                'documents_limit': documents_limit
            })
            meta_info.append(save_metadata_info(meta_dict))

        # TODO: disabled for now
        # elif osint_intensity == 'deep':
        # 	subdomains = Subdomain.objects
        # 	if self.scan:
        # 		subdomains = subdomains.filter(scan_history=self.scan)
        # 	for subdomain in subdomains:
        # 		meta_dict = DottedDict({
        # 			'osint_target': subdomain.name,
        # 			'domain': self.domain,
        # 			'scan_id': self.scan_id,
        # 			'documents_limit': documents_limit
        # 		})
        # 		meta_info.append(save_metadata_info(meta_dict))

    grouped_tasks = []

    if 'emails' in osint_lookup:
        logger.info('Lookup for emails')
        _task = h8mail.si(
            config=config,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
            ctx=ctx
        )
        grouped_tasks.append(_task)

    if 'employees' in osint_lookup:
        logger.info('Lookup for employees')
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        _task = theHarvester.si(
            config=config,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
            ctx=custom_ctx
        )
        grouped_tasks.append(_task)

    # Launch OSINT discovery tasks asynchronously without waiting for completion
    # This avoids Celery deadlock by not blocking the worker
    if grouped_tasks:
        celery_group = group(grouped_tasks)
        job = celery_group.apply_async()
        logger.info(f'Started {len(grouped_tasks)} OSINT discovery tasks asynchronously')
    else:
        logger.info('No OSINT discovery tasks to run')

    # results['emails'] = results.get('emails', []) + emails
    # results['creds'] = creds
    # results['meta_info'] = meta_info
    return results


@app.task(name='dorking', bind=False, queue='dorking_queue')
def dorking(config, host, scan_history_id, results_dir):
    """Run Google dorks.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results

    Returns:
        list: Dorking results for each dork ran.
    """
    # Some dork sources: https://github.com/six2dez/degoogle_hunter/blob/master/degoogle_hunter.sh
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    dorks = config.get(OSINT_DORK, [])
    custom_dorks = config.get(OSINT_CUSTOM_DORK, [])
    results = []
    # custom dorking has higher priority
    try:
        for custom_dork in custom_dorks:
            lookup_target = custom_dork.get('lookup_site')
            # replace with original host if _target_
            lookup_target = host if lookup_target == '_target_' else lookup_target
            if 'lookup_extensions' in custom_dork:
                results = get_and_save_dork_results(
                    lookup_target=lookup_target,
                    results_dir=results_dir,
                    type='custom_dork',
                    lookup_extensions=custom_dork.get('lookup_extensions'),
                    scan_history=scan_history
                )
            elif 'lookup_keywords' in custom_dork:
                results = get_and_save_dork_results(
                    lookup_target=lookup_target,
                    results_dir=results_dir,
                    type='custom_dork',
                    lookup_keywords=custom_dork.get('lookup_keywords'),
                    scan_history=scan_history
                )
    except Exception as e:
        logger.exception(e)

    # default dorking
    try:
        for dork in dorks:
            logger.info(f'Getting dork information for {dork}')
            if dork == 'stackoverflow':
                results = get_and_save_dork_results(
                    lookup_target='stackoverflow.com',
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=host,
                    scan_history=scan_history
                )

            elif dork == 'login_pages':
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords='/login/,login.html',
                    page_count=5,
                    scan_history=scan_history
                )

            elif dork == 'admin_panels':
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords='/admin/,admin.html',
                    page_count=5,
                    scan_history=scan_history
                )

            elif dork == 'dashboard_pages':
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords='/dashboard/,dashboard.html',
                    page_count=5,
                    scan_history=scan_history
                )

            elif dork == 'social_media' :
                social_websites = [
                    'tiktok.com',
                    'facebook.com',
                    'twitter.com',
                    'youtube.com',
                    'reddit.com'
                ]
                for site in social_websites:
                    results = get_and_save_dork_results(
                        lookup_target=site,
                        results_dir=results_dir,
                        type=dork,
                        lookup_keywords=host,
                        scan_history=scan_history
                    )

            elif dork == 'project_management' :
                project_websites = [
                    'trello.com',
                    'atlassian.net'
                ]
                for site in project_websites:
                    results = get_and_save_dork_results(
                        lookup_target=site,
                        results_dir=results_dir,
                        type=dork,
                        lookup_keywords=host,
                        scan_history=scan_history
                    )

            elif dork == 'code_sharing' :
                project_websites = [
                    'github.com',
                    'gitlab.com',
                    'bitbucket.org'
                ]
                for site in project_websites:
                    results = get_and_save_dork_results(
                        lookup_target=site,
                        results_dir=results_dir,
                        type=dork,
                        lookup_keywords=host,
                        scan_history=scan_history
                    )

            elif dork == 'config_files' :
                config_file_exts = [
                    'env',
                    'xml',
                    'conf',
                    'toml',
                    'yml',
                    'yaml',
                    'cnf',
                    'inf',
                    'rdp',
                    'ora',
                    'txt',
                    'cfg',
                    'ini'
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=','.join(config_file_exts),
                    page_count=4,
                    scan_history=scan_history
                )

            elif dork == 'jenkins' :
                lookup_keyword = 'Jenkins'
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=lookup_keyword,
                    page_count=1,
                    scan_history=scan_history
                )

            elif dork == 'wordpress_files' :
                lookup_keywords = [
                    '/wp-content/',
                    '/wp-includes/'
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=','.join(lookup_keywords),
                    page_count=5,
                    scan_history=scan_history
                )

            elif dork == 'php_error' :
                lookup_keywords = [
                    'PHP Parse error',
                    'PHP Warning',
                    'PHP Error'
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=','.join(lookup_keywords),
                    page_count=5,
                    scan_history=scan_history
                )

            elif dork == 'jenkins' :
                lookup_keywords = [
                    'PHP Parse error',
                    'PHP Warning',
                    'PHP Error'
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=','.join(lookup_keywords),
                    page_count=5,
                    scan_history=scan_history
                )

            elif dork == 'exposed_documents' :
                docs_file_ext = [
                    'doc',
                    'docx',
                    'odt',
                    'pdf',
                    'rtf',
                    'sxw',
                    'psw',
                    'ppt',
                    'pptx',
                    'pps',
                    'csv'
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=','.join(docs_file_ext),
                    page_count=7,
                    scan_history=scan_history
                )

            elif dork == 'db_files' :
                file_ext = [
                    'sql',
                    'db',
                    'dbf',
                    'mdb'
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=','.join(file_ext),
                    page_count=1,
                    scan_history=scan_history
                )

            elif dork == 'git_exposed' :
                file_ext = [
                    'git',
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=','.join(file_ext),
                    page_count=1,
                    scan_history=scan_history
                )

    except Exception as e:
        logger.exception(e)
    return results


@app.task(name='theHarvester', queue='theHarvester_queue', bind=False)
def theHarvester(config, host, scan_history_id, activity_id, results_dir, ctx={}):
    """Run theHarvester to get save emails, hosts, employees found in domain.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        activity_id: ScanActivity ID
        results_dir (str): Path to store scan results
        ctx (dict): context of scan

    Returns:
        dict: Dict of emails, employees, hosts and ips found during crawling.
    """
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    output_path_json = str(Path(results_dir) / 'theHarvester.json')
    theHarvester_dir = str(Path.home() / ".config"  / 'theHarvester')
    history_file = str(Path(results_dir) / 'commands.txt')
    cmd  = f'theHarvester -d {host} -f {output_path_json} -b anubis,baidu,bevigil,binaryedge,bing,bingapi,bufferoverun,brave,censys,certspotter,criminalip,crtsh,dnsdumpster,duckduckgo,fullhunt,hackertarget,hunter,hunterhow,intelx,netlas,onyphe,otx,pentesttools,projectdiscovery,rapiddns,rocketreach,securityTrails,sitedossier,subdomaincenter,subdomainfinderc99,threatminer,tomba,urlscan,virustotal,yahoo,zoomeye'

    # Update proxies.yaml
    proxy_query = Proxy.objects.all()
    if proxy_query.exists():
        proxy = proxy_query.first()
        if proxy.use_proxy:
            proxy_list = proxy.proxies.splitlines()
            yaml_data = {'http' : proxy_list}
            with open(Path(theHarvester_dir) / 'proxies.yaml', 'w') as file:
                yaml.dump(yaml_data, file)

    # Run cmd
    run_command(
        cmd,
        shell=False,
        cwd=theHarvester_dir,
        history_file=history_file,
        scan_id=scan_history_id,
        activity_id=activity_id)

    # Get file location
    if not os.path.isfile(output_path_json):
        logger.error(f'Could not open {output_path_json}')
        return {}

    # Load theHarvester results
    with open(output_path_json, 'r') as f:
        data = json.load(f)

    # Re-indent theHarvester JSON
    with open(output_path_json, 'w') as f:
        json.dump(data, f, indent=4)

    emails = data.get('emails', [])
    for email_address in emails:
        email, _ = save_email(email_address, scan_history=scan_history)
        # if email:
        # 	self.notify(fields={'Emails': f'• `{email.address}`'})

    linkedin_people = data.get('linkedin_people', [])
    for people in linkedin_people:
        employee, _ = save_employee(
            people,
            designation='linkedin',
            scan_history=scan_history)
        # if employee:
        # 	self.notify(fields={'LinkedIn people': f'• {employee.name}'})

    twitter_people = data.get('twitter_people', [])
    for people in twitter_people:
        employee, _ = save_employee(
            people,
            designation='twitter',
            scan_history=scan_history)
        # if employee:
        # 	self.notify(fields={'Twitter people': f'• {employee.name}'})

    hosts = data.get('hosts', [])
    urls = []
    for host in hosts:
        split = tuple(host.split(':'))
        http_url = split[0]
        subdomain_name = get_subdomain_from_url(http_url)
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        if not isinstance(subdomain, Subdomain):
            logger.error(f"Invalid subdomain encountered: {subdomain}")
            continue
        endpoint, _ = save_endpoint(
            http_url,
            ctx=ctx,
            subdomain=subdomain)
        # if endpoint:
        # 	urls.append(endpoint.http_url)
            # self.notify(fields={'Hosts': f'• {endpoint.http_url}'})


    # TODO: Lots of ips unrelated with our domain are found, disabling
    # this for now.
    # ips = data.get('ips', [])
    # for ip_address in ips:
    # 	ip, created = save_ip_address(
    # 		ip_address,
    # 		subscan=subscan)
    # 	if ip:
    # 		send_task_notif.delay(
    # 			'osint',
    # 			scan_history_id=scan_history_id,
    # 			subscan_id=subscan_id,
    # 			severity='success',
    # 			update_fields={'IPs': f'{ip.address}'})
    return data


@app.task(name='h8mail', queue='h8mail_queue', bind=False)
def h8mail(config, host, scan_history_id, activity_id, results_dir, ctx={}):
    """Run h8mail.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        activity_id: ScanActivity ID
        results_dir (str): Path to store scan results
        ctx (dict): context of scan

    Returns:
        list[dict]: List of credentials info.
    """
    logger.warning('Getting leaked credentials')
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    input_path = str(Path(results_dir) / 'emails.txt')
    output_file = str(Path(results_dir) / 'h8mail.json')

    cmd = f'h8mail -t {input_path} --json {output_file}'
    history_file = str(Path(results_dir) / 'commands.txt')

    run_command(
        cmd,
        history_file=history_file,
        scan_id=scan_history_id,
        activity_id=activity_id)

    with open(output_file) as f:
        data = json.load(f)
        creds = data.get('targets', [])

    # TODO: go through h8mail output and save emails to DB
    for cred in creds:
        logger.warning(cred)
        email_address = cred['target']
        pwn_num = cred['pwn_num']
        pwn_data = cred.get('data', [])
        email, created = save_email(email_address, scan_history=scan)
        # if email:
        # 	self.notify(fields={'Emails': f'• `{email.address}`'})
    return creds


@app.task(name='screenshot', queue='main_scan_queue', base=RengineTask, bind=True)
def screenshot(self, ctx={}, description=None):
    """Uses EyeWitness to gather screenshot of a domain and/or url.

    Args:
        description (str, optional): Task description shown in UI.
    """
    
    # Use the smart crawl-then-execute pattern
    def _execute_screenshot(ctx, description):
        # Config
        screenshots_path = str(Path(self.results_dir) / 'screenshots')
        output_path = str(Path(self.results_dir) / 'screenshots' / self.filename)
        alive_endpoints_file = str(Path(self.results_dir) / 'endpoints_alive.txt')
        config = self.yaml_configuration.get(SCREENSHOT) or {}
        intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
        timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5)
        threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)

        # If intensity is normal, grab only the root endpoints of each subdomain
        strict = True if intensity == 'normal' else False

        # Get URLs to take screenshot of
        urls = get_http_urls(
            is_alive=True,
            strict=strict,
            write_filepath=alive_endpoints_file,
            get_only_default_urls=True,
            ctx=ctx
        )
        if not urls:
            logger.error(f'No alive URLs found for screenshot. Skipping.')
            return

        # Send start notif
        notification = Notification.objects.first()
        send_output_file = notification.send_scan_output_file if notification else False

        # Run cmd
        cmd = f'EyeWitness -f {alive_endpoints_file} -d {screenshots_path} --no-prompt'
        cmd += f' --timeout {timeout}' if timeout > 0 else ''
        cmd += f' --threads {threads}' if threads > 0 else ''
        run_command(
            cmd,
            shell=False,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id)
        if not os.path.isfile(output_path):
            logger.error(f'Could not load EyeWitness results at {output_path} for {self.domain.name}.')
            return

        # Loop through results and save objects in DB
        screenshot_paths = []
        with open(output_path, 'r') as file:
            reader = csv.reader(file)
            header = next(reader)  # Skip header row
            indices = [header.index(col) for col in ["Protocol", "Port", "Domain", "Request Status", "Screenshot Path", " Source Path"]]
            for row in reader:
                protocol, port, subdomain_name, status, screenshot_path, source_path = extract_columns(row, indices)
                subdomain_query = Subdomain.objects.filter(name=subdomain_name)
                if self.scan:
                    subdomain_query = subdomain_query.filter(scan_history=self.scan)
                if status == 'Successful' and subdomain_query.exists():
                    subdomain = subdomain_query.first()
                    screenshot_paths.append(screenshot_path)
                    subdomain.screenshot_path = screenshot_path.replace(RENGINE_RESULTS, '')
                    subdomain.save()
                    logger.warning(f'Added screenshot for {protocol}://{subdomain.name}:{port} to DB')


        # Remove all db, html extra files in screenshot results
        patterns = ['*.csv', '*.db', '*.js', '*.html', '*.css']
        for pattern in patterns:
            remove_file_or_pattern(
                screenshots_path,
                pattern=pattern,
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id
            )

        # Delete source folder
        remove_file_or_pattern(
            str(Path(screenshots_path) / 'source'),
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id
        )

        # Send finish notifs
        screenshots_str = '• ' + '\n• '.join([f'`{path}`' for path in screenshot_paths])
        self.notify(fields={'Screenshots': screenshots_str})
        if send_output_file:
            for path in screenshot_paths:
                title = get_output_file_name(
                    self.scan_id,
                    self.subscan_id,
                    self.filename)
                send_file_to_discord.delay(path, title)
        
        return screenshot_paths
    
    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_screenshot, ctx, description)


@app.task(name='port_scan', queue='main_scan_queue', base=RengineTask, bind=True)
def port_scan(self, hosts=None, ctx=None, description=None):
    """Run port scan and detect web services.

    Args:
        hosts (list, optional): Hosts to run port scan on.
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of open ports (dict).
    """
    # Initialize mutable parameters
    hosts = hosts or []
    ctx = ctx or {}

    input_file = str(Path(self.results_dir) / 'input_subdomains_port_scan.txt')
    proxy = get_random_proxy()

    # Config
    config = self.yaml_configuration.get(PORT_SCAN) or {}
    timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
    exclude_ports = config.get(NAABU_EXCLUDE_PORTS, [])
    exclude_subdomains = config.get(NAABU_EXCLUDE_SUBDOMAINS, False)
    ports = config.get(PORTS, NAABU_DEFAULT_PORTS)
    ports = [str(port) for port in ports]
    rate_limit = config.get(NAABU_RATE) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    passive = config.get(NAABU_PASSIVE, False)
    use_naabu_config = config.get(USE_NAABU_CONFIG, False)
    exclude_ports_str = ','.join(return_iterable(exclude_ports))
    
    # Web service detection configuration
    web_ports = config.get('web_ports', UNCOMMON_WEB_PORTS + [80, 443, 8080, 8443])
    
    # nmap args
    nmap_enabled = config.get(ENABLE_NMAP, False)
    nmap_cmd = config.get(NMAP_COMMAND, '')
    nmap_script = config.get(NMAP_SCRIPT, '')
    nmap_script = ','.join(return_iterable(nmap_script))
    nmap_script_args = config.get(NMAP_SCRIPT_ARGS)

    if hosts:
        with open(input_file, 'w') as f:
            f.write('\n'.join(hosts))
    else:
        hosts = get_subdomains(
            write_filepath=input_file,
            exclude_subdomains=exclude_subdomains,
            ctx=ctx)

    # Build cmd
    cmd = 'naabu -json -exclude-cdn'
    cmd += f' -list {input_file}' if len(hosts) > 0 else f' -host {hosts[0]}'
    if 'full' in ports or 'all' in ports:
        ports_str = ' -p "-"'
    elif 'top-100' in ports:
        ports_str = ' -top-ports 100'
    elif 'top-1000' in ports:
        ports_str = ' -top-ports 1000'
    else:
        ports_str = ','.join(ports)
        ports_str = f' -p {ports_str}'
    cmd += ports_str
    cmd += (' -config ' + str(Path.home() / '.config' / 'naabu' / 'config.yaml')) if use_naabu_config else ''
    cmd += f' -proxy "{proxy}"' if proxy else ''
    cmd += f' -c {threads}' if threads else ''
    cmd += f' -rate {rate_limit}' if rate_limit > 0 else ''
    cmd += f' -timeout {timeout*1000}' if timeout > 0 else ''
    cmd += ' -passive' if passive else ''
    cmd += f' -exclude-ports {exclude_ports_str}' if exclude_ports else ''
    cmd += ' -silent'

    # Execute cmd and gather results
    results = []
    urls = []
    ports_data = {}
    web_services = []
    
    for line in stream_command(
            cmd,
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id):

        if not isinstance(line, dict):
            continue
        results.append(line)
        port_number = line['port']
        ip_address = line['ip']
        host = line.get('host') or ip_address
        if port_number == 0:
            continue

        # Grab subdomain
        subdomain = Subdomain.objects.filter(
            name=host,
            target_domain=self.domain,
            scan_history=self.scan
        ).first()

        # Add IP DB
        ip, _ = save_ip_address(ip_address, subdomain, subscan=self.subscan)
        if self.subscan:
            ip.ip_subscan_ids.add(self.subscan)
            ip.save()

        # Check if this is a web service port
        is_web_port = port_number in web_ports
        
        if is_web_port:
            # Determine scheme based on port
            scheme = 'https' if port_number in [443, 8443] or 'ssl' in str(port_number) else 'http'
            
            # Create web service endpoint
            http_url = f'{scheme}://{host}:{port_number}'
            endpoint, _ = save_endpoint(
                http_url,
                ctx=ctx,
                subdomain=subdomain,
                is_default=(port_number in [80, 443])
            )
            
            if endpoint:
                web_services.append({
                    'host': host,
                    'port': port_number,
                    'scheme': scheme,
                    'url': http_url
                })
                urls.append(http_url)
                logger.info(f'Created web service endpoint: {http_url}')

        # Add Port in DB
        if any(c.isalpha() for c in ip_address):
            logger.warning(f"Skipping hostname, not a valid IP: {ip_address}")
            continue

        # Update or create port with service info
        port, created = Port.objects.update_or_create(
            ip_address=ip,
            number=port_number,
            defaults={
                'service_name': 'http' if is_web_port else 'unknown',
                'description': f'Web service on port {port_number}' if is_web_port else '',
                'is_uncommon': port_number in UNCOMMON_WEB_PORTS
            }
        )

        if created:
            logger.warning(f'Found opened port {port_number} on {ip_address} ({host})')
        else:
            logger.debug(f'Port {port_number} already exists for {ip_address}')

        if host in ports_data:
            if port_number not in ports_data[host]:
                ports_data[host].append(port_number)
        else:
            ports_data[host] = [port_number]

    if not ports_data:
        logger.info('Finished running naabu port scan - No open ports found.')
        if nmap_enabled:
            logger.info('Nmap scans skipped')
        return ports_data

    # Send notification
    fields_str = ''
    for host, ports in ports_data.items():
        ports_str = ', '.join([f'`{port}`' for port in ports])
        fields_str += f'• `{host}`: {ports_str}\n'
    self.notify(fields={'Ports discovered': fields_str})
    
    # Send web services notification
    if web_services:
        web_services_str = '\n'.join([f'• `{ws["url"]}`' for ws in web_services])
        self.notify(fields={'Web services found': web_services_str})

    # Save output to file
    with open(self.output_path, 'w') as f:
        json.dump(results, f, indent=4)

    logger.info('Finished running naabu port scan.')

    # Process nmap results: 1 process per host
    if nmap_enabled:
        logger.warning(f'Starting nmap scans on {len(ports_data)} hosts ...')
        logger.warning(ports_data)
        nmap_args = {
            'rate_limit': rate_limit,
            'nmap_cmd': nmap_cmd,
            'nmap_script': nmap_script,
            'nmap_script_args': nmap_script_args,
            'ports_data': ports_data
        }
        run_nmap(ctx, **nmap_args)

    return ports_data

@app.task(name='run_nmap', queue='main_scan_queue', base=RengineTask, bind=True)
def run_nmap(self, ctx, **nmap_args):
    """Run nmap scans in parallel for each host.
    
    Args:
        self: RengineTask instance
        ctx: Scan context
        nmap_args: Dictionary containing nmap configuration
            - nmap_cmd: Custom nmap args
            - nmap_script: NSE scripts to run
            - nmap_script_args: NSE script arguments
            - ports_data: Dictionary mapping hosts to their open ports
    """
    sigs = []
    for host, port_list in nmap_args.get('ports_data', {}).items():
        custom_ctx = deepcopy(ctx)
        custom_ctx['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
        custom_ctx['track'] = False
        sig = nmap.si(
                args=nmap_args.get('nmap_cmd'),
                ports=port_list,
                host=host,
                script=nmap_args.get('nmap_script'),
                script_args=nmap_args.get('nmap_script_args'),
                max_rate=nmap_args.get('rate_limit'),
                ctx=custom_ctx)
        sigs.append(sig)
    task = group(sigs).apply_async()
    with allow_join_result():
        task.get()


@app.task(name='nmap', queue='main_scan_queue', base=RengineTask, bind=True)
def nmap(
        self,
        args=None,
        ports=[],
        host=None,
        input_file=None,
        script=None,
        script_args=None,
        max_rate=None,
        ctx={},
        description=None):
    """Run nmap on a host.

    Args:
        args (str, optional): Existing nmap args to complete.
        ports (list, optional): List of ports to scan.
        host (str, optional): Host to scan.
        input_file (str, optional): Input hosts file.
        script (str, optional): NSE script to run.
        script_args (str, optional): NSE script args.
        max_rate (int): Max rate.
        description (str, optional): Task description shown in UI.
    """
    notif = Notification.objects.first()
    ports_str = ','.join(str(port) for port in ports)
    self.filename = 'nmap.xml'
    filename_vulns = self.filename.replace('.xml', '_vulns.json')
    output_file = self.output_path
    output_file_xml = f'{self.results_dir}/{host}_{self.filename}'
    vulns_file = f'{self.results_dir}/{host}_{filename_vulns}'
    logger.warning(f'Running nmap on {host}')
    logger.debug(f'Scan Engine args: {args}')

    # Build cmd
    nmap_cmd = get_nmap_cmd(
        args=args,
        ports=ports_str,
        script=script,
        script_args=script_args,
        max_rate=max_rate,
        host=host,
        input_file=input_file,
        output_file=output_file_xml)

    # Run cmd
    run_command(
        nmap_cmd,
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)

    # Update port service information
    process_nmap_service_results(output_file_xml)

    # Get nmap XML results and convert to JSON
    vulns = parse_nmap_results(output_file_xml, output_file, parse_type='vulnerabilities')
    save_vulns(self, notif, vulns_file, vulns)
    return vulns

def save_vulns(self, notif, vulns_file, vulns):
    with open(vulns_file, 'w') as f:
        json.dump(vulns, f, indent=4)

    # Save vulnerabilities found by nmap
    vulns_str = ''
    for vuln_data in vulns:
        # URL is not necessarily an HTTP URL when running nmap (can be any
        # other vulnerable protocols). Look for existing endpoint and use its
        # URL as vulnerability.http_url if it exists.
        url = vuln_data['http_url']
        endpoint = EndPoint.objects.filter(http_url__contains=url).first()
        if endpoint:
            vuln_data['http_url'] = endpoint.http_url
        vuln, created = save_vulnerability(
            target_domain=self.domain,
            subdomain=self.subdomain,
            scan_history=self.scan,
            subscan=self.subscan,
            endpoint=endpoint,
            **vuln_data)
        vulns_str += f'• {str(vuln)}\n'
        if created:
            logger.warning(str(vuln))

    # Send only 1 notif for all vulns to reduce number of notifs
    if notif and notif.send_vuln_notif and vulns_str:
        logger.warning(vulns_str)
        self.notify(fields={'CVEs': vulns_str})


@app.task(name='waf_detection', queue='main_scan_queue', base=RengineTask, bind=True)
def waf_detection(self, ctx={}, description=None):
    """
    Uses wafw00f to check for the presence of a WAF.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of startScan.models.Waf objects.
    """
    
    def _execute_waf_detection(ctx, description):
        input_path = str(Path(self.results_dir) / 'input_endpoints_waf_detection.txt')
        config = self.yaml_configuration.get(WAF_DETECTION) or {}

        # Get alive endpoints from DB
        urls = get_http_urls(
            is_alive=True,
            write_filepath=input_path,
            get_only_default_urls=True,
            ctx=ctx
        )
        if not urls:
            logger.error(f'No alive URLs found for WAF detection. Skipping.')
            return

        cmd = f'wafw00f -i {input_path} -o {self.output_path} -f json'
        run_command(
            cmd,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id)
            
        if not os.path.isfile(self.output_path):
            logger.error(f'Could not find {self.output_path}')
            return

        with open(self.output_path) as file:
            wafs = json.load(file)

        for waf_data in wafs:
            if not waf_data.get('detected') or not waf_data.get('firewall'):
                continue

            # Add waf to db
            waf, _ = Waf.objects.get_or_create(
                name=waf_data['firewall'],
                manufacturer=waf_data.get('manufacturer', '')
            )

            # Add waf info to Subdomain in DB
            subdomain_name = get_subdomain_from_url(waf_data['url'])
            logger.info(f'Wafw00f Subdomain : {subdomain_name}')

            try:
                subdomain = Subdomain.objects.get(
                    name=subdomain_name,
                    scan_history=self.scan,
                )
                # Clear existing WAFs and set the new one
                subdomain.waf.clear()
                subdomain.waf.add(waf)
                subdomain.save()
            except Subdomain.DoesNotExist:
                logger.warning(f'Subdomain {subdomain_name} was not found in the db, skipping waf detection.')

        return wafs
    
    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_waf_detection, ctx, description)


@app.task(name='dir_file_fuzz', queue='main_scan_queue', base=RengineTask, bind=True)
def dir_file_fuzz(self, ctx={}, description=None):
    """Perform directory scan, and currently uses `ffuf` as a default tool.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of URLs discovered.
    """
    
    def _execute_dir_file_fuzz(ctx, description):
        # Config
        cmd = 'ffuf'
        config = self.yaml_configuration.get(DIR_FILE_FUZZ) or {}
        custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
        if custom_header:
            custom_header = generate_header_param(custom_header,'common')
        auto_calibration = config.get(AUTO_CALIBRATION, True)
        rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
        extensions = config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)
        # prepend . on extensions
        extensions = [ext if ext.startswith('.') else '.' + ext for ext in extensions]
        extensions_str = ','.join(map(str, extensions))
        follow_redirect = config.get(FOLLOW_REDIRECT, FFUF_DEFAULT_FOLLOW_REDIRECT)
        max_time = config.get(MAX_TIME, 0)
        match_http_status = config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)
        mc = ','.join([str(c) for c in match_http_status])
        recursive_level = config.get(RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL)
        stop_on_error = config.get(STOP_ON_ERROR, False)
        timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
        threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
        wordlist_name = config.get(WORDLIST, FFUF_DEFAULT_WORDLIST_NAME)
        delay = rate_limit / (threads * 100) # calculate request pause delay from rate_limit and number of threads
        input_path = str(Path(self.results_dir) / 'input_dir_file_fuzz.txt')

        # Get wordlist
        wordlist_name = FFUF_DEFAULT_WORDLIST_NAME if wordlist_name == 'default' else wordlist_name
        wordlist_path = str(Path(FFUF_DEFAULT_WORDLIST_PATH) / f'{wordlist_name}.txt')

        # Build command
        cmd += f' -w {wordlist_path}'
        cmd += f' -e {extensions_str}' if extensions else ''
        cmd += f' -maxtime {max_time}' if max_time > 0 else ''
        cmd += f' -p {delay}' if delay > 0 else ''
        cmd += f' -recursion -recursion-depth {recursive_level} ' if recursive_level > 0 else ''
        cmd += f' -t {threads}' if threads and threads > 0 else ''
        cmd += f' -timeout {timeout}' if timeout and timeout > 0 else ''
        cmd += ' -se' if stop_on_error else ''
        cmd += ' -fr' if follow_redirect else ''
        cmd += ' -ac' if auto_calibration else ''
        cmd += f' -mc {mc}' if mc else ''
        cmd += f' {custom_header}' if custom_header else ''

        # Grab URLs to fuzz
        urls = get_http_urls(
            is_alive=True,
            ignore_files=False,
            write_filepath=input_path,
            get_only_default_urls=True,
            ctx=ctx
        )
        
        if not urls:
            logger.error(f'No alive URLs found for directory fuzzing. Skipping.')
            return
        
        logger.warning(urls)

        # Loop through URLs and run command
        results = []
        for url in urls:
            '''
                Above while fetching urls, we are not ignoring files, because some
                default urls may redirect to https://example.com/login.php
                so, ignore_files is set to False
                but, during fuzzing, we will only need part of the path, in above example
                it is still a good idea to ffuf base url https://example.com
                so files from base url
            '''
            url_parse = urlparse(url)
            url = url_parse.scheme + '://' + url_parse.netloc
            url += '/FUZZ' # TODO: fuzz not only URL but also POST / PUT / headers
            proxy = get_random_proxy()

            # Build final cmd
            fcmd = cmd
            fcmd += f' -x {proxy}' if proxy else ''
            fcmd += f' -u {url} -json'

            # Initialize DirectoryScan object
            dirscan = DirectoryScan()
            dirscan.scanned_date = timezone.now()
            dirscan.command_line = fcmd
            dirscan.save()

            # Loop through results and populate EndPoint and DirectoryFile in DB
            for line in stream_command(
                    fcmd,
                    shell=True,
                    history_file=self.history_file,
                    scan_id=self.scan_id,
                    activity_id=self.activity_id):

                # Empty line, continue to the next record
                if not isinstance(line, dict):
                    continue

                # Append line to results
                results.append(line)

                # Retrieve FFUF output
                url = line['url']
                # Extract path and convert to base64 (need byte string encode & decode)
                name = base64.b64encode(extract_path_from_url(url).encode()).decode()
                length = line['length']
                status = line['status']
                words = line['words']
                lines = line['lines']
                content_type = line['content-type']
                duration = line['duration']

                # If name empty log error and continue
                if not name:
                    logger.error(f'FUZZ not found for "{url}"')
                    continue

                # Get or create endpoint from URL
                endpoint, created = save_endpoint(url, ctx=ctx)

                # Continue to next line if endpoint returned is None
                if endpoint == None:
                    continue

                # Save endpoint data from FFUF output
                endpoint.http_status = status
                endpoint.content_length = length
                endpoint.response_time = duration / 1000000000
                endpoint.content_type = content_type
                endpoint.content_length = length
                endpoint.save()

                # Save directory file output from FFUF output
                dfile, created = DirectoryFile.objects.get_or_create(
                    name=name,
                    length=length,
                    words=words,
                    lines=lines,
                    content_type=content_type,
                    url=url,
                    http_status=status)

                # Log newly created file or directory if debug activated
                if created and CELERY_DEBUG:
                    logger.warning(f'Found new directory or file {url}')

                # Add file to current dirscan
                dirscan.directory_files.add(dfile)

                # Add subscan relation to dirscan if exists
                if self.subscan:
                    dirscan.dir_subscan_ids.add(self.subscan)

                # Save dirscan datas
                dirscan.save()

                # Get subdomain and add dirscan
                if ctx.get('subdomain_id') and ctx['subdomain_id'] > 0:
                    subdomain = Subdomain.objects.get(id=ctx['subdomain_id'])
                else:
                    subdomain_name = get_subdomain_from_url(endpoint.http_url)
                    subdomain = Subdomain.objects.get(name=subdomain_name, scan_history=self.scan)
                subdomain.directories.add(dirscan)
                subdomain.save()


        return results
    
    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_dir_file_fuzz, ctx, description)


@app.task(name='fetch_url', queue='main_scan_queue', base=RengineTask, bind=True)
def fetch_url(self, urls=[], ctx={}, description=None):
    """Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

    Args:
        urls (list): List of URLs to start from.
        description (str, optional): Task description shown in UI.
    """
    input_path = str(Path(self.results_dir) / 'input_endpoints_fetch_url.txt')
    proxy = get_random_proxy()

    # Config
    config = self.yaml_configuration.get(FETCH_URL) or {}
    should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
    duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)

    gf_patterns = config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)
    ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
    tools = config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS)
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    domain_request_headers = self.domain.request_headers if self.domain else None
    custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    follow_redirect = config.get(FOLLOW_REDIRECT, False)  # Get follow redirect setting
    if domain_request_headers or custom_header:
        custom_header = domain_request_headers or custom_header
    exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

    # Initialize the URLs
    if urls and is_iterable(urls) and any(url for url in urls if url):
        logger.debug(f'URLs provided by user')
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        logger.debug(f'URLs gathered from database')
        urls = get_http_urls(
            is_alive=True,
            write_filepath=input_path,
            exclude_subdomains=exclude_subdomains,
            get_only_default_urls=True,
            ctx=ctx
        )

    # check if urls is empty
    if not urls:
        logger.warning("No URLs found. Exiting fetch_url.")
        return

    # Log initial URLs
    logger.debug(f'Initial URLs: {urls}')

    # Initialize command map for tools
    cmd_map = {
        'gau': 'gau --config ' + str(Path.home() / '.config' / 'gau' / 'config.toml'),
        'hakrawler': 'hakrawler -subs -u',
        'waybackurls': 'waybackurls',
        'gospider': 'gospider --js -d 2 --sitemap --robots -w -r -a',
        'katana': 'katana -silent -jc -kf all -d 3 -fs rdn',
    }
    if proxy:
        cmd_map['gau'] += f' --proxy "{proxy}"'
        cmd_map['gospider'] += f' -p {proxy}'
        cmd_map['hakrawler'] += f' -proxy {proxy}'
        cmd_map['katana'] += f' -proxy {proxy}'
    if threads > 0:
        cmd_map['gau'] += f' --threads {threads}'
        cmd_map['gospider'] += f' -t {threads}'
        cmd_map['hakrawler'] += f' -t {threads}'
        cmd_map['katana'] += f' -c {threads}'
    if custom_header:
        cmd_map['gospider'] += generate_header_param(custom_header, 'gospider')
        cmd_map['hakrawler'] += generate_header_param(custom_header, 'hakrawler')
        cmd_map['katana'] += generate_header_param(custom_header, 'common')

    # Add follow_redirect option to tools that support it
    if follow_redirect is False:
        cmd_map['gospider'] += f' --no-redirect'
        cmd_map['hakrawler'] += f' -dr'
        cmd_map['katana'] += f' -dr'

    tasks = []

    # Iterate over each URL and generate commands for each tool
    for url in urls:
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc.split(':')[0]  # Remove port if present
        host_regex = f"'https?://{re.escape(base_domain)}(:[0-9]+)?(/.*)?$'"

        # Log the generated regex for the current URL
        logger.debug(f'Generated regex for domain {base_domain}: {host_regex}')

        cat_input = f'echo "{url}"'

        # Generate commands for each tool for the current URL
        for tool in tools:  # Only use tools specified in the config
            if tool in cmd_map:
                cmd = cmd_map[tool]
                tool_cmd = f'{cat_input} | {cmd} | grep -Eo {host_regex} > {self.results_dir}/urls_{tool}_{base_domain}.txt'
                tasks.append(run_command.si(
                    tool_cmd,
                    shell=True,
                    scan_id=self.scan_id,
                    activity_id=self.activity_id)
                )
                logger.debug(f'Generated command for tool {tool}: {tool_cmd}')

    # Group the tasks
    task_group = group(tasks)

    # Cleanup task
    sort_output = [
        f'cat ' + str(Path(self.results_dir) / 'urls_*') + f' > {self.output_path}',
        f'cat {input_path} >> {self.output_path}',
        f'sort -u {self.output_path} -o {self.output_path}',
    ]
    if ignore_file_extension and is_iterable(ignore_file_extension):
        ignore_exts = '|'.join(ignore_file_extension)
        grep_ext_filtered_output = [
            f'cat {self.output_path} | grep -Eiv "\\.({ignore_exts}).*" > ' + str(Path(self.results_dir) / 'urls_filtered.txt'),
            f'mv ' + str(Path(self.results_dir) / 'urls_filtered.txt') + f' {self.output_path}'
        ]
        sort_output.extend(grep_ext_filtered_output)
    cleanup = chain(
        run_command.si(
            cmd,
            shell=True,
            scan_id=self.scan_id,
            activity_id=self.activity_id)
        for cmd in sort_output
    )

    # Run all commands
    task = chord(task_group)(cleanup)
    with allow_join_result():
        task.get()

    # Store all the endpoints and run httpx
    all_urls = []
    tool_mapping = {}  # New dictionary to map URLs to tools
    for tool in tools:
        for url in urls:
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc.split(':')[0]  # Remove port if present
            tool_output_file = f'{self.results_dir}/urls_{tool}_{base_domain}.txt'
            if os.path.exists(tool_output_file):
                with open(tool_output_file, 'r') as f:
                    discovered_urls = f.readlines()
                    for url in discovered_urls:
                        url = url.strip()
                        urlpath = None
                        base_url = None
                        if '] ' in url:  # found JS scraped endpoint e.g from gospider
                            split = tuple(url.split('] '))
                            if not len(split) == 2:
                                logger.warning(f'URL format not recognized for "{url}". Skipping.')
                                continue
                            base_url, urlpath = split
                            urlpath = urlpath.lstrip('- ')
                        elif ' - ' in url:  # found JS scraped endpoint e.g from gospider
                            base_url, urlpath = tuple(url.split(' - '))

                        if base_url and urlpath:
                            # Handle both cases: path-only and full URLs
                            if urlpath.startswith(('http://', 'https://')):
                                # Full URL case - check if in scope
                                parsed_url = urlparse(urlpath)
                                if self.domain.name in parsed_url.netloc:
                                    url = urlpath  # Use the full URL directly
                                    logger.debug(f'Found in-scope URL: {url}')
                                else:
                                    logger.debug(f'URL {urlpath} not in scope for domain {self.domain.name}. Skipping.')
                                    continue
                            else:
                                # Path-only case
                                subdomain = urlparse(base_url)
                                # Remove ./ at beginning of urlpath
                                urlpath = urlpath.lstrip('./')
                                # Ensure urlpath starts with /
                                if not urlpath.startswith('/'):
                                    urlpath = '/' + urlpath
                                url = f'{subdomain.scheme}://{subdomain.netloc}{urlpath}'

                        if not validators.url(url):
                            logger.warning(f'Invalid URL "{url}". Skipping.')
                            continue

                        if url not in tool_mapping:
                            tool_mapping[url] = set()
                        tool_mapping[url].add(tool)  # Use a set to ensure uniqueness

    all_urls = list(tool_mapping.keys())
    for url, found_tools in tool_mapping.items():
        unique_tools = ', '.join(found_tools)
        logger.info(f'URL {url} found by tools: {unique_tools}')

    # Filter out URLs if a path filter was passed
    if self.url_filter:
        all_urls = [url for url in all_urls if self.url_filter in url]

    # Write result to output path
    with open(self.output_path, 'w') as f:
        f.write('\n'.join(all_urls))
    logger.warning(f'Found {len(all_urls)} usable URLs')


    #-------------------#
    # GF PATTERNS MATCH #
    #-------------------#

    # Combine old gf patterns with new ones
    if gf_patterns and is_iterable(gf_patterns):
        self.scan.used_gf_patterns = ','.join(gf_patterns)
        self.scan.save()

    # Run gf patterns on saved endpoints
    # TODO: refactor to Celery task
    for gf_pattern in gf_patterns:
        # TODO: js var is causing issues, removing for now
        if gf_pattern == 'jsvar':
            logger.info('Ignoring jsvar as it is causing issues.')
            continue

        # Run gf on current pattern
        logger.warning(f'Running gf on pattern "{gf_pattern}"')
        gf_output_file = str(Path(self.results_dir) / f'gf_patterns_{gf_pattern}.txt')
        cmd = f'cat {self.output_path} | gf {gf_pattern} | grep -Eo {host_regex} >> {gf_output_file}'
        run_command(
            cmd,
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id)

        # Check output file
        if not os.path.exists(gf_output_file):
            logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
            continue

        # Read output file line by line and
        with open(gf_output_file, 'r') as f:
            lines = f.readlines()

        # Add endpoints / subdomains to DB
        for url in lines:
            http_url = sanitize_url(url)
            subdomain_name = get_subdomain_from_url(http_url)
            subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
            if not isinstance(subdomain, Subdomain):
                logger.error(f"Invalid subdomain encountered: {subdomain}")
                continue
            endpoint, created = save_endpoint(
                http_url=http_url,
                subdomain=subdomain,
                ctx=ctx)
            if not endpoint:
                continue
            earlier_pattern = None
            if not created:
                earlier_pattern = endpoint.matched_gf_patterns
            pattern = f'{earlier_pattern},{gf_pattern}' if earlier_pattern else gf_pattern
            endpoint.matched_gf_patterns = pattern
            # TODO Add tool that found the URL to the db (need to update db model)
            # endpoint.found_by_tools = ','.join(tool_mapping.get(url, []))  # Save tools in the endpoint
            endpoint.save()

    return all_urls

def parse_curl_output(response):
    # TODO: Enrich from other cURL fields.
    CURL_REGEX_HTTP_STATUS = f'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
    http_status = 0
    if response:
        failed = False
        regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
        try:
            http_status = int(regex.findall(response)[0])
        except (KeyError, TypeError, IndexError):
            pass
    return {
        'http_status': http_status,
    }

@app.task(name='vulnerability_scan', queue='main_scan_queue', bind=True, base=RengineTask)
def vulnerability_scan(self, urls=[], ctx={}, description=None):
    """
        This function will serve as an entrypoint to vulnerability scan.
        All other vulnerability scan will be run from here including nuclei, crlfuzz, etc
    """
    logger.info('Running Vulnerability Scan Queue')
    config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
    should_run_nuclei = config.get(RUN_NUCLEI, True)
    should_run_crlfuzz = config.get(RUN_CRLFUZZ, False)
    should_run_dalfox = config.get(RUN_DALFOX, False)
    should_run_s3scanner = config.get(RUN_S3SCANNER, True)

    grouped_tasks = []
    if should_run_nuclei:
        _task = nuclei_scan.si(
            urls=urls,
            ctx=ctx,
            description=f'Nuclei Scan'
        )
        grouped_tasks.append(_task)

    if should_run_crlfuzz:
        _task = crlfuzz_scan.si(
            urls=urls,
            ctx=ctx,
            description=f'CRLFuzz Scan'
        )
        grouped_tasks.append(_task)

    if should_run_dalfox:
        _task = dalfox_xss_scan.si(
            urls=urls,
            ctx=ctx,
            description=f'Dalfox XSS Scan'
        )
        grouped_tasks.append(_task)

    if should_run_s3scanner:
        _task = s3scanner.si(
            ctx=ctx,
            description=f'Misconfigured S3 Buckets Scanner'
        )
        grouped_tasks.append(_task)

    # Launch tasks asynchronously without waiting for completion
    # This avoids Celery deadlock by not blocking the worker
    if grouped_tasks:
        celery_group = group(grouped_tasks)
        job = celery_group.apply_async()
        logger.info(f'Started {len(grouped_tasks)} vulnerability scan tasks asynchronously')
    else:
        logger.info('No vulnerability scan tasks to run')

    # return results
    return None

@app.task(name='nuclei_individual_severity_module', queue='main_scan_queue', base=RengineTask, bind=True)
def nuclei_individual_severity_module(self, cmd, severity, should_fetch_llm_report, ctx={}, description=None):
    '''
        This celery task will run vulnerability scan in parallel.
        All severities supplied should run in parallel as grouped tasks.
    '''
    results = []
    logger.info(f'Running vulnerability scan with severity: {severity}')
    cmd += f' -severity {severity}'
    # Send start notification
    notif = Notification.objects.first()
    send_status = notif.send_scan_status_notif if notif else False

    for line in stream_command(
            cmd,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id):

        if not isinstance(line, dict):
            continue

        results.append(line)

        # Gather nuclei results
        vuln_data = parse_nuclei_result(line)

        # Get corresponding subdomain
        http_url = sanitize_url(line.get('matched-at'))
        subdomain_name = get_subdomain_from_url(http_url)

        try:
            subdomain = Subdomain.objects.get(
                name=subdomain_name,
                scan_history=self.scan,
                target_domain=self.domain
            )
        except:
            logger.warning(f'Subdomain {subdomain_name} was not found in the db, skipping vulnerability scan for this subdomain.')
            continue

        # Look for duplicate vulnerabilities by excluding records that might change but are irrelevant.
        object_comparison_exclude = ['response', 'curl_command', 'tags', 'references', 'cve_ids', 'cwe_ids']

        # Add subdomain and target domain to the duplicate check
        vuln_data_copy = vuln_data.copy()
        vuln_data_copy['subdomain'] = subdomain
        vuln_data_copy['target_domain'] = self.domain

        # Check if record exists, if exists do not save it
        if record_exists(Vulnerability, data=vuln_data_copy, exclude_keys=object_comparison_exclude):
            logger.warning(f'Nuclei vulnerability of severity {severity} : {vuln_data_copy["name"]} for {subdomain_name} already exists')
            continue

        # Get or create EndPoint object
        response = line.get('response')
        endpoint, _ = save_endpoint(
            http_url=http_url,
            subdomain=subdomain,
            ctx=ctx)
        if endpoint:
            http_url = endpoint.http_url

        # Get or create Vulnerability object
        vuln, _ = save_vulnerability(
            target_domain=self.domain,
            http_url=http_url,
            scan_history=self.scan,
            subscan=self.subscan,
            subdomain=subdomain,
            **vuln_data)
        if not vuln:
            continue

        # Print vuln
        severity = line['info'].get('severity', 'unknown')
        logger.warning(str(vuln))


        # Send notification for all vulnerabilities except info
        url = vuln.http_url or vuln.subdomain
        send_vuln = (
            notif and
            notif.send_vuln_notif and
            vuln and
            severity in ['low', 'medium', 'high', 'critical'])
        if send_vuln:
            fields = {
                'Severity': f'**{severity.upper()}**',
                'URL': http_url,
                'Subdomain': subdomain_name,
                'Name': vuln.name,
                'Type': vuln.type,
                'Description': vuln.description,
                'Template': vuln.template_url,
                'Tags': vuln.get_tags_str(),
                'CVEs': vuln.get_cve_str(),
                'CWEs': vuln.get_cwe_str(),
                'References': vuln.get_refs_str()
            }
            severity_map = {
                'low': 'info',
                'medium': 'warning',
                'high': 'error',
                'critical': 'error'
            }
            self.notify(
                f'vulnerability_scan_#{vuln.id}',
                severity_map[severity],
                fields,
                add_meta_info=False)

        # Send report to hackerone
        hackerone_query = Hackerone.objects.all()
        send_report = (
            hackerone_query.exists() and
            severity not in ('info', 'low') and
            vuln.target_domain.h1_team_handle
        )
        if send_report:
            hackerone = hackerone_query.first()
            if hackerone.send_critical and severity == 'critical':
                send_hackerone_report.delay(vuln.id)
            elif hackerone.send_high and severity == 'high':
                send_hackerone_report.delay(vuln.id)
            elif hackerone.send_medium and severity == 'medium':
                send_hackerone_report.delay(vuln.id)

    # Write results to JSON file
    with open(self.output_path, 'w') as f:
        json.dump(results, f, indent=4)

    # Send finish notif
    if send_status:
        vulns = Vulnerability.objects.filter(scan_history__id=self.scan_id)
        info_count = vulns.filter(severity=0).count()
        low_count = vulns.filter(severity=1).count()
        medium_count = vulns.filter(severity=2).count()
        high_count = vulns.filter(severity=3).count()
        critical_count = vulns.filter(severity=4).count()
        unknown_count = vulns.filter(severity=-1).count()
        vulnerability_count = info_count + low_count + medium_count + high_count + critical_count + unknown_count
        fields = {
            'Total': vulnerability_count,
            'Critical': critical_count,
            'High': high_count,
            'Medium': medium_count,
            'Low': low_count,
            'Info': info_count,
            'Unknown': unknown_count
        }
        self.notify(fields=fields)

    # after vulnerability scan is done, we need to run llm if
    # should_fetch_llm_report and openapi key exists

    if should_fetch_llm_report and OpenAiAPIKey.objects.exists():
        vulns = Vulnerability.objects.filter(
            scan_history__id=self.scan_id
        ).filter(
            source=NUCLEI
        ).exclude(
            severity=0
        )
        # find all unique vulnerabilities based on path and title
        # all unique vulnerability will go thru llm function and get report
        # once report is got, it will be matched with other vulnerabilities and saved
        unique_vulns = set()
        for vuln in vulns:
            unique_vulns.add((vuln.name, vuln.get_path()))

        unique_vulns = list(unique_vulns)

        with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
            future_to_llm = {executor.submit(llm_vulnerability_report, vuln): vuln for vuln in unique_vulns}

            # Wait for all tasks to complete
            for future in concurrent.futures.as_completed(future_to_llm):
                vuln = future_to_llm[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Exception for Vulnerability {vuln[0]} - {vuln[1]}: {e}")  # Display title and path

        return None

@app.task(name='llm_vulnerability_report', bind=False, queue='llm_queue')
def llm_vulnerability_report(vulnerability_id=None, vuln_tuple=None):
    """
    Generate and store Vulnerability Report using LLM.
    Can be called either with a vulnerability_id or a vuln_tuple (title, path)

    Args:
        vulnerability_id (int, optional): Vulnerability ID to fetch Description
        vuln_tuple (tuple, optional): Tuple containing (title, path)
    
    Returns:
        dict: LLM response containing description, impact, remediation and references
    """
    logger.info('Getting LLM Vulnerability Description')
    try:
        # Get title and path from either vulnerability_id or vuln_tuple
        if vulnerability_id:
            lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
            lookup_url = urlparse(lookup_vulnerability.http_url)
            title = lookup_vulnerability.name
            path = lookup_url.path
        elif vuln_tuple:
            title, path = vuln_tuple
        else:
            raise ValueError("Either vulnerability_id or vuln_tuple must be provided")

        logger.info(f'Processing vulnerability: {title}, PATH: {path}')

        # Check if report already exists in database
        stored = LLMVulnerabilityReport.objects.filter(
            url_path=path,
            title=title
        ).first()

        if stored:
            response = {
                'status': True,
                'description': stored.formatted_description,
                'impact': stored.formatted_impact,
                'remediation': stored.formatted_remediation,
                'references': stored.formatted_references,
            }
            logger.info(f'Found stored report: {stored}')
        else:
            # Generate new report
            vulnerability_description = get_llm_vuln_input_description(title, path)
            llm_generator = LLMVulnerabilityReportGenerator()
            response = llm_generator.get_vulnerability_report(vulnerability_description)
            
            # Store new report in database
            llm_report = LLMVulnerabilityReport()
            llm_report.url_path = path
            llm_report.title = title
            llm_report.description = response.get('description')
            llm_report.impact = response.get('impact')
            llm_report.remediation = response.get('remediation')
            llm_report.references = response.get('references')
            llm_report.save()            
            logger.info('Added new report to database')

        # Update all matching vulnerabilities
        vulnerabilities = Vulnerability.objects.filter(
            name=title,
            http_url__icontains=path
        )
        
        for vuln in vulnerabilities:
            # Update vulnerability fields
            vuln.description = response.get('description', vuln.description)
            vuln.impact = response.get('impact')
            vuln.remediation = response.get('remediation')
            vuln.is_llm_used = True
            vuln.references = response.get('references')
            
            vuln.save()
            logger.info(f'Updated vulnerability {vuln.id} with LLM report')

        response['description'] = convert_markdown_to_html(response.get('description', ''))
        response['impact'] = convert_markdown_to_html(response.get('impact', ''))
        response['remediation'] = convert_markdown_to_html(response.get('remediation', ''))
        response['references'] = convert_markdown_to_html(response.get('references', ''))

        return response

    except Exception as e:
        error_msg = f"Error in get_vulnerability_report: {str(e)}"
        logger.error(error_msg)
        return {
            'status': False,
            'error': error_msg
        }


@app.task(name='nuclei_scan', queue='main_scan_queue', base=RengineTask, bind=True)
def nuclei_scan(self, urls=[], ctx={}, description=None):
    """Nuclei vulnerability scanner.

    Args:
        urls (list, optional): If passed, filter on those URLs.
        description (str, optional): Task description shown in UI.
    """
    
    def _execute_nuclei_scan(ctx, description):
        # Config
        config = self.yaml_configuration.get(VULNERABILITY_SCAN, {})
        nuclei_config = config.get(NUCLEI, {})
        should_fetch_llm_report = nuclei_config.get(FETCH_LLM_REPORT, DEFAULT_GET_LLM_REPORT)
        custom_header = nuclei_config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
        if custom_header:
            custom_header = generate_header_param(custom_header, 'common')
        intensity = nuclei_config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
        rate_limit = nuclei_config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
        retries = nuclei_config.get(RETRIES) or self.yaml_configuration.get(RETRIES, DEFAULT_RETRIES)
        timeout = nuclei_config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
        # templates = nuclei_config.get(NUCLEI_TEMPLATES, [])
        # custom_nuclei_templates = nuclei_config.get(NUCLEI_CUSTOM_TEMPLATES, [])
        # severities = nuclei_config.get(NUCLEI_SEVERITIES, NUCLEI_DEFAULT_SEVERITIES)
        # tags = nuclei_config.get(NUCLEI_TAGS, [])
        # excluded_tags = nuclei_config.get(NUCLEI_EXCLUDED_TAGS, [])
        # excluded_templates = nuclei_config.get(NUCLEI_EXCLUDED_TEMPLATES, [])
        # excluded_severities = nuclei_config.get(NUCLEI_EXCLUDED_SEVERITIES, [])
        user_agent = nuclei_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
        threads = nuclei_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
        nuclei_templates = nuclei_config.get(NUCLEI_TEMPLATES, [])
        custom_nuclei_templates = nuclei_config.get(NUCLEI_CUSTOM_TEMPLATES, [])
        input_path = str(Path(self.results_dir) / 'input_endpoints_nuclei.txt')
        proxy = get_random_proxy()
        # severities_str = ','.join(severities)

        # Get alive endpoints
        if not urls or not any(url for url in urls if url):
            logger.debug(f'Getting alive endpoints for Nuclei scan')
            urls = get_http_urls(
                is_alive=True,
                ignore_files=True,
                write_filepath=input_path,
                ctx=ctx
            )

        if not urls:
            logger.error(f'No alive URLs found for Nuclei scan. Skipping.')
            return

        # Rest of the nuclei scan logic...
        # (I'll continue with the existing nuclei scan code)
        if intensity == 'normal': # reduce number of endpoints to scan
            if not os.path.exists(input_path):
                with open(input_path, 'w') as f:
                    f.write('\n'.join(urls))

            unfurl_filter = str(Path(self.results_dir) / 'urls_unfurled.txt')
            
            run_command(
                f"cat {input_path} | unfurl -u format %s://%d%p |uro > {unfurl_filter}",
                shell=True,
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id)
            run_command(
                f'sort -u {unfurl_filter} -o {unfurl_filter}',
                shell=True,
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id)
                
            if not os.path.exists(unfurl_filter) or os.path.getsize(unfurl_filter) == 0:
                logger.error(f"Failed to create or empty unfurled URLs file at {unfurl_filter}")
                unfurl_filter = input_path
                
            input_path = unfurl_filter

        # Build templates
        logger.info('Updating Nuclei templates ...')
        run_command(
            'nuclei -update-templates',
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id)
        templates = []
        if not (nuclei_templates or custom_nuclei_templates):
            templates.append(NUCLEI_DEFAULT_TEMPLATES_PATH)
        else:
            if nuclei_templates:
                templates.extend(nuclei_templates)
            if custom_nuclei_templates:
                templates.extend(custom_nuclei_templates)

        # Build cmd
        cmd = 'nuclei'
        cmd += f' -target {input_path}'
        cmd += f' -H {custom_header}' if custom_header else ''
        cmd += f' -t {",".join(templates)}' if templates else ''
        cmd += f' -rl {rate_limit}' if rate_limit and rate_limit > 0 else ''
        cmd += f' -retries {retries}' if retries and retries > 0 else ''
        cmd += f' -timeout {timeout}' if timeout and timeout > 0 else ''
        cmd += f' -c {threads}' if threads and threads > 0 else ''
        cmd += f' -proxy {proxy}' if proxy else ''
        cmd += f' -H "User-Agent: {user_agent}"' if user_agent else ''
        cmd += f' -jsonl'
        cmd += f' -o {self.output_path}'

        run_command(
            cmd,
            shell=False,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id)

        results = []
        if not os.path.isfile(self.output_path):
            logger.error(f'Nuclei json output file {self.output_path} not found.')
            return results

        # Parse results
        with open(self.output_path, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        result = json.loads(line)
                        results.append(result)
                        parsed_result = parse_nuclei_result(result)
                        if parsed_result:
                            vuln = save_vulnerability(
                                target_domain=self.domain,
                                scan_history=self.scan,
                                subscan=self.subscan,
                                **parsed_result
                            )
                            if vuln and should_fetch_llm_report:
                                llm_vulnerability_report.delay(vuln.id)
                    except json.JSONDecodeError:
                        logger.error(f'Invalid JSON in nuclei output: {line}')
                        continue

        return results
    
    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_nuclei_scan, ctx, description)

@app.task(name='dalfox_xss_scan', queue='main_scan_queue', base=RengineTask, bind=True)
def dalfox_xss_scan(self, urls=[], ctx={}, description=None):
    """XSS Scan using dalfox

    Args:
        urls (list, optional): If passed, filter on those URLs.
        description (str, optional): Task description shown in UI.
    """
    vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
    should_fetch_llm_report = vuln_config.get(FETCH_LLM_REPORT, DEFAULT_GET_LLM_REPORT)
    dalfox_config = vuln_config.get(DALFOX) or {}
    custom_header = dalfox_config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    if custom_header:
        custom_header = generate_header_param(custom_header, 'dalfox')
    proxy = get_random_proxy()
    is_waf_evasion = dalfox_config.get(WAF_EVASION, False)
    blind_xss_server = dalfox_config.get(BLIND_XSS_SERVER)
    user_agent = dalfox_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
    timeout = dalfox_config.get(TIMEOUT)
    delay = dalfox_config.get(DELAY)
    threads = dalfox_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    input_path = str(Path(self.results_dir) / 'input_endpoints_dalfox_xss.txt')

    if urls and is_iterable(urls) and any(url for url in urls if url):
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        urls = get_http_urls(
            is_alive=True,
            ignore_files=False,
            write_filepath=input_path,
            ctx=ctx
        )

    if not urls:
        logger.error(f'No URLs to scan for XSS. Skipping.')
        return

    notif = Notification.objects.first()
    send_status = notif.send_scan_status_notif if notif else False

    # command builder
    cmd = 'dalfox --silence --no-color --no-spinner'
    cmd += f' --only-poc r '
    cmd += f' --ignore-return 302,404,403'
    cmd += f' --skip-bav'
    cmd += f' file {input_path}'
    cmd += f' --proxy {proxy}' if proxy else ''
    cmd += f' --waf-evasion' if is_waf_evasion else ''
    cmd += f' -b {blind_xss_server}' if blind_xss_server else ''
    cmd += f' --delay {delay}' if delay else ''
    cmd += f' --timeout {timeout}' if timeout else ''
    cmd += f' --user-agent {user_agent}' if user_agent else ''
    cmd += f' {custom_header}' if custom_header else ''
    cmd += f' --worker {threads}' if threads else ''
    cmd += f' --format json'

    results = []
    for line in stream_command(
            cmd,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id,
            trunc_char=','
        ):
        if not isinstance(line, dict):
            continue

        results.append(line)

        vuln_data = parse_dalfox_result(line)

        http_url = sanitize_url(line.get('data'))
        subdomain_name = get_subdomain_from_url(http_url)

        try:
            subdomain = Subdomain.objects.get(
                name=subdomain_name,
                scan_history=self.scan,
                target_domain=self.domain
            )
        except:
            logger.warning(f'Subdomain {subdomain_name} was not found in the db, skipping dalfox scan for this subdomain.')
            continue

        endpoint, _ = save_endpoint(
            http_url=http_url,
            subdomain=subdomain,
            ctx=ctx
        )
        if endpoint:
            http_url = endpoint.http_url
            endpoint.save()

        vuln, _ = save_vulnerability(
            target_domain=self.domain,
            http_url=http_url,
            scan_history=self.scan,
            subscan=self.subscan,
            **vuln_data
        )

        if not vuln:
            continue

    # after vulnerability scan is done, we need to run llm if
    # should_fetch_llm_report and openapi key exists

    if should_fetch_llm_report and OpenAiAPIKey.objects.all().first():
        logger.info('Getting Dalfox Vulnerability LLM Report')
        vulns = Vulnerability.objects.filter(
            scan_history__id=self.scan_id
        ).filter(
            source=DALFOX
        ).exclude(
            severity=0
        )

        _vulns = []
        for vuln in vulns:
            _vulns.append((vuln.name, vuln.http_url))

        with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
            future_to_llm = {executor.submit(llm_vulnerability_report, vuln): vuln for vuln in _vulns}

            # Wait for all tasks to complete
            for future in concurrent.futures.as_completed(future_to_llm):
                vuln = future_to_llm[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Exception for Vulnerability {vuln[0]} - {vuln[1]}: {e}")  # Display title and path
    return results


@app.task(name='crlfuzz_scan', queue='main_scan_queue', base=RengineTask, bind=True)
def crlfuzz_scan(self, urls=[], ctx={}, description=None):
    """CRLF Fuzzing with CRLFuzz

    Args:
        urls (list, optional): If passed, filter on those URLs.
        description (str, optional): Task description shown in UI.
    """
    vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
    should_fetch_llm_report = vuln_config.get(FETCH_LLM_REPORT, DEFAULT_GET_LLM_REPORT)
    custom_header = vuln_config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    if custom_header:
        custom_header = generate_header_param(custom_header, 'common')
    proxy = get_random_proxy()
    user_agent = vuln_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
    threads = vuln_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    input_path = str(Path(self.results_dir) / 'input_endpoints_crlf.txt')
    output_path = str(Path(self.results_dir) / f'{self.filename}')

    if urls and is_iterable(urls) and any(url for url in urls if url):
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        urls = get_http_urls(
            is_alive=True,
            ignore_files=True,
            write_filepath=input_path,
            ctx=ctx
        )

    if not urls:
        logger.error(f'No URLs to scan for CRLF. Skipping.')
        return

    notif = Notification.objects.first()
    send_status = notif.send_scan_status_notif if notif else False

    # command builder
    cmd = 'crlfuzz -s'
    cmd += f' -l {input_path}'
    cmd += f' -x {proxy}' if proxy else ''
    cmd += f' {custom_header}' if custom_header else ''
    cmd += f' -o {output_path}'

    run_command(
        cmd,
        shell=False,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )

    if not os.path.isfile(output_path):
        logger.info('No Results from CRLFuzz')
        return

    crlfs = []
    results = []
    with open(output_path, 'r') as file:
        crlfs = file.readlines()

    for crlf in crlfs:
        url = crlf.strip()

        vuln_data = parse_crlfuzz_result(url)

        http_url = sanitize_url(url)
        subdomain_name = get_subdomain_from_url(http_url)

        try:
            subdomain = Subdomain.objects.get(
                name=subdomain_name,
                scan_history=self.scan,
                target_domain=self.domain
            )
        except:
            logger.warning(f'Subdomain {subdomain_name} was not found in the db, skipping crlfuzz scan for this subdomain.')
            continue

        endpoint, _ = save_endpoint(
            http_url=http_url,
            subdomain=subdomain,
            ctx=ctx
        )
        if endpoint:
            http_url = endpoint.http_url
            endpoint.save()

        vuln, _ = save_vulnerability(
            target_domain=self.domain,
            http_url=http_url,
            scan_history=self.scan,
            subscan=self.subscan,
            **vuln_data
        )

        if not vuln:
            continue

    # after vulnerability scan is done, we need to run llm if
    # should_fetch_llm_report and openapi key exists

    if should_fetch_llm_report and OpenAiAPIKey.objects.all().first():
        logger.info('Getting CRLFuzz Vulnerability LLM Report')
        vulns = Vulnerability.objects.filter(
            scan_history__id=self.scan_id
        ).filter(
            source=CRLFUZZ
        ).exclude(
            severity=0
        )

        _vulns = []
        for vuln in vulns:
            _vulns.append((vuln.name, vuln.http_url))

        with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
            future_to_llm = {executor.submit(llm_vulnerability_report, vuln): vuln for vuln in _vulns}

            # Wait for all tasks to complete
            for future in concurrent.futures.as_completed(future_to_llm):
                vuln = future_to_llm[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Exception for Vulnerability {vuln[0]} - {vuln[1]}: {e}")  # Display title and path

    return results


@app.task(name='s3scanner', queue='main_scan_queue', base=RengineTask, bind=True)
def s3scanner(self, ctx={}, description=None):
    """Bucket Scanner

    Args:
        ctx (dict): Context
        description (str, optional): Task description shown in UI.
    """
    input_path = str(Path(self.results_dir) / f'{self.scan_id}_s3_bucket_discovery.txt')

    subdomains = Subdomain.objects.filter(scan_history=self.scan)
    if not subdomains:
        logger.error(f'No subdomains found for S3Scanner. Skipping.')
        return

    with open(input_path, 'w') as f:
        for subdomain in subdomains:
            f.write(subdomain.name + '\n')

    vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
    s3_config = vuln_config.get(S3SCANNER) or {}
    threads = s3_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    providers = s3_config.get(PROVIDERS, S3SCANNER_DEFAULT_PROVIDERS)
    scan_history = ScanHistory.objects.filter(pk=self.scan_id).first()
    for provider in providers:
        cmd = f's3scanner -bucket-file {input_path} -enumerate -provider {provider} -threads {threads} -json'
        for line in stream_command(
                cmd,
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id):

            if not isinstance(line, dict):
                continue

            if line.get('bucket', {}).get('exists', 0) == 1:
                result = parse_s3scanner_result(line)
                s3bucket, created = S3Bucket.objects.get_or_create(**result)
                scan_history.buckets.add(s3bucket)
                logger.info(f"s3 bucket added {result['provider']}-{result['name']}-{result['region']}")


@app.task(name='http_crawl', queue='main_scan_queue', base=RengineTask, bind=True)
def http_crawl(
        self,
        urls=None,  # Changed from urls=[]
        method=None,
        recrawl=False,
        ctx={},
        track=True,
        description=None,
        update_subdomain_metadatas=False,
        should_remove_duplicate_endpoints=True,
        duplicate_removal_fields=[]):
    """Use httpx to query HTTP URLs for important info like page titles, http
    status, etc...

    Args:
        urls (list, optional): A set of URLs to check. Overrides default
            behavior which queries all endpoints related to this scan.
        method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
        recrawl (bool, optional): If False, filter out URLs that have already
            been crawled.
        should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
        duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates

    Returns:
        list: httpx results.
    """
    logger.info('Initiating HTTP Crawl')

    debug()

    # Initialize urls as empty list if None
    if urls is None:
        urls = []
    
    cmd = 'httpx'
    config = self.yaml_configuration.get(HTTP_CRAWL) or {}
    custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    if custom_header:
        custom_header = generate_header_param(custom_header, 'common')
    threads = config.get(THREADS, DEFAULT_THREADS)
    follow_redirect = config.get(FOLLOW_REDIRECT, False)
    self.output_path = None
    input_path = f'{self.results_dir}/httpx_input.txt'
    history_file = f'{self.results_dir}/commands.txt'
    if urls and is_iterable(urls) and any(url for url in urls if url):
        if self.url_filter:
            urls = [u for u in urls if self.url_filter in u]
        urls = [url for url in urls if url is not None]
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        # No url provided, so it's a subscan launched from subdomain list
        update_subdomain_metadatas = True
        all_urls = []

        # Append the base subdomain to get subdomain info if task is launched directly from subscan
        subdomain_id = ctx.get('subdomain_id')
        if subdomain_id:
            subdomain = Subdomain.objects.filter(id=ctx.get('subdomain_id')).first()
            all_urls.append(subdomain.name)

        # Get subdomain endpoints to crawl the entire list
        http_urls = get_http_urls(
            is_uncrawled=not recrawl,
            write_filepath=input_path,
            ctx=ctx
        )
        if not http_urls:
            logger.error('No URLs to crawl. Skipping.')
            return

        if http_urls:
            all_urls.extend(http_urls)
            
        urls = all_urls

        logger.debug(urls)

    # If no URLs found, skip it
    if not urls:
        return

    # Re-adjust thread number if few URLs to avoid spinning up a monster to
    # kill a fly.
    if len(urls) < threads:
        threads = len(urls)

    # Get random proxy
    proxy = get_random_proxy()

    # Run command
    cmd += f' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent'
    cmd += f' -t {threads}' if threads > 0 else ''
    cmd += f' --http-proxy {proxy}' if proxy else ''
    cmd += f' {custom_header}' if custom_header else ''
    cmd += f' -json'
    cmd += f' -u {urls[0]}' if len(urls) == 1 else f' -l {input_path}'
    cmd += f' -x {method}' if method else ''
    cmd += f' -retries 5'
    cmd += f' -silent'
    if follow_redirect:
        cmd += ' -fr'
    results = []
    endpoint_ids = []
    for line in stream_command(
            cmd,
            history_file=history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id):

        if not line or not isinstance(line, dict):
            logger.error("No line found")
            continue

        # Check if the http request has an error
        if 'error' in line:
            logger.error(line)
            continue

        line_str = json.dumps(line, indent=2)
        logger.debug(line_str)

        # No response from endpoint
        if line.get('failed', False):
            logger.error("Failed to crawl endpoint")
            continue

        # Parse httpx output
        host = line.get('host', '')
        content_length = line.get('content_length', 0)
        http_status = line.get('status_code')
        http_url, is_redirect = extract_httpx_url(line, follow_redirect)
        page_title = line.get('title')
        webserver = line.get('webserver')
        cdn = line.get('cdn', False)
        rt = line.get('time')
        techs = line.get('tech', [])
        cname = line.get('cname', '')
        content_type = line.get('content_type', '')
        response_time = -1
        if rt:
            response_time = float(''.join(ch for ch in rt if not ch.isalpha()))
            if rt[-2:] == 'ms':
                response_time = response_time / 1000

        # Create/get Subdomain object in DB
        subdomain_name = get_subdomain_from_url(http_url)
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        if not isinstance(subdomain, Subdomain):
            logger.error(f"Invalid subdomain encountered: {subdomain}")
            continue

        # Save default HTTP URL to endpoint object in DB
        endpoint, created = save_endpoint(
            http_url=http_url,
            http_status=http_status,
            ctx=ctx,
            subdomain=subdomain,
            is_default=update_subdomain_metadatas
        )
        if not endpoint:
            continue
        # Update endpoint object
        endpoint.discovered_date = datetime.now()
        endpoint.http_status = http_status
        endpoint.http_url = http_url
        endpoint.page_title = page_title
        endpoint.content_length = content_length
        endpoint.webserver = webserver
        endpoint.response_time = response_time
        endpoint.content_type = content_type
        endpoint.save()
        endpoint_str = f'{http_url} [{http_status}] `{content_length}B` `{webserver}` `{rt}`'
        logger.warning(endpoint_str)
        if endpoint and endpoint.is_alive and endpoint.http_status != 403:
            self.notify(
                fields={'Alive endpoint': f'• {endpoint_str}'},
                add_meta_info=False)

        # Add endpoint to results
        line['_cmd'] = cmd
        line['final_url'] = http_url
        line['endpoint_id'] = endpoint.id
        line['endpoint_created'] = created
        line['is_redirect'] = is_redirect
        results.append(line)

        # Add technology objects to DB
        for technology in techs:
            tech, _ = Technology.objects.get_or_create(name=technology)
            endpoint.techs.add(tech)
            endpoint.save()
        techs_str = ', '.join([f'`{tech}`' for tech in techs])
        self.notify(
            fields={'Technologies': techs_str},
            add_meta_info=False)

        # Add IP objects for 'a' records to DB
        a_records = line.get('a', [])
        for ip_address in a_records:
            ip, created = save_ip_address(
                ip_address,
                subdomain,
                subscan=self.subscan,
                cdn=cdn)
        ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in a_records])
        self.notify(
            fields={'IPs': ips_str},
            add_meta_info=False)

        # Add IP object for host in DB
        if host:
            ip, created = save_ip_address(
                host,
                subdomain,
                subscan=self.subscan,
                cdn=cdn)
            self.notify(
                fields={'IPs': f'• `{ip.address}`'},
                add_meta_info=False)

        # Save subdomain metadatas
        if update_subdomain_metadatas:
            save_subdomain_metadata(subdomain, endpoint, line)

        endpoint_ids.append(endpoint.id)

    # Check if httpx returned any lines
    if not results:
        logger.error(f"httpx returned no lines for command: {cmd}")
        logger.error(f"URLs processed: {urls}")
        if len(urls) > 1:
            logger.error(f"Input file path: {input_path}")

    if should_remove_duplicate_endpoints:
        # Remove 'fake' alive endpoints that are just redirects to the same page
        remove_duplicate_endpoints(
            self.scan_id,
            self.domain_id,
            self.subdomain_id,
            filter_ids=endpoint_ids
        )

    # Remove input file
    if not remove_file_or_pattern(
        input_path,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    ):
        logger.error(f"Failed to clean up input file {input_path}")

    return results


#---------------------#
# Notifications tasks #
#---------------------#

@app.task(name='send_notif', bind=False, queue='send_notif_queue')
def send_notif(
        message,
        scan_history_id=None,
        subscan_id=None,
        **options):
    if not 'title' in options:
        message = enrich_notification(message, scan_history_id, subscan_id)
    send_discord_message(message, **options)
    send_slack_message(message)
    send_lark_message(message)
    send_telegram_message(message)


@app.task(name='send_scan_notif', bind=False, queue='send_scan_notif_queue')
def send_scan_notif(
        scan_history_id,
        subscan_id=None,
        engine_id=None,
        status='RUNNING'):
    """Send scan status notification. Works for scan or a subscan if subscan_id
    is passed.

    Args:
        scan_history_id (int, optional): ScanHistory id.
        subscan_id (int, optional): SuScan id.
        engine_id (int, optional): EngineType id.
    """

    # Skip send if notification settings are not configured
    notif = Notification.objects.first()
    if not (notif and notif.send_scan_status_notif):
        return

    # Get domain, engine, scan_history objects
    engine = EngineType.objects.filter(pk=engine_id).first()
    scan = ScanHistory.objects.filter(pk=scan_history_id).first()
    subscan = SubScan.objects.filter(pk=subscan_id).first()
    tasks = ScanActivity.objects.filter(scan_of=scan) if scan else 0

    # Build notif options
    url = get_scan_url(scan_history_id, subscan_id)
    title = get_scan_title(scan_history_id, subscan_id)
    fields = get_scan_fields(engine, scan, subscan, status, tasks)
    severity = None
    msg = f'{title} {status}\n'
    msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())
    if status:
        severity = STATUS_TO_SEVERITIES.get(status)
    opts = {
        'title': title,
        'url': url,
        'fields': fields,
        'severity': severity
    }
    logger.warning(f'Sending notification "{title}" [{severity}]')

    # Send notification
    send_notif(
        msg,
        scan_history_id,
        subscan_id,
        **opts)


@app.task(name='send_task_notif', bind=False, queue='send_task_notif_queue')
def send_task_notif(
        task_name,
        status=None,
        result=None,
        output_path=None,
        traceback=None,
        scan_history_id=None,
        engine_id=None,
        subscan_id=None,
        severity=None,
        add_meta_info=True,
        update_fields={}):
    """Send task status notification.

    Args:
        task_name (str): Task name.
        status (str, optional): Task status.
        result (str, optional): Task result.
        output_path (str, optional): Task output path.
        traceback (str, optional): Task traceback.
        scan_history_id (int, optional): ScanHistory id.
        subscan_id (int, optional): SuScan id.
        engine_id (int, optional): EngineType id.
        severity (str, optional): Severity (will be mapped to notif colors)
        add_meta_info (bool, optional): Wheter to add scan / subscan info to notif.
        update_fields (dict, optional): Fields key / value to update.
    """

    # Skip send if notification settings are not configured
    notif = Notification.objects.first()
    if not (notif and notif.send_scan_status_notif):
        return

    # Build fields
    url = None
    fields = {}
    if add_meta_info:
        engine = EngineType.objects.filter(pk=engine_id).first()
        scan = ScanHistory.objects.filter(pk=scan_history_id).first()
        subscan = SubScan.objects.filter(pk=subscan_id).first()
        url = get_scan_url(scan_history_id)
        if status:
            fields['Status'] = f'**{status}**'
        if engine:
            fields['Engine'] = engine.engine_name
        if scan:
            fields['Scan ID'] = f'[#{scan.id}]({url})'
        if subscan:
            url = get_scan_url(scan_history_id, subscan_id)
            fields['Subscan ID'] = f'[#{subscan.id}]({url})'
    title = get_task_title(task_name, scan_history_id, subscan_id)
    if status:
        severity = STATUS_TO_SEVERITIES.get(status)

    msg = f'{title} {status}\n'
    msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())

    # Add fields to update
    for k, v in update_fields.items():
        fields[k] = v

    # Add traceback to notif
    if traceback and notif.send_scan_tracebacks:
        fields['Traceback'] = f'```\n{traceback}\n```'

    # Add files to notif
    files = []
    attach_file = (
        notif.send_scan_output_file and
        output_path and
        result and
        not traceback
    )
    if attach_file:
        output_title = output_path.split('/')[-1]
        files = [(output_path, output_title)]

    # Send notif
    opts = {
        'title': title,
        'url': url,
        'files': files,
        'severity': severity,
        'fields': fields,
        'fields_append': update_fields.keys()
    }
    send_notif(
        msg,
        scan_history_id=scan_history_id,
        subscan_id=subscan_id,
        **opts)


@app.task(name='send_file_to_discord', bind=False, queue='send_file_to_discord_queue')
def send_file_to_discord(file_path, title=None):
    notif = Notification.objects.first()
    do_send = notif and notif.send_to_discord and notif.discord_hook_url
    if not do_send:
        return False

    webhook = DiscordWebhook(
        url=notif.discord_hook_url,
        rate_limit_retry=True,
        username=title or "reNgine Discord Plugin"
    )
    with open(file_path, "rb") as f:
        head, tail = os.path.split(file_path)
        webhook.add_file(file=f.read(), filename=tail)
    webhook.execute()


@app.task(name='send_hackerone_report', bind=False, queue='send_hackerone_report_queue')
def send_hackerone_report(vulnerability_id):
    """Send HackerOne vulnerability report.

    Args:
        vulnerability_id (int): Vulnerability id.

    Returns:
        int: HTTP response status code.
    """
    vulnerability = Vulnerability.objects.get(id=vulnerability_id)
    severities = {v: k for k,v in NUCLEI_SEVERITY_MAP.items()}
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # can only send vulnerability report if team_handle exists
    if len(vulnerability.target_domain.h1_team_handle) !=0:
        hackerone_query = Hackerone.objects.all()
        if hackerone_query.exists():
            hackerone = Hackerone.objects.first()
            severity_value = severities[vulnerability.severity]
            tpl = hackerone.report_template

            # Replace syntax of report template with actual content
            tpl = tpl.replace('{vulnerability_name}', vulnerability.name)
            tpl = tpl.replace('{vulnerable_url}', vulnerability.http_url)
            tpl = tpl.replace('{vulnerability_severity}', severity_value)
            tpl = tpl.replace('{vulnerability_description}', vulnerability.description if vulnerability.description else '')
            tpl = tpl.replace('{vulnerability_extracted_results}', vulnerability.extracted_results if vulnerability.extracted_results else '')
            tpl = tpl.replace('{vulnerability_reference}', vulnerability.reference if vulnerability.reference else '')

            data = {
              "data": {
                "type": "report",
                "attributes": {
                  "team_handle": vulnerability.target_domain.h1_team_handle,
                  "title": f'{vulnerability.name} found in {vulnerability.http_url}',
                  "vulnerability_information": tpl,
                  "severity_rating": severity_value,
                  "impact": "More information about the impact and vulnerability can be found here: \n" + vulnerability.reference if vulnerability.reference else "NA",
                }
              }
            }

            r = requests.post(
              'https://api.hackerone.com/v1/hackers/reports',
              auth=(hackerone.username, hackerone.api_key),
              json=data,
              headers=headers
            )
            response = r.json()
            status_code = r.status_code
            if status_code == 201:
                vulnerability.hackerone_report_id = response['data']["id"]
                vulnerability.open_status = False
                vulnerability.save()
            return status_code

    else:
        logger.error('No team handle found.')
        status_code = 111
        return status_code


#-------------#
# Utils tasks #
#-------------#


@app.task(name='parse_nmap_results', bind=False, queue='parse_nmap_results_queue')
def parse_nmap_results(xml_file, output_file=None, parse_type='vulnerabilities'):
    """Parse results from nmap output file.

    Args:
        xml_file (str): nmap XML report file path.
        output_file (str, optional): JSON output file path.
        parse_type (str): Type of parsing to perform:
            - 'vulnerabilities': Parse vulnerabilities from nmap scripts
            - 'services': Parse service banners from -sV
            - 'ports': Parse only open ports

    Returns:
        list: List of parsed results depending on parse_type:
            - vulnerabilities: List of vulnerability dictionaries
            - services: List of service dictionaries
            - ports: List of port dictionaries
    """
    with open(xml_file, encoding='utf8') as f:
        content = f.read()
        try:
            nmap_results = xmltodict.parse(content)
        except Exception as e:
            logger.warning(e)
            logger.error(f'Cannot parse {xml_file} to valid JSON. Skipping.')
            return []

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(nmap_results, f, indent=4)

    hosts = nmap_results.get('nmaprun', {}).get('host', {})
    if isinstance(hosts, dict):
        hosts = [hosts]

    results = []
    
    for host in hosts:
        # Get hostname/IP
        hostnames_dict = host.get('hostnames', {})
        
        # Get all IP addresses of the host
        addresses = []
        host_addresses = host.get('address', [])
        if isinstance(host_addresses, dict):
            host_addresses = [host_addresses]
        for addr in host_addresses:
            if addr.get('@addrtype') in ['ipv4', 'ipv6']:
                addresses.append({
                    'addr': addr.get('@addr'),
                    'type': addr.get('@addrtype')
                })

        if hostnames_dict:
            if not (hostname_data := hostnames_dict.get('hostname', [])):
                hostnames = [addresses[0]['addr'] if addresses else 'unknown']
            else:
                # Convert to list if it's a unique dictionary
                if isinstance(hostname_data, dict):
                    hostname_data = [hostname_data]
                hostnames = [entry.get('@name') for entry in hostname_data if entry.get('@name')] or [addresses[0]['addr'] if addresses else 'unknown']
        else:
            hostnames = [addresses[0]['addr'] if addresses else 'unknown']

        # Process each hostname
        for hostname in hostnames:
            ports = host.get('ports', {}).get('port', [])
            if isinstance(ports, dict):
                ports = [ports]

            for port in ports:
                port_number = port['@portid']
                if not port_number or not port_number.isdigit():
                    continue
                    
                port_protocol = port['@protocol']
                port_state = port.get('state', {}).get('@state')
                
                # Skip closed ports
                if port_state != 'open':
                    continue

                url = sanitize_url(f'{hostname}:{port_number}')

                if parse_type == 'ports':
                    # Return only open ports info with addresses
                    results.append({
                        'host': hostname,
                        'port': port_number,
                        'protocol': port_protocol,
                        'state': port_state,
                        'addresses': addresses
                    })
                    continue

                if parse_type == 'services':
                    # Parse service information from -sV
                    service = port.get('service', {})
                    results.append({
                        'host': hostname,
                        'port': port_number,
                        'protocol': port_protocol,
                        'service_name': service.get('@name'),
                        'service_product': service.get('@product'),
                        'service_version': service.get('@version'),
                        'service_extrainfo': service.get('@extrainfo'),
                        'service_ostype': service.get('@ostype'),
                        'service_method': service.get('@method'),
                        'service_conf': service.get('@conf')
                    })
                    continue

                if parse_type == 'vulnerabilities':
                    # Original vulnerability parsing logic
                    url_vulns = []
                    scripts = port.get('script', [])
                    if isinstance(scripts, dict):
                        scripts = [scripts]

                    for script in scripts:
                        script_id = script['@id']
                        script_output = script['@output']
                        
                        if script_id == 'vulscan':
                            vulns = parse_nmap_vulscan_output(script_output)
                            url_vulns.extend(vulns)
                        elif script_id == 'vulners':
                            vulns = parse_nmap_vulners_output(script_output)
                            url_vulns.extend(vulns)
                        else:
                            logger.warning(f'Script output parsing for script "{script_id}" is not supported yet.')

                    for vuln in url_vulns:
                        vuln['source'] = NMAP
                        vuln['http_url'] = url
                        if 'http_path' in vuln:
                            vuln['http_url'] += vuln['http_path']
                        results.append(vuln)

    return results

def parse_nmap_http_csrf_output(script_output):
    pass


def parse_nmap_vulscan_output(script_output):
    """Parse nmap vulscan script output.

    Args:
        script_output (str): Vulscan script output.

    Returns:
        list: List of Vulnerability dicts.
    """
    data = {}
    vulns = []
    provider_name = ''

    # Sort all vulns found by provider so that we can match each provider with
    # a function that pulls from its API to get more info about the
    # vulnerability.
    for line in script_output.splitlines():
        if not line:
            continue
        if not line.startswith('['): # provider line
            if "No findings" in line:
                logger.info(f"No findings: {line}")
                continue
            elif ' - ' in line:
                provider_name, provider_url = tuple(line.split(' - '))
                data[provider_name] = {'url': provider_url.rstrip(':'), 'entries': []}
                continue
            else:
                # Log a warning
                logger.warning(f"Unexpected line format: {line}")
                continue
        reg = r'\[(.*)\] (.*)'
        matches = re.match(reg, line)
        id, title = matches.groups()
        entry = {'id': id, 'title': title}
        data[provider_name]['entries'].append(entry)

    logger.warning('Vulscan parsed output:')
    logger.warning(pprint.pformat(data))

    for provider_name in data:
        if provider_name == 'Exploit-DB':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'IBM X-Force':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'MITRE CVE':
            logger.error(f'Provider {provider_name} is not supported YET.')
            for entry in data[provider_name]['entries']:
                cve_id = entry['id']
                vuln = cve_to_vuln(cve_id)
                vulns.append(vuln)
        elif provider_name == 'OSVDB':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'OpenVAS (Nessus)':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'SecurityFocus':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'VulDB':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        else:
            logger.error(f'Provider {provider_name} is not supported.')
    return vulns


def parse_nmap_vulners_output(script_output, url=''):
    """Parse nmap vulners script output.

    TODO: Rework this as it's currently matching all CVEs no matter the
    confidence.

    Args:
        script_output (str): Script output.

    Returns:
        list: List of found vulnerabilities.
    """
    vulns = []
    # Check for CVE in script output
    CVE_REGEX = re.compile(r'.*(CVE-\d\d\d\d-\d+).*')
    matches = CVE_REGEX.findall(script_output)
    matches = list(dict.fromkeys(matches))
    for cve_id in matches: # get CVE info
        vuln = cve_to_vuln(cve_id, vuln_type='nmap-vulners-nse')
        if vuln:
            vulns.append(vuln)
    return vulns


def cve_to_vuln(cve_id, vuln_type=''):
    """Search for a CVE using CVESearch and return Vulnerability data.

    Args:
        cve_id (str): CVE ID in the form CVE-*

    Returns:
        dict: Vulnerability dict.
    """
    cve_info = CVESearch('https://cve.circl.lu').id(cve_id)
    if not cve_info:
        logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
        return None
    vuln_cve_id = cve_info['id']
    vuln_name = vuln_cve_id
    vuln_description = cve_info.get('summary', 'none').replace(vuln_cve_id, '').strip()
    try:
        vuln_cvss = float(cve_info.get('cvss', -1))
    except (ValueError, TypeError):
        vuln_cvss = -1
    vuln_cwe_id = cve_info.get('cwe', '')
    exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
    osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])
    references = cve_info.get('references', [])
    capec_objects = cve_info.get('capec', [])

    # Parse ovals for a better vuln name / type
    ovals = cve_info.get('oval', [])
    if ovals:
        vuln_name = ovals[0]['title']
        vuln_type = ovals[0]['family']

    # Set vulnerability severity based on CVSS score
    vuln_severity = 'info'
    if vuln_cvss < 4:
        vuln_severity = 'low'
    elif vuln_cvss < 7:
        vuln_severity = 'medium'
    elif vuln_cvss < 9:
        vuln_severity = 'high'
    else:
        vuln_severity = 'critical'

    # Build console warning message
    msg = f'{vuln_name} | {vuln_severity.upper()} | {vuln_cve_id} | {vuln_cwe_id} | {vuln_cvss}'
    for id in osvdb_ids:
        msg += f'\n\tOSVDB: {id}'
    for exploit_id in exploit_ids:
        msg += f'\n\tEXPLOITDB: {exploit_id}'
    logger.warning(msg)
    vuln = {
        'name': vuln_name,
        'type': vuln_type,
        'severity': NUCLEI_SEVERITY_MAP[vuln_severity],
        'description': vuln_description,
        'cvss_score': vuln_cvss,
        'references': references,
        'cve_ids': [vuln_cve_id],
        'cwe_ids': [vuln_cwe_id]
    }
    return vuln


def parse_s3scanner_result(line):
    '''
        Parses and returns s3Scanner Data
    '''
    bucket = line['bucket']
    return {
        'name': bucket['name'],
        'region': bucket['region'],
        'provider': bucket['provider'],
        'owner_display_name': bucket['owner_display_name'],
        'owner_id': bucket['owner_id'],
        'perm_auth_users_read': bucket['perm_auth_users_read'],
        'perm_auth_users_write': bucket['perm_auth_users_write'],
        'perm_auth_users_read_acl': bucket['perm_auth_users_read_acl'],
        'perm_auth_users_write_acl': bucket['perm_auth_users_write_acl'],
        'perm_auth_users_full_control': bucket['perm_auth_users_full_control'],
        'perm_all_users_read': bucket['perm_all_users_read'],
        'perm_all_users_write': bucket['perm_all_users_write'],
        'perm_all_users_read_acl': bucket['perm_all_users_read_acl'],
        'perm_all_users_write_acl': bucket['perm_all_users_write_acl'],
        'perm_all_users_full_control': bucket['perm_all_users_full_control'],
        'num_objects': bucket['num_objects'],
        'size': bucket['bucket_size']
    }

def parse_nuclei_result(line):
    """Parse results from nuclei JSON output.

    Args:
        line (dict): Nuclei JSON line output.

    Returns:
        dict: Vulnerability data.
    """
    return {
        'name': line.get('info', {}).get('name', ''),
        'type': line.get('type', ''),
        'severity': NUCLEI_SEVERITY_MAP.get(line.get('info', {}).get('severity', 'unknown'), 0),
        'template': line.get('template-path', '').replace(NUCLEI_DEFAULT_TEMPLATES_PATH + '/', ''),
        'template_url': line.get('template-url', ''),
        'template_id': line.get('template-id', ''),
        'description': line.get('info', {}).get('description', ''),
        'matcher_name': line.get('matcher-name', ''),
        'curl_command': line.get('curl-command'),
        'request': html.escape(line.get('request', '')),
        'response': html.escape(line.get('response', '')),
        'extracted_results': line.get('extracted-results', []),
        'cvss_metrics': line.get('info', {}).get('classification', {}).get('cvss-metrics', ''),
        'cvss_score': line.get('info', {}).get('classification', {}).get('cvss-score'),
        'cve_ids': line.get('info', {}).get('classification', {}).get('cve_id', []) or [],
        'cwe_ids': line.get('info', {}).get('classification', {}).get('cwe_id', []) or [],
        'references': line.get('info', {}).get('reference', []) or [],
        'tags': line.get('info', {}).get('tags', []),
        'source': NUCLEI,
    }

def parse_dalfox_result(line):
    """Parse results from nuclei JSON output.

    Args:
        line (dict): Nuclei JSON line output.

    Returns:
        dict: Vulnerability data.
    """

    description = ''
    description += f" Evidence: {line.get('evidence')} <br>" if line.get('evidence') else ''
    description += f" Message: {line.get('message')} <br>" if line.get('message') else ''
    description += f" Payload: {line.get('message_str')} <br>" if line.get('message_str') else ''
    description += f" Vulnerable Parameter: {line.get('param')} <br>" if line.get('param') else ''

    return {
        'name': 'XSS (Cross Site Scripting)',
        'type': 'XSS',
        'severity': DALFOX_SEVERITY_MAP[line.get('severity', 'unknown')],
        'description': description,
        'source': DALFOX,
        'cwe_ids': [line.get('cwe')]
    }


def parse_crlfuzz_result(url):
    """Parse CRLF results

    Args:
        url (str): CRLF Vulnerable URL

    Returns:
        dict: Vulnerability data.
    """

    return {
        'name': 'CRLF (HTTP Response Splitting)',
        'type': 'CRLF',
        'severity': 2,
        'description': 'A CRLF (HTTP Response Splitting) vulnerability has been discovered.',
        'source': CRLFUZZ,
    }


def record_exists(model, data, exclude_keys=[]):
    """
    Check if a record already exists in the database based on the given data.

    Args:
        model (django.db.models.Model): The Django model to check against.
        data (dict): Data dictionary containing fields and values.
        exclude_keys (list): List of keys to exclude from the lookup.

    Returns:
        bool: True if the record exists, False otherwise.
    """
    def clean_request(request_str):
        if not request_str:
            return request_str
        request_lines = request_str.split('\r\n')
        cleaned_lines = [line for line in request_lines if not line.startswith('User-Agent:')]
        return '\r\n'.join(cleaned_lines)

    # Extract the keys that will be used for the lookup
    lookup_fields = data.copy()
    
    # Clean the request field if it contains a User-Agent line
    if 'request' in lookup_fields:
        lookup_fields['request'] = clean_request(lookup_fields['request'])

    # Remove the fields to exclude
    lookup_fields = {key: lookup_fields[key] for key in lookup_fields if key not in exclude_keys}

    # Get all existing records that might match
    base_query = {key: value for key, value in lookup_fields.items() if key != 'request'}
    existing_records = model.objects.filter(**base_query)
    
    if not existing_records.exists():
        logger.debug(f"No existing records found with lookup fields: {lookup_fields}")
        return False
    
    # For each existing record, log the differences
    for record in existing_records:
        differences = {}
        for key, value in lookup_fields.items():
            existing_value = getattr(record, key)
            if key == 'request':
                existing_value = clean_request(existing_value)
            if existing_value != value:
                differences[key] = {
                    'existing': existing_value,
                    'new': value
                }
        
        if differences:
            logger.debug(f"Record {record.id} has differences: {differences}")
        else:
            logger.debug(f"Record {record.id} matches exactly with lookup fields: {lookup_fields}")
            return True
            
    return False

@app.task(name='geo_localize', bind=False, queue='geo_localize_queue')
def geo_localize(host, ip_id=None):
    """Uses geoiplookup to find location associated with host.

    Args:
        host (str): Hostname.
        ip_id (int): IpAddress object id.

    Returns:
        startScan.models.CountryISO: CountryISO object from DB or None.
    """
    if validators.ipv6(host):
        logger.info(f'Ipv6 "{host}" is not supported by geoiplookup. Skipping.')
        return None
    cmd = f'geoiplookup {host}'
    _, out = run_command(cmd)
    if 'IP Address not found' not in out and "can't resolve hostname" not in out:
        country_iso = out.split(':')[1].strip().split(',')[0]
        country_name = out.split(':')[1].strip().split(',')[1].strip()
        geo_object, _ = CountryISO.objects.get_or_create(
            iso=country_iso,
            name=country_name
        )
        geo_json = {
            'iso': country_iso,
            'name': country_name
        }
        if ip_id:
            ip = IpAddress.objects.get(pk=ip_id)
            ip.geo_iso = geo_object
            ip.save()
        return geo_json
    logger.info(f'Geo IP lookup failed for host "{host}"')
    return None


@app.task(name='query_whois', bind=False, queue='query_whois_queue')
def query_whois(ip_domain, force_reload_whois=False):
    """Query WHOIS information for an IP or a domain name.

    Args:
        ip_domain (str): IP address or domain name.
        save_domain (bool): Whether to save domain or not, default False
    Returns:
        dict: WHOIS information.
    """
    if not force_reload_whois and Domain.objects.filter(name=ip_domain).exists() and Domain.objects.get(name=ip_domain).domain_info:
        domain = Domain.objects.get(name=ip_domain)
        if not domain.insert_date:
            domain.insert_date = timezone.now()
            domain.save()
        domain_info_db = domain.domain_info
        domain_info = DottedDict(
            dnssec=domain_info_db.dnssec,
            created=domain_info_db.created,
            updated=domain_info_db.updated,
            expires=domain_info_db.expires,
            geolocation_iso=domain_info_db.geolocation_iso,
            status=[status['name'] for status in DomainWhoisStatusSerializer(domain_info_db.status, many=True).data],
            whois_server=domain_info_db.whois_server,
            ns_records=[ns['name'] for ns in NameServersSerializer(domain_info_db.name_servers, many=True).data],
            registrar_name=domain_info_db.registrar.name,
            registrar_phone=domain_info_db.registrar.phone,
            registrar_email=domain_info_db.registrar.email,
            registrar_url=domain_info_db.registrar.url,
            registrant_name=domain_info_db.registrant.name,
            registrant_id=domain_info_db.registrant.id_str,
            registrant_organization=domain_info_db.registrant.organization,
            registrant_city=domain_info_db.registrant.city,
            registrant_state=domain_info_db.registrant.state,
            registrant_zip_code=domain_info_db.registrant.zip_code,
            registrant_country=domain_info_db.registrant.country,
            registrant_phone=domain_info_db.registrant.phone,
            registrant_fax=domain_info_db.registrant.fax,
            registrant_email=domain_info_db.registrant.email,
            registrant_address=domain_info_db.registrant.address,
            admin_name=domain_info_db.admin.name,
            admin_id=domain_info_db.admin.id_str,
            admin_organization=domain_info_db.admin.organization,
            admin_city=domain_info_db.admin.city,
            admin_state=domain_info_db.admin.state,
            admin_zip_code=domain_info_db.admin.zip_code,
            admin_country=domain_info_db.admin.country,
            admin_phone=domain_info_db.admin.phone,
            admin_fax=domain_info_db.admin.fax,
            admin_email=domain_info_db.admin.email,
            admin_address=domain_info_db.admin.address,
            tech_name=domain_info_db.tech.name,
            tech_id=domain_info_db.tech.id_str,
            tech_organization=domain_info_db.tech.organization,
            tech_city=domain_info_db.tech.city,
            tech_state=domain_info_db.tech.state,
            tech_zip_code=domain_info_db.tech.zip_code,
            tech_country=domain_info_db.tech.country,
            tech_phone=domain_info_db.tech.phone,
            tech_fax=domain_info_db.tech.fax,
            tech_email=domain_info_db.tech.email,
            tech_address=domain_info_db.tech.address,
            related_tlds=[domain['name'] for domain in RelatedDomainSerializer(domain_info_db.related_tlds, many=True).data],
            related_domains=[domain['name'] for domain in RelatedDomainSerializer(domain_info_db.related_domains, many=True).data],
            historical_ips=[ip for ip in HistoricalIPSerializer(domain_info_db.historical_ips, many=True).data],
        )
        if domain_info_db.dns_records:
            a_records = []
            txt_records = []
            mx_records = []
            dns_records = [{'name': dns['name'], 'type': dns['type']} for dns in DomainDNSRecordSerializer(domain_info_db.dns_records, many=True).data]
            for dns in dns_records:
                if dns['type'] == 'a':
                    a_records.append(dns['name'])
                elif dns['type'] == 'txt':
                    txt_records.append(dns['name'])
                elif dns['type'] == 'mx':
                    mx_records.append(dns['name'])
            domain_info.a_records = a_records
            domain_info.txt_records = txt_records
            domain_info.mx_records = mx_records
    else:
        logger.info(f'Domain info for "{ip_domain}" not found in DB, querying whois')
        domain_info = DottedDict()
        # find domain historical ip
        try:
            historical_ips = get_domain_historical_ip_address(ip_domain)
            domain_info.historical_ips = historical_ips
        except Exception as e:
            logger.error(f'HistoricalIP for {ip_domain} not found!\nError: {str(e)}')
            historical_ips = []
        # find associated domains using ip_domain
        try:
            related_domains = reverse_whois(ip_domain.split('.')[0])
        except Exception as e:
            logger.error(f'Associated domain not found for {ip_domain}\nError: {str(e)}')
            similar_domains = []
        # find related tlds using TLSx
        try:
            related_tlds = []
            output_path = '/tmp/ip_domain_tlsx.txt'
            tlsx_command = f'tlsx -san -cn -silent -ro -host {ip_domain} -o {output_path}'
            run_command(
                tlsx_command,
                shell=True,
            )
            tlsx_output = []
            with open(output_path) as f:
                tlsx_output = f.readlines()

            tldextract_target = tldextract.extract(ip_domain)
            for doms in tlsx_output:
                doms = doms.strip()
                tldextract_res = tldextract.extract(doms)
                if ip_domain != doms and tldextract_res.domain == tldextract_target.domain and tldextract_res.subdomain == '':
                    related_tlds.append(doms)

            related_tlds = list(set(related_tlds))
            domain_info.related_tlds = related_tlds
        except Exception as e:
            logger.error(f'Associated domain not found for {ip_domain}\nError: {str(e)}')
            similar_domains = []

        related_domains_list = []
        if Domain.objects.filter(name=ip_domain).exists():
            domain = Domain.objects.get(name=ip_domain)
            db_domain_info = domain.domain_info if domain.domain_info else DomainInfo()
            db_domain_info.save()
            for _domain in related_domains:
                domain_related = RelatedDomain.objects.get_or_create(
                    name=_domain['name'],
                )[0]
                db_domain_info.related_domains.add(domain_related)
                related_domains_list.append(_domain['name'])

            for _domain in related_tlds:
                domain_related = RelatedDomain.objects.get_or_create(
                    name=_domain,
                )[0]
                db_domain_info.related_tlds.add(domain_related)

            for _ip in historical_ips:
                historical_ip = HistoricalIP.objects.get_or_create(
                    ip=_ip['ip'],
                    owner=_ip['owner'],
                    location=_ip['location'],
                    last_seen=_ip['last_seen'],
                )[0]
                db_domain_info.historical_ips.add(historical_ip)
            domain.domain_info = db_domain_info
            domain.save()

        command = f'netlas host {ip_domain} -f json'
        # check if netlas key is provided
        netlas_key = get_netlas_key()
        command += f' -a {netlas_key}' if netlas_key else ''

        result = subprocess.check_output(command.split()).decode('utf-8')
        if 'Failed to parse response data' in result:
            # do fallback
            return {
                'status': False,
                'ip_domain': ip_domain,
                'result': "Netlas limit exceeded.",
                'message': 'Netlas limit exceeded.'
            }
        try:
            result = json.loads(result)
            logger.info(result)
            whois = result.get('whois') if result.get('whois') else {}

            domain_info.created = whois.get('created_date')
            domain_info.expires = whois.get('expiration_date')
            domain_info.updated = whois.get('updated_date')
            domain_info.whois_server = whois.get('whois_server')


            if 'registrant' in whois:
                registrant = whois.get('registrant')
                domain_info.registrant_name = registrant.get('name')
                domain_info.registrant_country = registrant.get('country')
                domain_info.registrant_id = registrant.get('id')
                domain_info.registrant_state = registrant.get('province')
                domain_info.registrant_city = registrant.get('city')
                domain_info.registrant_phone = registrant.get('phone')
                domain_info.registrant_address = registrant.get('street')
                domain_info.registrant_organization = registrant.get('organization')
                domain_info.registrant_fax = registrant.get('fax')
                domain_info.registrant_zip_code = registrant.get('postal_code')
                email_search = EMAIL_REGEX.search(str(registrant.get('email')))
                field_content = email_search.group(0) if email_search else None
                domain_info.registrant_email = field_content

            if 'administrative' in whois:
                administrative = whois.get('administrative')
                domain_info.admin_name = administrative.get('name')
                domain_info.admin_country = administrative.get('country')
                domain_info.admin_id = administrative.get('id')
                domain_info.admin_state = administrative.get('province')
                domain_info.admin_city = administrative.get('city')
                domain_info.admin_phone = administrative.get('phone')
                domain_info.admin_address = administrative.get('street')
                domain_info.admin_organization = administrative.get('organization')
                domain_info.admin_fax = administrative.get('fax')
                domain_info.admin_zip_code = administrative.get('postal_code')
                mail_search = EMAIL_REGEX.search(str(administrative.get('email')))
                field_content = email_search.group(0) if email_search else None
                domain_info.admin_email = field_content

            if 'technical' in whois:
                technical = whois.get('technical')
                domain_info.tech_name = technical.get('name')
                domain_info.tech_country = technical.get('country')
                domain_info.tech_state = technical.get('province')
                domain_info.tech_id = technical.get('id')
                domain_info.tech_city = technical.get('city')
                domain_info.tech_phone = technical.get('phone')
                domain_info.tech_address = technical.get('street')
                domain_info.tech_organization = technical.get('organization')
                domain_info.tech_fax = technical.get('fax')
                domain_info.tech_zip_code = technical.get('postal_code')
                mail_search = EMAIL_REGEX.search(str(technical.get('email')))
                field_content = email_search.group(0) if email_search else None
                domain_info.tech_email = field_content

            if 'dns' in result:
                dns = result.get('dns')
                domain_info.mx_records = dns.get('mx')
                domain_info.txt_records = dns.get('txt')
                domain_info.a_records = dns.get('a')

            domain_info.ns_records = whois.get('name_servers')
            domain_info.dnssec = True if whois.get('dnssec') else False
            domain_info.status = whois.get('status')

            if 'registrar' in whois:
                registrar = whois.get('registrar')
                domain_info.registrar_name = registrar.get('name')
                domain_info.registrar_email = registrar.get('email')
                domain_info.registrar_phone = registrar.get('phone')
                domain_info.registrar_url = registrar.get('url')

            # find associated domains if registrant email is found
            related_domains = reverse_whois(domain_info.get('registrant_email')) if domain_info.get('registrant_email') else []
            for _domain in related_domains:
                related_domains_list.append(_domain['name'])

            # remove duplicate domains from related domains list
            related_domains_list = list(set(related_domains_list))
            domain_info.related_domains = related_domains_list

            # save to db if domain exists
            if Domain.objects.filter(name=ip_domain).exists():
                domain = Domain.objects.get(name=ip_domain)
                db_domain_info = domain.domain_info if domain.domain_info else DomainInfo()
                db_domain_info.save()
                for _domain in related_domains:
                    domain_rel = RelatedDomain.objects.get_or_create(
                        name=_domain['name'],
                    )[0]
                    db_domain_info.related_domains.add(domain_rel)

                db_domain_info.dnssec = domain_info.get('dnssec')
                #dates
                db_domain_info.created = domain_info.get('created')
                db_domain_info.updated = domain_info.get('updated')
                db_domain_info.expires = domain_info.get('expires')
                #registrar
                db_domain_info.registrar = Registrar.objects.get_or_create(
                    name=domain_info.get('registrar_name'),
                    email=domain_info.get('registrar_email'),
                    phone=domain_info.get('registrar_phone'),
                    url=domain_info.get('registrar_url'),
                )[0]
                db_domain_info.registrant = DomainRegistration.objects.get_or_create(
                    name=domain_info.get('registrant_name'),
                    organization=domain_info.get('registrant_organization'),
                    address=domain_info.get('registrant_address'),
                    city=domain_info.get('registrant_city'),
                    state=domain_info.get('registrant_state'),
                    zip_code=domain_info.get('registrant_zip_code'),
                    country=domain_info.get('registrant_country'),
                    email=domain_info.get('registrant_email'),
                    phone=domain_info.get('registrant_phone'),
                    fax=domain_info.get('registrant_fax'),
                    id_str=domain_info.get('registrant_id'),
                )[0]
                db_domain_info.admin = DomainRegistration.objects.get_or_create(
                    name=domain_info.get('admin_name'),
                    organization=domain_info.get('admin_organization'),
                    address=domain_info.get('admin_address'),
                    city=domain_info.get('admin_city'),
                    state=domain_info.get('admin_state'),
                    zip_code=domain_info.get('admin_zip_code'),
                    country=domain_info.get('admin_country'),
                    email=domain_info.get('admin_email'),
                    phone=domain_info.get('admin_phone'),
                    fax=domain_info.get('admin_fax'),
                    id_str=domain_info.get('admin_id'),
                )[0]
                db_domain_info.tech = DomainRegistration.objects.get_or_create(
                    name=domain_info.get('tech_name'),
                    organization=domain_info.get('tech_organization'),
                    address=domain_info.get('tech_address'),
                    city=domain_info.get('tech_city'),
                    state=domain_info.get('tech_state'),
                    zip_code=domain_info.get('tech_zip_code'),
                    country=domain_info.get('tech_country'),
                    email=domain_info.get('tech_email'),
                    phone=domain_info.get('tech_phone'),
                    fax=domain_info.get('tech_fax'),
                    id_str=domain_info.get('tech_id'),
                )[0]
                for status in domain_info.get('status') or []:
                    _status = WhoisStatus.objects.get_or_create(
                        name=status
                    )[0]
                    _status.save()
                    db_domain_info.status.add(_status)

                for ns in domain_info.get('ns_records') or []:
                    _ns = NameServer.objects.get_or_create(
                        name=ns
                    )[0]
                    _ns.save()
                    db_domain_info.name_servers.add(_ns)

                for a in domain_info.get('a_records') or []:
                    _a = DNSRecord.objects.get_or_create(
                        name=a,
                        type='a'
                    )[0]
                    _a.save()
                    db_domain_info.dns_records.add(_a)
                for mx in domain_info.get('mx_records') or []:
                    _mx = DNSRecord.objects.get_or_create(
                        name=mx,
                        type='mx'
                    )[0]
                    _mx.save()
                    db_domain_info.dns_records.add(_mx)
                for txt in domain_info.get('txt_records') or []:
                    _txt = DNSRecord.objects.get_or_create(
                        name=txt,
                        type='txt'
                    )[0]
                    _txt.save()
                    db_domain_info.dns_records.add(_txt)

                db_domain_info.geolocation_iso = domain_info.get('registrant_country')
                db_domain_info.whois_server = domain_info.get('whois_server')
                db_domain_info.save()
                domain.domain_info = db_domain_info
                domain.save()

        except Exception as e:
            return {
                'status': False,
                'ip_domain': ip_domain,
                'result': "unable to fetch records from WHOIS database.",
                'message': str(e)
            }

    return {
        'status': True,
        'ip_domain': ip_domain,
        'dnssec': domain_info.get('dnssec'),
        'created': domain_info.get('created'),
        'updated': domain_info.get('updated'),
        'expires': domain_info.get('expires'),
        'geolocation_iso': domain_info.get('registrant_country'),
        'domain_statuses': domain_info.get('status'),
        'whois_server': domain_info.get('whois_server'),
        'dns': {
            'a': domain_info.get('a_records'),
            'mx': domain_info.get('mx_records'),
            'txt': domain_info.get('txt_records'),
        },
        'registrar': {
            'name': domain_info.get('registrar_name'),
            'phone': domain_info.get('registrar_phone'),
            'email': domain_info.get('registrar_email'),
            'url': domain_info.get('registrar_url'),
        },
        'registrant': {
            'name': domain_info.get('registrant_name'),
            'id': domain_info.get('registrant_id'),
            'organization': domain_info.get('registrant_organization'),
            'address': domain_info.get('registrant_address'),
            'city': domain_info.get('registrant_city'),
            'state': domain_info.get('registrant_state'),
            'zipcode': domain_info.get('registrant_zip_code'),
            'country': domain_info.get('registrant_country'),
            'phone': domain_info.get('registrant_phone'),
            'fax': domain_info.get('registrant_fax'),
            'email': domain_info.get('registrant_email'),
        },
        'admin': {
            'name': domain_info.get('admin_name'),
            'id': domain_info.get('admin_id'),
            'organization': domain_info.get('admin_organization'),
            'address':domain_info.get('admin_address'),
            'city': domain_info.get('admin_city'),
            'state': domain_info.get('admin_state'),
            'zipcode': domain_info.get('admin_zip_code'),
            'country': domain_info.get('admin_country'),
            'phone': domain_info.get('admin_phone'),
            'fax': domain_info.get('admin_fax'),
            'email': domain_info.get('admin_email'),
        },
        'technical_contact': {
            'name': domain_info.get('tech_name'),
            'id': domain_info.get('tech_id'),
            'organization': domain_info.get('tech_organization'),
            'address': domain_info.get('tech_address'),
            'city': domain_info.get('tech_city'),
            'state': domain_info.get('tech_state'),
            'zipcode': domain_info.get('tech_zip_code'),
            'country': domain_info.get('tech_country'),
            'phone': domain_info.get('tech_phone'),
            'fax': domain_info.get('tech_fax'),
            'email': domain_info.get('tech_email'),
        },
        'nameservers': domain_info.get('ns_records'),
        # 'similar_domains': domain_info.get('similar_domains'),
        'related_domains': domain_info.get('related_domains'),
        'related_tlds': domain_info.get('related_tlds'),
        'historical_ips': domain_info.get('historical_ips'),
    }


@app.task(name='remove_duplicate_endpoints', bind=False, queue='remove_duplicate_endpoints_queue')
def remove_duplicate_endpoints(
        scan_history_id,
        domain_id,
        subdomain_id=None,
        filter_ids=[],
        # TODO Check if the status code could be set as parameters of the scan engine instead of hardcoded values
        filter_status=[200, 301, 302, 303, 307, 404, 410],  # Extended status codes
        duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS
    ):
    """Remove duplicate endpoints.

    Check for implicit redirections by comparing endpoints:
    - [x] `content_length` similarities indicating redirections
    - [x] `page_title` (check for same page title)
    - [ ] Sign-in / login page (check for endpoints with the same words)

    Args:
        scan_history_id: ScanHistory id.
        domain_id (int): Domain id.
        subdomain_id (int, optional): Subdomain id.
        filter_ids (list): List of endpoint ids to filter on.
        filter_status (list): List of HTTP status codes to filter on.
        duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates
    """
    logger.info(f'Removing duplicate endpoints based on {duplicate_removal_fields}')
    
    # Filter endpoints based on scan history and domain
    endpoints = (
        EndPoint.objects
        .filter(scan_history__id=scan_history_id)
        .filter(target_domain__id=domain_id)
    )
    if filter_status:
        endpoints = endpoints.filter(http_status__in=filter_status)

    if subdomain_id:
        endpoints = endpoints.filter(subdomain__id=subdomain_id)

    if filter_ids:
        endpoints = endpoints.filter(id__in=filter_ids)

    # Group by all duplicate removal fields combined
    fields_combined = duplicate_removal_fields[:]
    fields_combined.append('id')  # Add ID to ensure unique identification

    cl_query = (
        endpoints
        .values(*duplicate_removal_fields)
        .annotate(mc=Count('id'))
        .order_by('-mc')
    )

    for field_values in cl_query:
        if field_values['mc'] > DELETE_DUPLICATES_THRESHOLD:
            filter_criteria = {field: field_values[field] for field in duplicate_removal_fields}
            eps_to_delete = (
                endpoints
                .filter(**filter_criteria)
                .order_by('discovered_date')
                .all()[1:]
            )
            msg = f'Deleting {len(eps_to_delete)} endpoints [reason: same {filter_criteria}]'
            for ep in eps_to_delete:
                url = urlparse(ep.http_url)
                if url.path in ['', '/', '/login']:  # Ensure not to delete the original page that other pages redirect to
                    continue
                msg += f'\n\t {ep.http_url} [{ep.http_status}] {filter_criteria}'
                ep.delete()
            logger.warning(msg)


@app.task(name='run_command', bind=False, queue='run_command_queue')
def run_command(cmd, cwd=None, shell=False, history_file=None, scan_id=None, activity_id=None, remove_ansi_sequence=False):
    """
    Execute a command and return its output.

    Args:
        cmd (str): The command to execute.
        cwd (str, optional): The working directory for the command. Defaults to None.
        shell (bool, optional): Whether to use shell execution. Defaults to False.
        history_file (str, optional): File to write command history. Defaults to None.
        scan_id (int, optional): ID of the associated scan. Defaults to None.
        activity_id (int, optional): ID of the associated activity. Defaults to None.
        remove_ansi_sequence (bool, optional): Whether to remove ANSI escape sequences from output. Defaults to False.

    Returns:
        tuple: A tuple containing the return code and output of the command.
    """
    logger.info(f"Starting execution of command: {cmd}")
    command_obj = create_command_object(cmd, scan_id, activity_id)
    command = prepare_command(cmd, shell)
    logger.debug(f"Prepared run command: {command}")
    
    process = execute_command(command, shell, cwd)
    output, error_output = process.communicate()
    return_code = process.returncode

    if output:
        output = re.sub(r'\x1b\[[0-9;]*[mGKH]', '', output) if remove_ansi_sequence else output 
    
    if return_code != 0:
        error_msg = f"Command failed with exit code {return_code}"
        if error_output:
            error_msg += f"\nError output:\n{error_output}"
        logger.error(error_msg)
        
    command_obj.output = output or None
    command_obj.error_output = error_output or None
    command_obj.return_code = return_code
    command_obj.save()
    
    if history_file:
        write_history(history_file, cmd, return_code, output)
    
    return return_code, output

def stream_command(cmd, cwd=None, shell=False, history_file=None, encoding='utf-8', scan_id=None, activity_id=None, trunc_char=None):
    """
    Execute a command and yield its output line by line in real-time.
    
    This function uses select.select() to monitor file descriptors and processes
    output as soon as it becomes available, ensuring proper streaming behavior
    for tools like httpx and nuclei.

    Args:
        cmd (str): The command to execute.
        cwd (str, optional): The working directory for the command. Defaults to None.
        shell (bool, optional): Whether to use shell execution. Defaults to False.
        history_file (str, optional): File to write command history. Defaults to None.
        encoding (str, optional): Encoding for the command output. Defaults to 'utf-8'.
        scan_id (int, optional): ID of the associated scan. Defaults to None.
        activity_id (int, optional): ID of the associated activity. Defaults to None.
        trunc_char (str, optional): Character to truncate lines. Defaults to None.

    Yields:
        str or dict: Each line of the command output, processed and potentially parsed as JSON.
    """
    logger.info(f"Starting real-time execution of command: {cmd}")
    command_obj = create_command_object(cmd, scan_id, activity_id)
    command = prepare_command(cmd, shell)
    logger.debug(f"Prepared stream command: {command}")
    
    # Execute command with line buffering for better streaming
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=shell,
        cwd=cwd,
        bufsize=1,  # Line buffered
        universal_newlines=True,
        encoding=encoding
    )
    
    # Initialize buffers and tracking variables
    stdout_buffer = ""
    stderr_buffer = ""
    full_output = ""
    full_error = ""
    
    # Use select for real-time streaming on Linux
    while True:
        # Check if process has terminated
        if process.poll() is not None:
            # Read any remaining data
            remaining_stdout = process.stdout.read()
            remaining_stderr = process.stderr.read()
            
            if remaining_stdout:
                stdout_buffer += remaining_stdout
                full_output += remaining_stdout
            if remaining_stderr:
                stderr_buffer += remaining_stderr
                full_error += remaining_stderr
            
            # Process any remaining complete lines
            while '\n' in stdout_buffer:
                line, stdout_buffer = stdout_buffer.split('\n', 1)
                if line.strip():
                    try:
                        item = process_line(line, trunc_char)
                        if item:
                            yield item
                    except Exception as e:
                        logger.error(f"Error processing output line: {e}")
            break
        
        # Use select to wait for data availability
        try:
            ready, _, _ = select.select([process.stdout, process.stderr], [], [], 0.1)
            
            for fd in ready:
                try:
                    data = fd.read(1024)
                    if data:
                        if fd == process.stdout:
                            stdout_buffer += data
                            full_output += data
                            
                            # Process complete lines immediately
                            while '\n' in stdout_buffer:
                                line, stdout_buffer = stdout_buffer.split('\n', 1)
                                if line.strip():
                                    try:
                                        item = process_line(line, trunc_char)
                                        if item:
                                            yield item
                                    except Exception as e:
                                        logger.error(f"Error processing output line: {e}")
                        else:
                            stderr_buffer += data
                            full_error += data
                except Exception as e:
                    logger.debug(f"Error reading from file descriptor: {e}")
                    continue
                    
        except Exception as e:
            logger.debug(f"Select error: {e}")
            # Fallback to simple polling if select fails
            time.sleep(0.1)
    
    # Wait for process completion
    process.wait()
    return_code = process.returncode
    
    # Log completion status
    if return_code != 0:
        error_msg = f"Command failed with exit code {return_code}"
        if full_error:
            error_msg += f"\nError output:\n{full_error}"
        logger.error(error_msg)
    else:
        logger.info(f"Command completed successfully with exit code {return_code}")
    
    # Save command results
    command_obj.output = full_output or None
    command_obj.error_output = full_error or None
    command_obj.return_code = return_code
    command_obj.save()
    
    logger.debug(f'Command returned exit code: {return_code}')

    # Write history if requested
    if history_file:
        write_history(history_file, cmd, return_code, full_output)

def process_httpx_response(line):
    """TODO: implement this"""


def extract_httpx_url(line, follow_redirect):
    """Extract final URL from httpx results.

    Args:
        line (dict): URL data output by httpx.

    Returns:
        tuple: (final_url, redirect_bool) tuple.
    """
    status_code = line.get('status_code', 0)
    final_url = line.get('final_url')
    location = line.get('location')
    chain_status_codes = line.get('chain_status_codes', [])
    http_url = line.get('url')

    # Final URL is already looking nice, if it exists and follow redirect is enabled, return it
    if final_url and follow_redirect:
        return final_url, False

    # Handle redirects manually if follow redirect is enabled
    if follow_redirect:
        REDIRECT_STATUS_CODES = [301, 302]
        is_redirect = (
            status_code in REDIRECT_STATUS_CODES
            or
            any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)
        )
        if is_redirect and location:
            if location.startswith(('http', 'https')):
                http_url = location
            else:
                http_url = f'{http_url}/{location.lstrip("/")}'
    else:
        is_redirect = False

    # Sanitize URL
    http_url = sanitize_url(http_url)

    return http_url, is_redirect


#-------------#
# OSInt utils #
#-------------#

def get_and_save_dork_results(lookup_target, results_dir, type, lookup_keywords=None, lookup_extensions=None, delay=3, page_count=2, scan_history=None):
    """
        Uses gofuzz to dork and store information

        Args:
            lookup_target (str): target to look into such as stackoverflow or even the target itself
            results_dir (str): Results directory
            type (str): Dork Type Title
            lookup_keywords (str): comma separated keywords or paths to look for
            lookup_extensions (str): comma separated extensions to look for
            delay (int): delay between each requests
            page_count (int): pages in google to extract information
            scan_history (startScan.ScanHistory): Scan History Object
    """
    results = []
    gofuzz_command = f'{GOFUZZ_EXEC_PATH} -t {lookup_target} -d {delay} -p {page_count}'

    if lookup_extensions:
        gofuzz_command += f' -e {lookup_extensions}'
    elif lookup_keywords:
        gofuzz_command += f' -w {lookup_keywords}'

    output_file = str(Path(results_dir) / 'gofuzz.txt')
    gofuzz_command += f' -o {output_file}'
    history_file = str(Path(results_dir) / 'commands.txt')

    try:
        run_command(
            gofuzz_command,
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id,
        )

        if not os.path.isfile(output_file):
            return

        with open(output_file) as f:
            for line in f.readlines():
                url = line.strip()
                if url:
                    results.append(url)
                    dork, created = Dork.objects.get_or_create(
                        type=type,
                        url=url
                    )
                    if scan_history:
                        scan_history.dorks.add(dork)

        # remove output file
        os.remove(output_file)

    except Exception as e:
        logger.exception(e)

    return results


def get_and_save_emails(scan_history, activity_id, results_dir):
    """Get and save emails from Google, Bing and Baidu.

    Args:
        scan_history (startScan.ScanHistory): Scan history object.
        activity_id: ScanActivity Object
        results_dir (str): Results directory.

    Returns:
        list: List of emails found.
    """
    emails = []

    # Proxy settings
    # get_random_proxy()

    # Gather emails from Google, Bing and Baidu
    output_file = str(Path(results_dir) / 'emails_tmp.txt')
    history_file = str(Path(results_dir) / 'commands.txt')
    command = f'infoga --domain {scan_history.domain.name} --source all --report {output_file}'
    try:
        run_command(
            command,
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id,
            activity_id=activity_id)

        if not os.path.isfile(output_file):
            logger.info('No Email results')
            return []

        with open(output_file) as f:
            for line in f.readlines():
                if 'Email' in line:
                    split_email = line.split(' ')[2]
                    emails.append(split_email)

        output_path = str(Path(results_dir) / 'emails.txt')
        with open(output_path, 'w') as output_file:
            for email_address in emails:
                save_email(email_address, scan_history)
                output_file.write(f'{email_address}\n')

    except Exception as e:
        logger.exception(e)
    return emails


def save_metadata_info(meta_dict):
    """Extract metadata from Google Search.

    Args:
        meta_dict (dict): Info dict.

    Returns:
        list: List of startScan.MetaFinderDocument objects.
    """
    logger.warning(f'Getting metadata for {meta_dict.osint_target}')

    scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

    # Proxy settings
    get_random_proxy()

    # Get metadata
    result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
    if not result:
        logger.error(f'No metadata result from Google Search for {meta_dict.osint_target}.')
        return []

    # Add metadata info to DB
    results = []
    for metadata_name, data in result.get_metadata().items():
        subdomain = Subdomain.objects.get(
            scan_history=meta_dict.scan_id,
            name=meta_dict.osint_target)
        metadata = DottedDict({k: v for k, v in data.items()})
        meta_finder_document = MetaFinderDocument(
            subdomain=subdomain,
            target_domain=meta_dict.domain,
            scan_history=scan_history,
            url=metadata.url,
            doc_name=metadata_name,
            http_status=metadata.status_code,
            producer=metadata.metadata.get('Producer'),
            creator=metadata.metadata.get('Creator'),
            creation_date=metadata.metadata.get('CreationDate'),
            modified_date=metadata.metadata.get('ModDate'),
            author=metadata.metadata.get('Author'),
            title=metadata.metadata.get('Title'),
            os=metadata.metadata.get('OSInfo'))
        meta_finder_document.save()
        results.append(data)
    return results


#-----------------#
# Utils functions #
#-----------------#

def create_scan_activity(scan_history_id, message, status):
    scan_activity = ScanActivity()
    scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
    scan_activity.title = message
    scan_activity.time = timezone.now()
    scan_activity.status = status
    scan_activity.save()
    return scan_activity.id


#--------------------#
# Database functions #
#--------------------#


def save_vulnerability(**vuln_data):
    references = vuln_data.pop('references', [])
    cve_ids = vuln_data.pop('cve_ids', [])
    cwe_ids = vuln_data.pop('cwe_ids', [])
    tags = vuln_data.pop('tags', [])
    subscan = vuln_data.pop('subscan', None)

    # remove nulls
    vuln_data = replace_nulls(vuln_data)

    # Create vulnerability
    vuln, created = Vulnerability.objects.get_or_create(**vuln_data)
    if created:
        vuln.discovered_date = timezone.now()
        vuln.open_status = True
        vuln.save()

    # Save vuln tags
    for tag_name in tags or []:
        tag, created = VulnerabilityTags.objects.get_or_create(name=tag_name)
        if tag:
            vuln.tags.add(tag)
            vuln.save()

    # Save CVEs
    for cve_id in cve_ids or []:
        cve, created = CveId.objects.get_or_create(name=cve_id)
        if cve:
            vuln.cve_ids.add(cve)
            vuln.save()

    # Save CWEs
    for cve_id in cwe_ids or []:
        cwe, created = CweId.objects.get_or_create(name=cve_id)
        if cwe:
            vuln.cwe_ids.add(cwe)
            vuln.save()

    # Save vuln reference
    if references:
        vuln.references = references
        vuln.save()

    # Save subscan id in vuln object
    if subscan:
        vuln.vuln_subscan_ids.add(subscan)
        vuln.save()

    return vuln, created


def save_endpoint(
        http_url,
        ctx={},
        is_default=False,
        http_status=0,
        **endpoint_data):
    """Get or create EndPoint object.

    Args:
        http_url (str): Input HTTP URL.
        ctx (dict): Context containing scan and domain information.
        is_default (bool): If the url is a default url for SubDomains.
        http_status (int): HTTP status code.
        endpoint_data: Additional endpoint data (including subdomain).
        
    Returns:
        tuple: (EndPoint, created) or (None, False) if invalid
    """
    # Remove nulls and validate basic inputs
    endpoint_data = replace_nulls(endpoint_data)
    scheme = urlparse(http_url).scheme

    if not scheme:
        logger.error(f'{http_url} is missing scheme (http or https). Creating default endpoint with http scheme.')
        http_url = f'http://{http_url.strip()}'

    if not is_valid_url(http_url):
        logger.error(f'{http_url} is not a valid URL. Skipping.')
        return None, False

    # Get required objects
    scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
    domain = Domain.objects.filter(pk=ctx.get('domain_id')).first()
    subdomain = endpoint_data.get('subdomain')

    if not all([scan, domain]):
        logger.error('Missing scan or domain information')
        return None, False

    # Check if we're scanning an IP
    is_ip_scan = validators.ipv4(domain.name) or validators.ipv6(domain.name)

    # For regular domain scans, validate URL belongs to domain
    if not is_ip_scan and domain.name not in http_url:
        logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
        return None, False

    http_url = sanitize_url(http_url)

    # If this is a default endpoint, check if one already exists for this subdomain
    if is_default and subdomain:
        existing_default = EndPoint.objects.filter(
            scan_history=scan,
            target_domain=domain,
            subdomain=subdomain,
            is_default=True
        ).first()

        if existing_default:
            logger.info(f'Default endpoint already exists for subdomain {subdomain}')
            return existing_default, False

    # Check for existing endpoint with same URL
    existing_endpoint = EndPoint.objects.filter(
        scan_history=scan,
        target_domain=domain,
        http_url=http_url
    ).first()

    if existing_endpoint:
        return existing_endpoint, False

    # Create new endpoint
    create_data = {
        'scan_history': scan,
        'target_domain': domain,
        'http_url': http_url,
        'is_default': is_default,
        'discovered_date': timezone.now(),
        'http_status': http_status
    }

    create_data |= endpoint_data

    endpoint = EndPoint.objects.create(**create_data)
    created = True

    # Add subscan relation if needed
    if created and ctx.get('subscan_id'):
        endpoint.endpoint_subscan_ids.add(ctx.get('subscan_id'))
        endpoint.save()

    return endpoint, created


def save_subdomain(subdomain_name, ctx={}):
    """Get or create Subdomain object.

    Args:
        subdomain_name (str): Subdomain name.
        ctx (dict): Context containing scan information and settings.

    Returns:
        tuple: (startScan.models.Subdomain, created) where `created` is a
            boolean indicating if the object has been created in DB.
    """
    scan_id = ctx.get('scan_history_id')
    subscan_id = ctx.get('subscan_id')
    out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
    subdomain_name = subdomain_name.lower()

    # Validate domain/IP format
    valid_domain = (
        validators.domain(subdomain_name) or
        validators.ipv4(subdomain_name) or
        validators.ipv6(subdomain_name)
    )
    if not valid_domain:
        logger.error(f'{subdomain_name} is not a valid domain/IP. Skipping.')
        return None, False

    # Check if subdomain is in scope
    if subdomain_name in out_of_scope_subdomains:
        logger.error(f'{subdomain_name} is out-of-scope. Skipping.')
        return None, False

    # Get domain object and check if we're scanning an IP
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    domain = scan.domain if scan else None
    
    if not domain:
        logger.error('No domain found in scan history. Skipping.')
        return None, False
        
    is_ip_scan = validators.ipv4(domain.name) or validators.ipv6(domain.name)

    # For regular domain scans, validate subdomain belongs to domain
    if not is_ip_scan and ctx.get('domain_id'):
        if domain.name not in subdomain_name:
            logger.error(f"{subdomain_name} is not a subdomain of domain {domain.name}. Skipping.")
            return None, False

    # Create or get subdomain object
    subdomain, created = Subdomain.objects.get_or_create(
        scan_history=scan,
        target_domain=domain,
        name=subdomain_name)

    if created:
        logger.info(f'Found new subdomain/rDNS: {subdomain_name}')
        subdomain.discovered_date = timezone.now()
        if subscan_id:
            subdomain.subdomain_subscan_ids.add(subscan_id)
        subdomain.save()

    return subdomain, created

def save_subdomain_metadata(subdomain, endpoint, extra_datas={}):
    if endpoint and endpoint.is_alive:
        logger.info(f'Saving HTTP metadatas from {endpoint.http_url}')
        subdomain.http_url = endpoint.http_url
        subdomain.http_status = endpoint.http_status
        subdomain.response_time = endpoint.response_time
        subdomain.page_title = endpoint.page_title
        subdomain.content_type = endpoint.content_type
        subdomain.content_length = endpoint.content_length
        subdomain.webserver = endpoint.webserver
        cname = extra_datas.get('cname')
        if cname and is_iterable(cname):
            subdomain.cname = ','.join(cname)
        cdn = extra_datas.get('cdn')
        if cdn and is_iterable(cdn):
            subdomain.is_cdn = ','.join(cdn)
            subdomain.cdn_name = extra_datas.get('cdn_name')
        for tech in endpoint.techs.all():
            subdomain.technologies.add(tech)
        subdomain.save()
    else:
        http_url = extra_datas.get('http_url')
        if http_url:
            subdomain.http_url = http_url
            subdomain.save()
        else:
            logger.error(f'No HTTP URL found for {subdomain.name}. Skipping.')

def save_email(email_address, scan_history=None):
    if not validators.email(email_address):
        logger.info(f'Email {email_address} is invalid. Skipping.')
        return None, False
    email, created = Email.objects.get_or_create(address=email_address)
    if created:
        logger.info(f'Found new email address {email_address}')

    # Add email to ScanHistory
    if scan_history:
        scan_history.emails.add(email)
        scan_history.save()

    return email, created


def save_employee(name, designation, scan_history=None):
    employee, created = Employee.objects.get_or_create(
        name=name,
        designation=designation)
    if created:
        logger.warning(f'Found new employee {name}')

    # Add employee to ScanHistory
    if scan_history:
        scan_history.employees.add(employee)
        scan_history.save()

    return employee, created


def save_ip_address(ip_address, subdomain=None, subscan=None, **kwargs):
    if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
        logger.info(f'IP {ip_address} is not a valid IP. Skipping.')
        return None, False
    ip, created = IpAddress.objects.get_or_create(address=ip_address)
    if created:
        logger.warning(f'Found new IP {ip_address}')

    # Set extra attributes
    for key, value in kwargs.items():
        setattr(ip, key, value)
    ip.save()

    # Add IP to subdomain
    if subdomain:
        subdomain.ip_addresses.add(ip)
        subdomain.save()

    # Add subscan to IP
    if subscan:
        ip.ip_subscan_ids.add(subscan)

    # Geo-localize IP asynchronously
    if created:
        geo_localize.delay(ip_address, ip.id)

    return ip, created


def save_imported_subdomains(subdomains, ctx={}):
    """Take a list of subdomains imported and write them to from_imported.txt.

    Args:
        subdomains (list): List of subdomain names.
        scan_history (startScan.models.ScanHistory): ScanHistory instance.
        domain (startScan.models.Domain): Domain instance.
        results_dir (str): Results directory.
    """
    domain_id = ctx['domain_id']
    domain = Domain.objects.get(pk=domain_id)
    results_dir = ctx.get('results_dir', RENGINE_RESULTS)

    # Validate each subdomain and de-duplicate entries
    subdomains = list(
        {
            subdomain
            for subdomain in subdomains
            if domain.name == get_domain_from_subdomain(subdomain)
        }
    )
    if not subdomains:
        return

    logger.warning(f'Found {len(subdomains)} imported subdomains.')
    with open(f'{results_dir}/from_imported.txt', 'w+') as output_file:
        url_filter = ctx.get('url_filter')
        for subdomain in subdomains:
            # Save valid imported subdomains
            subdomain_name = subdomain.strip()
            subdomain_obj, _ = save_subdomain(subdomain_name, ctx=ctx)
            if not isinstance(subdomain_obj, Subdomain):
                logger.error(f"Invalid subdomain encountered: {subdomain}")
                continue
            subdomain_obj.is_imported_subdomain = True
            subdomain_obj.save()
            output_file.write(f'{subdomain}\n')

            # Create base endpoint (for scan)
            http_url = f'{subdomain_obj.name}{url_filter}' if url_filter else subdomain_obj.name
            endpoint, _ = save_endpoint(
                http_url=http_url,
                ctx=ctx,
                is_default=True,
                subdomain=subdomain_obj
            )
            save_subdomain_metadata(subdomain_obj, endpoint)

@app.task(name='query_reverse_whois', bind=False, queue='query_reverse_whois_queue')
def query_reverse_whois(lookup_keyword):
    """Queries Reverse WHOIS information for an organization or email address.

    Args:
        lookup_keyword (str): Registrar Name or email
    Returns:
        dict: Reverse WHOIS information.
    """

    return get_associated_domains(lookup_keyword)


@app.task(name='query_ip_history', bind=False, queue='query_ip_history_queue')
def query_ip_history(domain):
    """Queries the IP history for a domain

    Args:
        domain (str): domain_name
    Returns:
        list: list of historical ip addresses
    """

    return get_domain_historical_ip_address(domain)

@app.task(name='run_wafw00f', bind=False, queue='run_command_queue')
def run_wafw00f(url):
    try:
        logger.info(f"Starting WAF detection for URL: {url}")
        wafw00f_command = f'wafw00f {url}'
        return_code, output = run_command(
            cmd=wafw00f_command,
            shell=True,
            remove_ansi_sequence=True
        )
        
        logger.info(f"Raw output from wafw00f: {output}")
        
        # Use regex to extract the WAF name
        regex = r"behind (.+)"
        match = re.search(regex, output)
        
        if match:
            result = match.group(1)
            logger.info(f"WAF detected: {result}")
            return result
        else:
            logger.info("No WAF detected")
            return "No WAF detected"
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return f"Unexpected error: {str(e)}"

@app.task(name='run_cmseek', queue='run_command_queue')
def run_cmseek(url):
    try:
        # Prepare CMSeeK command
        cms_detector_command = f'cmseek --random-agent --batch --follow-redirect -u {url}'
        
        # Run CMSeeK
        _, output = run_command(cms_detector_command, remove_ansi_sequence=True)
        
        # Parse CMSeeK output
        base_path = RENGINE_TOOL_PATH + "/.github/CMSeeK/Result"
        domain_name = urlparse(url).netloc
        json_path = os.path.join(base_path, domain_name, "cms.json")

        if os.path.isfile(json_path):
            with open(json_path, 'r') as f:
                cms_data = json.load(f)
    
            if cms_data.get('cms_name'):
                # CMS detected
                result = {'status': True}
                result.update(cms_data)
        
            # Clean up CMSeeK results
            try:
                shutil.rmtree(os.path.dirname(json_path))
            except Exception as e:
                logger.error(f"Error cleaning up CMSeeK results: {e}")
            
            return result
        
        # CMS not detected
        return {'status': False, 'message': 'Could not detect CMS!'}
    
    except Exception as e:
        logger.error(f"Error running CMSeeK: {e}")
        return {'status': False, 'message': str(e)}

@app.task(name='run_gf_list', queue='run_command_queue')
def run_gf_list():
    try:
        # Prepare GF list command
        gf_command = 'gf -list'
        
        # Run GF list command
        return_code, output = run_command(
            cmd=gf_command,
            shell=True,
            remove_ansi_sequence=True
        )
        
        # Log the raw output
        logger.info(f"Raw output from GF list: {output}")
        
        # Check if the command was successful
        if return_code == 0:
            # Split the output into a list of patterns
            patterns = [pattern.strip() for pattern in output.split('\n') if pattern.strip()]
            return {
                'status': True,
                'output': patterns
            }
        else:
            logger.error(f"GF list command failed with return code: {return_code}")
            return {
                'status': False,
                'message': f"GF list command failed with return code: {return_code}"
            }
    
    except Exception as e:
        logger.error(f"Error running GF list: {e}")
        return {
            'status': False,
            'message': str(e)
        }

def get_nmap_http_datas(host, ctx):
    """Check if standard and non-standard HTTP ports are open for given hosts.
    
    Args:
        host (str): Initial hostname to scan
        ctx (dict): Context dictionary
        
    Returns:
        dict: Dictionary of results per host:
            {
                'host1': {'scheme': 'https', 'ports': [80, 443, 8080]},
                'host2': {'scheme': 'http', 'ports': [80, 8000]}
            }
    """
    results_dir = ctx.get('results_dir', '/tmp')
    filename = ctx.get('filename', 'nmap.xml')
    try:
        xml_file = SafePath.create_safe_path(
            base_dir=results_dir,
            components=[f"{host}_{filename}"],
            create_dir=False
        )
    except (ValueError, OSError) as e:
        logger.error(f"Failed to create safe path for XML file: {str(e)}")
        return None
    
    # Combine standard (80,443) and uncommon web ports
    all_ports = [80, 443] + UNCOMMON_WEB_PORTS
    # Convert ports list to nmap format (e.g. "80,443,8000-8089,...")
    ports_str = ','.join(str(p) for p in sorted(set(all_ports)))
    
    # Basic nmap scan for all HTTP ports
    nmap_args = {
        'rate_limit': 150,
        'nmap_cmd': f'-Pn -p {ports_str} --open',
        'nmap_script': None,
        'nmap_script_args': None,
        'ports_data': {host: all_ports},
    }
    
    logger.info(f'Scanning ports: {ports_str}')
    
    # Add retry logic for nmap scan
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            run_nmap(ctx, **nmap_args)
            if os.path.exists(xml_file):
                break
            logger.warning(f"Attempt {attempt + 1}/{max_retries}: Nmap output file not found, retrying in {retry_delay}s...")
            time.sleep(retry_delay)
        except Exception as e:
            logger.error(f"Attempt {attempt + 1}/{max_retries}: Nmap scan failed: {str(e)}")
            if attempt == max_retries - 1:
                logger.error(f"Nmap scan failed after {max_retries} attempts: {str(e)}")
                return None
            time.sleep(retry_delay)
    else:
        logger.error(f"Failed to generate output file after {max_retries} retries")
        return None
    
    # Parse results to get open ports and services
    port_results = parse_nmap_results(xml_file, parse_type='ports')
    service_results = parse_nmap_results(xml_file, parse_type='services')
    
    # Create service lookup dict for efficiency
    service_lookup = {
        f"{service['host']}:{service['port']}": service 
        for service in service_results
    }
    
    # Group results by host using atomic transaction
    hosts_data = {}
    with transaction.atomic():
        for result in port_results:
            hostname = result['host']
            if hostname not in hosts_data:
                hosts_data[hostname] = {
                    'ports': [],
                    'schemes': set()
                }
                
            if result['state'] == 'open':
                port_number = int(result['port'])
                logger.info(f'Found open port {port_number} for host {hostname}')
                
                # Get service info if available
                service_info = service_lookup.get(f"{hostname}:{port_number}", {})
                service_name = service_info.get('service_name', '').lower()
                
                # Detect scheme from service
                if service_name in ['http', 'http-proxy', 'http-alt']:
                    hosts_data[hostname]['schemes'].add('http')
                elif service_name in ['https', 'https-alt', 'ssl/http', 'ssl/https']:
                    hosts_data[hostname]['schemes'].add('https')
                
                # Get IP address from nmap XML result
                ip = None
                if 'addresses' in result and result['addresses']:
                    for addr in result['addresses']:
                        if addr.get('type') == 'ipv4':
                            ip = addr.get('addr')
                            break
                        elif addr.get('type') == 'ipv6':
                            ip = addr.get('addr')
                
                if ip:
                    ip_address, _ = IpAddress.objects.get_or_create(
                        address=ip
                    )
                else:
                    logger.warning(f'No IP address found in nmap results for {hostname}')
                    ip_address = None
                
                # Create or update port with service info
                create_or_update_port_with_service(
                    port_number=port_number,
                    service_info=service_info,
                    ip_address=ip_address
                )
                
                # Add port to hosts_data
                if port_number not in hosts_data[hostname]['ports']:
                    hosts_data[hostname]['ports'].append(port_number)
        
        # Determine final scheme for each host
        for hostname, data in hosts_data.items():
            # Prefer HTTPS over HTTP if both are detected
            if 'https' in data['schemes']:
                data['scheme'] = 'https'
            elif 'http' in data['schemes']:
                data['scheme'] = 'http'
            else:
                # Fallback to port-based detection if no service info
                if 443 in data['ports']:
                    data['scheme'] = 'https'
                elif 80 in data['ports']:
                    data['scheme'] = 'http'
                else:
                    data['scheme'] = None
            
            # Clean up the data structure
            del data['schemes']
            logger.debug(f'Host {hostname} - scheme: {data["scheme"]}, ports: {data["ports"]}')
    
    return hosts_data

def process_nmap_service_results(xml_file):
    """Update port information with nmap service detection results"""
    services = parse_nmap_results(xml_file, parse_type='services')
    
    for service in services:
        try:
            # Get IP from host address node
            ip = service.get('ip', '')
            host = service.get('host', '')
            
            # If IP is empty, try to get it from the host
            if not ip and host:
                # Parse XML to get IP for this host
                tree = ET.parse(xml_file)
                root = tree.getroot()
                for host_elem in root.findall('.//host'):
                    hostnames = host_elem.find('hostnames')
                    if hostnames is not None:
                        for hostname in hostnames.findall('hostname'):
                            if hostname.get('name') == host:
                                ip = host_elem.find('address').get('addr')
                                break
            
            # Skip if still empty or if it's a hostname
            if not ip or any(c.isalpha() for c in ip):
                logger.warning(f"Skipping invalid IP address: {ip} for host {host}")
                continue
                
            ip_address, _ = IpAddress.objects.get_or_create(
                address=ip
            )
            create_or_update_port_with_service(
                port_number=int(service['port']),
                service_info=service,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error(f"Failed to process port {service['port']}: {str(e)}")

def create_or_update_port_with_service(port_number, service_info, ip_address=None):
    """Create or update port with service information from nmap for specific IP."""
    port = get_or_create_port(ip_address, port_number)
    if ip_address and service_info:
        update_port_service_info(port, service_info)
    return port

#----------------------#
#     Remote debug     #
#----------------------#

def debug():
    try:
        # Activate remote debug for scan worker
        if CELERY_REMOTE_DEBUG:
            logger.info(f"\n⚡ Debugger started on port "+ str(CELERY_REMOTE_DEBUG_PORT) +", task is waiting IDE (VSCode ...) to be attached to continue ⚡\n")
            os.environ['GEVENT_SUPPORT'] = 'True'
            debugpy.listen(('0.0.0.0',CELERY_REMOTE_DEBUG_PORT))
            debugpy.wait_for_client()
    except Exception as e:
        logger.error(e)

def remove_file_or_pattern(path, pattern=None, shell=True, history_file=None, scan_id=None, activity_id=None):
    """
    Safely removes a file/directory or pattern matching files
    Args:
        path: Path to file/directory to remove
        pattern: Optional pattern for multiple files (e.g. "*.csv")
        shell: Whether to use shell=True in run_command
        history_file: History file for logging
        scan_id: Scan ID for logging
        activity_id: Activity ID for logging
    Returns:
        bool: True if successful, False if error occurred
    """
    try:
        if pattern:
            # Check for files matching the pattern
            match_count = len(glob.glob(os.path.join(path, pattern)))
            if match_count == 0:
                logger.warning(f"No files matching pattern '{pattern}' in {path}")
                return True
            full_path = os.path.join(path, pattern)
        else:
            if not os.path.exists(path):
                logger.warning(f"Path {path} does not exist")
                return True
            full_path = path

        # Execute secure command
        run_command(
            f'rm -rf {full_path}',
            shell=shell,
            history_file=history_file,
            scan_id=scan_id,
            activity_id=activity_id
        )
        return True
    except Exception as e:
        logger.error(f"Failed to delete {full_path}: {str(e)}")
        return False

@app.task(name='pre_crawl', queue='main_scan_queue', base=RengineTask, bind=True)
def pre_crawl(self, ctx={}, description=None):
    """
    Pre-crawl existing subdomains to ensure endpoints are alive
    before heavy tasks like screenshot, waf_detection, etc.
    Also handles initial web service detection if no endpoints exist.
    """
    logger.info('Starting pre-crawl phase')
    
    domain_id = ctx.get('domain_id')
    
    # Get configuration for pre-crawl limits
    precrawl_batch_size = self.yaml_configuration.get('precrawl_batch_size', 50)
    
    # Get existing subdomains from current scan
    existing_subdomains = Subdomain.objects.filter(
        target_domain_id=domain_id
    )
    
    total_subdomains = existing_subdomains.count()
    logger.info(f'Found {total_subdomains} existing subdomains')
    
    # Check if we have any endpoints at all
    existing_endpoints = get_http_urls(ctx=ctx)
    
    if not existing_endpoints:
        # No endpoints exist - need to create basic web service endpoints
        # Use UNCOMMON_WEB_PORTS for detection
        logger.info('No existing endpoints found - creating basic web service endpoints')
        
        web_ports = self.yaml_configuration.get('web_ports', UNCOMMON_WEB_PORTS + [80, 443, 8080, 8443])
        domain = Domain.objects.get(id=domain_id)
        
        # Create basic endpoints for the main domain
        for subdomain in existing_subdomains:  # Limit to first 10 for initial detection
            for port in [80, 443, 8080, 8443]:  # Start with common web ports
                scheme = 'https' if port in [443, 8443] else 'http'
                url = f'{scheme}://{subdomain.name}:{port}'
                
                _, created = save_endpoint(
                    url,
                    ctx=ctx,
                    subdomain=subdomain,
                    is_default=(port in [80, 443])
                )
                
                if created:
                    logger.info(f'Created initial endpoint: {url}')
    
    # Get URLs to crawl (both existing and newly created)
    urls_to_crawl = []
    for subdomain in existing_subdomains:
        # Get endpoints for this subdomain that need crawling
        subdomain_endpoints = get_http_urls(is_uncrawled=True, ctx={'subdomain_id': subdomain.id})
        urls_to_crawl.extend(subdomain_endpoints)
    
    if urls_to_crawl:
        logger.info(f'Pre-crawling {len(urls_to_crawl)} URLs (batch size: {precrawl_batch_size})')
        
        # Count alive endpoints before pre-crawl
        alive_before = len(get_http_urls(is_alive=True, ctx=ctx))
        
        # Process in batches to avoid overwhelming the system
        for i in range(0, len(urls_to_crawl), precrawl_batch_size):
            batch = urls_to_crawl[i:i+precrawl_batch_size]
            logger.info(f'Processing batch {i//precrawl_batch_size + 1}: {len(batch)} URLs')
            
            # Use smart crawl with completion wait
            smart_http_crawl_if_needed(
                batch,
                ctx,
                wait_for_completion=False,
                max_wait_time=300  # 5 minutes max per batch
            )
        
        # Log results
        alive_count = len(get_http_urls(is_alive=True, ctx=ctx))
        new_alive = alive_count - alive_before
        logger.info(f'Pre-crawl completed. {new_alive} new alive endpoints discovered (total: {alive_count})')
    else:
        alive_count = 0
        logger.info('No URLs to pre-crawl')
    
    return {
        'urls_crawled': len(urls_to_crawl), 
        'alive_endpoints': alive_count,
        'total_subdomains': total_subdomains,
    }

@app.task(name='intermediate_crawl', queue='main_scan_queue', base=RengineTask, bind=True)
def intermediate_crawl(self, ctx={}, description=None):
    """
    Intermediate crawl phase - crawl newly discovered endpoints after fetch_url
    """
    logger.info('Starting intermediate crawl phase')
    
    # Get all uncrawled endpoints
    uncrawled_endpoints = get_http_urls(is_uncrawled=True, ctx=ctx)
    
    if not uncrawled_endpoints:
        logger.info('No uncrawled endpoints found for intermediate crawl')
        return {'urls_crawled': 0, 'alive_endpoints': 0}
    
    # Get batch size from configuration
    batch_size = self.yaml_configuration.get('precrawl_batch_size', 50)
    
    logger.info(f'Intermediate crawling {len(uncrawled_endpoints)} URLs (batch size: {batch_size})')
    
    # Process in batches
    for i in range(0, len(uncrawled_endpoints), batch_size):
        batch = uncrawled_endpoints[i:i+batch_size]
        logger.info(f'Processing intermediate crawl batch {i//batch_size + 1}: {len(batch)} URLs')
        
        # Use smart crawl with completion wait
        smart_http_crawl_if_needed(
            batch,
            ctx,
            wait_for_completion=False,
            max_wait_time=180  # 3 minutes max per batch
        )
    
    # Log results
    alive_count = len(get_http_urls(is_alive=True, ctx=ctx))
    logger.info(f'Intermediate crawl completed. {alive_count} alive endpoints available.')
    
    return {
        'urls_crawled': len(uncrawled_endpoints),
        'alive_endpoints': alive_count
    }

@app.task(name='post_crawl', queue='main_scan_queue', base=RengineTask, bind=True)
def post_crawl(self, ctx={}, description=None):
    """
    Post-crawl phase - final verification and cleanup of endpoints
    """
    logger.info('Starting post-crawl verification phase')
    
    # Get all endpoints
    all_endpoints = get_http_urls(ctx=ctx)
    alive_endpoints = get_http_urls(is_alive=True, ctx=ctx)
    
    logger.info(f'Post-crawl verification: {len(alive_endpoints)} alive endpoints out of {len(all_endpoints)} total')
    
    # Check for any remaining uncrawled endpoints and crawl them
    uncrawled_endpoints = get_http_urls(is_uncrawled=True, ctx=ctx)
    
    if uncrawled_endpoints:
        logger.info(f'Found {len(uncrawled_endpoints)} uncrawled endpoints, performing final crawl')
        
        # Final crawl with smaller batch size for reliability
        batch_size = min(20, len(uncrawled_endpoints))
        
        for i in range(0, len(uncrawled_endpoints), batch_size):
            batch = uncrawled_endpoints[i:i+batch_size]
            logger.info(f'Final crawl batch {i//batch_size + 1}: {len(batch)} URLs')
            
            smart_http_crawl_if_needed(
                batch,
                ctx,
                wait_for_completion=False,
                max_wait_time=120  # 2 minutes max per batch
            )
    
    # Final statistics
    final_alive_count = len(get_http_urls(is_alive=True, ctx=ctx))
    final_total_count = len(get_http_urls(ctx=ctx))
    
    logger.info(f'Post-crawl completed. Final stats: {final_alive_count} alive endpoints out of {final_total_count} total')
    
    return {
        'total_endpoints': final_total_count,
        'alive_endpoints': final_alive_count,
        'uncrawled_processed': len(uncrawled_endpoints)
    }

