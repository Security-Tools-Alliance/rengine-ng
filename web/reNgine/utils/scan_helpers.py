import uuid
import yaml
import validators

from celery import chain, group
from django.utils import timezone
from django.db import transaction
from reNgine.utils.logger import Logger
from reNgine.utils.utils import is_iterable
from reNgine.utils.formatters import SafePath
from scanEngine.models import EngineType
from reNgine.definitions import FAILED_TASK, GF_PATTERNS, RUNNING_TASK, SCHEDULED_SCAN, LIVE_SCAN
from reNgine.settings import YAML_CACHE_TIMEOUT
from reNgine.tasks.subdomain import subdomain_discovery
from reNgine.tasks.osint import osint
from reNgine.tasks.port_scan import port_scan, scan_http_ports
from reNgine.tasks.url import fetch_url
from reNgine.tasks.fuzzing import dir_file_fuzz
from reNgine.tasks.vulnerability import vulnerability_scan
from reNgine.tasks.screenshot import screenshot
from reNgine.tasks.detect import waf_detection
from reNgine.tasks.reporting import report

from reNgine.utils.db import create_scan_object
from startScan.models import ScanHistory
from django.core.exceptions import ValidationError
from django.core.cache import cache

logger = Logger(True)

def get_scan_engine(engine_id, scan):
    """Get scan engine and log available engines."""
    engine_id = engine_id or scan.scan_type.id
    logger.info(f'Engine ID: {engine_id}')
    engines = EngineType.objects.all()
    for engine in engines:
        logger.info(f'Engine: {engine.id} - {engine.engine_name}')
    return EngineType.objects.get(pk=engine_id)

def setup_scan_directory(domain_name, results_dir):
    """Create scan results directory with UUID."""
    uuid_scan = uuid.uuid1()
    return SafePath.create_safe_path(
        base_dir=results_dir,
        components=[domain_name, 'scans', str(uuid_scan)]
    )

def handle_ip_scan(domain, engine):
    """Adjust tasks for IP-based scans."""
    if validators.ip_address.ipv4(domain.name) or validators.ip_address.ipv6(domain.name):
        allowed_tasks = ['port_scan', 'fetch_url', 'dir_file_fuzz', 
                        'vulnerability_scan', 'screenshot', 'waf_detection']
        engine.tasks = [task for task in engine.tasks if task in allowed_tasks]
        logger.info(f'IP scan detected - Limited available tasks to: {engine.tasks}')
    return engine

def initialize_scan_history(scan, domain, engine, scan_type, initiated_by_id, results_dir,
                          celery_ids=None, out_of_scope_subdomains=None, url_filter=''):
    """Initialize scan history object and create context.
    
    Args:
        scan (ScanHistory): Scan history object
        domain (Domain): Domain object
        engine (EngineType): Engine configuration
        scan_type (str): Type of scan
        initiated_by_id (int): User ID who initiated the scan
        results_dir (str): Results directory path
        celery_ids (list): List of Celery task IDs
        out_of_scope_subdomains (list): List of subdomains to exclude
        url_filter (str): URL filter pattern
    
    Returns:
        tuple: (ScanHistory, dict) Updated scan object and context dictionary
    """
    try:
        with transaction.atomic():
            if scan_type == SCHEDULED_SCAN:
                scan_history_id = create_scan_object(
                    host_id=domain.id,
                    engine_id=engine.id,
                    initiated_by_id=initiated_by_id
                )
                scan = ScanHistory.objects.get(pk=scan_history_id)
            
            # Update scan attributes atomically
            scan.scan_status = RUNNING_TASK
            scan.scan_type = engine
            scan.celery_ids = celery_ids or []  # Initialize with provided IDs or empty list
            scan.domain = domain
            scan.start_scan_date = timezone.now()
            scan.tasks = engine.tasks
            
            # Create directory and context
            setup_scan_directory(domain.name, results_dir)
            setup_gf_patterns(scan, engine, get_cached_yaml_config(engine))
            
            ctx = create_scan_context(
                scan=scan,
                domain=domain,
                engine=engine,
                results_dir=results_dir,
                out_of_scope_subdomains=out_of_scope_subdomains,
                initiated_by_id=initiated_by_id,
                url_filter=url_filter
            )
            
            scan.save()
            return scan, ctx
            
    except Exception as e:
        logger.error(f"Failed to initialize scan: {str(e)}")
        if scan:
            scan.scan_status = FAILED_TASK
            scan.error_message = str(e)
            scan.save()
        return None, None

def setup_gf_patterns(scan, engine, config):
    """Setup GF patterns if needed."""
    gf_patterns = config.get(GF_PATTERNS, [])
    add_gf_patterns = gf_patterns and 'fetch_url' in engine.tasks
    if add_gf_patterns and is_iterable(gf_patterns):
        scan.used_gf_patterns = ','.join(gf_patterns)

def create_scan_context(scan, domain, engine, results_dir, out_of_scope_subdomains=None, 
                       initiated_by_id=None, url_filter=''):
    """Create and initialize scan context dictionary.
    
    Args:
        scan (ScanHistory): Scan history object
        domain (Domain): Domain object
        engine (EngineType): Engine type object
        results_dir (str): Results directory path
        out_of_scope_subdomains (list): List of out of scope subdomains
        initiated_by_id (int): User ID who initiated the scan
        url_filter (str): URL filter string
        
    Returns:
        dict: Initialized context dictionary
    """
    config = yaml.safe_load(engine.yaml_configuration)
    
    return {
        'scan_history_id': scan.id,
        'domain_id': domain.id,
        'domain_name': domain.name,
        'engine_id': engine.id,
        'results_dir': results_dir,
        'out_of_scope_subdomains': out_of_scope_subdomains or [],
        'initiated_by_id': initiated_by_id,
        'url_filter': url_filter,
        'yaml_configuration': config
    }

def validate_scan_inputs(domain_id, engine_id, scan_type, scan_history_id=None):
    """Validate all scan input parameters.
    
    Raises:
        ValidationError: If any validation fails
    """
    if not domain_id:
        raise ValidationError("Domain ID is required")
        
    if scan_type not in [LIVE_SCAN, SCHEDULED_SCAN]:
        raise ValidationError(f"Invalid scan type: {scan_type}")
        
    if scan_type == LIVE_SCAN and not scan_history_id:
        raise ValidationError("Scan history ID required for live scans")
        
    return True 

def get_cached_yaml_config(engine):
    """Get YAML configuration with caching."""
    cache_key = f'engine_yaml_{engine.id}'
    config = cache.get(cache_key)
    
    if not config:
        config = yaml.safe_load(engine.yaml_configuration)
        cache.set(cache_key, config, timeout=YAML_CACHE_TIMEOUT)
        
    return config 

def build_scan_workflow(domain, engine, ctx):
    """Build scan workflow based on engine configuration.
    
    The workflow follows this sequence:
    1. Initial port scan to detect web services
    2. Parallel subdomain discovery and OSINT
    3. Full port scan on discovered subdomains
    4. URL fetching
    5. Parallel security tasks (fuzzing, vulns, screenshots, WAF)

    Args:
        domain (Domain): Domain object
        engine (EngineType): Engine configuration
        ctx (dict): Scan context
        
    Returns:
        tuple: (celery.Task, list) Workflow chain and task IDs
    """
    # Build initial workflow
    initial_scan = scan_http_ports.si(
        host=domain.name,
        ctx=ctx,
        description='Initial web services detection'
    )
    task_ids = [initial_scan.id]
    # Build parallel tasks
    parallel_tasks = []
    if 'subdomain_discovery' in engine.tasks:
        task = subdomain_discovery.si(ctx=ctx)
        parallel_tasks.append(task)
        task_ids.append(task.id)
    if 'osint' in engine.tasks:
        task = osint.si(ctx=ctx)
        parallel_tasks.append(task)
        task_ids.append(task.id)

    # Build main workflow with task tracking
    workflow_tasks = [
        initial_scan,
        group(parallel_tasks) if parallel_tasks else None,
        port_scan.si(ctx=ctx) if 'port_scan' in engine.tasks else None,
        fetch_url.si(ctx=ctx) if 'fetch_url' in engine.tasks else None
    ]

    # Track IDs of optional tasks
    if 'port_scan' in engine.tasks:
        task_ids.append(workflow_tasks[2].id)
    if 'fetch_url' in engine.tasks:
        task_ids.append(workflow_tasks[3].id)

    workflow = chain(*[t for t in workflow_tasks if t])

    # Build and track security tasks
    security_tasks = []
    security_task_map = {
        'dir_file_fuzz': dir_file_fuzz,
        'vulnerability_scan': vulnerability_scan,
        'screenshot': screenshot,
        'waf_detection': waf_detection
    }

    for task_name, task_func in security_task_map.items():
        if task_name in engine.tasks:
            task = task_func.si(ctx=ctx)
            security_tasks.append(task)
            task_ids.append(task.id)

    # Add security tasks and report to workflow
    final_workflow = chain(
        workflow,
        group(security_tasks) if security_tasks else None,
        report.si(ctx=ctx)
    )
    task_ids.append(report.si(ctx=ctx).id)

    return final_workflow, task_ids 