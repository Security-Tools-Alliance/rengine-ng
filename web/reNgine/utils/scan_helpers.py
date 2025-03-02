import uuid
import yaml
import validators

from celery import chain, group
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError
from django.core.cache import cache

from reNgine.definitions import DEFAULT_GF_PATTERNS, FAILED_TASK, FETCH_URL, GF_PATTERNS, RUNNING_TASK, SCHEDULED_SCAN, LIVE_SCAN
from reNgine.settings import YAML_CACHE_TIMEOUT
from reNgine.utils.db import create_scan_object
from reNgine.utils.logger import Logger
from reNgine.utils.utils import is_iterable
from reNgine.utils.formatters import SafePath, fmt_traceback
from reNgine.utils.task_config import TaskConfig
from reNgine.tasks.subdomain import subdomain_discovery
from reNgine.tasks.osint import osint
from reNgine.tasks.port_scan import port_scan, scan_http_ports
from reNgine.tasks.url import fetch_url
from reNgine.tasks.fuzzing import dir_file_fuzz
from reNgine.tasks.vulnerability import vulnerability_scan
from reNgine.tasks.screenshot import screenshot
from reNgine.tasks.detect import waf_detection
from reNgine.tasks.reporting import report

from startScan.models import ScanHistory
from scanEngine.models import EngineType


logger = Logger(True)

def get_scan_engine(engine_id, scan):
    """Get scan engine and log available engines."""
    engine_id = engine_id or scan.scan_type.id
    logger.info(f'Engine ID: {engine_id}')
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
        logger.info(f'🔧 IP scan detected - Limited available tasks to: {engine.tasks}')
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
            results_dir = setup_scan_directory(domain.name, results_dir)
            config = TaskConfig(engine.yaml_configuration, results_dir, scan.id, domain.name)
            setup_gf_patterns(scan, engine, config.get_config(FETCH_URL))
            
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
        logger.error(f"Failed to initialize scan: {str(e)} {fmt_traceback(e)}")

        if scan:
            scan.scan_status = FAILED_TASK
            scan.error_message = str(e)
            scan.save()
        return None, None

def setup_gf_patterns(scan, engine, config):
    """Setup GF patterns if needed."""
    gf_patterns = config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)
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

def visualize_workflow(domain, engine, ctx, show_details=False):
    """Generate a text-based visualization of scan workflow.
    
    Creates a terminal-friendly visualization of the scan workflow with emojis
    and tree structure to show sequences, parallelism, and dependencies.
    
    Args:
        domain (Domain): Domain object
        engine (EngineType): Engine configuration
        ctx (dict): Scan context
        show_details (bool): Whether to show detailed task configuration
        
    Returns:
        str: Text-based visualization of the workflow
    """
    # Define task emojis
    task_emojis = {
        'scan_http_ports': '🔎',
        'subdomain_discovery': '🔍',
        'osint': '🌐',
        'port_scan': '🔌',
        'fetch_url': '📥',
        'dir_file_fuzz': '📂',
        'vulnerability_scan': '🛡️',
        'screenshot': '📷',
        'waf_detection': '🧱',
        'report': '📊',
        # Sub-tasks
        'nuclei_scan': '🔬',
        'dalfox_scan': '🕸️ ',
        'crlfuzz_scan': '🐛',
        's3scanner': '☁️',
        'nuclei_individual_severity_module': '🎯',
        'http_crawl': '🕷️  ',
        'run_nmap': '🔍',
        'nmap': '🔍',
        'naabu': '📡',
        # Severity levels
        'unknown': '❔',
        'info': 'ℹ️ ',
        'low': '🟢',
        'medium': '🟡',
        'high': '🟠',
        'critical': '🔴',
        # OSINT sub-tasks
        'github_scan': '🐙',
        'email_search': '📧',
        'emails': '📧',
        'api_key_search': '🔑',
        'dork_search': '🔍',
        'social_scan': '👥',
        'social_media': '👥',
        'metadata_search': '📝',
        'metainfo': '📝',
        'pastebin_search': '📌',
        'employees_search': '👔',
        'employees': '👔',
        'cloud_assets': '☁️',
        'whois_lookup': '❓',
        # Subdomain discovery sub-tasks
        'subfinder': '🔎',
        'amass': '🌐',
        'amass-passive': '🌐',
        'amass-active': '🌐',
        'assetfinder': '💼',
        'findomain': '🏠',
        'sublist3r': '📜',
        'dnsx': '🧩',
        'altdns': '🔄',
        'dnsgen': '🧬',
        'oneforall': '🎯',
        'censys': '🔭',
        'shodan': '👁️',
        'virustotal': '🦠',
        'crt_sh': '📜',
        'ctfr': '📜',
        'certspotter': '🔍',
        'chaos': '⚡',
        'waybackurls': '⏪',
        'github_subdomains': '😺',
        'tlsx': '🔒',
        'netlas': '🕸️ ',
        # Fetch URL tools
        'gospider': '🕷️  ',
        'hakrawler': '🦿',
        'gau': '🔍',
        'katana': '⚔️ ',
        # Dorks
        'login_pages': '🔐',
        'admin_panels': '👑',
        'dashboard_pages': '📊',
        'stackoverflow': '💻',
        'project_management': '📋',
        'code_sharing': '📝',
        'config_files': '⚙️ ',
        'jenkins': '🤖',
        'wordpress_files': '📰',
        'php_error': '⚠️',
        'exposed_documents': '📄',
        'db_files': '💾',
        'git_exposed': '🐙'
    }

    # Helper function to get task symbol
    def get_task_symbol(task_name):
        return task_emojis.get(task_name, '❓')

    # Parse YAML configuration if available
    yaml_config = {}
    if hasattr(engine, 'yaml_configuration'):
        import yaml
        yaml_config = yaml.safe_load(engine.yaml_configuration) or {}

    # Build initial visualization
    lines = []
    lines.append(f"🚀 Scan Workflow for domain: {domain.name}")
    lines.append(f"📋 Engine: {engine.engine_name}")
    lines.append("=" * 50)

    # Initial task - always present
    lines.append(f"┌─ {get_task_symbol('scan_http_ports')} Initial HTTP ports scan")

    # Parallel subdomain and OSINT tasks
    parallel_tasks = []
    parallel_task_details = {}

    # Subdomain discovery
    if 'subdomain_discovery' in engine.tasks:
        parallel_tasks.append('subdomain_discovery')
        subdomain_config = yaml_config.get('subdomain_discovery', {})
        tools = subdomain_config.get('uses_tools', [])
        if tools:
            parallel_task_details['subdomain_discovery'] = tools

    # OSINT
    if 'osint' in engine.tasks:
        parallel_tasks.append('osint')
        osint_config = yaml_config.get('osint', {})

        # Combine discover and dorks lists
        osint_subtasks = []
        osint_subtasks.extend(osint_config.get('discover', []))
        osint_subtasks.extend(osint_config.get('dorks', []))

        if osint_subtasks:
            parallel_task_details['osint'] = osint_subtasks

    if parallel_tasks:
        lines.append("│")
        lines.append("├─ 🔄 Parallel Tasks")
        for i, task_name in enumerate(parallel_tasks):
            is_last = i == len(parallel_tasks) - 1
            task_display = f"{get_task_symbol(task_name)} {task_name.replace('_', ' ').title()}"

            # Check if task has subtasks
            subtasks = parallel_task_details.get(task_name, [])

            if is_last and not subtasks:
                lines.append(f"│  └─ {task_display}")
            else:
                lines.append(f"│  ├─ {task_display}")

            # Add subtasks with proper indentation
            if subtasks:
                for j, subtask in enumerate(subtasks):
                    subtask_is_last = j == len(subtasks) - 1 and is_last
                    subtask_display = f"{get_task_symbol(subtask)} {subtask.replace('_', ' ').title()}"

                    if subtask_is_last:
                        lines.append(f"│  │  └─ {subtask_display}")
                    else:
                        lines.append(f"│  │  ├─ {subtask_display}")

        lines.append("│")

    # Port scan task
    if 'port_scan' in engine.tasks:
        lines.append(f"├─ {get_task_symbol('port_scan')} Port Scan")

        # Port scan always uses naabu first
        port_scan_config = yaml_config.get('port_scan', {})
        port_scan_subtasks = ['naabu']

        # Then nmap if enabled
        if port_scan_config.get('enable_nmap', True):
            port_scan_subtasks.append('nmap')

        # Add subtasks
        for j, subtask in enumerate(port_scan_subtasks):
            is_last = j == len(port_scan_subtasks) - 1
            if is_last:
                lines.append(f"│  └─ {get_task_symbol(subtask)} {subtask.replace('_', ' ').title()}")
            else:
                lines.append(f"│  ├─ {get_task_symbol(subtask)} {subtask.replace('_', ' ').title()}")

    if 'fetch_url' in engine.tasks:
        lines.append(f"├─ {get_task_symbol('fetch_url')} URL Fetching")
        # Check which tools are configured
        fetch_url_config = yaml_config.get('fetch_url', {})
        fetch_url_tools = fetch_url_config.get('uses_tools', [])

        # Add subtasks if any
        for j, subtask in enumerate(fetch_url_tools):
            is_last = j == len(fetch_url_tools) - 1
            if is_last:
                lines.append(f"│  └─ {get_task_symbol(subtask)} {subtask.replace('_', ' ').title()}")
            else:
                lines.append(f"│  ├─ {get_task_symbol(subtask)} {subtask.replace('_', ' ').title()}")

        # Check if http_crawl is enabled
        if fetch_url_config.get('enable_http_crawl', True):
            if not fetch_url_tools:
                lines.append(f"│  └─ {get_task_symbol('http_crawl')} Http Crawl")
            else:
                lines.append(f"│  ├─ {get_task_symbol('http_crawl')} Http Crawl")

    # Security tasks - parallel execution
    security_tasks = []
    security_task_details = {}

    # Check dir_file_fuzz
    if 'dir_file_fuzz' in engine.tasks:
        security_tasks.append('dir_file_fuzz')
        dir_fuzz_config = yaml_config.get('dir_file_fuzz', {})
        if dir_fuzz_config.get('enable_http_crawl', True):
            security_task_details['dir_file_fuzz'] = ['http_crawl']

    # Check vulnerability_scan
    if 'vulnerability_scan' in engine.tasks:
        security_tasks.append('vulnerability_scan')
        vuln_config = yaml_config.get('vulnerability_scan', {})
        vuln_subtasks = []

        if vuln_config.get('run_nuclei', True):
            vuln_subtasks.append('nuclei_scan')

        if vuln_config.get('run_dalfox', False):
            vuln_subtasks.append('dalfox_scan')

        if vuln_config.get('run_crlfuzz', False):
            vuln_subtasks.append('crlfuzz_scan')

        if vuln_config.get('run_s3scanner', False):
            vuln_subtasks.append('s3scanner')

        if vuln_subtasks:
            security_task_details['vulnerability_scan'] = vuln_subtasks

    # Check screenshot
    if 'screenshot' in engine.tasks:
        security_tasks.append('screenshot')

    # Check waf_detection
    if 'waf_detection' in engine.tasks:
        security_tasks.append('waf_detection')

    if security_tasks:
        lines.append("│")
        lines.append("├─ 🔄 Security Tasks (Parallel)")
        for i, task_name in enumerate(security_tasks):
            is_last = i == len(security_tasks) - 1
            task_display = f"{get_task_symbol(task_name)} {task_name.replace('_', ' ').title()}"

            # Check if task has subtasks
            subtasks = security_task_details.get(task_name, [])

            if is_last and not subtasks:
                lines.append(f"│  └─ {task_display}")
            else:
                lines.append(f"│  ├─ {task_display}")

            # Add subtasks with proper indentation
            if subtasks:
                for j, subtask in enumerate(subtasks):
                    subtask_is_last = j == len(subtasks) - 1 and is_last
                    subtask_display = f"{get_task_symbol(subtask)} {subtask.replace('_', ' ').title()}"

                    # Add severity info for nuclei scan
                    if subtask == 'nuclei_scan':
                        nuclei_config = vuln_config.get('nuclei', {})
                        severities = nuclei_config.get('severities', ['unknown', 'info', 'low', 'medium', 'high', 'critical'])

                        if subtask_is_last:
                            lines.append(f"│  │  └─ {subtask_display}")
                        else:
                            lines.append(f"│  │  ├─ {subtask_display}")

                        # Add severity levels with proper indentation
                        sev_prefix = "│  │  │  "
                        sev_line = f"{sev_prefix}Severities: "

                        for k, severity in enumerate(severities):
                            sev_emoji = get_task_symbol(severity)
                            sev_line += f"{sev_emoji} {severity.title()}"
                            if k < len(severities) - 1:
                                sev_line += ", "

                        lines.append(sev_line)
                    else:
                        if subtask_is_last:
                            lines.append(f"│  │  └─ {subtask_display}")
                        else:
                            lines.append(f"│  │  ├─ {subtask_display}")

        lines.append("│")

    # Final report task - always present
    lines.append(f"└─ {get_task_symbol('report')} Final Report Generation")

    # Show details if requested
    if show_details and yaml_config:
        lines.append("\n" + "=" * 50)
        lines.append("📝 Task Details:")
        for task_name in engine.tasks:
            config = yaml_config.get(task_name, {})
            lines.append(f"\n{get_task_symbol(task_name)} {task_name.replace('_', ' ').title()}:")

            if not config:
                lines.append("  └─ No specific configuration")
                continue

            for i, (key, value) in enumerate(config.items()):
                if isinstance(value, (dict, list)):
                    import json
                    value_str = json.dumps(value, indent=2)
                    # Indent each line of the JSON
                    value_str = '\n'.join([f'    {line}' for line in value_str.split('\n')])
                    lines.append(f"  └─ {key}:\n{value_str}")
                else:
                    lines.append(f"  └─ {key}: {value}")

    return "\n".join(lines)

def build_scan_workflow(domain, engine, ctx, show_visualization=False):
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
        show_visualization (bool): Show ASCII visualization of workflow
        
    Returns:
        tuple: (celery.Task, list) Workflow chain and task IDs
    """
    # Display workflow visualization if requested
    if show_visualization:
        logger.info(f"\n{visualize_workflow(domain, engine, ctx)}")
    
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

    workflow_parts = [
        workflow,
        group(security_tasks) if security_tasks else None,
        report.si(ctx=ctx)
    ]
    
    final_workflow = chain(*[part for part in workflow_parts if part])
    
    return final_workflow, task_ids


def execute_grouped_tasks(task_instance, grouped_tasks, task_name="unnamed_task", 
                        store_ids=True, callback_kwargs=None):
    """
    Execute a group of tasks with proper callback handling.
    This avoids the deadlock issues of using job.ready() in the main task.
    
    Args:
        task_instance: The RengineTask instance (self)
        grouped_tasks: List of task signatures to execute in parallel
        task_name: Name of the parent task for logging
        store_ids: Whether to store celery IDs in scan history
        callback_kwargs: Additional kwargs to pass to post_process
    
    Returns:
        tuple: (AsyncResult object, group task ID)
    """
    from reNgine.tasks.scan import post_process

    if not grouped_tasks:
        logger.info(f'⚠️  No tasks to run for {task_name}')
        return None, None
    
    # Create a group + callback chain
    if callback_kwargs is None:
        callback_kwargs = {}
    
    # Add parent task name
    callback_kwargs['source_task'] = task_name
    
    # Log all subtasks that will be launched
    logger.info(f'🚀 [{task_name}] Starting {len(grouped_tasks)} tasks:')
    for i, task in enumerate(grouped_tasks, 1):
        # Extract task name and any identifiable parameters
        task_info = f"  📋 {i}. {task.name}"
        
        # Try to extract key parameters for better logging
        if task.kwargs:
            key_params = []
            # Extract description if available
            if 'description' in task.kwargs:
                key_params.append(f"description='{task.kwargs['description']}'")
            # Extract any 'host' parameter
            if 'host' in task.kwargs:
                key_params.append(f"host='{task.kwargs['host']}'")
            # Add any other important parameters here
            
            if key_params:
                task_info += f" ({', '.join(key_params)})"
        
        logger.info(task_info)
    
    # Create the group and callback chain
    task_group = group(grouped_tasks)
    workflow = chain(
        task_group,
        post_process.s(**callback_kwargs)
    )
    
    # Execute the workflow
    result = workflow.apply_async()
    
    # Store IDs for monitoring if needed
    if store_ids and hasattr(task_instance, 'scan'):
        if not hasattr(task_instance.scan, 'celery_ids'):
            task_instance.scan.celery_ids = []
        task_instance.scan.celery_ids.append(result.id)
        task_instance.scan.save()
    
    logger.info(f'✅ Started {len(grouped_tasks)} tasks for {task_name} with ID {result.id}')
    
    # Add more detailed error handling and timeout management
    try:
        # Note: We don't wait for group completion here to avoid deadlocks
        # The post_process callback will handle completion
        return result, result.id
    except Exception as e:
        logger.error(f'❌ Error executing tasks for {task_name}: {str(e)}')
        # Re-raise to let Celery handle the error
        raise