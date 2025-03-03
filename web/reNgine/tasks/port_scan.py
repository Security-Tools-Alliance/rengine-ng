import json
import os
import time

from copy import deepcopy
from pathlib import Path
from celery import group

from reNgine.definitions import PORT_SCAN, UNCOMMON_WEB_PORTS
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.command_builder import build_naabu_cmd
from reNgine.utils.command_executor import stream_command
from reNgine.utils.formatters import SafePath, get_task_title
from reNgine.utils.logger import default_logger as logger
from reNgine.utils.nmap import parse_http_ports_data
from reNgine.utils.nmap_service import process_nmap_service_results
from reNgine.utils.parsers import parse_nmap_results, parse_naabu_result
from reNgine.utils.task_config import TaskConfig
from reNgine.tasks.command import run_command_line

from scanEngine.models import Notification

@app.task(name='port_scan', queue='io_queue', base=RengineTask, bind=True)
def port_scan(self, hosts=None, ctx=None, description=None):
    """Run port scan.

    Args:
        hosts (list, optional): Hosts to run port scan on.
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of open ports (dict).
    """
    from reNgine.utils.db import get_subdomains

    if hosts is None:
        hosts = []
    if ctx is None:
        ctx = {}

    # Initialize task config
    config = TaskConfig(ctx, PORT_SCAN)
    task_config = config.get_task_config()

    if hosts:
        with open(task_config['input_path'], 'w') as f:
            f.write('\n'.join(hosts))
    else:
        hosts = get_subdomains(
            write_filepath=task_config['input_path'],
            exclude_subdomains=task_config['exclude_subdomains'],
            ctx=ctx)

    if not hosts:
        logger.info('🔌 No hosts to scan')
        return {}

    # Execute command more securely using list mode
    cmd_list = build_naabu_cmd(config, hosts)
    results = []
    urls = []
    ports_data = {}
    for line in stream_command(
            cmd_list,
            shell=False,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id):

        # Parse port scan result
        parsed_result = parse_naabu_result(line, ctx)
        
        # Skip if parsing failed
        if not parsed_result:
            continue
        
        # Append raw line to results
        results.append(line)
        
        # Process the result
        if not process_port_scan_result(
            parsed_result,
            self.domain,
            self.scan,
            urls,
            ports_data,
            ctx,
            enable_http_crawl=task_config['enable_http_crawl'],
            subscan=self.subscan
        ):
            logger.error(f'❌ Failed to process port scan result: {line}')

    if not ports_data:
        logger.info('🔌 Finished running naabu port scan - No open ports found.')
        if task_config['nmap_enabled']:
            logger.info('🔌 Nmap scans skipped')
        return ports_data

    # Send notification
    fields_str = ''
    for host, ports in ports_data.items():
        ports_str = ', '.join([f'`{port}`' for port in ports])
        fields_str += f'• `{host}`: {ports_str}\n'
    self.notify(fields={'Ports discovered': fields_str})

    # Save output to file
    with open(self.output_path, 'w') as f:
        json.dump(results, f, indent=4)

    logger.info('🔌 Finished running naabu port scan.')

    if task_config['nmap_enabled']:
        logger.info('🔌 Starting nmap scans ...')
        logger.info(ports_data)
        # Process nmap results: 1 process per host
        sigs = []
        for host, port_list in ports_data.items():
            ports_str = '_'.join([str(p) for p in port_list])
            ctx_nmap = ctx.copy()
            ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
            ctx_nmap['track'] = False
            sig = nmap.si(
                cmd=task_config['nmap_cmd'],
                ports=port_list,
                host=host,
                script=task_config['nmap_script'],
                script_args=task_config['nmap_script_args'],
                max_rate=task_config['rate_limit'],
                ctx=ctx_nmap)
            sigs.append(sig)
        group(sigs).apply_async()

    return ports_data

@app.task(name='run_nmap', queue='io_queue', base=RengineTask, bind=True)
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
    group(sigs).apply_async()

@app.task(name='nmap', queue='io_queue', base=RengineTask, bind=True)
def nmap(self, args=None, ports=None, host=None, input_file=None, script=None, script_args=None, max_rate=None, ctx=None, description=None):
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
    from reNgine.utils.db import save_vulns
    from reNgine.utils.command_builder import build_nmap_cmd

    if ports is None:
        ports = []
    if ctx is None:
        ctx = {}
    notif = Notification.objects.first()
    ports_str = ','.join(str(port) for port in ports)
    self.filename = 'nmap.xml'
    filename_vulns = self.filename.replace('.xml', '_vulns.json')
    output_file = self.output_path
    output_file_xml = f'{self.results_dir}/{host}_{self.filename}'
    vulns_file = f'{self.results_dir}/{host}_{filename_vulns}'
    logger.info(f'Running nmap on {host}')

    # Build cmd
    nmap_cmd = build_nmap_cmd(
        args=args,
        ports=ports_str,
        script=script,
        script_args=script_args,
        max_rate=max_rate,
        host=host,
        input_file=input_file,
        output_file=output_file_xml)

    # Run cmd and wait for completion
    run_command_line.delay(
        nmap_cmd,
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)
    
    # Check if the file exists
    if not os.path.exists(output_file_xml):
        logger.error(f"Output file nmap not created: {output_file_xml}")
        return None

    # Update port service information
    process_nmap_service_results(output_file_xml)

    # Get nmap XML results and convert to JSON
    vulns = parse_nmap_results(output_file_xml, output_file, parse_type='vulnerabilities')
    save_vulns(self, notif, vulns_file, vulns)
    return vulns

@app.task(name='scan_http_ports', queue='io_queue', base=RengineTask, bind=True)
def scan_http_ports(self, host, ctx=None, description=None):
    """Celery task to scan HTTP ports of a host.
    
    Args:
        host (str): Host to scan
        ctx (dict): Execution context
        description (str): Task description
        
    Returns:
        dict: HTTP ports data per host 
    """
    from reNgine.utils.mock import prepare_port_scan_mock
    import os

    if ctx is None:
        ctx = {}

    # Check cache first
    cache_key = f"port_scan_{host}"
    if cached_result := self.get_from_cache(cache_key):
        logger.info(f'Using cached port scan results for {host}')
        return cached_result

    # Check if dry run mode is enabled
    if ctx.get('dry_run'):
        results_dir = ctx.get('results_dir', '/tmp')
        return prepare_port_scan_mock(host, results_dir, ctx)

    # Prepare output file path
    results_dir = ctx.get('results_dir', '/tmp')
    filename = f"{host}_nmap.xml"

    try:
        xml_file = SafePath.create_safe_path(
            base_dir=results_dir,
            components=[filename],
            create_dir=False
        )
    except (ValueError, OSError) as e:
        logger.exception(f"Failed to create safe path for XML file: {str(e)}")
        return None

    # Configure ports to scan
    all_ports = [80, 443] + UNCOMMON_WEB_PORTS
    ports_str = ','.join(str(p) for p in sorted(set(all_ports)))

    # Run nmap scan with retries
    max_retries = 3
    retry_delay = 1

    for attempt in range(max_retries):
        try:
            task = run_command_line.delay(
                f'nmap -Pn -sV -p {ports_str} --open {host}',
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id
            )

            while not task.ready():
                # wait for all jobs to complete
                time.sleep(1)

            if os.path.exists(xml_file):
                break

            logger.warning(f"Attempt {attempt + 1}/{max_retries}: Nmap output file not found")
            time.sleep(retry_delay)

        except Exception as e:
            logger.exception(f"Attempt {attempt + 1}/{max_retries}: Nmap scan failed: {str(e)}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)

    return parse_http_ports_data(xml_file) if Path(xml_file).exists() else None

def process_port_scan_result(parsed_result, domain, scan, urls, ports_data, ctx, enable_http_crawl=False, subscan=None):
    """Process a parsed port scan result and save to database
    
    Args:
        parsed_result (dict): Parsed port scan result
        domain: The domain object
        scan: The scan history object
        urls (list): List to append URLs for further processing
        ports_data (dict): Dictionary to track ports per host
        ctx (dict): Context information
        enable_http_crawl (bool): Whether to enable HTTP crawling
        subscan: Optional subscan object
        
    Returns:
        bool: True if processing succeeded, False otherwise
    """
    from startScan.models import Subdomain, Port
    from reNgine.utils.db import save_ip_address, save_endpoint
    
    # Extract parsed data
    port_number = parsed_result['port_number']
    ip_address = parsed_result['ip_address']
    host = parsed_result['host']
    service_name = parsed_result['service_name']
    description = parsed_result['description']
    is_uncommon = parsed_result['is_uncommon']
    needs_endpoint = parsed_result['needs_endpoint']
    
    # Grab subdomain
    subdomain = Subdomain.objects.filter(
        name=host,
        target_domain=domain,
        scan_history=scan
    ).first()
    
    # Add IP DB
    ip, _ = save_ip_address(ip_address, subdomain, subscan=subscan)
    if subscan:
        ip.ip_subscan_ids.add(subscan)
        ip.save()
    
    # Add endpoint to DB if needed
    if needs_endpoint:
        http_url = f'{host}:{port_number}'
        endpoint, _ = save_endpoint(
            http_url,
            crawl=enable_http_crawl,
            ctx=ctx,
            subdomain=subdomain)
        if endpoint:
            http_url = endpoint.http_url
        urls.append(http_url)
    
    # Add Port in DB
    port, created = Port.objects.get_or_create(
        number=port_number,
        service_name=service_name,
        description=description
    )
    
    if is_uncommon:
        port.is_uncommon = True
        port.save()
    
    ip.ports.add(port)
    ip.save()
    
    if host in ports_data:
        ports_data[host].append(port_number)
    else:
        ports_data[host] = [port_number]
    
    # Send notification
    logger.info(f'🔌 Found opened port {port_number} on {ip_address} ({host})')
    return True
