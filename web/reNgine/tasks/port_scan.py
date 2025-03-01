import json
import whatportis
import os
import time

from copy import deepcopy
from pathlib import Path
from celery import group
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.tasks.command import run_command_line
from reNgine.utils.formatters import get_task_title
from reNgine.utils.nmap_service import process_nmap_service_results
from reNgine.utils.parsers import parse_nmap_results
from scanEngine.models import Notification
from reNgine.definitions import (
    NAABU_DEFAULT_PORTS,
    PORT_SCAN,
    NAABU_EXCLUDE_PORTS,
    NAABU_EXCLUDE_SUBDOMAINS,
    PORTS,
    NAABU_PASSIVE,
    UNCOMMON_WEB_PORTS,
    USE_NAABU_CONFIG,
    ENABLE_NMAP,
    NMAP_COMMAND,
    NMAP_SCRIPT,
    NMAP_SCRIPT_ARGS,
)
from reNgine.utils.utils import return_iterable
from reNgine.utils.command_executor import stream_command
from reNgine.utils.ip import save_ip_address
from startScan.models import Port, Subdomain
from reNgine.utils.nmap import parse_http_ports_data
from reNgine.utils.formatters import SafePath
from reNgine.utils.command_builder import CommandBuilder
from reNgine.utils.task_config import TaskConfig

logger = Logger(True)

@app.task(name='port_scan', queue='io_queue', base=RengineTask, bind=True)
def port_scan(self, hosts=None, ctx=None, description=None):
    """Run port scan.

    Args:
        hosts (list, optional): Hosts to run port scan on.
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of open ports (dict).
    """
    from reNgine.utils.db import (
        get_subdomains,
        save_endpoint,
    )

    if hosts is None:
        hosts = []
    if ctx is None:
        ctx = {}

    # Initialize task config
    config = TaskConfig(self.yaml_configuration, self.results_dir, self.scan_id, self.filename)

    # Get configuration values
    input_file = config.get_input_path('subdomains_port_scan')
    proxy = config.get_proxy()

    # Get port scan specific configs
    port_config = config.get_config(PORT_SCAN)
    enable_http_crawl = config.get_http_crawl_enabled(PORT_SCAN)
    timeout = config.get_timeout(PORT_SCAN)
    exclude_ports = port_config.get(NAABU_EXCLUDE_PORTS, [])
    exclude_subdomains = port_config.get(NAABU_EXCLUDE_SUBDOMAINS, False)
    ports = port_config.get(PORTS, NAABU_DEFAULT_PORTS)
    ports = [str(port) for port in ports]
    rate_limit = config.get_rate_limit(PORT_SCAN)
    threads = config.get_threads(PORT_SCAN)
    passive = port_config.get(NAABU_PASSIVE, False)
    use_naabu_config = port_config.get(USE_NAABU_CONFIG, False)
    exclude_ports_str = ','.join(return_iterable(exclude_ports))

    # nmap args
    nmap_enabled = port_config.get(ENABLE_NMAP, False)
    nmap_cmd = port_config.get(NMAP_COMMAND, '')
    nmap_script = port_config.get(NMAP_SCRIPT, '')
    nmap_script = ','.join(return_iterable(nmap_script))
    nmap_script_args = port_config.get(NMAP_SCRIPT_ARGS)

    if hosts:
        with open(input_file, 'w') as f:
            f.write('\n'.join(hosts))
    else:
        hosts = get_subdomains(
            write_filepath=input_file,
            exclude_subdomains=exclude_subdomains,
            ctx=ctx)

    if not hosts:
        logger.info('🔌 No hosts to scan')
        return {}

    # Build cmd using the secure builder
    cmd_builder = CommandBuilder('naabu')
    cmd_builder.add_option('-json')
    cmd_builder.add_option('-exclude-cdn')
    cmd_builder.add_option('-list', input_file, len(hosts) > 0)
    cmd_builder.add_option('-host', hosts[0], len(hosts) == 0)

    # Port configuration
    if 'full' in ports or 'all' in ports:
        cmd_builder.add_option('-p', '-')
    elif 'top-100' in ports:
        cmd_builder.add_option('-top-ports', '100')
    elif 'top-1000' in ports:
        cmd_builder.add_option('-top-ports', '1000')
    else:
        ports_str = ','.join(ports)
        cmd_builder.add_option('-p', ports_str)

    # Add remaining options
    cmd_builder.add_option('-config', str(Path.home() / '.config' / 'naabu' / 'config.yaml'), use_naabu_config)
    cmd_builder.add_option('-proxy', proxy, bool(proxy))
    cmd_builder.add_option('-c', threads, bool(threads))
    cmd_builder.add_option('-rate', rate_limit, rate_limit > 0)
    cmd_builder.add_option('-timeout', timeout*1000, timeout > 0)
    cmd_builder.add_option('-passive', condition=passive)
    cmd_builder.add_option('-exclude-ports', exclude_ports_str, bool(exclude_ports))
    cmd_builder.add_option('-silent')

    # Execute command more securely using list mode
    cmd_list = cmd_builder.build_list()
    results = []
    urls = []
    ports_data = {}
    for line in stream_command(
            cmd_list,
            shell=False,
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

        # Add endpoint to DB
        # port 80 and 443 not needed as http crawl already does that.
        if port_number not in [80, 443]:
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
        port_details = whatportis.get_ports(str(port_number))
        service_name = port_details[0].name if len(port_details) > 0 else 'unknown'
        description = port_details[0].description if len(port_details) > 0 else ''

        # get or create port
        port, created = Port.objects.get_or_create(
            number=port_number,
            service_name=service_name,
            description=description
        )
        if port_number in UNCOMMON_WEB_PORTS:
            port.is_uncommon = True
            port.save()
        ip.ports.add(port)
        ip.save()
        if host in ports_data:
            ports_data[host].append(port_number)
        else:
            ports_data[host] = [port_number]

        # Send notification
        logger.warning(f'🔌 Found opened port {port_number} on {ip_address} ({host})')

    if not ports_data:
        logger.info('🔌 Finished running naabu port scan - No open ports found.')
        if nmap_enabled:
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

    if nmap_enabled:
        logger.warning('🔌 Starting nmap scans ...')
        logger.warning(ports_data)
        # Process nmap results: 1 process per host
        sigs = []
        for host, port_list in ports_data.items():
            ports_str = '_'.join([str(p) for p in port_list])
            ctx_nmap = ctx.copy()
            ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
            ctx_nmap['track'] = False
            sig = nmap.si(
                cmd=nmap_cmd,
                ports=port_list,
                host=host,
                script=nmap_script,
                script_args=nmap_script_args,
                max_rate=rate_limit,
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
    from reNgine.utils.command_builder import get_nmap_cmd

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
    logger.warning(f'Running nmap on {host}')

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

    if ctx is None:
        ctx = {}

    # Check cache first
    cache_key = f"port_scan_{host}"
    if cached_result := self.get_from_cache(cache_key):
        logger.info(f'Using cached port scan results for {host}')
        return cached_result

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
        logger.error(f"Failed to create safe path for XML file: {str(e)}")
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
            logger.error(f"Attempt {attempt + 1}/{max_retries}: Nmap scan failed: {str(e)}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)

    return parse_http_ports_data(xml_file) if Path(xml_file).exists() else None
