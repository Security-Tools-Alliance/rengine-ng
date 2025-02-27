import json
import whatportis
import os
import time

from copy import deepcopy
from pathlib import Path
from celery import group
from celery.result import allow_join_result

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.tasks.command import run_command_line
from reNgine.utils.builders import build_cmd
from reNgine.utils.formatters import get_task_title
from reNgine.utils.nmap_service import process_nmap_service_results
from reNgine.utils.parsers import parse_nmap_results
from scanEngine.models import Notification
from reNgine.definitions import (
    NAABU_DEFAULT_PORTS,
    PORT_SCAN,
    ENABLE_HTTP_CRAWL,
    TIMEOUT,
    NAABU_EXCLUDE_PORTS,
    NAABU_EXCLUDE_SUBDOMAINS,
    PORTS,
    NAABU_RATE,
    THREADS,
    NAABU_PASSIVE,
    UNCOMMON_WEB_PORTS,
    USE_NAABU_CONFIG,
    ENABLE_NMAP,
    NMAP_COMMAND,
    NMAP_SCRIPT,
    NMAP_SCRIPT_ARGS,
    RATE_LIMIT,
)
from reNgine.settings import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_THREADS,
    DEFAULT_ENABLE_HTTP_CRAWL,
    DEFAULT_RATE_LIMIT,
)
from reNgine.utils.utils import return_iterable
from reNgine.utils.command_executor import stream_command
from reNgine.utils.ip import save_ip_address
from startScan.models import Port, Subdomain
from reNgine.utils.nmap import parse_http_ports_data
from reNgine.utils.formatters import SafePath

logger = Logger(True)

@app.task(name='port_scan', queue='port_scan_queue', base=RengineTask, bind=True)
def port_scan(self, hosts=None, ctx=None, description=None):
    """Run port scan using Naabu then Nmap."""
    from reNgine.utils.db import (
        get_random_proxy,
        get_subdomains,
        save_endpoint,
    )

    if hosts is None:
        hosts = []
    if ctx is None:
        ctx = {}
    input_file = str(Path(self.results_dir) / 'input_subdomains_port_scan.txt')
    proxy = get_random_proxy()

    # Config
    config = self.yaml_configuration.get(PORT_SCAN) or {}
    enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
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
        logger.warning(f'Found opened port {port_number} on {ip_address} ({host})')

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

    # Save output to file
    with open(self.output_path, 'w') as f:
        json.dump(results, f, indent=4)

    logger.info('Finished running naabu port scan.')

    # Process nmap results: 1 process per host
    sigs = []
    if nmap_enabled:
        logger.warning('Starting nmap scans ...')
        logger.warning(ports_data)
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
        task = group(sigs).apply_async()
        with allow_join_result():
            results = task.get()

    # Run parallel nmap scans on discovered ports
    workflow = run_nmap.si(
        hosts_data=ports_data,
        ctx={
            'nmap_cmd': nmap_cmd,
            'nmap_script': nmap_script,
            'nmap_script_args': nmap_script_args,
            'rate_limit': rate_limit,
            **ctx
        }
    )
    return workflow

@app.task(name='run_nmap', queue='port_scan_queue', base=RengineTask, bind=True)
def run_nmap(self, hosts_data, ctx=None):
    """Run nmap scans in parallel for multiple hosts."""
    if ctx is None:
        ctx = {}
    
    logger.warning(f'Launching nmap scans for {len(hosts_data)} hosts')
    
    # Create parallel tasks group
    group_tasks = []
    for host, ports in hosts_data.items():
        ctx_host = ctx.copy()
        ctx_host.update({
            'description': get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id),
            'track': False
        })
        
        group_tasks.append(
            nmap.s(
                args=ctx.get('nmap_cmd', '-Pn -sV --open'),
                ports=ports,
                host=host,
                script=ctx.get('nmap_script'),
                script_args=ctx.get('nmap_script_args'),
                max_rate=ctx.get('rate_limit', 150),
                ctx=ctx_host
            )
        )
    
    # Return group directly
    return group(group_tasks)

@app.task(name='nmap', queue='port_scan_queue', base=RengineTask, bind=True)
def nmap(self, args=None, ports=None, host=None, input_file=None, script=None, script_args=None, max_rate=None, ctx=None, description=None):
    """Run nmap on a host."""
    from reNgine.utils.db import save_vulns

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
    logger.warning(f'🔍 Starting nmap scan on {host}')

    # Construction de la commande
    nmap_cmd = get_nmap_cmd(
        args=args,
        ports=','.join(map(str, ports)),
        host=host,
        output_file=output_file_xml
    )
    
    # Exécution directe
    task = run_command_line.delay(
        nmap_cmd,
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )
    
    # Attente synchrone pour ce cas critique
    with allow_join_result():
        task.get()
    
    # Traitement des résultats
    if os.path.exists(output_file_xml):
        process_nmap_service_results(output_file_xml)
        vulns = parse_nmap_results(output_file_xml, output_file, 'vulnerabilities')
        save_vulns(self, notif, vulns_file, vulns)
        return vulns
    
    logger.error('Nmap scan failed: no output file')
    return None

@app.task(name='scan_http_ports', queue='port_scan_queue', base=RengineTask, bind=True)
def scan_http_ports(self, host, ctx=None, description=None):
    """Scan HTTP ports of a host."""
    if ctx is None:
        ctx = {}

    if cached_result := self.get_from_cache(host=host, ctx=ctx):
        logger.info(f'Using cached port scan results for {host}')
        return cached_result

    logger.warning(f'🚀 Starting HTTP port scan for {host}')
    
    # Configuration des ports à scanner
    target_ports = sorted({80, 443} | set(UNCOMMON_WEB_PORTS))
    
    # Prepare scan parameters
    scan_params = {
        'hosts_data': {host: target_ports},
        'ctx': {
            'nmap_cmd': '-Pn -sV --open',
            'rate_limit': 150,
            **ctx
        }
    }
    
    # Let Celery handle the workflow
    return run_nmap.s(**scan_params)

def get_nmap_cmd(input_file=None, args=None, host=None, ports=None, output_file=None, script=None, script_args=None, max_rate=None, flags=None):

	if flags is None:
		flags = []

	# Initialize base options
	options = {
		"--max-rate": max_rate,
		"-oX": output_file,
		"--script": script,
		"--script-args": script_args,
	}

	# Build command with options
	cmd = 'nmap'
	cmd = build_cmd(cmd, options, flags)

	# Add existing arguments if provided
	if args:
		cmd += f' {args}'

	# Add ports and service detection
	if ports and '-p' not in cmd:
		cmd = f'{cmd} -p {ports}'
	if '-sV' not in cmd:
		cmd = f'{cmd} -sV'
	if '-Pn' not in cmd:
		cmd = f'{cmd} -Pn'

	# Add input source
	if not input_file:
		cmd += f" {host}" if host else ""
	else:
		cmd += f" -iL {input_file}"

	return cmd
