import json
from copy import deepcopy
from pathlib import Path

from celery import group
from celery.result import allow_join_result
from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    PORT_SCAN,
    TIMEOUT,
    NAABU_EXCLUDE_PORTS,
    NAABU_EXCLUDE_SUBDOMAINS,
    PORTS,
    NAABU_DEFAULT_PORTS,
    NAABU_RATE,
    RATE_LIMIT,
    THREADS,
    NAABU_PASSIVE,
    USE_NAABU_CONFIG,
    UNCOMMON_WEB_PORTS,
    ENABLE_NMAP,
    NMAP_COMMAND,
    NMAP_SCRIPT,
    NMAP_SCRIPT_ARGS,
)
from reNgine.settings import (
    DEFAULT_THREADS,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RATE_LIMIT,
)
from reNgine.tasks.command import stream_command, run_command
from reNgine.utilities.subdomain import get_subdomains
from reNgine.utilities.proxy import get_random_proxy
from reNgine.utilities.command import get_nmap_cmd
from reNgine.utilities.notification import get_task_title
from reNgine.utilities.data import return_iterable
from reNgine.utilities.parser import parse_nmap_results, process_nmap_service_results
from reNgine.utilities.database import save_endpoint, save_ip_address, save_vulnerability
from scanEngine.models import Notification
from startScan.models import Port, Subdomain, EndPoint

logger = get_task_logger(__name__)


@app.task(name='port_scan', queue='io_queue', base=RengineTask, bind=True)
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
    if ctx is None:
        ctx = {}

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

        # If no subdomain exists for this host/IP, create one
        if not subdomain:
            from reNgine.utilities.database import save_subdomain
            subdomain, created = save_subdomain(host, ctx=ctx)
            if created:
                logger.info(f'Created subdomain entry for host/IP: {host}')

        # Add IP DB
        ip, _ = save_ip_address(ip_address, subdomain, subscan=self.subscan)
        if self.subscan:
            ip.ip_subscan_ids.add(self.subscan)
            ip.save()

        # Check if this is a web service port
        is_web_port = port_number in web_ports
        
        # Create endpoints only for web service ports to avoid endpoint bloat
        # Other services (SSH, FTP, etc.) don't need HTTP/HTTPS endpoints
        endpoints_created = []
        
        if is_web_port:
            if port_number == 80:
                # Port 80: Only HTTP (default port)
                http_url = f'http://{ip_address}'
                endpoint, created = save_endpoint(
                    http_url,
                    ctx=ctx,
                    subdomain=subdomain,
                    is_default=True
                )
                if endpoint:
                    endpoints_created.append({'url': http_url, 'scheme': 'http', 'port': port_number})
                    urls.append(http_url)
                    logger.info(f'Created HTTP endpoint: {http_url}')
                    
            elif port_number == 443:
                # Port 443: Only HTTPS (default port) 
                http_url = f'https://{ip_address}'
                endpoint, created = save_endpoint(
                    http_url,
                    ctx=ctx,
                    subdomain=subdomain,
                    is_default=True
                )
                if endpoint:
                    endpoints_created.append({'url': http_url, 'scheme': 'https', 'port': port_number})
                    urls.append(http_url)
                    logger.info(f'Created HTTPS endpoint: {http_url}')
                    
            else:
                # For other web ports: Create both HTTP and HTTPS endpoints
                for scheme in ['http', 'https']:
                    http_url = f'{scheme}://{ip_address}:{port_number}'
                    endpoint, created = save_endpoint(
                        http_url,
                        ctx=ctx,
                        subdomain=subdomain,
                        is_default=False
                    )
                    if endpoint:
                        endpoints_created.append({'url': http_url, 'scheme': scheme, 'port': port_number})
                        urls.append(http_url)
                        logger.info(f'Created {scheme.upper()} endpoint: {http_url}')
        
        # Add to web_services list for notification
        if is_web_port:
            web_services.extend([{
                'host': ip_address,
                'port': port_number, 
                'scheme': ep['scheme'],
                'url': ep['url']
            } for ep in endpoints_created])

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
                'description': f'Web service on port {port_number}' if is_web_port else f'Service on port {port_number}',
                'is_uncommon': port_number in UNCOMMON_WEB_PORTS
            }
        )

        if created:
            logger.warning(f'Found opened port {port_number} on {ip_address} ({host}) - Created {len(endpoints_created)} endpoint(s)')
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


@app.task(name='run_nmap', queue='group_queue', base=RengineTask, bind=True)
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


@app.task(name='nmap', queue='io_queue', base=RengineTask, bind=True)
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