import json
import os

from copy import deepcopy
from celery import group

from reNgine.definitions import PORT_SCAN, UNCOMMON_WEB_PORTS
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.settings import RENGINE_CACHE_ENABLED
from reNgine.utils.command_builder import build_naabu_cmd
from reNgine.utils.command_executor import stream_command
from reNgine.utils.debug import debug
from reNgine.utils.formatters import get_task_title
from reNgine.utils.logger import default_logger as logger
from reNgine.utils.nmap_service import create_nmap_xml_file
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
        
        ctx_nmap = ctx.copy()
        ctx_nmap['track'] = False
        
        nmap_args = {
            'nmap_cmd': task_config['nmap_cmd'],
            'nmap_script': task_config['nmap_script'],
            'nmap_script_args': task_config['nmap_script_args'],
            'rate_limit': task_config['rate_limit'],
            'ports_data': ports_data,
            'wait_for_results': False,
            'use_cache': RENGINE_CACHE_ENABLED
        }
        
        run_nmap.delay(ctx=ctx_nmap, **nmap_args)
        
        logger.info(f'🔌 Launched nmap scans for {len(ports_data)} hosts')

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
            - wait_for_results: If True, wait for results and return them
            - use_cache: If True, use task cache for results
    """
    from reNgine.utils.scan_helpers import execute_grouped_tasks

    wait_for_results = nmap_args.pop('wait_for_results', False)
    use_cache = nmap_args.pop('use_cache', False)
    ports_data = nmap_args.get('ports_data', {})

    # Prepare task signatures
    task_signatures = []
    host_map = {}

    # Create task signatures for each host
    for i, (host, port_list) in enumerate(ports_data.items()):
        custom_ctx = deepcopy(ctx)
        custom_ctx['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
        custom_ctx['track'] = False
        output_file_xml = create_nmap_xml_file(host, self.results_dir, 'nmap.xml')
        logger.info(f'🔌 Running nmap on {host} with output file {output_file_xml}')

        # Create task signature
        sig = nmap.si(
            args=nmap_args.get('nmap_cmd'),
            ports=port_list,
            host=host,
            script=nmap_args.get('nmap_script'),
            script_args=nmap_args.get('nmap_script_args'),
            max_rate=nmap_args.get('rate_limit'),
            ctx=custom_ctx,
            output_file_xml=output_file_xml
        )

        task_signatures.append(sig)
        host_map[i] = host

    if not task_signatures:
        logger.info('🔌 No nmap tasks to run - no hosts with open ports')
        return None

    if wait_for_results:
        # Let execute_grouped_tasks handle caching and task execution
        task_results, task_id = execute_grouped_tasks(
            task_instance=self,
            grouped_tasks=task_signatures,
            task_name="nmap_scan",
            use_cache=use_cache,
            callback_kwargs={
                'host_map': host_map,
                'scan_ctx': ctx,
                #'callback': process_nmap_results.s(ctx=ctx),
                'parent_task_id': self.request.id
            }
        )

        return {
            'task_id': task_id,
            'status': 'processing',
            'host_count': len(host_map)
        }
    else:
        # Just run tasks in parallel and don't wait
        group(task_signatures).apply_async()
        return None

@app.task(name='nmap', queue='io_queue', base=RengineTask, bind=True)
def nmap(self, args=None, ports=None, host=None, input_file=None, output_file_xml=None,
         script=None, script_args=None, max_rate=None, ctx=None, description=None):
    """Run nmap on a host.

    Args:
        args (str, optional): Existing nmap args to complete.
        ports (list, optional): List of ports to scan.
        host (str, optional): Host to scan.
        input_file (str, optional): Input hosts file.
        xml_file (str, optional): XML file to save.
        script (str, optional): NSE script to run.
        script_args (str, optional): NSE script args.
        max_rate (int): Max rate.
        description (str, optional): Task description shown in UI.
    """
    from reNgine.utils.db import save_vulns
    from reNgine.utils.command_builder import build_nmap_cmd
    from reNgine.utils.nmap_service import process_nmap_xml

    if ports is None:
        ports = []
    if ctx is None:
        ctx = {}
    notif = Notification.objects.first()
    ports_str = ','.join(str(port) for port in ports)
    output_file = f'{self.results_dir}/{host}_nmap.json'
    if not output_file_xml:
        output_file_xml = create_nmap_xml_file(host, self.results_dir, 'nmap.xml')
    vulns_file = f'{self.results_dir}/{host}_nmap_vulns.json'
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
    process_nmap_xml(output_file_xml)

    # Get nmap XML results and convert to JSON
    vulns = parse_nmap_results(output_file_xml, output_file, parse_type='vulnerabilities')
    save_vulns(self, notif, vulns_file, vulns)

    return {'vulns': vulns, 'xml_file': output_file_xml, 'host': host}

@app.task(name='scan_http_ports', queue='io_queue', base=RengineTask, bind=True)
def scan_http_ports(self, hosts=None, ctx=None, description=None):
    """Celery task to scan HTTP ports of hosts and process results.
    
    Args:
        hosts (str or list): Host(s) to scan. Can be a single host or list of hosts.
        ctx (dict): Execution context
        description (str): Task description
        
    Returns:
        dict: HTTP ports data per host with scheme detection
    """
    if ctx is None:
        ctx = {}

    # Convert string host to list for consistent handling
    if hosts is None:
        hosts = []
    elif isinstance(hosts, str):
        hosts = [hosts]

    if not hosts:
        logger.info('No hosts to scan')
        return {}

    # Prepare ports to scan
    all_ports = [80, 443] + UNCOMMON_WEB_PORTS

    # Build ports data for run_nmap
    ports_data = {host: all_ports for host in hosts}

    # Configure nmap arguments
    nmap_args = {
        'nmap_cmd': '-Pn -sV --open',
        'ports_data': ports_data,
        'rate_limit': 150,
        'wait_for_results': True,
        'use_cache': True,
        'results_dir': ctx.get('results_dir', '/tmp')
    }

    # Execute nmap scan with results waiting
    nmap_results = run_nmap(ctx=ctx, **nmap_args)

    if not nmap_results:
        logger.error("🔌 Nmap scan failed or returned no results")
        return {}

    return

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

#@app.task(name='process_nmap_results', queue='cpu_queue', base=RengineTask, bind=True)
def process_nmap_results(ctx, combined_results=None, host_map=None, source_task=None, **kwargs):
    """Process results from nmap scans and prepare structured data.
    
    Args:
        combined_results (dict): Results from post_process task
        host_map (dict): Map of indices to hosts
        source_task (str): Name of source task
        **kwargs: Additional keyword arguments
        
    Returns:
        dict: Processed results with XML files paths and vulnerabilities per host
    """
    #debug()

    from reNgine.utils.db import save_subdomain
    from reNgine.utils.nmap_service import create_first_endpoint_from_nmap_data
    from reNgine.utils.parsers import parse_http_ports_data

    logger.info(f"📊 Processing nmap results from {source_task}")
    
    if not combined_results:
        logger.error("❌ No results to process")
        return {}
    
    processed_results = {}
    
    # Process results based on the structure returned by post_process
    for key, result in combined_results.items():
        # Check if this is a result with a host parameter
        if isinstance(result, dict) and 'host' in result:
            host = result.get('host')
            xml_file = result.get('xml_file')
            vulns = result.get('vulns')
            
            if host and xml_file:
                processed_results[host] = {
                    'xml_file': xml_file,
                    'vulns': vulns
                }
        # Also check numeric keys from host_map
        elif host_map and key.startswith('result_'):
            try:
                # Extract index from result_X format
                index = int(key.split('_')[1])
                if index in host_map:
                    host = host_map[index]
                    if isinstance(result, dict):
                        processed_results[host] = {
                            'xml_file': result.get('xml_file'),
                            'vulns': result.get('vulns')
                        }
            except (ValueError, IndexError):
                pass
    
    # Also check for direct host entries in combined_results
    for host, host_data in combined_results.items():
        if isinstance(host_data, dict) and 'xml_file' in host_data and host not in processed_results:
            processed_results[host] = {
                'xml_file': host_data.get('xml_file'),
                'vulns': host_data.get('vulns')
            }
    
    # Process and organize results by host
    hosts_data = {}

    # Extract XML file paths from nmap_results
    xml_files = {}
    for host, result in processed_results.items():
        if isinstance(result, dict) and 'xml_file' in result:
            xml_file = result['xml_file']
            if os.path.exists(xml_file):
                xml_files[host] = xml_file
            else:
                logger.error(f"Nmap output file not found: {xml_file}")

    # Process each XML file to extract detailed information
    for host, xml_file in xml_files.items():
        # Create subdomain
        subdomain_name = ctx.get('domain_name')
        if subdomain_name:
            subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        else:
            subdomain = None
            logger.warning(f"No domain name in context for host {host}")

        # Parse HTTP ports data
        hosts_data |= parse_http_ports_data(xml_file)

        # Create first HTTP endpoint if domain name is provided
        if subdomain_name and subdomain:
            endpoint = create_first_endpoint_from_nmap_data(hosts_data, subdomain.target_domain, subdomain, ctx)
            if not endpoint:
                logger.error(f'Could not create any valid endpoints for {subdomain_name}. Scan failed.')


    logger.info(f"✅ Processed nmap results for {len(processed_results)} hosts")
    
    return processed_results
