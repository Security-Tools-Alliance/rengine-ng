import os
import time
from django.db import transaction

from reNgine.definitions import UNCOMMON_WEB_PORTS
from reNgine.utils.logger import Logger
from reNgine.utils.formatters import SafePath
from reNgine.utils.ip import save_ip_address
from reNgine.utils.nmap_service import create_or_update_port_with_service
from reNgine.utils.parsers import parse_nmap_results

logger = Logger(True)

def get_nmap_http_datas(host, ctx):
    """Check if standard and non-standard HTTP ports are open for given hosts.
    
    Args:
        host (str): Initial hostname to scan
        ctx (dict): Context dictionary
        
    Returns:
        dict: Dictionary of results per host
    """
    from reNgine.tasks.port_scan import run_nmap
    results_dir = ctx.get('results_dir', '/tmp')
    filename = ctx.get('filename', 'nmap.xml')
    try:
        xml_file = SafePath.create_safe_path(
            base_dir=results_dir,
            components=[f"{host}_{filename}"],
            create_dir=False
        )
    except (ValueError, OSError) as e:
        logger.error(f"🔌 Failed to create safe path for XML file: {str(e)}")
        return None

    # Combine standard and uncommon web ports
    all_ports = [80, 443] + UNCOMMON_WEB_PORTS
    ports_str = ','.join(str(p) for p in sorted(set(all_ports)))

    # Configuration pour nmap
    nmap_args = {
        'rate_limit': 150,
        'nmap_cmd': f'-Pn -p {ports_str} --open',
        'nmap_script': None,
        'nmap_script_args': None,
        'ports_data': {host: all_ports},
    }

    logger.info(f'Scanning ports: {ports_str}')

    try:
        # Launch Celery task and wait for result
        task = run_nmap.delay(ctx, **nmap_args)
        while not task.ready():
            # wait for all jobs to complete
            time.sleep(5)

        if not os.path.exists(xml_file):
            logger.error(f"Nmap output file not found: {xml_file}")
            return None
            
    except Exception as e:
        logger.error(f"Nmap scan failed: {str(e)}")
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
                logger.info(f'🔌 Found open port {port_number} for host {hostname}')

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
                    ip_address, _ = save_ip_address(
                        ip
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
            if (
                'https' not in data['schemes']
                and 'http' not in data['schemes']
                and 443 in data['ports']
                or 'https' in data['schemes']
            ):
                data['scheme'] = 'https'
            elif (
                'http' not in data['schemes']
                and 80 in data['ports']
                or 'http' in data['schemes']
            ):
                data['scheme'] = 'http'
            else:
                data['scheme'] = None

            # Clean up the data structure
            del data['schemes']
            logger.debug(f'Host {hostname} - scheme: {data["scheme"]}, ports: {data["ports"]}')

    return hosts_data

def parse_http_ports_data(xml_file):
    """Parse Nmap XML file to extract HTTP ports data.
    
    Args:
        xml_file (str): Path to Nmap XML file
        
    Returns:
        dict: HTTP data per host with format:
        {
            'hostname': {
                'ports': [80, 443, ...],
                'scheme': 'http' or 'https',
                'ip': '1.2.3.4'
            }
        }
    """
    hosts_data = {}
    port_results = parse_nmap_results(xml_file, parse_type='ports')
    service_results = parse_nmap_results(xml_file, parse_type='services')

    # Create service lookup dict for efficiency
    service_lookup = {
        f"{service['host']}:{service['port']}": service 
        for service in service_results
    }

    # Process results per host
    for result in port_results:
        hostname = result.get('hostname') or result.get('host')
        if not hostname:
            continue

        if hostname not in hosts_data:
            hosts_data[hostname] = {
                'ports': [],
                'schemes': set(),
                'ip': None
            }

        if result['state'] == 'open':
            port_number = int(result['port'])
            
            # Get service info
            service_info = service_lookup.get(f"{hostname}:{port_number}", {})
            service_name = service_info.get('service_name', '').lower()

            # Detect scheme
            if service_name in ['http', 'http-proxy', 'http-alt']:
                hosts_data[hostname]['schemes'].add('http')
            elif service_name in ['https', 'https-alt', 'ssl/http', 'ssl/https']:
                hosts_data[hostname]['schemes'].add('https')

            # Get IP address
            if not hosts_data[hostname]['ip']:
                for addr in result.get('addresses', []):
                    if addr.get('type') == 'ipv4':
                        hosts_data[hostname]['ip'] = addr.get('addr')
                        break

            hosts_data[hostname]['ports'].append(port_number)

    # Finalize schemes
    for host_data in hosts_data.values():
        if 'https' in host_data['schemes'] or 443 in host_data['ports']:
            host_data['scheme'] = 'https'
        elif 'http' in host_data['schemes'] or 80 in host_data['ports']:
            host_data['scheme'] = 'http'
        else:
            host_data['scheme'] = None
        del host_data['schemes']

    return hosts_data

