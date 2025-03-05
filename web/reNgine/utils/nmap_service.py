import xml.etree.ElementTree as ET

import validators

from reNgine.definitions import UNCOMMON_WEB_PORTS
from reNgine.utils.formatters import SafePath
from reNgine.utils.logger import default_logger as logger
from startScan.models import IpAddress, Port


def get_port_datas(port_lookup, hostname, service_lookup, host_data):
    port_number = int(port_lookup['port'])
    logger.info(f'🔌 Found open port {port_number} for host {hostname}')
    service_info = service_lookup.get(f"{hostname}:{port_number}", {})
    service_name = service_info.get('service_name', '').lower()

    host_data.update(process_service_info(hostname, host_data, port_number, service_name, service_lookup, port_lookup))
    host_data.update(finalize_host_schemes(hostname, host_data))

    return host_data

def process_nmap_xml(xml_file):
    """Update port information with nmap service detection results"""
    from reNgine.utils.parsers import parse_nmap_results

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
            get_or_create_port(
                ip_address=ip_address,
                port_number=int(service['port']),
                service_info=service,
            )
        except Exception as e:
            logger.exception(f"Failed to process port {service['port']}: {str(e)}")

def process_service_info(hostname, hosts_data, port_number, service_name, service_lookup, port_lookup):
    """Process service information and update database.
    
    Args:
        hostname (str): Host being processed
        port_number (int): Port number
        service_name (str): Service name from nmap
        service_lookup (dict): Service lookup dictionary
        port_lookup (dict): Port lookup dictionary
        hosts_data (dict): Data structure to update
    """
    from reNgine.utils.ip import save_ip_address

    # Detect scheme from service name
    if service_name in ['http', 'http-proxy', 'http-alt']:
        hosts_data['schemes'].add('http')
    elif service_name in ['https', 'https-alt', 'ssl/http', 'ssl/https']:
        hosts_data['schemes'].add('https')

    # Extract IP address
    ip = None
    if 'addresses' in port_lookup and port_lookup['addresses']:
        for addr in port_lookup['addresses']:
            if addr.get('type') == 'ipv4':
                ip = addr.get('addr')
                break
            elif addr.get('type') == 'ipv6':
                ip = addr.get('addr')

    # Save IP address if found
    if ip:
        ip_address, _ = save_ip_address(ip)
    else:
        logger.warning(f'No IP address found in nmap results for {hostname}')
        ip_address = None

    # Update port and service in database
    get_or_create_port(
        ip_address=ip_address,
        port_number=int(port_number),
        service_info=service_lookup
    )

    # Add port to hosts_data if not already present
    if port_number not in hosts_data['ports']:
        hosts_data['ports'].append(port_number)
    
    return hosts_data

def get_or_create_port(ip_address, port_number, service_info=None):
    """
    Get or create a port record with optional service information.
    
    Args:
        ip_address: IP address associated with the port
        port_number: Port number
        service_info: Optional service information (name, version, etc.)
        
    Returns:
        Port: The port object (either existing or newly created)
    """
    port, created = Port.objects.get_or_create(
        ip_address=ip_address,
        number=port_number,
        defaults={
            'is_uncommon': port_number in UNCOMMON_WEB_PORTS,
            'service_name': 'unknown',
            'description': ''
        }
    )
    
    if service_info:
        update_port_service_info(port, service_info)
    
    return port

def update_port_service_info(port, service_info):
    """Update port service information consistently."""
    try:
        description_parts = []
        for key in ['service_product', 'service_version', 'service_extrainfo']:
            value = service_info.get(key)
            if value and value not in description_parts:
                description_parts.append(value)
        
        port.service_name = service_info.get('service_name', 'unknown').strip() or 'unknown'
        port.description = ' - '.join(filter(None, description_parts))[:1000]
        
        if port.ip_address:
            logger.debug(f'Updating service info for {port.ip_address.address}:{port.number}')
            
        port.save(update_fields=['service_name', 'description'])
        
    except Exception as e:
        logger.exception(f"Error updating port {port.number}: {str(e)}")
        raise

def finalize_host_schemes(hostname, host_data):
    """Determine final scheme for each host and cleanup data structure.
    
    Args:
        hostname (str): Host name
        host_data (dict): Host data with schemes set
        
    Returns:
        dict: Dict with finalized schemes or None if error
    """
    # Prefer HTTPS over HTTP if both are detected
    if (
        'https' not in host_data['schemes']
        and 'http' not in host_data['schemes']
        and 443 in host_data['ports']
        or 'https' in host_data['schemes']
    ):
        host_data['scheme'] = 'https'
    elif (
        'http' not in host_data['schemes']
        and 80 in host_data['ports']
        or 'http' in host_data['schemes']
    ):
        host_data['scheme'] = 'http'
    else:
        host_data['scheme'] = None

    # Clean up temporary schemes set
    host_data['schemes'] = set()

    return host_data

def create_nmap_xml_file(host, results_dir, filename):
    try:
        return SafePath.create_safe_path(
            base_dir=results_dir,
            components=[f"{host}_{filename}"],
            create_dir=False,
        )
    except (ValueError, OSError) as e:
        logger.error(f"🔌 Failed to create safe path for XML file: {str(e)}")
        return None

def create_first_endpoint_from_nmap_data(hosts_data, domain, subdomain, ctx):
    """Create endpoints from Nmap service detection results.
    Returns the first created endpoint or None if failed."""
    from reNgine.utils.db import save_subdomain, save_endpoint, save_subdomain_metadata
    if not hosts_data:
        logger.warning("No Nmap data provided. Skipping endpoint creation.")
        return None

    endpoint = None
    is_ip_scan = validators.ipv4(domain.name) or validators.ipv6(domain.name)
    url_filter = ctx.get('url_filter', '').rstrip('/')

    # For IP scans, ensure we have an entry for the IP itself
    if is_ip_scan and domain.name not in hosts_data:
        rdns_hostname = next(iter(hosts_data.keys()), None)
        if rdns_hostname and hosts_data[rdns_hostname]:
            hosts_data[domain.name] = hosts_data[rdns_hostname].copy()
            logger.info(f"Created IP endpoint data from rDNS {rdns_hostname}")

    for hostname, data in hosts_data.items():
        current_subdomain = subdomain
        schemes_to_try = []

        # If scheme is detected, try it first
        if data['scheme']:
            schemes_to_try.append(data['scheme'])

        # Add any missing schemes to try
        for scheme in ['https', 'http']:
            if scheme not in schemes_to_try:
                schemes_to_try.append(scheme)

        # Try each port with each scheme
        successful_endpoint = None
        for port in data['ports']:
            for scheme in schemes_to_try:
                host_url = f"{scheme}://{hostname}:{port}{url_filter}"
                logger.debug(f'Processing HTTP URL: {host_url}')

                # For IP scans, create endpoints for both IP and rDNS
                if is_ip_scan:
                    if hostname != domain.name:
                        # Create subdomain for rDNS
                        logger.info(f'Creating subdomain for rDNS hostname: {hostname}')
                        rdns_subdomain, _ = save_subdomain(hostname, ctx=ctx)
                        if rdns_subdomain:
                            # Try to create endpoint for rDNS
                            rdns_endpoint, _ = save_endpoint(
                                host_url,
                                ctx=ctx,
                                crawl=True,
                                is_default=True,
                                subdomain=rdns_subdomain
                            )
                            if rdns_endpoint:
                                successful_endpoint = rdns_endpoint
                                save_subdomain_metadata(
                                    rdns_subdomain,
                                    successful_endpoint,
                                    extra_datas={
                                        'open_ports': data['ports'],
                                    },
                                )
                                break  # Found working scheme, try next port

                    # Always try to create endpoint for IP itself
                    if hostname == domain.name or not endpoint:
                        current_endpoint, _ = save_endpoint(
                            f"{scheme}://{domain.name}:{port}{url_filter}",
                            ctx=ctx,
                            crawl=True,
                            is_default=True,
                            subdomain=current_subdomain
                        )
                        if current_endpoint:
                            successful_endpoint = current_endpoint
                            save_subdomain_metadata(
                                current_subdomain,
                                current_endpoint,
                                extra_datas={
                                    'http_url': f"{scheme}://{domain.name}:{port}{url_filter}",
                                    'open_ports': data['ports']
                                }
                            )
                            break  # Found working scheme, try next port

                else:
                    if hostname != domain.name:
                        logger.info(f'Creating subdomain for hostname: {hostname}')
                        current_subdomain, _ = save_subdomain(hostname, ctx=ctx)
                        if not current_subdomain:
                            logger.warning(f'Could not create subdomain for hostname: {hostname}. Skipping this host.')
                            continue

                    # Try to create endpoint with crawling
                    current_endpoint, _ = save_endpoint(
                        host_url,
                        ctx=ctx,
                        crawl=True,
                        is_default=True,
                        subdomain=current_subdomain
                    )

                    if current_endpoint:
                        successful_endpoint = current_endpoint
                        save_subdomain_metadata(
                            current_subdomain,
                            successful_endpoint,
                            extra_datas={
                                'open_ports': data['ports'],
                            },
                        )
                        break  # Found working scheme, try next port

            if successful_endpoint:
                break  # Found working port, stop trying others

        # Keep track of hostname data even if no endpoint was created
        if not successful_endpoint and current_subdomain:  # Added check for current_subdomain
            save_subdomain_metadata(
                current_subdomain,
                None,
                extra_datas={
                    'http_url': f"unknown://{hostname}{url_filter}",
                    'open_ports': data['ports']
                }
            )
        # Update main endpoint if needed
        elif not endpoint or hostname == domain.name:
            endpoint = successful_endpoint

    return endpoint