import xml.etree.ElementTree as ET

from reNgine.definitions import UNCOMMON_WEB_PORTS
from reNgine.utils.logger import Logger
from reNgine.utils.parsers import parse_nmap_results
from startScan.models import IpAddress, Port

logger = Logger(True)

def create_or_update_port_with_service(port_number, service_info, ip_address=None):
    """Create or update port with service information from nmap for specific IP."""
    port = get_or_create_port(ip_address, port_number)
    if ip_address and service_info:
        update_port_service_info(port, service_info)
    return port

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
        logger.error(f"Error updating port {port.number}: {str(e)}")
        raise

def get_or_create_port(ip_address, port_number, service_info=None):
    """Centralized port handling with service info management."""
    port, created = Port.objects.get_or_create(
        ip_address=ip_address,
        number=port_number,
        defaults={
            'is_uncommon': port_number in UNCOMMON_WEB_PORTS,
            'service_name': 'unknown',
            'description': ''
        }
    )
    
    if not created and service_info:
        update_port_service_info(port, service_info)
    
    return port

def process_service_info(hostname, port_number, service_name, result, hosts_data):
    """Process service information and update database.
    
    Args:
        hostname (str): Host being processed
        port_number (int): Port number
        service_name (str): Service name from nmap
        result (dict): Nmap result dictionary
        hosts_data (dict): Data structure to update
    """
    from reNgine.utils.ip import save_ip_address

    # Detect scheme from service name
    if service_name in ['http', 'http-proxy', 'http-alt']:
        hosts_data[hostname]['schemes'].add('http')
    elif service_name in ['https', 'https-alt', 'ssl/http', 'ssl/https']:
        hosts_data[hostname]['schemes'].add('https')

    # Extract IP address
    ip = None
    if 'addresses' in result and result['addresses']:
        for addr in result['addresses']:
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
    create_or_update_port_with_service(
        port_number=port_number,
        service_info=result.get('service_info', {}),
        ip_address=ip_address
    )

    # Add port to hosts_data if not already present
    if port_number not in hosts_data[hostname]['ports']:
        hosts_data[hostname]['ports'].append(port_number)

def finalize_host_schemes(hosts_data):
    """Determine final scheme for each host and cleanup data structure.
    
    Args:
        hosts_data (dict): Data structure to finalize
    """
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

        # Clean up temporary schemes set
        del data['schemes']
        logger.debug(f'Host {hostname} - scheme: {data["scheme"]}, ports: {data["ports"]}')