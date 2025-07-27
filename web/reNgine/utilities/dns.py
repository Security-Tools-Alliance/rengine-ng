import socket
import validators
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def resolve_subdomain_ips(subdomain_name):
    """Simple DNS resolution to get IP addresses for a subdomain.
    
    Args:
        subdomain_name (str): Subdomain name to resolve
        
    Returns:
        list: List of IP addresses
    """
    ips = []
    try:
        # Get all IPs for the subdomain
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(subdomain_name)
        
        for ip in ipaddrlist:
            # Validate IP before adding
            if validators.ipv4(ip) or validators.ipv6(ip):
                ips.append(ip)
                logger.debug(f'Resolved {subdomain_name} -> {ip}')
        
    except socket.gaierror as e:
        logger.debug(f'DNS resolution failed for {subdomain_name}: {e}')
    except Exception as e:
        logger.warning(f'Unexpected error resolving {subdomain_name}: {e}')
    
    return ips 