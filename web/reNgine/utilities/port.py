from celery.utils.log import get_task_logger
from reNgine.definitions import UNCOMMON_WEB_PORTS
from startScan.models import Port

logger = get_task_logger(__name__)


#-----------------#
# Port Management #
#-----------------#

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


def create_or_update_port_with_service(port_number, service_info, ip_address=None):
    """Create or update port with service information from nmap for specific IP."""
    port = get_or_create_port(ip_address, port_number)
    if ip_address and service_info:
        update_port_service_info(port, service_info)
    return port 