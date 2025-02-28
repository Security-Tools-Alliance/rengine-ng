import ipaddress
import validators
from reNgine.utils.command_executor import run_command
from reNgine.utils.logger import Logger
from startScan.models import IpAddress, CountryISO
from django.db import transaction

logger = Logger(True)

def get_ip_info(ip_address):
    """
    get_ip_info retrieves information about a given IP address, determining whether it is an IPv4 or IPv6 address. It returns an appropriate IP address object if the input is valid, or None if the input is not a valid IP address.

    Args:
        ip_address (str): The IP address to validate and retrieve information for.

    Returns:
        IPv4Address or IPv6Address or None: An IP address object if the input is valid, otherwise None.
    """
    is_ipv4 = bool(validators.ipv4(ip_address))
    is_ipv6 = bool(validators.ipv6(ip_address))
    ip_data = None
    if is_ipv4:
        ip_data = ipaddress.IPv4Address(ip_address)
    elif is_ipv6:
        ip_data = ipaddress.IPv6Address(ip_address)
    else:
        return None
    return ip_data

def get_ips_from_cidr_range(target):
    """
    get_ips_from_cidr_range generates a list of IP addresses from a given CIDR range. It returns the list of valid IPv4 addresses or logs an error if the provided CIDR range is invalid.

    Args:
        target (str): The CIDR range from which to generate IP addresses.

    Returns:
        list of str: A list of IP addresses as strings if the CIDR range is valid; otherwise, an empty list is returned.
        
    Raises:
        ValueError: If the target is not a valid CIDR range, an error is logged.
    """
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(target)]
    except ValueError:
        logger.error(f'🌍 {target} is not a valid CIDR range. Skipping.')
        return []

def save_ip_address(ip_address, subdomain=None, subscan=None, **kwargs):
    if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
        logger.info(f'🌍 IP {ip_address} is not a valid IP. Skipping.')
        return None, False
    ip, created = IpAddress.objects.get_or_create(address=ip_address)
    if created:
        logger.info(f'🌍 Found new IP {ip_address}')

    # Set extra attributes
    for key, value in kwargs.items():
        setattr(ip, key, value)
    ip.save()

    # Add IP to subdomain
    if subdomain:
        subdomain.ip_addresses.add(ip)
        subdomain.save()

    # Add subscan to IP
    if subscan:
        ip.ip_subscan_ids.add(subscan)

    # Geo-localize IP asynchronously
    if created:
        geo_localize_ip(ip_address, ip.id)

    return ip, created

def geo_localize_ip(host, ip_id=None):
    """Geolocalize an IP address or hostname
    
    Args:
        host (str): IP address or hostname to geolocate
        ip_id (int, optional): ID of the IpAddress object to update
        
    Returns:
        dict: Geolocation data or None if lookup fails
            {
                'iso': ISO country code,
                'name': country name
            }
    """
    try:
        # Skip IPv6 addresses
        if validators.ipv6(host):
            logger.info(f'🌍 IPv6 "{host}" is not supported by geoiplookup. Skipping.')
            return None

        # Run geoiplookup command
        cmd = f'geoiplookup {host}'
        _, out = run_command(cmd)

        # Check if lookup was successful
        if 'IP Address not found' in out or "can't resolve hostname" in out:
            logger.info(f'🌍 Geo IP lookup failed for host "{host}"')
            return None

        # Parse geoiplookup output
        country_iso = out.split(':')[1].strip().split(',')[0]
        country_name = out.split(':')[1].strip().split(',')[1].strip()

        # Save country info in database
        with transaction.atomic():
            geo_object, _ = CountryISO.objects.get_or_create(
                iso=country_iso,
                name=country_name
            )

            # Update IP address if ID provided
            if ip_id:
                try:
                    ip = IpAddress.objects.get(pk=ip_id)
                    ip.geo_iso = geo_object
                    ip.save()
                except IpAddress.DoesNotExist:
                    logger.error(f"🌍 IP address with id {ip_id} not found")
                    return None

        # Return geo data
        return {
            'iso': country_iso,
            'name': country_name
        }

    except Exception as e:
        logger.error(f"🌍 Error during geolocation of {host}: {str(e)}")
        return None
