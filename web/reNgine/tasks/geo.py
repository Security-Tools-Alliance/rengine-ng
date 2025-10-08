from celery.utils.log import get_task_logger
import validators

from reNgine.celery import app
from reNgine.utilities.data import geoiplookup
from startScan.models import CountryISO, IpAddress


logger = get_task_logger(__name__)


@app.task(name="geo_localize", bind=False, queue="io_queue")
def geo_localize(host, ip_id=None):
    """Uses geoiplookup to find location associated with host.

    Args:
        host (str): Hostname.
        ip_id (int): IpAddress object id.

    Returns:
        startScan.models.CountryISO: CountryISO object from DB or None.
    """
    if validators.ipv6(host):
        logger.info(f'Ipv6 "{host}" is not supported by geoiplookup. Skipping.')
        return None

    # Use geoiplookup function with robust parsing
    success, country_iso, country_name, error = geoiplookup(host)
    if not success:
        logger.warning(f"Failed to geolocalize {host}: {error}")
        return None

    if country_iso and country_name:
        geo_object, _ = CountryISO.objects.get_or_create(iso=country_iso, name=country_name)
        geo_json = {"iso": country_iso, "name": country_name}
        if ip_id:
            ip = IpAddress.objects.get(pk=ip_id)
            ip.geo_iso = geo_object
            ip.save()
        return geo_json
    logger.info(f'Geo IP lookup failed for host "{host}"')
    return None


@app.task(name="geo_localize_batch", bind=False, queue="io_queue")
def geo_localize_batch(ip_addresses):
    """Batch geolocalization for multiple IP addresses.

    Args:
        ip_addresses (list): List of IP addresses to geolocalize.

    Returns:
        dict: Results of geolocalization with success/failure counts.
    """
    if not ip_addresses:
        logger.info("No IP addresses provided for batch geolocalization")
        return {"success": 0, "failed": 0, "skipped": 0}

    logger.info(f"Starting batch geolocalization for {len(ip_addresses)} IP addresses")

    success_count = 0
    failed_count = 0
    skipped_count = 0

    for ip_address in ip_addresses:
        try:
            # Skip IPv6 addresses
            if validators.ipv6(ip_address):
                logger.debug(f"Skipping IPv6 address: {ip_address}")
                skipped_count += 1
                continue

            # Skip private/internal IP addresses
            from reNgine.utilities.data import get_ip_info

            ip_info = get_ip_info(ip_address)
            if ip_info and ip_info.is_private:
                logger.debug(f"Skipping private IP address: {ip_address}")
                skipped_count += 1
                continue

            # Get the IP object from database
            ip_obj = IpAddress.objects.filter(address=ip_address).first()
            if not ip_obj:
                logger.warning(f"IP object not found for address: {ip_address}")
                failed_count += 1
                continue

            # Skip if already geolocalized
            if ip_obj.geo_iso:
                logger.debug(f"IP {ip_address} already geolocalized, skipping")
                skipped_count += 1
                continue

            # Perform geolocalization using function with robust parsing
            success, country_iso, country_name, error = geoiplookup(ip_address)
            if not success:
                logger.warning(f"Failed to geolocalize {ip_address}: {error}")
                failed_count += 1
                continue

            if country_iso and country_name:
                geo_object, _ = CountryISO.objects.get_or_create(iso=country_iso, name=country_name)

                # Update IP object
                ip_obj.geo_iso = geo_object
                ip_obj.save()

                logger.debug(f"Successfully geolocalized {ip_address} -> {country_name}")
                success_count += 1
            else:
                logger.debug(f'Geo IP lookup failed for "{ip_address}"')
                failed_count += 1

        except Exception as e:
            logger.error(f"Error geolocalizing {ip_address}: {str(e)}")
            failed_count += 1

    result = {"success": success_count, "failed": failed_count, "skipped": skipped_count, "total": len(ip_addresses)}

    logger.info(f"Batch geolocalization completed: {result}")
    return result
