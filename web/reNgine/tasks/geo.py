import validators
from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.tasks.command import run_command
from startScan.models import CountryISO, IpAddress

logger = get_task_logger(__name__)


@app.task(name='geo_localize', bind=False, queue='io_queue')
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
    cmd = f'geoiplookup {host}'
    _, out = run_command(cmd)
    if 'IP Address not found' not in out and "can't resolve hostname" not in out:
        country_iso = out.split(':')[1].strip().split(',')[0]
        country_name = out.split(':')[1].strip().split(',')[1].strip()
        geo_object, _ = CountryISO.objects.get_or_create(
            iso=country_iso,
            name=country_name
        )
        geo_json = {
            'iso': country_iso,
            'name': country_name
        }
        if ip_id:
            ip = IpAddress.objects.get(pk=ip_id)
            ip.geo_iso = geo_object
            ip.save()
        return geo_json
    logger.info(f'Geo IP lookup failed for host "{host}"')
    return None 