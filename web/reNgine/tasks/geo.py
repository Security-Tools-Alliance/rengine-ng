from reNgine.celery import app
from reNgine.utils.logger import default_logger as logger
from reNgine.utils.ip import geo_localize_ip


@app.task(name='geo_localize', bind=False, queue='io_queue')
def geo_localize(host, ip_id=None):
    """Uses geoiplookup to find location associated with host.

    Args:
        host (str): Hostname.
        ip_id (int): IpAddress object id.

    Returns:
        startScan.models.CountryISO: CountryISO object from DB or None.
    """
    return geo_localize_ip(host, ip_id)
