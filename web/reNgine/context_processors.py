from . import settings
import requests
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)

def version(request):
    return {"RENGINE_CURRENT_VERSION": settings.RENGINE_CURRENT_VERSION}

def misc(request):
    # Attempt to retrieve the external IP address from the cache
    external_ip = cache.get('external_ip')

    if external_ip is None:
        try:
            # If the IP address is not in the cache, make the request
            external_ip = requests.get('https://checkip.amazonaws.com').text.strip()
            # Cache the IP address for 1 hour (3600 seconds)
            cache.set('external_ip', external_ip, timeout=3600)
        except requests.RequestException as e:
            # Handle the exception if the request fails
            external_ip = 'Unable to retrieve IP'  # Default value in case of error
            # You can also log the error if necessary
            logger.error(f"Error retrieving external IP: {e}")

    return {
        'external_ip': external_ip
    }