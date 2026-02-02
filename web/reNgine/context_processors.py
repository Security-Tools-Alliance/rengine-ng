import logging
import re

from django.core.cache import cache
import requests

from . import settings
from .definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    RUNNING_BACKGROUND,
    RUNNING_TASK,
    SUCCESS_TASK,
)


logger = logging.getLogger(__name__)


def version(request):
    return {"RENGINE_CURRENT_VERSION": settings.RENGINE_CURRENT_VERSION}


def _get_external_ip_with_fallback():
    """
    Retrieve external IP address using multiple fallback services.

    Returns:
        str: External IP address or "Unable to retrieve IP" if all services fail
    """
    # List of IP services to try in order
    ip_services = [
        "https://checkip.amazonaws.com",
        "https://ipecho.net/plain",
        "https://api.ipify.org",
        "https://httpbin.org/ip",
        "https://icanhazip.com",
    ]

    for service_url in ip_services:
        try:
            logger.debug(f"Attempting to retrieve IP from: {service_url}")
            response = requests.get(service_url, timeout=settings.IP_SERVICE_TIMEOUT)
            response.raise_for_status()

            # Extract IP from response
            ip_text = response.text.strip()

            # For httpbin.org, the response is JSON
            if "httpbin.org" in service_url:
                import json

                data = json.loads(ip_text)
                ip_text = data.get("origin", "").split(",")[0].strip()

            # Validate that we got a valid IP address
            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_text):
                logger.info(f"Successfully retrieved external IP: {ip_text} from {service_url}")
                return ip_text
            else:
                logger.warning(f"Invalid IP format received from {service_url}: {ip_text}")

        except requests.RequestException as e:
            logger.warning(f"Failed to retrieve IP from {service_url}: {e}")
            continue
        except Exception as e:
            logger.warning(f"Unexpected error retrieving IP from {service_url}: {e}")
            continue

    logger.error("All IP services failed to retrieve external IP")
    return "Unable to retrieve IP"


def misc(request):
    # Scan status constants from definitions (single source of truth for timeline sort in JS)
    scan_status = {
        "INITIATED_TASK": INITIATED_TASK,
        "FAILED_TASK": FAILED_TASK,
        "RUNNING_TASK": RUNNING_TASK,
        "SUCCESS_TASK": SUCCESS_TASK,
        "ABORTED_TASK": ABORTED_TASK,
        "RUNNING_BACKGROUND": RUNNING_BACKGROUND,
    }
    # Attempt to retrieve the external IP address from the cache
    external_ip = cache.get("external_ip")

    if external_ip is None:
        # external_ip = _get_external_ip_with_fallback()
        # Cache the IP address for 1 hour (3600 seconds) only if successful
        if external_ip != "Unable to retrieve IP":
            cache.set("external_ip", external_ip, timeout=3600)
        else:
            # Cache the failure for a shorter time (5 minutes) to avoid repeated failures
            cache.set("external_ip", external_ip, timeout=300)

    return {"external_ip": external_ip, "RENGINE_SCAN_STATUS": scan_status}
