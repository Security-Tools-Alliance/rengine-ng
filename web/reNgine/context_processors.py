import json
import re
import threading
import time
from urllib.parse import urlparse

from django.core.cache import cache
import requests

from reNgine.utilities.logger import get_module_logger

from . import settings
from .definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    RUNNING_BACKGROUND,
    RUNNING_TASK,
    SKIPPED_TASK,
    SUCCESS_TASK,
)


PREFIX_CONTEXT_PROCESSORS = "[CONTEXT_PROCESSORS]"
logger = get_module_logger(__name__)

EXTERNAL_IP_CACHE_KEY = "rengine_external_ip"
EXTERNAL_IP_CACHE_TTL_SUCCESS = 3600
EXTERNAL_IP_CACHE_TTL_FAILURE = 300

# In-process cache: first-level cache for all environments. Avoids hitting external IP
# services or Django cache on every request within the same process. With multiple
# workers (uWSGI, Gunicorn) each process has its own in-process cache; Django cache
# (e.g. Redis) is used as second level and for cross-process sharing.
_cached_external_ip_value: str | None = None
_cached_external_ip_expires_at: float = 0.0
_cached_external_ip_lock = threading.Lock()


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
            logger.log_line(
                PREFIX_CONTEXT_PROCESSORS,
                "EXTERNAL_IP",
                "Attempting to retrieve IP from: %s" % (service_url,),
                level="debug",
            )
            response = requests.get(service_url, timeout=settings.IP_SERVICE_TIMEOUT)
            response.raise_for_status()

            # Extract IP from response
            ip_text = response.text.strip()

            # For httpbin.org, the response is JSON
            if urlparse(service_url).netloc == "httpbin.org":
                data = json.loads(ip_text)
                ip_text = data.get("origin", "").split(",")[0].strip()

            # Validate that we got a valid IP address
            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_text):
                logger.log_line(
                    PREFIX_CONTEXT_PROCESSORS,
                    "EXTERNAL_IP",
                    "Successfully retrieved external IP: %s from %s" % (ip_text, service_url),
                    level="info",
                )
                return ip_text
            else:
                logger.log_line(
                    PREFIX_CONTEXT_PROCESSORS,
                    "EXTERNAL_IP",
                    "Invalid IP format received from %s: %s" % (service_url, ip_text),
                    level="warning",
                )

        except requests.RequestException as e:
            logger.log_line(
                PREFIX_CONTEXT_PROCESSORS,
                "EXTERNAL_IP",
                "Failed to retrieve IP from %s: %s" % (service_url, e),
                level="warning",
            )
            continue
        except Exception as e:
            logger.log_line(
                PREFIX_CONTEXT_PROCESSORS,
                "EXTERNAL_IP",
                "Unexpected error retrieving IP from %s: %s" % (service_url, e),
                level="warning",
            )
            continue

    logger.log_line(
        PREFIX_CONTEXT_PROCESSORS,
        "EXTERNAL_IP",
        "All IP services failed to retrieve external IP",
        level="error",
    )
    return "Unable to retrieve IP"


def clear_external_ip_in_process_cache() -> None:
    """
    Clear the in-process external IP cache. Use in tests or startup to avoid
    stale values across processes or long-lived workers.
    """
    global _cached_external_ip_value, _cached_external_ip_expires_at
    with _cached_external_ip_lock:
        _cached_external_ip_value = None
        _cached_external_ip_expires_at = 0.0


def _get_cached_external_ip() -> str:
    """
    Return external IP. Always check in-process cache first, then Django cache, then
    fetch from external services. In-process cache avoids repeated network or cache
    calls within the same process; thread-safe.
    """
    global _cached_external_ip_value, _cached_external_ip_expires_at
    now = time.monotonic()
    if _cached_external_ip_value is not None and now < _cached_external_ip_expires_at:
        return _cached_external_ip_value

    with _cached_external_ip_lock:
        now = time.monotonic()
        if _cached_external_ip_value is not None and now < _cached_external_ip_expires_at:
            return _cached_external_ip_value

        external_ip = cache.get(EXTERNAL_IP_CACHE_KEY)
        if external_ip is not None:
            ttl = (
                EXTERNAL_IP_CACHE_TTL_SUCCESS
                if external_ip != "Unable to retrieve IP"
                else EXTERNAL_IP_CACHE_TTL_FAILURE
            )
            _cached_external_ip_value = external_ip
            _cached_external_ip_expires_at = time.monotonic() + ttl
            return external_ip

        external_ip = _get_external_ip_with_fallback()
        ttl = EXTERNAL_IP_CACHE_TTL_SUCCESS if external_ip != "Unable to retrieve IP" else EXTERNAL_IP_CACHE_TTL_FAILURE
        cache.set(EXTERNAL_IP_CACHE_KEY, external_ip, timeout=ttl)
        _cached_external_ip_value = external_ip
        _cached_external_ip_expires_at = time.monotonic() + ttl
        return external_ip


def user_preferences(request):
    """Expose user interface preferences (e.g. DataTables display mode, page length) for templates."""
    from dashboard.models import DATATABLES_PAGE_LENGTH_MENU_VALUES
    from dashboard.services.user_preferences import get_datatables_display, get_datatables_page_length

    user = getattr(request, "user", None)
    datatables_display = get_datatables_display(user)
    use_datatables_scroller = datatables_display == "scroller"
    datatables_page_length = get_datatables_page_length(user)
    return {
        "datatables_display": datatables_display,
        "use_datatables_scroller": use_datatables_scroller,
        "datatables_page_length": datatables_page_length,
        "datatables_page_length_menu_values": DATATABLES_PAGE_LENGTH_MENU_VALUES,
    }


def dompurify_sanitize_config(request):
    """Expose HTML sanitization allowlist for frontend DOMPurify (single source of truth from core.html_sanitization)."""
    from reNgine.core.html_sanitization import get_dompurify_config_for_frontend

    return {"dompurify_sanitize_config": get_dompurify_config_for_frontend()}


def misc(request):
    # Scan status constants from definitions (single source of truth for timeline sort in JS)
    scan_status = {
        "INITIATED_TASK": INITIATED_TASK,
        "FAILED_TASK": FAILED_TASK,
        "RUNNING_TASK": RUNNING_TASK,
        "SUCCESS_TASK": SUCCESS_TASK,
        "ABORTED_TASK": ABORTED_TASK,
        "RUNNING_BACKGROUND": RUNNING_BACKGROUND,
        "SKIPPED_TASK": SKIPPED_TASK,
    }
    external_ip = _get_cached_external_ip()
    return {"external_ip": external_ip, "RENGINE_SCAN_STATUS": scan_status}
