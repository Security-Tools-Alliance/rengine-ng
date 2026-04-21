import json
import re
import threading
import time
from urllib.parse import urlparse

from django.core.cache import cache
import requests

from dashboard.utils import is_oauth_user
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

# Ordered fallback list; fourth entry is httpbin (JSON) — see tests.
_EXTERNAL_IP_SERVICE_URLS: tuple[str, ...] = (
    "https://checkip.amazonaws.com",
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://httpbin.org/ip",
    "https://ifconfig.me/ip",
)


def version(request):
    return {"RENGINE_CURRENT_VERSION": settings.RENGINE_CURRENT_VERSION}


def oauth_providers(request):
    """Expose which OAuth providers are actually usable at runtime.

    Detection checks **both** paths allauth supports:
    1. Settings-based — ``SOCIALACCOUNT_PROVIDERS[provider]["APP"]`` with a
       non-empty ``client_id`` and ``secret``.
    2. Database-based — a ``SocialApp`` record exists for the provider.

    A provider is considered configured if *either* source has valid
    credentials.  This avoids the "grayed-out buttons" problem that occurs
    when settings carry the credentials but ``setup_oauth`` has not (yet)
    created the corresponding ``SocialApp`` row.

    To avoid an extra DB query on every template render, ``is_oauth_user`` is
    only evaluated when OAuth is actually configured *and* the user is
    authenticated.  Views that need user-specific OAuth information for other
    purposes should call ``dashboard.utils.is_oauth_user`` explicitly.
    """
    # --- 1. Settings-based providers (SOCIALACCOUNT_PROVIDERS → APP/APPS) ---
    socialaccount_providers = getattr(settings, "SOCIALACCOUNT_PROVIDERS", {})
    settings_configured = set()
    for provider_id, config in socialaccount_providers.items():
        # Single-app providers use "APP"
        app_cfg = config.get("APP", {})
        if app_cfg.get("client_id") and app_cfg.get("secret"):
            settings_configured.add(provider_id)
            continue
        # Multi-app providers (e.g. openid_connect) use "APPS"
        for app in config.get("APPS", []):
            if app.get("client_id") and app.get("secret"):
                settings_configured.add(provider_id)
                break

    # Use settings as the source of truth for OAuth availability.
    # The database (SocialApp) is just a cache that gets updated by setup_oauth.
    # Only check settings to ensure .env changes are immediately reflected.
    app_providers = settings_configured

    # Ensure commonly-used provider keys are always present so templates can
    # safely reference them (e.g. ``oauth_providers.github``).
    configured = {
        provider_id: provider_id in app_providers
        for provider_id in ("google", "github", "microsoft", "gitlab", "openid_connect")
    }

    # Also expose any additional providers that have a SocialApp but aren't in
    # the hard-coded list above.
    for provider_id in app_providers:
        configured.setdefault(provider_id, True)

    has_any_oauth = bool(app_providers)

    # Only hit the DB when OAuth is configured and the user is logged in
    _is_oauth_user = False
    if has_any_oauth and getattr(getattr(request, "user", None), "is_authenticated", False):
        _is_oauth_user = is_oauth_user(request.user)

    return {
        "oauth_providers": configured,
        "has_any_oauth": has_any_oauth,
        "is_oauth_user": _is_oauth_user,
    }


def _get_external_ip_with_fallback() -> str:
    """
    Fetch public IPv4 from external services in order until one succeeds.
    Returns a dotted-quad string or the sentinel ``Unable to retrieve IP``.
    """
    for service_url in _EXTERNAL_IP_SERVICE_URLS:
        try:
            logger.log_line(
                PREFIX_CONTEXT_PROCESSORS,
                "EXTERNAL_IP",
                "Attempting to retrieve IP from: %s" % (service_url,),
                level="debug",
            )
            response = requests.get(service_url, timeout=settings.IP_SERVICE_TIMEOUT)
            response.raise_for_status()

            ip_text = response.text.strip()

            if urlparse(service_url).netloc == "httpbin.org":
                data = json.loads(ip_text)
                ip_text = data.get("origin", "").split(",")[0].strip()

            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_text):
                logger.log_line(
                    PREFIX_CONTEXT_PROCESSORS,
                    "EXTERNAL_IP",
                    "Successfully retrieved external IP: %s from %s" % (ip_text, service_url),
                    level="info",
                )
                return ip_text

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
        except Exception as e:
            logger.log_line(
                PREFIX_CONTEXT_PROCESSORS,
                "EXTERNAL_IP",
                "Unexpected error retrieving IP from %s: %s" % (service_url, e),
                level="warning",
            )

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
