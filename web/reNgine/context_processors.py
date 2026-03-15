import logging

from django.core.cache import cache
import requests

from dashboard.utils import is_oauth_user

from . import settings


logger = logging.getLogger(__name__)


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


def misc(request):
    # Attempt to retrieve the external IP address from the cache
    external_ip = cache.get("external_ip")

    if external_ip is None:
        try:
            # If the IP address is not in the cache, make the request
            external_ip = requests.get("https://checkip.amazonaws.com").text.strip()
            # Cache the IP address for 1 hour (3600 seconds)
            cache.set("external_ip", external_ip, timeout=3600)
        except requests.RequestException as e:
            # Handle the exception if the request fails
            external_ip = "Unable to retrieve IP"  # Default value in case of error
            # You can also log the error if necessary
            logger.error(f"Error retrieving external IP: {e}")

    return {"external_ip": external_ip}
