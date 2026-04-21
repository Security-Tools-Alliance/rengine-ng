from django.conf import settings
from django.utils import timezone
from rest_framework_api_key.models import APIKey

from dashboard.models import UserAPIKey
from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)


class APIKeyAuthenticationMiddleware:
    """
    Middleware to handle API Key authentication for external access (e.g., Burp Suite).

    This middleware intercepts API requests and simulates an authenticated user
    when a valid API key is provided, allowing bypass of LoginRequiredMiddleware
    and CSRF verification (since API keys provide sufficient authentication security).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only process API requests
        if request.path.startswith("/api/"):
            user_api_key = self.get_api_key_from_request(request)
            if (
                user_api_key
                and user_api_key.is_active
                and not user_api_key.revoked
                and (not user_api_key.expiry_date or user_api_key.expiry_date > timezone.now())
            ):
                # Simulate authenticated user for LoginRequiredMiddleware
                request.user = user_api_key.user
                request._api_key_authenticated = True
                # Store the API key for permission checking
                request._api_key = user_api_key
                # Exempt from CSRF verification for API key authenticated requests
                request._dont_enforce_csrf_checks = True
                # Update last used timestamp (throttled to reduce DB writes)
                now = timezone.now()
                if not user_api_key.last_used or (now - user_api_key.last_used).total_seconds() > 300:  # 5 minutes
                    user_api_key.last_used = now
                    user_api_key.save(update_fields=["last_used"])

        return self.get_response(request)

    def get_api_key_from_request(self, request):
        """
        Extract API key from Authorization header.
        Expected format: Authorization: <header_name> <key>
        """
        auth_header = (request.META.get("HTTP_AUTHORIZATION", "") or "").strip()
        if not auth_header:
            return None

        configured_header_name = (getattr(settings, "SECATOR_ADDONS_API_HEADER_NAME", "") or "").strip()
        candidate_header_names = [configured_header_name, "Api-Key"]

        for header_name in candidate_header_names:
            if not header_name:
                continue
            prefix = f"{header_name} "
            if not auth_header.lower().startswith(prefix.lower()):
                continue
            key = auth_header[len(prefix) :].strip()
            if not key:
                return None
            try:
                # Try to find UserAPIKey directly using get_from_key
                return UserAPIKey.objects.get_from_key(key)
            except (APIKey.DoesNotExist, UserAPIKey.DoesNotExist):
                return None
        return None
