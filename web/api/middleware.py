import logging

from django.utils import timezone
from rest_framework_api_key.models import APIKey

from dashboard.models import UserAPIKey


logger = logging.getLogger(__name__)


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
        Expected format: Authorization: Api-Key <key>
        """
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        if auth_header.startswith("Api-Key "):
            key = auth_header[8:]  # Remove 'Api-Key ' prefix
            try:
                # Try to find UserAPIKey directly using get_from_key
                return UserAPIKey.objects.get_from_key(key)
            except (APIKey.DoesNotExist, UserAPIKey.DoesNotExist):
                return None
        return None
