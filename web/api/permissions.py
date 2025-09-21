from rest_framework.permissions import BasePermission
from rest_framework_api_key.permissions import HasAPIKey


class HasAPIKeyOrIsAuthenticated(BasePermission):
    """
    Permission class that allows access with either:
    1. Valid API Key (processed by our middleware)
    2. Regular Django session authentication

    This combines the functionality of HasAPIKey and IsAuthenticated.
    """

    def has_permission(self, request, view):
        # Check if middleware set API key authentication
        if hasattr(request, "_api_key_authenticated") and request._api_key_authenticated:
            return True

        # Check if user is authenticated via session
        if request.user and request.user.is_authenticated:
            return True

        # Also try the standard HasAPIKey permission as fallback
        return HasAPIKey().has_permission(request, view)
