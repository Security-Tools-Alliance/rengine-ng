"""
Custom OAuth adapter for reNgine-ng
Handles user creation with minimal permissions and proper redirects
"""

import logging

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib import messages
from django.urls import reverse
from rolepermissions.checkers import has_role
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.utils import get_user_projects, is_oauth_user


logger = logging.getLogger(__name__)


class OAuthAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom adapter for OAuth authentication
    - Sets unusable password (OAuth users don't need one)
    - Username comes from OAuth provider
    - Role assignment handled by signals.py to avoid duplication
    """

    def save_user(self, request, sociallogin, form=None):
        """
        Save new OAuth user with unusable password.
        Role assignment is handled by the user_signed_up signal in signals.py.
        """
        user = super().save_user(request, sociallogin, form)

        # Set unusable password - OAuth users authenticate via provider
        user.set_unusable_password()
        user.save()

        return user

    def _get_oauth_error_message(self, error=None, default_message="OAuth authentication failed."):
        """
        Generate an OAuth error message suitable for user display.

        The raw error from the provider is intentionally not exposed to the user
        to avoid leaking implementation details or sensitive information.
        """
        return default_message

    def on_authentication_error(self, request, provider_id, error=None, exception=None, extra_context=None):
        """
        Handle OAuth authentication errors by redirecting to login page with an error message.
        """
        # Log the raw error/exception details for internal diagnostics only.
        logger.warning(
            "OAuth authentication error for provider '%s': error=%r, exception=%r, extra_context=%r",
            provider_id,
            error,
            exception,
            extra_context,
        )

        error_message = self._get_oauth_error_message(error)
        messages.error(request, error_message)
        # Return None to let allauth handle the redirect, which will go to login
        return None

    def authentication_error(self, request, provider_id, error=None, exception=None, extra_context=None):
        """
        Called when OAuth authentication fails.
        Redirect to login page with an error message.
        """
        error_message = self._get_oauth_error_message(
            error, "OAuth authentication failed. Please try again or use another login method."
        )
        messages.error(request, error_message)


class AccountAdapter(DefaultAccountAdapter):
    """
    Custom account adapter to handle login redirects
    """

    def get_login_redirect_url(self, request):
        """
        Redirect users appropriately after login:
        - OAuth users skip onboarding and land on the projects list (no project access by default)
        - If project exists: go to dashboard
        - If no project and user is admin: go to onboarding
        - If no project and user is not admin: go to projects list (they can't create)
        """
        user = request.user

        if is_oauth_user(user):
            # Ensure OAuth users keep the minimum Auditor role
            if not has_role(user, "auditor"):
                assign_role(user, "auditor")

            # If they have project access, go to their project dashboard.
            # Order explicitly so the selected project is deterministic
            # (most recently created project).
            if user_project := (Project.objects.filter(users=user).order_by("-insert_date").first()):
                return reverse("dashboardIndex", kwargs={"slug": user_project.slug})

            # First-ever login: show welcome page once
            # Note: last_login is updated during login, so it's None only on the very first login.
            # While this may have edge cases in read-replica setups, it's acceptable for this feature -
            # worst case is the welcome page shows one extra time or skips once (non-critical).
            if user.last_login is None:
                return reverse("oauth_welcome")

            return reverse("list_projects")

        if project := get_user_projects(user).first():
            return reverse("dashboardIndex", kwargs={"slug": project.slug})

        # No accessible project exists
        if user.is_superuser or has_role(user, "sys_admin"):
            # Admins can create projects via onboarding
            return reverse("onboarding")

        # Non-admin users see projects list (read-only message)
        return reverse("list_projects")
