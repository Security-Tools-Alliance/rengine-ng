"""
Custom OAuth adapter for reNgine-ng
Handles user creation with minimal permissions and proper redirects
"""
from django.contrib import messages
from django.urls import reverse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.adapter import DefaultAccountAdapter
from rolepermissions.roles import assign_role
from rolepermissions.checkers import has_role

from dashboard.models import Project


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
        Generate an OAuth error message.
        """
        return f"OAuth authentication failed: {error}" if error else default_message

    def on_authentication_error(self, request, provider_id, error=None, exception=None, extra_context=None):
        """
        Handle OAuth authentication errors by redirecting to login page with an error message.
        """
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

        if (social_accounts := getattr(user, 'socialaccount_set', None)) and social_accounts.exists():
            # Ensure OAuth users keep the minimum Auditor role
            if not has_role(user, 'auditor'):
                assign_role(user, 'auditor')

            # OAuth users should not be sent to onboarding; show assigned project if any
            user_project = Project.objects.filter(users=user).first()
            if user_project:
                return reverse('dashboardIndex', kwargs={'slug': user_project.slug})
            return reverse('list_projects')

        if project := Project.objects.first():
            return reverse('dashboardIndex', kwargs={'slug': project.slug})

        # No project exists
        if user.is_superuser or has_role(user, 'sys_admin'):
            # Admins can create projects via onboarding
            return reverse('onboarding')

        # Non-admin users see projects list (read-only message)
        return reverse('list_projects')
