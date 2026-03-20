"""
Signal handlers for dashboard app.
Kept in a separate module to ensure idempotent registration when imported in AppConfig.ready().
"""

from allauth.account.signals import user_signed_up
from django.dispatch import receiver
from rolepermissions.roles import assign_role


@receiver(user_signed_up)
def setup_oauth_user(request, user, **kwargs):
    """
    Assign minimum role to OAuth users and disable password.
    This runs once when a user signs up via OAuth.
    """
    sociallogin = kwargs.get("sociallogin")
    if sociallogin:
        # Assign Auditor role (minimum permissions - read-only)
        assign_role(user, "auditor")
        # Set unusable password - OAuth users can set it later if needed
        user.set_unusable_password()
        user.save()
