from functools import wraps

from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse

from .models import Project


# Mapping of allauth provider IDs to human-friendly display names for OAuth flows.
# Shared so we keep naming consistent across views and templates.
PROVIDER_DISPLAY_NAMES = {
    "github": "GitHub",
    "google": "Google",
    "microsoft": "Microsoft",
    "gitlab": "GitLab",
    "openid_connect": "OpenID Connect",
}


def get_oauth_provider_display_name(user):
    """Return the human-friendly OAuth provider name for *user*, or ``'OAuth'``."""
    social_account = getattr(user, "socialaccount_set", None)
    if social_account is None:
        return "OAuth"
    first = social_account.first()
    if first is None:
        return "OAuth"
    return PROVIDER_DISPLAY_NAMES.get(
        first.provider,
        first.provider.replace("_", " ").title(),
    )


def is_oauth_user(user):
    """Return True if the given user authenticated via a social (OAuth) account.

    Keeps the logic for detecting OAuth users in one place so it can be reused
    in views and context processors.
    """
    if user is None:
        return False
    if not getattr(user, "is_authenticated", False):
        return False
    if not hasattr(user, "socialaccount_set"):
        return False
    return user.socialaccount_set.exists()


def get_user_projects(user):
    # Superusers see everything, ordered by name for consistency
    if user.is_superuser:
        return Project.objects.all().order_by("name")

    # SysAdmin users see all projects (regardless of OAuth status), ordered by name
    if get_user_groups(user) == "sys_admin":
        return Project.objects.all().order_by("name")

    # Other roles only see assigned projects, ordered by name
    return Project.objects.filter(users=user).order_by("name")


def user_has_project_access(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        project_slug = kwargs.get("slug")
        if project_slug:
            project = Project.objects.filter(slug=project_slug).first()
            if project and project in get_user_projects(request.user):
                return view_func(request, *args, **kwargs)
            if not project and request.user.is_superuser:
                return redirect(reverse("onboarding"))

            return redirect(reverse("page_not_found"))

        # Check if it's an API request
        if request.path.startswith("/api/"):
            return JsonResponse({"error": "Permission denied"}, status=403)

        return redirect(reverse("permission_denied"))

    return _wrapped_view


def get_user_groups(user):
    if user.is_superuser or user.groups.filter(name="sys_admin").exists():
        return "sys_admin"
    elif user.groups.filter(name="auditor").exists():
        return "auditor"
    elif user.groups.filter(name="penetration_tester").exists():
        return "penetration_tester"
    else:
        return "unknown"
