from functools import wraps

from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse

from .models import Project


def get_user_projects(user):
    # Superusers see everything
    if user.is_superuser:
        return Project.objects.all()

    # SysAdmin users see all projects unless they are OAuth users, who only see explicit assignments
    if get_user_groups(user) == "sys_admin":
        is_oauth_user = hasattr(user, 'socialaccount_set') and user.socialaccount_set.exists()
        if is_oauth_user:
            return Project.objects.filter(users=user)
        return Project.objects.all().order_by("name")

    # Other roles only see assigned projects
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
