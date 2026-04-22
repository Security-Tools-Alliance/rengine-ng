from urllib.parse import quote

from django.core.exceptions import SynchronousOnlyOperation

from dashboard.constants import PROJECT_CONTEXT_QUERY_PARAM
from dashboard.utils import get_user_projects  # Assuming this function exists


def project_context(request):
    current_project = getattr(request, "current_project", None)  # Get the project from the request
    project_slug_from_url = ""

    if getattr(request, "resolver_match", None) and "slug" in request.resolver_match.kwargs:
        raw_slug = request.resolver_match.kwargs.get("slug")
        if raw_slug:
            project_slug_from_url = str(raw_slug)

    # Force evaluation of the queryset to avoid SynchronousOnlyOperation in async context
    if request.user.is_authenticated:
        try:
            projects = list(get_user_projects(request.user))
        except SynchronousOnlyOperation:
            # Skip project lookup in async context to avoid SynchronousOnlyOperation
            projects = []
    else:
        projects = []

    # If project is None, take the first project from the projects list
    if current_project is None and projects:
        current_project = projects[0]  # Get the first project from the projects list

    project_nav_q = ""
    project_nav_a = ""
    if current_project:
        enc = quote(current_project.slug, safe="")
        project_nav_q = f"?{PROJECT_CONTEXT_QUERY_PARAM}={enc}"
        project_nav_a = f"&{PROJECT_CONTEXT_QUERY_PARAM}={enc}"

    context = {
        "current_project": current_project,  # Add the current project to the context
        "projects": projects,  # Add user projects to the context if needed
        "project_slug_from_url": project_slug_from_url,
        "project_nav_q": project_nav_q,
        "project_nav_a": project_nav_a,
        "project_context_query_param": PROJECT_CONTEXT_QUERY_PARAM,
    }
    if current_project:
        from api.helpers.datatables import get_datatable_action_urls

        context["datatable_action_urls"] = get_datatable_action_urls(current_project.slug)
    return context
