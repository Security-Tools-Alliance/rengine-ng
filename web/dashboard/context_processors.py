from django.core.exceptions import SynchronousOnlyOperation

from dashboard.utils import get_user_projects  # Assuming this function exists


def project_context(request):
    current_project = getattr(request, "current_project", None)  # Get the project from the request

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

    return {
        "current_project": current_project,  # Add the current project to the context
        "projects": projects,  # Add user projects to the context if needed
    }
