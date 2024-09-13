from .models import Project
from dashboard.utils import get_user_projects  # Assuming this function exists

def project_context(request):
    project = getattr(request, 'project', None)  # Get the project from the request
    projects = get_user_projects(request.user) if request.user.is_authenticated else []

    # If project is None, take the first project from the projects list
    if project is None and projects:
        project = projects[0]  # Get the first project from the projects list

    return {
        'project': project,  # Add the current project to the context
        'projects': projects,  # Add user projects to the context if needed
    }
