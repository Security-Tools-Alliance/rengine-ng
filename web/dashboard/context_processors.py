from dashboard.utils import get_user_projects  # Assuming this function exists

def project_context(request):
    current_project = getattr(request, 'current_project', None)  # Get the project from the request
    projects = get_user_projects(request.user) if request.user.is_authenticated else []

    # If project is None, take the first project from the projects list
    if current_project is None and projects:
        current_project = projects[0]  # Get the first project from the projects list

    return {
        'current_project': current_project,  # Add the current project to the context
        'projects': projects,  # Add user projects to the context if needed
    }
