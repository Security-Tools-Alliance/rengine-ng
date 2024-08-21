from functools import wraps
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from .models import Project

def get_user_projects(user):
    if user.is_superuser:
        return Project.objects.all()
    return Project.objects.filter(users=user)

def user_has_project_access_by_id(user, project_id):
    if user.is_superuser:
        return True
    try:
        project = Project.objects.get(id=project_id)
        return project in get_user_projects(user)
    except Project.DoesNotExist:
        return False

def user_has_project_access(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        project_slug = kwargs.get('slug')
        if project_slug:
            project = Project.objects.filter(slug=project_slug).first()
            if project and project in get_user_projects(request.user):
                return view_func(request, *args, **kwargs)
        
        # Check if it's an API request
        if request.path.startswith('/api/'):
            return JsonResponse({'error': 'Permission denied'}, status=403)
        else:
            # Redirect to a "Permission denied" page for the UI
            return redirect(reverse('permission_denied', kwargs={'slug': project_slug}))

    return _wrapped_view