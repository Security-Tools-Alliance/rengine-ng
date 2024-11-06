from django.urls import resolve
from dashboard.utils import get_user_projects
from django.shortcuts import redirect
from django.urls import reverse
from dashboard.models import Project
from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import get_object_or_404
from .models import Project

class ProjectAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        resolved = resolve(request.path_info)
        if 'slug' in resolved.kwargs:
            slug = resolved.kwargs['slug']
            project = Project.objects.filter(slug=slug).first()

            # Check if the user is authenticated
            if not request.user.is_authenticated:
                return redirect(reverse('permission_denied'))

            # If the project exists and the user has access
            if project and project in get_user_projects(request.user):
                return self.get_response(request)

            # If the project does not exist or the user does not have access
            if project:
                return redirect(reverse('page_not_found'))
            else:
                return redirect(reverse('permission_denied'))

        return self.get_response(request)


class SlugMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.current_project = None
        request.slug = None

        # Try to get the project ID from the cookie
        if project_id := request.COOKIES.get('currentProjectId'):
            request.current_project = get_object_or_404(Project, id=project_id)
            request.slug = request.current_project.slug
        elif request.resolver_match and 'slug' in request.resolver_match.kwargs:
            slug = request.resolver_match.kwargs['slug']
            request.slug = slug
            request.current_project = get_object_or_404(Project, slug=slug)

        # If no project is found, use the first project of the user
        if request.current_project is None and request.user.is_authenticated:
            request.current_project = Project.objects.filter(users=request.user).first()
            if request.current_project:
                request.slug = request.current_project.slug

        # Update the session with the current project ID
        if request.current_project:
            request.session['current_project_id'] = request.current_project.id
