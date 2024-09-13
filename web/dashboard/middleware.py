from django.http import HttpResponseForbidden
from django.urls import resolve
from dashboard.utils import get_user_projects
from django.shortcuts import redirect
from django.urls import reverse
from dashboard.models import Project
from django.utils.deprecation import MiddlewareMixin
from django.template.response import TemplateResponse

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
        # Initialize project to None
        request.project = None
        request.slug = None  # Initialize slug in the request

        # Check if the resolver_match is available
        if request.resolver_match:
            # Check if the slug is already in the kwargs
            if 'slug' not in request.resolver_match.kwargs:
                # Try to retrieve it from the query parameters
                slug = request.GET.get('slug')
                if slug:
                    request.resolver_match.kwargs['slug'] = slug

            # Fetch the current project based on the slug
            slug = request.resolver_match.kwargs.get('slug')
            if slug:
                request.slug = slug  # Set the slug in the request
                project = Project.objects.filter(slug=slug).first()
                request.project = project  # Attach project to the request
                request.context = {'project': project}

        # If no slug is provided or resolver_match is None, retrieve the first project for the authenticated user
        if request.project is None and request.user.is_authenticated:
            first_project = Project.objects.filter(users=request.user).first()
            if first_project:
                request.project = first_project  # Attach the first project to the request
                request.slug = first_project.slug  # Set the slug in the request
                request.context = {'project': first_project}

