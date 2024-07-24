from dashboard.models import *
from . import settings

def projects(request):
    projects = Project.objects.all()
    try:
        slug = request.resolver_match.kwargs.get('slug')
        project = Project.objects.get(slug=slug)
    except Exception as e:
        project = None
    return {
        'projects': projects,
        'current_project': project
    }

def version(request):
    return {"RENGINE_CURRENT_VERSION": settings.RENGINE_CURRENT_VERSION}
