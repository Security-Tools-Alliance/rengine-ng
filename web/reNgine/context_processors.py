from dashboard.models import Project
from dashboard.utils import get_user_projects
from . import settings
import requests

def projects(request):
    if(request.user.is_authenticated):
        projects = get_user_projects(request.user)
        try:
            slug = request.resolver_match.kwargs.get('slug')
            project = Project.objects.get(slug=slug)
        except Exception:
            project = None
        return {
            'projects': projects,
            'current_project': project
        }
    else:
        return {
            'projects': [],
            'current_project': None
        }

def version(request):
    return {"RENGINE_CURRENT_VERSION": settings.RENGINE_CURRENT_VERSION}

def misc(request):
    externalIp = requests.get('https://checkip.amazonaws.com').text.strip()
    return {
        'external_ip': externalIp
    }