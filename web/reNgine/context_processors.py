from . import settings
import requests

def version(request):
    return {"RENGINE_CURRENT_VERSION": settings.RENGINE_CURRENT_VERSION}

def misc(request):
    externalIp = requests.get('https://checkip.amazonaws.com').text.strip()
    return {
        'external_ip': externalIp
    }