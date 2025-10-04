import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

from reNgine.settings import UI_REMOTE_DEBUG

from .routing import websocket_urlpatterns


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "reNgine.settings")

# Initialize Django settings first
import django


django.setup()

# Remote debug setup for ASGI (daphne) development server
if UI_REMOTE_DEBUG:
    try:
        from debugger_setup import setup_debugger

        setup_debugger()
    except ImportError:
        print("⚠️  Could not import debugger_setup module")

application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(),
        "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
    }
)
