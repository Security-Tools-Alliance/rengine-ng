from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path

from api.consumers import IPScanProgressConsumer, OllamaDownloadConsumer, ScanStatusConsumer


websocket_urlpatterns = [
    re_path(r"^ws/ollama/download/(?P<model_name>[\w\-\.]+)/$", OllamaDownloadConsumer.as_asgi()),
    re_path(r"^ws/ip-scan/(?P<scan_id>[\w\-\.]+)/$", IPScanProgressConsumer.as_asgi()),
    re_path(r"^ws/scan-status/(?P<scan_id>[\w\-\.]+)/$", ScanStatusConsumer.as_asgi()),
    re_path(r"^ws/scan-status/project/(?P<project_slug>[\w\-\.]+)/$", ScanStatusConsumer.as_asgi()),
]

application = ProtocolTypeRouter(
    {
        "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
    }
)
