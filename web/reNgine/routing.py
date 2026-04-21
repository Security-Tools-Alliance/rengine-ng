from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path

from api.consumers import (
    IPScanProgressConsumer,
    OllamaDownloadConsumer,
    ScanStatusConsumer,
    WorkerDeployConsumer,
    WorkerRefreshConsumer,
    WorkerStatusConsumer,
)


websocket_urlpatterns = [
    re_path(r"^ws/ollama/download/(?P<model_name>[\w\-\.]+)/$", OllamaDownloadConsumer.as_asgi()),
    re_path(r"^ws/ip-scan/(?P<scan_id>[\w\-\.]+)/$", IPScanProgressConsumer.as_asgi()),
    re_path(r"^ws/scan-status/(?P<scan_id>[\w\-\.]+)/$", ScanStatusConsumer.as_asgi()),
    re_path(r"^ws/scan-status/project/(?P<project_slug>[\w\-\.]+)/$", ScanStatusConsumer.as_asgi()),
    re_path(r"^ws/worker-status/$", WorkerStatusConsumer.as_asgi()),
    re_path(r"^ws/worker-deploy/(?P<worker_id>\d+)/$", WorkerDeployConsumer.as_asgi()),
    re_path(r"^ws/worker-refresh/(?P<worker_id>\d+)/$", WorkerRefreshConsumer.as_asgi()),
]

application = ProtocolTypeRouter(
    {
        "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
    }
)
