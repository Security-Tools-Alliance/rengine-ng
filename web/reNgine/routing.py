from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from api.consumers import OllamaDownloadConsumer

websocket_urlpatterns = [
    re_path(r'^ws/ollama/download/(?P<model_name>[\w\-\.]+)/$', OllamaDownloadConsumer.as_asgi()),
]

application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})