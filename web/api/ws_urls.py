from django.urls import path
from . import consumers, views

websocket_urlpatterns = [
    path('ollama/download/<str:model_name>/', consumers.OllamaDownloadConsumer.as_asgi()),
]

# URLs HTTP normales pour la découverte des WebSockets
urlpatterns = [
    path('status/', views.websocket_status, name='websocket_status'),
]