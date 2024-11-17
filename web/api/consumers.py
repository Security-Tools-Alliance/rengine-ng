from channels.generic.websocket import WebsocketConsumer
from asgiref.sync import async_to_sync
import json
import re
import logging

logger = logging.getLogger(__name__)

class OllamaDownloadConsumer(WebsocketConsumer):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(r'[^a-zA-Z0-9\-\.]', '-', name)

    def connect(self):
        try:
            logger.info(f"WebSocket connection attempt with scope: {self.scope}")
            self.model_name = self.scope['url_route']['kwargs']['model_name']
            self.room_group_name = f"ollama-download-{self.clean_channel_name(self.model_name)}"
            
            logger.info(f"Joining group: {self.room_group_name}")
            
            # Join room group
            async_to_sync(self.channel_layer.group_add)(
                self.room_group_name,
                self.channel_name
            )
            
            logger.info("WebSocket connection accepted")
            self.accept()
            
        except Exception as e:
            logger.error(f"Error in WebSocket connect: {e}")
            raise

    def disconnect(self, close_code):
        try:
            logger.info(f"WebSocket disconnecting with code: {close_code}")
            # Leave room group
            async_to_sync(self.channel_layer.group_discard)(
                self.room_group_name,
                self.channel_name
            )
        except Exception as e:
            logger.error(f"Error in WebSocket disconnect: {e}")

    def receive(self, text_data):
        try:
            logger.info(f"WebSocket received data: {text_data}")
            text_data_json = json.loads(text_data)
            message = text_data_json['message']

            # Send message to room group
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name,
                {
                    'type': 'download_progress',
                    'message': message
                }
            )
        except Exception as e:
            logger.error(f"Error in WebSocket receive: {e}")

    def download_progress(self, event):
        try:
            message = event['message']
            # Send message to WebSocket
            self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.error(f"Error in download_progress: {e}")