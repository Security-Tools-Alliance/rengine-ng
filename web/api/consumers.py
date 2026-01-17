import json
import logging
import re

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer


logger = logging.getLogger(__name__)

# Constants
CHANNEL_NAME_PATTERN = r"[^a-zA-Z0-9\-\.]"


class OllamaDownloadConsumer(WebsocketConsumer):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(CHANNEL_NAME_PATTERN, "-", name)

    def connect(self):
        try:
            logger.info(f"WebSocket connection attempt with scope: {self.scope}")
            self.model_name = self.scope["url_route"]["kwargs"]["model_name"]
            self.room_group_name = f"ollama-download-{self.clean_channel_name(self.model_name)}"

            logger.info(f"Joining group: {self.room_group_name}")

            # Join room group
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)

            logger.info("WebSocket connection accepted")
            self.accept()

        except Exception as e:
            logger.error(f"Error in WebSocket connect: {e}")
            raise

    def disconnect(self, close_code):
        try:
            logger.info(f"WebSocket disconnecting with code: {close_code}")
            # Leave room group
            async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.error(f"Error in WebSocket disconnect: {e}")

    def receive(self, text_data):
        try:
            logger.info(f"WebSocket received data: {text_data}")
            text_data_json = json.loads(text_data)
            message = text_data_json.get("message")

            if not message:
                logger.warning("No 'message' field in received WebSocket data")
                return

            # Send message to room group
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name, {"type": "download_progress", "message": message}
            )
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in WebSocket receive: {e}")
        except Exception as e:
            logger.error(f"Error in WebSocket receive: {e}")

    def download_progress(self, event):
        try:
            message = event["message"]
            # Send message to WebSocket
            self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.error(f"Error in download_progress: {e}")


class IPScanProgressConsumer(WebsocketConsumer):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(CHANNEL_NAME_PATTERN, "-", name)

    def connect(self):
        try:
            logger.info(f"IP Scan WebSocket connection attempt with scope: {self.scope}")
            self.scan_id = self.scope["url_route"]["kwargs"]["scan_id"]
            self.room_group_name = f"ip-scan-{self.clean_channel_name(self.scan_id)}"

            logger.info(f"Joining IP scan group: {self.room_group_name}")

            # Join room group
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)

            logger.info("IP Scan WebSocket connection accepted")
            self.accept()

        except Exception as e:
            logger.error(f"Error in IP Scan WebSocket connect: {e}")
            raise

    def disconnect(self, close_code):
        try:
            logger.info(f"IP Scan WebSocket disconnecting with code: {close_code}")
            # Leave room group
            async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.error(f"Error in IP Scan WebSocket disconnect: {e}")

    def receive(self, text_data):
        try:
            logger.info(f"IP Scan WebSocket received data: {text_data}")
            text_data_json = json.loads(text_data)
            message = text_data_json.get("message")

            if not message:
                logger.warning("No 'message' field in received IP Scan WebSocket data")
                return

            # Send message to room group
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name, {"type": "scan_progress", "message": message}
            )
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in IP Scan WebSocket receive: {e}")
        except Exception as e:
            logger.error(f"Error in IP Scan WebSocket receive: {e}")

    def scan_progress(self, event):
        try:
            message = event["message"]
            # Send message to WebSocket
            self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.error(f"Error in IP scan_progress: {e}")
