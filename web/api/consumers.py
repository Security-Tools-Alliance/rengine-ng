import json
import logging
import re

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer

from reNgine.utilities.worker_ws_groups import worker_deploy_group, worker_refresh_group


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


class ScanStatusConsumer(WebsocketConsumer):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(CHANNEL_NAME_PATTERN, "-", name)

    def connect(self):
        try:
            logger.info(f"Scan Status WebSocket connection attempt with scope: {self.scope}")
            scan_id = self.scope["url_route"]["kwargs"].get("scan_id")
            project_slug = self.scope["url_route"]["kwargs"].get("project_slug")

            if scan_id:
                self.room_group_name = f"scan-status-{self.clean_channel_name(str(scan_id))}"
            elif project_slug:
                self.room_group_name = f"scan-status-project-{self.clean_channel_name(project_slug)}"
            else:
                logger.error("No scan_id or project_slug provided in WebSocket connection")
                self.close()
                return

            logger.info(f"Joining scan status group: {self.room_group_name}")

            # Join room group
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)

            logger.info("Scan Status WebSocket connection accepted")
            self.accept()

        except Exception as e:
            logger.error(f"Error in Scan Status WebSocket connect: {e}")
            raise

    def disconnect(self, close_code):
        try:
            logger.info(f"Scan Status WebSocket disconnecting with code: {close_code}")
            # Leave room group
            async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.error(f"Error in Scan Status WebSocket disconnect: {e}")

    def scan_status_update(self, event):
        """Send scan status update to WebSocket client"""
        try:
            message = event["message"]
            # Send message to WebSocket
            self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.error(f"Error in scan_status_update: {e}")


WORKER_STATUS_GROUP = "worker-status"


class WorkerStatusConsumer(WebsocketConsumer):
    """WebSocket consumer for Secator worker status updates (list/detail UI)."""

    def connect(self):
        try:
            async_to_sync(self.channel_layer.group_add)(WORKER_STATUS_GROUP, self.channel_name)
            self.accept()
        except Exception as e:
            logger.error("Worker status WebSocket connect failed: %s", e)
            raise

    def disconnect(self, close_code):
        try:
            async_to_sync(self.channel_layer.group_discard)(WORKER_STATUS_GROUP, self.channel_name)
        except Exception as e:
            logger.error("Worker status WebSocket disconnect failed: %s", e)

    def worker_status_update(self, event):
        """Send worker status update to WebSocket client."""
        try:
            self.send(text_data=json.dumps(event.get("payload", {})))
        except Exception as e:
            logger.error("Error in worker_status_update: %s", e)


class WorkerDeployConsumer(WebsocketConsumer):
    """WebSocket consumer for worker deploy log stream (modal progress)."""

    def connect(self):
        try:
            worker_id = self.scope["url_route"]["kwargs"].get("worker_id")
            if worker_id is None or (isinstance(worker_id, str) and not worker_id.isdigit()):
                self.close(code=4000)
                return
            self.worker_id = int(worker_id)
            if self.worker_id <= 0:
                self.close(code=4000)
                return
            self.room_group_name = worker_deploy_group(self.worker_id)
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)
            self.accept()
        except Exception as e:
            logger.error("Worker deploy WebSocket connect failed: %s", e)
            raise

    def disconnect(self, close_code):
        try:
            if hasattr(self, "room_group_name"):
                async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.error("Worker deploy WebSocket disconnect failed: %s", e)

    def worker_deploy_log(self, event):
        """Forward deploy log payload to WebSocket client."""
        try:
            self.send(text_data=json.dumps(event.get("payload", {})))
        except Exception as e:
            logger.error("Error in worker_deploy_log: %s", e)


class WorkerRefreshConsumer(WebsocketConsumer):
    """WebSocket consumer for worker refresh log stream (modal progress)."""

    def connect(self):
        try:
            worker_id = self.scope["url_route"]["kwargs"].get("worker_id")
            if worker_id is None or (isinstance(worker_id, str) and not worker_id.isdigit()):
                self.close(code=4000)
                return
            self.worker_id = int(worker_id)
            if self.worker_id <= 0:
                self.close(code=4000)
                return
            self.room_group_name = worker_refresh_group(self.worker_id)
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)
            self.accept()
        except Exception as e:
            logger.error("Worker refresh WebSocket connect failed: %s", e)
            raise

    def disconnect(self, close_code):
        try:
            if hasattr(self, "room_group_name"):
                async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.error("Worker refresh WebSocket disconnect failed: %s", e)

    def worker_refresh_log(self, event):
        """Forward refresh log payload to WebSocket client."""
        try:
            self.send(text_data=json.dumps(event.get("payload", {})))
        except Exception as e:
            logger.error("Error in worker_refresh_log: %s", e)
