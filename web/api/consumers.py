import json
import re

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer

from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.worker_ws_groups import worker_deploy_group, worker_refresh_group

PREFIX_API = "[API]"
logger = get_module_logger(__name__)

# Constants
CHANNEL_NAME_PATTERN = r"[^a-zA-Z0-9\-\.]"


class OllamaDownloadConsumer(WebsocketConsumer):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(CHANNEL_NAME_PATTERN, "-", name)

    def connect(self):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "WebSocket connection attempt with scope: %s" % (self.scope,),
                level="info",
            )
            self.model_name = self.scope["url_route"]["kwargs"]["model_name"]
            self.room_group_name = f"ollama-download-{self.clean_channel_name(self.model_name)}"

            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "Joining group: %s" % (self.room_group_name,),
                level="info",
            )

            # Join room group
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)

            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "WebSocket connection accepted",
                level="info",
            )
            self.accept()

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "Error in WebSocket connect: %s" % (e,),
                level="error",
            )
            raise

    def disconnect(self, close_code):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "WebSocket disconnecting with code: %s" % (close_code,),
                level="info",
            )
            # Leave room group
            async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "Error in WebSocket disconnect: %s" % (e,),
                level="error",
            )

    def receive(self, text_data):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "WebSocket received data: %s" % (text_data,),
                level="info",
            )
            text_data_json = json.loads(text_data)
            message = text_data_json.get("message")

            if not message:
                logger.log_line(
                    PREFIX_API,
                    "WS_OLLAMA",
                    "No 'message' field in received WebSocket data",
                    level="warning",
                )
                return

            # Send message to room group
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name, {"type": "download_progress", "message": message}
            )
        except json.JSONDecodeError as e:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "Invalid JSON in WebSocket receive: %s" % (e,),
                level="error",
            )
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "Error in WebSocket receive: %s" % (e,),
                level="error",
            )

    def download_progress(self, event):
        try:
            message = event["message"]
            # Send message to WebSocket
            self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_OLLAMA",
                "Error in download_progress: %s" % (e,),
                level="error",
            )


class IPScanProgressConsumer(WebsocketConsumer):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(CHANNEL_NAME_PATTERN, "-", name)

    def connect(self):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "IP Scan WebSocket connection attempt with scope: %s" % (self.scope,),
                level="info",
            )
            self.scan_id = self.scope["url_route"]["kwargs"]["scan_id"]
            self.room_group_name = f"ip-scan-{self.clean_channel_name(self.scan_id)}"

            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "Joining IP scan group: %s" % (self.room_group_name,),
                level="info",
            )

            # Join room group
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)

            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "IP Scan WebSocket connection accepted",
                level="info",
            )
            self.accept()

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "Error in IP Scan WebSocket connect: %s" % (e,),
                level="error",
            )
            raise

    def disconnect(self, close_code):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "IP Scan WebSocket disconnecting with code: %s" % (close_code,),
                level="info",
            )
            # Leave room group
            async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "Error in IP Scan WebSocket disconnect: %s" % (e,),
                level="error",
            )

    def receive(self, text_data):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "IP Scan WebSocket received data: %s" % (text_data,),
                level="info",
            )
            text_data_json = json.loads(text_data)
            message = text_data_json.get("message")

            if not message:
                logger.log_line(
                    PREFIX_API,
                    "WS_IP_SCAN",
                    "No 'message' field in received IP Scan WebSocket data",
                    level="warning",
                )
                return

            # Send message to room group
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name, {"type": "scan_progress", "message": message}
            )
        except json.JSONDecodeError as e:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "Invalid JSON in IP Scan WebSocket receive: %s" % (e,),
                level="error",
            )
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "Error in IP Scan WebSocket receive: %s" % (e,),
                level="error",
            )

    def scan_progress(self, event):
        try:
            message = event["message"]
            # Send message to WebSocket
            self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_IP_SCAN",
                "Error in IP scan_progress: %s" % (e,),
                level="error",
            )


class ScanStatusConsumer(WebsocketConsumer):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(CHANNEL_NAME_PATTERN, "-", name)

    def connect(self):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_SCAN_STATUS",
                "Scan Status WebSocket connection attempt with scope: %s" % (self.scope,),
                level="info",
            )
            scan_id = self.scope["url_route"]["kwargs"].get("scan_id")
            project_slug = self.scope["url_route"]["kwargs"].get("project_slug")

            if scan_id:
                self.room_group_name = f"scan-status-{self.clean_channel_name(str(scan_id))}"
            elif project_slug:
                self.room_group_name = f"scan-status-project-{self.clean_channel_name(project_slug)}"
            else:
                logger.log_line(
                    PREFIX_API,
                    "WS_SCAN_STATUS",
                    "No scan_id or project_slug provided in WebSocket connection",
                    level="error",
                )
                self.close()
                return

            logger.log_line(
                PREFIX_API,
                "WS_SCAN_STATUS",
                "Joining scan status group: %s" % (self.room_group_name,),
                level="info",
            )

            # Join room group
            async_to_sync(self.channel_layer.group_add)(self.room_group_name, self.channel_name)

            logger.log_line(
                PREFIX_API,
                "WS_SCAN_STATUS",
                "Scan Status WebSocket connection accepted",
                level="info",
            )
            self.accept()

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_SCAN_STATUS",
                "Error in Scan Status WebSocket connect: %s" % (e,),
                level="error",
            )
            raise

    def disconnect(self, close_code):
        try:
            logger.log_line(
                PREFIX_API,
                "WS_SCAN_STATUS",
                "Scan Status WebSocket disconnecting with code: %s" % (close_code,),
                level="info",
            )
            # Leave room group
            async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_SCAN_STATUS",
                "Error in Scan Status WebSocket disconnect: %s" % (e,),
                level="error",
            )

    def scan_status_update(self, event):
        """Send scan status update to WebSocket client"""
        try:
            message = event["message"]
            # Send message to WebSocket
            self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_SCAN_STATUS",
                "Error in scan_status_update: %s" % (e,),
                level="error",
            )


WORKER_STATUS_GROUP = "worker-status"


class WorkerStatusConsumer(WebsocketConsumer):
    """WebSocket consumer for Secator worker status updates (list/detail UI)."""

    def connect(self):
        try:
            async_to_sync(self.channel_layer.group_add)(WORKER_STATUS_GROUP, self.channel_name)
            self.accept()
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_STATUS",
                "Worker status WebSocket connect failed: %s" % (e,),
                level="error",
            )
            raise

    def disconnect(self, close_code):
        try:
            async_to_sync(self.channel_layer.group_discard)(WORKER_STATUS_GROUP, self.channel_name)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_STATUS",
                "Worker status WebSocket disconnect failed: %s" % (e,),
                level="error",
            )

    def worker_status_update(self, event):
        """Send worker status update to WebSocket client."""
        try:
            self.send(text_data=json.dumps(event.get("payload", {})))
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_STATUS",
                "Error in worker_status_update: %s" % (e,),
                level="error",
            )


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
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_DEPLOY",
                "Worker deploy WebSocket connect failed: %s" % (e,),
                level="error",
            )
            raise

    def disconnect(self, close_code):
        try:
            if hasattr(self, "room_group_name"):
                async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_DEPLOY",
                "Worker deploy WebSocket disconnect failed: %s" % (e,),
                level="error",
            )

    def worker_deploy_log(self, event):
        """Forward deploy log payload to WebSocket client."""
        try:
            self.send(text_data=json.dumps(event.get("payload", {})))
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_DEPLOY",
                "Error in worker_deploy_log: %s" % (e,),
                level="error",
            )


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
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_REFRESH",
                "Worker refresh WebSocket connect failed: %s" % (e,),
                level="error",
            )
            raise

    def disconnect(self, close_code):
        try:
            if hasattr(self, "room_group_name"):
                async_to_sync(self.channel_layer.group_discard)(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_REFRESH",
                "Worker refresh WebSocket disconnect failed: %s" % (e,),
                level="error",
            )

    def worker_refresh_log(self, event):
        """Forward refresh log payload to WebSocket client."""
        try:
            self.send(text_data=json.dumps(event.get("payload", {})))
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WS_WORKER_REFRESH",
                "Error in worker_refresh_log: %s" % (e,),
                level="error",
            )
