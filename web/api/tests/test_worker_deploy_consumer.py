"""
Tests for WorkerDeployConsumer: connect joins worker-deploy-{id} group and forwards worker_deploy_log to client.
"""

from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from django.test import override_settings

from reNgine.asgi import application
from reNgine.utilities.worker_ws_groups import worker_deploy_group
from utils.test_base import BaseTestCase


@override_settings(CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}})
class TestWorkerDeployConsumer(BaseTestCase):
    """WorkerDeployConsumer joins group and sends worker_deploy_log payload to client."""

    async def test_connect_accepts_and_receives_deploy_log(self):
        """Connect to ws/worker-deploy/1/, then group_send worker_deploy_log; client receives payload."""
        communicator = WebsocketCommunicator(
            application,
            "/ws/worker-deploy/1/",
        )
        connected, _ = await communicator.connect()
        self.assertTrue(connected, "WebSocket should be accepted")

        channel_layer = get_channel_layer()
        payload = {
            "worker_id": 1,
            "step": "validating",
            "message": "Deploy path validated.",
            "done": False,
            "error": None,
        }
        await channel_layer.group_send(
            worker_deploy_group(1),
            {"type": "worker_deploy_log", "payload": payload},
        )

        response = await communicator.receive_json_from(timeout=2)
        self.assertEqual(response.get("worker_id"), 1)
        self.assertEqual(response.get("step"), "validating")
        self.assertEqual(response.get("message"), "Deploy path validated.")
        self.assertFalse(response.get("done"))
        self.assertIsNone(response.get("error"))

        await communicator.disconnect()
