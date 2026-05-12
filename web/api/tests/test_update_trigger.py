"""
Tests for the in-app update trigger and status API endpoints, and the
UpdateProgressConsumer WebSocket consumer.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from django.test import override_settings

from reNgine.asgi import application
from utils.test_base import BaseTestCase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TRIGGER_URL = "/api/rengine/update/trigger/"
STATUS_URL  = "/api/rengine/update/status/"


class _ShareDirMixin:
    """Set up a temporary share directory for trigger/status file tests."""

    def setUp(self) -> None:
        super().setUp()  # type: ignore[misc]
        self._share_tmpdir = tempfile.TemporaryDirectory()
        self._share_dir = self._share_tmpdir.name
        self._env_patch = mock.patch.dict(
            os.environ, {"RENGINE_UPDATE_SHARE_DIR": self._share_dir}
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._share_tmpdir.cleanup()
        super().tearDown()  # type: ignore[misc]

    def _trigger_path(self) -> Path:
        return Path(self._share_dir) / "update_trigger"

    def _status_path(self) -> Path:
        return Path(self._share_dir) / "update_status.json"


# ---------------------------------------------------------------------------
# Trigger endpoint
# ---------------------------------------------------------------------------


class TestRengineUpdateTrigger(_ShareDirMixin, BaseTestCase):
    """POST /api/rengine/update/trigger/ requires admin permission."""

    def _post(self, payload: dict) -> object:
        return self.client.post(
            TRIGGER_URL,
            data=json.dumps(payload),
            content_type="application/json",
        )

    # -- Permission guard --------------------------------------------------

    def test_non_admin_receives_403(self) -> None:
        from rolepermissions.roles import assign_role

        assign_role(self.user, "auditor")
        response = self._post({"install_type": "prebuilt"})
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertFalse(data["status"])

    # -- Successful trigger ------------------------------------------------

    def test_admin_can_trigger_prebuilt(self) -> None:
        response = self._post({"install_type": "prebuilt"})
        self.assertEqual(response.status_code, 202)
        data = json.loads(response.content)
        self.assertTrue(data["status"])
        self.assertTrue(self._trigger_path().exists())
        trigger_data = json.loads(self._trigger_path().read_text())
        self.assertEqual(trigger_data["install_type"], "prebuilt")

    def test_admin_can_trigger_source(self) -> None:
        response = self._post({"install_type": "source"})
        self.assertEqual(response.status_code, 202)
        trigger_data = json.loads(self._trigger_path().read_text())
        self.assertEqual(trigger_data["install_type"], "source")

    # -- Input validation --------------------------------------------------

    def test_invalid_install_type_rejected(self) -> None:
        response = self._post({"install_type": "malicious; rm -rf /"})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertFalse(data["status"])
        self.assertFalse(self._trigger_path().exists())

    def test_defaults_to_prebuilt_when_install_type_missing(self) -> None:
        response = self._post({})
        self.assertEqual(response.status_code, 202)
        trigger_data = json.loads(self._trigger_path().read_text())
        self.assertEqual(trigger_data["install_type"], "prebuilt")

    # -- Duplicate trigger guard -------------------------------------------

    def test_second_trigger_returns_409_while_running(self) -> None:
        self._post({"install_type": "prebuilt"})
        response = self._post({"install_type": "prebuilt"})
        self.assertEqual(response.status_code, 409)
        data = json.loads(response.content)
        self.assertFalse(data["status"])


# ---------------------------------------------------------------------------
# Status endpoint
# ---------------------------------------------------------------------------


class TestRengineUpdateStatus(_ShareDirMixin, BaseTestCase):
    """GET /api/rengine/update/status/ returns current sidecar state."""

    def _get(self) -> object:
        return self.client.get(STATUS_URL)

    def _post(self) -> object:
        return self.client.post(STATUS_URL)

    def test_idle_when_no_files_exist(self) -> None:
        response = self._get()
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["status"])
        self.assertEqual(data.get("update_status"), "idle")

    def test_returns_complete_status_from_file(self) -> None:
        self._status_path().write_text(
            json.dumps({
                "status": "complete",
                "new_version": "3.1.0",
                "freshly_updated": True,
            }),
            encoding="utf-8",
        )
        response = self._get()
        data = json.loads(response.content)
        self.assertEqual(data["status"], "complete")
        self.assertEqual(data["new_version"], "3.1.0")
        self.assertTrue(data["freshly_updated"])

    def test_post_clears_freshly_updated_flag(self) -> None:
        self._status_path().write_text(
            json.dumps({"status": "complete", "freshly_updated": True}),
            encoding="utf-8",
        )
        self._post()
        remaining = json.loads(self._status_path().read_text())
        self.assertNotIn("freshly_updated", remaining)

    def test_running_when_trigger_file_exists(self) -> None:
        # Write a trigger file to simulate a pending update
        self._trigger_path().write_text(
            json.dumps({"install_type": "prebuilt", "requested_at": "2026-01-01T00:00:00+00:00"}),
            encoding="utf-8",
        )
        response = self._get()
        data = json.loads(response.content)
        self.assertEqual(data.get("status"), "running")


# ---------------------------------------------------------------------------
# UpdateProgressConsumer
# ---------------------------------------------------------------------------


@override_settings(
    CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
)
class TestUpdateProgressConsumer(BaseTestCase):
    """UpdateProgressConsumer joins the update-progress group and forwards events."""

    async def test_connect_accepts_and_receives_update_progress(self) -> None:
        communicator = WebsocketCommunicator(application, "/ws/update-progress/")
        connected, _ = await communicator.connect()
        self.assertTrue(connected, "WebSocket should be accepted")

        channel_layer = get_channel_layer()
        payload = {
            "step": "pulling_code",
            "message": "Pulling latest code from repository...",
            "status": "running",
            "step_index": 2,
            "total_steps": 5,
        }
        await channel_layer.group_send(
            "update-progress",
            {"type": "update_progress", "payload": payload},
        )

        response = await communicator.receive_json_from(timeout=2)
        self.assertEqual(response.get("step"), "pulling_code")
        self.assertEqual(response.get("status"), "running")
        self.assertEqual(response.get("step_index"), 2)

        await communicator.disconnect()

    async def test_disconnect_does_not_raise(self) -> None:
        communicator = WebsocketCommunicator(application, "/ws/update-progress/")
        connected, _ = await communicator.connect()
        self.assertTrue(connected)
        await communicator.disconnect()
