"""Tests for Secator worker pull-agent API endpoints."""

import json
import uuid

from django.urls import reverse

from scanEngine.models import SecatorWorker, SecatorWorkerQueuedCommand
from scanEngine.services.worker_pull import enqueue_run_job
from utils.test_base import BaseTestCase


class TestWorkerPullApi(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.worker = SecatorWorker.objects.create(
            name="pull-worker-api",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
            https_pull_agent=True,
            is_active=True,
        )
        self.claim_url = reverse("api:secator_worker_pull_claim", kwargs={"worker_id": self.worker.id})
        self.complete_url = reverse("api:secator_worker_pull_complete", kwargs={"worker_id": self.worker.id})
        self.checkin_url = reverse("api:secator_worker_pull_checkin", kwargs={"worker_id": self.worker.id})

    def test_claim_without_token_returns_403(self) -> None:
        r = self.client.post(self.claim_url, content_type="application/json")
        self.assertEqual(r.status_code, 403)

    def test_claim_with_wrong_token_returns_403(self) -> None:
        r = self.client.post(
            self.claim_url,
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN="wrong-token",
        )
        self.assertEqual(r.status_code, 403)

    def test_claim_with_oversized_token_returns_403(self) -> None:
        r = self.client.post(
            self.claim_url,
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN="a" * 300,
        )
        self.assertEqual(r.status_code, 403)

    def test_claim_with_invalid_token_charset_returns_403(self) -> None:
        r = self.client.post(
            self.claim_url,
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN="bad token with spaces",
        )
        self.assertEqual(r.status_code, 403)

    def test_claim_empty_queue_returns_204(self) -> None:
        r = self.client.post(
            self.claim_url,
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 204)

    def test_claim_complete_cycle(self) -> None:
        job = {"execution_mode": "workflow", "targets": ["https://example.com"]}
        cmd_id = enqueue_run_job(self.worker, job, scan_history_id=42)
        r = self.client.post(
            self.claim_url,
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.content.decode())
        self.assertEqual(data["command_id"], str(cmd_id))
        self.assertEqual(data["kind"], "run_job")
        self.assertEqual(data["payload"]["scan_history_id"], 42)

        r2 = self.client.post(
            self.complete_url,
            data=json.dumps({"command_id": str(cmd_id), "ok": True}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r2.status_code, 200)
        cmd = SecatorWorkerQueuedCommand.objects.get(pk=cmd_id)
        self.assertEqual(cmd.status, SecatorWorkerQueuedCommand.STATUS_SUCCEEDED)

    def test_complete_invalid_command_returns_409(self) -> None:
        r = self.client.post(
            self.complete_url,
            data=json.dumps({"command_id": str(uuid.uuid4()), "ok": True}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 409)

    def test_pull_disabled_worker_returns_403(self) -> None:
        self.worker.https_pull_agent = False
        self.worker.save(update_fields=["https_pull_agent"])
        r = self.client.post(
            self.claim_url,
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 403)

    def test_checkin_updates_worker_status(self) -> None:
        r = self.client.post(
            self.checkin_url,
            data=json.dumps({"api_reachable": True, "last_error": ""}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 200)
        self.worker.refresh_from_db()
        self.assertTrue(self.worker.api_reachable)
        self.assertIsNone(self.worker.last_error)
        self.assertIsNotNone(self.worker.last_status_at)

    def test_checkin_preserves_last_error_when_key_is_absent(self) -> None:
        self.worker.last_error = "previous error"
        self.worker.save_partial(update_fields=["last_error"])

        r = self.client.post(
            self.checkin_url,
            data=json.dumps({"api_reachable": False}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 200)
        self.worker.refresh_from_db()
        self.assertFalse(self.worker.api_reachable)
        self.assertEqual(self.worker.last_error, "previous error")

    def test_checkin_rejects_last_error_when_non_string_value_is_provided(self) -> None:
        self.worker.last_error = "previous error"
        self.worker.save_partial(update_fields=["last_error"])

        r = self.client.post(
            self.checkin_url,
            data=json.dumps({"api_reachable": True, "last_error": False}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 400)
        self.worker.refresh_from_db()
        self.assertEqual(self.worker.last_error, "previous error")

    def test_checkin_clears_last_error_when_null_is_provided(self) -> None:
        self.worker.last_error = "previous error"
        self.worker.save_partial(update_fields=["last_error"])

        r = self.client.post(
            self.checkin_url,
            data=json.dumps({"api_reachable": True, "last_error": None}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 200)
        self.worker.refresh_from_db()
        self.assertTrue(self.worker.api_reachable)
        self.assertIsNone(self.worker.last_error)

    def test_checkin_rejects_last_error_when_too_long(self) -> None:
        too_long_error = "x" * 4001
        r = self.client.post(
            self.checkin_url,
            data=json.dumps({"api_reachable": True, "last_error": too_long_error}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 400)

    def test_checkin_preserves_api_reachable_when_key_is_absent(self) -> None:
        self.worker.api_reachable = False
        self.worker.save_partial(update_fields=["api_reachable"])

        r = self.client.post(
            self.checkin_url,
            data=json.dumps({"last_error": "intermittent network issue"}),
            content_type="application/json",
            HTTP_X_RENGINE_WORKER_PULL_TOKEN=self.worker.pull_token,
        )
        self.assertEqual(r.status_code, 200)
        self.worker.refresh_from_db()
        self.assertFalse(self.worker.api_reachable)
        self.assertEqual(self.worker.last_error, "intermittent network issue")
