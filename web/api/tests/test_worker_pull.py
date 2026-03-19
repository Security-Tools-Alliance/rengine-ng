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
