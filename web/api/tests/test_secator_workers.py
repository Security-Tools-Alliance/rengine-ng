"""
Test cases for Secator worker API: health, check-in, and ViewSet (list, retrieve, deploy, refresh, disable, delete, check_connection, install_public_key).
"""

from unittest.mock import MagicMock, patch

from django.urls import reverse
from rest_framework import status

from scanEngine.models import SecatorWorker
from utils.test_base import BaseTestCase


class TestSecatorHealth(BaseTestCase):
    """Tests for GET /api/secator/health/."""

    def test_health_returns_ok(self):
        """Health endpoint returns status ok."""
        url = reverse("api:secator_health")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), "ok")


class TestSecatorWorkerCheckIn(BaseTestCase):
    """Tests for POST /api/secator/worker/<id>/check/."""

    def setUp(self):
        super().setUp()
        self.worker = SecatorWorker.objects.create(
            name="checkin-worker",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
        )

    def test_checkin_updates_status(self):
        """Check-in updates api_reachable, last_status_at."""
        url = reverse("api:secator_worker_check", kwargs={"worker_id": self.worker.id})
        data = {"api_reachable": True, "last_error": None}
        response = self.client.post(url, data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.worker.refresh_from_db()
        self.assertTrue(self.worker.api_reachable)
        self.assertIsNotNone(self.worker.last_status_at)

    def test_checkin_404_for_invalid_id(self):
        """Check-in returns 404 for non-existent worker."""
        url = reverse("api:secator_worker_check", kwargs={"worker_id": 99999})
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class TestSecatorWorkerViewSet(BaseTestCase):
    """Tests for Secator worker ViewSet (list, create, retrieve, disable)."""

    def setUp(self):
        super().setUp()
        self.worker = SecatorWorker.objects.create(
            name="api-worker-1",
            ssh_host="192.0.2.2",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
        )

    def test_list_workers_200(self):
        """List workers returns 200 and list of workers."""
        url = reverse("api:secator-workers-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        if isinstance(data, dict) and "results" in data:
            items = data["results"]
        else:
            items = data if isinstance(data, list) else []
        names = [w.get("name") for w in items]
        self.assertIn("api-worker-1", names)

    def test_retrieve_worker_200(self):
        """Retrieve single worker returns 200 and detail."""
        url = reverse("api:secator-workers-detail", kwargs={"pk": self.worker.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("name"), "api-worker-1")
        self.assertIn("runners", response.data)

    def test_create_worker_201(self):
        """Create worker via API returns 201."""
        url = reverse("api:secator-workers-list")
        data = {
            "name": "new-api-worker",
            "ssh_host": "192.0.2.3",
            "ssh_port": 22,
            "ssh_user": "deploy",
            "ssh_auth_type": SecatorWorker.AUTH_KEY,
            "ssh_key_path": "/tmp/k",
            "deploy_path": "/opt/secator-worker",
            "is_active": True,
        }
        response = self.client.post(url, data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(SecatorWorker.objects.filter(name="new-api-worker").exists())

    def test_disable_worker_200(self):
        """Disable action sets is_active=False."""
        self.assertTrue(self.worker.is_active)
        url = reverse(
            "api:secator-workers-disable",
            kwargs={"pk": self.worker.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.worker.refresh_from_db()
        self.assertFalse(self.worker.is_active)

    def test_enable_worker_200(self):
        """Enable action sets is_active=True."""
        self.worker.is_active = False
        self.worker.save(update_fields=["is_active"])
        url = reverse(
            "api:secator-workers-enable",
            kwargs={"pk": self.worker.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), "ok")
        self.worker.refresh_from_db()
        self.assertTrue(self.worker.is_active)

    def test_list_requires_auth(self):
        """List workers requires authentication."""
        from django.test import Client

        unauthenticated_client = Client()
        url = reverse("api:secator-workers-list")
        response = unauthenticated_client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch("api.views.run_remote_command")
    @patch("api.views.get_ssh_client")
    def test_check_connection_success(self, mock_get_ssh, mock_run_remote):
        """Check connection returns ok when SSH and echo succeed."""
        mock_client = MagicMock()
        mock_get_ssh.return_value = mock_client
        mock_run_remote.return_value = (0, "ok", "")
        url = reverse(
            "api:secator-workers-check-connection",
            kwargs={"pk": self.worker.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("ok") is True)
        mock_client.close.assert_called()

    @patch("api.views.get_ssh_client")
    def test_check_connection_failure(self, mock_get_ssh):
        """Check connection returns error when SSH fails."""
        mock_get_ssh.side_effect = Exception("Connection refused")
        url = reverse(
            "api:secator-workers-check-connection",
            kwargs={"pk": self.worker.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("ok"))
        self.assertIn("error", response.data)

    def test_deploy_returns_202_accepted(self):
        """Deploy returns 202 Accepted and status accepted without waiting for thread."""
        url = reverse(
            "api:secator-workers-deploy",
            kwargs={"pk": self.worker.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data.get("status"), "accepted")
        self.assertEqual(response.data.get("worker_id"), self.worker.id)

    def test_deploy_invalid_path_returns_400(self):
        """Deploy returns 400 when deploy_path is invalid."""
        self.worker.deploy_path = ""
        self.worker.save(update_fields=["deploy_path"])
        url = reverse(
            "api:secator-workers-deploy",
            kwargs={"pk": self.worker.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("status"), "error")
        self.assertIn("invalid", response.data.get("message", "").lower())

    def test_refresh_returns_202_accepted(self):
        """Refresh returns 202 Accepted and status accepted without waiting for thread."""
        url = reverse(
            "api:secator-workers-refresh",
            kwargs={"pk": self.worker.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data.get("status"), "accepted")
        self.assertEqual(response.data.get("worker_id"), self.worker.id)


class TestSecatorWorkerInstallPublicKey(BaseTestCase):
    """Tests for install-public-key action."""

    def setUp(self):
        super().setUp()
        self.worker_password = SecatorWorker.objects.create(
            name="worker-password",
            ssh_host="192.0.2.5",
            ssh_port=22,
            ssh_user="deploy",
            ssh_auth_type=SecatorWorker.AUTH_PASSWORD,
            ssh_password_encrypted="secret",
            deploy_path="/opt/w",
        )

    def test_install_public_key_requires_password_auth(self):
        """install-public-key returns 400 when worker uses key auth."""
        worker_key = SecatorWorker.objects.create(
            name="worker-key",
            ssh_host="192.0.2.6",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        url = reverse(
            "api:secator-workers-install-public-key",
            kwargs={"pk": worker_key.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_install_public_key_requires_password_set(self):
        """install-public-key returns 400 when worker has no password."""
        self.worker_password.ssh_password_encrypted = ""
        self.worker_password.save(update_fields=["ssh_password_encrypted"])
        url = reverse(
            "api:secator-workers-install-public-key",
            kwargs={"pk": self.worker_password.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("api.views.run_remote_command")
    @patch("api.views.get_ssh_client")
    @patch("api.views.install_public_key_on_host")
    @patch("api.views.get_public_key_content")
    def test_install_public_key_success(self, mock_get_pubkey, mock_install, mock_get_ssh, mock_run_remote):
        """install-public-key installs key, tests connection, switches worker to key auth."""
        mock_get_pubkey.return_value = "ssh-ed25519 AAAAB3 rengine@host"
        mock_client = MagicMock()
        mock_get_ssh.return_value = mock_client
        mock_run_remote.return_value = (0, "ok", "")
        url = reverse(
            "api:secator-workers-install-public-key",
            kwargs={"pk": self.worker_password.id},
        )
        response = self.client.post(url, {}, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("ok"))
        mock_install.assert_called_once()
        self.worker_password.refresh_from_db()
        self.assertEqual(self.worker_password.ssh_auth_type, SecatorWorker.AUTH_KEY)
        self.assertEqual(self.worker_password.ssh_key_path, "")
        self.assertEqual(self.worker_password.ssh_password_encrypted, "")
