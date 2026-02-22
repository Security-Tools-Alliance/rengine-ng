"""
Unit tests for SecatorWorker model, worker deploy service, and worker views.
"""

from io import BytesIO
from unittest.mock import MagicMock, patch
import zipfile

from django.urls import reverse

from reNgine.utilities.error import UserSafeError
from scanEngine.forms import SecatorWorkerForm
from scanEngine.models import SecatorWorker
from scanEngine.services.worker_config import (
    REMOTE_SCRIPTS_DIR,
    get_container_script_base,
    is_tunnel_api_access,
)
from scanEngine.services.worker_config_sync import sync_configs_for_run
from scanEngine.services.worker_deploy import (
    _build_worker_env_content,
    build_worker_bundle_zip,
    deploy_worker,
    push_env_and_restart_worker,
    refresh_worker_status,
    teardown_worker_remote,
)
from scanEngine.services.worker_ssh import (
    default_ssh_key_path,
    get_public_key_content,
    quote_for_shell,
    validate_deploy_path,
)
from utils.test_base import BaseTestCase


class TestSecatorWorkerModel(BaseTestCase):
    """Tests for SecatorWorker model."""

    def test_create_worker(self):
        """Test creating a Secator worker."""
        worker = SecatorWorker.objects.create(
            name="worker-test-1",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="deploy",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/tmp/key",
            deploy_path="/opt/secator-worker",
        )
        self.assertEqual(worker.name, "worker-test-1")
        self.assertEqual(worker.ssh_host, "192.0.2.1")
        self.assertFalse(worker.api_reachable)
        self.assertTrue(worker.is_active)

    def test_worker_str(self):
        """Test string representation."""
        worker = SecatorWorker.objects.create(
            name="worker-str",
            ssh_host="192.0.2.2",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_PASSWORD,
            ssh_password_encrypted="secret",
            deploy_path="/opt/w",
        )
        self.assertEqual(str(worker), "worker-str")

    @patch("scanEngine.models.settings")
    def test_get_api_base_url_tunnel(self, mock_settings):
        """Tunnel mode derives URL from SECATOR_ADDONS_API_URL, replacing only host and port."""
        mock_settings.SECATOR_ADDONS_API_URL = "https://rengine.example.com/api/secator"
        worker = SecatorWorker.objects.create(
            name="w-tunnel",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_TUNNEL,
            api_tunnel_port=8443,
        )
        self.assertEqual(
            worker.get_api_base_url(),
            "https://host.docker.internal:8443/api/secator",
        )

    def test_get_api_base_url_classic(self):
        """Classic mode returns stripped api_url without trailing slash."""
        worker = SecatorWorker.objects.create(
            name="w-classic",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com/",
        )
        self.assertEqual(worker.get_api_base_url(), "https://rengine.example.com")


class TestWorkerDeployValidation(BaseTestCase):
    """Tests for deploy path validation."""

    def test_validate_deploy_path_ok(self):
        """Valid paths do not raise."""
        validate_deploy_path("/opt/secator-worker")
        validate_deploy_path("/home/user/worker")

    def test_validate_deploy_path_empty_raises(self):
        """Empty path raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            validate_deploy_path("")
        self.assertIn("Invalid", str(ctx.exception))

    def test_validate_deploy_path_null_raises(self):
        """Path with null byte raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            validate_deploy_path("/opt/worker\0evil")
        self.assertIn("Invalid", str(ctx.exception))

    def test_validate_deploy_path_traversal_raises(self):
        """Path with .. raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            validate_deploy_path("/opt/../etc")
        self.assertIn("Invalid", str(ctx.exception))

    def test_validate_deploy_path_root_raises(self):
        """Root path / is rejected."""
        with self.assertRaises(ValueError) as ctx:
            validate_deploy_path("/")
        self.assertIn("Invalid", str(ctx.exception))

    def test_validate_deploy_path_single_segment_allowed(self):
        """Single-segment absolute paths like /opt, /srv, /var are allowed."""
        validate_deploy_path("/opt")
        validate_deploy_path("/srv")
        validate_deploy_path("/var")

    def test_validate_deploy_path_only_slashes_raises(self):
        """Path with only slashes (e.g. ///) is rejected."""
        with self.assertRaises(ValueError) as ctx:
            validate_deploy_path("///")
        self.assertIn("Invalid", str(ctx.exception))

    def test_validate_deploy_path_shell_metacharacters_raise(self):
        """Path containing shell metacharacters is rejected."""
        for path in ["/opt/worker;rm -rf /", "/opt/worker$(id)", "/opt/worker`id`"]:
            with self.subTest(path=path):
                with self.assertRaises(ValueError) as ctx:
                    validate_deploy_path(path)
                self.assertIn("Invalid", str(ctx.exception))


class TestBuildWorkerEnvContent(BaseTestCase):
    """Tests for worker .env content building."""

    def test_build_worker_env_includes_container_name(self):
        """Container name is included when set."""
        worker = SecatorWorker.objects.create(
            name="w1",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
            container_name="my-worker",
        )
        content = _build_worker_env_content(worker)
        self.assertIn("SECATOR_WORKER_CONTAINER_NAME=my-worker", content)

    def test_build_worker_env_no_container_name(self):
        """Container name line omitted when not set."""
        worker = SecatorWorker.objects.create(
            name="w2",
            ssh_host="192.0.2.2",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
            container_name="",
        )
        content = _build_worker_env_content(worker)
        self.assertNotIn("SECATOR_WORKER_CONTAINER_NAME", content)

    @patch("scanEngine.services.worker_deploy.settings")
    @patch("scanEngine.models.settings")
    def test_build_worker_env_tunnel_url(self, mock_models_settings, mock_settings):
        """Tunnel worker gets API URL derived from SECATOR_ADDONS_API_URL (host/port replaced)."""
        mock_models_settings.SECATOR_ADDONS_API_URL = "https://rengine.example.com/api/secator"
        mock_settings.SECATOR_ADDONS_API_KEY = "test-key"
        mock_settings.SECATOR_ADDONS_API_HEADER_NAME = "Api-Key"
        mock_settings.SECATOR_ADDONS_API_FORCE_SSL = False
        mock_settings.DOMAIN_NAME = "rengine.example.com"
        worker = SecatorWorker.objects.create(
            name="w-tunnel-env",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_TUNNEL,
            api_tunnel_port=9000,
        )
        content = _build_worker_env_content(worker)
        self.assertIn(
            "SECATOR_ADDONS_API_URL=https://host.docker.internal:9000/api/secator",
            content,
        )

    @patch("scanEngine.services.worker_deploy.settings")
    def test_build_worker_env_classic_url(self, mock_settings):
        """Classic worker gets api_url as API URL in .env."""
        mock_settings.SECATOR_ADDONS_API_KEY = "key"
        mock_settings.SECATOR_ADDONS_API_HEADER_NAME = "Api-Key"
        mock_settings.SECATOR_ADDONS_API_FORCE_SSL = False
        worker = SecatorWorker.objects.create(
            name="w-classic-env",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://api.example.com",
        )
        content = _build_worker_env_content(worker)
        self.assertIn("SECATOR_ADDONS_API_URL=https://api.example.com", content)

    @patch("scanEngine.services.worker_deploy.settings")
    def test_build_worker_env_includes_api_host_from_domain_name(self, mock_settings):
        """Worker .env includes SECATOR_ADDONS_API_HOST from DOMAIN_NAME for Host header."""
        mock_settings.SECATOR_ADDONS_API_KEY = "key"
        mock_settings.SECATOR_ADDONS_API_HEADER_NAME = "Api-Key"
        mock_settings.SECATOR_ADDONS_API_FORCE_SSL = False
        mock_settings.DOMAIN_NAME = "rengine.example.com"
        worker = SecatorWorker.objects.create(
            name="w-api-host",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://api.example.com",
        )
        content = _build_worker_env_content(worker)
        self.assertIn("SECATOR_ADDONS_API_HOST=rengine.example.com", content)

    @patch("scanEngine.services.worker_deploy.settings")
    def test_build_worker_env_raises_when_api_key_missing(self, mock_settings):
        """_build_worker_env_content raises UserSafeError when API key is missing or placeholder."""
        mock_settings.SECATOR_ADDONS_API_KEY = ""
        mock_settings.SECATOR_ADDONS_API_HEADER_NAME = "Api-Key"
        worker = SecatorWorker.objects.create(
            name="w-no-key",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        with self.assertRaises(UserSafeError) as ctx:
            _build_worker_env_content(worker)
        self.assertIn("SECATOR_ADDONS_API_KEY", str(ctx.exception))

    @patch("scanEngine.services.worker_deploy.settings")
    def test_build_worker_env_raises_when_api_key_placeholder(self, mock_settings):
        """_build_worker_env_content raises UserSafeError when API key is placeholder."""
        mock_settings.SECATOR_ADDONS_API_KEY = "your-generated-api-key-here"
        mock_settings.SECATOR_ADDONS_API_HEADER_NAME = "Api-Key"
        worker = SecatorWorker.objects.create(
            name="w-placeholder",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        with self.assertRaises(UserSafeError) as ctx:
            _build_worker_env_content(worker)
        self.assertIn("SECATOR_ADDONS_API_KEY", str(ctx.exception))


class TestWorkerConfig(BaseTestCase):
    """Tests for worker_config helpers: is_tunnel_api_access, get_container_script_base."""

    def test_is_tunnel_api_access_true(self):
        """is_tunnel_api_access returns True when api_access_type is tunnel."""
        worker = SecatorWorker.objects.create(
            name="w-tunnel",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_TUNNEL,
        )
        self.assertTrue(is_tunnel_api_access(worker))

    def test_is_tunnel_api_access_false(self):
        """is_tunnel_api_access returns False when api_access_type is classic."""
        worker = SecatorWorker.objects.create(
            name="w-classic",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
        )
        self.assertFalse(is_tunnel_api_access(worker))

    def test_get_container_script_base_uses_deploy_path_when_no_setting(self):
        """get_container_script_base returns deploy_path/scripts when no container base setting."""
        with patch("scanEngine.services.worker_config.settings") as mock_settings:
            mock_settings.SECATOR_WORKER_CONTAINER_SCRIPT_BASE = ""
            mock_settings.SECATOR_WORKER_CONTAINER_PYTHON = "python"
            worker = SecatorWorker.objects.create(
                name="w-script",
                ssh_host="192.0.2.1",
                ssh_port=22,
                ssh_user="u",
                ssh_auth_type=SecatorWorker.AUTH_KEY,
                deploy_path="/opt/my-worker",
            )
            python_exe, base_cmd = get_container_script_base(worker)
            self.assertEqual(python_exe, "python")
            self.assertEqual(base_cmd, f"/opt/my-worker/{REMOTE_SCRIPTS_DIR}")

    def test_get_container_script_base_uses_setting_when_set(self):
        """get_container_script_base uses SECATOR_WORKER_CONTAINER_* when set."""
        with patch("scanEngine.services.worker_config.settings") as mock_settings:
            mock_settings.SECATOR_WORKER_CONTAINER_SCRIPT_BASE = "/home/secator"
            mock_settings.SECATOR_WORKER_CONTAINER_PYTHON = "/usr/bin/python3"
            worker = SecatorWorker.objects.create(
                name="w-container",
                ssh_host="192.0.2.1",
                ssh_port=22,
                ssh_user="u",
                ssh_auth_type=SecatorWorker.AUTH_KEY,
                deploy_path="/opt/w",
            )
            python_exe, base_cmd = get_container_script_base(worker)
            self.assertEqual(python_exe, "/usr/bin/python3")
            self.assertEqual(base_cmd, f"/home/secator/{REMOTE_SCRIPTS_DIR}")


class TestQuoteForShell(BaseTestCase):
    """Tests for worker_ssh.quote_for_shell."""

    def test_quote_for_shell_simple(self):
        """Simple path is quoted for safe shell use (delegates to shlex.quote)."""
        import shlex

        path = "/opt/worker"
        self.assertEqual(quote_for_shell(path), shlex.quote(path))

    def test_quote_for_shell_with_spaces(self):
        """Path with spaces is properly quoted."""
        import shlex

        path = "/opt/my worker"
        self.assertEqual(quote_for_shell(path), shlex.quote(path))

    def test_quote_for_shell_empty(self):
        """Empty string is quoted."""
        import shlex

        self.assertEqual(quote_for_shell(""), shlex.quote(""))


class TestDeployWorkerRaisesOnInvalidPath(BaseTestCase):
    """deploy_worker raises when deploy_path is invalid."""

    def test_deploy_worker_invalid_path_raises(self):
        """Invalid deploy path leads to ValueError."""
        worker = SecatorWorker.objects.create(
            name="w-invalid",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="../etc",
        )
        with self.assertRaises(ValueError):
            deploy_worker(worker, progress_callback=lambda s, m: None)


class TestDeployWorkerProgressCallback(BaseTestCase):
    """deploy_worker calls progress_callback at each step; error step on failure."""

    def test_deploy_worker_callback_on_compose_missing(self):
        """When compose file is missing, callback receives validating then error."""
        from pathlib import Path

        worker = SecatorWorker.objects.create(
            name="w-callback-compose",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
        )
        calls = []

        def collect(step: str, message: str) -> None:
            calls.append((step, message))

        with patch("scanEngine.services.worker_deploy._get_compose_path") as mock_path:
            mock_path.return_value = Path("/nonexistent/docker-compose.worker.yml")
            with self.assertRaises(UserSafeError):
                deploy_worker(worker, progress_callback=collect)
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "validating")
        error_calls = [c for c in calls if c[0] == "error"]
        self.assertTrue(error_calls, "callback should receive error step when compose is missing")

    @patch("scanEngine.services.worker_deploy.settings")
    @patch("scanEngine.services.worker_deploy.get_ssh_client")
    @patch("scanEngine.services.worker_deploy.run_remote_command")
    @patch("scanEngine.services.worker_deploy.detect_compose_cmd")
    def test_deploy_worker_raises_when_api_key_missing(self, mock_detect, mock_run, mock_get_ssh, mock_settings):
        """Deploy raises UserSafeError when SECATOR_ADDONS_API_KEY is missing or placeholder."""
        from pathlib import Path
        import tempfile

        mock_settings.SECATOR_ADDONS_API_KEY = ""
        mock_detect.return_value = "docker compose"
        mock_run.return_value = (0, "", "")
        mock_client = MagicMock()
        mock_get_ssh.return_value = mock_client
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp
        mock_sftp.stat.side_effect = FileNotFoundError
        mock_sftp.file.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_sftp.file.return_value.__exit__ = MagicMock(return_value=False)
        worker = SecatorWorker.objects.create(
            name="w-no-key",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
        )
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False) as f:
            f.write(b"version: '3'")
            compose_path = Path(f.name)
        try:
            with patch(
                "scanEngine.services.worker_deploy._get_compose_path",
                return_value=compose_path,
            ):
                with patch("scanEngine.services.worker_deploy._get_entrypoint_path") as mock_ep:
                    mock_ep.return_value = Path("/nonexistent/entrypoint.sh")
                    with self.assertRaises(UserSafeError) as ctx:
                        deploy_worker(worker, progress_callback=lambda s, m: None)
                    self.assertIn("SECATOR_ADDONS_API_KEY", str(ctx.exception))
        finally:
            compose_path.unlink(missing_ok=True)


class TestRefreshWorkerStatus(BaseTestCase):
    """refresh_worker_status returns dict; SSH is mocked."""

    @patch("scanEngine.services.worker_deploy.get_ssh_client")
    def test_refresh_returns_dict(self, mock_get_ssh):
        """Returns dict with ssh_ok, container_running, last_error."""
        mock_client = MagicMock()
        mock_get_ssh.return_value = mock_client
        worker = SecatorWorker.objects.create(
            name="w-refresh",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
        )
        result = refresh_worker_status(worker, progress_callback=lambda s, m: None)
        self.assertIn("ssh_ok", result)
        self.assertIn("container_running", result)
        self.assertIn("api_reachable", result)
        self.assertIn("last_error", result)


class TestTeardownWorkerRemote(BaseTestCase):
    """teardown_worker_remote validates path and returns tuple."""

    def test_teardown_invalid_path_raises(self):
        """Invalid deploy path raises ValueError before SSH."""
        worker = SecatorWorker.objects.create(
            name="w-teardown",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="..",
        )
        with self.assertRaises(ValueError):
            teardown_worker_remote(worker)


class TestSyncConfigsForRun(BaseTestCase):
    """Tests for sync_configs_for_run (worker_config_sync)."""

    @patch("scanEngine.services.worker_config_sync.get_ssh_client")
    def test_sync_configs_for_run_raises_user_safe_error_on_sftp_failure(self, mock_get_ssh):
        """sync_configs_for_run raises UserSafeError when SFTP fails inside the try block."""
        mock_client = MagicMock()
        mock_client.open_sftp.side_effect = OSError("SFTP failed")
        mock_get_ssh.return_value = mock_client
        worker = SecatorWorker.objects.create(
            name="w-sync-fail",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        with self.assertRaises(UserSafeError) as ctx:
            sync_configs_for_run(worker, workflow_name="some-workflow")
        self.assertIn("Config sync failed", str(ctx.exception))

    @patch("scanEngine.services.worker_config_sync.get_ssh_client")
    def test_sync_configs_for_run_ensures_dirs_and_calls_put_string(self, mock_get_ssh):
        """sync_configs_for_run ensures subdirs exist and writes workflow when custom exists."""
        mock_client = MagicMock()
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp
        mock_get_ssh.return_value = mock_client
        from scanEngine.models import SecatorWorkflow

        workflow = SecatorWorkflow.objects.create(
            name="custom-wf",
            workflow_type="custom",
            is_active=True,
            yaml_configuration="name: custom-wf\ntasks: []",
        )
        worker = SecatorWorker.objects.create(
            name="w-sync-ok",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        sync_configs_for_run(worker, workflow_name="custom-wf")
        mock_sftp.close.assert_called_once()
        file_calls = [str(c) for c in mock_sftp.file.call_args_list]
        self.assertTrue(
            any("workflows" in c and "custom-wf" in c for c in file_calls),
            f"sftp.file should be called with workflow path: {file_calls}",
        )
        workflow.delete()


class TestWorkerViews(BaseTestCase):
    """Tests for scanEngine worker list/add/update views."""

    def test_worker_list_requires_login(self):
        """Worker list view requires authentication."""
        from django.test import Client

        unauthenticated_client = Client()
        response = unauthenticated_client.get(reverse("worker_list"))
        self.assertEqual(response.status_code, 302)

    def test_worker_list_200(self):
        """Worker list returns 200 when logged in."""
        response = self.client.get(reverse("worker_list"))
        self.assertEqual(response.status_code, 200)

    def test_worker_add_get_200(self):
        """Worker add form returns 200."""
        response = self.client.get(reverse("worker_add"))
        self.assertEqual(response.status_code, 200)

    def test_worker_add_post_creates_worker(self):
        """POST to worker add creates a worker and redirects (auth=key, classic API with URL)."""
        data = {
            "name": "test-worker-view",
            "ssh_host": "192.0.2.10",
            "ssh_port": "22",
            "ssh_user": "deploy",
            "ssh_auth_type": SecatorWorker.AUTH_KEY,
            "deploy_path": "/opt/secator-worker",
            "api_access_type": SecatorWorker.API_ACCESS_CLASSIC,
            "api_url": "https://rengine.example.com",
            "is_active": "on",
        }
        response = self.client.post(reverse("worker_add"), data)
        self.assertEqual(response.status_code, 302)
        worker = SecatorWorker.objects.get(name="test-worker-view")
        self.assertEqual(worker.ssh_auth_type, SecatorWorker.AUTH_KEY)
        self.assertEqual(worker.ssh_key_path, "")
        self.assertEqual(worker.api_access_type, SecatorWorker.API_ACCESS_CLASSIC)
        self.assertEqual(worker.api_url, "https://rengine.example.com")

    def test_worker_update_get_200(self):
        """Worker update form returns 200."""
        worker = SecatorWorker.objects.create(
            name="w-update",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            ssh_key_path="/k",
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )
        response = self.client.get(reverse("worker_update", kwargs={"worker_id": worker.id}))
        self.assertEqual(response.status_code, 200)


class TestSecatorWorkerFormApiAccess(BaseTestCase):
    """SecatorWorkerForm validation for API access fields."""

    def test_classic_requires_api_url(self):
        """Classic mode requires api_url."""
        form = SecatorWorkerForm(
            data={
                "name": "w1",
                "ssh_host": "192.0.2.1",
                "ssh_port": "22",
                "ssh_user": "u",
                "ssh_auth_type": SecatorWorker.AUTH_KEY,
                "deploy_path": "/opt/w",
                "api_access_type": SecatorWorker.API_ACCESS_CLASSIC,
                "api_url": "",
                "is_active": "on",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("api_url", form.errors)

    def test_classic_with_api_url_valid(self):
        """Classic mode with api_url is valid."""
        form = SecatorWorkerForm(
            data={
                "name": "w2",
                "ssh_host": "192.0.2.1",
                "ssh_port": "22",
                "ssh_user": "u",
                "ssh_auth_type": SecatorWorker.AUTH_KEY,
                "deploy_path": "/opt/w",
                "api_access_type": SecatorWorker.API_ACCESS_CLASSIC,
                "api_url": "https://rengine.example.com",
                "is_active": "on",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)

    def test_tunnel_invalid_port_raises(self):
        """Tunnel mode with port out of range fails validation."""
        form = SecatorWorkerForm(
            data={
                "name": "w3",
                "ssh_host": "192.0.2.1",
                "ssh_port": "22",
                "ssh_user": "u",
                "ssh_auth_type": SecatorWorker.AUTH_KEY,
                "deploy_path": "/opt/w",
                "api_access_type": SecatorWorker.API_ACCESS_TUNNEL,
                "api_tunnel_port": 70000,
                "is_active": "on",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("api_tunnel_port", form.errors)

    def test_tunnel_password_auth_rejected(self):
        """Tunnel mode with password auth fails validation (tunnel requires key-based auth)."""
        form = SecatorWorkerForm(
            data={
                "name": "w-tunnel-pw",
                "ssh_host": "192.0.2.1",
                "ssh_port": "22",
                "ssh_user": "u",
                "ssh_auth_type": SecatorWorker.AUTH_PASSWORD,
                "ssh_password_encrypted": "secret",
                "deploy_path": "/opt/w",
                "api_access_type": SecatorWorker.API_ACCESS_TUNNEL,
                "api_tunnel_port": 8443,
                "is_active": "on",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("ssh_auth_type", form.errors)


class TestPushEnvAndRestartWorker(BaseTestCase):
    """push_env_and_restart_worker returns (bool, optional error)."""

    @patch("scanEngine.services.worker_deploy.run_remote_command")
    @patch("scanEngine.services.worker_deploy.detect_compose_cmd")
    @patch("scanEngine.services.worker_deploy.get_ssh_client")
    def test_push_env_and_restart_success(self, mock_ssh, mock_compose, mock_run):
        """When SSH and compose succeed, returns (True, None)."""
        mock_client = MagicMock()
        mock_ssh.return_value = mock_client
        mock_compose.return_value = "docker compose"
        mock_run.return_value = (0, "", "")
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp
        worker = SecatorWorker.objects.create(
            name="w-push",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )
        ok, err = push_env_and_restart_worker(worker)
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_push_env_invalid_path_raises(self):
        """Invalid deploy path leads to ValueError from validate_deploy_path."""
        worker = SecatorWorker.objects.create(
            name="w-push-bad",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="../etc",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )
        with self.assertRaises(ValueError):
            push_env_and_restart_worker(worker)


class TestWorkerTunnel(BaseTestCase):
    """start_worker_tunnel / stop_worker_tunnel with mocked subprocess."""

    @patch("scanEngine.services.worker_tunnel.subprocess.Popen")
    def test_start_worker_tunnel_classic_returns_none(self, mock_popen):
        """When api_access_type is classic, start_worker_tunnel returns None."""
        from scanEngine.services.worker_tunnel import start_worker_tunnel

        worker = SecatorWorker.objects.create(
            name="w-classic",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )
        result = start_worker_tunnel(worker)
        self.assertIsNone(result)
        mock_popen.assert_not_called()

    @patch("scanEngine.services.worker_tunnel.subprocess.Popen")
    def test_start_worker_tunnel_tunnel_returns_handle(self, mock_popen):
        """When api_access_type is tunnel, start_worker_tunnel returns Popen handle."""
        from scanEngine.services.worker_tunnel import start_worker_tunnel, stop_worker_tunnel

        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        worker = SecatorWorker.objects.create(
            name="w-tunnel",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            api_access_type=SecatorWorker.API_ACCESS_TUNNEL,
            api_tunnel_port=8443,
        )
        result = start_worker_tunnel(worker)
        self.assertIsNotNone(result)
        self.assertEqual(result, mock_proc)
        stop_worker_tunnel(result)
        mock_proc.terminate.assert_called_once()


class TestWorkerSshHelpers(BaseTestCase):
    """Tests for default SSH key path and public key content."""

    def test_default_ssh_key_path_returns_string(self):
        """default_ssh_key_path returns a non-empty string."""
        path = default_ssh_key_path()
        self.assertIsInstance(path, str)
        self.assertIn(".ssh", path)
        self.assertIn("id_ed25519", path)

    def test_get_public_key_content_returns_none_or_string(self):
        """get_public_key_content returns None or a string (no key file in tests)."""
        content = get_public_key_content()
        self.assertTrue(content is None or isinstance(content, str))


class TestRemoteRunnerContainerPython(BaseTestCase):
    """run_scan_on_worker uses SECATOR_WORKER_CONTAINER_PYTHON when building the container command."""

    @patch("reNgine.secator.remote_runner.run_in_container")
    @patch("reNgine.secator.remote_runner.sync_configs_for_run")
    @patch("reNgine.secator.remote_runner.get_ssh_client")
    def test_run_scan_on_worker_uses_default_python(self, mock_get_ssh, mock_sync, mock_run_in_container):
        """Without SECATOR_WORKER_CONTAINER_PYTHON set (or set to 'python'), command starts with 'python '."""
        mock_run_in_container.return_value = (0, "", "")
        mock_client = MagicMock()
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp
        mock_get_ssh.return_value = mock_client

        worker = SecatorWorker.objects.create(
            name="w-runner",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/home/secator",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )

        from django.test import override_settings

        from reNgine.secator.remote_runner import run_scan_on_worker

        with override_settings(SECATOR_WORKER_CONTAINER_PYTHON="python"):
            run_scan_on_worker(
                worker,
                scan_history_id=1,
                target_id=self.data_generator.target.id,
                workspace_name="default",
                execution_mode="workflow",
                targets=["https://example.com"],
                workflow_name="test_workflow",
            )

        mock_run_in_container.assert_called_once()
        call_args = mock_run_in_container.call_args
        cmd = call_args[0][2]
        self.assertTrue(cmd.startswith("python "), f"Expected command to start with 'python ', got: {cmd}")
        self.assertIn("run_secator_job.py", cmd)
        self.assertIn("job_1.json", cmd)

    @patch("reNgine.secator.remote_runner.run_in_container")
    @patch("reNgine.secator.remote_runner.sync_configs_for_run")
    @patch("reNgine.secator.remote_runner.get_ssh_client")
    def test_run_scan_on_worker_uses_custom_python_when_set(self, mock_get_ssh, mock_sync, mock_run_in_container):
        """With SECATOR_WORKER_CONTAINER_PYTHON set, command uses that executable."""
        mock_run_in_container.return_value = (0, "", "")
        mock_client = MagicMock()
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp
        mock_get_ssh.return_value = mock_client

        worker = SecatorWorker.objects.create(
            name="w-runner-pipx",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/home/secator",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )

        from django.test import override_settings

        from reNgine.secator.remote_runner import run_scan_on_worker

        custom_python = "/root/.local/share/pipx/venvs/secator/bin/python"
        with override_settings(SECATOR_WORKER_CONTAINER_PYTHON=custom_python):
            run_scan_on_worker(
                worker,
                scan_history_id=42,
                target_id=self.data_generator.target.id,
                workspace_name="default",
                execution_mode="scan",
                targets=["https://scan.example.com"],
                scan_type="domain",
            )

        mock_run_in_container.assert_called_once()
        cmd = mock_run_in_container.call_args[0][2]
        self.assertTrue(
            cmd.startswith(f"{custom_python} "),
            f"Expected command to start with '{custom_python} ', got: {cmd}",
        )
        self.assertIn("run_secator_job.py", cmd)
        self.assertIn("job_42.json", cmd)

    @patch("reNgine.secator.remote_runner.run_in_container")
    @patch("reNgine.secator.remote_runner.sync_configs_for_run")
    @patch("reNgine.secator.remote_runner.get_ssh_client")
    def test_run_scan_on_worker_uses_container_script_base_when_set(
        self, mock_get_ssh, mock_sync, mock_run_in_container
    ):
        """With SECATOR_WORKER_CONTAINER_SCRIPT_BASE set, command uses that path inside container."""
        mock_run_in_container.return_value = (0, "", "")
        mock_client = MagicMock()
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp
        mock_get_ssh.return_value = mock_client

        worker = SecatorWorker.objects.create(
            name="w-runner-container-path",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/home/rengine/secator-worker",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )

        from django.test import override_settings

        from reNgine.secator.remote_runner import run_scan_on_worker

        container_base = "/home/secator/secator-worker"
        with override_settings(SECATOR_WORKER_CONTAINER_SCRIPT_BASE=container_base):
            run_scan_on_worker(
                worker,
                scan_history_id=99,
                target_id=self.data_generator.target.id,
                workspace_name="default",
                execution_mode="workflow",
                targets=["https://example.com"],
                workflow_name="test_wf",
            )

        mock_run_in_container.assert_called_once()
        cmd = mock_run_in_container.call_args[0][2]
        self.assertIn(
            f"{container_base}/scripts/run_secator_job.py",
            cmd,
            f"Command should use container path, got: {cmd}",
        )
        self.assertIn(f"{container_base}/scripts/job_99.json", cmd)
        self.assertNotIn("/home/rengine/secator-worker", cmd)


class TestBuildWorkerBundleZip(BaseTestCase):
    """Tests for build_worker_bundle_zip (manual deploy ZIP)."""

    @patch("scanEngine.services.worker_deploy._get_entrypoint_path")
    @patch("scanEngine.services.worker_deploy._get_compose_path")
    def test_build_worker_bundle_zip_contains_required_files(self, mock_compose_path, mock_entrypoint_path):
        """ZIP contains docker-compose.worker.yml, .env and README.txt."""
        mock_compose = MagicMock()
        mock_compose.is_file.return_value = True
        mock_compose.read_bytes.return_value = b'version: "3"\nservices:\n  worker:\n    image: secator\n'
        mock_compose_path.return_value = mock_compose
        mock_ep = MagicMock()
        mock_ep.is_file.return_value = False
        mock_entrypoint_path.return_value = mock_ep

        worker = SecatorWorker.objects.create(
            name="bundle-worker",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/bundle",
            api_access_type=SecatorWorker.API_ACCESS_CLASSIC,
            api_url="https://rengine.example.com",
        )
        zip_bytes = build_worker_bundle_zip(worker)
        self.assertIsInstance(zip_bytes, bytes)
        self.assertGreater(len(zip_bytes), 0)

        with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
        self.assertIn("docker-compose.worker.yml", names)
        self.assertIn(".env", names)
        self.assertIn("README.txt", names)
        # templates/ entries are added only when custom configs exist; both cases are valid

    @patch("scanEngine.services.worker_deploy._get_compose_path")
    def test_build_worker_bundle_zip_missing_compose_raises(self, mock_compose_path):
        """When compose file is missing, UserSafeError is raised."""
        mock_compose = MagicMock()
        mock_compose.is_file.return_value = False
        mock_compose_path.return_value = mock_compose

        worker = SecatorWorker.objects.create(
            name="bundle-missing",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        with self.assertRaises(UserSafeError) as ctx:
            build_worker_bundle_zip(worker)
        self.assertIn("compose", str(ctx.exception).lower())


class TestWorkerDownloadBundleView(BaseTestCase):
    """Tests for worker_download_bundle view."""

    @patch("scanEngine.services.worker_deploy._get_entrypoint_path")
    @patch("scanEngine.services.worker_deploy._get_compose_path")
    def test_worker_download_bundle_returns_zip(self, mock_compose_path, mock_entrypoint_path):
        """GET download-bundle returns 200 and application/zip."""
        mock_compose = MagicMock()
        mock_compose.is_file.return_value = True
        mock_compose.read_bytes.return_value = b'version: "3"\n'
        mock_compose_path.return_value = mock_compose
        mock_ep = MagicMock()
        mock_ep.is_file.return_value = False
        mock_entrypoint_path.return_value = mock_ep

        worker = SecatorWorker.objects.create(
            name="download-test",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        url = reverse("worker_download_bundle", kwargs={"worker_id": worker.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/zip")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertIn("worker-", response["Content-Disposition"])
        self.assertIn(".zip", response["Content-Disposition"])

    def test_worker_download_bundle_404_for_invalid_id(self):
        """GET download-bundle with invalid worker_id returns 404."""
        url = reverse("worker_download_bundle", kwargs={"worker_id": 999999})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    @patch("scanEngine.services.worker_deploy.build_worker_bundle_zip")
    def test_worker_download_bundle_redirects_on_user_safe_error(self, mock_build_zip):
        """When build_worker_bundle_zip raises UserSafeError, redirect to worker_list with message."""
        mock_build_zip.side_effect = UserSafeError("Compose file not found.")
        worker = SecatorWorker.objects.create(
            name="error-worker",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )
        url = reverse("worker_download_bundle", kwargs={"worker_id": worker.id})
        response = self.client.get(url)
        self.assertRedirects(response, reverse("worker_list"))
