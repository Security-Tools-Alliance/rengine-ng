"""Focused unit tests for SecatorWorker pull-token save helpers."""

from unittest.mock import patch

from scanEngine.models import SecatorWorker
from utils.test_base import BaseTestCase


class TestSecatorWorkerPullTokenSaveLogic(BaseTestCase):
    """Unit-level tests for pull-token branching in save helpers."""

    def _create_worker(self) -> SecatorWorker:
        return SecatorWorker.objects.create(
            name="pull-token-unit",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="u",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
        )

    def test_append_pull_token_update_field_returns_tuple_without_mutating_input(self) -> None:
        update_fields = ["name", "updated_at"]
        result = SecatorWorker._append_pull_token_update_field(update_fields)
        self.assertEqual(result, ("name", "updated_at", "pull_token"))
        self.assertEqual(update_fields, ["name", "updated_at"])

    def test_prepare_pull_token_for_save_generates_when_pull_token_is_explicitly_updated(self) -> None:
        worker = self._create_worker()
        worker.pull_token = ""
        kwargs = {"update_fields": ["name", "pull_token"]}

        with patch("scanEngine.models.secrets.token_urlsafe", return_value="generated-token"):
            worker._prepare_pull_token_for_save(kwargs)

        self.assertEqual(worker.pull_token, "generated-token")
        self.assertEqual(kwargs["update_fields"], ["name", "pull_token"])

    def test_prepare_pull_token_for_save_restores_existing_token_when_partial_without_pull_token(self) -> None:
        worker = self._create_worker()
        original = worker.pull_token
        worker.pull_token = ""
        kwargs = {"update_fields": ["container_name"]}

        worker._prepare_pull_token_for_save(kwargs)

        self.assertEqual(worker.pull_token, original)
        self.assertEqual(kwargs["update_fields"], ["container_name"])

    def test_prepare_pull_token_for_save_generates_when_restore_fails(self) -> None:
        worker = self._create_worker()
        worker.pull_token = ""
        kwargs = {"update_fields": ["container_name"]}

        with (
            patch.object(worker, "_restore_pull_token_from_db", return_value=False),
            patch("scanEngine.models.secrets.token_urlsafe", return_value="fallback-token"),
        ):
            worker._prepare_pull_token_for_save(kwargs)

        self.assertEqual(worker.pull_token, "fallback-token")
        self.assertEqual(kwargs["update_fields"], ("container_name", "pull_token"))
