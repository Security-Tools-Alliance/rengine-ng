"""Tests for ip_discovery_secator (Secator fping wiring)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from reNgine.services.ip_discovery_secator import run_fping_sync
from utils.test_base import BaseTestCase


class RunFpingSyncHooksTestCase(BaseTestCase):
    @patch("reNgine.services.ip_discovery_secator.Task")
    def test_run_fping_sync_enables_secator_hooks(self, mock_task: MagicMock) -> None:
        instance = MagicMock()
        instance.run.return_value = []
        mock_task.return_value = instance
        run_fping_sync(["10.250.0.0/30"])
        mock_task.assert_called_once()
        run_opts = mock_task.call_args.kwargs["run_opts"]
        self.assertTrue(run_opts.get("enable_hooks"))

    @patch("reNgine.services.ip_discovery_secator.Task")
    def test_run_fping_sync_forces_hooks_even_if_caller_disables(self, mock_task: MagicMock) -> None:
        instance = MagicMock()
        instance.run.return_value = []
        mock_task.return_value = instance
        run_fping_sync(["10.250.0.1"], enable_hooks=False)
        run_opts = mock_task.call_args.kwargs["run_opts"]
        self.assertTrue(run_opts.get("enable_hooks"))
