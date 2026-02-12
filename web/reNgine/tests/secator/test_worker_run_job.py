"""
Tests for worker_run_job standalone script (revoke mode).
"""

import unittest
from unittest.mock import patch


class TestWorkerRunJobRevokeMode(unittest.TestCase):
    """Test revoke mode of worker_run_job."""

    @patch("reNgine.secator.worker_run_job.sys.exit")
    @patch("secator.celery.revoke_task")
    def test_run_revoke_mode_calls_revoke_task(self, mock_revoke_task, mock_sys_exit):
        """_run_revoke_mode calls secator.celery.revoke_task with the given celery_id."""
        from reNgine.secator.worker_run_job import _run_revoke_mode

        _run_revoke_mode("task-abc-123")

        mock_revoke_task.assert_called_once_with("task-abc-123")
        mock_sys_exit.assert_called_once_with(0)

    @patch("reNgine.secator.worker_run_job.sys.exit")
    @patch("secator.celery.revoke_task")
    def test_run_revoke_mode_exits_non_zero_on_failure(self, mock_revoke_task, mock_sys_exit):
        """_run_revoke_mode exits with 1 when revoke_task raises."""
        from reNgine.secator.worker_run_job import _run_revoke_mode

        mock_revoke_task.side_effect = RuntimeError("Broker unreachable")

        _run_revoke_mode("task-xyz")

        mock_sys_exit.assert_called_once_with(1)
