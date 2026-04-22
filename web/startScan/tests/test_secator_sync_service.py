"""
Unit tests for startScan.secator.sync_service (pool lifecycle, submit_sync, shutdown_pool).
"""

from concurrent.futures import ThreadPoolExecutor
import time
from unittest.mock import patch

from startScan.secator.sync_service import (
    PREFIX_SYNC,
    get_executor,
    shutdown_pool,
    submit_sync,
)
from utils.test_base import BaseTestCase


class SecatorSyncServiceTestCase(BaseTestCase):
    """Tests for the Secator sync thread pool service."""

    def tearDown(self):
        """Ensure pool is shut down so it does not leak into other tests."""
        shutdown_pool(wait=False)
        super().tearDown()

    def test_get_executor_returns_thread_pool_executor(self):
        """get_executor() returns a ThreadPoolExecutor."""
        executor = get_executor()
        self.assertIsInstance(executor, ThreadPoolExecutor)

    def test_get_executor_same_instance_until_shutdown(self):
        """get_executor() returns the same instance until shutdown_pool is called."""
        e1 = get_executor()
        e2 = get_executor()
        self.assertIs(e1, e2)
        shutdown_pool(wait=False)
        e3 = get_executor()
        self.assertIsNot(e1, e3)

    def test_shutdown_pool_clears_executor(self):
        """After shutdown_pool(wait=False), a new executor is created on next get_executor()."""
        executor_before = get_executor()
        shutdown_pool(wait=False)
        executor_after = get_executor()
        self.assertIsNot(executor_before, executor_after)

    def test_submit_sync_does_not_raise(self):
        """submit_sync(id) does not raise (worker may log and return for non-existent runner)."""
        submit_sync(999999)

    def test_submit_sync_exception_in_worker_is_logged_via_callback(self):
        """When _run_sync_worker raises, the done callback logs via log_line and process does not crash."""
        runner_id = 12345
        with (
            patch(
                "startScan.secator.sync_service._run_sync_worker",
                side_effect=ValueError("expected test error"),
            ),
            patch("startScan.secator.sync_service.logger") as mock_logger,
        ):
            submit_sync(runner_id)
            time.sleep(1.0)
            error_calls = [
                c for c in mock_logger.log_line.call_args_list if len(c[0]) >= 3 and c[1].get("level") == "error"
            ]
            self.assertEqual(len(error_calls), 1)
            call_args = error_calls[0]
            self.assertEqual(call_args[0][0], PREFIX_SYNC)
            self.assertEqual(call_args[0][1], "BACKGROUND_SYNC")
            message = call_args[0][2]
            self.assertIn("worker failed", message)
            self.assertIn(str(runner_id), message)
            self.assertIn("expected test error", message)
            self.assertTrue(call_args[1]["exc_info"])
