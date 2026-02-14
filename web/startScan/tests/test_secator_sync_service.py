"""
Unit tests for startScan.secator.sync_service (pool lifecycle, submit_sync, shutdown_pool).
"""

from concurrent.futures import ThreadPoolExecutor

from startScan.secator.sync_service import get_executor, shutdown_pool, submit_sync
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
