"""
Background sync service for SecatorRunner → ScanHistory.

Public API (use only these entry points):
  - get_executor()   : obtain the sync thread pool (lazy init).
  - submit_sync(id)  : submit a runner sync task (non-blocking).
  - shutdown_pool()  : shut down the pool (call on process/worker shutdown).

Do not use _SecatorSyncPool or _sync_pool directly; the atexit hook and
lifecycle are tied to the module-level shutdown_pool(). Bypassing the public
API can lead to inconsistent state (e.g. pool created but never shut down, or
atexit shutting a different instance).

Centralizes the thread pool and connection lifecycle: uses Django's
close_old_connections and explicit connection.close() to reduce connection leaks
in long-running processes. For graceful shutdown with drain, call
shutdown_pool(wait=True) from a signal or server hook (e.g. gunicorn/uvicorn
worker shutdown); atexit uses wait=False to avoid blocking.

Multi-process: Each worker process has its own pool instance; there is no
cross-process sharing. Tasks submitted via submit_sync() are only visible in
the process that submitted them (no shared queue across workers). Safe for
multi-worker deployments (e.g. uvicorn --workers N).
"""

import atexit
from concurrent.futures import ThreadPoolExecutor
import logging
import threading
from typing import Optional

from django.conf import settings
from django.db import connection


logger = logging.getLogger(__name__)


def _run_sync_worker(secator_runner_id: int) -> None:
    """
    Worker run in pool thread: sync one runner with ScanHistory.

    Uses close_old_connections() at start to avoid reusing a stale connection,
    and connection.close() in finally so the thread does not hold a connection
    after the task (recommended for thread pools in long-running processes).
    """
    from reNgine.utilities.logger import get_secator_api_logger
    from startScan.models import SecatorRunner
    from startScan.secator.runner_sync import sync_runner_with_scan_history

    connection.close_old_connections()
    log = get_secator_api_logger()
    try:
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(id=secator_runner_id)
    except SecatorRunner.DoesNotExist:
        log.log_warning(
            f"Runner {secator_runner_id} not found for background sync",
            {
                "prefix": log.PREFIX_SYNC,
                "action": "BACKGROUND_SYNC",
                "id": str(secator_runner_id),
            },
        )
        return
    runner_data = secator_runner.runner_data or {}
    if not secator_runner.scan_history_id:
        return
    try:
        sync_runner_with_scan_history(secator_runner, runner_data, log)
    except Exception as e:
        log.log_error(
            e,
            {"prefix": log.PREFIX_SYNC, "action": "BACKGROUND_SYNC", "id": str(secator_runner_id)},
            exc_info=True,
        )
    finally:
        connection.close()


class _SecatorSyncPool:
    """
    Internal pool wrapper for Secator runner sync. Do not instantiate or use
    directly; use the module-level get_executor(), submit_sync(), and
    shutdown_pool() so lifecycle and atexit remain consistent.

    One instance per process (module-level _sync_pool). No cross-process
    sharing: each uvicorn/gunicorn worker has its own pool. Uses a lock around
    lazy init to avoid creating multiple executors under concurrent access.
    """

    def __init__(self) -> None:
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.RLock()

    def _get_or_create_executor_unlocked(self) -> ThreadPoolExecutor:
        """Create executor if needed and return it. Caller must hold self._lock."""
        if self._executor is None:
            max_workers = settings.SECATOR_RUNNER_UPDATE_SYNC_MAX_WORKERS
            self._executor = ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="secator_sync",
            )
            logger.debug("Secator sync executor started with max_workers=%s", max_workers)
        return self._executor

    def get_executor(self) -> ThreadPoolExecutor:
        """Return the bounded thread pool for runner sync (lazy init, thread-safe)."""
        with self._lock:
            return self._get_or_create_executor_unlocked()

    def submit_sync(self, secator_runner_id: int) -> None:
        """
        Submit a runner sync to the pool (non-blocking).

        Use when SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND is True so the API can
        respond immediately and avoid Secator hook read timeout.
        Lazily initializes the pool on first submit.
        """
        with self._lock:
            executor = self._get_or_create_executor_unlocked()
        executor.submit(_run_sync_worker, secator_runner_id)

    def shutdown_pool(self, wait: bool = False) -> None:
        """
        Shut down the sync pool. Call on process shutdown for clean teardown.

        For graceful shutdown with drain, call shutdown_pool(wait=True) from a
        signal or server worker shutdown hook; atexit uses wait=False to avoid
        blocking process exit.

        Args:
            wait: If True, block until pending tasks finish (can block indefinitely).
                  If False, return immediately; pending tasks may be lost.
        """
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=wait)
                self._executor = None
                logger.debug("Secator sync executor shut down (wait=%s)", wait)


# Private: single process-wide pool. Use get_executor/submit_sync/shutdown_pool only.
_sync_pool: _SecatorSyncPool = _SecatorSyncPool()


def get_executor() -> ThreadPoolExecutor:
    """Return the bounded thread pool for runner sync (lazy init)."""
    return _sync_pool.get_executor()


def submit_sync(secator_runner_id: int) -> None:
    """
    Submit a runner sync to the pool (non-blocking).

    Use when SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND is True so the API can
    respond immediately and avoid Secator hook read timeout.
    """
    _sync_pool.submit_sync(secator_runner_id)


def shutdown_pool(wait: bool = False) -> None:
    """
    Shut down the sync pool. Call on process shutdown for clean teardown.

    For graceful shutdown with drain, call shutdown_pool(wait=True) from a
    signal or server worker shutdown hook; atexit uses wait=False to avoid
    blocking process exit.

    Args:
        wait: If True, block until pending tasks finish (can block indefinitely).
              If False, return immediately; pending tasks may be lost.
    """
    _sync_pool.shutdown_pool(wait=wait)


atexit.register(lambda: shutdown_pool(wait=False))
