"""
Background sync service for SecatorRunner → ScanHistory.

Centralizes the thread pool and connection lifecycle: uses Django's
close_old_connections and explicit connection.close() to reduce connection leaks
in long-running processes. Call shutdown_pool() on process shutdown (e.g. atexit
or app teardown) for clean teardown.
"""

import atexit
from concurrent.futures import ThreadPoolExecutor
import logging
from typing import Optional

from django.conf import settings
from django.db import connection


logger = logging.getLogger(__name__)

_executor: Optional[ThreadPoolExecutor] = None


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


def get_executor() -> ThreadPoolExecutor:
    """Return the bounded thread pool for runner sync (lazy init)."""
    global _executor
    if _executor is None:
        max_workers = settings.SECATOR_RUNNER_UPDATE_SYNC_MAX_WORKERS
        _executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="secator_sync",
        )
        logger.debug("Secator sync executor started with max_workers=%s", max_workers)
    return _executor


def submit_sync(secator_runner_id: int) -> None:
    """
    Submit a runner sync to the pool (non-blocking).

    Use when SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND is True so the API can
    respond immediately and avoid Secator hook read timeout.
    """
    get_executor().submit(_run_sync_worker, secator_runner_id)


def shutdown_pool(wait: bool = False) -> None:
    """
    Shut down the sync pool. Call on process shutdown for clean teardown.

    Args:
        wait: If True, block until pending tasks finish (can block indefinitely).
              If False, return immediately; pending tasks may be lost. Use False
              in atexit to avoid blocking process exit.
    """
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=wait)
        _executor = None
        logger.debug("Secator sync executor shut down (wait=%s)", wait)


# Register atexit so we don't leave threads hanging on process exit.
# wait=False avoids blocking; for graceful shutdown with drain, call shutdown_pool(wait=True) explicitly.
atexit.register(lambda: shutdown_pool(wait=False))
