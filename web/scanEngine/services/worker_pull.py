"""
Pull-mode worker queue: enqueue commands for HTTPS workers with rengine_pull_agent.

Polling/backoff interplay:
- command polling cadence is read once from pull_agent_config (min/max/jitter)
- wait_for_command uses that cadence to bound DB polling load
- retention cleanup keeps terminal command rows bounded over time
"""

from __future__ import annotations

from datetime import timedelta
import logging
import random
import re
import time
from typing import Any, Optional
import uuid

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from pull_agent_constants import PULL_TOKEN_HEADER

from scanEngine.models import SecatorWorker, SecatorWorkerQueuedCommand
from scanEngine.services.pull_agent_config import (
    get_pull_command_wait_config,
    pull_command_retention_seconds,
    pull_token_max_length,
)


logger = logging.getLogger(__name__)


CLAIM_POLL_INTERVAL = 3
PULL_TOKEN_META_KEY = "HTTP_X_RENGINE_WORKER_PULL_TOKEN"
_PULL_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_PULL_COMMAND_WAIT_CONFIG = get_pull_command_wait_config()
_INVALID_PULL_ATTEMPT_CACHE_TTL_SECONDS = 300
_INVALID_PULL_ATTEMPT_LOG_THRESHOLDS = {1, 5, 10}


def _compute_poll_sleep_seconds(poll_interval: float, remaining: float) -> float:
    """
    Compute a bounded sleep duration to avoid tight polling loops.

    Controlled via env vars (seconds):
    - RENGINE_PULL_COMMAND_POLL_INTERVAL_MIN_SECONDS (default: 0.5)
    - RENGINE_PULL_COMMAND_POLL_INTERVAL_MAX_SECONDS (default: 10)
    - RENGINE_PULL_COMMAND_POLL_JITTER_RATIO (default: 0.2)
    """

    min_seconds = _PULL_COMMAND_WAIT_CONFIG.poll_interval_min_seconds
    max_seconds = _PULL_COMMAND_WAIT_CONFIG.poll_interval_max_seconds
    jitter_ratio = _PULL_COMMAND_WAIT_CONFIG.poll_jitter_ratio

    base = min(poll_interval, max(0.0, remaining))
    base = max(min_seconds, min(base, max_seconds))

    if jitter_ratio > 0 and base > 0:
        # Symmetric jitter in [-jitter_ratio, +jitter_ratio] of base.
        jitter = (random.random() * 2.0 - 1.0) * jitter_ratio * base
        base = base + jitter

    return max(0.0, min(base, remaining))


def _terminal_command_retention_seconds() -> int:
    """
    How long pull-agent terminal commands are kept.

    Use the direct env reader instead of the cached startup config so tests and
    runtime overrides can adjust retention without reloading this module.
    """
    return pull_command_retention_seconds()


def _cleanup_old_terminal_commands(worker: SecatorWorker) -> None:
    cutoff = timezone.now() - timedelta(seconds=_terminal_command_retention_seconds())
    SecatorWorkerQueuedCommand.objects.filter(
        worker=worker,
        status__in=(
            SecatorWorkerQueuedCommand.STATUS_SUCCEEDED,
            SecatorWorkerQueuedCommand.STATUS_FAILED,
            SecatorWorkerQueuedCommand.STATUS_TIMED_OUT,
        ),
        created_at__lt=cutoff,
    ).delete()


def worker_from_pull_request(request: Any, worker_id: int, token: str | None = None) -> Optional[SecatorWorker]:
    """Return worker if pull token matches and pull mode is enabled."""
    token = token or extract_validated_pull_token_from_request(request)
    if not token:
        return None
    try:
        worker = SecatorWorker.objects.only("id", "is_active", "https_pull_agent", "api_access_type", "pull_token").get(
            pk=worker_id
        )
    except SecatorWorker.DoesNotExist:
        return None
    if not worker.is_active or not worker.uses_https_pull_agent():
        return None
    if token != worker.pull_token:
        _log_invalid_pull_attempt(request, worker_id, reason="token_mismatch")
        logger.warning(
            "worker_from_pull_request token mismatch for worker_id=%s (pull_agent_enabled=%s ip=%s)",
            worker_id,
            worker.https_pull_agent,
            _request_client_ip(request),
        )
        return None
    return worker


def extract_validated_pull_token_from_request(request: Any) -> str | None:
    """
    Extract and validate the worker pull token from request headers.

    Validation is strict by default to reduce the impact of token leakage and
    reject pathological header payloads.
    """
    raw_token = request.headers.get(PULL_TOKEN_HEADER)
    if raw_token is None:
        raw_token = request.META.get(PULL_TOKEN_META_KEY)
    if raw_token is None:
        _log_invalid_pull_attempt(request, worker_id=None, reason="missing_header")
        logger.warning("Worker pull request missing token header %s", PULL_TOKEN_HEADER)
        return None

    token = str(raw_token).strip()
    if not token:
        _log_invalid_pull_attempt(request, worker_id=None, reason="empty_header")
        logger.warning("Worker pull request with empty token header %s", PULL_TOKEN_HEADER)
        return None

    max_len = pull_token_max_length()
    if len(token) > max_len:
        _log_invalid_pull_attempt(request, worker_id=None, reason="token_too_long")
        logger.warning(
            "Worker pull token too long (len=%s > %s) for header %s",
            len(token),
            max_len,
            PULL_TOKEN_HEADER,
        )
        return None

    if not _PULL_TOKEN_RE.fullmatch(token):
        _log_invalid_pull_attempt(request, worker_id=None, reason="invalid_token_chars")
        logger.warning("Worker pull token contains invalid characters (header=%s)", PULL_TOKEN_HEADER)
        return None

    return token


def _request_client_ip(request: Any) -> str:
    """Best-effort client IP extraction for pull-agent abuse diagnostics."""
    xff = str(request.META.get("HTTP_X_FORWARDED_FOR", "") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return str(request.META.get("REMOTE_ADDR", "") or "").strip() or "unknown"


def _log_invalid_pull_attempt(request: Any, worker_id: int | None, reason: str) -> None:
    """Count invalid pull-token attempts by client IP and log threshold hits."""
    client_ip = _request_client_ip(request)
    cache_key = f"pull_invalid_token:{client_ip}:{reason}"
    attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, attempts, timeout=_INVALID_PULL_ATTEMPT_CACHE_TTL_SECONDS)
    if attempts in _INVALID_PULL_ATTEMPT_LOG_THRESHOLDS or attempts % 10 == 0:
        logger.warning(
            "Repeated invalid pull token attempts ip=%s worker_id=%s reason=%s attempts=%s ttl=%s",
            client_ip,
            worker_id,
            reason,
            attempts,
            _INVALID_PULL_ATTEMPT_CACHE_TTL_SECONDS,
        )


def enqueue_run_job(worker: SecatorWorker, job: dict, scan_history_id: int) -> uuid.UUID:
    """Create a pending run_job command; returns command id."""
    if not worker.uses_https_pull_agent():
        logger.warning(
            "enqueue_run_job called for non pull-agent worker id=%s (api_access_type=%s https_pull_agent=%s)",
            worker.id,
            worker.api_access_type,
            getattr(worker, "https_pull_agent", None),
        )
        raise ValueError("enqueue_run_job can only be used for pull-agent workers.")
    cmd = SecatorWorkerQueuedCommand.objects.create(
        worker=worker,
        kind=SecatorWorkerQueuedCommand.KIND_RUN_JOB,
        payload={"job": job, "scan_history_id": scan_history_id},
    )
    return cmd.id


def enqueue_revoke(worker: SecatorWorker, celery_id: str) -> uuid.UUID:
    if not worker.uses_https_pull_agent():
        logger.warning(
            "enqueue_revoke called for non pull-agent worker id=%s (api_access_type=%s https_pull_agent=%s)",
            worker.id,
            worker.api_access_type,
            getattr(worker, "https_pull_agent", None),
        )
        raise ValueError("enqueue_revoke can only be used for pull-agent workers.")
    cmd = SecatorWorkerQueuedCommand.objects.create(
        worker=worker,
        kind=SecatorWorkerQueuedCommand.KIND_REVOKE,
        payload={"celery_id": celery_id},
    )
    return cmd.id


def wait_for_command(
    command_id: uuid.UUID,
    timeout_seconds: int,
    poll_interval: float = CLAIM_POLL_INTERVAL,
) -> None:
    """Block until command succeeds or fails; raises RuntimeError on failure or timeout.

    On timeout, transitions a still non-terminal command to TIMED_OUT and logs the event.

    TIMED_OUT is intentionally not a final failed state, because the pull-agent can
    still report a later outcome via the /pull/complete/ endpoint.
    """
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        cmd = SecatorWorkerQueuedCommand.objects.filter(pk=command_id).only("status", "error_message").first()
        if cmd is None:
            raise RuntimeError("Worker command was removed.")
        if cmd.status == SecatorWorkerQueuedCommand.STATUS_SUCCEEDED:
            return
        if cmd.status == SecatorWorkerQueuedCommand.STATUS_FAILED:
            msg = (cmd.error_message or "").strip() or "Remote worker command failed."
            raise RuntimeError(msg)
        if cmd.status == SecatorWorkerQueuedCommand.STATUS_TIMED_OUT:
            msg = (cmd.error_message or "").strip() or "Remote worker command timed out."
            raise RuntimeError(msg)
        time.sleep(_compute_poll_sleep_seconds(poll_interval=poll_interval, remaining=remaining))

    # Timeout: try to mark still-running command as TIMED_OUT and log for operators.
    try:
        with transaction.atomic():
            cmd = (
                SecatorWorkerQueuedCommand.objects.select_for_update()
                .only("status", "error_message")
                .get(pk=command_id)
            )
            if cmd.status not in (
                SecatorWorkerQueuedCommand.STATUS_SUCCEEDED,
                SecatorWorkerQueuedCommand.STATUS_FAILED,
                SecatorWorkerQueuedCommand.STATUS_TIMED_OUT,
            ):
                cmd.status = SecatorWorkerQueuedCommand.STATUS_TIMED_OUT
                if not (cmd.error_message or "").strip():
                    cmd.error_message = "Remote worker command timed out while RUNNING or PENDING."
                cmd.save(update_fields=["status", "error_message"])

            logger.warning(
                "Timeout while waiting for worker command %s (final status=%s)",
                command_id,
                cmd.status,
            )
    except SecatorWorkerQueuedCommand.DoesNotExist:
        logger.warning(
            "Timeout while waiting for worker command %s, but command no longer exists.",
            command_id,
        )

    final_status = "unknown"
    try:
        last = SecatorWorkerQueuedCommand.objects.only("status").get(pk=command_id)
        final_status = last.status
    except SecatorWorkerQueuedCommand.DoesNotExist:
        final_status = "missing"

    raise RuntimeError(f"Remote worker command timed out (command_id={command_id}, status={final_status}).")


def claim_next_command(worker: SecatorWorker) -> Optional[SecatorWorkerQueuedCommand]:
    """Atomically claim the oldest pending command for this worker, or None."""
    with transaction.atomic():
        _cleanup_old_terminal_commands(worker)
        qs = (
            SecatorWorkerQueuedCommand.objects.select_for_update(skip_locked=True)
            .filter(worker=worker, status=SecatorWorkerQueuedCommand.STATUS_PENDING)
            .order_by("created_at")
        )
        cmd = qs.first()
        if cmd is None:
            return None
        cmd.status = SecatorWorkerQueuedCommand.STATUS_RUNNING
        cmd.started_at = timezone.now()
        cmd.save(update_fields=["status", "started_at"])
        return cmd


def complete_command(
    command_id: uuid.UUID,
    worker: SecatorWorker,
    succeeded: bool,
    error_message: str = "",
) -> bool:
    """Mark a command succeeded or failed.

    Returns False if not found or if the command is not in a state that can be finalized.
    """
    with transaction.atomic():
        try:
            cmd = SecatorWorkerQueuedCommand.objects.select_for_update().get(pk=command_id, worker=worker)
        except SecatorWorkerQueuedCommand.DoesNotExist:
            return False
        if cmd.status not in (SecatorWorkerQueuedCommand.STATUS_RUNNING, SecatorWorkerQueuedCommand.STATUS_TIMED_OUT):
            return False
        cmd.status = (
            SecatorWorkerQueuedCommand.STATUS_SUCCEEDED if succeeded else SecatorWorkerQueuedCommand.STATUS_FAILED
        )
        cmd.completed_at = timezone.now()
        if succeeded:
            # Avoid keeping the previous timeout error message when the pull-agent eventually succeeds.
            cmd.error_message = ""
        elif error_message:
            cmd.error_message = error_message[:4000]
        cmd.save(update_fields=["status", "completed_at", "error_message"])
    return True
