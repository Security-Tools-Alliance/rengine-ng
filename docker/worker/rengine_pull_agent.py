#!/usr/bin/env python3
"""
Polls reNgine API for Secator worker commands (run_job / revoke) and executes them locally.
Stdlib only. Configure via environment variables (see README in worker bundle).
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


try:
    from pull_agent_constants import (  # type: ignore[import-not-found]
        DEFAULT_PULL_CHECKIN_INTERVAL_SECONDS,
        DEFAULT_PULL_FAILURE_BACKOFF_MAX_DELAY,
        DEFAULT_PULL_HTTP_TIMEOUT,
        DEFAULT_PULL_JOB_TIMEOUT,
        DEFAULT_PULL_MAX_CONSECUTIVE_FAILURES,
        DEFAULT_PULL_POLL_INTERVAL,
        DEFAULT_PULL_REVOKE_WAIT_SECONDS,
        ENV_PULL_API_BASE_URL,
        ENV_PULL_CHECKIN_INTERVAL_SECONDS,
        ENV_PULL_FAILURE_BACKOFF_MAX_DELAY,
        ENV_PULL_HTTP_TIMEOUT,
        ENV_PULL_JOB_TIMEOUT,
        ENV_PULL_MAX_CONSECUTIVE_FAILURES,
        ENV_PULL_POLL_INTERVAL,
        ENV_PULL_PYTHON,
        ENV_PULL_REVOKE_WAIT_SECONDS,
        ENV_PULL_RUNNER_SCRIPT,
        ENV_PULL_SCRIPTS_DIR,
        ENV_PULL_SSL_VERIFY,
        ENV_PULL_WORKER_ID,
        ENV_PULL_WORKER_TOKEN,
        PULL_TOKEN_HEADER,
    )
except ModuleNotFoundError:
    # Fallback for local execution (bundle should include pull_agent_constants.py).
    PULL_TOKEN_HEADER = "X-Rengine-Worker-Pull-Token"
    ENV_PULL_API_BASE_URL = "RENGINE_PULL_API_BASE_URL"
    ENV_PULL_FAILURE_BACKOFF_MAX_DELAY = "RENGINE_PULL_FAILURE_BACKOFF_MAX_DELAY"
    ENV_PULL_CHECKIN_INTERVAL_SECONDS = "RENGINE_PULL_CHECKIN_INTERVAL_SECONDS"
    ENV_PULL_HTTP_TIMEOUT = "RENGINE_PULL_TIMEOUT"
    ENV_PULL_JOB_TIMEOUT = "RENGINE_PULL_JOB_TIMEOUT"
    ENV_PULL_MAX_CONSECUTIVE_FAILURES = "RENGINE_PULL_MAX_CONSECUTIVE_FAILURES"
    ENV_PULL_POLL_INTERVAL = "RENGINE_PULL_POLL_INTERVAL"
    ENV_PULL_PYTHON = "RENGINE_PULL_PYTHON"
    ENV_PULL_REVOKE_WAIT_SECONDS = "RENGINE_PULL_REVOKE_WAIT_SECONDS"
    ENV_PULL_RUNNER_SCRIPT = "RENGINE_PULL_RUNNER_SCRIPT"
    ENV_PULL_SCRIPTS_DIR = "RENGINE_PULL_SCRIPTS_DIR"
    ENV_PULL_SSL_VERIFY = "RENGINE_PULL_SSL_VERIFY"
    ENV_PULL_WORKER_ID = "RENGINE_WORKER_ID"
    ENV_PULL_WORKER_TOKEN = "RENGINE_WORKER_PULL_TOKEN"
    DEFAULT_PULL_FAILURE_BACKOFF_MAX_DELAY = 300.0
    DEFAULT_PULL_CHECKIN_INTERVAL_SECONDS = 60.0
    DEFAULT_PULL_HTTP_TIMEOUT = 120.0
    DEFAULT_PULL_JOB_TIMEOUT = 86400
    DEFAULT_PULL_MAX_CONSECUTIVE_FAILURES = 12
    DEFAULT_PULL_POLL_INTERVAL = 5.0
    DEFAULT_PULL_REVOKE_WAIT_SECONDS = 90

_SSL_CONTEXT_CACHE: ssl.SSLContext | None = None
_SSL_DISABLE_WARNING_EMITTED = False
TIMEOUT_EXIT_CODE = -1
_CHECKIN_WARNING_THRESHOLD = 3
_CHECKIN_LAST_ERROR_MAX_LEN = 2000
_CHECKIN_LAST_ERROR_LOG_PREVIEW_LEN = 200
_SUBPROCESS_HEARTBEAT_SECONDS = 30.0
_SUBPROCESS_TERMINATE_GRACE_SECONDS = 10.0
ENV_PULL_AGENT_LOG_FILE = "RENGINE_PULL_AGENT_LOG_FILE"
ENV_PULL_AGENT_LOG_LEVEL = "RENGINE_PULL_AGENT_LOG_LEVEL"
ENV_PULL_DEBUG_PAYLOADS_DIR = "RENGINE_PULL_DEBUG_PAYLOADS_DIR"
DEFAULT_PULL_AGENT_LOG_FILE = "/home/secator/scripts/rengine_pull_agent.log"
DEFAULT_PULL_DEBUG_PAYLOADS_DIR = "/home/secator/scripts/pull_payloads"
logger = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _configure_logging() -> None:
    """
    Configure pull-agent logging for both container logs and optional file logging.

    Env vars:
    - RENGINE_PULL_AGENT_LOG_LEVEL (default: INFO)
    - RENGINE_PULL_AGENT_LOG_FILE (default: /home/secator/scripts/rengine_pull_agent.log)
    """
    level_name = _env(ENV_PULL_AGENT_LOG_LEVEL, "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s | %(message)s")

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    if not root_logger.handlers:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        root_logger.addHandler(stream_handler)
    else:
        for handler in root_logger.handlers:
            handler.setLevel(level)

    log_file = _env(ENV_PULL_AGENT_LOG_FILE, DEFAULT_PULL_AGENT_LOG_FILE)
    if not log_file:
        return

    log_path = Path(log_file)
    with suppress(OSError):
        log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
    except OSError as exc:
        logger.warning("cannot enable file logging at %s: %s", log_path, exc)
        return
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)


def _dump_payload_snapshot(command_id: str, kind: str, payload: dict) -> None:
    """
    Persist incoming command payload to a text file for offline debugging.
    """
    base_dir = _env(ENV_PULL_DEBUG_PAYLOADS_DIR, DEFAULT_PULL_DEBUG_PAYLOADS_DIR)
    if not base_dir:
        return

    safe_kind = kind or "unknown"
    dump_dir = Path(base_dir)
    ts = int(time.time())
    file_path = dump_dir / f"{ts}_{safe_kind}_{command_id}.txt"
    with suppress(OSError):
        dump_dir.mkdir(parents=True, exist_ok=True)
    try:
        payload_dump = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
        file_path.write_text(
            "\n".join(
                [
                    f"timestamp_unix={ts}",
                    f"command_id={command_id}",
                    f"kind={safe_kind}",
                    "",
                    "payload_json:",
                    payload_dump,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        logger.info("payload snapshot written command_id=%s path=%s", command_id, file_path)
    except OSError as exc:
        logger.warning("failed to write payload snapshot command_id=%s error=%s", command_id, exc)


def _max_consecutive_claim_failures() -> int:
    raw = _env(ENV_PULL_MAX_CONSECUTIVE_FAILURES, str(DEFAULT_PULL_MAX_CONSECUTIVE_FAILURES))
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_PULL_MAX_CONSECUTIVE_FAILURES


def _failure_backoff_max_delay() -> float:
    raw = _env(ENV_PULL_FAILURE_BACKOFF_MAX_DELAY, str(DEFAULT_PULL_FAILURE_BACKOFF_MAX_DELAY))
    try:
        return max(2.0, float(raw))
    except ValueError:
        return DEFAULT_PULL_FAILURE_BACKOFF_MAX_DELAY


def _compute_backoff_delay(consecutive_failures: int, base_delay: float, max_delay: float) -> float:
    """
    Exponential backoff with a cap.

    For consecutive_failures=1 => base_delay
    For consecutive_failures=2 => base_delay*2
    etc.
    """
    if consecutive_failures <= 1:
        return base_delay
    delay = base_delay * (2 ** (consecutive_failures - 1))
    return min(max_delay, delay)


def _is_non_retriable_http_code(code: int) -> bool:
    # Persistent auth/config issues: retrying forever only creates load and noise.
    return code in {401, 403}


def _api_base() -> str:
    base = _env(ENV_PULL_API_BASE_URL)
    if not base:
        logger.error("%s is required", ENV_PULL_API_BASE_URL)
        sys.exit(1)
    return base.rstrip("/")


def _worker_id() -> int:
    raw = _env(ENV_PULL_WORKER_ID)
    if not raw:
        logger.error("%s is required", ENV_PULL_WORKER_ID)
        sys.exit(1)
    try:
        return int(raw)
    except ValueError:
        logger.error("%s must be an integer", ENV_PULL_WORKER_ID)
        sys.exit(1)


def _token() -> str:
    t = _env(ENV_PULL_WORKER_TOKEN)
    if not t:
        logger.error("%s is required", ENV_PULL_WORKER_TOKEN)
        sys.exit(1)
    return t


def _poll_interval() -> float:
    try:
        return max(2.0, float(_env(ENV_PULL_POLL_INTERVAL, str(DEFAULT_PULL_POLL_INTERVAL))))
    except ValueError:
        return DEFAULT_PULL_POLL_INTERVAL


def _revoke_timeout() -> int:
    """Timeout in seconds for the revoke subprocess; aligned with server-side wait."""
    try:
        return max(10, int(_env(ENV_PULL_REVOKE_WAIT_SECONDS, str(DEFAULT_PULL_REVOKE_WAIT_SECONDS))))
    except ValueError:
        return DEFAULT_PULL_REVOKE_WAIT_SECONDS


def _load_job_timeout() -> int:
    """Job execution timeout (seconds) for run_job subprocess."""
    job_timeout = 86400
    with suppress(ValueError):
        job_timeout = int(_env(ENV_PULL_JOB_TIMEOUT, str(DEFAULT_PULL_JOB_TIMEOUT)))
    return job_timeout


def _load_pull_agent_tuning() -> tuple[int, float]:
    """
    Pull-agent tuning for claim retry loop.

    Env vars:
    - RENGINE_PULL_MAX_CONSECUTIVE_FAILURES (default: 12)
    - RENGINE_PULL_FAILURE_BACKOFF_MAX_DELAY (default: 300)
    """
    max_failures = _max_consecutive_claim_failures()
    backoff_max_delay = _failure_backoff_max_delay()
    return max_failures, backoff_max_delay


@dataclass(frozen=True)
class PullAgentRuntimeConfig:
    poll_interval: float
    max_consecutive_failures: int
    failure_backoff_max_delay: float
    revoke_timeout: int
    job_timeout: int
    checkin_interval_seconds: float


@dataclass(frozen=True)
class CheckinScheduleState:
    consecutive_failures: int
    next_checkin_at: float


def _load_runtime_config() -> PullAgentRuntimeConfig:
    """Load, validate and return pull-agent runtime config from environment."""
    max_failures, backoff_max_delay = _load_pull_agent_tuning()
    return PullAgentRuntimeConfig(
        poll_interval=_poll_interval(),
        max_consecutive_failures=max_failures,
        failure_backoff_max_delay=backoff_max_delay,
        revoke_timeout=_revoke_timeout(),
        job_timeout=_load_job_timeout(),
        checkin_interval_seconds=_load_checkin_interval_seconds(),
    )


def _log_runtime_config(config: PullAgentRuntimeConfig) -> None:
    """Log effective runtime tuning once at startup."""
    checkin_mode = "disabled" if config.checkin_interval_seconds <= 0 else "enabled"
    logger.info(
        "pull-agent config: poll_interval=%.1fs max_consecutive_failures=%s backoff_max_delay=%.1fs revoke_timeout=%ss job_timeout=%ss checkin_interval=%.1fs checkin_mode=%s",
        config.poll_interval,
        config.max_consecutive_failures,
        config.failure_backoff_max_delay,
        config.revoke_timeout,
        config.job_timeout,
        config.checkin_interval_seconds,
        checkin_mode,
    )


def _load_checkin_interval_seconds() -> float:
    """
    Interval between pull-agent status check-ins.

    <= 0 disables periodic check-ins.
    """
    raw = os.environ.get(ENV_PULL_CHECKIN_INTERVAL_SECONDS)
    if raw is None:
        return DEFAULT_PULL_CHECKIN_INTERVAL_SECONDS

    normalized = raw.strip().lower()
    if normalized in {"", "0", "false", "none", "off"}:
        logger.info(
            "%s=%r interpreted as disabled; periodic check-ins are disabled.",
            ENV_PULL_CHECKIN_INTERVAL_SECONDS,
            raw,
        )
        return 0.0

    try:
        parsed = float(raw)
    except ValueError:
        logger.warning(
            "Invalid %s value; using default %.1fs",
            ENV_PULL_CHECKIN_INTERVAL_SECONDS,
            DEFAULT_PULL_CHECKIN_INTERVAL_SECONDS,
        )
        return DEFAULT_PULL_CHECKIN_INTERVAL_SECONDS

    if parsed <= 0:
        logger.info(
            "%s=%r parsed as non-positive; periodic check-ins are disabled.",
            ENV_PULL_CHECKIN_INTERVAL_SECONDS,
            raw,
        )
        return 0.0
    return parsed


def _ssl_context() -> ssl.SSLContext | None:
    global _SSL_CONTEXT_CACHE
    global _SSL_DISABLE_WARNING_EMITTED

    if _env(ENV_PULL_SSL_VERIFY, "true").lower() in ("0", "false", "no"):
        if not _SSL_DISABLE_WARNING_EMITTED:
            logger.warning(
                "TLS verification is disabled (RENGINE_PULL_SSL_VERIFY). Connections to the reNgine API are not verified."
            )
            _SSL_DISABLE_WARNING_EMITTED = True
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if _SSL_CONTEXT_CACHE is None:
        _SSL_CONTEXT_CACHE = ssl.create_default_context()
    return _SSL_CONTEXT_CACHE


def _request_timeout() -> float:
    """Return per-request HTTP timeout in seconds."""
    try:
        return max(1.0, float(_env(ENV_PULL_HTTP_TIMEOUT, str(DEFAULT_PULL_HTTP_TIMEOUT))))
    except ValueError:
        return DEFAULT_PULL_HTTP_TIMEOUT


def _request(method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header(PULL_TOKEN_HEADER, _token())
    if body is not None:
        req.add_header("Content-Type", "application/json")
    parsed_url = urllib.parse.urlparse(url)
    use_ssl_context = parsed_url.scheme.lower() == "https"
    ctx = _ssl_context() if use_ssl_context else None
    timeout = _request_timeout()
    try:
        if use_ssl_context and ctx is not None:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""


def _complete(command_id: str, ok: bool, error: str = "") -> None:
    wid = _worker_id()
    url = f"{_api_base()}/secator/workers/{wid}/pull/complete/"
    payload = json.dumps({"command_id": command_id, "ok": ok, "error": error[:2000]}).encode("utf-8")
    code, data = _request("POST", url, payload)
    if code == 200:
        logger.info("complete ok command_id=%s ok=%s", command_id, ok)
        return
    logger.warning("complete failed %s: %s", code, data.decode("utf-8", errors="replace")[:500])


def _checkin(
    wid: int,
    *,
    api_reachable: bool = True,
    last_error: str = "",
    consecutive_failures: int,
) -> bool:
    """
    Push worker API status for UI label updates.

    This check-in is best-effort: failures are logged but do not affect
    claim/backoff/liveness exit decisions for the pull-agent process.
    """
    url = f"{_api_base()}/secator/workers/{wid}/pull/checkin/"
    last_error_for_checkin = (last_error or "")[:_CHECKIN_LAST_ERROR_MAX_LEN]
    last_error_preview = last_error_for_checkin[:_CHECKIN_LAST_ERROR_LOG_PREVIEW_LEN]
    payload = json.dumps(
        {
            "api_reachable": api_reachable,
            "last_error": last_error_for_checkin,
        }
    ).encode("utf-8")
    try:
        code, data = _request("POST", url, payload)
    except urllib.error.URLError as exc:
        if consecutive_failures + 1 >= _CHECKIN_WARNING_THRESHOLD:
            logger.warning(
                "checkin request error consecutive_failures=%s api_reachable=%s last_error=%r error=%s",
                consecutive_failures + 1,
                api_reachable,
                last_error_preview,
                exc,
            )
        else:
            logger.debug(
                "checkin request error consecutive_failures=%s api_reachable=%s last_error=%r error=%s",
                consecutive_failures + 1,
                api_reachable,
                last_error_preview,
                exc,
            )
        return False
    except Exception as exc:  # pragma: no cover - defensive guardrail
        logger.warning(
            "checkin unexpected error consecutive_failures=%s api_reachable=%s last_error=%r error=%s",
            consecutive_failures + 1,
            api_reachable,
            last_error_preview,
            exc,
        )
        return False

    if code == 200:
        return True

    body_preview = data.decode("utf-8", errors="replace")[:500]
    if consecutive_failures + 1 >= _CHECKIN_WARNING_THRESHOLD:
        logger.warning(
            "checkin failed http_code=%s consecutive_failures=%s api_reachable=%s last_error=%r body=%s",
            code,
            consecutive_failures + 1,
            api_reachable,
            last_error_preview,
            body_preview,
        )
        return False

    logger.debug(
        "checkin failed http_code=%s consecutive_failures=%s api_reachable=%s last_error=%r body=%s",
        code,
        consecutive_failures + 1,
        api_reachable,
        last_error_preview,
        body_preview,
    )
    return False


def _maybe_run_periodic_checkin(
    *,
    should_checkin: bool,
    worker_id: int,
    current_next_checkin_at: float,
    checkin_interval_seconds: float,
    consecutive_checkin_failures: int,
    api_reachable: bool,
    last_error: str,
) -> CheckinScheduleState:
    """
    Execute one periodic check-in attempt if due.

    Returns the updated check-in schedule state.
    """
    if not should_checkin:
        return CheckinScheduleState(
            consecutive_failures=consecutive_checkin_failures,
            next_checkin_at=current_next_checkin_at,
        )

    try:
        checkin_ok = _checkin(
            worker_id,
            api_reachable=api_reachable,
            last_error=last_error,
            consecutive_failures=consecutive_checkin_failures,
        )
    except Exception as exc:  # pragma: no cover - defensive guardrail
        logger.warning("checkin failed with unexpected exception: %s", exc)
        checkin_ok = False
    if checkin_ok:
        logger.info("periodic checkin ok worker_id=%s api_reachable=%s", worker_id, api_reachable)
    updated_failures = 0 if checkin_ok else consecutive_checkin_failures + 1
    next_checkin_at = time.monotonic() + checkin_interval_seconds if checkin_interval_seconds > 0 else 0.0
    return CheckinScheduleState(
        consecutive_failures=updated_failures,
        next_checkin_at=next_checkin_at,
    )


def _run_subprocess(argv: list[str], timeout: int | None) -> tuple[int, str, str]:
    cmd_repr = " ".join(argv)
    start = time.monotonic()
    logger.info("subprocess starting timeout=%s cmd=%s", timeout, cmd_repr)
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        last_heartbeat_at = start

        while True:
            now = time.monotonic()
            if proc.poll() is not None:
                break

            if now - last_heartbeat_at >= _SUBPROCESS_HEARTBEAT_SECONDS:
                elapsed = now - start
                logger.info(
                    "subprocess still running elapsed=%.2fs timeout=%s cmd=%s",
                    elapsed,
                    timeout,
                    cmd_repr,
                )
                last_heartbeat_at = now

            if timeout is not None and now - start >= timeout:
                effective_timeout = f"{timeout}s"
                elapsed = now - start
                logger.warning(
                    "subprocess timed out elapsed=%.2fs timeout=%s cmd=%s; sending terminate",
                    elapsed,
                    effective_timeout,
                    cmd_repr,
                )
                proc.terminate()
                try:
                    out, err = proc.communicate(timeout=_SUBPROCESS_TERMINATE_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    logger.warning(
                        "subprocess did not terminate after %.1fs; sending kill cmd=%s",
                        _SUBPROCESS_TERMINATE_GRACE_SECONDS,
                        cmd_repr,
                    )
                    proc.kill()
                    out, err = proc.communicate()
                stderr_msg = f"Command timed out after {effective_timeout}: {cmd_repr}"
                merged_err = (err or "")[:1800]
                return TIMEOUT_EXIT_CODE, out or "", f"{stderr_msg}. tail={merged_err}"

            time.sleep(1.0)

        out, err = proc.communicate()
        elapsed = time.monotonic() - start
        logger.info("subprocess finished rc=%s elapsed=%.2fs cmd=%s", proc.returncode, elapsed, cmd_repr)
        return proc.returncode, out or "", err or ""
    except Exception as exc:  # pragma: no cover - defensive guardrail
        elapsed = time.monotonic() - start
        logger.exception("subprocess failed elapsed=%.2fs cmd=%s error=%s", elapsed, cmd_repr, exc)
        return TIMEOUT_EXIT_CODE, "", f"subprocess failed: {exc}"


def _log_final_exit_summary(
    *,
    worker_id: int,
    reason: str,
    consecutive_claim_failures: int,
    max_failures: int,
    last_http_code: int | None,
    last_body_preview: str,
    last_error: str,
) -> None:
    """
    Print a last summary to stderr before exiting.

    This helps operators correlate why the pull agent stopped polling.
    """
    tail = (last_body_preview or "")[:1000]
    err = (last_error or "")[:500]
    code_part = "None" if last_http_code is None else str(last_http_code)
    logger.error(
        "FINAL pull-agent exit: worker_id=%s reason=%s consecutive_failures=%s/%s last_http=%s last_error=%s last_body_preview=%s",
        worker_id,
        reason,
        consecutive_claim_failures,
        max_failures,
        code_part,
        err,
        repr(tail),
    )


def _handle_revoke(
    command_id: str,
    payload: dict,
    *,
    python_exe: str,
    runner_script: Path,
    config: PullAgentRuntimeConfig,
) -> None:
    celery_id = str(payload.get("celery_id") or "")
    if not celery_id:
        _complete(command_id, False, "missing celery_id")
        return

    logger.info("revoke started command_id=%s celery_id=%s", command_id, celery_id)
    rc, out, err = _run_subprocess(
        [python_exe, str(runner_script), "revoke", celery_id],
        timeout=config.revoke_timeout,
    )
    if out:
        logger.info("revoke stdout command_id=%s output=%s", command_id, out[-2000:])
    if err:
        logger.warning("revoke stderr command_id=%s output=%s", command_id, err[-2000:])
    logger.info("revoke finished command_id=%s rc=%s", command_id, rc)
    if rc == TIMEOUT_EXIT_CODE:
        _complete(command_id, False, f"revoke command timed out: {(err or out or '')[:1900]}")
        return
    _complete(command_id, rc == 0, (err or out or "")[:2000])


def _handle_run_job(
    command_id: str,
    payload: dict,
    *,
    scripts_dir: Path,
    python_exe: str,
    runner_script: Path,
    config: PullAgentRuntimeConfig,
) -> None:
    job = payload.get("job")
    scan_history_id = payload.get("scan_history_id")
    if not isinstance(job, dict) or scan_history_id is None:
        _complete(command_id, False, "invalid run_job payload")
        return

    try:
        safe_command_id = uuid.UUID(command_id)
    except (ValueError, TypeError):
        _complete(command_id, False, "invalid command_id")
        return

    # Use a per-command filename to avoid collisions between concurrent jobs.
    job_path = scripts_dir / f"job_{safe_command_id}.json"
    with suppress(OSError):
        job_path.unlink()

    execution_mode = job.get("execution_mode")
    raw_targets = job.get("targets") or []
    targets_count = len(raw_targets) if isinstance(raw_targets, list) else 0
    task_names = job.get("task_names") or []
    task_count = len(task_names) if isinstance(task_names, list) else 0
    logger.info(
        "run_job started command_id=%s execution_mode=%s targets=%s tasks=%s scan_history_id=%s",
        command_id,
        execution_mode,
        targets_count,
        task_count,
        scan_history_id,
    )
    job_path.write_text(json.dumps(job, indent=2), encoding="utf-8")
    logger.info(
        "run_job invoke command_id=%s cmd=%s %s %s",
        command_id,
        python_exe,
        runner_script,
        job_path,
    )
    rc, out, err = _run_subprocess(
        [python_exe, str(runner_script), str(job_path)],
        timeout=config.job_timeout,
    )
    if out:
        logger.info("run_job stdout command_id=%s output=%s", command_id, out[-3000:])
    if err:
        logger.warning("run_job stderr command_id=%s output=%s", command_id, err[-3000:])
    logger.info(
        "run_job finished command_id=%s rc=%s stdout_len=%s stderr_len=%s",
        command_id,
        rc,
        len(out or ""),
        len(err or ""),
    )
    if rc == TIMEOUT_EXIT_CODE:
        _complete(command_id, False, f"run_job timed out: {(err or out or '')[:1900]}")
        with suppress(OSError):
            job_path.unlink()
        return
    tail = (err or out or "")[-4000:]
    _complete(command_id, rc == 0, tail if rc != 0 else "")

    with suppress(OSError):
        job_path.unlink()


def _handle_command(
    command_id: str,
    kind: str,
    payload: dict,
    *,
    scripts_dir: Path,
    python_exe: str,
    runner_script: Path,
    config: PullAgentRuntimeConfig,
) -> None:
    _dump_payload_snapshot(command_id, kind, payload)
    if kind == "revoke":
        _handle_revoke(
            command_id,
            payload,
            python_exe=python_exe,
            runner_script=runner_script,
            config=config,
        )
        return
    if kind == "run_job":
        _handle_run_job(
            command_id,
            payload,
            scripts_dir=scripts_dir,
            python_exe=python_exe,
            runner_script=runner_script,
            config=config,
        )
        return
    logger.warning("unknown command kind=%s command_id=%s", kind, command_id)
    _complete(command_id, False, f"unknown kind: {kind}")


def main() -> None:
    _configure_logging()

    scripts_dir = Path(_env(ENV_PULL_SCRIPTS_DIR, "/home/secator/scripts"))
    python_exe = _env(
        ENV_PULL_PYTHON,
        "/home/secator/.local/share/pipx/venvs/secator/bin/python",
    )
    runner_script = Path(_env(ENV_PULL_RUNNER_SCRIPT, str(scripts_dir / "run_secator_job.py")))
    if not runner_script.is_file():
        logger.error("RENGINE_PULL_RUNNER_SCRIPT is misconfigured or missing: %s", runner_script)
        sys.exit(2)

    runtime_config = _load_runtime_config()
    _log_runtime_config(runtime_config)

    wid = _worker_id()
    claim_url = f"{_api_base()}/secator/workers/{wid}/pull/claim/"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    consecutive_claim_failures = 0
    max_failures = runtime_config.max_consecutive_failures
    backoff_max_delay = runtime_config.failure_backoff_max_delay
    last_claim_http_code: int | None = None
    last_claim_body_preview: str = ""
    last_claim_error: str = ""
    checkin_last_error: str = ""
    checkin_api_reachable = True
    consecutive_checkin_failures = 0
    # Uses monotonic time only for local scheduling; API persists wall-clock
    # timestamps independently (`last_status_at`), so these clocks are not compared.
    next_checkin_at = (
        time.monotonic() + runtime_config.checkin_interval_seconds
        if runtime_config.checkin_interval_seconds > 0
        else 0.0
    )
    consecutive_empty_claims = 0

    while True:
        now = time.monotonic()
        should_checkin = runtime_config.checkin_interval_seconds > 0 and now >= next_checkin_at
        poll_interval = runtime_config.poll_interval
        try:
            code, data = _request("POST", claim_url, b"{}")
        except urllib.error.URLError as e:
            consecutive_claim_failures += 1
            last_claim_http_code = getattr(e, "code", None)
            last_claim_error = str(e)
            last_claim_body_preview = ""
            checkin_api_reachable = False
            checkin_last_error = last_claim_error
            consecutive_empty_claims = 0
            delay = _compute_backoff_delay(consecutive_claim_failures, poll_interval, backoff_max_delay)
            logger.warning(
                "claim request error (%s/%s); retrying in %.1fs: %s",
                consecutive_claim_failures,
                max_failures,
                delay,
                e,
            )
            if _is_non_retriable_http_code(getattr(e, "code", 0) or 0):
                logger.error("Non-retriable claim request error, exiting.")
                _log_final_exit_summary(
                    worker_id=wid,
                    reason="non-retriable claim request error",
                    consecutive_claim_failures=consecutive_claim_failures,
                    max_failures=max_failures,
                    last_http_code=last_claim_http_code,
                    last_body_preview=last_claim_body_preview,
                    last_error=last_claim_error,
                )
                sys.exit(1)
            if consecutive_claim_failures >= max_failures:
                logger.error("Too many consecutive claim errors; exiting.")
                _log_final_exit_summary(
                    worker_id=wid,
                    reason="too many consecutive claim request errors",
                    consecutive_claim_failures=consecutive_claim_failures,
                    max_failures=max_failures,
                    last_http_code=last_claim_http_code,
                    last_body_preview=last_claim_body_preview,
                    last_error=last_claim_error,
                )
                sys.exit(1)
            time.sleep(delay)
            continue

        if code == 204:
            consecutive_claim_failures = 0
            checkin_api_reachable = True
            checkin_last_error = ""
            consecutive_empty_claims += 1
            checkin_state = _maybe_run_periodic_checkin(
                should_checkin=should_checkin,
                worker_id=wid,
                current_next_checkin_at=next_checkin_at,
                checkin_interval_seconds=runtime_config.checkin_interval_seconds,
                consecutive_checkin_failures=consecutive_checkin_failures,
                api_reachable=checkin_api_reachable,
                last_error=checkin_last_error,
            )
            consecutive_checkin_failures = checkin_state.consecutive_failures
            next_checkin_at = checkin_state.next_checkin_at
            if consecutive_empty_claims % 12 == 0:
                logger.info(
                    "claim empty queue (204) worker_id=%s consecutive_empty_claims=%s",
                    wid,
                    consecutive_empty_claims,
                )
            time.sleep(poll_interval)
            continue
        if code != 200:
            consecutive_claim_failures += 1
            consecutive_empty_claims = 0
            delay = _compute_backoff_delay(consecutive_claim_failures, poll_interval, backoff_max_delay)
            last_claim_http_code = code
            last_claim_body_preview = data.decode("utf-8", errors="replace")[:500]
            last_claim_error = ""
            checkin_api_reachable = False
            checkin_last_error = f"claim failed http={code}: {last_claim_body_preview}"
            logger.warning(
                "claim failed (http=%s, %s/%s); retrying in %.1fs: %s",
                last_claim_http_code,
                consecutive_claim_failures,
                max_failures,
                delay,
                last_claim_body_preview,
            )
            if _is_non_retriable_http_code(code):
                logger.error("Non-retriable auth/config error; exiting.")
                _log_final_exit_summary(
                    worker_id=wid,
                    reason="non-retriable auth/config error",
                    consecutive_claim_failures=consecutive_claim_failures,
                    max_failures=max_failures,
                    last_http_code=last_claim_http_code,
                    last_body_preview=last_claim_body_preview,
                    last_error=last_claim_error,
                )
                sys.exit(1)
            if consecutive_claim_failures >= max_failures:
                logger.error("Too many consecutive claim errors; exiting.")
                _log_final_exit_summary(
                    worker_id=wid,
                    reason="too many consecutive claim errors",
                    consecutive_claim_failures=consecutive_claim_failures,
                    max_failures=max_failures,
                    last_http_code=last_claim_http_code,
                    last_body_preview=last_claim_body_preview,
                    last_error=last_claim_error,
                )
                sys.exit(1)
            time.sleep(delay)
            continue
        try:
            msg = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as e:
            consecutive_claim_failures += 1
            delay = _compute_backoff_delay(consecutive_claim_failures, poll_interval, backoff_max_delay)
            raw_preview_len = 500
            raw_body = data.decode("utf-8", errors="replace")
            preview = raw_body[:raw_preview_len] if len(raw_body) > raw_preview_len else raw_body
            if len(raw_body) > raw_preview_len:
                preview += f"... [truncated, total {len(raw_body)} chars]"
            last_claim_http_code = code
            last_claim_body_preview = preview
            last_claim_error = str(e)
            checkin_api_reachable = False
            checkin_last_error = f"claim JSON decode error: {e}"
            logger.warning(
                "claim JSON decode error (%s/%s); retrying in %.1fs | http=%s | json_error=%s (line %s col %s) | body_preview=%s",
                consecutive_claim_failures,
                max_failures,
                delay,
                code,
                e.msg,
                getattr(e, "lineno", "?"),
                getattr(e, "colno", "?"),
                repr(preview),
            )
            if consecutive_claim_failures >= max_failures:
                logger.error("Too many consecutive claim errors; exiting.")
                _log_final_exit_summary(
                    worker_id=wid,
                    reason="too many consecutive claim errors (json decode)",
                    consecutive_claim_failures=consecutive_claim_failures,
                    max_failures=max_failures,
                    last_http_code=last_claim_http_code,
                    last_body_preview=last_claim_body_preview,
                    last_error=last_claim_error,
                )
                sys.exit(1)
            time.sleep(delay)
            continue

        consecutive_claim_failures = 0
        checkin_api_reachable = True
        checkin_last_error = ""
        checkin_state = _maybe_run_periodic_checkin(
            should_checkin=should_checkin,
            worker_id=wid,
            current_next_checkin_at=next_checkin_at,
            checkin_interval_seconds=runtime_config.checkin_interval_seconds,
            consecutive_checkin_failures=consecutive_checkin_failures,
            api_reachable=checkin_api_reachable,
            last_error=checkin_last_error,
        )
        consecutive_checkin_failures = checkin_state.consecutive_failures
        next_checkin_at = checkin_state.next_checkin_at
        consecutive_empty_claims = 0
        command_id = msg.get("command_id") or ""
        kind = msg.get("kind") or ""
        payload = msg.get("payload") or {}

        logger.info("claim received command_id=%s kind=%s", command_id, kind)
        _handle_command(
            command_id,
            kind,
            payload,
            scripts_dir=scripts_dir,
            python_exe=python_exe,
            runner_script=runner_script,
            config=runtime_config,
        )
        continue


if __name__ == "__main__":
    main()
