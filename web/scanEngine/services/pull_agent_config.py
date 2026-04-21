"""
Centralized server-side tuning for pull-agent command waiting.

Key interactions:
- min/max/jitter control how aggressively `wait_for_command()` polls DB state
- retention controls terminal command cleanup window
- token max length constrains accepted pull headers before auth matching

Ownership map:
- `pull_agent_constants.py`: env var names + shared defaults (server + worker script)
- `pull_agent_config.py` (this module): server-side parsing/validation for wait logic
- `worker_pull.py`: queue wait/cleanup behavior and token header validation
- `docker/worker/rengine_pull_agent.py`: worker-side polling/backoff/runtime behavior
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import logging
import os

from pull_agent_constants import (
    DEFAULT_PULL_COMMAND_POLL_INTERVAL_MAX_SECONDS,
    DEFAULT_PULL_COMMAND_POLL_INTERVAL_MIN_SECONDS,
    DEFAULT_PULL_COMMAND_POLL_JITTER_RATIO,
    DEFAULT_PULL_COMMAND_RETENTION_SECONDS,
    DEFAULT_PULL_REVOKE_WAIT_SECONDS,
    DEFAULT_PULL_TOKEN_MAX_LENGTH,
    ENV_PULL_COMMAND_POLL_INTERVAL_MAX_SECONDS,
    ENV_PULL_COMMAND_POLL_INTERVAL_MIN_SECONDS,
    ENV_PULL_COMMAND_POLL_JITTER_RATIO,
    ENV_PULL_COMMAND_RETENTION_SECONDS,
    ENV_PULL_REVOKE_WAIT_SECONDS,
    ENV_PULL_TOKEN_MAX_LENGTH,
)


logger = logging.getLogger(__name__)


def _read_int_env(name: str, default: int, minimum: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _read_float_env(name: str, default: float, minimum: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        return default


def pull_command_retention_seconds() -> int:
    """
    How long succeeded/failed pull-agent commands are kept.

    Environment variable:
    - RENGINE_PULL_COMMAND_RETENTION_SECONDS (default: 604800 = 7 days)
    """

    return _read_int_env(ENV_PULL_COMMAND_RETENTION_SECONDS, default=DEFAULT_PULL_COMMAND_RETENTION_SECONDS, minimum=60)


def pull_revoke_wait_seconds() -> int:
    """
    Timeout in seconds for pull-agent revoke waiting.

    Environment variable:
    - RENGINE_PULL_REVOKE_WAIT_SECONDS (default: 90)
    """

    return _read_int_env(ENV_PULL_REVOKE_WAIT_SECONDS, default=DEFAULT_PULL_REVOKE_WAIT_SECONDS, minimum=10)


def pull_command_poll_interval_min_seconds() -> float:
    """Minimum polling sleep when waiting for a pull-agent command status."""
    return _read_float_env(
        ENV_PULL_COMMAND_POLL_INTERVAL_MIN_SECONDS,
        default=DEFAULT_PULL_COMMAND_POLL_INTERVAL_MIN_SECONDS,
        minimum=0.05,
    )


def pull_command_poll_interval_max_seconds() -> float:
    """Maximum polling sleep when waiting for a pull-agent command status."""
    return _read_float_env(
        ENV_PULL_COMMAND_POLL_INTERVAL_MAX_SECONDS,
        default=DEFAULT_PULL_COMMAND_POLL_INTERVAL_MAX_SECONDS,
        minimum=0.1,
    )


def pull_command_poll_jitter_ratio() -> float:
    """Symmetric jitter ratio applied to polling sleep (0 disables jitter)."""
    return _read_float_env(
        ENV_PULL_COMMAND_POLL_JITTER_RATIO,
        default=DEFAULT_PULL_COMMAND_POLL_JITTER_RATIO,
        minimum=0.0,
    )


def pull_token_max_length() -> int:
    """Upper bound for the pull token length accepted from HTTP headers."""
    return _read_int_env(ENV_PULL_TOKEN_MAX_LENGTH, default=DEFAULT_PULL_TOKEN_MAX_LENGTH, minimum=32)


@dataclass(frozen=True)
class PullCommandWaitConfig:
    poll_interval_min_seconds: float
    poll_interval_max_seconds: float
    poll_jitter_ratio: float
    command_retention_seconds: int


@lru_cache(maxsize=1)
def get_pull_command_wait_config() -> PullCommandWaitConfig:
    """Return validated pull command wait config and log effective values once."""
    config = PullCommandWaitConfig(
        poll_interval_min_seconds=pull_command_poll_interval_min_seconds(),
        poll_interval_max_seconds=pull_command_poll_interval_max_seconds(),
        poll_jitter_ratio=pull_command_poll_jitter_ratio(),
        command_retention_seconds=pull_command_retention_seconds(),
    )
    logger.info(
        "Pull command wait config loaded min=%s max=%s jitter=%s retention_seconds=%s",
        config.poll_interval_min_seconds,
        config.poll_interval_max_seconds,
        config.poll_jitter_ratio,
        config.command_retention_seconds,
    )
    return config
