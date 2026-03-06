"""
Shared construction of Secator run_opts from scan config.

Centralizes option building so semantics stay consistent across
runner, remote_runner, and any other consumers.
"""

from __future__ import annotations

from typing import Any

from targetApp.services.scan_param_definitions import PARAM_KEYS as SCAN_PARAM_KEYS


def build_run_opts(secator_config: dict[str, Any], profile_names: list[str]) -> dict[str, Any]:
    """
    Build the run options dict for Secator runs.

    Centralizes option construction so semantics remain consistent across
    runner, remote_runner, worker, and tasks.

    All keys in SCAN_PARAM_KEYS are forwarded when non-None and non-empty.
    ``sync`` and ``profiles`` are the only keys added outside that iteration.
    """
    run_opts: dict[str, Any] = {
        "sync": False,
        "profiles": profile_names,
    }
    for key in SCAN_PARAM_KEYS:
        value = secator_config.get(key)
        if value is not None and value != "":
            run_opts[key] = value
    extra = secator_config.get("extra_config")
    if isinstance(extra, dict) and extra:
        run_opts["extra_config"] = extra
    return run_opts
