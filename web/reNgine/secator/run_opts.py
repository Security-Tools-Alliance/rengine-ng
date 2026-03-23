"""
Shared construction of Secator run_opts from scan config.

Centralizes option building so semantics stay consistent across
runner, remote_runner, and any other consumers.
"""

from __future__ import annotations

from typing import Any

from reNgine.utilities.logger import get_module_logger
from targetApp.services.scan_param_definitions import PARAM_KEYS as SCAN_PARAM_KEYS


logger = get_module_logger(__name__)


def _header_dict_to_secator_string(header_dict: dict[str, Any]) -> str:
    """
    Convert header dict (scan_config format) to Secator string format.

    Secator tasks (e.g. wafw00f) expect "Name1: value1;;Name2: value2".
    Non-string keys are skipped and a warning is logged so misconfigurations
    are visible. Header order is preserved as in header_dict (insertion order).
    """
    if not header_dict or not isinstance(header_dict, dict):
        return ""
    parts: list[str] = []
    for k, v in header_dict.items():
        if not isinstance(k, str):
            logger.warning(
                "Header key skipped (expected str, got %s)",
                type(k).__name__,
            )
            continue
        val_str = str(v) if v is not None else ""
        parts.append("%s: %s" % (k, val_str))
    return ";;".join(parts)


def build_ephemeral_sync_run_opts(**extra: Any) -> dict[str, Any]:
    """
    Build run_opts for short in-process Secator runs (e.g. UI tools, fping discovery).

    Sets ``sync`` True so work runs locally in the current process instead of
    delegating to Celery inside Secator. Disables reports, hooks, profiles,
    duplicate checks, and verbose printing for a minimal footprint.

    Do not use for long-running scans; use :func:`build_run_opts` (default
    ``sync`` False / Celery) for normal orchestration.
    """
    base: dict[str, Any] = {
        "sync": True,
        "process": True,
        "enable_reports": False,
        "enable_hooks": False,
        "enable_profiles": False,
        "enable_duplicate_check": False,
        "print_start": False,
        "print_end": False,
        "print_item": False,
        "quiet": True,
    }
    base.update(extra)
    return base


def build_run_opts(
    secator_config: dict[str, Any],
    profile_items: list[str] | list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build the run options dict for Secator runs.

    Centralizes option construction so semantics remain consistent across
    runner, remote_runner, worker, and tasks.

    Default ``sync`` is False so Secator sub-tasks use Celery. For interactive
    UI paths that need low latency, use :func:`build_ephemeral_sync_run_opts`.

    profile_items: list of profile names (str) and/or inline profile dicts (for
    built-in profiles). The worker builds TemplateLoader from each: dict -> input,
    str -> name="profiles/<name>".

    All keys in SCAN_PARAM_KEYS are forwarded when non-None and non-empty.
    ``header``: if value is a dict, converted to Secator string format
    ("Name1: value1;;Name2: value2") so tasks like wafw00f do not crash.
    """
    run_opts: dict[str, Any] = {
        "sync": False,
        "profiles": list(profile_items),
    }
    for key in SCAN_PARAM_KEYS:
        value = secator_config.get(key)
        if value is None:
            continue
        if key == "header" and isinstance(value, dict):
            if not value:
                continue
            run_opts[key] = _header_dict_to_secator_string(value)
            continue
        if value != "":
            run_opts[key] = value
    extra = secator_config.get("extra_config")
    if isinstance(extra, dict) and extra:
        run_opts["extra_config"] = extra
    return run_opts
