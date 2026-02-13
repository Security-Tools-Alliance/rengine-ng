from __future__ import annotations

import json
import logging
from typing import Any, Literal, TypedDict

from django.conf import settings
from django.http import QueryDict

from reNgine.core.data import safe_bool_cast, safe_int_cast
from reNgine.secator.selected_targets import resolve_selected_targets


logger = logging.getLogger(__name__)


class SecatorConfig(TypedDict):
    proxy: str | None
    delay: int
    profiles: list[str]


class ExecutionModeParams(TypedDict):
    execution_mode: Literal["workflow", "tasks", "scan"]
    workflow_id: int | None
    task_ids: list[int] | None
    secator_scan_type: str | None


class StartSecatorScanKwargs(ExecutionModeParams, total=False):
    scan_existing_elements: bool
    secator_config: SecatorConfig
    targets_override: list[str]
    selected_targets_per_task: dict[str, list[str]]
    scan_history_id: int
    worker_id: int


def parse_secator_config(post: QueryDict) -> SecatorConfig:
    """
    Parse Secator runtime configuration from a POST payload.

    Values are clamped to safe ranges to avoid accidental resource exhaustion.
    """
    profiles: list[str] = []
    proxy: str | None = None
    delay: int | None = None

    secator_config_data = post.get("secator_config")
    if secator_config_data:
        parsed_dict: dict[str, Any] | None = None

        if isinstance(secator_config_data, dict):
            parsed_dict = secator_config_data
        elif isinstance(secator_config_data, str):
            try:
                parsed = json.loads(secator_config_data)
                if isinstance(parsed, dict):
                    parsed_dict = parsed
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning(
                    "Failed to decode 'secator_config' JSON from POST: %s (raw value=%r)",
                    exc,
                    secator_config_data,
                )
                if getattr(settings, "DEBUG", False):
                    raise ValueError("Invalid JSON in 'secator_config'; expected a JSON object.") from exc

        if parsed_dict is not None:
            profiles = parsed_dict.get("profiles", [])
            proxy = parsed_dict.get("proxy")
            delay_value = parsed_dict.get("delay")
            if delay_value is not None:
                delay = max(0, min(60, safe_int_cast(delay_value, 0)))

    # Fallback to top-level fields if not in secator_config
    if proxy is None:
        proxy = post.get("proxy") or None
    if delay is None:
        delay = max(0, min(60, safe_int_cast(post.get("delay", 0), 0)))

    return {
        "proxy": proxy,
        "delay": delay,
        "profiles": profiles if isinstance(profiles, list) else [],
    }


def parse_secator_profiles(post: QueryDict) -> list[str]:
    """
    Parse profile selections from a POST payload.

    Returns a list of profile names that are enabled.
    Custom profile selectors take precedence over builtin profile hidden inputs.
    Each profile is only parsed if its corresponding switch is enabled.
    """
    profiles = []

    profile_configs = [
        (safe_bool_cast(post.get("use_speed_profile")), "speed_custom_profile", "speed_profile"),
        (safe_bool_cast(post.get("use_evasion_profile")), "evasion_custom_profile", "stealth_profile"),
        (safe_bool_cast(post.get("use_general_profile")), "general_custom_profile", "general_profile"),
        (safe_bool_cast(post.get("use_network_profile")), "network_custom_profile", "network_profile"),
    ]
    for use_profile, custom_key, fallback_key in profile_configs:
        if use_profile and (profile := post.get(custom_key) or post.get(fallback_key)):
            profiles.append(profile)
    return profiles


def parse_execution_mode_params(post: QueryDict) -> ExecutionModeParams:
    """
    Parse execution mode and required parameters.

    Returns:
        Dict containing:
        - execution_mode: str
        - workflow_id: int | None
        - task_ids: list[int] | None
        - secator_scan_type: str | None

    Raises:
        ValueError: On missing/invalid selection (message suitable for end-user).
    """
    execution_mode = (post.get("execution_mode") or "").strip().lower()
    if not execution_mode:
        raise ValueError("Please select an execution mode.")

    if execution_mode == "workflow":
        workflow_id = safe_int_cast(post.get("workflow_id"))
        if workflow_id is None:
            raise ValueError("Please select a workflow.")
        return {
            "execution_mode": execution_mode,
            "workflow_id": workflow_id,
            "task_ids": None,
            "secator_scan_type": None,
        }

    if execution_mode == "tasks":
        task_ids_raw = post.getlist("task_ids")
        if not task_ids_raw:
            raise ValueError("Please select at least one task.")
        task_ids: list[int] = []
        for raw_id in task_ids_raw:
            task_id = safe_int_cast(raw_id)
            if task_id is None:
                raise ValueError("Please select at least one valid task.")
            task_ids.append(task_id)
        return {
            "execution_mode": execution_mode,
            "workflow_id": None,
            "task_ids": task_ids,
            "secator_scan_type": None,
        }

    if execution_mode == "scan":
        if secator_scan_type := post.get("secator_scan_type"):
            return {
                "execution_mode": execution_mode,
                "workflow_id": None,
                "task_ids": None,
                "secator_scan_type": secator_scan_type,
            }
        raise ValueError("Please select a scan type.")
    raise ValueError("Please select an execution mode.")


def build_start_secator_scan_kwargs(post: QueryDict) -> StartSecatorScanKwargs:
    """
    Build normalized kwargs for reNgine's start_secator_scan service.

    Uses resolve_selected_targets for parsing and precedence: tasks + selected_targets_per_task
    => per-task mode (selected_targets ignored); otherwise single mode with targets_override.
    """
    mode_params = parse_execution_mode_params(post)
    secator_config = parse_secator_config(post)
    profiles = parse_secator_profiles(post)
    if profiles and "profiles" not in secator_config:
        secator_config["profiles"] = profiles

    execution_mode = mode_params.get("execution_mode")
    resolved = resolve_selected_targets(
        post.get("selected_targets"),
        post.get("selected_targets_per_task"),
        execution_mode,
    )

    kwargs: StartSecatorScanKwargs = {
        **mode_params,
        "secator_config": secator_config,
    }
    if resolved["use_per_task"]:
        kwargs["selected_targets_per_task"] = resolved["selected_targets_per_task"]
    elif resolved.get("targets_override") is not None:
        kwargs["targets_override"] = resolved["targets_override"]
    optional_scan_history_id = safe_int_cast(post.get("scan_history_id"))
    if optional_scan_history_id is not None:
        kwargs["scan_history_id"] = optional_scan_history_id
    optional_worker_id = safe_int_cast(post.get("worker_id"))
    if optional_worker_id is not None:
        kwargs["worker_id"] = optional_worker_id
    return kwargs
