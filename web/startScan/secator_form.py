from __future__ import annotations

import json
import logging
from typing import Any, Literal, TypedDict

from django.conf import settings
from django.http import QueryDict

from reNgine.core.data import safe_bool_cast, safe_int_cast


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

    # Check if each profile category is enabled
    use_speed_profile = safe_bool_cast(post.get("use_speed_profile"))
    use_evasion_profile = safe_bool_cast(post.get("use_evasion_profile"))
    use_general_profile = safe_bool_cast(post.get("use_general_profile"))
    use_network_profile = safe_bool_cast(post.get("use_network_profile"))

    # Parse profiles only if their switches are enabled
    if use_speed_profile:
        if speed_profile := post.get("speed_custom_profile") or post.get("speed_profile"):
            profiles.append(speed_profile)

    if use_evasion_profile:
        if evasion_profile := post.get("evasion_custom_profile") or post.get("stealth_profile"):
            profiles.append(evasion_profile)

    if use_general_profile:
        if general_profile := post.get("general_custom_profile") or post.get("general_profile"):
            profiles.append(general_profile)

    if use_network_profile:
        if network_profile := post.get("network_custom_profile") or post.get("network_profile"):
            profiles.append(network_profile)

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

        else:
            raise ValueError("Please select a scan type.")
    raise ValueError("Please select an execution mode.")


def build_start_secator_scan_kwargs(post: QueryDict) -> StartSecatorScanKwargs:
    """
    Build normalized kwargs for reNgine's start_secator_scan service.
    """
    mode_params = parse_execution_mode_params(post)
    secator_config = parse_secator_config(post)
    profiles = parse_secator_profiles(post)
    # Add profiles to secator_config if not already present
    if profiles and "profiles" not in secator_config:
        secator_config["profiles"] = profiles
    scan_existing_elements = post.get("scan_existing_elements") == "true"

    return {
        **mode_params,
        "scan_existing_elements": scan_existing_elements,
        "secator_config": secator_config,
    }
