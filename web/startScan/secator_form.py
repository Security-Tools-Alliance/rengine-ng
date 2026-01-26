from __future__ import annotations

from typing import Any, Literal, TypedDict

from django.http import QueryDict

from reNgine.core.data import safe_bool_cast, safe_int_cast


class SecatorConfig(TypedDict):
    proxy: str
    rate_limit: int
    threads: int
    timeout: int
    delay: int


class ExecutionModeParams(TypedDict):
    execution_mode: Literal["workflow", "tasks", "scan"]
    workflow_id: int | None
    task_ids: list[int] | None
    secator_scan_type: str | None


class StartSecatorScanKwargs(ExecutionModeParams, total=False):
    scan_existing_elements: bool
    secator_config: SecatorConfig
    speed_profile: str | None
    stealth_profile: str | None
    general_profile: str | None
    network_profile: str | None
    expert_mode: bool


def parse_secator_config(post: QueryDict) -> SecatorConfig:
    """
    Parse Secator runtime configuration from a POST payload.

    Values are clamped to safe ranges to avoid accidental resource exhaustion.
    """
    return {
        "proxy": post.get("proxy", ""),
        "rate_limit": max(1, min(10000, safe_int_cast(post.get("rate_limit", 150), 150))),
        "threads": max(1, min(1000, safe_int_cast(post.get("threads", 20), 20))),
        "timeout": max(1, min(3600, safe_int_cast(post.get("timeout", 300), 300))),
        "delay": max(0, min(60, safe_int_cast(post.get("delay", 0), 0))),
    }


def parse_secator_profiles(post: QueryDict) -> tuple[str | None, str | None, str | None, str | None, bool]:
    """
    Parse profile selections from a POST payload.

    Custom profile selectors take precedence over builtin profile hidden inputs.
    Each profile is only parsed if its corresponding switch is enabled.
    """
    # Check if each profile category is enabled
    use_speed_profile = safe_bool_cast(post.get("use_speed_profile"))
    use_evasion_profile = safe_bool_cast(post.get("use_evasion_profile"))
    use_general_profile = safe_bool_cast(post.get("use_general_profile"))
    use_network_profile = safe_bool_cast(post.get("use_network_profile"))
    
    # Parse profiles only if their switches are enabled
    speed_profile = None
    if use_speed_profile:
        speed_profile = post.get("speed_custom_profile") or post.get("speed_profile")
    
    stealth_profile = None
    if use_evasion_profile:
        stealth_profile = post.get("evasion_custom_profile") or post.get("stealth_profile")
    
    general_profile = None
    if use_general_profile:
        general_profile = post.get("general_custom_profile") or post.get("general_profile")
    
    network_profile = None
    if use_network_profile:
        network_profile = post.get("network_custom_profile") or post.get("network_profile")
    
    expert_mode = safe_bool_cast(post.get("expert_mode"))
    return speed_profile, stealth_profile, general_profile, network_profile, expert_mode


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
        secator_scan_type = post.get("secator_scan_type")
        if not secator_scan_type:
            raise ValueError("Please select a scan type.")
        return {
            "execution_mode": execution_mode,
            "workflow_id": None,
            "task_ids": None,
            "secator_scan_type": secator_scan_type,
        }

    raise ValueError("Please select an execution mode.")


def build_start_secator_scan_kwargs(post: QueryDict) -> StartSecatorScanKwargs:
    """
    Build normalized kwargs for reNgine's start_secator_scan service.
    """
    mode_params = parse_execution_mode_params(post)
    secator_config = parse_secator_config(post)
    speed_profile, stealth_profile, general_profile, network_profile, expert_mode = parse_secator_profiles(post)
    scan_existing_elements = post.get("scan_existing_elements") == "true"

    return {
        **mode_params,
        "scan_existing_elements": scan_existing_elements,
        "secator_config": secator_config,
        "speed_profile": speed_profile,
        "stealth_profile": stealth_profile,
        "general_profile": general_profile,
        "network_profile": network_profile,
        "expert_mode": expert_mode,
    }

