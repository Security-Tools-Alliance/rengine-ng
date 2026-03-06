from __future__ import annotations

import json
from typing import Any, Literal, TypedDict

from django.conf import settings
from django.http import QueryDict

from reNgine.core.data import safe_bool_cast, safe_int_cast
from reNgine.secator.selected_targets import resolve_selected_targets
from reNgine.utilities.logger import get_module_logger
from targetApp.services.scan_param_definitions import PARAM_KEYS, cast_param_value
from targetApp.services.scope_params import (
    apply_resolved_to_secator_config,
    get_scope_for_target,
    resolve_scan_params,
)


PREFIX_SECATOR_FORM = "[SECATOR_FORM]"
logger = get_module_logger(__name__)


class SecatorConfig(TypedDict, total=False):
    """
    User-facing Secator configuration (proxy, delay, profiles, scan params).

    Internal runtime-only fields such as scope-derived worker IDs are stored
    on the kwargs root (e.g. _worker_ids) so they are not logged or serialized
    as part of user config.
    """

    proxy: str | None
    delay: int | float
    profiles: list[str]
    threads: int | None
    rate_limit: int | None
    timeout: int | None
    retries: int | None
    user_agent: str | None
    follow_redirect: bool | None
    depth: int | None
    header: dict[str, str] | None


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
    _worker_ids: list[int]  # scope-derived worker IDs; internal, not part of secator_config


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
                logger.log_line(
                    PREFIX_SECATOR_FORM,
                    "FORM",
                    "Failed to decode 'secator_config' JSON from POST: %s (raw value=%r)" % (exc, secator_config_data),
                    level="warning",
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
        raw_delay = post.get("delay")
        if raw_delay is not None and raw_delay != "":
            delay = max(0, min(60, safe_int_cast(raw_delay, 0)))

    result: dict[str, Any] = {"profiles": profiles if isinstance(profiles, list) else []}
    if proxy is not None:
        result["proxy"] = proxy
    if delay is not None:
        result["delay"] = delay
    return result


_PROFILE_CATEGORY_POST_KEYS: list[tuple[str, str, str, str]] = [
    ("speed", "use_speed_profile", "speed_custom_profile", "speed_profile"),
    ("evasion", "use_evasion_profile", "evasion_custom_profile", "stealth_profile"),
    ("general", "use_general_profile", "general_custom_profile", "general_profile"),
    ("network", "use_network_profile", "network_custom_profile", "network_profile"),
]


def parse_secator_profiles(post: QueryDict) -> list[str]:
    """
    Parse profile selections from a POST payload.

    Returns a list of profile names that are enabled.
    Custom profile selectors take precedence over builtin profile hidden inputs.
    Each profile is only parsed if its corresponding switch is enabled.
    """
    return list(parse_secator_profiles_to_dict(post).values())


def parse_secator_profiles_to_dict(post: QueryDict) -> dict[str, str]:
    """
    Parse profile selections from a POST payload into a per-category dict.

    Returns a mapping of category -> profile name for enabled categories only.
    Custom profile selectors take precedence over builtin profile hidden inputs.
    Each category is only included if its corresponding switch is enabled.

    Example: {"speed": "polite", "evasion": "stealth"}
    """
    profiles: dict[str, str] = {}
    for category, switch_key, custom_key, fallback_key in _PROFILE_CATEGORY_POST_KEYS:
        if safe_bool_cast(post.get(switch_key)) and (profile := post.get(custom_key) or post.get(fallback_key)):
            profiles[category] = profile
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


def _get_target_and_scope_for_scope_merge(
    post: QueryDict,
    target_id: int | None,
    target: Any,
    scope: Any,
) -> tuple[Any, Any]:
    """
    Resolve (target, scope) for scope-based param merge, with security check.

    If target and scope are already provided (both not None), validates they belong
    to the same project and returns (target, scope) or (None, None) on mismatch.
    Otherwise fetches target and scope by target_id and scope_id from POST; returns
    (None, None) if ids missing, not found, or project mismatch.

    Returns:
        (target, scope) to use for merge, or (None, None) to skip merging.
    """
    have_prefetched = target is not None and scope is not None
    if have_prefetched:
        if scope is not None and target.project_id != scope.organization.project_id:
            logger.log_line(
                PREFIX_SECATOR_FORM,
                "SECURITY",
                "Rejected scope/target mismatch: target and scope belong to different projects",
                level="warning",
            )
            return (None, None)
        return (target, scope)

    from targetApp.models import Scope, Target

    scope_id = safe_int_cast(post.get("scope_id"))
    if target_id is None:
        return (None, None)

    try:
        target = Target.objects.select_related("project").get(id=target_id)
    except Target.DoesNotExist:
        return (None, None)

    if scope_id is not None:
        try:
            scope = Scope.objects.select_related("organization__project").get(id=scope_id)
        except Scope.DoesNotExist:
            return (None, None)
        if target.project_id != scope.organization.project_id:
            logger.log_line(
                PREFIX_SECATOR_FORM,
                "SECURITY",
                "Rejected scope/target mismatch: target %s belongs to project %s, scope %s belongs to project %s"
                % (target_id, target.project_id, scope_id, scope.organization.project_id),
                level="warning",
            )
            return (None, None)
        return (target, scope)

    scope = get_scope_for_target(target)
    return (target, scope)


def _parse_secator_user_override_from_post(post: QueryDict) -> dict[str, Any]:
    """
    Build user_override dict from POST for scope param merge.

    Reads PARAM_KEYS from post; values are cast with cast_param_value.
    Used by _merge_scope_params_into_config. header, if present,
    remains as raw string (caller/resolution may parse JSON elsewhere).
    """
    user_override: dict[str, Any] = {}
    for key in PARAM_KEYS:
        raw = post.get(key)
        if raw is not None and raw != "":
            val = cast_param_value(key, raw)
            if val is not None:
                user_override[key] = val
    return user_override


def _merge_scope_params_into_config(
    secator_config: SecatorConfig,
    post: QueryDict,
    target_id: int | None = None,
    *,
    target: Any = None,
    scope: Any = None,
) -> tuple[SecatorConfig, list[int]]:
    """
    If the POST contains a ``scope_id``, resolve effective scan params from the
    Scope/Target chain and merge them into *secator_config*.  User-submitted
    values from the POST already present in *secator_config* take precedence.

    When target and scope are provided (e.g. already fetched by the caller),
    no DB lookup or model import is performed. Otherwise target_id and scope_id
    from POST are used to fetch them.

    Merge strategy is centralized in scope_params.apply_resolved_to_secator_config
    (scalar PARAM_KEYS, then profiles). Worker IDs from resolved are returned
    so the caller can attach them to the kwargs root, not to secator_config.

    Expected shape of user_override (built from POST in this function): a dict
    whose keys are a subset of PARAM_KEYS, with values already cast by
    cast_param_value (int/float/bool/str). header, if present, must be
    a dict (caller must parse JSON elsewhere).
    """
    target, scope = _get_target_and_scope_for_scope_merge(post, target_id, target, scope)
    if target is None:
        return secator_config, []

    organization = None
    if scope is not None:
        organization = getattr(scope, "organization", None)
    elif target is not None:
        orgs = getattr(target, "organizations", None)
        if orgs is not None:
            organization = orgs.first()

    user_override = _parse_secator_user_override_from_post(post)
    resolved = resolve_scan_params(target, scope=scope, organization=organization, user_override=user_override)
    apply_resolved_to_secator_config(secator_config, resolved)
    return secator_config, list(resolved.get("worker_ids", []))


def build_start_secator_scan_kwargs(
    post: QueryDict,
    target: Any = None,
    scope: Any = None,
) -> StartSecatorScanKwargs:
    """
    Build normalized kwargs for reNgine's start_secator_scan service.

    Uses resolve_selected_targets for parsing and precedence: tasks + selected_targets_per_task
    => per-task mode (selected_targets ignored); otherwise single mode with targets_override.

    When target and scope are provided (e.g. already fetched by the caller), they are
    passed to _merge_scope_params_into_config to avoid repeated DB lookups.
    """
    mode_params = parse_execution_mode_params(post)
    secator_config = parse_secator_config(post)
    profiles = parse_secator_profiles(post)
    if profiles and not secator_config.get("profiles"):
        secator_config["profiles"] = profiles

    execution_mode = mode_params.get("execution_mode")
    resolved = resolve_selected_targets(
        post.get("selected_targets"),
        post.get("selected_targets_per_task"),
        execution_mode,
    )

    post_target_id = safe_int_cast(post.get("target_id"))
    if target is not None:
        effective_target_id = getattr(target, "id", None) or getattr(target, "pk", None)
        if post_target_id is not None and post_target_id != effective_target_id:
            logger.log_line(
                PREFIX_SECATOR_FORM,
                "SECURITY",
                "POST target_id (%s) does not match provided target instance (id=%s); using instance"
                % (post_target_id, effective_target_id),
                level="warning",
            )
        target_id_for_merge = effective_target_id
    else:
        target_id_for_merge = post_target_id
    secator_config, scope_worker_ids = _merge_scope_params_into_config(
        secator_config, post, target_id_for_merge, target=target, scope=scope
    )

    kwargs: StartSecatorScanKwargs = {
        **mode_params,
        "secator_config": secator_config,
    }
    if scope_worker_ids:
        kwargs["_worker_ids"] = scope_worker_ids
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
