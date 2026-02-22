"""
Scan parameter resolution service.

Resolves effective scan parameters by merging values from multiple sources
following a strict priority chain:
    1. User override at scan launch
    2. Target.scan_config_override["profiles"] (for profiles) / Target.scan_config_override[param]
    3. Target.request_headers (for request_headers only, historical compat)
    4. Scope[param] / Scope.default_profiles (if scope provided)
    5. Default (settings.DEFAULT_*)
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.http import QueryDict

from reNgine.utilities.logger import get_module_logger
from scanEngine.models import SecatorWorker

from .scan_param_definitions import (
    BOOL_PARAM_KEYS,
    FLOAT_PARAM_KEYS,
    INT_PARAM_KEYS,
    PARAM_KEYS,
    STR_PARAM_KEYS,
    TARGET_OVERRIDE_PREFIX,
    cast_param_value,
    parse_request_headers_value,
)

PREFIX_SCOPE_PARAMS = "[SCOPE_PARAMS]"
logger = get_module_logger(__name__)

_SETTINGS_DEFAULTS: dict[str, str] = {
    "threads": "DEFAULT_THREADS",
    "rate_limit": "DEFAULT_RATE_LIMIT",
    "timeout": "DEFAULT_HTTP_TIMEOUT",
    "retries": "DEFAULT_RETRIES",
    "delay": "DEFAULT_DELAY",
    "follow_redirect": "DEFAULT_FOLLOW_REDIRECT",
    "depth": "DEFAULT_DEPTH",
}

_PROFILE_CATEGORIES = ("speed", "evasion", "general", "network")


def _get_default(param: str) -> Any:
    setting_name = _SETTINGS_DEFAULTS.get(param)
    if setting_name is None:
        return None
    return getattr(settings, setting_name, None)


def _normalize_scan_config_override(raw: Any) -> dict[str, Any]:
    """Ensure scan_config_override is a dict; legacy or malformed JSONField values become {}."""
    return raw if isinstance(raw, dict) else {}


def _profiles_to_list(profiles_data: Any) -> list[str]:
    """
    Convert profiles from either dict or list format to a flat list of names.

    Scope.default_profiles is stored as a dict (category -> name). Legacy data may
    still be a list of profile names; resolution code accepts both. A data migration
    can use normalize_scope_default_profiles_to_dict() to normalize list-form values
    so that resolution can assume dict-only and this helper can be simplified.
    """
    if isinstance(profiles_data, dict):
        return [v for k, v in profiles_data.items() if k in _PROFILE_CATEGORIES and v]
    if isinstance(profiles_data, list):
        return [p for p in profiles_data if isinstance(p, str) and p]
    return []


def normalize_scope_default_profiles_to_dict(raw: Any) -> dict[str, str] | None:
    """
    Normalize Scope.default_profiles to dict form for storage.

    If raw is already a dict (with keys in _PROFILE_CATEGORIES), returns it as-is.
    If raw is a legacy list of profile names, maps them to categories by order
    (first category gets first name, etc.) and returns the dict. Otherwise returns None.
    Intended for use in a data migration to normalize list-form default_profiles
    so that resolution code can assume dict-only and _profiles_to_list can be simplified.
    """
    if raw is None:
        return None
    if isinstance(raw, dict):
        return {k: v for k, v in raw.items() if k in _PROFILE_CATEGORIES and isinstance(v, str) and v}
    if isinstance(raw, list):
        names = [p for p in raw if isinstance(p, str) and p]
        return dict(zip(_PROFILE_CATEGORIES[: len(names)], names))
    return None


def resolve_scan_params(
    target: Any,
    scope: Any | None = None,
    user_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Resolve effective scan parameters following the priority chain.

    Args:
        target: Target model instance.
        scope: Scope model instance (optional). Must be explicitly provided by the caller.
        user_override: Dict of user-provided overrides at scan launch time.

    Returns:
        Dict with resolved values for all PARAM_KEYS plus ``profiles``,
        ``worker_ids``, and ``extra_config``.
    """
    override = user_override or {}
    raw = getattr(target, "scan_config_override", None) if target else None
    if raw is not None and not isinstance(raw, dict):
        target_id = getattr(target, "id", None) or getattr(target, "pk", None) or target
        logger.log_line(
            PREFIX_SCOPE_PARAMS,
            "SCAN_CONFIG",
            "Non-dict scan_config_override for target %s: %r; treating as empty."
            % (target_id, raw),
            level="warning",
        )
    target_config = _normalize_scan_config_override(raw)

    result: dict[str, Any] = {}

    for param in PARAM_KEYS:
        value = _resolve_single_param(param, override, target_config, target, scope)
        result[param] = value

    result["profiles"] = _resolve_profiles(override, target_config, scope)
    result["worker_ids"] = _resolve_worker_ids(scope)
    result["extra_config"] = _resolve_extra_config(override, target_config, scope)

    return result


def build_effective_params_display(
    scope: Any | None = None,
    target: Any | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Build a display-oriented dict showing the effective value and its source for each param.

    Used in templates to show the user which values will be applied and where they come from.

    Returns a dict keyed by param name, with {"value": ..., "source": "target|scope|default"}.
    """
    raw = getattr(target, "scan_config_override", None) if target else None
    if raw is not None and not isinstance(raw, dict):
        target_id = getattr(target, "id", None) or getattr(target, "pk", None) or target
        logger.log_line(
            PREFIX_SCOPE_PARAMS,
            "SCAN_CONFIG",
            "Non-dict scan_config_override for target %s: %r; treating as empty."
            % (target_id, raw),
            level="warning",
        )
    target_config = _normalize_scan_config_override(raw)

    result: dict[str, dict[str, Any]] = {}

    for param in PARAM_KEYS:
        if target_config.get(param) is not None:
            result[param] = {"value": target_config[param], "source": "target"}
        elif scope is not None and (scope_val := getattr(scope, param, None)) is not None:
            result[param] = {"value": scope_val, "source": "scope"}
        else:
            result[param] = {"value": _get_default(param), "source": "default"}

    target_profiles = _profiles_to_list(target_config.get("profiles"))
    scope_profiles = _profiles_to_list(getattr(scope, "default_profiles", None)) if scope else []
    if target_profiles:
        result["profiles"] = {"value": target_config.get("profiles"), "source": "target"}
    elif scope_profiles:
        result["profiles"] = {"value": getattr(scope, "default_profiles"), "source": "scope"}
    else:
        result["profiles"] = {"value": None, "source": "default"}

    return result


def _resolve_single_param(
    param: str,
    override: dict[str, Any],
    target_config: dict[str, Any],
    target: Any,
    scope: Any | None,
) -> Any:
    # 1. User override
    if param in override and override[param] is not None:
        return override[param]

    # 2. Target.scan_config_override
    if param in target_config and target_config[param] is not None:
        return target_config[param]

    # 3. Target.request_headers (historical compat, only for request_headers)
    if param == "request_headers" and target is not None:
        historical = getattr(target, "request_headers", None)
        if historical is not None:
            return historical

    # 4. Scope field
    if scope is not None:
        scope_value = getattr(scope, param, None)
        if scope_value is not None:
            return scope_value

    # 5. Default
    return _get_default(param)


def _resolve_profiles(
    override: dict[str, Any],
    target_config: dict[str, Any],
    scope: Any | None,
) -> list[str]:
    # 1. User override (list from parse_secator_profiles at scan launch)
    if override_profiles := _profiles_to_list(override.get("profiles")):
        return override_profiles

    # 2. Target.scan_config_override["profiles"] (dict per category)
    if target_profiles := _profiles_to_list(target_config.get("profiles")):
        return target_profiles

    # 3. Scope.default_profiles (dict per category)
    if scope is not None:
        if scope_profiles := _profiles_to_list(getattr(scope, "default_profiles", None)):
            return scope_profiles

    return []


def _resolve_worker_ids(scope: Any | None) -> list[int]:
    """
    Return active worker IDs for the scope. Caller (e.g. _merge_scope_params_into_config)
    must ensure scope and target belong to the same project before using these IDs.
    """
    if scope is None:
        return []
    workers = SecatorWorker.objects.active().filter(scopes=scope)
    return list(workers.values_list("id", flat=True))


def _resolve_extra_config(
    override: dict[str, Any],
    target_config: dict[str, Any],
    scope: Any | None,
) -> dict[str, Any]:
    base: dict[str, Any] = {}

    if scope is not None:
        scope_extra = getattr(scope, "extra_config", None)
        if isinstance(scope_extra, dict):
            base.update(scope_extra)

    target_extra = target_config.get("extra_config")
    if isinstance(target_extra, dict):
        base.update(target_extra)

    override_extra = override.get("extra_config")
    if isinstance(override_extra, dict):
        base.update(override_extra)

    return base


def apply_resolved_to_secator_config(
    secator_config: dict[str, Any],
    resolved: dict[str, Any],
) -> None:
    """
    Merge resolved scan params into a Secator config in place.

    Single place for merge strategy; add new param handling here to avoid
    divergence between resolve_scan_params output and what gets merged.

    Strategy:
    - Scalar params (PARAM_KEYS): set only when current value is None or "".
    - profiles: set only when resolved has profiles and config has none.
    - worker_ids are not written here; caller should put them on the kwargs root.
    """
    for key in PARAM_KEYS:
        value = resolved.get(key)
        if value is not None:
            existing = secator_config.get(key)
            if existing is None or existing == "":
                secator_config[key] = value

    if resolved.get("profiles") and not secator_config.get("profiles"):
        secator_config["profiles"] = resolved["profiles"]


def parse_target_scan_override_from_post(
    post: QueryDict,
    profiles_dict: dict[str, str] | None = None,
    existing_override: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """
    Parse target scan_config_override from a POST payload (target update form).

    Reads keys with prefix TARGET_OVERRIDE_PREFIX. Invalid or empty values are
    omitted. When existing_override is provided, result is initialized from a
    shallow copy and POST values override.
    For override_request_headers: when the POST value is invalid JSON or not a
    JSON object, existing request_headers are left unchanged and an error is
    appended; only an empty string clears the override.
    Caller may pass profiles_dict from parse_secator_profiles_to_dict(post)
    to avoid importing startScan in this module.

    Returns:
        (override_dict, list of user-facing error messages)
    """
    result = dict(existing_override) if existing_override else {}
    errors: list[str] = []

    for param in INT_PARAM_KEYS + STR_PARAM_KEYS + FLOAT_PARAM_KEYS + BOOL_PARAM_KEYS:
        raw = post.get(TARGET_OVERRIDE_PREFIX + param)
        if raw is None:
            continue
        raw = raw.strip()
        if raw == "":
            result.pop(param, None)
            continue
        val = cast_param_value(param, raw)
        if val is not None:
            result[param] = val

    raw_headers = post.get(TARGET_OVERRIDE_PREFIX + "request_headers")
    if raw_headers is not None:
        parsed, err = parse_request_headers_value(raw_headers)
        if err:
            errors.append(err)
        elif parsed is not None:
            result["request_headers"] = parsed
        else:
            result.pop("request_headers", None)

    if profiles_dict:
        result["profiles"] = profiles_dict

    return result, errors
