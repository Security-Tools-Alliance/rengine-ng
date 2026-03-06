"""
Scan parameter resolution service.

Resolves effective scan parameters by merging values from multiple sources
following a strict priority chain:
    1. User override at scan launch
    2. Target.scan_config[param] / Target.scan_config["profiles"]
    3. Scope.scan_config[param] / Scope.scan_config["profiles"] (if scope provided)
    4. Organization.scan_config[param] / Organization.scan_config["profiles"] (if org provided)
    5. Default (settings.DEFAULT_*)
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.http import QueryDict

from reNgine.utilities.logger import get_module_logger
from scanEngine.models import SecatorProfile, SecatorWorker

from .scan_param_definitions import (
    BOOL_PARAM_KEYS,
    FLOAT_PARAM_KEYS,
    INT_PARAM_KEYS,
    PARAM_KEYS,
    STR_PARAM_KEYS,
    TARGET_OVERRIDE_PREFIX,
    cast_param_value,
    parse_header_value,
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
PROFILE_CATEGORIES = _PROFILE_CATEGORIES


def get_scope_for_target(target: Any) -> Any:
    """
    Return the scope to use for a target when scope_id is not specified.

    Selection contract: when a target belongs to more than one scope, this
    function always returns the scope with the lowest database ID (``order_by("id")``).
    This is intentionally deterministic so that all call sites — forms, API
    preview, and views — agree on the same scope without any additional
    tie-breaking logic.  A warning is logged whenever multiple scopes are
    found so that operators can diagnose unexpected associations.

    Returns ``None`` if ``target`` is ``None`` or has no associated scopes.
    """
    if target is None:
        return None
    qs = target.scopes.select_related("organization", "organization__project").order_by("id")
    scopes = list(qs[:2])
    if len(scopes) > 1:
        logger.log_line(
            PREFIX_SCOPE_PARAMS,
            "SCOPE",
            "Target %s has multiple scopes; using first by id" % (target.id,),
            level="warning",
        )
    return scopes[0] if scopes else None


def _get_profile_opts(profile_name: str) -> dict[str, Any]:
    """Return parsed opts dict for a Secator profile by name, or empty dict.

    If the stored YAML is the full file (with top-level key 'opts'), the inner
    opts dict is returned so that rate_limit, delay, timeout, retries etc. are
    applied correctly.
    """
    if not profile_name or not isinstance(profile_name, str):
        return {}
    profile = SecatorProfile.objects.filter(name=profile_name.strip(), is_active=True).first()
    if profile is None:
        return _get_profile_opts_from_secator_loader(profile_name.strip())
    parsed = profile._parse_opts()
    if isinstance(parsed, dict) and "opts" in parsed and isinstance(parsed["opts"], dict):
        return parsed["opts"]
    return parsed if isinstance(parsed, dict) else {}


_secator_profiles_cache: list[Any] | None = None


def _get_secator_profiles() -> list[Any]:
    """Load built-in Secator profiles once and cache; avoid repeated imports."""
    global _secator_profiles_cache
    if _secator_profiles_cache is not None:
        return _secator_profiles_cache
    try:
        from secator.loader import get_configs_by_type

        profiles = get_configs_by_type("profile")
        loaded = list(profiles) if profiles else []
    except (ImportError, AttributeError, TypeError) as e:
        logger.log_line(
            PREFIX_SCOPE_PARAMS,
            "SECATOR_LOADER",
            "Could not load Secator profiles for fallback opts: %s" % (e,),
            level="debug",
        )
        loaded = []
    _secator_profiles_cache = loaded
    return _secator_profiles_cache


def _get_profile_opts_from_secator_loader(profile_name: str) -> dict[str, Any]:
    """Fallback: load built-in profile opts from Secator package if available."""
    for p in _get_secator_profiles():
        try:
            if getattr(p, "name", None) != profile_name:
                continue
            if not hasattr(p, "opts"):
                continue
            opts = getattr(p, "opts", None)
            if isinstance(opts, dict):
                return opts
            if hasattr(opts, "toDict") and callable(getattr(opts, "toDict")):
                return opts.toDict()
            return {}
        except (AttributeError, TypeError):
            continue
    return {}


def _format_profile_opts_tooltip(opts: dict[str, Any]) -> str:
    """Format profile opts as multi-line tooltip text (param: value)."""
    if not opts:
        return ""
    lines = []
    for k in sorted(opts.keys()):
        v = opts[k]
        if v is None:
            v = ""
        elif isinstance(v, dict):
            v = str(v)
        else:
            v = str(v)
        lines.append("%s: %s" % (k, v))
    return ", ".join(lines)


def _get_default(param: str) -> Any:
    setting_name = _SETTINGS_DEFAULTS.get(param)
    if setting_name is None:
        return None
    return getattr(settings, setting_name, None)


def _normalize_scan_config(raw: Any) -> dict[str, Any]:
    """Ensure scan_config is a dict; legacy or malformed JSONField values become {}."""
    return raw if isinstance(raw, dict) else {}


def _profiles_to_list(profiles_data: Any) -> list[str]:
    """
    Convert profiles from either dict or list format to a flat list of names.

    scan_config["profiles"] is stored as a dict (category -> name). Legacy data may
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
    Normalize profiles to dict form for storage.

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
    organization: Any | None = None,
    user_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Resolve effective scan parameters following the priority chain.

    Args:
        target: Target model instance.
        scope: Scope model instance (optional). Must be explicitly provided by the caller.
        organization: Organization model instance (optional).
        user_override: Dict of user-provided overrides at scan launch time.

    Returns:
        Dict with resolved values for all PARAM_KEYS plus ``profiles``,
        ``worker_ids``, and ``extra_config``.
    """
    override = user_override or {}

    raw = getattr(target, "scan_config", None) if target else None
    if raw is not None and not isinstance(raw, dict):
        target_id = getattr(target, "id", None) or getattr(target, "pk", None) or target
        logger.log_line(
            PREFIX_SCOPE_PARAMS,
            "SCAN_CONFIG",
            "Non-dict scan_config for target %s: %r; treating as empty." % (target_id, raw),
            level="warning",
        )
    target_config = _normalize_scan_config(raw)

    scope_config = _normalize_scan_config(getattr(scope, "scan_config", None) if scope else None)
    org_config = _normalize_scan_config(getattr(organization, "scan_config", None) if organization else None)

    result: dict[str, Any] = {}

    for param in PARAM_KEYS:
        value = _resolve_single_param(param, override, target_config, scope_config, org_config)
        result[param] = value

    result["profiles"] = _resolve_profiles(override, target_config, scope_config, org_config)
    result["worker_ids"] = _resolve_worker_ids(scope)
    result["extra_config"] = _resolve_extra_config(override, target_config, scope_config, org_config)

    return result


def _build_effective_display_from_config_dicts(
    user_override: dict[str, Any],
    target_config: dict[str, Any],
    scope_config: dict[str, Any],
    org_config: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """
    Build display dict from four config dicts (override > target > scope > org > default).

    Source is "scan" when value comes from user_override, else "target"|"scope"|"organization"|"default".
    """
    result: dict[str, dict[str, Any]] = {}

    for param in PARAM_KEYS:
        if user_override.get(param) is not None:
            result[param] = {"value": user_override[param], "source": "scan"}
        elif target_config.get(param) is not None:
            result[param] = {"value": target_config[param], "source": "target"}
        elif scope_config.get(param) is not None:
            result[param] = {"value": scope_config[param], "source": "scope"}
        elif org_config.get(param) is not None:
            result[param] = {"value": org_config[param], "source": "organization"}
        else:
            result[param] = {"value": _get_default(param), "source": "default"}

    override_profiles = _profiles_to_list(user_override.get("profiles"))
    target_profiles = _profiles_to_list(target_config.get("profiles"))
    scope_profiles = _profiles_to_list(scope_config.get("profiles"))
    org_profiles = _profiles_to_list(org_config.get("profiles"))

    if override_profiles:
        result["profiles"] = {"value": user_override.get("profiles"), "source": "scan"}
    elif target_profiles:
        result["profiles"] = {"value": target_config.get("profiles"), "source": "target"}
    elif scope_profiles:
        result["profiles"] = {"value": scope_config.get("profiles"), "source": "scope"}
    elif org_profiles:
        result["profiles"] = {"value": org_config.get("profiles"), "source": "organization"}
    else:
        result["profiles"] = {"value": None, "source": "default"}

    profiles_value = result.get("profiles", {}).get("value")
    if isinstance(profiles_value, dict) and profiles_value:
        merged_profile_opts: dict[str, Any] = {}
        merged_profile_name: dict[str, str] = {}
        profile_opts_cache: dict[str, dict[str, Any]] = {}

        def _get_cached_profile_opts(profile_name: str) -> dict[str, Any]:
            if profile_name not in profile_opts_cache:
                profile_opts_cache[profile_name] = _get_profile_opts(profile_name)
            return profile_opts_cache[profile_name]

        for cat in _PROFILE_CATEGORIES:
            name = profiles_value.get(cat)
            if not name or not isinstance(name, str):
                continue
            opts = _get_cached_profile_opts(name)
            for k, v in opts.items():
                if k in PARAM_KEYS:
                    merged_profile_opts[k] = v
                    merged_profile_name[k] = name
        for param in PARAM_KEYS:
            if result[param]["source"] == "default" and param in merged_profile_opts:
                result[param] = {
                    "value": merged_profile_opts[param],
                    "source": "profile",
                    "profile_name": merged_profile_name.get(param),
                }
        profile_display_list: list[dict[str, Any]] = []
        for cat in _PROFILE_CATEGORIES:
            name = profiles_value.get(cat)
            if not name or not isinstance(name, str):
                continue
            opts = _get_cached_profile_opts(name)
            profile_display_list.append(
                {
                    "category": cat,
                    "name": name,
                    "tooltip": _format_profile_opts_tooltip(opts),
                }
            )
        result["profile_display_list"] = profile_display_list
    else:
        result["profile_display_list"] = []

    return result


def build_effective_params_display(
    scope: Any | None = None,
    target: Any | None = None,
    organization: Any | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Build a display-oriented dict showing the effective value and its source for each param.

    Used in templates to show the user which values will be applied and where they come from.

    Returns a dict keyed by param name, with {"value": ..., "source": "target|scope|organization|default"}.
    """
    raw = getattr(target, "scan_config", None) if target else None
    if raw is not None and not isinstance(raw, dict):
        target_id = getattr(target, "id", None) or getattr(target, "pk", None) or target
        logger.log_line(
            PREFIX_SCOPE_PARAMS,
            "SCAN_CONFIG",
            "Non-dict scan_config for target %s: %r; treating as empty." % (target_id, raw),
            level="warning",
        )
    target_config = _normalize_scan_config(raw)
    scope_config = _normalize_scan_config(getattr(scope, "scan_config", None) if scope else None)
    org_config = _normalize_scan_config(getattr(organization, "scan_config", None) if organization else None)
    result = _build_effective_display_from_config_dicts({}, target_config, scope_config, org_config)
    result["worker"] = get_effective_worker_display(scope=scope)
    return result


def build_effective_params_display_from_configs(
    org_config: dict[str, Any] | None = None,
    scope_config: dict[str, Any] | None = None,
    target_config: dict[str, Any] | None = None,
    user_override: dict[str, Any] | None = None,
    scope: Any | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Build effective params display from config dicts (e.g. draft form values + parent configs).

    Priority: user_override > target_config > scope_config > org_config > default.
    Used by the scan-params-effective-preview API for real-time effective block updates.
    When scope is provided and user_override contains worker_id, the worker entry reflects
    scan override; otherwise scope workers or "Local".
    """
    override = _normalize_scan_config(user_override) if user_override else {}
    target_c = _normalize_scan_config(target_config) if target_config else {}
    scope_c = _normalize_scan_config(scope_config) if scope_config else {}
    org_c = _normalize_scan_config(org_config) if org_config else {}
    result = _build_effective_display_from_config_dicts(override, target_c, scope_c, org_c)
    worker_id = (user_override or {}).get("worker_id") if user_override else None
    result["worker"] = get_effective_worker_display(worker_id=worker_id, scope=scope)
    return result


def _is_empty_dict_no_override(param: str, value: Any) -> bool:
    """Treat empty dict for header as 'no override' so parent config is not overwritten."""
    return param == "header" and isinstance(value, dict) and len(value) == 0


def _resolve_single_param(
    param: str,
    override: dict[str, Any],
    target_config: dict[str, Any],
    scope_config: dict[str, Any],
    org_config: dict[str, Any],
) -> Any:
    # 1. User override (empty dict for header does not override)
    if param in override and override[param] is not None and not _is_empty_dict_no_override(param, override[param]):
        return override[param]

    # 2. Target.scan_config
    if (
        param in target_config
        and target_config[param] is not None
        and not _is_empty_dict_no_override(param, target_config[param])
    ):
        return target_config[param]

    # 3. Scope.scan_config
    scope_val = scope_config.get(param)
    if scope_val is not None and not _is_empty_dict_no_override(param, scope_val):
        return scope_val

    # 4. Organization.scan_config
    org_val = org_config.get(param)
    if org_val is not None and not _is_empty_dict_no_override(param, org_val):
        return org_val

    # 5. Default
    return _get_default(param)


def _resolve_profiles(
    override: dict[str, Any],
    target_config: dict[str, Any],
    scope_config: dict[str, Any],
    org_config: dict[str, Any],
) -> list[str]:
    # 1. User override (list from parse_secator_profiles at scan launch)
    if override_profiles := _profiles_to_list(override.get("profiles")):
        return override_profiles

    # 2. Target.scan_config["profiles"] (dict per category)
    if target_profiles := _profiles_to_list(target_config.get("profiles")):
        return target_profiles

    # 3. Scope.scan_config["profiles"] (dict per category)
    if scope_profiles := _profiles_to_list(scope_config.get("profiles")):
        return scope_profiles

    # 4. Organization.scan_config["profiles"]
    if org_profiles := _profiles_to_list(org_config.get("profiles")):
        return org_profiles

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


def _scope_allow_local(scope: Any | None) -> bool:
    """Return True if Local is in the allowed list for the scope (backward compat: default True)."""
    if scope is None:
        return True
    return bool(getattr(scope, "allow_local_worker", True))


def scope_allow_local(scope: Any | None) -> bool:
    """Public helper: True if Local is in the scope's allowed workers (for templates/views)."""
    return _scope_allow_local(scope)


def get_allowed_workers_for_scope(scope: Any | None) -> list[tuple[Any, str]]:
    """
    Return the list of allowed options for the scope as (id_or_None, display_name).

    - If allow_local_worker: (None, "Local") is included.
    - Plus all active SecatorWorker in scope.workers, ordered by name, as (w.id, w.name).
    - If the list would be empty (no Local and no workers), returns [(None, "Local")] so
      scans can still run (exclusive Local fallback).
    """
    if scope is None:
        return [(None, "Local")]
    allow_local = _scope_allow_local(scope)
    remote = list(SecatorWorker.objects.active().filter(scopes=scope).order_by("name").values_list("id", "name"))
    options: list[tuple[Any, str]] = []
    if allow_local:
        options.append((None, "Local"))
    for wid, wname in remote:
        options.append((wid, wname or str(wid)))
    if not options:
        return [(None, "Local")]
    return options


def get_default_worker_for_scope(scope: Any | None) -> int | None:
    """
    Return the default worker for the scope: None (Local) or worker id (int).

    - No scope or allowed list empty -> None (Local).
    - One allowed option -> that one (None or worker id).
    - Two or more -> scope.default_worker_id if set and in allowed list, else None (Local).
    """
    if scope is None:
        return None
    options = get_allowed_workers_for_scope(scope)
    if not options:
        return None
    if len(options) == 1:
        return options[0][0]
    default_fk = getattr(scope, "default_worker", None)
    if default_fk is not None and default_fk.id is not None:
        for opt_id, _ in options:
            if opt_id is not None and opt_id == default_fk.id:
                return opt_id
    return None


def get_scope_worker_ids(scope: Any | None) -> list[int]:
    """
    Return active worker IDs allowed for the scope (public helper for validation).

    Use this when validating that a user-provided worker_id is allowed for the scope.
    Returns empty list if scope is None or scope has no workers.
    For "is Local allowed", use scope_allow_local_for_validation(scope) or
    get_scope_worker_validation(scope).
    """
    return _resolve_worker_ids(scope)


def get_scope_worker_validation(scope: Any | None) -> dict[str, Any]:
    """
    Return validation info for scope workers: allow_local (bool) and worker_ids (list[int]).

    Use when validating user-provided worker_id: allowed if (allow_local and worker_id empty)
    or (worker_id in worker_ids).
    """
    if scope is None:
        return {"allow_local": True, "worker_ids": []}
    return {
        "allow_local": _scope_allow_local(scope),
        "worker_ids": _resolve_worker_ids(scope),
    }


def resolve_worker_for_scope(
    scope: Any | None,
    requested_worker_id: int | None,
) -> int | None:
    """
    Resolve worker id for a scope: validate requested_worker_id against scope rules and
    fall back to the scope default when invalid or not provided.

    Used by the API and the form builder so worker selection logic stays in one place.
    Returns None for Local, or a valid worker id (int). When scope is None, returns
    requested_worker_id unchanged.
    """
    if scope is None:
        return requested_worker_id
    validation = get_scope_worker_validation(scope)
    allowed = (validation["allow_local"] and requested_worker_id is None) or (
        requested_worker_id is not None and requested_worker_id in validation["worker_ids"]
    )
    if not allowed or requested_worker_id is None:
        return get_default_worker_for_scope(scope)
    return requested_worker_id


def get_workers_for_scan_dropdown(
    scope: Any | None = None,
    allowed_worker_ids: list[int] | None = None,
    allow_local: bool | None = None,
) -> list[Any]:
    """
    Return the list of SecatorWorker instances to show in the "Run on worker" dropdown.

    - If scope is given: returns active workers linked to that scope, ordered by name.
      The template must show Local option when allow_local_worker is True (pass
      scope_allow_local(scope) and default_worker_id separately).
    - If allowed_worker_ids is given (e.g. scope add form): returns workers whose id
      is in that list, ordered by name. allow_local is independent (for scope add).
    - If neither scope nor allowed_worker_ids: returns all active workers (no scope).

    Deterministic order: order_by("name") for consistent UX.
    """
    if scope is not None:
        return list(SecatorWorker.objects.active().filter(scopes=scope).order_by("name"))
    if allowed_worker_ids is not None:
        if not allowed_worker_ids:
            return []
        return list(SecatorWorker.objects.active().filter(id__in=allowed_worker_ids).order_by("name"))
    return list(SecatorWorker.objects.active().order_by("name"))


def get_effective_worker_display(
    worker_id: int | str | None = None,
    scope: Any | None = None,
) -> dict[str, Any]:
    """
    Build the effective worker entry for the scan params effective display.

    Priority: explicit worker_id (scan override) > scope default worker > "Local".
    When no override is provided and scope is set, uses get_default_worker_for_scope(scope).
    Returns {"value": str, "source": "scan"|"scope"|"default"}.
    """
    if worker_id is not None:
        try:
            wid = int(worker_id)
            worker = SecatorWorker.objects.filter(id=wid).first()
            if worker:
                return {"value": worker.name, "source": "scan"}
        except (TypeError, ValueError):
            pass
    if scope is not None:
        default_id = get_default_worker_for_scope(scope)
        if default_id is not None:
            worker = SecatorWorker.objects.filter(id=default_id).first()
            if worker:
                return {"value": worker.name, "source": "scope"}
        if not _scope_allow_local(scope):
            options = get_allowed_workers_for_scope(scope)
            if options and options[0][0] is not None:
                first_worker = SecatorWorker.objects.filter(id=options[0][0]).first()
                if first_worker:
                    return {"value": first_worker.name, "source": "scope"}
        return {"value": "Local", "source": "scope"}
    return {"value": "Local", "source": "default"}


def _resolve_extra_config(
    override: dict[str, Any],
    target_config: dict[str, Any],
    scope_config: dict[str, Any],
    org_config: dict[str, Any],
) -> dict[str, Any]:
    base: dict[str, Any] = {}

    org_extra = org_config.get("extra_config")
    if isinstance(org_extra, dict):
        base.update(org_extra)

    scope_extra = scope_config.get("extra_config")
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
    - extra_config: merged (resolved keys take precedence over existing keys).
    - worker_ids are not written here; caller should put them on the kwargs root.
    """
    for key in PARAM_KEYS:
        value = resolved.get(key)
        if value is None:
            continue
        if key == "header" and isinstance(value, dict) and len(value) == 0:
            continue
        existing = secator_config.get(key)
        if existing is None or existing == "":
            secator_config[key] = value

    if resolved.get("profiles") and not secator_config.get("profiles"):
        secator_config["profiles"] = resolved["profiles"]

    extra = resolved.get("extra_config")
    if isinstance(extra, dict) and extra:
        existing_extra = secator_config.get("extra_config")
        if isinstance(existing_extra, dict):
            secator_config["extra_config"] = {**existing_extra, **extra}
        else:
            secator_config["extra_config"] = extra


def _prefixed(key: str, prefix: str) -> str:
    return f"{prefix}{key}"


def parse_scan_config_from_post(
    post: QueryDict,
    profiles_dict: dict[str, str] | None = None,
    existing_config: dict[str, Any] | None = None,
    prefix: str = TARGET_OVERRIDE_PREFIX,
) -> tuple[dict[str, Any], list[str]]:
    """
    Parse scan_config from a POST payload.

    Behaviour for empty / missing values:
    - Scalar fields (threads, rate_limit, etc.): missing POST key -> leave as-is
      (when existing_config is provided); present but value == '' -> clear override
      (key removed from result).
    - header: missing POST key -> leave as-is; present but value == ''
      -> explicitly clear (set to {}). parse_header_value returning
      (None, None) is treated as "no override" (key removed, not set to {}).
    - profiles: when profiles_dict is provided, result["profiles"] = profiles_dict
      (empty dict means clear). Caller builds profiles_dict from form (e.g.
      parse_secator_profiles_to_dict(post)).

    On header parse error, existing value is left unchanged and an error
    is appended. Returns the full config (result), not a delta.

    Returns:
        (config_dict, list of user-facing error messages)
    """
    result: dict[str, Any] = dict(_normalize_scan_config(existing_config)) if existing_config else {}
    errors: list[str] = []

    scalar_params = INT_PARAM_KEYS + STR_PARAM_KEYS + FLOAT_PARAM_KEYS + BOOL_PARAM_KEYS
    for param in scalar_params:
        key = _prefixed(param, prefix)
        if key not in post:
            continue
        raw = (post.get(key) or "").strip()
        if raw == "":
            result.pop(param, None)
            continue
        val = cast_param_value(param, raw)
        if val is not None:
            result[param] = val

    headers_key = _prefixed("header", prefix)
    if headers_key in post:
        raw_headers = (post.get(headers_key) or "").strip()
        if raw_headers == "":
            result["header"] = {}
        else:
            parsed, err = parse_header_value(raw_headers)
            if err:
                errors.append(err)
            elif parsed is not None:
                result["header"] = parsed
            else:
                result.pop("header", None)

    if profiles_dict is not None:
        result["profiles"] = profiles_dict

    return result, errors


def parse_target_scan_override_from_post(
    post: QueryDict,
    profiles_dict: dict[str, str] | None = None,
    existing_override: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Backward-compatible alias for parse_scan_config_from_post with default prefix."""
    return parse_scan_config_from_post(
        post,
        profiles_dict=profiles_dict,
        existing_config=existing_override,
        prefix=TARGET_OVERRIDE_PREFIX,
    )
