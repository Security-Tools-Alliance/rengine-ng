"""
Central definitions for scan parameter keys and type-casting rules.

SCAN CONFIG RESOLUTION — MODULE RESPONSIBILITIES AND DATA FLOW
==============================================================

  Precedence chain (highest to lowest): user override at scan launch → target.scan_config
  → scope.scan_config → organization.scan_config → settings defaults. Organization,
  Scope, and Target each have a single scan_config JSONField (same schema: PARAM_KEYS,
  profiles, extra_config). Only keys present at a lower level override the level above.

  scan_param_definitions (this module)
    - Defines PARAM_KEYS, type keys (INT_PARAM_KEYS, etc.), cast_param_value().
    - Defines parse_header_value() for consistent validation of
      header as a JSON object wherever scan_config is built from POST.
    - Single source of truth for param names and value types.

  targetApp.services.scope_params
    - resolve_scan_params(target, scope, organization, user_override): applies the
      precedence chain and returns effective dict (PARAM_KEYS + profiles, worker_ids,
      extra_config).
    - apply_resolved_to_secator_config(secator_config, resolved): merges resolved
      values into a Secator config (scalar params, profiles); worker_ids go to kwargs root.
      Single place for merge strategy when new params are added.
    - parse_scan_config_from_post(post, prefix, profiles_dict, existing_config):
      builds scan_config from POST for any form (org, scope, target); uses
      parse_header_value for the header key.
    - _normalize_scan_config(raw): ensures scan_config is a dict.
    - build_effective_params_display(scope, target, organization): for templates.

  startScan.secator.form
    - _parse_secator_user_override_from_post(post): builds user_override from
      scan launch POST (PARAM_KEYS + cast_param_value).
    - _get_target_and_scope_for_scope_merge(): resolves (target, scope) with
      same-project security check.
    - _merge_scope_params_into_config(): gets target/scope, builds user_override,
      calls resolve_scan_params then scope_params.apply_resolved_to_secator_config.
    - build_start_secator_scan_kwargs(post, target, scope): entry point for
      scan launch; calls _merge_scope_params_into_config.

  targetApp.services.target_update
    - process_target_scan_override_from_post(post): view helper for target update;
      calls parse_scan_config_from_post (via alias parse_target_scan_override_from_post)
      and builds fallback/context for the target update template.

Flow (scan launch):  POST → form.build_start_secator_scan_kwargs
  → _merge_scope_params_into_config → resolve_scan_params → apply_resolved_to_secator_config.
Flow (org/scope/target forms): POST → parse_scan_config_from_post (views call it with
  appropriate prefix and profiles_dict); header validated via parse_header_value.
"""

from __future__ import annotations

import json
from typing import Any

from reNgine.core.data import safe_bool_cast, safe_int_cast


PARAM_KEYS = frozenset(
    {
        "threads",
        "rate_limit",
        "timeout",
        "retries",
        "delay",
        "proxy",
        "user_agent",
        "header",
        "follow_redirect",
        "depth",
    }
)

INT_PARAM_KEYS = ("threads", "rate_limit", "timeout", "retries", "depth")
STR_PARAM_KEYS = ("proxy", "user_agent")
FLOAT_PARAM_KEYS = ("delay",)
BOOL_PARAM_KEYS = ("follow_redirect",)

# Order used by the target update form; form field names are TARGET_OVERRIDE_PREFIX + param.
ORDERED_PARAM_KEYS_FOR_FORM = (
    "threads",
    "rate_limit",
    "timeout",
    "retries",
    "delay",
    "depth",
    "follow_redirect",
    "proxy",
    "user_agent",
    "header",
)

TARGET_OVERRIDE_PREFIX = "override_"

# User-facing copy for header (Scope, Target, target update form, scope form).
HEADER_HELP_TEXT = 'Optional HTTP headers as a JSON object, e.g. {"X-Api-Key": "secret"}. Must be a valid JSON object.'
HEADER_ERROR_MUST_BE_OBJECT = 'Request headers must be a JSON object (e.g. {"X-Header": "value"}).'
HEADER_ERROR_INVALID_JSON = "Invalid JSON. Changes were not applied."


def parse_header_value(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """
    Parse and validate header from form/POST: must be a JSON object or empty.

    Used by parse_scan_config_from_post when building scan_config from POST so
    behavior and error messages stay consistent across org, scope, and target forms.

    Returns:
        (parsed_dict, None) on success (parsed_dict may be None for "clear").
        (None, error_message) when value is invalid JSON or not a JSON object.
    """
    if value is None or value == "":
        return (None, None)
    if isinstance(value, dict):
        return (value, None)
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return (None, None)
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return (None, HEADER_ERROR_INVALID_JSON)
        if not isinstance(parsed, dict):
            return (None, HEADER_ERROR_MUST_BE_OBJECT)
        return (parsed, None)
    return (None, HEADER_ERROR_MUST_BE_OBJECT)


def cast_param_value(key: str, raw: str | None) -> Any | None:
    """
    Cast a raw string from POST to the correct type for the given param key.

    Returns None for empty/invalid values. header is returned as-is
    (caller must parse JSON separately).
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    if isinstance(raw, str):
        raw = raw.strip()
    if key in INT_PARAM_KEYS:
        return safe_int_cast(raw)
    if key in FLOAT_PARAM_KEYS:
        try:
            return float(raw)
        except (ValueError, TypeError):
            return None
    if key in BOOL_PARAM_KEYS:
        return safe_bool_cast(raw)
    return raw if key in STR_PARAM_KEYS or key == "header" else None
