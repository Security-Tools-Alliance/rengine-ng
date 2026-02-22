"""
Central definitions for scan parameter keys and type-casting rules.

SCOPE/TARGET PARAMETER RESOLUTION — MODULE RESPONSIBILITIES AND DATA FLOW
==========================================================================

  scan_param_definitions (this module)
    - Defines PARAM_KEYS, type keys (INT_PARAM_KEYS, etc.), cast_param_value().
    - Defines request_headers user copy and parse_request_headers_value() for
      consistent validation of JSON-object headers everywhere.
    - Single source of truth for param names and value types.

  targetApp.services.scope_params
    - resolve_scan_params(target, scope, user_override): priority chain
      (user override → target.scan_config_override → target.request_headers →
      scope fields → settings defaults). Returns dict with PARAM_KEYS + profiles,
      worker_ids, extra_config.
    - apply_resolved_to_secator_config(secator_config, resolved): merges resolved
      values into a Secator config (scalar params, profiles); worker_ids go to kwargs root.
      Single place for merge strategy when new params are added.
    - parse_target_scan_override_from_post(post): builds target scan_config_override
      from target update form POST; uses parse_request_headers_value for headers.
    - _normalize_scan_config_override(raw): ensures scan_config_override is a dict.
    - build_effective_params_display(scope, target): for scope detail template.

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
    - process_target_scan_override_from_post(post): view helper; calls
      parse_target_scan_override_from_post and builds fallback/context for
      target update template.

  targetApp.forms (ScopeForm)
    - clean_request_headers(): uses parse_request_headers_value() so Scope
      request_headers matches the same JSON-object contract and error messages.

Flow (scan launch):  POST → form.build_start_secator_scan_kwargs
  → _merge_scope_params_into_config → resolve_scan_params → apply_resolved_to_secator_config.
Flow (target update): POST → target_update.process_target_scan_override_from_post
  → parse_target_scan_override_from_post (uses parse_request_headers_value).
Flow (scope form):    POST → ScopeForm.clean_request_headers
  → parse_request_headers_value.
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
        "request_headers",
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
    "request_headers",
)

TARGET_OVERRIDE_PREFIX = "override_"

# User-facing copy for request_headers (Scope, Target, target update form, scope form).
REQUEST_HEADERS_HELP_TEXT = (
    "Optional HTTP headers as a JSON object, e.g. {\"X-Api-Key\": \"secret\"}. Must be a valid JSON object."
)
REQUEST_HEADERS_ERROR_MUST_BE_OBJECT = (
    'Request headers must be a JSON object (e.g. {"X-Header": "value"}).'
)
REQUEST_HEADERS_ERROR_INVALID_JSON = "Invalid JSON. Changes were not applied."


def parse_request_headers_value(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """
    Parse and validate request_headers from form/POST: must be a JSON object or empty.

    Used by ScopeForm.clean_request_headers and parse_target_scan_override_from_post
    so behavior and error messages stay consistent.

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
            return (None, REQUEST_HEADERS_ERROR_INVALID_JSON)
        if not isinstance(parsed, dict):
            return (None, REQUEST_HEADERS_ERROR_MUST_BE_OBJECT)
        return (parsed, None)
    return (None, REQUEST_HEADERS_ERROR_MUST_BE_OBJECT)


def cast_param_value(key: str, raw: str | None) -> Any | None:
    """
    Cast a raw string from POST to the correct type for the given param key.

    Returns None for empty/invalid values. request_headers is returned as-is
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
    return raw if key in STR_PARAM_KEYS or key == "request_headers" else None
