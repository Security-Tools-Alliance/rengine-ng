"""
Target update view helpers.

Processes scan override from POST and builds template context for the target update page,
so the view stays focused on HTTP flow.
"""

from __future__ import annotations

import json
from typing import Any

from django.http import QueryDict

from startScan.secator.form import parse_secator_profiles_to_dict
from startScan.secator.profiles import build_secator_profiles_context

from .scan_param_definitions import ORDERED_PARAM_KEYS_FOR_FORM, TARGET_OVERRIDE_PREFIX
from .scope_params import (
    build_effective_params_display,
    parse_target_scan_override_from_post,
)


def process_target_scan_override_from_post(
    post: QueryDict,
) -> tuple[dict[str, Any], list[str], dict[str, str] | None, str | None]:
    """
    Parse target scan override from POST and build fallback values when parsing fails.

    Returns:
        (scan_override, errors, override_form_fallback, override_request_headers_initial).
        override_form_fallback and override_request_headers_initial are non-None only when
        errors is non-empty (so the template can re-display POSTed values).
    """
    profiles_dict = parse_secator_profiles_to_dict(post)
    scan_override, errors = parse_target_scan_override_from_post(post, profiles_dict=profiles_dict)
    override_form_fallback = None
    override_request_headers_initial = None
    if errors:
        override_request_headers_initial = post.get(TARGET_OVERRIDE_PREFIX + "request_headers", "")
        override_form_fallback = {
            param: post.get(TARGET_OVERRIDE_PREFIX + param, "") for param in ORDERED_PARAM_KEYS_FOR_FORM
        }
    return (
        scan_override,
        errors,
        override_form_fallback,
        override_request_headers_initial,
    )


def build_update_target_context(
    target: Any,
    form: Any,
    override_form_fallback: dict[str, str] | None = None,
    override_request_headers_initial: str | None = None,
) -> dict[str, Any]:
    """
    Build the template context for the target update page.

    When override_request_headers_initial is None, it is derived from
    target.scan_config_override["request_headers"].
    """
    scopes = list(target.scopes.select_related("organization").all())
    first_scope = scopes[0] if scopes else None
    effective = build_effective_params_display(scope=first_scope, target=target)
    profiles_ctx = build_secator_profiles_context()
    target_profiles_dict = None
    if target.scan_config_override and isinstance(target.scan_config_override, dict):
        target_profiles_dict = target.scan_config_override.get("profiles")
    if target_profiles_dict and isinstance(target_profiles_dict, dict):
        profiles_ctx["default_profiles"] = target_profiles_dict

    if override_request_headers_initial is None:
        headers_val = (target.scan_config_override or {}).get("request_headers")
        override_request_headers_initial = json.dumps(headers_val) if isinstance(headers_val, dict) else ""

    context = {
        "list_target_li": "active",
        "target_data_active": "active",
        "target": target,
        "form": form,
        "target_scopes": scopes,
        "first_scope": first_scope,
        "effective_params": effective,
        "override_request_headers_initial": override_request_headers_initial,
        "override_form_fallback": override_form_fallback,
        "override_prefix": TARGET_OVERRIDE_PREFIX,
    }
    context.update(profiles_ctx)
    return context
