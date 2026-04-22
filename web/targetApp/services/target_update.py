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

from .scan_param_definitions import (
    ORDERED_PARAM_KEYS_FOR_FORM,
    TARGET_OVERRIDE_PREFIX,
    header_dict_to_lines,
)
from .scan_params_context import build_scan_params_form_context
from .scope_params import parse_target_scan_override_from_post


def process_target_scan_override_from_post(
    post: QueryDict,
) -> tuple[dict[str, Any], list[str], dict[str, str] | None, str | None]:
    """
    Parse target scan override from POST and build fallback values when parsing fails.

    Returns:
        (scan_override, errors, override_form_fallback, override_header_initial).
        override_form_fallback and override_header_initial are non-None only when
        errors is non-empty (so the template can re-display POSTed values).
    """
    profiles_dict = parse_secator_profiles_to_dict(post)
    scan_override, errors = parse_target_scan_override_from_post(post, profiles_dict=profiles_dict)
    override_form_fallback = None
    override_header_initial = None
    if errors:
        override_header_initial = post.get(TARGET_OVERRIDE_PREFIX + "header", "")
        override_form_fallback = {
            param: post.get(TARGET_OVERRIDE_PREFIX + param, "") for param in ORDERED_PARAM_KEYS_FOR_FORM
        }
    return (
        scan_override,
        errors,
        override_form_fallback,
        override_header_initial,
    )


def build_update_target_context(
    target: Any,
    form: Any,
    override_form_fallback: dict[str, str] | None = None,
    override_header_initial: str | None = None,
    scan_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build the template context for the target update page.

    When scan_override is provided (POST error case), it is used as scan_params_values
    so the shared block re-displays the user's entered values with proper types.
    Otherwise scan_params_values is derived from target.scan_config.
    """
    scopes = list(target.scopes.select_related("organization").all())
    first_scope = scopes[0] if scopes else None

    if scan_override is not None:
        scan_params_values = dict(scan_override)
    else:
        scan_params_values = (
            dict(target.scan_config) if target.scan_config and isinstance(target.scan_config, dict) else {}
        )

    header_val = scan_params_values.get("header") if isinstance(scan_params_values, dict) else None
    if isinstance(header_val, str):
        try:
            parsed = json.loads(header_val)
            header_val = parsed if isinstance(parsed, dict) else None
        except (TypeError, ValueError):
            header_val = None
    if not isinstance(header_val, dict):
        header_val = None
    if header_val is not None:
        scan_params_values["header"] = header_val
    scan_params_values.setdefault("profiles", {})

    if override_header_initial is not None:
        if isinstance(override_header_initial, dict):
            header_initial = json.dumps(override_header_initial)
        else:
            header_initial = override_header_initial
    elif header_val is None or (isinstance(header_val, dict) and len(header_val) == 0):
        header_initial = ""
    else:
        header_initial = header_dict_to_lines(header_val)

    form_ctx = build_scan_params_form_context(target=target, scan_params_values=scan_params_values)
    context = {
        "list_target_li": "active",
        "target_data_active": "active",
        "target": target,
        "form": form,
        "target_scopes": scopes,
        "first_scope": first_scope,
        "override_header_initial": override_header_initial,
        "override_form_fallback": override_form_fallback,
        "override_prefix": TARGET_OVERRIDE_PREFIX,
    }
    context.update(form_ctx)
    context["header_initial"] = header_initial
    if context.get("override_header_initial") is None:
        context["override_header_initial"] = header_initial
    return context
