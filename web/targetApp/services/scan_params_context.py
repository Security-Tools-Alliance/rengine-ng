"""
Centralized builder for scan params template context (effective, values, profiles).

Used by organization, scope, and target form views to avoid divergence in how
scan_params_effective, scan_params_values, and default_profiles are built.
"""

from __future__ import annotations

from typing import Any

from startScan.secator.profiles import build_secator_profiles_context

from .scan_param_definitions import ORDERED_PARAM_KEYS_FOR_FORM, header_dict_to_lines
from .scope_params import (
    PROFILE_CATEGORIES,
    build_effective_params_display,
    get_default_worker_for_scope,
    get_scope_for_target,
    scope_allow_local,
)


def build_scan_params_form_context(
    organization: Any = None,
    scope: Any = None,
    target: Any = None,
    scan_params_values: dict[str, Any] | None = None,
    level: str | None = None,
) -> dict[str, Any]:
    """
    Build the common scan-params block context for organization/scope/target forms.

    Returns a dict with scan_params_level, scan_params_effective, scan_params_values, and
    profile context (default_profiles, custom_profiles_by_category). When an entity is
    provided, default_profiles is taken from its scan_config.profiles.

    The level parameter overrides the deduced level ("organization"|"scope"|"target"). Use it
    on add-forms where no entity exists yet (e.g. target/add should pass level="target").
    """
    if organization is None and scope is None and target is None:
        effective = build_effective_params_display()
    else:
        if target is not None and scope is None and organization is None:
            scope = get_scope_for_target(target)
            organization = scope.organization if scope else None
        effective = build_effective_params_display(
            scope=scope,
            target=target,
            organization=organization,
        )
    if scan_params_values is not None:
        values = scan_params_values
    elif target is not None and getattr(target, "scan_config", None) and isinstance(target.scan_config, dict):
        values = dict(target.scan_config)
    elif scope is not None and getattr(scope, "scan_config", None):
        values = dict(scope.scan_config) if isinstance(scope.scan_config, dict) else {}
    elif organization is not None and getattr(organization, "scan_config", None):
        values = dict(organization.scan_config) if isinstance(organization.scan_config, dict) else {}
    else:
        values = {}

    profiles_ctx = build_secator_profiles_context()
    entity_config = None
    if target and getattr(target, "scan_config", None) and isinstance(target.scan_config, dict):
        entity_config = target.scan_config
    elif scope and getattr(scope, "scan_config", None) and isinstance(scope.scan_config, dict):
        entity_config = scope.scan_config
    elif organization and getattr(organization, "scan_config", None) and isinstance(organization.scan_config, dict):
        entity_config = organization.scan_config
    if entity_config:
        profiles = entity_config.get("profiles")
        if profiles and isinstance(profiles, dict):
            profiles_ctx["default_profiles"] = {cat: (profiles.get(cat) or "") for cat in PROFILE_CATEGORIES}

    values.setdefault("profiles", {})
    raw_profiles = values.get("profiles")
    values["profiles"] = {
        cat: ((raw_profiles.get(cat) if isinstance(raw_profiles, dict) else "") or "") for cat in PROFILE_CATEGORIES
    }
    entity_profile_categories = [cat for cat in PROFILE_CATEGORIES if values["profiles"].get(cat, "").strip()]
    header_val = values.get("header")
    if isinstance(header_val, dict):
        header_initial = header_dict_to_lines(header_val)
    else:
        header_initial = ""

    if level is None:
        level = "target" if target else ("scope" if scope else "organization")
    has_overrides = any(
        v is not None and v != "" for k, v in values.items() if k != "profiles" and not (isinstance(v, dict) and not v)
    ) or any(((values.get("profiles") or {}).get(c) or "").strip() for c in PROFILE_CATEGORIES)
    if level == "target":
        section_title = "Scan Parameter Overrides"
        section_help_text = "Leave fields empty to inherit from the scope (if any) or system defaults. Filled values override the scope for this target only."
    else:
        section_title = "Scan Parameters"
        section_help_text = (
            "Leave fields empty to inherit from the level above or system defaults. Filled values apply at this level."
        )

    scan_params_effective_ordered = [(p, effective[p]) for p in ORDERED_PARAM_KEYS_FOR_FORM if p in effective]
    result = {
        "scan_params_level": level,
        "scan_params_effective": effective,
        "scan_params_effective_ordered": scan_params_effective_ordered,
        "scan_params_values": values,
        "header_initial": header_initial,
        "entity_profile_categories": entity_profile_categories,
        "scan_params_section_title": section_title,
        "scan_params_section_help_text": section_help_text,
        "scan_params_section_use_collapse": True,
        "scan_params_section_collapse_expanded": has_overrides,
        "scan_params_section_configure_button_label": "Configured" if has_overrides else "Configure",
        **profiles_ctx,
    }
    effective_scope = scope if scope is not None else (get_scope_for_target(target) if target else None)
    if effective_scope is not None:
        result["scan_params_allow_local_worker"] = scope_allow_local(effective_scope)
        result["scan_params_default_worker_id"] = get_default_worker_for_scope(effective_scope)
    return result
