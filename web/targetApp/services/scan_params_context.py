"""
Centralized builder for scan params template context (effective, values, profiles).

Used by organization, scope, and target form views to avoid divergence in how
scan_params_effective, scan_params_values, and default_profiles are built.
"""

from __future__ import annotations

from typing import Any

from startScan.secator.profiles import build_secator_profiles_context

from .scope_params import build_effective_params_display


def build_scan_params_form_context(
    organization: Any = None,
    scope: Any = None,
    target: Any = None,
    scan_params_values: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build the common scan-params block context for organization/scope/target forms.

    Returns a dict with scan_params_effective, scan_params_values, and profile
    context (default_profiles, custom_profiles_by_category). When an entity is
    provided, default_profiles is taken from its scan_config.profiles.
    """
    if organization is None and scope is None and target is None:
        effective = None
    else:
        if target is not None and scope is None and organization is None:
            first_scope = next(
                iter(target.scopes.select_related("organization").all()),
                None,
            )
            scope = first_scope
            organization = first_scope.organization if first_scope else None
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
            profiles_ctx["default_profiles"] = profiles

    values.setdefault("profiles", {})
    return {
        "scan_params_effective": effective,
        "scan_params_values": values,
        **profiles_ctx,
    }
