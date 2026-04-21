"""
Helpers for PostScanParamsEffectivePreview: resolve (org_config, scope_config, target_config, user_override) per level.
"""

from __future__ import annotations

from typing import Any

from targetApp.models import Organization, Scope, Target
from targetApp.services.scope_params import get_scope_for_target


class ScanParamsPreviewError(ValueError):
    """
    Exception type for controlled, user-facing errors in scan params preview.
    Raise this from preview helper functions when the message may be shown to the user.
    """


def _merge_draft_into_config(config: dict[str, Any], draft: dict[str, Any]) -> None:
    """
    Merge draft key/values into config.

    Keys in draft with value None leave config unchanged (no-op).
    Empty string clears the key. Other values set the key.
    Keys absent from draft leave config unchanged.
    """
    for k, v in draft.items():
        if v is None:
            continue
        if v == "":
            config.pop(k, None)
        else:
            config[k] = v


def _preview_config_organization(
    draft: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Organization level: draft is the only config (org_config)."""
    return (draft, None, None, None)


def _preview_config_scope(
    data: dict[str, Any],
    draft: dict[str, Any],
    normalize_scan_config: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Scope level: load org and scope, merge draft into scope_config."""
    project_slug = (data.get("project_slug") or "").strip()
    if not project_slug:
        raise ScanParamsPreviewError("Project required.")
    organization_id = data.get("organization_id")
    scope_id = data.get("scope_id")
    try:
        organization = Organization.objects.get(id=organization_id, project__slug=project_slug)
    except (Organization.DoesNotExist, TypeError, ValueError):
        organization = None
    org_config = normalize_scan_config(getattr(organization, "scan_config", None) if organization else None)
    scope_config_merged = {}
    if scope_id:
        try:
            scope = Scope.objects.get(id=scope_id, organization__project__slug=project_slug)
            scope_config_merged = normalize_scan_config(getattr(scope, "scan_config", None))
        except (Scope.DoesNotExist, TypeError, ValueError):
            pass
    _merge_draft_into_config(scope_config_merged, draft)
    return (org_config, scope_config_merged, None, None)


def _preview_config_target(
    data: dict[str, Any],
    draft: dict[str, Any],
    normalize_scan_config: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Target level: load target -> scope -> org, merge draft into target_config."""
    project_slug = (data.get("project_slug") or "").strip()
    if not project_slug:
        raise ScanParamsPreviewError("Project required.")
    target_id = data.get("target_id")
    target = None
    if target_id:
        try:
            target = Target.objects.get(id=int(target_id), project__slug=project_slug)
        except (Target.DoesNotExist, TypeError, ValueError):
            pass
    scope = None
    organization = None
    if target:
        scope = get_scope_for_target(target)
        organization = scope.organization if scope else None
    org_config = normalize_scan_config(getattr(organization, "scan_config", None) if organization else None)
    scope_config = normalize_scan_config(getattr(scope, "scan_config", None) if scope else None)
    target_config_merged = normalize_scan_config(getattr(target, "scan_config", None) if target else None)
    _merge_draft_into_config(target_config_merged, draft)
    return (org_config, scope_config, target_config_merged, None)


def _preview_config_scan(
    data: dict[str, Any],
    draft: dict[str, Any],
    normalize_scan_config: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Scan level: load target/org, user_override = draft."""
    project_slug = (data.get("project_slug") or "").strip()
    if not project_slug:
        raise ScanParamsPreviewError("Project required.")
    target_id = data.get("target_id")
    organization_id = data.get("organization_id")
    target = None
    scope = None
    organization = None
    if target_id:
        try:
            target = Target.objects.get(id=int(target_id), project__slug=project_slug)
        except (Target.DoesNotExist, TypeError, ValueError):
            pass
        if target:
            scope = get_scope_for_target(target)
            organization = scope.organization if scope else None
    if organization is None and organization_id:
        try:
            organization = Organization.objects.get(id=organization_id, project__slug=project_slug)
        except (Organization.DoesNotExist, TypeError, ValueError):
            pass
    org_config = normalize_scan_config(getattr(organization, "scan_config", None) if organization else None)
    scope_config = normalize_scan_config(getattr(scope, "scan_config", None) if scope else None)
    target_config = normalize_scan_config(getattr(target, "scan_config", None) if target else None)
    user_override = {k: v for k, v in draft.items() if v is not None and v != ""}
    return (org_config, scope_config, target_config, user_override)
