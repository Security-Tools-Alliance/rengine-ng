"""
Parse and validate selected_targets / selected_targets_per_task request payloads.

Shared by API (JSON body) and form (QueryDict) so validation and error messages
are consistent.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Literal, TypedDict

from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import get_subdomain_from_url


PREFIX_SELECTED_TARGETS = "[SECATOR_SELECTED_TARGETS]"
logger = get_module_logger(__name__)


class ResolvedTargets(TypedDict, total=False):
    """Resolved targets after parsing and precedence. Either single or per_task is set."""

    use_per_task: bool
    targets_override: list[str] | None
    selected_targets_per_task: dict[str, list[str]]


class PerTaskValidationError(TypedDict):
    """Validation error for one task in per_task mode."""

    task_type: str
    reason: Literal["unknown_task_type", "no_targets"]
    detail: str


def _normalize_target_list(items: Any) -> list[str]:
    """Convert iterable to list of non-empty stripped strings."""
    if items is None:
        return []
    result: list[str] = []
    for t in items:
        if t is None:
            continue
        if stripped := str(t).strip():
            result.append(stripped)
    return result


def parse_selected_targets(
    value: Any,
    field_name: str = "selected_targets",
) -> list[str]:
    """
    Parse and validate selected_targets (list of target strings).

    Accepts raw Python list or JSON-encoded string. Returns normalized list
    (stripped, non-empty). Empty/None returns []. Raises ValueError with
    unified message on parse or type error.
    """
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return _normalize_target_list(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.log_line(
                PREFIX_SELECTED_TARGETS,
                "PARSE",
                "Failed to decode %s JSON: %r" % (field_name, value),
                level="warning",
                exc_info=True,
            )
            raise ValueError(f"Invalid JSON in {field_name}. Please refresh and try again.") from exc
        if not isinstance(parsed, list):
            raise ValueError(f"{field_name} must be a JSON array. Please refresh and try again.")
        return _normalize_target_list(parsed)
    raise ValueError(f"{field_name} must be a JSON array. Please refresh and try again.")


def parse_selected_targets_per_task(
    value: Any,
    field_name: str = "selected_targets_per_task",
) -> dict[str, list[str]]:
    """
    Parse and validate selected_targets_per_task (task_type -> list of targets).

    Accepts raw Python dict or JSON-encoded string. Returns normalized dict:
    keys str, values list of stripped non-empty strings. Empty/None returns {}.
    Raises ValueError with unified message on parse or type error.
    """
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        return {str(k): lst for k, v in value.items() if v is not None and (lst := _normalize_target_list(v))}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.log_line(
                PREFIX_SELECTED_TARGETS,
                "PARSE",
                "Failed to decode %s JSON: %r" % (field_name, value),
                level="warning",
                exc_info=True,
            )
            raise ValueError(f"Invalid JSON in {field_name}. Please refresh and try again.") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"{field_name} must be a JSON object. Please refresh and try again.")
        return {str(k): lst for k, v in parsed.items() if v is not None and (lst := _normalize_target_list(v))}
    raise ValueError(f"{field_name} must be a JSON object. Please refresh and try again.")


def resolve_selected_targets(
    raw_selected_targets: Any,
    raw_selected_targets_per_task: Any,
    execution_mode: str | None,
) -> ResolvedTargets:
    """
    Parse raw selected_targets and selected_targets_per_task and apply precedence.

    High-level: Secator supports two execution modes. Single mode uses one scan with
    targets from selected_targets (targets_override). Per-task mode (execution_mode == "tasks"
    and selected_targets_per_task non-empty) runs one scan per task type with that task's
    targets; selected_targets is ignored. This function decides which mode applies and
    returns the corresponding ResolvedTargets.

    Precedence: if execution_mode == "tasks" and selected_targets_per_task is non-empty,
    use per_task mode (selected_targets ignored). Otherwise use single mode with
    targets_override from selected_targets (empty list becomes None for service).

    Returns a ResolvedTargets dict with use_per_task, targets_override (single mode),
    and selected_targets_per_task (per_task mode, empty dict in single mode).
    """
    selected_targets = parse_selected_targets(raw_selected_targets)
    selected_targets_per_task = parse_selected_targets_per_task(raw_selected_targets_per_task)

    use_per_task = execution_mode == "tasks" and bool(selected_targets_per_task)
    if use_per_task:
        return ResolvedTargets(
            use_per_task=True,
            targets_override=None,
            selected_targets_per_task=selected_targets_per_task,
        )
    targets_override = selected_targets or None
    return ResolvedTargets(
        use_per_task=False,
        targets_override=targets_override,
        selected_targets_per_task={},
    )


def validate_per_task_targets(
    selected_targets_per_task: dict[str, list[str]],
    task_type_to_id: dict[str, int],
) -> list[PerTaskValidationError]:
    """
    Validate per_task targets: unknown task_type and empty targets.

    Returns a list of validation errors (unknown_task_type, no_targets) that
    API and form views can use to build error responses or skip invalid entries.
    """
    errors: list[PerTaskValidationError] = []
    for task_type, targets in selected_targets_per_task.items():
        if task_type not in task_type_to_id:
            errors.append(
                PerTaskValidationError(
                    task_type=task_type,
                    reason="unknown_task_type",
                    detail=f"No active SecatorTask found for task_type='{task_type}'",
                )
            )
            continue
        if not targets:
            errors.append(
                PerTaskValidationError(
                    task_type=task_type,
                    reason="no_targets",
                    detail="No non-empty targets provided for this task",
                )
            )
    return errors


def _is_cidr(s: str) -> bool:
    """Return True if the string is a valid CIDR range (IPv4 or IPv6)."""
    if not s or not isinstance(s, str):
        return False
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return True
    except ValueError:
        return False


def _match_key_for_target_string(raw: str) -> str | None:
    """
    Return a normalized key for belonging comparison.

    For CIDR strings, returns the string as-is (strip) so that exact match works.
    For other strings, returns the host from get_subdomain_from_url (lowercased).
    Returns None on parse error or empty result.
    """
    if raw is None or not str(raw).strip():
        return None
    s = str(raw).strip()
    if _is_cidr(s):
        return s
    try:
        host = get_subdomain_from_url(s).strip().lower()
        return host if host else None
    except Exception:
        return None


def _target_string_belongs_to_value(host: str, target_value_lower: str) -> bool:
    """True if host equals target_value or is a subdomain of it (domain case)."""
    if host == target_value_lower:
        return True
    if "." in target_value_lower and host.endswith("." + target_value_lower):
        return True
    return False


def filter_targets_by_target_value(
    target_value: str,
    targets_list: list[str] | None,
) -> list[str] | None:
    """
    Keep only target strings whose extracted host (or exact value for CIDR) belongs to the given target value.

    Used when launching multiple scans (target list, scope, org): each scan must
    receive only proposed targets that belong to that scan's target (same apex or
    subdomain for domains; exact match for CIDR). Invalid or unparseable strings
    are excluded silently.

    Returns None if targets_list is None/empty or if the filtered list is empty.
    """
    if not targets_list:
        return None
    target_value_stripped = target_value.strip()
    if not target_value_stripped:
        return None
    target_value_lower = target_value_stripped.lower()
    target_is_cidr = _is_cidr(target_value_stripped)
    result: list[str] = []
    for raw in targets_list:
        if raw is None or not str(raw).strip():
            continue
        key = _match_key_for_target_string(str(raw).strip())
        if key is None:
            continue
        if target_is_cidr:
            if key == target_value_stripped:
                result.append(str(raw).strip())
        else:
            if _target_string_belongs_to_value(key, target_value_lower):
                result.append(str(raw).strip())
    return result if result else None


def filter_targets_override_for_target(
    target_value: str,
    targets_override: list[str] | None,
) -> list[str] | None:
    """Filter targets_override to only entries belonging to the given target value."""
    return filter_targets_by_target_value(target_value, targets_override)


def filter_selected_targets_per_task_for_target(
    target_value: str,
    selected_targets_per_task: dict[str, list[str]] | None,
) -> dict[str, list[str]] | None:
    """
    Filter each task's target list to only entries belonging to the given target value.

    Task types that end up with no targets after filtering are omitted.
    Returns None if the input is empty or the resulting dict is empty.
    """
    if not selected_targets_per_task:
        return None
    out: dict[str, list[str]] = {}
    for task_type, list_str in selected_targets_per_task.items():
        if not list_str:
            continue
        filtered = filter_targets_by_target_value(target_value, list_str)
        if filtered:
            out[task_type] = filtered
    return out if out else None
