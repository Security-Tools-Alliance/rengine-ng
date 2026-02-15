"""
Parse and validate selected_targets / selected_targets_per_task request payloads.

Shared by API (JSON body) and form (QueryDict) so validation and error messages
are consistent.
"""

from __future__ import annotations

import json
from typing import Any, Literal, TypedDict

from reNgine.utilities.logger import get_module_logger


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
