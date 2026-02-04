"""
WebSocket utility functions for sending scan status updates.
"""

from datetime import datetime
import logging
import re
from typing import Optional

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models import Case, Count, F, IntegerField, Prefetch, Value, When
from django.db.models.functions import Coalesce

from api.serializers import CommandSerializer, ScanActivitySerializer, SecatorRunnerSerializer
from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    RUNNING_BACKGROUND,
    RUNNING_TASK,
    SKIPPED_TASK,
    SUCCESS_TASK,
)
from startScan.models import (
    Command,
    EndPoint,
    ScanActivity,
    ScanHistory,
    SecatorRunner,
    Subdomain,
    SubScan,
    Vulnerability,
)


logger = logging.getLogger("websocket")

# Must match api.consumers.CHANNEL_NAME_PATTERN so group names align
_CHANNEL_NAME_PATTERN = re.compile(r"[^a-zA-Z0-9\-\.]")

# Vulnerability severity scale (aligned with startScan.models and vulnerability_repository)
SEVERITY_CRITICAL = 4
SEVERITY_HIGH = 3
SEVERITY_MEDIUM = 2
SEVERITY_LOW = 1
SEVERITY_INFO = 0
SEVERITY_UNKNOWN = -1

# Max items in WebSocket payload to bound DB load and message size
_MAX_RUNNING_COMMANDS = 30
_MAX_SUBSCANS = 30

try:
    from django.conf import settings

    _MAX_COMMANDS_LOGS = getattr(settings, "WEBSOCKET_MAX_COMMANDS_LOGS", 100)
except Exception:  # pragma: no cover - settings may not be available in some contexts
    _MAX_COMMANDS_LOGS = 100


def _clean_channel_name(name: str) -> str:
    """Sanitize name for use in channel group (alphanumeric, hyphen, period only)."""
    return _CHANNEL_NAME_PATTERN.sub("-", (name or "").strip())


def get_runner_status_code(runner: SecatorRunner) -> int:
    """Get reNgine status code from Secator runner."""
    from reNgine.secator import SecatorProgressSync

    if runner.runner_data:
        status = runner.runner_data.get("status", "PENDING")
        return SecatorProgressSync.map_secator_status_to_rengine(status)
    return 0  # INITIATED_TASK


def build_scan_status_message(scan_history_id: int) -> dict:
    """
    Build detailed scan status message for WebSocket.

    Args:
        scan_history_id: ID of the scan history

    Returns:
        dict: Detailed message with status, progress, runners, timeline, and findings counts
    """
    try:
        return _build_scan_status_payload(scan_history_id)
    except ScanHistory.DoesNotExist:
        logger.error(f"ScanHistory {scan_history_id} not found")
        return {}
    except Exception as e:
        logger.error(f"Error building scan status message for scan {scan_history_id}: {e}")
        return {}


def _build_scan_status_payload(scan_history_id: int) -> dict:
    """Assemble the full scan status payload (counts, severity, timeline, runners, commands, subscans)."""
    scan = ScanHistory.objects.get(id=scan_history_id)
    counts = _get_scan_counts(scan_history_id)
    severity_counts = _get_severity_counts(scan_history_id)

    message = _build_base_status_message(scan, scan_history_id, counts, severity_counts)

    if scan.is_legacy_scan:
        activities = ScanActivity.objects.filter(scan_of=scan).order_by("-time")[:10]
        message["timeline"] = ScanActivitySerializer(activities, many=True).data
        message["runners"] = []
    else:
        _add_secator_runners_to_message(scan, message)

    # Only include the most recent commands (bounded by _MAX_COMMANDS_LOGS) in the
    # WebSocket payload to keep bandwidth and UI work manageable for long scans.
    message["commands"] = _get_commands_payload(scan, limit=_MAX_COMMANDS_LOGS)
    timeline = message.get("timeline", [])
    _sort_timeline_by_priority(timeline)
    message["timeline"] = timeline
    runner_id_to_status = {item["id"]: item["status"] for item in timeline}
    runner_id_to_progress = {item["id"]: item.get("progress") for item in timeline}
    message["subscans"] = _build_subscans_payload(scan_history_id, runner_id_to_status, runner_id_to_progress)

    return message


def _timeline_status_order(status) -> int:
    """Priority for timeline sort: running first, then error, success, aborted, skipped, other (0=top)."""
    if status in (RUNNING_TASK, RUNNING_BACKGROUND):
        return 0
    if status == FAILED_TASK:
        return 1
    if status == SUCCESS_TASK:
        return 2
    if status == ABORTED_TASK:
        return 3
    if status == SKIPPED_TASK:
        return 4
    return 5  # INITIATED_TASK, other


def _parse_timeline_time(value) -> float:
    """Parse timeline item time to timestamp for sorting; return 0 if missing/invalid."""
    if not value:
        return 0.0
    try:
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        return getattr(value, "timestamp", lambda: 0)()
    except (ValueError, TypeError):
        return 0.0


def _timeline_hierarchy_order(runner_type: str | None) -> int:
    """Order by hierarchy: scan (0), workflow (1), task (2), other (3)."""
    if not runner_type:
        return 3
    t = runner_type.lower()
    if t == "scan":
        return 0
    if t == "workflow":
        return 1
    if t == "task":
        return 2
    return 3


def _sort_timeline_by_priority(timeline: list) -> None:
    """Sort timeline in place: status, then hierarchy (scan > workflow > task), then most recent first."""
    timeline.sort(
        key=lambda i: (
            _timeline_status_order(i.get("status")),
            _timeline_hierarchy_order(i.get("type")),
            -_parse_timeline_time(i.get("time")),
        )
    )


def _add_secator_runners_to_message(scan: ScanHistory, message: dict) -> None:
    """Populate message with Secator runners (timeline) for non-legacy scans."""
    runners = (
        SecatorRunner.objects.filter(scan_history=scan)
        .order_by("-created_at")
        .prefetch_related(
            Prefetch(
                "scanactivity_set",
                queryset=ScanActivity.objects.order_by("time"),
            )
        )
    )
    serializer = SecatorRunnerSerializer(runners, many=True)
    message["runners"] = serializer.data

    timeline_items = []
    for runner in runners:
        first_activity = next(iter(runner.scanactivity_set.all()), None)
        activity_id = first_activity.id if first_activity else None
        progress = None
        if runner.runner_data and isinstance(runner.runner_data, dict):
            progress = runner.runner_data.get("progress")

        timeline_items.append(
            {
                "id": runner.id,
                "title": f"{runner.runner_type.title()}: {runner.runner_name}",
                "name": runner.runner_name or "",
                "status": get_runner_status_code(runner),
                "time": runner.created_at.isoformat() if runner.created_at else None,
                "type": runner.runner_type,
                "activity_id": activity_id,
                "progress": progress,
            }
        )
    message["timeline"] = timeline_items


def _get_scan_counts(scan_history_id: int) -> dict:
    """Return subdomain, endpoint and vulnerability counts for a scan in one pass."""
    subdomain_count = Subdomain.objects.filter(scan_history__id=scan_history_id).count()
    alive_count = Subdomain.objects.filter(scan_history__id=scan_history_id, http_status__gt=0).count()
    endpoint_count = EndPoint.objects.filter(scan_history__id=scan_history_id).count()
    endpoint_alive_count = EndPoint.objects.filter(scan_history__id=scan_history_id, http_status__gt=0).count()
    vulnerability_count = Vulnerability.objects.filter(scan_history__id=scan_history_id).count()
    return {
        "subdomain_count": subdomain_count,
        "alive_count": alive_count,
        "endpoint_count": endpoint_count,
        "endpoint_alive_count": endpoint_alive_count,
        "vulnerability_count": vulnerability_count,
    }


def _get_severity_counts(scan_history_id: int) -> dict:
    """Return vulnerability counts by severity (critical, high, medium, low, info, unknown)."""
    vuln_severity_counts = (
        Vulnerability.objects.filter(scan_history__id=scan_history_id).values("severity").annotate(count=Count("id"))
    )
    severity_map = {item["severity"]: item["count"] for item in vuln_severity_counts}
    return {
        "critical_count": severity_map.get(SEVERITY_CRITICAL, 0),
        "high_count": severity_map.get(SEVERITY_HIGH, 0),
        "medium_count": severity_map.get(SEVERITY_MEDIUM, 0),
        "low_count": severity_map.get(SEVERITY_LOW, 0),
        "info_count": severity_map.get(SEVERITY_INFO, 0),
        "unknown_count": severity_map.get(SEVERITY_UNKNOWN, 0),
    }


def _build_base_status_message(
    scan: ScanHistory,
    scan_history_id: int,
    counts: dict,
    severity_counts: dict,
) -> dict:
    """Build the base scan status message with counts and severity."""
    return {
        "type": "scan_status_update",
        "scan_id": scan_history_id,
        "scan_type": "legacy" if scan.is_legacy_scan else "secator",
        "scan_name": f"{scan.display_runner_type}: {scan.display_scan_name}",
        "status": scan.scan_status,
        "progress": scan.get_progress(),
        "current_task": scan.get_current_task(),
        "subdomain_count": counts["subdomain_count"],
        "endpoint_count": counts["endpoint_count"],
        "vulnerability_count": counts["vulnerability_count"],
        "alive_count": counts["alive_count"],
        "endpoint_alive_count": counts["endpoint_alive_count"],
        **severity_counts,
    }


def _get_commands_payload(scan: ScanHistory, *, limit: Optional[int] = None) -> list:
    """Return serialized commands for the scan (up to limit), same order as scan_logs_view.
    UIs must not assume only running commands are sent; all commands up to limit are included.
    """
    if limit is None:
        limit = _MAX_COMMANDS_LOGS
    type_order_case = Case(
        When(runner_type="scan", then=Value(0)),
        When(runner_type="workflow", then=Value(1)),
        When(runner_type="task", then=Value(2)),
        default=Value(3),
        output_field=IntegerField(),
    )
    queryset = (
        Command.objects.filter(scan_history=scan)
        .select_related("activity")
        .annotate(
            type_order=type_order_case,
            group_key=Coalesce(
                F("ancestor_id"),
                F("workflow_name"),
                F("name"),
                Value(""),
            ),
        )
        .order_by("type_order", "group_key", "time", "id")[:limit]
    )
    return CommandSerializer(list(queryset), many=True).data


def _build_subscan_item(
    subscan: SubScan,
    runner_id_to_status: dict,
    runner_id_to_progress: dict,
) -> dict:
    """Build a single subscan payload entry."""
    task_name = subscan.type or subscan.get_task_name_str()
    if subscan.secator_runner:
        if subscan.secator_runner.runner_name:
            task_name = subscan.secator_runner.runner_name
        status = runner_id_to_status.get(subscan.secator_runner_id, get_runner_status_code(subscan.secator_runner))
        progress = runner_id_to_progress.get(subscan.secator_runner_id)
        if progress is None and subscan.secator_runner.runner_data:
            progress = subscan.secator_runner.runner_data.get("progress")
    else:
        status = subscan.status
        progress = None
    return {
        "subscan_id": subscan.id,
        "status": status,
        "progress": progress,
        "task_name": task_name,
        "scan_engine_used": subscan.scan_engine_used,
    }


def _build_subscans_payload(
    scan_history_id: int,
    runner_id_to_status: dict,
    runner_id_to_progress: dict,
) -> list:
    """Build list of subscan payloads for the scan (most recent up to _MAX_SUBSCANS)."""
    subscans_qs = (
        SubScan.objects.filter(scan_history_id=scan_history_id)
        .select_related("secator_runner", "engine")
        .order_by("-start_scan_date")[:_MAX_SUBSCANS]
    )
    return [_build_subscan_item(subscan, runner_id_to_status, runner_id_to_progress) for subscan in subscans_qs]


def send_scan_status_update(scan_history_id: int, scan_status=None, progress=None, current_task=None):
    """
    Send detailed scan status update via WebSocket.

    Args:
        scan_history_id: ID of the scan history
        scan_status: Optional status to override
        progress: Optional progress to override
        current_task: Optional current task to override

    Raises:
        ScanHistory.DoesNotExist: If the scan history is not found.
        Exception: Re-raised after logging on channel/DB/serialization failures so callers can handle.
    """
    try:
        scan = ScanHistory.objects.get(id=scan_history_id)
        channel_layer = get_channel_layer()
        if not channel_layer:
            logger.debug(f"No channel layer available, skipping WebSocket update for scan {scan_history_id}")
            return

        # Build detailed message
        message = build_scan_status_message(scan_history_id)

        if not message:
            logger.warning(f"Empty message for scan {scan_history_id}, skipping WebSocket update")
            return

        # Override with provided values if any
        if scan_status is not None:
            message["status"] = scan_status
        if progress is not None:
            message["progress"] = progress
        if current_task is not None:
            message["current_task"] = current_task

        logger.debug(
            "Sending WebSocket update for scan %s - status: %s, progress: %s, current_task: %s",
            scan_history_id,
            message.get("status"),
            message.get("progress"),
            message.get("current_task"),
        )

        # Send to scan-specific group
        scan_group = f"scan-status-{scan_history_id}"
        async_to_sync(channel_layer.group_send)(
            scan_group,
            {"type": "scan_status_update", "message": message},
        )
        logger.debug("Sent WebSocket update to scan-specific group: %s", scan_group)

        # Send to project-level group (slug cleaned to match consumer)
        if scan.domain and scan.domain.project:
            project_group = f"scan-status-project-{_clean_channel_name(scan.domain.project.slug)}"
            async_to_sync(channel_layer.group_send)(
                project_group,
                {"type": "scan_status_update", "message": message},
            )
            logger.debug(f"Sent WebSocket update to project-level group: {project_group}")

        logger.debug(f"Successfully sent WebSocket update for scan {scan_history_id}")

    except ScanHistory.DoesNotExist:
        logger.error(f"ScanHistory {scan_history_id} not found for WebSocket update")
        raise
    except Exception as e:
        logger.error(f"Error sending WebSocket update for scan {scan_history_id}: {e}", exc_info=True)
        raise
