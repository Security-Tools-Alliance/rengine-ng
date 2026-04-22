"""
WebSocket utility functions for sending scan status updates.
"""

from datetime import datetime
import re
import time
from typing import Any, Optional

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Case, Count, F, IntegerField, Prefetch, Value, When


try:
    from redis.exceptions import (
        BusyLoadingError,
    )
    from redis.exceptions import (
        ConnectionError as RedisConnectionError,
    )
    from redis.exceptions import (
        TimeoutError as RedisTimeoutError,
    )

    _REDIS_RETRY_EXCEPTIONS = (BusyLoadingError, RedisConnectionError, RedisTimeoutError)
except ImportError:
    BusyLoadingError = None
    RedisConnectionError = None
    RedisTimeoutError = None
    _REDIS_RETRY_EXCEPTIONS = ()
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
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.worker_ws_groups import worker_deploy_group, worker_refresh_group
from startScan.models import (
    Command,
    ScanActivity,
    ScanHistory,
    SecatorRunner,
    SubScan,
    Vulnerability,
)


PREFIX_WS = "[WS]"
logger = get_module_logger(__name__)

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
    _MAX_COMMANDS_LOGS = getattr(settings, "WEBSOCKET_MAX_COMMANDS_LOGS", 100)
    _THROTTLE_SECONDS = getattr(settings, "WEBSOCKET_SCAN_STATUS_THROTTLE_SECONDS", 2)
    _FULL_INTERVAL_SECONDS = getattr(settings, "WEBSOCKET_SCAN_STATUS_FULL_INTERVAL_SECONDS", 15)
except ImproperlyConfigured:  # pragma: no cover - Django settings not ready in some contexts
    _MAX_COMMANDS_LOGS = 100
    _THROTTLE_SECONDS = 2
    _FULL_INTERVAL_SECONDS = 15


def _clean_channel_name(name: str) -> str:
    """Sanitize name for use in channel group (alphanumeric, hyphen, period only)."""
    return _CHANNEL_NAME_PATTERN.sub("-", (name or "").strip())


def _scan_ws_last_sent_key(scan_id: int) -> str:
    """Cache key for last WebSocket send timestamp per scan (throttle)."""
    return "scan_status_ws_last_%s" % (scan_id,)


def _scan_ws_last_full_key(scan_id: int) -> str:
    """Cache key for last full payload send timestamp per scan."""
    return "scan_status_ws_last_full_%s" % (scan_id,)


def _get_last_sent_ts(scan_id: int) -> Optional[float]:
    """Return last send timestamp for scan from cache, or None."""
    return cache.get(_scan_ws_last_sent_key(scan_id))


def _set_last_sent_ts(scan_id: int, ts: float) -> None:
    """Store last send timestamp for scan in cache."""
    cache.set(_scan_ws_last_sent_key(scan_id), ts, timeout=_THROTTLE_SECONDS * 2)


def _get_last_full_ts(scan_id: int) -> Optional[float]:
    """Return last full payload send timestamp for scan from cache, or None."""
    return cache.get(_scan_ws_last_full_key(scan_id))


def _set_last_full_ts(scan_id: int, ts: float) -> None:
    """Store last full payload send timestamp for scan in cache."""
    cache.set(_scan_ws_last_full_key(scan_id), ts, timeout=_FULL_INTERVAL_SECONDS * 2)


# Backoff delays (seconds) between retries when Redis is loading or connection is reset
_CHANNEL_SEND_RETRY_DELAYS = [2, 5, 10]


def _channel_group_send_with_retry(
    channel_layer: Any,
    group: str,
    message: dict,
) -> None:
    """
    Send message to channel group with retry on Redis transient errors.

    On BusyLoadingError, ConnectionError, or TimeoutError: retry with backoff.
    After retries exhausted, log at warning and return (do not raise).
    Other exceptions propagate.
    """
    for attempt in range(len(_CHANNEL_SEND_RETRY_DELAYS) + 1):
        try:
            async_to_sync(channel_layer.group_send)(group, message)
            return
        except _REDIS_RETRY_EXCEPTIONS as e:
            if attempt < len(_CHANNEL_SEND_RETRY_DELAYS):
                time.sleep(_CHANNEL_SEND_RETRY_DELAYS[attempt])
            else:
                logger.log_line(
                    PREFIX_WS,
                    "CHANNEL_SEND",
                    "Redis transient error after %s attempts, skipping send to group %s: %s"
                    % (len(_CHANNEL_SEND_RETRY_DELAYS) + 1, group, e),
                    level="warning",
                )
                return


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
        logger.log_line(
            PREFIX_WS,
            "BUILD_STATUS",
            "ScanHistory %s not found" % (scan_history_id,),
            level="error",
        )
        return {}
    except Exception as e:
        logger.log_line(
            PREFIX_WS,
            "BUILD_STATUS",
            "Error building scan status message for scan %s: %s" % (scan_history_id, e),
            level="error",
        )
        return {}


def build_light_scan_status_message(
    scan_history_id: int,
    scan: Optional[ScanHistory] = None,
) -> dict:
    """
    Build light scan status message for WebSocket (no runners, commands, subscans, timeline).

    Contains base status, progress, current_task and counts so table/detail/sidebar can update.

    Args:
        scan_history_id: ID of the scan history.
        scan: Optional existing ScanHistory instance to avoid an extra query when already loaded
            (e.g. from send_scan_status_update). If None, the scan is fetched.
    """
    if scan is None:
        try:
            scan = ScanHistory.objects.select_related("scan_type").get(id=scan_history_id)
        except ScanHistory.DoesNotExist:
            logger.log_line(
                PREFIX_WS,
                "BUILD_STATUS_LIGHT",
                "ScanHistory %s not found" % (scan_history_id,),
                level="error",
            )
            return {}
    else:
        scan_history_id = scan.id
    counts = _get_scan_counts(scan_history_id)
    severity_counts = _get_severity_counts(scan_history_id)
    return _build_base_status_message(scan, scan_history_id, counts, severity_counts)


def _build_scan_status_payload(scan_history_id: int) -> dict:
    """Assemble the full scan status payload (counts, severity, timeline, runners, commands, subscans)."""
    scan = ScanHistory.objects.select_related("scan_type").get(id=scan_history_id)
    counts = _get_scan_counts(scan_history_id)
    severity_counts = _get_severity_counts(scan_history_id)

    message = _build_base_status_message(scan, scan_history_id, counts, severity_counts)

    if scan.uses_legacy_engine_profile:
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
    return 4 if status == SKIPPED_TASK else 5


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
    return 2 if t == "task" else 3


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
    """Return domain, subdomain, endpoint, vulnerability, secret, exploit and IP counts for a scan."""
    from reNgine.services.scan_finding_metrics import get_scan_finding_counts

    return get_scan_finding_counts(scan_history_id)


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
        "scan_name": scan.scan_engine_used,
        "status": scan.scan_status,
        "progress": scan.get_progress(),
        "current_task": scan.get_current_task(),
        "domain_count": counts["domain_count"],
        "subdomain_count": counts["subdomain_count"],
        "endpoint_count": counts["endpoint_count"],
        "vulnerability_count": counts["vulnerability_count"],
        "secret_count": counts["secret_count"],
        "exploit_count": counts["exploit_count"],
        "alive_count": counts["alive_count"],
        "endpoint_alive_count": counts["endpoint_alive_count"],
        "ip_address_count": counts["ip_address_count"],
        "ip_alive_count": counts["ip_alive_count"],
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


def send_scan_status_update(
    scan_history_id: int,
    scan_status=None,
    progress=None,
    current_task=None,
    force: bool = False,
) -> None:
    """
    Send scan status update via WebSocket (light or full payload).

    Throttles sends per scan unless force=True. When not forced, sends light payload
    for intermediate updates and full payload periodically (WEBSOCKET_SCAN_STATUS_FULL_INTERVAL_SECONDS).

    Args:
        scan_history_id: ID of the scan history
        scan_status: Optional status to override
        progress: Optional progress to override
        current_task: Optional current task to override
        force: If True, bypass throttle and always send full payload (e.g. terminal state).

    Raises:
        ScanHistory.DoesNotExist: If the scan history is not found.
        Exception: Re-raised after logging on non-transient failures (e.g. serialization).
        Redis transient errors (BusyLoadingError, ConnectionError) are retried then skipped without raising.
    """
    try:
        now = time.time()

        if not force and _THROTTLE_SECONDS > 0:
            last_ts = _get_last_sent_ts(scan_history_id)
            if last_ts is not None and (now - last_ts) < _THROTTLE_SECONDS:
                logger.log_line(
                    PREFIX_WS,
                    "SEND_STATUS",
                    "Throttled WebSocket update for scan %s (last sent %.1fs ago)" % (scan_history_id, now - last_ts),
                    level="debug",
                )
                return

        scan = ScanHistory.objects.select_related("target__project", "scan_type").get(id=scan_history_id)
        channel_layer = get_channel_layer()
        if not channel_layer:
            logger.log_line(
                PREFIX_WS,
                "SEND_STATUS",
                "No channel layer available, skipping WebSocket update for scan %s" % (scan_history_id,),
                level="debug",
            )
            return

        use_full = force
        if not use_full and _FULL_INTERVAL_SECONDS > 0:
            last_full_ts = _get_last_full_ts(scan_history_id)
            if last_full_ts is None or (now - last_full_ts) >= _FULL_INTERVAL_SECONDS:
                use_full = True

        if use_full:
            message = build_scan_status_message(scan_history_id)
        else:
            message = build_light_scan_status_message(scan_history_id, scan=scan)

        if not message:
            logger.log_line(
                PREFIX_WS,
                "SEND_STATUS",
                "Empty message for scan %s, skipping WebSocket update" % (scan_history_id,),
                level="warning",
            )
            return

        if scan_status is not None:
            message["status"] = scan_status
        if progress is not None:
            message["progress"] = progress
        if current_task is not None:
            message["current_task"] = current_task

        logger.log_line(
            PREFIX_WS,
            "SEND_STATUS",
            "Sending WebSocket update for scan %s - status: %s, progress: %s, current_task: %s (full=%s)"
            % (scan_history_id, message.get("status"), message.get("progress"), message.get("current_task"), use_full),
            level="debug",
        )
        logger.log_line(
            PREFIX_WS,
            "SEND_STATUS",
            "WebSocket group_send for scan %s (scan-status and project group)" % (scan_history_id,),
            level="info",
        )

        scan_group = "scan-status-%s" % (scan_history_id,)
        _channel_group_send_with_retry(
            channel_layer,
            scan_group,
            {"type": "scan_status_update", "message": message},
        )
        logger.log_line(
            PREFIX_WS,
            "SEND_STATUS",
            "Sent WebSocket update to scan-specific group: %s" % (scan_group,),
            level="debug",
        )

        if scan.target_id and scan.target and scan.target.project_id:
            project_group = "scan-status-project-%s" % (_clean_channel_name(scan.target.project.slug),)
            _channel_group_send_with_retry(
                channel_layer,
                project_group,
                {"type": "scan_status_update", "message": message},
            )
            logger.log_line(
                PREFIX_WS,
                "SEND_STATUS",
                "Sent WebSocket update to project-level group: %s" % (project_group,),
                level="debug",
            )

        _set_last_sent_ts(scan_history_id, now)
        if use_full:
            _set_last_full_ts(scan_history_id, now)

        logger.log_line(
            PREFIX_WS,
            "SEND_STATUS",
            "Successfully sent WebSocket update for scan %s" % (scan_history_id,),
            level="debug",
        )

    except ScanHistory.DoesNotExist:
        logger.log_line(
            PREFIX_WS,
            "SEND_STATUS",
            "ScanHistory %s not found for WebSocket update" % (scan_history_id,),
            level="error",
        )
        raise
    except Exception as e:
        logger.log_line(
            PREFIX_WS,
            "SEND_STATUS",
            "Error sending WebSocket update for scan %s: %s" % (scan_history_id, e),
            level="error",
            exc_info=True,
        )
        raise


WORKER_STATUS_GROUP = "worker-status"


def send_worker_status_update(worker_id: int) -> None:
    """
    Notify WebSocket clients subscribed to worker status that a worker was updated.
    Payload includes worker_id so the client can refetch or update local state.
    """
    channel_layer = get_channel_layer()
    if not channel_layer:
        logger.log_line(
            PREFIX_WS,
            "WORKER_STATUS",
            "No channel layer available, skipping worker status update for worker_id=%s" % (worker_id,),
            level="debug",
        )
        return
    try:
        _channel_group_send_with_retry(
            channel_layer,
            WORKER_STATUS_GROUP,
            {"type": "worker_status_update", "payload": {"worker_id": worker_id}},
        )
    except Exception:
        logger.log_line(
            PREFIX_WS,
            "WORKER_STATUS",
            "Error sending worker status update for worker_id=%s" % (worker_id,),
            level="error",
            exc_info=True,
        )


def send_worker_deploy_log(
    worker_id: int,
    step: Optional[str],
    message: Optional[str],
    *,
    done: bool = False,
    error: Optional[str] = None,
) -> None:
    """
    Send a deploy log line to WebSocket clients subscribed to this worker's deploy stream.
    Used for real-time deploy progress in the UI modal.
    """
    channel_layer = get_channel_layer()
    if not channel_layer:
        logger.log_line(
            PREFIX_WS,
            "WORKER_DEPLOY",
            "No channel layer available, skipping worker deploy log for worker_id=%s" % (worker_id,),
            level="debug",
        )
        return
    payload = {
        "worker_id": worker_id,
        "step": step,
        "message": message,
        "done": done,
        "error": error,
    }
    try:
        _channel_group_send_with_retry(
            channel_layer,
            worker_deploy_group(worker_id),
            {"type": "worker_deploy_log", "payload": payload},
        )
    except Exception:
        logger.log_line(
            PREFIX_WS,
            "WORKER_DEPLOY",
            "Error sending worker deploy log for worker_id=%s" % (worker_id,),
            level="error",
            exc_info=True,
        )


def send_worker_refresh_log(
    worker_id: int,
    step: Optional[str],
    message: Optional[str],
    *,
    done: bool = False,
    error: Optional[str] = None,
    ssh_ok: Optional[bool] = None,
    container_running: Optional[bool] = None,
    api_reachable: Optional[bool] = None,
) -> None:
    """
    Send a refresh log line to WebSocket clients subscribed to this worker's refresh stream.
    When done=True, pass ssh_ok, container_running, api_reachable so the UI can update badges.
    """
    channel_layer = get_channel_layer()
    if not channel_layer:
        logger.log_line(
            PREFIX_WS,
            "WORKER_REFRESH",
            "No channel layer available, skipping worker refresh log for worker_id=%s" % (worker_id,),
            level="debug",
        )
        return
    payload = {
        "worker_id": worker_id,
        "step": step,
        "message": message,
        "done": done,
        "error": error,
    }
    if done and ssh_ok is not None:
        payload["ssh_ok"] = ssh_ok
    if done and container_running is not None:
        payload["container_running"] = container_running
    if done and api_reachable is not None:
        payload["api_reachable"] = api_reachable
    try:
        _channel_group_send_with_retry(
            channel_layer,
            worker_refresh_group(worker_id),
            {"type": "worker_refresh_log", "payload": payload},
        )
    except Exception:
        logger.log_line(
            PREFIX_WS,
            "WORKER_REFRESH",
            "Error sending worker refresh log for worker_id=%s" % (worker_id,),
            level="error",
            exc_info=True,
        )
