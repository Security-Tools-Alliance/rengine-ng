"""
WebSocket utility functions for sending scan status updates.
"""

import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models import Count, Q

from api.serializers import CommandSerializer, ScanActivitySerializer, SecatorRunnerSerializer
from startScan.models import Command, EndPoint, ScanActivity, ScanHistory, SecatorRunner, Subdomain, Vulnerability


logger = logging.getLogger("websocket")


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
        scan = ScanHistory.objects.get(id=scan_history_id)

        # Calculate all counts in optimized queries to avoid N+1
        subdomain_count = Subdomain.objects.filter(scan_history__id=scan_history_id).count()
        alive_count = Subdomain.objects.filter(scan_history__id=scan_history_id, http_status__gt=0).count()

        endpoint_count = EndPoint.objects.filter(scan_history__id=scan_history_id).count()
        endpoint_alive_count = EndPoint.objects.filter(scan_history__id=scan_history_id, http_status__gt=0).count()

        vulnerability_count = Vulnerability.objects.filter(scan_history__id=scan_history_id).count()

        # Get vulnerability counts by severity in a single query
        vuln_severity_counts = (
            Vulnerability.objects.filter(scan_history__id=scan_history_id)
            .values("severity")
            .annotate(count=Count("id"))
        )
        severity_map = {item["severity"]: item["count"] for item in vuln_severity_counts}

        critical_count = severity_map.get(4, 0)
        high_count = severity_map.get(3, 0)
        medium_count = severity_map.get(2, 0)
        low_count = severity_map.get(1, 0)
        info_count = severity_map.get(0, 0)
        unknown_count = severity_map.get(-1, 0)

        message = {
            "type": "scan_status_update",
            "scan_id": scan_history_id,
            "scan_type": "legacy" if scan.is_legacy_scan else "secator",
            "scan_name": scan.display_runner_type + ": " + scan.display_scan_name,
            "status": scan.scan_status,
            "progress": scan.get_progress(),
            "current_task": scan.get_current_task(),
            "subdomain_count": subdomain_count,
            "endpoint_count": endpoint_count,
            "vulnerability_count": vulnerability_count,
            "alive_count": alive_count,
            "endpoint_alive_count": endpoint_alive_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "info_count": info_count,
            "unknown_count": unknown_count,
        }

        if scan.is_legacy_scan:
            # Legacy: use ScanActivity
            activities = ScanActivity.objects.filter(scan_of=scan).order_by("-time")[:10]
            message["timeline"] = ScanActivitySerializer(activities, many=True).data
            message["runners"] = []
        else:
            # Secator: use SecatorRunner
            runners = SecatorRunner.objects.filter(scan_history=scan).order_by("-created_at")
            # Use serializer to get consistent data, including elapsed_seconds
            serializer = SecatorRunnerSerializer(runners, many=True)
            message["runners"] = serializer.data

            # Build timeline from runners with activity_id and progress
            timeline_items = []
            for runner in runners:
                # Get activity_id from ScanActivity if it exists
                activity_id = None
                try:
                    activity = ScanActivity.objects.filter(runner_id=runner).first()
                    if activity:
                        activity_id = activity.id
                except Exception:
                    pass

                # Get progress from runner_data
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

        # Include running commands with their outputs for real-time updates
        running_commands = (
            Command.objects.filter(
                scan_history=scan,
            )
            .filter(
                # Commands that are running: status is RUNNING or end_time is None
                Q(status="RUNNING") | Q(end_time__isnull=True)
            )
            .order_by("-time")[:30]
        )  # Limit to last 30 running commands to avoid large messages

        if running_commands.exists():
            serializer = CommandSerializer(running_commands, many=True)
            message["commands"] = serializer.data
        else:
            message["commands"] = []

        return message

    except ScanHistory.DoesNotExist:
        logger.error(f"ScanHistory {scan_history_id} not found")
        return {}
    except Exception as e:
        logger.error(f"Error building scan status message for scan {scan_history_id}: {e}")
        return {}


def send_scan_status_update(scan_history_id: int, scan_status=None, progress=None, current_task=None):
    """
    Send detailed scan status update via WebSocket.

    Args:
        scan_history_id: ID of the scan history
        scan_status: Optional status to override
        progress: Optional progress to override
        current_task: Optional current task to override
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
            f"Sending WebSocket update for scan {scan_history_id} - "
            f"status: {message.get('status')}, progress: {message.get('progress')}, "
            f"current_task: {message.get('current_task')}"
        )

        # Send to scan-specific group
        scan_group = f"scan-status-{scan_history_id}"
        async_to_sync(channel_layer.group_send)(
            scan_group,
            {"type": "scan_status_update", "message": message},
        )
        logger.debug(f"Sent WebSocket update to scan-specific group: {scan_group}")

        # Send to project-level group
        if scan.domain and scan.domain.project:
            project_group = f"scan-status-project-{scan.domain.project.slug}"
            async_to_sync(channel_layer.group_send)(
                project_group,
                {"type": "scan_status_update", "message": message},
            )
            logger.debug(f"Sent WebSocket update to project-level group: {project_group}")

        logger.debug(f"Successfully sent WebSocket update for scan {scan_history_id}")

    except ScanHistory.DoesNotExist:
        logger.error(f"ScanHistory {scan_history_id} not found for WebSocket update")
    except Exception as e:
        logger.error(f"Error sending WebSocket update for scan {scan_history_id}: {e}", exc_info=True)
