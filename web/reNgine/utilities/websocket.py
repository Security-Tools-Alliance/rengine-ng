"""
WebSocket utility functions for sending scan status updates.
"""

import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models import Count

from api.serializers import ScanActivitySerializer
from startScan.models import EndPoint, ScanActivity, ScanHistory, SecatorRunner, Subdomain, Vulnerability


logger = logging.getLogger("websocket")


def get_runner_status_code(runner: SecatorRunner) -> int:
    """Get reNgine status code from Secator runner."""
    from reNgine.services.secator.progress_sync import SecatorProgressSync

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
            # Build runners data manually (avoiding serializer validation issue)
            message["runners"] = [
                {
                    "id": runner.id,
                    "runner_type": runner.runner_type,
                    "runner_name": runner.runner_name or "",
                    "status": runner.runner_data.get("status", "PENDING") if runner.runner_data else "PENDING",
                    "status_display": (
                        "Running" if runner.runner_data and runner.runner_data.get("status") == "RUNNING"
                        else "Success" if runner.runner_data and runner.runner_data.get("status") == "SUCCESS"
                        else "Failed" if runner.runner_data and runner.runner_data.get("status") in ["FAILURE", "FAILED"]
                        else "Pending"
                    ),
                    "status_code": get_runner_status_code(runner),
                    "progress": runner.runner_data.get("progress", 0) if runner.runner_data else 0,
                    "done": runner.runner_data.get("done", False) if runner.runner_data else False,
                    "created_at": runner.created_at.isoformat() if runner.created_at else None,
                    "updated_at": runner.updated_at.isoformat() if runner.updated_at else None,
                    "elapsed": None,  # Will be calculated on frontend if needed
                    "start_time": runner.runner_data.get("start_time") if runner.runner_data and "start_time" in runner.runner_data else (runner.created_at.isoformat() if runner.created_at else None),
                    "scan_history": runner.scan_history_id,
                    "domain": runner.domain_id,
                }
                for runner in runners
            ]

            # Build timeline from runners
            message["timeline"] = [
                {
                    "id": runner.id,
                    "title": f"{runner.runner_type.title()}: {runner.runner_name}",
                    "name": runner.runner_name or "",
                    "status": get_runner_status_code(runner),
                    "time": runner.created_at.isoformat() if runner.created_at else None,
                    "type": runner.runner_type,
                }
                for runner in runners
            ]

        return message

    except ScanHistory.DoesNotExist:
        logger.error(f"ScanHistory {scan_history_id} not found")
        return {}
    except Exception as e:
        logger.error(f"Error building scan status message for scan {scan_history_id}: {e}")
        return {}


def send_scan_status_update(
    scan_history_id: int, scan_status=None, progress=None, current_task=None
):
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

        # Send to scan-specific group
        async_to_sync(channel_layer.group_send)(
            f"scan-status-{scan_history_id}",
            {"type": "scan_status_update", "message": message},
        )

        # Send to project-level group
        if scan.domain and scan.domain.project:
            async_to_sync(channel_layer.group_send)(
                f"scan-status-project-{scan.domain.project.slug}",
                {"type": "scan_status_update", "message": message},
            )

        logger.debug(f"Sent WebSocket update for scan {scan_history_id}")

    except ScanHistory.DoesNotExist:
        logger.error(f"ScanHistory {scan_history_id} not found for WebSocket update")
    except Exception as e:
        logger.error(f"Error sending WebSocket update for scan {scan_history_id}: {e}")
