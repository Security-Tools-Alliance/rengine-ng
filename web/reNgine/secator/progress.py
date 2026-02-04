"""
Progress synchronization service for Secator scans.
Handles synchronization between Secator runner data and ScanHistory.
"""

from typing import Optional

from reNgine.utilities.logger import get_module_logger
from django.utils import timezone

from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    RUNNING_TASK,
    SKIPPED_TASK,
    SUCCESS_TASK,
)
from reNgine.services.repositories.scan_repository import ScanRepository
from startScan.models import ScanActivity, ScanHistory, SecatorRunner


logger = get_module_logger(__name__)

TERMINAL_RUNNER_STATUSES = frozenset({"SUCCESS", "FAILURE", "FAILED", "REVOKED"})

UNKNOWN_SECATOR_STATUS_FALLBACK = INITIATED_TASK


class SecatorProgressSync:
    """Service for synchronizing Secator runner progress with ScanHistory."""

    @staticmethod
    def map_secator_status_to_rengine(secator_status: Optional[str]) -> int:
        """
        Map Secator status to reNgine status.

        Args:
            secator_status: Secator status string (RUNNING, SUCCESS, FAILURE, etc.).
                None or empty string map to UNKNOWN_SECATOR_STATUS_FALLBACK.

        Returns:
            int: reNgine status code
        """
        status_map = {
            "RUNNING": RUNNING_TASK,
            "SUCCESS": SUCCESS_TASK,
            "FAILURE": FAILED_TASK,
            "FAILED": FAILED_TASK,
            "PENDING": INITIATED_TASK,
            "REVOKED": ABORTED_TASK,
            "SKIPPED": SKIPPED_TASK,
        }
        if secator_status is None or not secator_status.strip():
            return UNKNOWN_SECATOR_STATUS_FALLBACK
        normalized = secator_status.upper()
        if normalized not in status_map:
            logger.warning(
                "Unknown Secator status %r, using fallback %s",
                secator_status,
                UNKNOWN_SECATOR_STATUS_FALLBACK,
            )
        return status_map.get(normalized, UNKNOWN_SECATOR_STATUS_FALLBACK)

    @staticmethod
    def calculate_workflow_progress(scan_history_id: int) -> float:
        """
        Calculate overall progress for a workflow scan.

        Rules:
        - For workflow/scan: use the workflow/scan progress percentage if > 0
        - If workflow/scan progress is 0, calculate based on tasks belonging to the workflow
        - For tasks only (no workflow/scan): calculate based on number of completed tasks vs total tasks

        Args:
            scan_history_id: ID of the scan history

        Returns:
            float: Progress percentage (0-100)
        """
        try:
            # Get all runners for this scan
            runners = SecatorRunner.objects.filter(scan_history_id=scan_history_id)

            if not runners.exists():
                return 0.0

            # Get the main workflow/scan runner
            main_runner = runners.filter(runner_type__in=["workflow", "scan"]).first()

            # Helper function to calculate progress from tasks
            def calculate_task_progress(task_runners_list):
                """Calculate progress based on completed tasks."""
                if not task_runners_list:
                    return 0.0

                total_tasks = len(task_runners_list)
                completed_tasks = 0

                for runner in task_runners_list:
                    if runner.runner_data:
                        status = runner.runner_data.get("status", "").upper()
                        done = runner.runner_data.get("done", False)
                        # Count as completed if status is SUCCESS or done is True
                        if status == "SUCCESS" or done:
                            completed_tasks += 1

                if total_tasks > 0:
                    progress = (completed_tasks / total_tasks) * 100
                    return round(progress, 2)
                return 0.0

            # Get all task runners
            task_runners = list(runners.filter(runner_type="task"))

            if main_runner and main_runner.runner_data:
                # For workflow/scan: check if progress is available and > 0
                workflow_progress = main_runner.runner_data.get("progress", 0)
                workflow_progress = float(workflow_progress)

                # If workflow has a valid progress (> 0), use it
                if workflow_progress > 0:
                    return workflow_progress

                # If workflow progress is 0 or not available, calculate from tasks
                # This handles cases where Secator doesn't send intermediate progress updates
                return calculate_task_progress(task_runners) if task_runners else 0.0
            # If no main runner, calculate based on number of completed tasks vs total tasks
            return calculate_task_progress(task_runners) if task_runners else 0.0
        except Exception as e:
            logger.error(f"Error calculating workflow progress for scan {scan_history_id}: {e}")
            return 0.0

    @staticmethod
    def get_current_running_runner(scan_history_id: int) -> Optional[SecatorRunner]:
        """
        Get the currently running Secator runner for a scan.

        Args:
            scan_history_id: ID of the scan history

        Returns:
            SecatorRunner: Currently running runner or None
        """
        try:
            if runner := (
                SecatorRunner.objects.filter(scan_history_id=scan_history_id, runner_data__status="RUNNING")
                .order_by("-updated_at")
                .first()
            ):
                return runner

            # Fallback: check for any running runner by status in runner_data
            all_runners = SecatorRunner.objects.filter(scan_history_id=scan_history_id)
            for runner in all_runners:
                if runner.runner_data:
                    status = runner.runner_data.get("status", "").upper()
                    done = runner.runner_data.get("done", False)
                    if status == "RUNNING" and not done:
                        return runner

            return None

        except Exception as e:
            logger.error(f"Error getting current running runner for scan {scan_history_id}: {e}")
            return None

    @staticmethod
    def update_scan_history_from_runners(scan_history_id: int) -> bool:
        """
        Update ScanHistory status and progress from Secator runners.

        Args:
            scan_history_id: ID of the scan history

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)

            # Get all runners for this scan
            runners = SecatorRunner.objects.filter(scan_history_id=scan_history_id)

            if not runners.exists():
                logger.debug(f"No Secator runners found for scan {scan_history_id}")
                return False

            # Get main workflow/scan runner
            main_runner = runners.filter(runner_type__in=["workflow", "scan"]).first()

            if main_runner and main_runner.runner_data:
                runner_data = main_runner.runner_data
                runner_status = runner_data.get("status", "").upper()
                runner_done = runner_data.get("done", False)

                # Map status
                rengine_status = SecatorProgressSync.map_secator_status_to_rengine(runner_status)

                # Update scan status if needed
                if runner_status in ["RUNNING", "SUCCESS", "FAILURE", "FAILED"]:
                    scan_history.scan_status = rengine_status
                    if runner_done and not scan_history.stop_scan_date:
                        scan_history.stop_scan_date = timezone.now()
                    scan_history.save(update_fields=["scan_status", "stop_scan_date"])
                    logger.debug(f"Updated scan {scan_history_id} status to {rengine_status}")

            return True

        except ScanHistory.DoesNotExist:
            logger.error(f"ScanHistory {scan_history_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating scan history from runners for scan {scan_history_id}: {e}")
            return False

    @staticmethod
    def _get_runner(runner_id: Optional[int]) -> Optional[SecatorRunner]:
        if runner_id is None:
            return None
        try:
            return SecatorRunner.objects.get(id=runner_id)
        except SecatorRunner.DoesNotExist:
            logger.warning(f"SecatorRunner {runner_id} not found when syncing progress")
            return None

    @staticmethod
    def _sync_subscans_if_terminal(runner_id: Optional[int], runner_status: str, rengine_status: int) -> None:
        if runner_id is not None and runner_status in TERMINAL_RUNNER_STATUSES:
            ScanRepository().mark_subscans_finished_for_runner(runner_id, rengine_status)

    @staticmethod
    def _update_existing_activity(
        existing_activity: ScanActivity,
        runner: Optional[SecatorRunner],
        runner_name: str,
        runner_status: str,
        activity_title: str,
        rengine_status: int,
        runner_id: Optional[int],
    ) -> int:
        if runner is not None:
            runner.status = runner_status.upper()
            runner.save(update_fields=["status"])
        existing_activity.status = rengine_status
        existing_activity.time = timezone.now()
        if runner_status in {"SUCCESS", "FAILURE", "FAILED"}:
            existing_activity.title = f"{activity_title} - Completed"
        elif runner_status == "REVOKED":
            existing_activity.title = f"{activity_title} - Aborted"
        existing_activity.save(update_fields=["status", "time", "title"])
        SecatorProgressSync._sync_subscans_if_terminal(runner_id, runner_status, rengine_status)
        logger.debug(f"Updated ScanActivity {existing_activity.id} for runner {runner_name}")
        return existing_activity.id

    @staticmethod
    def _create_new_activity(
        scan_history: ScanHistory,
        runner: Optional[SecatorRunner],
        runner_name: str,
        runner_type: str,
        runner_status: str,
        activity_title: str,
        rengine_status: int,
        runner_id: Optional[int],
    ) -> int:
        from reNgine.services.repositories.scan_repository import ScanRepository

        scan_repo = ScanRepository()
        activity_id = scan_repo.create_activity(scan_history.id, activity_title, rengine_status)
        if runner is not None:
            try:
                new_activity = ScanActivity.objects.get(id=activity_id)
                new_activity.runner_id = runner
                new_activity.name = runner_name
                new_activity.save(update_fields=["runner_id", "name"])
            except ScanActivity.DoesNotExist as e:
                logger.warning(f"Could not link runner to activity: {e}")
        SecatorProgressSync._sync_subscans_if_terminal(runner_id, runner_status, rengine_status)
        logger.debug(f"Created ScanActivity {activity_id} for runner {runner_name}")
        return activity_id

    @staticmethod
    def create_or_update_scan_activity(
        scan_history_id: int,
        runner_name: str,
        runner_type: str,
        runner_status: str,
        runner_id: Optional[int] = None,
    ) -> Optional[int]:
        """
        Create or update a ScanActivity for a Secator runner.

        Args:
            scan_history_id: ID of the scan history
            runner_name: Name of the runner
            runner_type: Type of runner (workflow, scan, task)
            runner_status: Status of the runner
            runner_id: Optional ID of the SecatorRunner

        Returns:
            ID of the created/updated ScanActivity or None on error.
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            rengine_status = SecatorProgressSync.map_secator_status_to_rengine(runner_status)
            activity_title = f"{runner_type.title()}: {runner_name}"
            runner = SecatorProgressSync._get_runner(runner_id)
            existing_activity = (
                ScanActivity.objects.filter(scan_of=scan_history, name=runner_name, runner_id=runner)
                .order_by("-time")
                .first()
                if runner
                else None
            )
            if existing_activity:
                return SecatorProgressSync._update_existing_activity(
                    existing_activity,
                    runner,
                    runner_name,
                    runner_status,
                    activity_title,
                    rengine_status,
                    runner_id,
                )
            return SecatorProgressSync._create_new_activity(
                scan_history,
                runner,
                runner_name,
                runner_type,
                runner_status,
                activity_title,
                rengine_status,
                runner_id,
            )
        except ScanHistory.DoesNotExist:
            logger.error(f"ScanHistory {scan_history_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error creating/updating scan activity: {e}")
            return None
