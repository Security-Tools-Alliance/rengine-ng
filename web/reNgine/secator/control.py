"""
Scan control operations for Secator scans.
Provides start, stop, pause functionality.
"""

from typing import Optional

from reNgine.utilities.logger import get_module_logger
from django.utils import timezone

from reNgine.definitions import ABORTED_TASK, RUNNING_TASK
from reNgine.services.repositories.scan_repository import ScanRepository
from startScan.models import ScanActivity, SecatorRunner, SubScan


logger = get_module_logger(__name__)


class SecatorScanController:
    """Controls Secator scan lifecycle."""

    def __init__(self, scan_history_id: int):
        """
        Initialize scan controller.

        Args:
            scan_history_id: ID of the scan history
        """
        self.scan_history_id = scan_history_id
        self.scan_repo = ScanRepository()

    def _create_or_update_command_for_runner(self, runner: SecatorRunner, activity_id: Optional[int] = None) -> None:
        """
        Create or update Command for a runner to ensure it appears in logs.

        Args:
            runner: SecatorRunner instance
            activity_id: Optional activity ID to link the command to
        """
        try:
            from reNgine.services.repositories.command_repository import CommandRepository

            # Update runner_data with REVOKED status to ensure consistency
            if runner.runner_data:
                self._mark_runner_data_revoked(runner)
            # Get or create activity for this runner
            activity = None
            if activity_id:
                try:
                    activity = ScanActivity.objects.get(id=activity_id)
                except ScanActivity.DoesNotExist:
                    logger.warning(f"ScanActivity {activity_id} not found")
            elif runner.scan_history:
                # Try to find existing activity for this runner
                activity = ScanActivity.objects.filter(scan_of=runner.scan_history, runner_id=runner).first()

            # Create or update Command
            command_repo = CommandRepository()
            scan_history_id = runner.scan_history.id if runner.scan_history else self.scan_history_id
            command_repo.save_from_secator(runner.runner_data or {}, scan_history_id, activity.id if activity else None)
        except Exception as e:
            logger.warning(f"Failed to create/update Command for runner {runner.id}: {e}")

    def stop_scan(self) -> bool:
        """
        Stop a running Secator scan by revoking all associated Celery tasks.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from secator.celery import revoke_task

            scan = self.scan_repo.get_by_id(self.scan_history_id)
            if not scan:
                logger.error(f"Scan {self.scan_history_id} not found")
                return False

            # Get all SecatorRunner instances associated with this scan
            runners = list(SecatorRunner.objects.filter(scan_history_id=self.scan_history_id))

            if not runners:
                logger.warning(f"No SecatorRunner found for scan {self.scan_history_id}")
                self.scan_repo.update_status(self.scan_history_id, ABORTED_TASK)
                return True

            # Revoke all Celery tasks associated with this scan
            revoked_count = 0
            failed_count = 0

            for runner in runners:
                # Try to get celery_id from the runner's celery_id field first
                celery_id = runner.celery_id

                # If not found, try to extract from runner_data context
                if not celery_id and runner.runner_data:
                    context = runner.runner_data.get("context", {})
                    celery_id = context.get("celery_id")

                if celery_id:
                    try:
                        revoke_task(celery_id, task_name=f"scan_{self.scan_history_id}")
                        revoked_count += 1
                        logger.debug(f"Successfully revoked Celery task {celery_id} for scan {self.scan_history_id}")
                    except Exception as e:
                        failed_count += 1
                        logger.error(f"Failed to revoke Celery task {celery_id} for scan {self.scan_history_id}: {e}")
                else:
                    logger.warning(
                        f"Runner {runner.id} ({runner.runner_type}: {runner.runner_name}) has no celery_id to revoke"
                    )

                # Update runner status to REVOKED
                runner.status = "REVOKED"
                runner.save(update_fields=["status"])

                # Create or update Command for this runner to ensure it appears in logs
                self._create_or_update_command_for_runner(runner)

            # Log summary of revocation results
            if revoked_count > 0:
                logger.info(f"Revoked {revoked_count} Celery task(s) for scan {self.scan_history_id}")
            if failed_count > 0:
                logger.warning(f"Failed to revoke {failed_count} Celery task(s) for scan {self.scan_history_id}")

            # Update scan status regardless of individual task revocation results
            self.scan_repo.update_status(self.scan_history_id, ABORTED_TASK)
            self.scan_repo.create_scan_activity(self.scan_history_id, "Scan stopped by user", ABORTED_TASK)

            # Update all running activities to ABORTED_TASK
            running_activities = ScanActivity.objects.filter(scan_of_id=self.scan_history_id, status=RUNNING_TASK)
            running_activities.update(status=ABORTED_TASK)

            logger.info(f"Stopped scan {self.scan_history_id} (revoked {revoked_count}/{len(runners)} runners)")
            return True

        except Exception as e:
            logger.error(f"Error stopping scan {self.scan_history_id}: {e}")
            return False

    def stop_subscan(self, subscan_id: int) -> bool:
        """
        Stop a running subscan by revoking associated Celery tasks.

        Note: In the current architecture, subscans share runners with their parent scan.
        This method revokes all runners associated with the parent scan, which may affect
        other subscans sharing the same scan. If multiple subscans share a scan, stopping
        one subscan will stop all runners for the parent scan, effectively stopping all
        subscans for that scan.

        Args:
            subscan_id: ID of the subscan

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            subscan = SubScan.objects.filter(id=subscan_id).first()
            if not subscan:
                logger.error(f"Subscan {subscan_id} not found")
                return False

            scan = subscan.scan_history
            if not scan:
                logger.error(f"Scan not found for subscan {subscan_id}")
                return False

            # Check if there are other running subscans for this scan
            other_running_subscans = (
                SubScan.objects.filter(scan_history=scan, status=RUNNING_TASK).exclude(id=subscan_id).count()
            )

            if other_running_subscans > 0:
                logger.warning(
                    f"Stopping subscan {subscan_id} will also affect {other_running_subscans} "
                    f"other running subscan(s) for scan {scan.id} as they share the same runners"
                )

            runners = self._get_runners_to_revoke_for_subscan(subscan, scan)
            if not runners:
                logger.warning(f"No SecatorRunner found for subscan {subscan_id}")
                self._abort_subscan(subscan)
                return True

            revoked_count = self._revoke_runners_for_subscan(runners, subscan_id, scan)
            self._abort_subscan(subscan)
            self.scan_repo.create_activity(scan.id, f"Subscan {subscan_id} aborted", ABORTED_TASK)
            ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK).update(status=ABORTED_TASK)

            logger.info(f"Stopped subscan {subscan_id} (revoked {revoked_count}/{len(runners)} runners)")
            return True

        except Exception as e:
            logger.error(f"Error stopping subscan {subscan_id}: {e}")
            return False

    def _get_runners_to_revoke_for_subscan(self, subscan: SubScan, scan) -> list:
        """
        Collect SecatorRunner instances to revoke for this subscan.
        Scopes by subdomain when subscan has a subdomain; otherwise uses domain-level runners only.
        """
        subscan_activities = ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK).select_related("runner_id")
        activity_runner_ids = set()
        subscan_subdomain = subscan.subdomain
        for activity in subscan_activities:
            if not activity.runner_id:
                continue
            runner = activity.runner_id
            runner_context = runner.runner_data.get("context", {}) if runner.runner_data else {}
            runner_subdomain_id = runner_context.get("subdomain_id")
            if subscan_subdomain is None:
                if runner_subdomain_id is None:
                    activity_runner_ids.add(runner.id)
            elif runner_subdomain_id is not None and runner_subdomain_id == subscan_subdomain.id:
                activity_runner_ids.add(runner.id)

        if activity_runner_ids:
            runners = list(SecatorRunner.objects.filter(id__in=activity_runner_ids, scan_history_id=scan.id))
            logger.debug(f"Scoping subscan {subscan.id} stop to {len(runners)} activity-specific runner(s)")
        else:
            runners = list(SecatorRunner.objects.filter(scan_history_id=scan.id))
            logger.debug(
                f"No activity-specific runners found for subscan {subscan.id}, "
                f"using all {len(runners)} runner(s) from parent scan {scan.id}"
            )
        return runners

    def _revoke_runners_for_subscan(self, runners: list, subscan_id: int, scan) -> int:
        """Revoke Celery tasks for runners, update status and Command; returns count of successfully revoked."""
        from secator.celery import revoke_task

        revoked_count = 0
        for runner in runners:
            if celery_id := runner.celery_id or (runner.runner_data or {}).get("context", {}).get("celery_id"):
                try:
                    revoke_task(celery_id, task_name=f"subscan_{subscan_id}")
                    revoked_count += 1
                    logger.debug(f"Successfully revoked Celery task {celery_id} for subscan {subscan_id}")
                except Exception as e:
                    logger.error(f"Failed to revoke Celery task {celery_id} for subscan {subscan_id}: {e}")
            else:
                logger.warning(
                    f"Runner {runner.id} ({runner.runner_type}: {runner.runner_name}) has no celery_id to revoke"
                )

            runner.status = "REVOKED"
            runner.save(update_fields=["status"])
            if runner.runner_data:
                self._mark_runner_data_revoked(runner)
            try:
                from reNgine.services.repositories.command_repository import CommandRepository

                activity = (
                    ScanActivity.objects.filter(scan_of=runner.scan_history, runner_id=runner).first()
                    if runner.scan_history
                    else None
                )
                CommandRepository().save_from_secator(
                    runner.runner_data or {},
                    runner.scan_history.id if runner.scan_history else scan.id,
                    activity.id if activity else None,
                )
            except Exception as e:
                logger.warning(f"Failed to create/update Command for runner {runner.id}: {e}")

        return revoked_count

    def _mark_runner_data_revoked(self, runner) -> None:
        """Set runner_data status to REVOKED and persist."""
        runner.runner_data["status"] = "REVOKED"
        runner.runner_data["done"] = True
        runner.save(update_fields=["runner_data"])

    def _abort_subscan(self, subscan: SubScan) -> None:
        """
        Mark a subscan as aborted and record the stop time.

        Args:
            subscan: SubScan instance to mark as aborted
        """
        from reNgine.utilities.websocket import send_scan_status_update

        subscan.status = ABORTED_TASK
        subscan.stop_scan_date = timezone.now()
        subscan.save()
        send_scan_status_update(subscan.scan_history_id)

    def stop_activity(self, activity_id: int) -> bool:
        """
        Stop a running ScanActivity by revoking its associated Celery task.

        This method includes a correlation check to ensure that the runner's celery_id
        is actually associated with this specific activity. If multiple activities share
        a runner, only the activity with the matching runner_id will be stopped.

        Args:
            activity_id: ID of the ScanActivity

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from secator.celery import revoke_task

            activity = ScanActivity.objects.filter(id=activity_id).select_related("runner_id").first()
            if not activity:
                logger.error(f"ScanActivity {activity_id} not found")
                return False

            # Check if activity has a runner_id and celery_id
            if not activity.runner_id:
                logger.warning(f"ScanActivity {activity_id} has no associated runner_id")
                self._abort_activity(activity)
                return True

            if not activity.runner_id.celery_id:
                logger.warning(f"ScanActivity {activity_id} has runner_id {activity.runner_id.id} but no celery_id")
                self._abort_activity(activity)
                return True

            # Correlation check: Verify that this activity is actually associated with this runner
            # Check if there are other activities using the same runner to ensure we're stopping the right one
            other_activities_with_same_runner = (
                ScanActivity.objects.filter(runner_id=activity.runner_id, status=RUNNING_TASK)
                .exclude(id=activity_id)
                .count()
            )

            if other_activities_with_same_runner > 0:
                logger.warning(
                    f"Activity {activity_id} shares runner {activity.runner_id.id} with "
                    f"{other_activities_with_same_runner} other running activity/activities. "
                    f"Stopping this activity will revoke the shared runner's celery task."
                )

            # Additional guard: Verify the runner belongs to the same scan as the activity
            if (
                activity.scan_of
                and activity.runner_id.scan_history
                and activity.scan_of.id != activity.runner_id.scan_history.id
            ):
                logger.error(
                    f"Activity {activity_id} (scan {activity.scan_of.id}) has runner "
                    f"{activity.runner_id.id} associated with different scan "
                    f"{activity.runner_id.scan_history.id}. This may indicate data inconsistency."
                )
                # Detected data inconsistency: avoid revoking a task that may belong to a different scan
                return False

            # Revoke the Celery task
            try:
                revoke_task(activity.runner_id.celery_id, task_name=f"activity_{activity_id}")
                logger.debug(
                    f"Successfully revoked Celery task {activity.runner_id.celery_id} for activity {activity_id}"
                )
            except Exception as e:
                logger.error(
                    f"Failed to revoke Celery task {activity.runner_id.celery_id} for activity {activity_id}: {e}"
                )
                return False

            # Update runner status to REVOKED
            runner = activity.runner_id
            runner.status = "REVOKED"
            runner.save(update_fields=["status"])

            # Create or update Command for this runner to ensure it appears in logs
            self._create_or_update_command_for_runner(runner, activity.id)

            self._abort_activity(activity)
            logger.info(f"Stopped activity {activity_id}")
            return True

        except Exception as e:
            logger.error(f"Error stopping activity {activity_id}: {e}")
            return False

    def _abort_activity(self, activity: ScanActivity) -> None:
        """
        Mark a ScanActivity as aborted and record the stop time.

        Args:
            activity: ScanActivity instance to mark as aborted
        """
        activity.status = ABORTED_TASK
        activity.time = timezone.now()
        activity.save()

    def pause_scan(self):
        """
        Pause a running Secator scan.

        Note: This requires Secator support for pausing.

        Returns:
            bool: True if successful, False otherwise
        """
        logger.warning("Pause functionality not yet implemented for Secator scans")
        return False

    def resume_scan(self):
        """
        Resume a paused Secator scan.

        Note: This requires Secator support for resuming.

        Returns:
            bool: True if successful, False otherwise
        """
        logger.warning("Resume functionality not yet implemented for Secator scans")
        return False
