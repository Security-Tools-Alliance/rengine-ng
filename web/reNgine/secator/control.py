"""
Scan control operations for Secator scans.
Provides start, stop, pause functionality.
"""

from typing import Optional

from django.utils import timezone

from reNgine.definitions import ABORTED_TASK, RUNNING_TASK
from reNgine.services.repositories.scan_repository import ScanRepository
from reNgine.utilities.logger import get_module_logger
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
                    logger.warning("ScanActivity %s not found", activity_id)
            elif runner.scan_history:
                # Try to find existing activity for this runner
                activity = ScanActivity.objects.filter(scan_of=runner.scan_history, runner_id=runner).first()

            # Create or update Command
            command_repo = CommandRepository()
            scan_history_id = runner.scan_history.id if runner.scan_history else self.scan_history_id
            command_repo.save_from_secator(runner.runner_data or {}, scan_history_id, activity.id if activity else None)
        except Exception as e:
            logger.warning("Failed to create/update Command for runner %s: %s", runner.id, e)

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
                logger.error("Scan %s not found", self.scan_history_id)
                return False

            # Get all SecatorRunner instances associated with this scan (include worker for remote revoke)
            runners = list(SecatorRunner.objects.filter(scan_history_id=self.scan_history_id).select_related("worker"))

            if not runners:
                logger.warning("No SecatorRunner found for scan %s", self.scan_history_id)
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
                    task_name = f"scan_{self.scan_history_id}"
                    try:
                        if runner.worker_id:
                            from reNgine.secator.remote_runner import revoke_task_on_remote_worker

                            if revoke_task_on_remote_worker(runner.worker, celery_id, task_name=task_name):
                                revoked_count += 1
                                logger.debug(
                                    "Successfully revoked Celery task %s for scan %s (remote)",
                                    celery_id,
                                    self.scan_history_id,
                                )
                            else:
                                failed_count += 1
                        else:
                            revoke_task(celery_id, task_name=task_name)
                            revoked_count += 1
                            logger.debug(
                                "Successfully revoked Celery task %s for scan %s", celery_id, self.scan_history_id
                            )
                    except Exception as e:
                        failed_count += 1
                        logger.error(
                            "Failed to revoke Celery task %s for scan %s: %s",
                            celery_id,
                            self.scan_history_id,
                            e,
                        )
                else:
                    logger.warning(
                        "Runner %s (%s: %s) has no celery_id to revoke",
                        runner.id,
                        runner.runner_type,
                        runner.runner_name,
                    )

                # Update runner status to REVOKED
                runner.status = "REVOKED"
                runner.save(update_fields=["status"])

                # Create or update Command for this runner to ensure it appears in logs
                self._create_or_update_command_for_runner(runner)

            # Log summary of revocation results
            if revoked_count > 0:
                logger.info("Revoked %s Celery task(s) for scan %s", revoked_count, self.scan_history_id)
            if failed_count > 0:
                logger.warning("Failed to revoke %s Celery task(s) for scan %s", failed_count, self.scan_history_id)

            # Update scan status regardless of individual task revocation results
            self.scan_repo.update_status(self.scan_history_id, ABORTED_TASK)
            self.scan_repo.create_scan_activity(self.scan_history_id, "Scan stopped by user", ABORTED_TASK)

            # Update all running activities to ABORTED_TASK
            running_activities = ScanActivity.objects.filter(scan_of_id=self.scan_history_id, status=RUNNING_TASK)
            running_activities.update(status=ABORTED_TASK)

            logger.info("Stopped scan %s (revoked %s/%s runners)", self.scan_history_id, revoked_count, len(runners))
            return True

        except Exception as e:
            logger.error("Error stopping scan %s: %s", self.scan_history_id, e)
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
                logger.error("Subscan %s not found", subscan_id)
                return False

            scan = subscan.scan_history
            if not scan:
                logger.error("Scan not found for subscan %s", subscan_id)
                return False

            # Check if there are other running subscans for this scan
            other_running_subscans = (
                SubScan.objects.filter(scan_history=scan, status=RUNNING_TASK).exclude(id=subscan_id).count()
            )

            if other_running_subscans > 0:
                logger.warning(
                    "Stopping subscan %s will also affect %s other running subscan(s) for scan %s as they share the same runners",
                    subscan_id,
                    other_running_subscans,
                    scan.id,
                )

            runners = self._get_runners_to_revoke_for_subscan(subscan, scan)
            if not runners:
                logger.warning("No SecatorRunner found for subscan %s", subscan_id)
                self._abort_subscan(subscan)
                return True

            revoked_count = self._revoke_runners_for_subscan(runners, subscan_id, scan)
            self._abort_subscan(subscan)
            self.scan_repo.create_activity(scan.id, f"Subscan {subscan_id} aborted", ABORTED_TASK)
            ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK).update(status=ABORTED_TASK)

            logger.info("Stopped subscan %s (revoked %s/%s runners)", subscan_id, revoked_count, len(runners))
            return True

        except Exception as e:
            logger.error("Error stopping subscan %s: %s", subscan_id, e)
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
            runners = list(
                SecatorRunner.objects.filter(id__in=activity_runner_ids, scan_history_id=scan.id).select_related(
                    "worker"
                )
            )
            logger.debug("Scoping subscan %s stop to %s activity-specific runner(s)", subscan.id, len(runners))
        else:
            runners = list(SecatorRunner.objects.filter(scan_history_id=scan.id).select_related("worker"))
            logger.debug(
                "No activity-specific runners found for subscan %s, using all %s runner(s) from parent scan %s",
                subscan.id,
                len(runners),
                scan.id,
            )
        return runners

    def _revoke_runners_for_subscan(self, runners: list, subscan_id: int, scan) -> int:
        """Revoke Celery tasks for runners, update status and Command; returns count of successfully revoked."""
        from secator.celery import revoke_task

        revoked_count = 0
        task_name = f"subscan_{subscan_id}"
        for runner in runners:
            if celery_id := runner.celery_id or (runner.runner_data or {}).get("context", {}).get("celery_id"):
                try:
                    if runner.worker_id:
                        from reNgine.secator.remote_runner import revoke_task_on_remote_worker

                        if revoke_task_on_remote_worker(runner.worker, celery_id, task_name=task_name):
                            revoked_count += 1
                            logger.debug(
                                "Successfully revoked Celery task %s for subscan %s (remote)",
                                celery_id,
                                subscan_id,
                            )
                        else:
                            logger.error(
                                "Failed to revoke Celery task %s for subscan %s on remote worker",
                                celery_id,
                                subscan_id,
                            )
                    else:
                        revoke_task(celery_id, task_name=task_name)
                        revoked_count += 1
                        logger.debug("Successfully revoked Celery task %s for subscan %s", celery_id, subscan_id)
                except Exception as e:
                    logger.error("Failed to revoke Celery task %s for subscan %s: %s", celery_id, subscan_id, e)
            else:
                logger.warning(
                    "Runner %s (%s: %s) has no celery_id to revoke",
                    runner.id,
                    runner.runner_type,
                    runner.runner_name,
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
                logger.warning("Failed to create/update Command for runner %s: %s", runner.id, e)

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

            activity = ScanActivity.objects.filter(id=activity_id).select_related("runner_id__worker").first()
            if not activity:
                logger.error("ScanActivity %s not found", activity_id)
                return False

            # Check if activity has a runner_id and celery_id
            if not activity.runner_id:
                logger.warning("ScanActivity %s has no associated runner_id", activity_id)
                self._abort_activity(activity)
                return True

            if not activity.runner_id.celery_id:
                logger.warning("ScanActivity %s has runner_id %s but no celery_id", activity_id, activity.runner_id.id)
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
                    "Activity %s shares runner %s with %s other running activity/activities. "
                    "Stopping this activity will revoke the shared runner's celery task.",
                    activity_id,
                    activity.runner_id.id,
                    other_activities_with_same_runner,
                )

            # Additional guard: Verify the runner belongs to the same scan as the activity
            if (
                activity.scan_of
                and activity.runner_id.scan_history
                and activity.scan_of.id != activity.runner_id.scan_history.id
            ):
                logger.error(
                    "Activity %s (scan %s) has runner %s associated with different scan %s. "
                    "This may indicate data inconsistency.",
                    activity_id,
                    activity.scan_of.id,
                    activity.runner_id.id,
                    activity.runner_id.scan_history.id,
                )
                # Detected data inconsistency: avoid revoking a task that may belong to a different scan
                return False

            # Revoke the Celery task (remote or local)
            task_name = f"activity_{activity_id}"
            try:
                if activity.runner_id.worker_id:
                    from reNgine.secator.remote_runner import revoke_task_on_remote_worker

                    if not revoke_task_on_remote_worker(
                        activity.runner_id.worker,
                        activity.runner_id.celery_id,
                        task_name=task_name,
                    ):
                        logger.error(
                            "Failed to revoke Celery task %s for activity %s on remote worker",
                            activity.runner_id.celery_id,
                            activity_id,
                        )
                        return False
                else:
                    revoke_task(activity.runner_id.celery_id, task_name=task_name)
                logger.debug(
                    "Successfully revoked Celery task %s for activity %s",
                    activity.runner_id.celery_id,
                    activity_id,
                )
            except Exception as e:
                logger.error(
                    "Failed to revoke Celery task %s for activity %s: %s",
                    activity.runner_id.celery_id,
                    activity_id,
                    e,
                )
                return False

            # Update runner status to REVOKED
            runner = activity.runner_id
            runner.status = "REVOKED"
            runner.save(update_fields=["status"])

            # Create or update Command for this runner to ensure it appears in logs
            self._create_or_update_command_for_runner(runner, activity.id)

            self._abort_activity(activity)
            logger.info("Stopped activity %s", activity_id)
            return True

        except Exception as e:
            logger.error("Error stopping activity %s: %s", activity_id, e)
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
