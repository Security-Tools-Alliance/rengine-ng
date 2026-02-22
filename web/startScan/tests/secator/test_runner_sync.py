"""
Unit tests for startScan.secator.runner_sync (sync_runner_with_scan_history).

Verify that ScanHistory.scan_status is updated with SCAN_STATUS_* constants
and ScanActivity uses task status constants.
"""

from reNgine.definitions import (
    FAILED_TASK,
    RUNNING_TASK,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_VALUES,
    SUCCESS_TASK,
)
from reNgine.utilities.domain import get_domain_for_scan_by_name
from reNgine.utilities.logger import get_secator_api_logger
from startScan.models import ScanActivity, ScanHistory, SecatorRunner
from startScan.secator.runner_sync import sync_runner_with_scan_history
from utils.test_base import BaseTestCase


class SyncRunnerWithScanHistoryTestCase(BaseTestCase):
    """Tests for sync_runner_with_scan_history: ScanHistory gets SCAN_STATUS_*, ScanActivity gets task status."""

    def setUp(self):
        super().setUp()
        self.logger = get_secator_api_logger()
        self.scan_history = ScanHistory.objects.get(id=self.data_generator.scan_history.id)
        self.scan_history.scan_status = SCAN_STATUS_PENDING
        self.scan_history.save(update_fields=["scan_status"])

    def _create_runner(self, runner_type="workflow", runner_data=None):
        runner_data = runner_data or {}
        domain = get_domain_for_scan_by_name(self.scan_history.id, self.data_generator.target.value)
        return SecatorRunner.objects.create(
            scan_history=self.scan_history,
            domain=domain,
            runner_type=runner_type,
            runner_name="test-workflow",
            runner_data=runner_data,
        )

    def test_running_status_sets_scan_status_running(self):
        """sync with status=RUNNING sets ScanHistory.scan_status to SCAN_STATUS_RUNNING."""
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={"status": "RUNNING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}},
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {"status": "RUNNING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}}
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SCAN_STATUS_RUNNING)

    def test_success_done_all_runners_sets_scan_status_completed(self):
        """sync with status=SUCCESS, done=True and single runner sets ScanHistory.scan_status to SCAN_STATUS_COMPLETED."""
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={
                "status": "SUCCESS",
                "done": True,
                "name": "test-workflow",
                "config": {"type": "workflow"},
            },
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {
            "status": "SUCCESS",
            "done": True,
            "name": "test-workflow",
            "config": {"type": "workflow"},
        }
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SCAN_STATUS_COMPLETED)

    def test_failed_status_sets_scan_status_failed(self):
        """sync with status=FAILED sets ScanHistory.scan_status to SCAN_STATUS_FAILED (not QUEUED)."""
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={"status": "FAILED", "done": True, "name": "test-workflow", "config": {"type": "workflow"}},
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {"status": "FAILED", "done": True, "name": "test-workflow", "config": {"type": "workflow"}}
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SCAN_STATUS_FAILED)

    def test_failure_status_sets_scan_status_failed(self):
        """sync with status=FAILURE sets ScanHistory.scan_status to SCAN_STATUS_FAILED."""
        secator_runner = self._create_runner(
            runner_type="scan",
            runner_data={"status": "FAILURE", "done": True, "name": "test-scan", "config": {"type": "scan"}},
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {"status": "FAILURE", "done": True, "name": "test-scan", "config": {"type": "scan"}}
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SCAN_STATUS_FAILED)

    def test_pending_when_scan_running_is_blocked(self):
        """PENDING status does not overwrite scan when ScanHistory is already RUNNING."""
        self.scan_history.scan_status = SCAN_STATUS_RUNNING
        self.scan_history.save(update_fields=["scan_status"])
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={"status": "PENDING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}},
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {"status": "PENDING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}}
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SCAN_STATUS_RUNNING)

    def test_scan_status_remains_in_valid_values(self):
        """After sync, ScanHistory.scan_status is in SCAN_STATUS_VALUES."""
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={"status": "RUNNING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}},
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {"status": "RUNNING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}}
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        self.scan_history.refresh_from_db()
        self.assertIn(self.scan_history.scan_status, SCAN_STATUS_VALUES)

    def test_scan_activity_receives_task_status(self):
        """ScanActivity created/updated by sync uses task status (e.g. RUNNING_TASK, SUCCESS_TASK)."""
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={"status": "RUNNING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}},
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {"status": "RUNNING", "done": False, "name": "test-workflow", "config": {"type": "workflow"}}
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        activity = ScanActivity.objects.filter(scan_of=self.scan_history, name="test-workflow").first()
        self.assertIsNotNone(activity)
        self.assertEqual(activity.status, RUNNING_TASK)

    def test_scan_activity_success_task_on_success_sync(self):
        """When runner syncs with SUCCESS and done, ScanActivity has SUCCESS_TASK."""
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={
                "status": "SUCCESS",
                "done": True,
                "name": "test-workflow",
                "config": {"type": "workflow"},
            },
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {
            "status": "SUCCESS",
            "done": True,
            "name": "test-workflow",
            "config": {"type": "workflow"},
        }
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        activity = ScanActivity.objects.filter(scan_of=self.scan_history, name="test-workflow").first()
        self.assertIsNotNone(activity)
        self.assertEqual(activity.status, SUCCESS_TASK)

    def test_scan_activity_failed_task_on_failed_sync(self):
        """When runner syncs with FAILED, ScanActivity has FAILED_TASK."""
        secator_runner = self._create_runner(
            runner_type="workflow",
            runner_data={"status": "FAILED", "done": True, "name": "test-workflow", "config": {"type": "workflow"}},
        )
        secator_runner = SecatorRunner.objects.select_related("scan_history").get(pk=secator_runner.pk)
        runner_data = {"status": "FAILED", "done": True, "name": "test-workflow", "config": {"type": "workflow"}}
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)
        activity = ScanActivity.objects.filter(scan_of=self.scan_history, name="test-workflow").first()
        self.assertIsNotNone(activity)
        self.assertEqual(activity.status, FAILED_TASK)
