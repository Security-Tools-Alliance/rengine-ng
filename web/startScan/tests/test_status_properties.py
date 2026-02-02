"""
Tests for status properties in ScanHistory, SubScan, ScanActivity, and Command models.
Tests the new status_string and status_code properties that read from SecatorRunner.
"""

from django.utils import timezone

from reNgine.definitions import ABORTED_TASK, INITIATED_TASK, SUCCESS_TASK
from startScan.models import ScanActivity, SecatorRunner, SubScan
from utils.test_base import BaseTestCase


class TestScanHistoryStatusProperties(BaseTestCase):
    """Test status properties for ScanHistory model."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.scan_history = self.data_generator.scan_history

    def test_status_string_legacy_scan(self):
        """Test status_string for legacy scans returns scan_status as string."""
        self.scan_history.scan_status = SUCCESS_TASK
        self.scan_history.is_legacy_scan = True
        self.scan_history.save()
        # Force legacy scan - should not query for runners
        with self.assertNumQueries(0):
            status_str = self.scan_history.status_string
        self.assertEqual(status_str, str(SUCCESS_TASK))

    def test_status_string_secator_scan_with_runner_status(self):
        """Test status_string for Secator scans with runner status."""
        # Create SecatorRunner for this scan
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="SUCCESS",
            celery_id="test-celery-id",
        )
        self.scan_history._main_runner = runner

        status_str = self.scan_history.status_string
        self.assertEqual(status_str, "SUCCESS")

    def test_status_string_secator_scan_with_runner_data(self):
        """Test status_string for Secator scans with status in runner_data."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            runner_data={"status": "RUNNING"},
            celery_id="test-celery-id",
        )
        self.scan_history._main_runner = runner

        status_str = self.scan_history.status_string
        self.assertEqual(status_str, "RUNNING")

    def test_status_string_secator_scan_revoked(self):
        """Test status_string for Secator scans with REVOKED status."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="REVOKED",
            celery_id="test-celery-id",
        )
        self.scan_history._main_runner = runner

        status_str = self.scan_history.status_string
        self.assertEqual(status_str, "REVOKED")

    def test_status_code_legacy_scan(self):
        """Test status_code for legacy scans returns scan_status."""
        self.scan_history.scan_status = SUCCESS_TASK
        self.scan_history.is_legacy_scan = True
        self.scan_history.save()

        status_code = self.scan_history.status_code
        self.assertEqual(status_code, SUCCESS_TASK)

    def test_status_code_secator_scan_success(self):
        """Test status_code for Secator scans maps SUCCESS correctly."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="SUCCESS",
            celery_id="test-celery-id",
        )
        self.scan_history._main_runner = runner

        status_code = self.scan_history.status_code
        self.assertEqual(status_code, SUCCESS_TASK)

    def test_status_code_secator_scan_revoked(self):
        """Test status_code for Secator scans maps REVOKED to ABORTED_TASK."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="REVOKED",
            celery_id="test-celery-id",
        )
        self.scan_history._main_runner = runner

        status_code = self.scan_history.status_code
        self.assertEqual(status_code, ABORTED_TASK)

    def test_status_code_secator_scan_non_numeric_fallback(self):
        """Test status_code handles non-numeric status strings safely."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="UNKNOWN_STATUS",
            celery_id="test-celery-id",
        )
        self.scan_history._main_runner = runner

        status_code = self.scan_history.status_code
        # Should return INITIATED_TASK as safe default
        self.assertEqual(status_code, INITIATED_TASK)

    def test_display_runner_type_and_scan_name_task_only(self):
        """Task-only Secator scans should display `Task: <task list>`."""
        # Ensure this scan is treated as a Secator scan
        self.scan_history.is_legacy_scan = False
        self.scan_history.save()

        SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="task",
            runner_name="cariddi",
            status="SUCCESS",
            celery_id="task-1",
        )
        SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="task",
            runner_name="katana",
            status="SUCCESS",
            celery_id="task-2",
        )

        # UI composes `display_runner_type + ": " + display_scan_name`
        self.assertEqual(self.scan_history.display_runner_type, "Task")
        self.assertEqual(self.scan_history.display_scan_name, "cariddi, katana")

    def test_display_runner_type_and_scan_name_prefers_workflow_runner(self):
        """If a workflow/scan runner exists, display should use it over tasks."""
        self.scan_history.is_legacy_scan = False
        self.scan_history.save()

        SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="task",
            runner_name="cariddi",
            status="SUCCESS",
            celery_id="task-1",
        )
        SecatorRunner.objects.create(
            scan_history=self.scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="RUNNING",
            celery_id="wf-1",
        )

        self.assertEqual(self.scan_history.display_runner_type, "Workflow")
        self.assertEqual(self.scan_history.display_scan_name, "Test Workflow")


class TestSubScanStatusProperties(BaseTestCase):
    """Test status properties for SubScan model."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        # Always use existing subscan from data_generator
        # The data_generator.create_project_full() already creates subscans
        if self.data_generator.subscans and len(self.data_generator.subscans) > 0:
            self.subscan = self.data_generator.subscans[0]
        else:
            # Create subscan using data_generator method
            subscans = self.data_generator.create_subscan()
            self.subscan = subscans[-1] if subscans else None
            if not self.subscan:
                # Fallback: create minimal subscan with existing objects
                scan_history = self.data_generator.scan_history
                self.subscan = SubScan.objects.create(
                    scan_history=scan_history,
                    subdomain=self.data_generator.subdomain,
                    type="active",
                    status=-1,
                )

    def test_status_string_legacy_scan(self):
        """Test status_string for legacy scans returns status field as string."""
        # Set status directly on the field
        self.subscan.status = SUCCESS_TASK
        self.subscan.save()

        status_str = self.subscan.status_string
        self.assertEqual(status_str, str(SUCCESS_TASK))

    def test_status_string_secator_scan_with_main_runner(self):
        """Test status_string for Secator scans uses cached _main_runner."""
        # Use scan_history from data_generator to ensure it exists
        scan_history = self.data_generator.scan_history
        runner = SecatorRunner.objects.create(
            scan_history=scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="RUNNING",
            celery_id="test-celery-id",
        )
        scan_history._main_runner = runner
        # Update subscan to use the same scan_history
        self.subscan.scan_history = scan_history
        self.subscan.save()

        status_str = self.subscan.status_string
        self.assertEqual(status_str, "RUNNING")

    def test_status_string_secator_scan_revoked(self):
        """Test status_string for Secator scans with REVOKED status."""
        # Use scan_history from data_generator to ensure it exists
        scan_history = self.data_generator.scan_history
        runner = SecatorRunner.objects.create(
            scan_history=scan_history,
            runner_type="workflow",
            runner_name="test_workflow",
            status="REVOKED",
            celery_id="test-celery-id",
        )
        scan_history._main_runner = runner
        # Update subscan to use the same scan_history
        self.subscan.scan_history = scan_history
        self.subscan.save()

        status_str = self.subscan.status_string
        self.assertEqual(status_str, "REVOKED")


class TestSubScanScanEngineUsed(BaseTestCase):
    """Test scan_engine_used property for SubScan model."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        if self.data_generator.subscans and len(self.data_generator.subscans) > 0:
            self.subscan = self.data_generator.subscans[0]
        else:
            subscans = self.data_generator.create_subscan()
            self.subscan = subscans[-1] if subscans else None
        if not self.subscan:
            self.subscan = SubScan.objects.create(
                scan_history=self.data_generator.scan_history,
                subdomain=self.data_generator.subdomain,
                type="subfinder",
                status=1,
            )

    def test_scan_engine_used_legacy_with_engine(self):
        """Test scan_engine_used for legacy subscan shows Legacy: engine_name."""
        from scanEngine.models import EngineType

        engine = EngineType.objects.filter(engine_name__isnull=False).first() or EngineType.objects.create(
            engine_name="Test Legacy Engine",
            scan_type="internet",
            yaml_configuration="",
        )
        self.subscan.engine = engine
        self.subscan.secator_runner = None
        self.subscan.save()
        self.assertEqual(self.subscan.display_runner_type, "Legacy")
        self.assertEqual(self.subscan.display_scan_name, engine.engine_name)
        self.assertEqual(self.subscan.scan_engine_used, f"Legacy: {engine.engine_name}")

    def test_scan_engine_used_legacy_without_engine_uses_type(self):
        """Test scan_engine_used for legacy subscan without engine shows Task: type."""
        self.subscan.engine = None
        self.subscan.secator_runner = None
        self.subscan.type = "nuclei"
        self.subscan.save()
        self.assertEqual(self.subscan.display_runner_type, "Task")
        self.assertIn(
            self.subscan.display_scan_name,
            ("nuclei", self.subscan.get_task_name_str()),
        )
        self.assertTrue(
            self.subscan.scan_engine_used.startswith("Task: "),
            f"scan_engine_used should start with 'Task: ', got {self.subscan.scan_engine_used!r}",
        )

    def test_scan_engine_used_secator_with_runner_name(self):
        """Test scan_engine_used for Secator subscan shows Task: runner_name."""
        runner = SecatorRunner.objects.create(
            scan_history=self.data_generator.scan_history,
            runner_type="task",
            runner_name="nuclei",
            status="RUNNING",
            celery_id="test-celery-id",
        )
        self.subscan.secator_runner = runner
        self.subscan.engine = None
        self.subscan.type = "nuclei"
        self.subscan.save()
        self.assertEqual(self.subscan.display_runner_type, "Task")
        self.assertEqual(self.subscan.display_scan_name, "nuclei")
        self.assertEqual(self.subscan.scan_engine_used, "Task: nuclei")

    def test_scan_engine_used_secator_without_runner_name_uses_type(self):
        """Test scan_engine_used for Secator subscan without runner_name shows Task: type."""
        runner = SecatorRunner.objects.create(
            scan_history=self.data_generator.scan_history,
            runner_type="task",
            runner_name="",
            status="RUNNING",
            celery_id="test-celery-id",
        )
        self.subscan.secator_runner = runner
        self.subscan.engine = None
        self.subscan.type = "httpx"
        self.subscan.save()
        self.assertEqual(self.subscan.display_runner_type, "Task")
        self.assertIn(
            self.subscan.display_scan_name,
            ("httpx", self.subscan.get_task_name_str()),
        )
        self.assertTrue(
            self.subscan.scan_engine_used.startswith("Task: "),
            f"scan_engine_used should start with 'Task: ', got {self.subscan.scan_engine_used!r}",
        )


class TestScanActivityStatusProperties(BaseTestCase):
    """Test status properties for ScanActivity model."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.scan_activity = self.data_generator.create_scan_activity()

    def test_status_string_legacy_scan(self):
        """Test status_string for legacy scans returns status field as string."""
        self.scan_activity.status = SUCCESS_TASK
        self.scan_activity.save()

        status_str = self.scan_activity.status_string
        self.assertEqual(status_str, str(SUCCESS_TASK))

    def test_status_string_secator_scan_with_runner(self):
        """Test status_string for Secator scans reads from runner."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_activity.scan_of,
            runner_type="task",
            runner_name="test_task",
            status="SUCCESS",
            celery_id="test-celery-id",
        )
        self.scan_activity.runner_id = runner
        self.scan_activity.save()

        status_str = self.scan_activity.status_string
        self.assertEqual(status_str, "SUCCESS")

    def test_status_string_secator_scan_revoked(self):
        """Test status_string for Secator scans with REVOKED status."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_activity.scan_of,
            runner_type="task",
            runner_name="test_task",
            status="REVOKED",
            celery_id="test-celery-id",
        )
        self.scan_activity.runner_id = runner
        self.scan_activity.save()

        status_str = self.scan_activity.status_string
        self.assertEqual(status_str, "REVOKED")

    def test_status_code_secator_scan_revoked(self):
        """Test status_code for Secator scans maps REVOKED to ABORTED_TASK."""
        runner = SecatorRunner.objects.create(
            scan_history=self.scan_activity.scan_of,
            runner_type="task",
            runner_name="test_task",
            status="REVOKED",
            celery_id="test-celery-id",
        )
        self.scan_activity.runner_id = runner
        self.scan_activity.save()

        status_code = self.scan_activity.status_code
        self.assertEqual(status_code, ABORTED_TASK)


class TestCommandStatusProperties(BaseTestCase):
    """Test status properties for Command model."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.command = self.data_generator.create_command()

    def test_status_string_legacy_scan(self):
        """Test status_string for legacy scans returns status field."""
        self.command.status = "SUCCESS"
        self.command.save()

        status_str = self.command.status_string
        self.assertEqual(status_str, "SUCCESS")

    def test_status_string_secator_scan_with_activity_runner(self):
        """Test status_string for Secator scans reads from activity's runner."""
        runner = SecatorRunner.objects.create(
            scan_history=self.command.scan_history,
            runner_type="task",
            runner_name="test_task",
            status="RUNNING",
            celery_id="test-celery-id",
        )
        activity = ScanActivity.objects.create(
            scan_of=self.command.scan_history,
            title="Test Activity",
            time=timezone.now(),
            status=INITIATED_TASK,  # Required non-null field
            runner_id=runner,
        )
        self.command.activity = activity
        self.command.save()

        status_str = self.command.status_string
        self.assertEqual(status_str, "RUNNING")

    def test_status_string_secator_scan_revoked(self):
        """Test status_string for Secator scans with REVOKED status."""
        runner = SecatorRunner.objects.create(
            scan_history=self.command.scan_history,
            runner_type="task",
            runner_name="test_task",
            status="REVOKED",
            celery_id="test-celery-id",
        )
        activity = ScanActivity.objects.create(
            scan_of=self.command.scan_history,
            title="Test Activity",
            time=timezone.now(),
            status=INITIATED_TASK,  # Required non-null field
            runner_id=runner,
        )
        self.command.activity = activity
        self.command.save()

        status_str = self.command.status_string
        self.assertEqual(status_str, "REVOKED")

    def test_status_code_secator_scan_revoked(self):
        """Test status_code for Secator scans maps REVOKED to ABORTED_TASK."""
        runner = SecatorRunner.objects.create(
            scan_history=self.command.scan_history,
            runner_type="task",
            runner_name="test_task",
            status="REVOKED",
            celery_id="test-celery-id",
        )
        activity = ScanActivity.objects.create(
            scan_of=self.command.scan_history,
            title="Test Activity",
            time=timezone.now(),
            status=INITIATED_TASK,  # Required non-null field
            runner_id=runner,
        )
        self.command.activity = activity
        self.command.save()

        # Command doesn't have status_code property, only status_string
        # We can test that status_string returns REVOKED
        status_str = self.command.status_string
        self.assertEqual(status_str, "REVOKED")
