"""
Tests for Secator tasks functionality.
"""

from unittest.mock import Mock, patch

from django.test import override_settings
from django.utils import timezone

from reNgine.secator import build_enriched_targets, initiate_secator_scan
from startScan.models import Domain, Subdomain
from utils.test_base import BaseTestCase


class TestSecatorTasks(BaseTestCase):
    """Test cases for Secator tasks."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create test domain with unique name
        import uuid

        unique_id = str(uuid.uuid4())[:8]
        self.domain_name = f"test-{unique_id}.com"

        # Create test domain
        self.domain = Domain.objects.create(
            name=self.domain_name, project=self.data_generator.project, insert_date=timezone.now()
        )

        # Create test scan history
        self.scan_history = self.data_generator.create_scan_history()

        # Create some existing subdomains
        self.existing_subdomain1 = Subdomain.objects.create(
            name=f"sub1.{self.domain_name}", target_domain=self.domain, scan_history=self.scan_history
        )
        self.existing_subdomain2 = Subdomain.objects.create(
            name=f"sub2.{self.domain_name}", target_domain=self.domain, scan_history=self.scan_history
        )

    def test_initiate_secator_scan_exists(self):
        """Test that initiate_secator_scan function exists and is no longer a Celery task."""
        self.assertTrue(callable(initiate_secator_scan))
        # Verify it's not a Celery task anymore
        self.assertFalse(hasattr(initiate_secator_scan, "delay"))
        self.assertFalse(hasattr(initiate_secator_scan, "apply_async"))

    def test_build_enriched_targets_basic(self):
        """Test building enriched targets with domain_id and input_types (host)."""
        targets = build_enriched_targets(
            domain_id=self.domain.id,
            input_types=["host"],
            subdomain_ids=[],
            out_of_scope_subdomains=[],
            url_filter="",
        )
        self.assertGreaterEqual(len(targets), 1)
        self.assertIn(self.domain_name, targets)

    def test_build_enriched_targets_with_subdomains(self):
        """Test building enriched targets includes domain and existing subdomains."""
        targets = build_enriched_targets(
            domain_id=self.domain.id,
            input_types=["host"],
            subdomain_ids=[],
            out_of_scope_subdomains=[],
            url_filter="",
        )
        self.assertGreaterEqual(len(targets), 3)
        self.assertIn(self.domain_name, targets)
        self.assertIn(f"sub1.{self.domain_name}", targets)
        self.assertIn(f"sub2.{self.domain_name}", targets)

    def test_build_enriched_targets_with_url_filter(self):
        """Test building enriched targets with URL filter."""
        targets = build_enriched_targets(
            domain_id=self.domain.id,
            input_types=["host"],
            subdomain_ids=[],
            out_of_scope_subdomains=[],
            url_filter="/admin",
        )
        self.assertGreaterEqual(len(targets), 1)
        self.assertIn(f"{self.domain_name}/admin", targets)

    def test_build_enriched_targets_with_out_of_scope_filtering(self):
        """Test building enriched targets with out-of-scope filtering."""
        out_of_scope_subdomains = [f"sub2.{self.domain_name}"]
        targets = build_enriched_targets(
            domain_id=self.domain.id,
            input_types=["host"],
            subdomain_ids=[],
            out_of_scope_subdomains=out_of_scope_subdomains,
            url_filter="",
        )
        self.assertIn(self.domain_name, targets)
        self.assertIn(f"sub1.{self.domain_name}", targets)
        self.assertNotIn(f"sub2.{self.domain_name}", targets)

    def test_build_enriched_targets_deduplication(self):
        """Test that built targets list has no duplicates."""
        targets = build_enriched_targets(
            domain_id=self.domain.id,
            input_types=["host"],
            subdomain_ids=[],
            out_of_scope_subdomains=[],
            url_filter="",
        )
        self.assertEqual(len(targets), len(set(targets)))
        self.assertIn(self.domain_name, targets)

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("reNgine.secator.orchestrator.ScanOrchestrator")
    @patch("reNgine.secator.tasks.build_enriched_targets")
    @patch("reNgine.secator.services.input_type_service.InputTypeService.get_input_types", return_value=["host"])
    def test_initiate_secator_scan_passes_parameters(self, mock_get_input_types, mock_build_targets, mock_orchestrator):
        """Test that initiate_secator_scan passes all reNgine parameters correctly."""
        from scanEngine.models import SecatorWorkflow

        mock_build_targets.return_value = [self.domain_name]
        mock_workflow = Mock(spec=SecatorWorkflow)
        mock_workflow.name = "test_workflow"

        mock_orchestrator.return_value.execute_scan.return_value = {"status": "success"}

        imported_subdomains = [f"imported1.{self.domain_name}"]
        out_of_scope_subdomains = [f"outofscope.{self.domain_name}"]
        url_filter = "/admin"
        initiated_by_id = self.user.id

        with patch("scanEngine.models.SecatorWorkflow.objects.get", return_value=mock_workflow):
            with patch("targetApp.models.Domain.objects.get", return_value=self.domain):
                with patch("startScan.models.ScanHistory.objects.get", return_value=self.scan_history):
                    initiate_secator_scan(
                        scan_history_id=self.scan_history.id,
                        domain_id=self.domain.id,
                        execution_mode="workflow",
                        workflow_id=1,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        initiated_by_id=initiated_by_id,
                    )

                    # Verify orchestrator was called with correct parameters
                    mock_orchestrator.return_value.execute_scan.assert_called_once()
                    call_args = mock_orchestrator.return_value.execute_scan.call_args

                    # Verify config contains workflow_name
                    config = call_args[1]["config"]
                    self.assertEqual(config["workflow_name"], "test_workflow")
                    # Verify rengine_context is no longer in config
                    self.assertNotIn("rengine_context", config)

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("reNgine.secator.orchestrator.ScanOrchestrator")
    @patch("reNgine.secator.tasks.build_enriched_targets")
    @patch("reNgine.secator.services.input_type_service.InputTypeService.get_input_types", return_value=["host"])
    def test_initiate_secator_scan_with_rengine_context(
        self, mock_get_input_types, mock_build_targets, mock_orchestrator
    ):
        """Test that initiate_secator_scan creates proper reNgine context."""
        from scanEngine.models import SecatorWorkflow

        mock_build_targets.return_value = [self.domain_name, f"imported1.{self.domain_name}"]
        mock_workflow = Mock(spec=SecatorWorkflow)
        mock_workflow.name = "test_workflow"

        with patch("secator.utils.autodetect_type", return_value="host"):
            with patch("scanEngine.models.SecatorWorkflow.objects.get", return_value=mock_workflow):
                with patch("targetApp.models.Domain.objects.get", return_value=self.domain):
                    with patch("startScan.models.ScanHistory.objects.get", return_value=self.scan_history):
                        mock_orchestrator.return_value.execute_scan.return_value = {"status": "success"}

                        initiate_secator_scan(
                            scan_history_id=self.scan_history.id,
                            domain_id=self.domain.id,
                            execution_mode="workflow",
                            workflow_id=1,
                            imported_subdomains=[f"imported1.{self.domain_name}"],
                            out_of_scope_subdomains=[f"outofscope.{self.domain_name}"],
                            url_filter="/admin",
                            initiated_by_id=self.user.id,
                        )

                        mock_orchestrator.return_value.execute_scan.assert_called_once()
                        call_args = mock_orchestrator.return_value.execute_scan.call_args
                        targets = call_args[1]["targets"]
                        self.assertIn(self.domain_name, targets)
                        config = call_args[1]["config"]
                        self.assertEqual(config["workflow_name"], "test_workflow")
                        self.assertNotIn("rengine_context", config)

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("reNgine.secator.orchestrator.ScanOrchestrator")
    @patch(
        "reNgine.secator.services.input_type_service.InputTypeService.get_input_types_for_task", return_value=["host"]
    )
    def test_initiate_secator_scan_uses_targets_override(self, mock_get_input_types_for_task, mock_orchestrator):
        """Test that when targets_override is provided, build_enriched_targets is not used."""
        mock_orchestrator.return_value.execute_scan.return_value = {"status": "success"}

        mock_task = Mock()
        mock_task.task_type = "httpx"
        mock_tasks_qs = Mock()
        mock_tasks_qs.values_list.return_value = ["httpx"]
        mock_tasks_qs.__len__ = Mock(return_value=1)
        mock_tasks_qs.__iter__ = Mock(return_value=iter([mock_task]))

        override_targets = [self.domain_name, f"sub1.{self.domain_name}"]

        with patch("secator.utils.autodetect_type", return_value="host"):
            with patch("scanEngine.models.SecatorTask.objects.filter", return_value=mock_tasks_qs):
                with patch("targetApp.models.Domain.objects.get", return_value=self.domain):
                    with patch("startScan.models.ScanHistory.objects.get", return_value=self.scan_history):
                        with patch("reNgine.secator.tasks.build_enriched_targets") as mock_build:
                            initiate_secator_scan(
                                scan_history_id=self.scan_history.id,
                                domain_id=self.domain.id,
                                execution_mode="tasks",
                                task_ids=[1],
                                initiated_by_id=self.user.id,
                                targets_override=override_targets,
                            )
                            mock_build.assert_not_called()
                        mock_orchestrator.return_value.execute_scan.assert_called_once()
                        call_args = mock_orchestrator.return_value.execute_scan.call_args
                        targets = call_args[1]["targets"]
                        self.assertEqual(targets, override_targets)

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    def test_initiate_secator_scan_tasks_mode_no_active_tasks_returns_error(self):
        """When task_ids match no SecatorTask, return error status with specific message."""
        result = initiate_secator_scan(
            scan_history_id=self.scan_history.id,
            domain_id=self.domain.id,
            execution_mode="tasks",
            task_ids=[999999],
            initiated_by_id=self.user.id,
        )
        self.assertEqual(result.get("status"), "error")
        self.assertIn("No active tasks found", result.get("error", ""))
        self.assertIn("999999", result.get("error", ""))
