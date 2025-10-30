"""
Tests for Secator tasks functionality.
"""

from unittest.mock import Mock, patch

from django.test import override_settings
from django.utils import timezone

from reNgine.tasks.scan import _build_enriched_targets, initiate_scan
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

    def test_initiate_scan_exists(self):
        """Test that initiate_scan function exists and is no longer a Celery task."""
        self.assertTrue(callable(initiate_scan))
        # Verify it's not a Celery task anymore
        self.assertFalse(hasattr(initiate_scan, "delay"))
        self.assertFalse(hasattr(initiate_scan, "apply_async"))

    def test_build_enriched_targets_basic(self):
        """Test building enriched targets with basic domain only."""
        targets = _build_enriched_targets(
            domain=self.domain,
            imported_subdomains=[],
            out_of_scope_subdomains=[],
            url_filter="",
            scan_existing_elements=False,
        )

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0], f"{self.domain_name}")

    def test_build_enriched_targets_with_imported_subdomains(self):
        """Test building enriched targets with imported subdomains."""
        imported_subdomains = [f"imported1.{self.domain_name}", f"imported2.{self.domain_name}"]

        targets = _build_enriched_targets(
            domain=self.domain,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=[],
            url_filter="",
            scan_existing_elements=False,
        )

        self.assertEqual(len(targets), 3)
        self.assertIn(f"{self.domain_name}", targets)
        self.assertIn(f"imported1.{self.domain_name}", targets)
        self.assertIn(f"imported2.{self.domain_name}", targets)

    def test_build_enriched_targets_with_existing_elements(self):
        """Test building enriched targets with existing elements."""
        targets = _build_enriched_targets(
            domain=self.domain,
            imported_subdomains=[],
            out_of_scope_subdomains=[],
            url_filter="",
            scan_existing_elements=True,
        )

        # Should include main domain + existing subdomains
        self.assertGreaterEqual(len(targets), 3)
        self.assertIn(f"{self.domain_name}", targets)
        self.assertIn(f"sub1.{self.domain_name}", targets)
        self.assertIn(f"sub2.{self.domain_name}", targets)

    def test_build_enriched_targets_with_url_filter(self):
        """Test building enriched targets with URL filter."""
        targets = _build_enriched_targets(
            domain=self.domain,
            imported_subdomains=[f"imported1.{self.domain_name}"],
            out_of_scope_subdomains=[],
            url_filter="/admin",
            scan_existing_elements=False,
        )

        self.assertEqual(len(targets), 2)
        self.assertIn(f"{self.domain_name}/admin", targets)
        self.assertIn(f"imported1.{self.domain_name}/admin", targets)

    def test_build_enriched_targets_with_out_of_scope_filtering(self):
        """Test building enriched targets with out-of-scope filtering."""
        imported_subdomains = [f"imported1.{self.domain_name}", f"imported2.{self.domain_name}"]
        out_of_scope_subdomains = [f"imported2.{self.domain_name}"]

        targets = _build_enriched_targets(
            domain=self.domain,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=out_of_scope_subdomains,
            url_filter="",
            scan_existing_elements=False,
        )

        self.assertEqual(len(targets), 2)
        self.assertIn(f"{self.domain_name}", targets)
        self.assertIn(f"imported1.{self.domain_name}", targets)
        self.assertNotIn(f"imported2.{self.domain_name}", targets)

    def test_build_enriched_targets_duplicate_removal(self):
        """Test that duplicate targets are removed."""
        # Create a subdomain that matches an imported one
        imported_subdomains = [f"sub1.{self.domain_name}"]  # This already exists

        targets = _build_enriched_targets(
            domain=self.domain,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=[],
            url_filter="",
            scan_existing_elements=True,
        )

        # Should not have duplicates
        self.assertEqual(len(targets), len(set(targets)))
        self.assertIn(f"{self.domain_name}", targets)
        self.assertIn(f"sub1.{self.domain_name}", targets)
        self.assertIn(f"sub2.{self.domain_name}", targets)

    def test_build_enriched_targets_invalid_imported_subdomain(self):
        """Test that invalid imported subdomains are filtered out."""
        imported_subdomains = [
            f"valid.{self.domain_name}",
            "invalid.otherdomain.com",  # Not a subdomain of f"{self.domain_name}"
            "",  # Empty
            "   ",  # Whitespace only
        ]

        targets = _build_enriched_targets(
            domain=self.domain,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=[],
            url_filter="",
            scan_existing_elements=False,
        )

        self.assertEqual(len(targets), 2)
        self.assertIn(f"{self.domain_name}", targets)
        self.assertIn(f"valid.{self.domain_name}", targets)
        self.assertNotIn("invalid.otherdomain.com", targets)

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("reNgine.services.scan.scan_orchestrator.ScanOrchestrator")
    def test_initiate_scan_passes_parameters(self, mock_orchestrator):
        """Test that initiate_scan passes all reNgine parameters correctly."""
        from reNgine.tasks.scan import initiate_scan
        from scanEngine.models import SecatorScan

        # Create mock SecatorScan
        mock_secator_scan = Mock(spec=SecatorScan)
        mock_secator_scan.execution_mode = "workflow"
        mock_secator_scan.workflow = Mock()
        mock_secator_scan.workflow.name = "test_workflow"

        mock_orchestrator.return_value.execute_scan.return_value = {"status": "success"}

        imported_subdomains = [f"imported1.{self.domain_name}"]
        out_of_scope_subdomains = [f"outofscope.{self.domain_name}"]
        url_filter = "/admin"
        scan_existing_elements = True
        initiated_by_id = self.user.id

        with patch("scanEngine.models.SecatorScan.objects.get", return_value=mock_secator_scan):
            with patch("targetApp.models.Domain.objects.get", return_value=self.domain):
                with patch("startScan.models.ScanHistory.objects.get", return_value=self.scan_history):
                    initiate_scan(
                        scan_history_id=self.scan_history.id,
                        domain_id=self.domain.id,
                        secator_scan_id=1,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        scan_existing_elements=scan_existing_elements,
                        initiated_by_id=initiated_by_id,
                    )

                    # Verify orchestrator was called with correct parameters
                    mock_orchestrator.return_value.execute_scan.assert_called_once()
                    call_args = mock_orchestrator.return_value.execute_scan.call_args

                    # Check that rengine_context contains the parameters
                    config = call_args[1]["config"]
                    rengine_context = config["rengine_context"]

                    self.assertEqual(rengine_context["imported_subdomains"], imported_subdomains)
                    self.assertEqual(rengine_context["out_of_scope_subdomains"], out_of_scope_subdomains)
                    self.assertEqual(rengine_context["url_filter"], url_filter)
                    self.assertEqual(rengine_context["scan_existing_elements"], scan_existing_elements)
                    self.assertEqual(rengine_context["initiated_by_id"], initiated_by_id)

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("reNgine.services.scan.scan_orchestrator.ScanOrchestrator")
    def test_initiate_scan_with_rengine_context(self, mock_orchestrator):
        """Test that initiate_scan creates proper reNgine context."""
        from reNgine.tasks.scan import initiate_scan
        from scanEngine.models import SecatorScan

        # Create mock SecatorScan
        mock_secator_scan = Mock(spec=SecatorScan)
        mock_secator_scan.execution_mode = "workflow"
        mock_secator_scan.workflow = Mock()
        mock_secator_scan.workflow.name = "test_workflow"

        with patch("scanEngine.models.SecatorScan.objects.get", return_value=mock_secator_scan):
            with patch("targetApp.models.Domain.objects.get", return_value=self.domain):
                with patch("startScan.models.ScanHistory.objects.get", return_value=self.scan_history):
                    mock_orchestrator.return_value.execute_scan.return_value = {"status": "success"}

                    initiate_scan(
                        scan_history_id=self.scan_history.id,
                        domain_id=self.domain.id,
                        secator_scan_id=1,
                        imported_subdomains=[f"imported1.{self.domain_name}"],
                        out_of_scope_subdomains=[f"outofscope.{self.domain_name}"],
                        url_filter="/admin",
                        scan_existing_elements=True,
                        initiated_by_id=self.user.id,
                    )

                    # Verify orchestrator was called with enriched targets and context
                    mock_orchestrator.return_value.execute_scan.assert_called_once()
                    call_args = mock_orchestrator.return_value.execute_scan.call_args

                    # Check that targets are enriched
                    targets = call_args[1]["targets"]
                    self.assertIn(f"{self.domain_name}/admin", targets)
                    self.assertIn(f"imported1.{self.domain_name}/admin", targets)

                    # Check that reNgine context is passed
                    config = call_args[1]["config"]
                    self.assertIn("rengine_context", config)
                    rengine_context = config["rengine_context"]
                    self.assertEqual(rengine_context["imported_subdomains"], [f"imported1.{self.domain_name}"])
                    self.assertEqual(rengine_context["out_of_scope_subdomains"], [f"outofscope.{self.domain_name}"])
                    self.assertEqual(rengine_context["url_filter"], "/admin")
                    self.assertEqual(rengine_context["scan_existing_elements"], True)
                    self.assertEqual(rengine_context["initiated_by_id"], self.user.id)
