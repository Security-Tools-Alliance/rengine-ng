"""
Test cases for Secator API endpoints.
Tests for SecatorRunnerCreate, SecatorRunnerUpdate, SecatorFindingCreate, SecatorFindingUpdate.
"""

from unittest.mock import MagicMock, patch

from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from reNgine.definitions import RUNNING_TASK, SUCCESS_TASK
from startScan.models import SecatorRunner, SubScan
from utils.test_base import BaseTestCase


class TestSecatorRunnerCreate(BaseTestCase):
    """Test cases for SecatorRunnerCreate endpoint."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.url = reverse("api:secator_runner_create")

    def test_create_runner_success(self):
        """Test successful runner creation."""
        runner_data = {
            "config": {"type": "workflow", "name": "test_workflow"},
            "context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
            },
            "status": "RUNNING",
        }
        response = self.client.post(self.url, runner_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn("id", response.data)

    def test_create_runner_minimal_data(self):
        """Test runner creation with minimal data."""
        runner_data = {
            "config": {"type": "task", "name": "test_task"},
        }
        response = self.client.post(self.url, runner_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    def test_create_runner_links_subscan_when_subscan_id_in_context(self):
        """Test that creating a runner with subscan_id in context updates SubScan.secator_runner_id."""
        from startScan.models import SecatorRunner, SubScan

        subscan = SubScan.objects.create(
            scan_history=self.data_generator.scan_history,
            subdomain=self.data_generator.subdomain,
            type="nuclei",
            start_scan_date=self.data_generator.scan_history.start_scan_date,
            status=RUNNING_TASK,
        )
        self.assertIsNone(subscan.secator_runner_id)
        runner_data = {
            "config": {"type": "task", "name": "nuclei"},
            "context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
                "subscan_id": subscan.id,
            },
            "status": "RUNNING",
        }
        response = self.client.post(self.url, runner_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        runner_id = response.data["id"]
        subscan.refresh_from_db()
        self.assertEqual(subscan.secator_runner_id, int(runner_id))
        self.assertTrue(SecatorRunner.objects.filter(id=runner_id).exists())

    def test_create_runner_invalid_data(self):
        """Test runner creation with invalid data format."""
        runner_data = "not a dict"
        response = self.client.post(self.url, runner_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])


class TestSecatorRunnerUpdate(BaseTestCase):
    """Test cases for SecatorRunnerUpdate endpoint."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_update_runner_success(self):
        """Test successful runner update."""
        runner = SecatorRunner.objects.create(
            runner_type="task",
            runner_name="test_task",
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
            runner_data={"status": "RUNNING"},
        )
        url = reverse("api:secator_runner_update", kwargs={"runner_id": runner.id})
        update_data = {
            "status": "COMPLETED",
            "progress": 100,
        }
        response = self.client.put(url, update_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["id"], str(runner.id))

    def test_update_runner_with_error(self):
        """Test runner update with error status."""
        runner = SecatorRunner.objects.create(
            runner_type="task",
            runner_name="test_task",
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
            runner_data={"status": "RUNNING"},
        )
        url = reverse("api:secator_runner_update", kwargs={"runner_id": runner.id})
        update_data = {
            "status": "FAILED",
            "error": "Connection timeout",
        }
        response = self.client.put(url, update_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    @override_settings(SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND=False)
    def test_update_runner_terminal_status_sets_subscan_stop_scan_date(self):
        """When runner update has terminal status (SUCCESS), linked subscan gets stop_scan_date and status."""
        scan_history = self.data_generator.scan_history
        runner = SecatorRunner.objects.create(
            runner_type="task",
            runner_name="nuclei",
            scan_history=scan_history,
            domain=self.data_generator.domain,
            runner_data={"status": "RUNNING", "done": False},
        )
        subscan = SubScan.objects.create(
            scan_history=scan_history,
            subdomain=self.data_generator.subdomain,
            type="nuclei",
            start_scan_date=scan_history.start_scan_date,
            status=RUNNING_TASK,
            stop_scan_date=None,
            secator_runner=runner,
        )
        self.assertIsNone(subscan.stop_scan_date)

        url = reverse("api:secator_runner_update", kwargs={"runner_id": runner.id})
        update_data = {
            "config": {"type": "task", "name": "nuclei"},
            "status": "SUCCESS",
            "done": True,
        }
        response = self.client.put(url, update_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

        subscan.refresh_from_db()
        self.assertIsNotNone(subscan.stop_scan_date)
        self.assertEqual(subscan.status, SUCCESS_TASK)


class TestSecatorFindingCreate(BaseTestCase):
    """Test cases for SecatorFindingCreate endpoint."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.url = reverse("api:secator_finding_create")

    def test_create_finding_missing_type(self):
        """Test finding creation with missing type."""
        finding_data = {
            "name": "test_finding",
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])
        self.assertIn("error", response.data)

    def test_create_finding_unknown_type(self):
        """Test finding creation with unknown type."""
        finding_data = {
            "_type": "unknown_type",
            "name": "test_finding",
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn("unknown_type_", response.data["id"])

    @patch(
        "reNgine.services.repositories.subdomain_repository.SubdomainRepository.save_from_secator",
        return_value=MagicMock(id=123),
    )
    def test_create_subdomain_finding(self, mock_save_from_secator):
        """Test creating a subdomain finding."""
        finding_data = {
            "_type": "subdomain",
            "name": "test.example.com",
            "host": "test.example.com",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_save_from_secator.assert_called_once()

    @patch(
        "reNgine.services.repositories.vulnerability_repository.VulnerabilityRepository.save_from_secator",
        return_value=MagicMock(id=456),
    )
    def test_create_vulnerability_finding(self, mock_save_from_secator):
        """Test creating a vulnerability finding."""
        finding_data = {
            "_type": "vulnerability",
            "name": "SQL Injection",
            "matched_at": "http://example.com/page?id=1",
            "severity": "high",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_save_from_secator.assert_called_once()

    @patch(
        "reNgine.services.repositories.ip_repository.IpRepository.save_from_secator",
        return_value=MagicMock(id=789),
    )
    def test_create_ip_finding(self, mock_save_from_secator):
        """Test creating an IP finding."""
        finding_data = {
            "_type": "ip",
            "ip": "192.168.1.1",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_save_from_secator.assert_called_once()

    def test_create_finding_without_context(self):
        """Test finding creation without scan context returns 400."""
        finding_data = {
            "_type": "subdomain",
            "name": "test.example.com",
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])
        self.assertIn("error", response.data)

    @patch(
        "reNgine.services.repositories.subdomain_repository.SubdomainRepository.save_from_secator",
        return_value=None,
    )
    def test_create_finding_repository_returns_none(self, mock_save_from_secator):
        """Test finding creation when repository returns None (validation error)."""
        finding_data = {
            "_type": "subdomain",
            "name": "invalid_subdomain",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertFalse(response.data["status"])
        self.assertIn("error", response.data)
        mock_save_from_secator.assert_called_once()


class TestSecatorFindingUpdate(BaseTestCase):
    """Test cases for SecatorFindingUpdate endpoint."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_update_finding_metadata_type(self):
        """Test finding update with metadata type (should be ignored)."""
        finding_id = "test-finding-123"
        url = reverse("api:secator_finding_update", kwargs={"finding_id": finding_id})
        update_data = {
            "_type": "warning",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
            },
        }
        response = self.client.put(url, update_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn("message", response.data)

    def test_update_finding_invalid_data(self):
        """Test finding update with invalid data format."""
        finding_id = "test-finding-456"
        url = reverse("api:secator_finding_update", kwargs={"finding_id": finding_id})
        response = self.client.put(url, "not a dict", content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])


class TestSecatorAPIAuthentication(BaseTestCase):
    """Test cases for Secator API authentication."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        with patch("dashboard.views.messages.add_message", lambda *args, **kwargs: None):
            self.client.logout()

    def test_runner_create_unauthenticated(self):
        """Test runner creation without authentication."""
        url = reverse("api:secator_runner_create")
        runner_data = {"config": {"type": "workflow", "name": "test"}}
        response = self.client.post(url, runner_data, content_type="application/json")
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_finding_create_unauthenticated(self):
        """Test finding creation without authentication."""
        url = reverse("api:secator_finding_create")
        finding_data = {"_type": "subdomain", "name": "test.example.com"}
        response = self.client.post(url, finding_data, content_type="application/json")
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])


class TestGetSecatorInputTypesAndTargets(BaseTestCase):
    """Integration tests for GetSecatorInputTypesAndTargets API."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.data_generator.create_essential_scan_engine_setup()
        self.secator_workflow = self.data_generator.create_secator_workflow()
        self.secator_scan = self.data_generator.create_secator_scan()
        self.secator_task = self.data_generator.create_secator_task()
        self.target = self.data_generator.target
        self.domain = self.data_generator.domain
        self.subdomain = self.data_generator.subdomain
        self.url = reverse("api:get_secator_input_types_targets")

    def test_requires_target_id_or_subdomain_ids(self):
        """API returns 400 when neither target_id nor subdomain_ids provided."""
        response = self.client.get(
            self.url,
            {"workflow_id": self.secator_workflow.id},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_requires_exactly_one_workflow_scan_task(self):
        """API returns 400 when none or multiple of workflow_id/scan_id/task_id provided."""
        response = self.client.get(
            self.url,
            {"target_id": self.target.id},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response2 = self.client.get(
            self.url,
            {
                "target_id": self.target.id,
                "workflow_id": self.secator_workflow.id,
                "scan_id": self.secator_scan.id,
            },
        )
        self.assertEqual(response2.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("reNgine.secator.services.input_type_service.InputTypeService.get_input_types")
    def test_success_with_workflow_id_and_target_id(self, mock_get_input_types):
        """API returns input_types and proposed_targets when workflow_id and target_id provided."""
        mock_get_input_types.return_value = ["host"]
        response = self.client.get(
            self.url,
            {
                "target_id": self.target.id,
                "workflow_id": self.secator_workflow.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("input_types", response.data)
        self.assertEqual(response.data["input_types"], ["host"])
        self.assertIn("proposed_targets", response.data)
        self.assertIn("targets_by_type", response.data)
        self.assertIn("total_count", response.data)

    @patch("reNgine.secator.services.input_type_service.InputTypeService.get_input_types")
    def test_success_with_scan_name_and_target_id(self, mock_get_input_types):
        """API returns data when scan_name and target_id provided."""
        mock_get_input_types.return_value = ["domain"]
        response = self.client.get(
            self.url,
            {
                "target_id": self.target.id,
                "scan_name": "domain",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["input_types"], ["domain"])

    @patch("reNgine.secator.services.input_type_service.InputTypeService.get_input_types")
    def test_resolves_target_id_from_subdomain_ids(self, mock_get_input_types):
        """API resolves target_id from subdomain_ids when target_id not provided."""
        mock_get_input_types.return_value = ["host"]
        response = self.client.get(
            self.url,
            {
                "subdomain_ids": str(self.subdomain.id),
                "workflow_id": self.secator_workflow.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("input_types", response.data)
