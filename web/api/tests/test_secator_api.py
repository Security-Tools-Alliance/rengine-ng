"""
Test cases for Secator API endpoints.
Tests for SecatorRunnerCreate, SecatorRunnerUpdate, SecatorFindingCreate, SecatorFindingUpdate.
"""

from unittest.mock import MagicMock, patch

from django.urls import reverse
from rest_framework import status

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
                "domain_id": self.data_generator.domain.id,
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
        runner_id = "test-runner-123"
        url = reverse("api:secator_runner_update", kwargs={"runner_id": runner_id})
        update_data = {
            "status": "COMPLETED",
            "progress": 100,
        }
        response = self.client.put(url, update_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["id"], runner_id)

    def test_update_runner_with_error(self):
        """Test runner update with error status."""
        runner_id = "test-runner-456"
        url = reverse("api:secator_runner_update", kwargs={"runner_id": runner_id})
        update_data = {
            "status": "FAILED",
            "error": "Connection timeout",
        }
        response = self.client.put(url, update_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])


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

    @patch("api.secator_api_base.SubdomainRepository")
    def test_create_subdomain_finding(self, mock_repo_class):
        """Test creating a subdomain finding."""
        mock_repo = MagicMock()
        mock_saved = MagicMock()
        mock_saved.id = 123
        mock_repo.save_from_secator.return_value = mock_saved
        mock_repo_class.return_value = mock_repo

        finding_data = {
            "_type": "subdomain",
            "name": "test.example.com",
            "host": "test.example.com",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "domain_id": self.data_generator.domain.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_repo.save_from_secator.assert_called_once()

    @patch("api.secator_api_base.VulnerabilityRepository")
    def test_create_vulnerability_finding(self, mock_repo_class):
        """Test creating a vulnerability finding."""
        mock_repo = MagicMock()
        mock_saved = MagicMock()
        mock_saved.id = 456
        mock_repo.save_from_secator.return_value = mock_saved
        mock_repo_class.return_value = mock_repo

        finding_data = {
            "_type": "vulnerability",
            "name": "SQL Injection",
            "matched_at": "http://example.com/page?id=1",
            "severity": "high",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "domain_id": self.data_generator.domain.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_repo.save_from_secator.assert_called_once()

    @patch("api.secator_api_base.IpRepository")
    def test_create_ip_finding(self, mock_repo_class):
        """Test creating an IP finding."""
        mock_repo = MagicMock()
        mock_saved = MagicMock()
        mock_saved.id = 789
        mock_repo.save_from_secator.return_value = mock_saved
        mock_repo_class.return_value = mock_repo

        finding_data = {
            "_type": "ip",
            "ip": "192.168.1.1",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "domain_id": self.data_generator.domain.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_repo.save_from_secator.assert_called_once()

    def test_create_finding_without_context(self):
        """Test finding creation without scan context returns success but doesn't save."""
        finding_data = {
            "_type": "subdomain",
            "name": "test.example.com",
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn("subdomain_", response.data["id"])

    @patch("api.secator_api_base.SubdomainRepository")
    def test_create_finding_repository_returns_none(self, mock_repo_class):
        """Test finding creation when repository returns None (validation error)."""
        mock_repo = MagicMock()
        mock_repo.save_from_secator.return_value = None
        mock_repo_class.return_value = mock_repo

        finding_data = {
            "_type": "subdomain",
            "name": "invalid_subdomain",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "domain_id": self.data_generator.domain.id,
            },
        }
        response = self.client.post(self.url, finding_data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertFalse(response.data["status"])
        self.assertIn("error", response.data)
        mock_repo.save_from_secator.assert_called_once()


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
                "domain_id": self.data_generator.domain.id,
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
