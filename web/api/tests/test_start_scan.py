"""
Test cases for StartScan API endpoint.
"""

from unittest.mock import patch

from django.urls import reverse
from rest_framework import status

from utils.test_base import BaseTestCase


class TestStartScanAPI(BaseTestCase):
    """Test cases for StartScan API endpoint."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.url = reverse("api:start_scan")

    @patch("api.views.start_secator_scan")
    def test_start_scan_success(self, mock_start_scan):
        """Test successful scan start returns http_status 200."""
        mock_start_scan.return_value = {
            "status": True,
            "scan_id": 1,
            "scan_status": 0,
            "domain_id": self.data_generator.domain.id,
            "domain_name": self.data_generator.domain.name,
            "execution_mode": "workflow",
            "message": "Scan started successfully",
            "http_status": 200,
        }

        data = {
            "domain_id": self.data_generator.domain.id,
            "execution_mode": "workflow",
            "workflow_id": 1,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["http_status"], 200)
        mock_start_scan.assert_called_once()

    def test_start_scan_missing_domain_id(self):
        """Test scan start with missing domain_id returns http_status 400."""
        data = {
            "execution_mode": "workflow",
            "workflow_id": 1,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["http_status"], 400)
        self.assertIn("domain_id is required", response.data["error"])

    def test_start_scan_domain_not_found(self):
        """Test scan start with non-existent domain returns http_status 404."""
        data = {
            "domain_id": 99999,
            "execution_mode": "workflow",
            "workflow_id": 1,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["http_status"], 404)
        self.assertIn("not found", response.data["error"].lower())

    @patch("api.views.start_secator_scan")
    def test_start_scan_secator_scan_not_found(self, mock_start_scan):
        """Test scan start with non-existent secator_scan_id returns http_status 404."""
        mock_start_scan.return_value = {
            "status": False,
            "error": "SecatorScan with ID 99999 not found",
            "http_status": 404,
        }

        data = {
            "domain_id": self.data_generator.domain.id,
            "secator_scan_id": 99999,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["http_status"], 404)

    def test_start_scan_missing_execution_mode(self):
        """Test scan start without execution_mode or secator_scan_id returns http_status 400."""
        data = {
            "domain_id": self.data_generator.domain.id,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["http_status"], 400)
        self.assertIn("secator_scan_id or execution_mode", response.data["error"])

    @patch("api.views.start_secator_scan")
    def test_start_scan_server_error(self, mock_start_scan):
        """Test scan start with server error returns http_status 500."""
        mock_start_scan.return_value = {
            "status": False,
            "error": "Failed to start scan due to a server error.",
            "http_status": 500,
        }

        data = {
            "domain_id": self.data_generator.domain.id,
            "execution_mode": "workflow",
            "workflow_id": 1,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["http_status"], 500)

    @patch("api.views.start_secator_scan")
    def test_start_scan_backward_compatibility_no_http_status(self, mock_start_scan):
        """Test backward compatibility when http_status is missing in result."""
        # Simulate old code that doesn't return http_status
        mock_start_scan.return_value = {
            "status": True,
            "scan_id": 1,
            "message": "Scan started successfully",
            # No http_status field
        }

        data = {
            "domain_id": self.data_generator.domain.id,
            "execution_mode": "workflow",
            "workflow_id": 1,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        # Should default to 200 for success
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    @patch("api.views.start_secator_scan")
    def test_start_scan_backward_compatibility_error_no_http_status(self, mock_start_scan):
        """Test backward compatibility for errors when http_status is missing."""
        # Simulate old code that doesn't return http_status
        mock_start_scan.return_value = {
            "status": False,
            "error": "Some error occurred",
            # No http_status field
        }

        data = {
            "domain_id": self.data_generator.domain.id,
            "execution_mode": "workflow",
            "workflow_id": 1,
        }
        response = self.client.post(self.url, data, content_type="application/json")

        # Should default to 500 for errors
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertFalse(response.data["status"])

    @patch("api.views.start_secator_scan")
    def test_start_scan_with_selected_targets_passes_targets_override(self, mock_start_scan):
        """When selected_targets is provided for workflow, start_secator_scan receives targets_override."""
        mock_start_scan.return_value = {"status": True, "scan_id": 1, "http_status": 200}
        data = {
            "domain_id": self.data_generator.domain.id,
            "execution_mode": "workflow",
            "workflow_id": 1,
            "selected_targets": ["https://example.com", "https://test.example.com"],
        }
        response = self.client.post(self.url, data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_start_scan.assert_called_once()
        call_kwargs = mock_start_scan.call_args[1]
        self.assertEqual(call_kwargs["targets_override"], ["https://example.com", "https://test.example.com"])

    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_start_scan_with_selected_targets_per_task_starts_one_scan_per_task(
        self, mock_scan_repo_cls, mock_start_scan
    ):
        """When selected_targets_per_task is provided, one shared ScanHistory for all tasks."""
        self.data_generator.create_secator_task()
        task_type = self.data_generator.secator_task.task_type
        shared_scan_id = 42
        mock_scan_repo_cls.return_value.create_scan.return_value = shared_scan_id
        mock_start_scan.return_value = {"status": True, "scan_id": shared_scan_id}
        data = {
            "domain_id": self.data_generator.domain.id,
            "execution_mode": "tasks",
            "task_ids": [self.data_generator.secator_task.id],
            "selected_targets_per_task": {
                task_type: [self.data_generator.domain.name, "sub.example.com"],
            },
        }
        response = self.client.post(self.url, data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["scan_id"], shared_scan_id)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["scan_id"], shared_scan_id)
        mock_start_scan.assert_called_once()
        call_kwargs = mock_start_scan.call_args[1]
        self.assertEqual(call_kwargs["execution_mode"], "tasks")
        self.assertEqual(call_kwargs["task_ids"], [self.data_generator.secator_task.id])
        self.assertEqual(call_kwargs["scan_history_id"], shared_scan_id)
        self.assertEqual(call_kwargs["targets_override"], [self.data_generator.domain.name, "sub.example.com"])
