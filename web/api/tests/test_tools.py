"""
This file contains the test cases for the API views.
"""

from unittest.mock import patch

from django.urls import reverse
from rest_framework import status

from dashboard.models import OllamaSettings
from reNgine.llm import config
from startScan.models import SubScan
from utils.test_base import BaseTestCase


class TestOllamaManager(BaseTestCase):
    """Tests for the OllamaManager API endpoints."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.ollama_settings = OllamaSettings.objects.create(id=1, selected_model="llama2", use_ollama=True)

    @patch("requests.post")
    def test_get_download_model(self, mock_post):
        """Test downloading an Ollama model."""
        mock_post.return_value.json.return_value = {"status": "success"}
        api_url = reverse("api:ollama_manager")
        response = self.client.get(api_url, data={"model": "llama2"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    @patch("requests.delete")
    @patch("requests.get")
    def test_delete_model(self, mock_get, mock_delete):
        """Test deleting an Ollama model."""
        mock_get.return_value.json.return_value = {"models": [{"name": "llama2"}]}
        mock_delete.return_value.status_code = 200

        model_name = "llama2"
        api_url = reverse("api:ollama_detail_manager", kwargs={"model_name": model_name})

        response = self.client.delete(api_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_delete.assert_called_once_with(f"{config.OLLAMA_INSTANCE}/api/delete", json={"name": model_name})

    @patch("requests.get")
    def test_put_update_model(self, mock_get):
        """Test updating the selected Ollama model."""
        mock_get.return_value.json.return_value = {"models": [{"name": "gpt-4"}]}

        model_name = "gpt-4"
        api_url = reverse("api:ollama_detail_manager", kwargs={"model_name": model_name})

        response = self.client.put(api_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

        updated_settings = OllamaSettings.objects.get(id=1)
        self.assertEqual(updated_settings.selected_model, model_name)


# TestWafDetector removed - WAF detection functionality migrated to Secator


# Note: TestCMSDetector removed - run_cmseek functionality moved to Secator


# Note: TestGfList removed - run_gf_list functionality moved to Secator


class TestRengineUpdateCheck(BaseTestCase):
    """Tests for checking reNgine updates."""

    @patch("requests.get")
    def test_rengine_update_check(self, mock_get):
        """Test checking for reNgine updates."""
        mock_get.return_value.json.return_value = [{"name": "v2.0.0", "body": "Changelog"}]
        api_url = reverse("api:check_rengine_update")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn("latest_version", response.data)
        self.assertIn("current_version", response.data)
        self.assertIn("update_available", response.data)


class TestGetFileContents(BaseTestCase):
    """Test case for retrieving file contents."""

    @patch("api.views.os.path.exists")
    @patch("api.views.run_command")
    def test_get_file_contents(self, mock_run_command, mock_exists):
        """Test retrieving contents of a file."""
        mock_exists.return_value = True
        mock_run_command.return_value = (0, "test content")
        url = reverse("api:getFileContents")
        response = self.client.get(url, {"nuclei_config": True})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertGreaterEqual(len(response.data["content"]), 1)


class TestDeleteMultipleRows(BaseTestCase):
    """Test case for deleting multiple rows."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_subscan()
        self.data_generator.create_subscan()

    def test_delete_multiple_rows(self):
        """Test deleting multiple rows."""
        api_url = reverse("api:delete_rows")
        data = {
            "type": "subscan",
            "rows": [
                int(self.data_generator.subscans[0].id),
                int(self.data_generator.subscans[1].id),
            ],
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertFalse(
            SubScan.objects.filter(
                id__in=[
                    self.data_generator.subscans[0].id,
                    self.data_generator.subscans[1].id,
                ]
            ).exists()
        )


# Deprecated endpoint tests removed - IPToDomain and PingHosts endpoints have been removed


# CSRF token endpoint tests removed - endpoint not implemented in URLs
