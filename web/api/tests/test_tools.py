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
    """Test case for preview of custom scan assets (GF patterns, Nuclei templates)."""

    @patch("api.views._read_asset_preview")
    def test_get_file_contents_nuclei_template(self, mock_read):
        """Test retrieving contents of a Nuclei template for preview."""
        mock_read.return_value = (True, "test template content", None)
        url = reverse("api:getFileContents")
        response = self.client.get(url, {"nuclei_template": True, "name": "my-template"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["content"], "test template content")
        mock_read.assert_called_once()

    @patch("api.views._read_asset_preview")
    def test_get_file_contents_invalid_params(self, mock_read):
        """Test that requests without supported params return 410 Gone."""
        mock_read.side_effect = AssertionError("should not be called")
        url = reverse("api:getFileContents")
        response = self.client.get(url, {})
        self.assertEqual(response.status_code, status.HTTP_410_GONE)
        self.assertFalse(response.data["status"])
        self.assertIn("message", response.data)
        self.assertIn("gf_pattern", response.data["message"])
        self.assertIn("nuclei_template", response.data["message"])
        self.assertIn("migration_note", response.data)
        mock_read.assert_not_called()


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
