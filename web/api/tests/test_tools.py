"""
This file contains the test cases for the API views.
"""

from unittest.mock import patch
from django.urls import reverse
from rest_framework import status
from startScan.models import SubScan
from utils.test_base import BaseTestCase
from reNgine.llm import config
from dashboard.models import OllamaSettings

__all__ = [
    'TestOllamaManager',
    'TestWafDetector',
    'TestCMSDetector',
    'TestGfList',
    'TestUpdateTool',
    'TestUninstallTool',
    'TestGetExternalToolCurrentVersion',
    'TestRengineUpdateCheck',
    'TestGithubToolCheckGetLatestRelease',
    'TestGetFileContents',
    'TestDeleteMultipleRows'
]

class TestOllamaManager(BaseTestCase):
    """Tests for the OllamaManager API endpoints."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.ollama_settings = OllamaSettings.objects.create(
            id=1,
            selected_model="llama2",
            use_ollama=True
        )

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
        mock_get.return_value.json.return_value = {
            "models": [{"name": "llama2"}]
        }
        mock_delete.return_value.status_code = 200
        
        model_name = "llama2"
        api_url = reverse("api:ollama_detail_manager", kwargs={"model_name": model_name})
        
        response = self.client.delete(api_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_delete.assert_called_once_with(
            f"{config.OLLAMA_INSTANCE}/api/delete",
            json={"name": model_name}
        )

    @patch("requests.get")
    def test_put_update_model(self, mock_get):
        """Test updating the selected Ollama model."""
        mock_get.return_value.json.return_value = {
            "models": [{"name": "gpt-4"}]
        }
        
        model_name = "gpt-4"
        api_url = reverse("api:ollama_detail_manager", kwargs={"model_name": model_name})
        
        response = self.client.put(api_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        
        updated_settings = OllamaSettings.objects.get(id=1)
        self.assertEqual(updated_settings.selected_model, model_name)

class TestWafDetector(BaseTestCase):
    """Tests for the WAF Detector API."""

    @patch("api.views.run_wafw00f")
    def test_waf_detection_success(self, mock_run_wafw00f):
        """Test successful WAF detection."""
        mock_run_wafw00f.delay.return_value.get.return_value = (
            "WAF Detected: CloudFlare"
        )
        api_url = reverse("api:waf_detector")
        response = self.client.get(api_url, {"url": "https://www.cloudflare.com"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["results"], "WAF Detected: CloudFlare")

    @patch("api.views.run_wafw00f")
    def test_waf_detection_no_waf(self, mock_run_wafw00f):
        """Test WAF detection when no WAF is detected."""
        mock_run_wafw00f.delay.return_value.get.return_value = "No WAF detected"
        api_url = reverse("api:waf_detector")
        response = self.client.get(api_url, {"url": "https://www.cloudflare.com"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["message"], "Could not detect any WAF!")

    def test_waf_detection_missing_url(self):
        """Test WAF detection with missing URL parameter."""
        api_url = reverse("api:waf_detector")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["message"], "URL parameter is missing")

class TestCMSDetector(BaseTestCase):
    """Test case for CMS detection functionality."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_base()

    @patch("api.views.run_cmseek.delay")
    def test_cms_detector(self, mock_run_cmseek):
        """Test CMS detection for a given URL."""
        mock_run_cmseek.return_value.get.return_value = {
            "status": True,
            "cms": "WordPress",
        }
        url = reverse("api:cms_detector")
        response = self.client.get(url, {"url": self.data_generator.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["cms"], "WordPress")

class TestGfList(BaseTestCase):
    """Test case for retrieving GF patterns."""

    @patch("api.views.run_gf_list.delay")
    def test_gf_list(self, mock_run_gf_list):
        """Test retrieving a list of GF patterns."""
        mock_run_gf_list.return_value.get.return_value = {
            "status": True,
            "output": ["pattern1", "pattern2"],
        }
        url = reverse("api:gf_list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, ["pattern1", "pattern2"])

class TestUpdateTool(BaseTestCase):
    """Test case for updating a tool."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_installed_external_tool()

    @patch("api.views.run_command")
    def test_update_tool(self, mock_run_command):
        """Test updating a tool."""
        api_url = reverse("api:update_tool")
        response = self.client.get(
            api_url, {"tool_id": self.data_generator.installed_external_tool.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_run_command.assert_called()
        mock_run_command.apply_async.assert_called_once()

class TestUninstallTool(BaseTestCase):
    """Tests for the UninstallTool class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_installed_external_tool()

    @patch("api.views.UninstallTool")
    def test_uninstall_tool(self, mock_uninstall_tool):
        """Test uninstalling a tool."""
        mock_uninstall_tool.return_value = True
        url = reverse("api:uninstall_tool")
        data = {"tool_id": self.data_generator.installed_external_tool.id}
        response = self.client.get(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

class TestGetExternalToolCurrentVersion(BaseTestCase):
    """Test case for getting the current version of an external tool."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.tool = self.data_generator.create_installed_external_tool()
        self.tool.version_lookup_command = "echo 'v1.0.0'"
        self.tool.version_match_regex = r"v\d+\.\d+\.\d+"
        self.tool.save()

    @patch("api.views.run_command")
    def test_get_external_tool_current_version(self, mock_run_command):
        """Test getting the current version of an external tool."""
        mock_run_command.return_value = (None, "v1.0.0")
        url = reverse("api:external_tool_get_current_release")
        response = self.client.get(url, {"tool_id": self.tool.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["version_number"], "v1.0.0")
        self.assertEqual(response.data["tool_name"], self.tool.name)

class TestRengineUpdateCheck(BaseTestCase):
    """Tests for checking reNgine updates."""

    @patch("requests.get")
    def test_rengine_update_check(self, mock_get):
        """Test checking for reNgine updates."""
        mock_get.return_value.json.return_value = [
            {"name": "v2.0.0", "body": "Changelog"}
        ]
        api_url = reverse("api:check_rengine_update")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn("latest_version", response.data)
        self.assertIn("current_version", response.data)
        self.assertIn("update_available", response.data)

class TestGithubToolCheckGetLatestRelease(BaseTestCase):
    """Test case for checking the latest release of a GitHub tool."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.tool = self.data_generator.create_installed_external_tool()
        self.tool.github_url = "https://github.com/example/tool"
        self.tool.save()

    @patch("api.views.requests.get")
    def test_github_tool_check_get_latest_release(self, mock_get):
        """Test checking the latest release of a GitHub tool."""
        mock_get.return_value.json.return_value = [
            {
                "url": "https://api.github.com/repos/example/tool/releases/1",
                "id": 1,
                "name": "v1.0.0",
                "body": "Release notes",
            }
        ]
        url = reverse("api:github_tool_latest_release")
        response = self.client.get(url, {"tool_id": self.tool.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["name"], "v1.0.0")

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
        self.data_generator.create_project_base()
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
