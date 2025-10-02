"""
test_scan_engine.py

This file contains unit tests for the views of the scanEngine application.
It tests functionalities related to scan engines, wordlists, settings, and tools.
"""

from django.urls import reverse

from scanEngine.models import EngineType, InstalledExternalTool, Wordlist
from utils.test_base import BaseTestCase


class TestScanEngineViews(BaseTestCase):
    """
    Test class for the scanEngine views.
    """

    def setUp(self):
        """
        Initial setup for the tests.
        Creates test objects for engines, wordlists, settings, and tools.
        """
        super().setUp()

    def test_index_view(self):
        """
        Tests the index view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("scan_engine_index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanEngine/index.html")

    def test_add_engine_view(self):
        """
        Tests the add engine view to ensure a new engine is created successfully.
        """
        response = self.client.post(
            reverse("add_engine"),
            {"engine_name": "New Engine", "yaml_configuration": "new: config", "scan_type": "bug_bounty"},
        )
        self.assertEqual(response.status_code, 302)
        engine = EngineType.objects.filter(engine_name="New Engine").first()
        self.assertTrue(engine is not None)
        self.assertEqual(engine.scan_type, "bug_bounty")

    def test_delete_engine_view(self):
        """
        Tests the delete engine view to ensure an engine is deleted successfully.
        """
        response = self.client.post(reverse("delete_engine_url", kwargs={"id": self.data_generator.engine_type.id}))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(EngineType.objects.filter(id=self.data_generator.engine_type.id).exists())

    def test_update_engine_view(self):
        """
        Tests the update engine view to ensure an engine is updated successfully.
        """
        response = self.client.post(
            reverse("update_engine", kwargs={"id": self.data_generator.engine_type.id}),
            {"engine_name": "Updated Engine", "yaml_configuration": "updated: config", "scan_type": "internal_network"},
        )
        self.assertEqual(response.status_code, 302)
        self.data_generator.engine_type.refresh_from_db()
        self.assertEqual(self.data_generator.engine_type.engine_name, "Updated Engine")
        self.assertEqual(self.data_generator.engine_type.scan_type, "internal_network")

    def test_wordlist_list_view(self):
        """
        Tests the wordlist list view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("wordlist_list"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanEngine/wordlist/index.html")

    def test_add_wordlist_view(self):
        """
        Tests the add wordlist view to ensure a new wordlist is created successfully.
        """
        with open("test_wordlist.txt", "w", encoding="utf-8") as f:
            f.write("test\nword\nlist")
        with open("test_wordlist.txt", "rb") as f:
            response = self.client.post(
                reverse("add_wordlist"), {"name": "New Wordlist", "short_name": "new", "upload_file": f}
            )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Wordlist.objects.filter(name="New Wordlist").exists())

    def test_delete_wordlist_view(self):
        """
        Tests the delete wordlist view to ensure a wordlist is deleted successfully.
        """
        response = self.client.post(reverse("delete_wordlist", kwargs={"id": self.data_generator.wordlist.id}))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Wordlist.objects.filter(id=self.data_generator.wordlist.id).exists())

    def test_interesting_lookup_view(self):
        """
        Tests the interesting lookup view to ensure it updates keywords successfully.
        """
        response = self.client.post(reverse("interesting_lookup"), {"custom_type": True, "keywords": "test,lookup"})
        self.assertEqual(response.status_code, 302)
        self.data_generator.interesting_lookup_model.refresh_from_db()
        self.assertEqual(self.data_generator.interesting_lookup_model.keywords, "test,lookup")

    def test_tool_specific_settings_view(self):
        """
        Tests the tool-specific settings view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("tool_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanEngine/settings/tool.html")

    def test_rengine_settings_view(self):
        """
        Tests the rengine settings view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("rengine_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanEngine/settings/rengine.html")

    def test_notification_settings_view(self):
        """
        Tests the notification settings view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("notification_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanEngine/settings/notification.html")

    def test_proxy_settings_view(self):
        """
        Tests the proxy settings view to ensure it updates proxy settings successfully.
        """
        response = self.client.post(
            reverse("proxy_settings"),
            {
                "use_proxy": True,
                "proxies": "192.168.1.1",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.data_generator.proxy.refresh_from_db()
        self.assertEqual(self.data_generator.proxy.proxies, "192.168.1.1")

    def test_hackerone_settings_view(self):
        """
        Tests the Hackerone settings view to ensure it updates settings successfully.
        """
        response = self.client.post(reverse("hackerone_settings"), {"username": "newuser", "api_key": "newapikey"})
        self.assertEqual(response.status_code, 302)
        self.data_generator.hackerone.refresh_from_db()
        self.assertEqual(self.data_generator.hackerone.username, "newuser")

    def test_report_settings_view(self):
        """
        Tests the report settings view to ensure it updates settings successfully.
        """
        response = self.client.post(
            reverse("report_settings"), {"primary_color": "#FFFFFF", "secondary_color": "#000000"}
        )
        self.assertEqual(response.status_code, 302)
        self.data_generator.report_setting.refresh_from_db()
        self.assertEqual(self.data_generator.report_setting.primary_color, "#FFFFFF")

    def test_tool_arsenal_section_view(self):
        """
        Tests the tool arsenal section view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("tool_arsenal"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanEngine/settings/tool_arsenal.html")

    def test_api_vault_view(self):
        """
        Tests the API vault view to ensure it updates API keys successfully.
        """
        response = self.client.post(
            reverse("api_vault"), {"key_openai": "test_openai_key", "key_netlas": "test_netlas_key"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanEngine/settings/api.html")

    def test_add_tool_view(self):
        """
        Tests the add tool view to ensure a new tool is created successfully.
        """
        response = self.client.post(
            reverse("add_tool"),
            {
                "name": "New Tool",
                "github_url": "https://github.com/new/tool",
                "install_command": "pip install new-tool",
                "description": "New Tool Description",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(InstalledExternalTool.objects.filter(name="New Tool").exists())

    def test_modify_tool_in_arsenal_view(self):
        """
        Tests the modify tool in arsenal view to ensure a tool is updated successfully.
        """
        response = self.client.post(
            reverse("update_tool_in_arsenal", kwargs={"id": self.data_generator.external_tool.id}),
            {
                "name": "Modified Tool",
                "github_url": "https://github.com/modified/tool",
                "install_command": "pip install modified-tool",
                "description": "Modified Tool Description",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.data_generator.external_tool.refresh_from_db()
        self.assertEqual(self.data_generator.external_tool.name, "Modified Tool")

    def test_add_engine_invalid_scan_type(self):
        """
        Tests the add engine view with invalid scan_type values to ensure proper error handling.
        """
        # Test with invalid scan_type value
        response = self.client.post(
            reverse("add_engine"),
            {
                "engine_name": "Invalid Scan Type Engine",
                "yaml_configuration": "new: config",
                "scan_type": "invalid_scan_type",
            },
        )
        # Should return 200 with form errors (validation failure)
        self.assertEqual(response.status_code, 200)
        # Engine should not be created due to validation error
        engine = EngineType.objects.filter(engine_name="Invalid Scan Type Engine").first()
        self.assertIsNone(engine)

    def test_add_engine_missing_scan_type(self):
        """
        Tests the add engine view with missing scan_type to ensure proper fallback.
        """
        # Test with missing scan_type field
        response = self.client.post(
            reverse("add_engine"),
            {
                "engine_name": "Missing Scan Type Engine",
                "yaml_configuration": "new: config",
                # scan_type field is missing
            },
        )
        # Should return 200 with form errors (validation failure)
        self.assertEqual(response.status_code, 200)
        # Engine should not be created due to validation error
        engine = EngineType.objects.filter(engine_name="Missing Scan Type Engine").first()
        self.assertIsNone(engine)

    def test_add_engine_empty_scan_type(self):
        """
        Tests the add engine view with empty scan_type to ensure proper fallback.
        """
        # Test with empty scan_type value
        response = self.client.post(
            reverse("add_engine"),
            {"engine_name": "Empty Scan Type Engine", "yaml_configuration": "new: config", "scan_type": ""},
        )
        # Should return 200 with form errors (validation failure)
        self.assertEqual(response.status_code, 200)
        # Engine should not be created due to validation error
        engine = EngineType.objects.filter(engine_name="Empty Scan Type Engine").first()
        self.assertIsNone(engine)

    def test_add_engine_scan_type_from_yaml(self):
        """
        Tests the add engine view with scan_type defined in YAML configuration.
        """
        # Test with scan_type defined in YAML
        yaml_config_with_scan_type = """
# Global vars for all tools
scan_type: 'internal_network'
custom_header: {
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
}

# Port scanning configuration
port_scan: {
  'uses_tools': ['nmap'],
  'threads': 50,
}
"""
        response = self.client.post(
            reverse("add_engine"),
            {
                "engine_name": "YAML Scan Type Engine",
                "yaml_configuration": yaml_config_with_scan_type,
                "scan_type": "bug_bounty",  # This should be overridden by YAML
            },
        )
        self.assertEqual(response.status_code, 302)
        engine = EngineType.objects.filter(engine_name="YAML Scan Type Engine").first()
        self.assertTrue(engine is not None)
        # Should use scan_type from YAML configuration
        self.assertEqual(engine.scan_type, "internal_network")

    def test_update_engine_invalid_scan_type(self):
        """
        Tests the update engine view with invalid scan_type values to ensure proper error handling.
        """
        # Test with invalid scan_type value
        response = self.client.post(
            reverse("update_engine", kwargs={"id": self.data_generator.engine_type.id}),
            {
                "engine_name": "Updated Engine Invalid",
                "yaml_configuration": "updated: config",
                "scan_type": "invalid_scan_type",
            },
        )
        # Should return 200 with form errors (validation failure)
        self.assertEqual(response.status_code, 200)
        # Engine should not be updated due to validation error
        self.data_generator.engine_type.refresh_from_db()
        self.assertNotEqual(self.data_generator.engine_type.engine_name, "Updated Engine Invalid")

    def test_update_engine_missing_scan_type(self):
        """
        Tests the update engine view with missing scan_type to ensure proper fallback.
        """
        # Test with missing scan_type field
        response = self.client.post(
            reverse("update_engine", kwargs={"id": self.data_generator.engine_type.id}),
            {
                "engine_name": "Updated Engine Missing",
                "yaml_configuration": "updated: config",
                # scan_type field is missing
            },
        )
        # Should return 200 with form errors (validation failure)
        self.assertEqual(response.status_code, 200)
        # Engine should not be updated due to validation error
        self.data_generator.engine_type.refresh_from_db()
        self.assertNotEqual(self.data_generator.engine_type.engine_name, "Updated Engine Missing")

    def test_engine_model_scan_type_validation(self):
        """
        Tests the EngineType model's scan_type validation and fallback mechanisms.
        """
        # Test creating engine with invalid scan_type
        engine = EngineType.objects.create(
            engine_name="Test Invalid Scan Type", yaml_configuration="test: config", scan_type="invalid_type"
        )
        # The model should handle this gracefully
        self.assertIn(engine.scan_type, ["bug_bounty", "internal_network"])

    def test_engine_model_yaml_scan_type_override(self):
        """
        Tests that scan_type from YAML configuration overrides the model field.
        """
        yaml_config = """
# Global vars for all tools
scan_type: 'internal_network'
custom_header: {
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
}
"""
        # Create engine with different scan_type in model field
        engine = EngineType.objects.create(
            engine_name="Test YAML Override",
            yaml_configuration=yaml_config,
            scan_type="bug_bounty",  # This should be overridden by YAML
        )
        # Should use scan_type from YAML
        self.assertEqual(engine.scan_type, "internal_network")

    def test_engine_model_get_scan_type_from_yaml(self):
        """
        Tests the get_scan_type_from_yaml method with various YAML configurations.
        """
        # Test with valid scan_type in YAML
        yaml_config_valid = """
scan_type: 'internal_network'
custom_header: {}
"""
        engine = EngineType.objects.create(engine_name="Test Valid YAML", yaml_configuration=yaml_config_valid)
        self.assertEqual(engine.get_scan_type_from_yaml(), "internal_network")

        # Test with invalid scan_type in YAML
        yaml_config_invalid = """
scan_type: 'invalid_type'
custom_header: {}
"""
        engine = EngineType.objects.create(engine_name="Test Invalid YAML", yaml_configuration=yaml_config_invalid)
        # Should return the invalid value as-is (validation happens elsewhere)
        self.assertEqual(engine.get_scan_type_from_yaml(), "invalid_type")

        # Test with missing scan_type in YAML
        yaml_config_missing = """
custom_header: {}
port_scan: {}
"""
        engine = EngineType.objects.create(engine_name="Test Missing YAML", yaml_configuration=yaml_config_missing)
        # Should return default fallback
        self.assertEqual(engine.get_scan_type_from_yaml(), "bug_bounty")

        # Test with malformed YAML
        engine = EngineType.objects.create(
            engine_name="Test Malformed YAML", yaml_configuration="invalid: yaml: content: ["
        )
        # Should return default fallback
        self.assertEqual(engine.get_scan_type_from_yaml(), "bug_bounty")

        # Test with empty YAML
        engine = EngineType.objects.create(engine_name="Test Empty YAML", yaml_configuration="")
        # Should return default fallback
        self.assertEqual(engine.get_scan_type_from_yaml(), "bug_bounty")
