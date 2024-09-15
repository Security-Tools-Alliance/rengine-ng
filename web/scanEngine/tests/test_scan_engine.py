"""
test_scan_engine.py

This file contains unit tests for the views of the scanEngine application.
It tests functionalities related to scan engines, wordlists, settings, and tools.
"""

from django.urls import reverse
from utils.test_base import BaseTestCase
from scanEngine.models import EngineType, Wordlist, InstalledExternalTool

__all__ = [
    'TestScanEngineViews',
]

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
        self.data_generator.create_project_full()

    def test_index_view(self):
        """
        Tests the index view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse('scan_engine_index', kwargs={'slug': 'default'}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanEngine/index.html')

    def test_add_engine_view(self):
        """
        Tests the add engine view to ensure a new engine is created successfully.
        """
        response = self.client.post(reverse('add_engine', kwargs={'slug': 'default'}), {
            'engine_name': 'New Engine',
            'yaml_configuration': 'new: config'
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(EngineType.objects.filter(engine_name='New Engine').exists())

    def test_delete_engine_view(self):
        """
        Tests the delete engine view to ensure an engine is deleted successfully.
        """
        response = self.client.post(reverse('delete_engine_url', kwargs={
            'slug': 'default',
            'id': self.data_generator.engine_type.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(EngineType.objects.filter(id=self.data_generator.engine_type.id).exists())

    def test_update_engine_view(self):
        """
        Tests the update engine view to ensure an engine is updated successfully.
        """
        response = self.client.post(reverse('update_engine', kwargs={
            'slug': 'default',
            'id': self.data_generator.engine_type.id
        }), {
            'engine_name': 'Updated Engine',
            'yaml_configuration': 'updated: config'
        })
        self.assertEqual(response.status_code, 302)
        self.data_generator.engine_type.refresh_from_db()
        self.assertEqual(self.data_generator.engine_type.engine_name, 'Updated Engine')

    def test_wordlist_list_view(self):
        """
        Tests the wordlist list view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse('wordlist_list', kwargs={'slug': 'default'}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanEngine/wordlist/index.html')

    def test_add_wordlist_view(self):
        """
        Tests the add wordlist view to ensure a new wordlist is created successfully.
        """
        with open('test_wordlist.txt', 'w', encoding='utf-8') as f:
            f.write('test\nword\nlist')
        with open('test_wordlist.txt', 'rb') as f:
            response = self.client.post(reverse('add_wordlist', kwargs={'slug': 'default'}), {
                'name': 'New Wordlist',
                'short_name': 'new',
                'upload_file': f
            })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Wordlist.objects.filter(name='New Wordlist').exists())

    def test_delete_wordlist_view(self):
        """
        Tests the delete wordlist view to ensure a wordlist is deleted successfully.
        """
        response = self.client.post(reverse('delete_wordlist', kwargs={
            'slug': 'default',
            'id': self.data_generator.wordlist.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Wordlist.objects.filter(id=self.data_generator.wordlist.id).exists())

    def test_interesting_lookup_view(self):
        """
        Tests the interesting lookup view to ensure it updates keywords successfully.
        """
        response = self.client.post(reverse('interesting_lookup', kwargs={'slug': 'default'}), {
            'custom_type': True,
            'keywords': 'test,lookup'
        })
        self.assertEqual(response.status_code, 302)
        self.data_generator.interesting_lookup_model.refresh_from_db()
        self.assertEqual(self.data_generator.interesting_lookup_model.keywords, 'test,lookup')

    def test_tool_specific_settings_view(self):
        """
        Tests the tool-specific settings view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse('tool_settings', kwargs={'slug': 'default'}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanEngine/settings/tool.html')

    def test_rengine_settings_view(self):
        """
        Tests the rengine settings view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse('rengine_settings', kwargs={'slug': 'default'}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanEngine/settings/rengine.html')

    def test_notification_settings_view(self):
        """
        Tests the notification settings view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse('notification_settings', kwargs={'slug': 'default'}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanEngine/settings/notification.html')

    def test_proxy_settings_view(self):
        """
        Tests the proxy settings view to ensure it updates proxy settings successfully.
        """
        response = self.client.post(reverse('proxy_settings', kwargs={'slug': 'default'}), {
            'use_proxy': True,
            'proxies': '192.168.1.1',
        })
        self.assertEqual(response.status_code, 302)
        self.data_generator.proxy.refresh_from_db()
        self.assertEqual(self.data_generator.proxy.proxies, '192.168.1.1')

    def test_hackerone_settings_view(self):
        """
        Tests the Hackerone settings view to ensure it updates settings successfully.
        """
        response = self.client.post(reverse('hackerone_settings', kwargs={'slug': 'default'}), {
            'username': 'newuser',
            'api_key': 'newapikey'
        })
        self.assertEqual(response.status_code, 302)
        self.data_generator.hackerone.refresh_from_db()
        self.assertEqual(self.data_generator.hackerone.username, 'newuser')

    def test_report_settings_view(self):
        """
        Tests the report settings view to ensure it updates settings successfully.
        """
        response = self.client.post(reverse('report_settings', kwargs={'slug': 'default'}), {
            'primary_color': '#FFFFFF',
            'secondary_color': '#000000'
        })
        self.assertEqual(response.status_code, 302)
        self.data_generator.report_setting.refresh_from_db()
        self.assertEqual(self.data_generator.report_setting.primary_color, '#FFFFFF')

    def test_tool_arsenal_section_view(self):
        """
        Tests the tool arsenal section view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse('tool_arsenal', kwargs={'slug': 'default'}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanEngine/settings/tool_arsenal.html')

    def test_api_vault_view(self):
        """
        Tests the API vault view to ensure it updates API keys successfully.
        """
        response = self.client.post(reverse('api_vault', kwargs={'slug': 'default'}), {
            'key_openai': 'test_openai_key',
            'key_netlas': 'test_netlas_key'
        })
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanEngine/settings/api.html')

    def test_add_tool_view(self):
        """
        Tests the add tool view to ensure a new tool is created successfully.
        """
        response = self.client.post(reverse('add_tool', kwargs={'slug': 'default'}), {
            'name': 'New Tool',
            'github_url': 'https://github.com/new/tool',
            'install_command': 'pip install new-tool',
            'description': 'New Tool Description'
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(InstalledExternalTool.objects.filter(name='New Tool').exists())

    def test_modify_tool_in_arsenal_view(self):
        """
        Tests the modify tool in arsenal view to ensure a tool is updated successfully.
        """
        response = self.client.post(reverse('update_tool_in_arsenal', kwargs={
            'slug': 'default',
            'id': self.data_generator.external_tool.id
        }), {
            'name': 'Modified Tool',
            'github_url': 'https://github.com/modified/tool',
            'install_command': 'pip install modified-tool',
            'description': 'Modified Tool Description'
        })
        self.assertEqual(response.status_code, 302)
        self.data_generator.external_tool.refresh_from_db()
        self.assertEqual(self.data_generator.external_tool.name, 'Modified Tool')
