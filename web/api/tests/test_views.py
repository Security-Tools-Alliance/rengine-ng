from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch, MagicMock

from targetApp.models import Domain, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, EndPoint, Vulnerability
from recon_note.models import TodoNote
from dashboard.models import *
from reNgine.models import *

class TestOllamaManager(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch('requests.post')
    def test_get_download_model(self, mock_post):
        mock_post.return_value.json.return_value = {'status': 'success'}
        url = reverse('ollama_manager')
        response = self.client.get(url, {'model': 'test_model'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    @patch('requests.delete')
    def test_delete_model(self, mock_delete):
        mock_delete.return_value.json.return_value = {'status': 'success'}
        url = reverse('ollama_manager')
        response = self.client.delete(url, {'model': 'test_model'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_put_update_model(self):
        url = reverse('ollama_manager')
        response = self.client.put(url, {'model': 'test_model'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

class TestGPTAttackSuggestion(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.project = Project.objects.create(name="Test Project")
        self.domain = Domain.objects.create(name="example.com", project=self.project)
        self.subdomain = Subdomain.objects.create(name="sub.example.com", target_domain=self.domain)

    @patch('reNgine.gpt.GPTAttackSuggestionGenerator.get_attack_suggestion')
    def test_get_attack_suggestion(self, mock_get_suggestion):
        mock_get_suggestion.return_value = {'status': True, 'description': 'Test attack suggestion'}
        url = reverse('gpt_attack_suggestion')
        response = self.client.get(url, {'subdomain_id': self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['description'], 'Test attack suggestion')

class TestGPTVulnerabilityReportGenerator(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.vulnerability = Vulnerability.objects.create(name="Test Vulnerability")

    @patch('reNgine.tasks.gpt_vulnerability_description.apply_async')
    def test_get_vulnerability_report(self, mock_apply_async):
        mock_task = MagicMock()
        mock_task.wait.return_value = {'status': True, 'description': 'Test vulnerability report'}
        mock_apply_async.return_value = mock_task
        url = reverse('gpt_vulnerability_report')
        response = self.client.get(url, {'id': self.vulnerability.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['description'], 'Test vulnerability report')

class TestCreateProjectApi(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_create_project_success(self):
        url = reverse('create_project')
        response = self.client.get(url, {'name': 'New Project'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['project_name'], 'New Project')

    def test_create_project_failure(self):
        url = reverse('create_project')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['status'])

class TestQueryInterestingSubdomains(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.project = Project.objects.create(name="Test Project")
        self.domain = Domain.objects.create(name="example.com", project=self.project)
        self.scan_history = ScanHistory.objects.create(domain=self.domain)
        self.subdomain = Subdomain.objects.create(name="sub.example.com", scan_history=self.scan_history, target_domain=self.domain)

    def test_query_interesting_subdomains(self):
        url = reverse('query_interesting_subdomains')
        response = self.client.get(url, {'scan_id': self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sub.example.com', [sub['name'] for sub in response.data])

# Continue with similar test classes for each view in the file...

class TestDeleteSubdomain(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.project = Project.objects.create(name="Test Project")
        self.domain = Domain.objects.create(name="example.com", project=self.project)
        self.scan_history = ScanHistory.objects.create(domain=self.domain)
        self.subdomain = Subdomain.objects.create(name="sub.example.com", scan_history=self.scan_history, target_domain=self.domain)

    def test_delete_subdomain(self):
        url = reverse('delete_subdomain')
        data = {'subdomain_ids': [self.subdomain.id]}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertFalse(Subdomain.objects.filter(id=self.subdomain.id).exists())

class TestDeleteVulnerability(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.vulnerability = Vulnerability.objects.create(name="Test Vulnerability")

    def test_delete_vulnerability(self):
        url = reverse('delete_vulnerability')
        data = {'vulnerability_ids': [self.vulnerability.id]}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertFalse(Vulnerability.objects.filter(id=self.vulnerability.id).exists())

class TestListInterestingKeywords(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch('reNgine.common_func.get_lookup_keywords')
    def test_list_interesting_keywords(self, mock_get_keywords):
        mock_get_keywords.return_value = ['keyword1', 'keyword2']
        url = reverse('list_interesting_keywords')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, ['keyword1', 'keyword2'])

class TestRengineUpdateCheck(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch('requests.get')
    def test_rengine_update_check(self, mock_get):
        mock_get.return_value.json.return_value = [{'name': 'v2.0.0', 'body': 'Changelog'}]
        url = reverse('rengine_update_check')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertTrue('latest_version' in response.data)
        self.assertTrue('current_version' in response.data)
        self.assertTrue('update_available' in response.data)

# Add more test classes for the remaining views...
