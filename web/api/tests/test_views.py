from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status

from dashboard.models import Project
from dashboard.views import on_user_logged_in
from recon_note.models import TodoNote
from scanEngine.models import EngineType, InterestingLookupModel
from startScan.models import ScanHistory, Subdomain, EndPoint, Vulnerability
from targetApp.models import Domain


class BaseTestCase(TestCase):
    """
    Base test case for all API tests.
    Sets up common fixtures and mocks the user login process.
    """
    fixtures = [
        'dashboard.json',
        'targetApp.json',
        'scanEngine.json',
        'startScan.json',
        'recon_note.json',
        'fixtures/auth.json',
        'fixtures/django_celery_beat.json'
    ]

    def setUp(self):
        self.client = Client()
        user = get_user_model()
        self.user = user.objects.get(username='rengine')

        # Save original on_user_logged_in function
        self.original_on_user_logged_in = on_user_logged_in

        # Replace on_user_logged_in with a mock function
        def mock_on_user_logged_in(sender, request, **kwargs):
            pass

        on_user_logged_in.__code__ = mock_on_user_logged_in.__code__

        # Login
        self.client.force_login(self.user)

        # Ensure the session is saved after login
        self.client.session.save()

    def tearDown(self):
        # Restore original on_user_logged_in function
        on_user_logged_in.__code__ = self.original_on_user_logged_in.__code__

class TestOllamaManager(BaseTestCase):
    """Tests for the OllamaManager API endpoints."""

    @patch('requests.post')
    def test_get_download_model(self, mock_post):
        """Test downloading an Ollama model."""
        mock_post.return_value.json.return_value = {'status': 'success'}
        api_url = reverse('api:ollama_manager')
        response = self.client.get(api_url, data={'model': 'gpt-4'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    @patch('requests.delete')
    def test_delete_model(self, mock_delete):
        """Test deleting an Ollama model."""
        mock_delete.return_value.json.return_value = {'status': 'success'}
        api_url = reverse('api:ollama_manager')
        response = self.client.delete(
            api_url,
            data={'model': 'gpt-4'},
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_put_update_model(self):
        """Test updating the selected Ollama model."""
        api_url = reverse('api:ollama_manager')
        response = self.client.put(
            api_url,
            data={'model': 'gpt-4'},
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

class TestGPTAttackSuggestion(BaseTestCase):
    """Tests for the GPT Attack Suggestion API."""

    def setUp(self):
        super().setUp()
        self.project = Project.objects.create(name="Test Project", insert_date=timezone.now())
        self.domain = Domain.objects.create(name="example.com", project=self.project)
        self.subdomain = Subdomain.objects.create(name="sub.example.com", target_domain=self.domain)

    @patch('reNgine.gpt.GPTAttackSuggestionGenerator.get_attack_suggestion')
    def test_get_attack_suggestion(self, mock_get_suggestion):
        """Test getting an attack suggestion for a subdomain."""
        mock_get_suggestion.return_value = {'status': True, 'description': 'Test attack suggestion'}
        api_url = reverse('api:gpt_get_possible_attacks')
        response = self.client.get(api_url, {'subdomain_id': self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['description'], 'Test attack suggestion')

class TestGPTVulnerabilityReportGenerator(BaseTestCase):
    """Tests for the GPT Vulnerability Report Generator API."""

    def setUp(self):
        super().setUp()
        self.vulnerability = Vulnerability.objects.create(name="Test Vulnerability", severity=1, scan_history_id=1)

    @patch('reNgine.tasks.gpt_vulnerability_description.apply_async')
    def test_get_vulnerability_report(self, mock_apply_async):
        """Test generating a vulnerability report."""
        mock_task = MagicMock()
        mock_task.wait.return_value = {'status': True, 'description': 'Test vulnerability report'}
        mock_apply_async.return_value = mock_task
        api_url = reverse('api:gpt_vulnerability_report_generator')
        response = self.client.get(api_url, {'id': self.vulnerability.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['description'], 'Test vulnerability report')


class TestCreateProjectApi(BaseTestCase):
    """Tests for the Create Project API."""

    def test_create_project_success(self):
        """Test successful project creation."""
        api_url = reverse('api:create_project')
        response = self.client.get(api_url, {'name': 'New Project'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['project_name'], 'New Project')

    def test_create_project_failure(self):
        """Test project creation failure when no name is provided."""
        api_url = reverse('api:create_project')
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['status'])

class TestQueryInterestingSubdomains(BaseTestCase):
    """Tests for querying interesting subdomains."""

    def setUp(self):
        super().setUp()
        self.project = Project.objects.create(name="Test Project", insert_date=timezone.now())
        self.domain = Domain.objects.create(name="example.com", project=self.project)
        self.scan_history = ScanHistory.objects.create(domain=self.domain, start_scan_date=timezone.now(), scan_type_id=1)
        self.subdomain = Subdomain.objects.create(name="admin.example.com", scan_history=self.scan_history, target_domain=self.domain)
        self.interesting_lookup = InterestingLookupModel.objects.create(keywords="admin", custom_type=True, title_lookup=True, url_lookup=True, condition_200_http_lookup=False)

    def test_query_interesting_subdomains(self):
        """Test querying interesting subdomains for a given scan."""
        api_url = reverse('api:queryInterestingSubdomains')
        response = self.client.get(api_url, {'scan_id': self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('admin.example.com', [sub['name'] for sub in response.data])

class TestDeleteSubdomain(BaseTestCase):
    """Tests for deleting subdomains."""

    def setUp(self):
        super().setUp()
        self.project = Project.objects.create(name="Test Project", insert_date=timezone.now())
        self.domain = Domain.objects.create(name="example.com", project=self.project)
        self.scan_history = ScanHistory.objects.create(domain=self.domain, start_scan_date=timezone.now(), scan_type_id=1)
        self.subdomain = Subdomain.objects.create(name="sub.example.com", scan_history=self.scan_history, target_domain=self.domain)

    def test_delete_subdomain(self):
        """Test deleting a subdomain."""
        api_url = reverse('api:delete_subdomain')
        data = {'subdomain_ids': [str(self.subdomain.id)]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertFalse(Subdomain.objects.filter(id=self.subdomain.id).exists())

class TestDeleteVulnerability(BaseTestCase):
    """Tests for deleting vulnerabilities."""

    def setUp(self):
        super().setUp()
        self.project = Project.objects.create(name="Test Project", insert_date=timezone.now())
        self.domain = Domain.objects.create(name="example.com", project=self.project)
        self.scan_history = ScanHistory.objects.create(domain=self.domain, start_scan_date=timezone.now(), scan_type_id=1)
        self.vulnerability = Vulnerability.objects.create(name="Test Vulnerability", severity=1, scan_history=self.scan_history)

    def test_delete_vulnerability(self):
        """Test deleting a vulnerability."""
        api_url = reverse('api:delete_vulnerability')
        data = {'vulnerability_ids': [self.vulnerability.id]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertFalse(Vulnerability.objects.filter(id=self.vulnerability.id).exists())

class TestListInterestingKeywords(BaseTestCase):
    """Tests for listing interesting keywords."""

    @patch('api.views.get_lookup_keywords')
    def test_list_interesting_keywords(self, mock_get_keywords):
        """Test listing interesting keywords."""
        mock_get_keywords.return_value = ['keyword1', 'keyword2']
        api_url = reverse('api:listInterestingKeywords')
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, ['keyword1', 'keyword2'])

class TestRengineUpdateCheck(BaseTestCase):
    """Tests for checking reNgine updates."""

    @patch('requests.get')
    def test_rengine_update_check(self, mock_get):
        """Test checking for reNgine updates."""
        mock_get.return_value.json.return_value = [{'name': 'v2.0.0', 'body': 'Changelog'}]
        api_url = reverse('api:check_rengine_update')
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertTrue('latest_version' in response.data)
        self.assertTrue('current_version' in response.data)
        self.assertTrue('update_available' in response.data)

# # Add more test classes for the remaining views...
