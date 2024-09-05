from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status

from dashboard.models import Project, SearchHistory
from dashboard.views import on_user_logged_in
from recon_note.models import TodoNote
from scanEngine.models import EngineType, InterestingLookupModel, InstalledExternalTool
from startScan.models import ScanHistory, Subdomain, EndPoint, Vulnerability, DirectoryScan, DirectoryFile, SubScan
from targetApp.models import Domain
import logging

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

        self.subscans = []
        self.vulnerabilities = []

    # Disable logging for tests
    logging.disable(logging.CRITICAL)

    def create_project(self):
        self.project = Project.objects.create(
            name="Test Project",
            insert_date=timezone.now(),
            slug="test-project"
        )
        return self.project

    def create_domain(self):
        self.domain = Domain.objects.create(
            name="example.com",
            project=self.project,
            insert_date=timezone.now()
        )
        return self.domain

    def create_subdomain(self):
        self.subdomain = Subdomain.objects.create(
            name="admin.example.com",
            target_domain=self.domain,
            scan_history=self.scan_history
        )
        return self.subdomain

    def create_scan_history(self):
        self.scan_history = ScanHistory.objects.create(
            domain=self.domain,
            start_scan_date=timezone.now(),
            scan_type_id=1
        )
        return self.scan_history

    def create_vulnerability(self):
        self.vulnerabilities.append(Vulnerability.objects.create(
            name="Common Vulnerability",
            severity=1,
            discovered_date=timezone.now(),
            target_domain=self.domain,
            subdomain=self.subdomain,
            scan_history=self.scan_history
        ))
        return self.vulnerabilities

    def create_endpoint(self):
        self.endpoint = EndPoint.objects.create(
            target_domain=self.domain,
            subdomain=self.subdomain,
            scan_history=self.scan_history,
            http_url="https://admin.example.com/endpoint"
        )
        return self.endpoint

    def create_directory_scan(self):
        self.directory_scan = DirectoryScan.objects.create(
            command_line="Test Command",
            scanned_date=timezone.now()
        )
        return self.directory_scan

    def create_directory_file(self):
        self.directory_file = DirectoryFile.objects.create(
            name="test.txt",
            url="https://example.com/test.txt"
        )
        return self.directory_file

    def create_subscan(self):
        self.subscans.append(SubScan.objects.create(
            start_scan_date=timezone.now(),
            scan_history=self.scan_history,
            subdomain=self.subdomain,
            status=1
        ))
        return self.subscans

    def create_installed_external_tool(self):
        self.installed_external_tool = InstalledExternalTool.objects.create(
            name="Test Tool",
            github_url="https://github.com/test-tool"
        )
        return self.installed_external_tool

    def create_todo_note(self):
        self.todo_note = TodoNote.objects.create(
            note="Test Note",
            subdomain=self.subdomain,
            scan_history=self.scan_history
        )
        return self.todo_note

    def create_search_history(self):
        self.search_history = SearchHistory.objects.create(
            query="Test Query"
        )
        return self.search_history

    def create_interesting_lookup_model(self):
        self.interesting_lookup_model = InterestingLookupModel.objects.create(
            keywords="Test Keywords",
            custom_type=True,
            title_lookup=True,
            url_lookup=True,
            condition_200_http_lookup=False
        )
        return self.interesting_lookup_model
    
    def create_project_full(self):
        self.create_project()
        self.create_domain()
        self.create_scan_history()
        self.create_subdomain()
        self.create_vulnerability()
        self.create_endpoint()
        self.create_directory_scan()
        self.create_directory_file()
        self.create_subscan()

    def create_project_base(self):
        self.create_project()
        self.create_domain()
        self.create_scan_history()
        self.create_subdomain()

    def create_project_additionals(self):
        self.create_vulnerability()
        self.create_endpoint()
        self.create_directory_scan()
        self.create_directory_file()
        self.create_subscan()

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
        self.create_project_base()

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
        self.create_project_base()
        self.create_vulnerability()

    @patch('reNgine.tasks.gpt_vulnerability_description.apply_async')
    def test_get_vulnerability_report(self, mock_apply_async):
        """Test generating a vulnerability report."""
        mock_task = MagicMock()
        mock_task.wait.return_value = {'status': True, 'description': 'Test vulnerability report'}
        mock_apply_async.return_value = mock_task
        api_url = reverse('api:gpt_vulnerability_report_generator')
        response = self.client.get(api_url, {'id': self.vulnerabilities[0].id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['description'], 'Test vulnerability report')


class TestCreateProjectApi(BaseTestCase):
    """Tests for the Create Project API."""

    def test_create_project_success(self):
        """Test successful project creation."""
        api_url = reverse('api:create_project')
        response = self.client.get(api_url, {'name': 'New Project', 'insert_date': timezone.now(), 'slug': 'new-project'})
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
        self.create_project_base()
        self.create_interesting_lookup_model()

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
        self.create_project_base()

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
        self.create_project_base()
        self.create_vulnerability()

    def test_delete_vulnerability(self):
        """Test deleting a vulnerability."""
        api_url = reverse('api:delete_vulnerability')
        data = {'vulnerability_ids': [self.vulnerabilities[0].id]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertFalse(Vulnerability.objects.filter(id=self.vulnerabilities[0].id).exists())

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

class TestWafDetector(BaseTestCase):
    """Tests for the WAF Detector API."""

    @patch('api.views.run_wafw00f')
    def test_waf_detection_success(self, mock_run_wafw00f):
        """Test successful WAF detection."""
        mock_run_wafw00f.delay.return_value.get.return_value = "WAF Detected: CloudFlare"
        api_url = reverse('api:waf_detector')
        response = self.client.get(api_url, {'url': 'https://www.cloudflare.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['results'], "WAF Detected: CloudFlare")

    @patch('api.views.run_wafw00f')
    def test_waf_detection_no_waf(self, mock_run_wafw00f):
        """Test WAF detection when no WAF is detected."""
        mock_run_wafw00f.delay.return_value.get.return_value = "No WAF detected"
        api_url = reverse('api:waf_detector')
        response = self.client.get(api_url, {'url': 'https://www.cloudflare.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['status'])
        self.assertEqual(response.data['message'], 'Could not detect any WAF!')

    def test_waf_detection_missing_url(self):
        """Test WAF detection with missing URL parameter."""
        api_url = reverse('api:waf_detector')
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['status'])
        self.assertEqual(response.data['message'], 'URL parameter is missing')


class TestSearchHistoryView(BaseTestCase):
    """Tests for the Search History API."""

    def setUp(self):
        super().setUp()
        self.create_search_history()

    def test_get_search_history(self):
        """Test retrieving search history."""
        api_url = reverse('api:search_history')
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['query'], "Test Query")


class TestListTargetsDatatableViewSet(BaseTestCase):
    """Tests for the List Targets Datatable API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_list_targets(self):
        """Test listing targets."""
        api_url = '/api/listTargets/'
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "example.com")

    def test_list_targets_with_slug(self):
        """Test listing targets with project slug."""
        api_url = '/api/listTargets/'
        response = self.client.get(api_url, {'slug': 'test-project'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "example.com")


class TestDirectoryViewSet(BaseTestCase):
    """Tests for the Directory ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_directory_scan()
        self.create_directory_file()
        self.directory_scan.directory_files.add(self.directory_file)
        self.subdomain.directories.add(self.directory_scan)

    def test_get_directory_files(self):
        """Test retrieving directory files."""
        api_url = '/api/listDirectories/'
        response = self.client.get(api_url, {'scan_history': self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "test.txt")

    def test_get_directory_files_by_subdomain(self):
        """Test retrieving directory files by subdomain."""
        api_url = '/api/listDirectories/'
        response = self.client.get(api_url, {'subdomain_id': self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "test.txt")


class TestVulnerabilityViewSet(BaseTestCase):
    """Tests for the Vulnerability ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_vulnerability()

    def test_list_vulnerabilities(self):
        """Test listing vulnerabilities."""
        api_url = '/api/listVulnerability/'
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertNotEqual(response.data['results'][0]['name'], "")

    def test_list_vulnerabilities_by_scan(self):
        """Test listing vulnerabilities by scan history."""
        api_url = '/api/listVulnerability/'
        response = self.client.get(api_url, {'scan_history': self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "Common Vulnerability")

    def test_list_vulnerabilities_by_domain(self):
        """Test listing vulnerabilities by domain."""
        api_url = '/api/listVulnerability/'
        response = self.client.get(api_url, {'domain': 'example.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "Common Vulnerability")

    def test_list_vulnerabilities_by_severity(self):
        """Test listing vulnerabilities by severity."""
        api_url = '/api/listVulnerability/'
        response = self.client.get(api_url, {'severity': 1})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "Common Vulnerability")

class TestSubdomainDatatableViewSet(BaseTestCase):
    """Tests for the Subdomain Datatable ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_list_subdomains(self):
        """Test listing subdomains."""
        api_url = '/api/listDatatableSubdomain/'
        response = self.client.get(api_url, {'project': self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "admin.example.com")

    def test_list_subdomains_by_domain(self):
        """Test listing subdomains by domain."""
        api_url = '/api/listDatatableSubdomain/'
        response = self.client.get(api_url, {'target_id': self.domain.id, 'project': self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "admin.example.com")

class TestEndPointViewSet(BaseTestCase):
    """Tests for the EndPoint ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.endpoint = EndPoint.objects.create(
            target_domain=self.domain,
            subdomain=self.subdomain,
            scan_history=self.scan_history,
            http_url="https://admin.example.com/endpoint"
        )

    def test_list_endpoints(self):
        """Test listing endpoints."""
        api_url = '/api/listEndpoints/'
        response = self.client.get(api_url, {'project': self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['http_url'], "https://admin.example.com/endpoint")

    def test_list_endpoints_by_subdomain(self):
        """Test listing endpoints by subdomain."""
        api_url = '/api/listEndpoints/'
        response = self.client.get(api_url, {'subdomain_id': self.subdomain.id, 'project': self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['http_url'], "https://admin.example.com/endpoint")

class TestInterestingSubdomainViewSet(BaseTestCase):
    """Tests for the Interesting Subdomain ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.interesting_lookup = InterestingLookupModel.objects.create(keywords="admin", custom_type=True, title_lookup=True, url_lookup=True, condition_200_http_lookup=False)

    def test_list_interesting_subdomains(self):
        """Test listing interesting subdomains."""
        api_url = '/api/listInterestingSubdomains/'
        response = self.client.get(api_url, {'project': self.project.slug, 'scan_id': self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "admin.example.com")

    def test_list_interesting_subdomains_by_domain(self):
        """Test listing interesting subdomains by domain."""
        api_url = '/api/listInterestingSubdomains/'
        response = self.client.get(api_url, {'target_id': self.domain.id, 'project': self.project.slug, 'scan_id': self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], "admin.example.com")
    
class TestUniversalSearch(BaseTestCase):
    """Tests for the Universal Search API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.create_vulnerability()

    def test_universal_search(self):
        api_url = reverse('api:search')
        response = self.client.get(api_url, {'query': 'admin'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertIn('admin.example.com', [sub['name'] for sub in response.data['results']['subdomains']])
        self.assertIn('https://admin.example.com/endpoint', [ep['http_url'] for ep in response.data['results']['endpoints']])

    def test_universal_search_no_query(self):
        api_url = reverse('api:search')
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['status'])
        self.assertEqual(response.data['message'], 'No query parameter provided!')

class TestFetchMostCommonVulnerability(BaseTestCase):
    """Tests for the Fetch Most Common Vulnerability API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_vulnerability()
        self.create_vulnerability()

    def test_fetch_most_common_vulnerability(self):
        api_url = reverse('api:fetch_most_common_vulnerability')
        data = {
                'target_id': int(self.domain.id),
                'scan_history_id': int(self.scan_history.id),
                # 'subdomain_id': int(self.scan_history.id),
                'slug': self.project.slug,
                'limit': 10
                }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['result'][0]['name'], "Common Vulnerability")
        self.assertEqual(response.data['result'][0]['count'], 2)

class TestFetchMostVulnerable(BaseTestCase):
    """Tests for the Fetch Most Vulnerable API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_vulnerability()
        self.create_vulnerability()

    def test_fetch_most_vulnerable(self):
        api_url = reverse('api:fetch_most_vulnerable')
        data = {
                'target_id': int(self.domain.id),
                'scan_history_id': int(self.scan_history.id),
                'slug': self.project.slug,
                'limit': 10
                }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['result'][0]['name'], "admin.example.com")
        self.assertEqual(response.data['result'][0]['vuln_count'], 2)

class TestCVEDetails(BaseTestCase):
    """Tests for the CVE Details API."""

    @patch('requests.get')
    def test_get_cve_details(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"id": "CVE-2021-44228", "summary": "Log4j vulnerability"}
        api_url = reverse('api:cve_details')
        response = self.client.get(api_url, {'cve_id': 'CVE-2021-44228'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['result']['id'], "CVE-2021-44228")

    def test_get_cve_details_missing_id(self):
        api_url = reverse('api:cve_details')
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['status'])
        self.assertEqual(response.data['message'], 'CVE ID not provided')

class TestAddReconNote(BaseTestCase):
    """Tests for the Add Recon Note API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_add_recon_note(self):
        api_url = reverse('api:addReconNote')
        data = {
            'subdomain_id': self.subdomain.id,
            'scan_history_id': self.scan_history.id,
            'title': 'Test Note',
            'description': 'This is a test note',
            'project': self.project.slug
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_add_recon_note_missing_data(self):
        api_url = reverse('api:addReconNote')
        data = {'title': 'Test Note', 'slug': 'test-project'}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['status'])

class TestToggleSubdomainImportantStatus(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_toggle_subdomain_important_status(self):
        api_url = reverse('api:toggle_subdomain')
        initial_status = self.subdomain.is_important
        response = self.client.post(api_url, {'subdomain_id': self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.subdomain.refresh_from_db()
        self.assertNotEqual(initial_status, self.subdomain.is_important)

class TestAddTarget(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project()

    def test_add_target(self):
        api_url = reverse('api:addTarget')
        data = {
            'domain_name': 'example.com',
            'h1_team_handle': 'team_handle',
            'description': 'Test description',
            'organization': 'Test Org',
            'slug': self.project.slug
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['domain_name'], 'example.com')
        self.assertTrue(Domain.objects.filter(name='example.com').exists())

class TestFetchSubscanResults(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_subscan()

    def test_fetch_subscan_results(self):
        api_url = reverse('api:fetch_subscan_results')
        response = self.client.get(api_url, {'subscan_id': self.subscans[0].id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('subscan', response.data)
        self.assertIn('result', response.data)

class TestListSubScans(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_subscan()

    def test_list_subscans(self):
        api_url = reverse('api:listSubScans')
        response = self.client.post(api_url, {'scan_history_id': self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertEqual(len(response.data['results']), 1)

class TestDeleteMultipleRows(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_subscan()
        self.create_subscan()

    def test_delete_multiple_rows(self):
        api_url = reverse('api:delete_rows')
        data = {
            'type': 'subscan',
            'rows': [int(self.subscans[0].id), int(self.subscans[1].id)]
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertFalse(SubScan.objects.filter(id__in=[self.subscans[0].id, self.subscans[1].id]).exists())

class TestUpdateTool(BaseTestCase):
    @patch('api.views.run_command')
    def test_update_tool(self, mock_run_command):
        self.create_installed_external_tool()
        tool = InstalledExternalTool.objects.first()
        api_url = reverse('api:update_tool')
        response = self.client.get(api_url, {'tool_id': tool.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        mock_run_command.assert_called()
        mock_run_command.apply_async.assert_called_once()