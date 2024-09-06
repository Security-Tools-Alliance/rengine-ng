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
from startScan.models import (
    ScanHistory,
    Subdomain,
    EndPoint,
    Vulnerability,
    DirectoryScan,
    DirectoryFile,
    SubScan,
    Technology,
    Port,
    Employee,
    Email,
    Dork,
    CountryISO,
    IpAddress,
    MetaFinderDocument
)
from targetApp.models import (
    Domain,
    Organization,
    WhoisStatus,
    NameServer,
    DNSRecord,
    RelatedDomain,
    HistoricalIP,
    DomainInfo,
    Registrar,
    DomainRegistration,
)
import logging


class BaseTestCase(TestCase):
    """
    Base test case for all API tests.
    Sets up common fixtures and mocks the user login process.
    """

    fixtures = [
        "dashboard.json",
        "targetApp.json",
        "scanEngine.json",
        "startScan.json",
        "recon_note.json",
        "fixtures/auth.json",
        "fixtures/django_celery_beat.json",
    ]

    def setUp(self):
        self.client = Client()
        user = get_user_model()
        self.user = user.objects.get(username="rengine")

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
            name="Test Project", insert_date=timezone.now(), slug="test-project"
        )
        return self.project

    def create_domain(self):
        self.domain = Domain.objects.create(
            name="example.com", project=self.project, insert_date=timezone.now()
        )
        return self.domain

    def create_scan_history(self):
        self.scan_history = ScanHistory.objects.create(
            domain=self.domain, start_scan_date=timezone.now(), scan_type_id=1
        )
        return self.scan_history

    def create_subdomain(self):
        self.subdomain = Subdomain.objects.create(
            name="admin.example.com",
            target_domain=self.domain,
            scan_history=self.scan_history,
        )
        return self.subdomain

    def create_endpoint(self):
        self.endpoint = EndPoint.objects.create(
            target_domain=self.domain,
            subdomain=self.subdomain,
            scan_history=self.scan_history,
            http_url="https://admin.example.com/endpoint",
        )
        return self.endpoint

    def create_vulnerability(self):
        self.vulnerabilities.append(
            Vulnerability.objects.create(
                name="Common Vulnerability",
                severity=1,
                discovered_date=timezone.now(),
                target_domain=self.domain,
                subdomain=self.subdomain,
                scan_history=self.scan_history,
                endpoint=self.endpoint,
            )
        )
        return self.vulnerabilities

    def create_directory_scan(self):
        self.directory_scan = DirectoryScan.objects.create(
            command_line="Test Command", scanned_date=timezone.now()
        )
        return self.directory_scan

    def create_directory_file(self):
        self.directory_file = DirectoryFile.objects.create(
            name="test.txt", url="https://example.com/test.txt"
        )
        return self.directory_file

    def create_subscan(self):
        self.subscans.append(
            SubScan.objects.create(
                start_scan_date=timezone.now(),
                scan_history=self.scan_history,
                subdomain=self.subdomain,
                status=1,
            )
        )
        return self.subscans

    def create_installed_external_tool(self):
        self.installed_external_tool = InstalledExternalTool.objects.create(
            name="OneForAll",
            github_url="https://github.com/shmilylty/OneForAll",
            update_command="git pull",
            install_command="git clone https://github.com/shmilylty/OneForAll"
        )
        return self.installed_external_tool

    def create_todo_note(self):
        self.todo_note = TodoNote.objects.create(
            title="Test Note",
            description="Test Description",
            project=self.project,
            subdomain=self.subdomain,
            scan_history=self.scan_history,
        )
        return self.todo_note

    def create_search_history(self):
        self.search_history = SearchHistory.objects.create(query="Test Query")
        return self.search_history

    def create_interesting_lookup_model(self):
        self.interesting_lookup_model = InterestingLookupModel.objects.create(
            keywords="Test Keywords",
            custom_type=True,
            title_lookup=True,
            url_lookup=True,
            condition_200_http_lookup=False,
        )
        return self.interesting_lookup_model

    def create_engine_type(self):
        self.engine_type = EngineType.objects.create(
            engine_name="Test Engine",
            yaml_configuration="http_crawl: \{\}",
            default_engine=True,
        )
        return self.engine_type

    def create_organization(self):
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test Description",
            insert_date=timezone.now(),
            project=self.project,
        )
        self.organization.domains.add(self.domain)
        return self.organization

    def create_employee(self):
        self.employee = Employee.objects.create(name="Test Employee")
        self.scan_history.employees.add(self.employee)
        return self.employee

    def create_email(self):
        self.email = Email.objects.create(
            address="test@example.com", password="password"
        )
        self.scan_history.emails.add(self.email)
        return self.email

    def create_dork(self):
        self.dork = Dork.objects.create(type="Test Dork", url="https://example.com")
        self.scan_history.dorks.add(self.dork)
        return self.dork

    def create_domain_info(self):
        self.domain_info = DomainInfo.objects.create(
            created=timezone.now(),
            updated=timezone.now(),
            expires=timezone.now(),
            geolocation_iso="US",
            registrant=self.domain_registration,
            admin=self.domain_registration,
            tech=self.domain_registration,
        )
        self.domain_info.name_servers.add(self.name_server)
        self.domain_info.dns_records.add(self.dns_record)
        self.domain_info.related_domains.add(self.related_domain)
        self.domain_info.related_tlds.add(self.related_domain)
        self.domain_info.similar_domains.add(self.related_domain)
        self.domain_info.historical_ips.add(self.historical_ip)
        return self.domain_info

    def create_whois_status(self):
        self.whois_status = WhoisStatus.objects.create(
            name="clienttransferprohibited",
        )
        return self.whois_status

    def create_name_server(self):
        self.name_server = NameServer.objects.create(
            name="Test Name Server",
        )
        return self.name_server

    def create_dns_record(self):
        self.dns_record = DNSRecord.objects.create(
            name="Test DNS Record",
            type="a",
        )
        return self.dns_record

    def create_related_domain(self):
        self.related_domain = RelatedDomain.objects.create(
            name="test.com",
        )
        return self.related_domain

    def create_domain_registration(self):
        self.domain_registration = DomainRegistration.objects.create(
            name="Test Domain Registration"
        )
        return self.domain_registration

    def create_registrar(self):
        self.registrar = Registrar.objects.create(
            name="Test Registrar",
        )
        return self.registrar

    def create_historical_ip(self):
        self.historical_ip = HistoricalIP.objects.create(ip="127.0.0.1")
        return self.historical_ip

    def create_technology(self):
        self.technology = Technology.objects.create(name="Test Technology")
        self.subdomain.technologies.add(self.technology)
        return self.technology

    def create_country_iso(self):
        self.country_iso = CountryISO.objects.create(iso="US")
        return self.country_iso

    def create_ip_address(self):
        self.ip_address = IpAddress.objects.create(address="1.1.1.1")
        self.ip_address.ports.add(self.port)
        self.subdomain.ip_addresses.add(self.ip_address)
        return self.ip_address

    def create_port(self):
        self.port = Port.objects.create(
            number=80, service_name="http", description="open", is_uncommon=True
        )
        return self.port

    def create_metafinder_document(self):
        self.metafinder_document = MetaFinderDocument.objects.create(
            title="Test MetaFinder Document",
            url="https://example.com",
            author="Test Author",
            doc_name="test.pdf",
            creation_date=timezone.now(),
            modified_date=timezone.now(),
            scan_history=self.scan_history,
            target_domain=self.domain,
            subdomain=self.subdomain,
        )
        return self.metafinder_document

    def create_project_full(self):
        self.create_project()
        self.create_domain()
        self.create_scan_history()
        self.create_subdomain()
        self.create_endpoint()
        self.create_port()
        self.create_ip_address()
        self.create_vulnerability()
        self.create_directory_scan()
        self.create_directory_file()
        self.create_subscan()
        self.create_todo_note()
        self.create_engine_type()
        self.create_organization()
        self.create_employee()
        self.create_email()
        self.create_dork()
        self.create_whois_status()
        self.create_name_server()
        self.create_dns_record()
        self.create_related_domain()
        self.create_historical_ip()
        self.create_technology()
        self.create_country_iso()
        self.create_domain_registration()
        self.create_domain_info()
        self.create_metafinder_document()

    def create_project_base(self):
        self.create_project()
        self.create_domain()
        self.create_scan_history()
        self.create_subdomain()
        self.create_port()
        self.create_ip_address()

    def create_project_additionals(self):
        self.create_vulnerability()
        self.create_endpoint()
        self.create_directory_scan()
        self.create_directory_file()
        self.create_subscan()
        self.create_todo_note()
        self.create_engine_type()
        self.create_organization()
        self.create_employee()
        self.create_email()
        self.create_dork()
        self.create_whois_status()
        self.create_name_server()
        self.create_dns_record()
        self.create_related_domain()
        self.create_historical_ip()
        self.create_technology()
        self.create_country_iso()
        self.create_domain_registration()
        self.create_domain_info()
        self.create_metafinder_document()

    def tearDown(self):
        # Restore original on_user_logged_in function
        on_user_logged_in.__code__ = self.original_on_user_logged_in.__code__


class TestOllamaManager(BaseTestCase):
    """Tests for the OllamaManager API endpoints."""

    @patch("requests.post")
    def test_get_download_model(self, mock_post):
        """Test downloading an Ollama model."""
        mock_post.return_value.json.return_value = {"status": "success"}
        api_url = reverse("api:ollama_manager")
        response = self.client.get(api_url, data={"model": "gpt-4"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    @patch("requests.delete")
    def test_delete_model(self, mock_delete):
        """Test deleting an Ollama model."""
        mock_delete.return_value.json.return_value = {"status": "success"}
        api_url = reverse("api:ollama_manager")
        response = self.client.delete(
            api_url, data={"model": "gpt-4"}, content_type="application/json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    def test_put_update_model(self):
        """Test updating the selected Ollama model."""
        api_url = reverse("api:ollama_manager")
        response = self.client.put(
            api_url, data={"model": "gpt-4"}, content_type="application/json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])


class TestGPTAttackSuggestion(BaseTestCase):
    """Tests for the GPT Attack Suggestion API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    @patch("reNgine.gpt.GPTAttackSuggestionGenerator.get_attack_suggestion")
    def test_get_attack_suggestion(self, mock_get_suggestion):
        """Test getting an attack suggestion for a subdomain."""
        mock_get_suggestion.return_value = {
            "status": True,
            "description": "Test attack suggestion",
        }
        api_url = reverse("api:gpt_get_possible_attacks")
        response = self.client.get(api_url, {"subdomain_id": self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["description"], "Test attack suggestion")


class TestGPTVulnerabilityReportGenerator(BaseTestCase):
    """Tests for the GPT Vulnerability Report Generator API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.create_vulnerability()

    @patch("reNgine.tasks.gpt_vulnerability_description.apply_async")
    def test_get_vulnerability_report(self, mock_apply_async):
        """Test generating a vulnerability report."""
        mock_task = MagicMock()
        mock_task.wait.return_value = {
            "status": True,
            "description": "Test vulnerability report",
        }
        mock_apply_async.return_value = mock_task
        api_url = reverse("api:gpt_vulnerability_report_generator")
        response = self.client.get(api_url, {"id": self.vulnerabilities[0].id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["description"], 'Test vulnerability report')


class TestCreateProjectApi(BaseTestCase):
    """Tests for the Create Project API."""

    def test_create_project_success(self):
        """Test successful project creation."""
        api_url = reverse("api:create_project")
        response = self.client.get(
            api_url,
            {
                "name": "New Project",
                "insert_date": timezone.now(),
                "slug": "new-project",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["project_name"], "New Project")

    def test_create_project_failure(self):
        """Test project creation failure when no name is provided."""
        api_url = reverse("api:create_project")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])


class TestQueryInterestingSubdomains(BaseTestCase):
    """Tests for querying interesting subdomains."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_interesting_lookup_model()

    def test_query_interesting_subdomains(self):
        """Test querying interesting subdomains for a given scan."""
        api_url = reverse("api:queryInterestingSubdomains")
        response = self.client.get(api_url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("admin.example.com", [sub["name"] for sub in response.data])


class TestDeleteSubdomain(BaseTestCase):
    """Tests for deleting subdomains."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_delete_subdomain(self):
        """Test deleting a subdomain."""
        api_url = reverse("api:delete_subdomain")
        data = {"subdomain_ids": [str(self.subdomain.id)]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertFalse(Subdomain.objects.filter(id=self.subdomain.id).exists())


class TestDeleteVulnerability(BaseTestCase):
    """Tests for deleting vulnerabilities."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.create_vulnerability()

    def test_delete_vulnerability(self):
        """Test deleting a vulnerability."""
        api_url = reverse("api:delete_vulnerability")
        data = {"vulnerability_ids": [self.vulnerabilities[0].id]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertFalse(
            Vulnerability.objects.filter(id=self.vulnerabilities[0].id).exists()
        )


class TestListInterestingKeywords(BaseTestCase):
    """Tests for listing interesting keywords."""

    @patch("api.views.get_lookup_keywords")
    def test_list_interesting_keywords(self, mock_get_keywords):
        """Test listing interesting keywords."""
        mock_get_keywords.return_value = ["keyword1", "keyword2"]
        api_url = reverse("api:listInterestingKeywords")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, ["keyword1", "keyword2"])


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


class TestSearchHistoryView(BaseTestCase):
    """Tests for the Search History API."""

    def setUp(self):
        super().setUp()
        self.create_search_history()

    def test_get_search_history(self):
        """Test retrieving search history."""
        api_url = reverse("api:search_history")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["query"], self.search_history.query)


class TestListTargetsDatatableViewSet(BaseTestCase):
    """Tests for the List Targets Datatable API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_list_targets(self):
        """Test listing targets."""
        api_url = "/api/listTargets/"
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.domain.name)

    def test_list_targets_with_slug(self):
        """Test listing targets with project slug."""
        api_url = "/api/listTargets/"
        response = self.client.get(api_url, {"slug": "test-project"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.domain.name)


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
        api_url = "/api/listDirectories/"
        response = self.client.get(api_url, {"scan_history": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.directory_file.name)

    def test_get_directory_files_by_subdomain(self):
        """Test retrieving directory files by subdomain."""
        api_url = "/api/listDirectories/"
        response = self.client.get(api_url, {"subdomain_id": self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.directory_file.name)


class TestVulnerabilityViewSet(BaseTestCase):
    """Tests for the Vulnerability ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.create_vulnerability()

    def test_list_vulnerabilities(self):
        """Test listing vulnerabilities."""
        api_url = "/api/listVulnerability/"
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.vulnerabilities[0].name)

    def test_list_vulnerabilities_by_scan(self):
        """Test listing vulnerabilities by scan history."""
        api_url = "/api/listVulnerability/"
        response = self.client.get(api_url, {"scan_history": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.vulnerabilities[0].name)

    def test_list_vulnerabilities_by_domain(self):
        """Test listing vulnerabilities by domain."""
        api_url = "/api/listVulnerability/"
        response = self.client.get(api_url, {"domain": "example.com"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.vulnerabilities[0].name)

    def test_list_vulnerabilities_by_severity(self):
        """Test listing vulnerabilities by severity."""
        api_url = "/api/listVulnerability/"
        response = self.client.get(api_url, {"severity": 1})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.vulnerabilities[0].name)


class TestSubdomainDatatableViewSet(BaseTestCase):
    """Tests for the Subdomain Datatable ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_list_subdomains(self):
        """Test listing subdomains."""
        api_url = "/api/listDatatableSubdomain/"
        response = self.client.get(api_url, {"project": self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.subdomain.name)

    def test_list_subdomains_by_domain(self):
        """Test listing subdomains by domain."""
        api_url = "/api/listDatatableSubdomain/"
        response = self.client.get(
            api_url, {"target_id": self.domain.id, "project": self.project.slug}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.subdomain.name)


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
            http_url=self.endpoint.http_url,
        )

    def test_list_endpoints(self):
        """Test listing endpoints."""
        api_url = "/api/listEndpoints/"
        response = self.client.get(api_url, {"project": self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.endpoint.http_url,
        )

    def test_list_endpoints_by_subdomain(self):
        """Test listing endpoints by subdomain."""
        api_url = "/api/listEndpoints/"
        response = self.client.get(
            api_url, {"subdomain_id": self.subdomain.id, "project": self.project.slug}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.endpoint.http_url,
        )


class TestInterestingSubdomainViewSet(BaseTestCase):
    """Tests for the Interesting Subdomain ViewSet API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.interesting_lookup = InterestingLookupModel.objects.create(
            keywords="admin",
            custom_type=True,
            title_lookup=True,
            url_lookup=True,
            condition_200_http_lookup=False,
        )

    def test_list_interesting_subdomains(self):
        """Test listing interesting subdomains."""
        api_url = "/api/listInterestingSubdomains/"
        response = self.client.get(
            api_url, {"project": self.project.slug, "scan_id": self.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.subdomain.name)

    def test_list_interesting_subdomains_by_domain(self):
        """Test listing interesting subdomains by domain."""
        api_url = "/api/listInterestingSubdomains/"
        response = self.client.get(
            api_url,
            {
                "target_id": self.domain.id,
                "project": self.project.slug,
                "scan_id": self.scan_history.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.subdomain.name)


class TestUniversalSearch(BaseTestCase):
    """Tests for the Universal Search API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.create_vulnerability()

    def test_universal_search(self):
        api_url = reverse("api:search")
        response = self.client.get(api_url, {"query": "admin"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn(
            "admin.example.com",
            [sub["name"] for sub in response.data["results"]["subdomains"]],
        )
        self.assertIn(
            "https://admin.example.com/endpoint",
            [ep["http_url"] for ep in response.data["results"]["endpoints"]],
        )

    def test_universal_search_no_query(self):
        api_url = reverse("api:search")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["message"], "No query parameter provided!")


class TestFetchMostCommonVulnerability(BaseTestCase):
    """Tests for the Fetch Most Common Vulnerability API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.create_vulnerability()
        self.create_vulnerability()

    def test_fetch_most_common_vulnerability(self):
        api_url = reverse("api:fetch_most_common_vulnerability")
        data = {
            "target_id": int(self.domain.id),
            "scan_history_id": int(self.scan_history.id),
            # 'subdomain_id': int(self.scan_history.id),
            "slug": self.project.slug,
            "limit": 10,
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["result"][0]["name"], self.vulnerabilities[0].name)
        self.assertEqual(response.data["result"][0]["count"], 2)


class TestFetchMostVulnerable(BaseTestCase):
    """Tests for the Fetch Most Vulnerable API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_endpoint()
        self.create_vulnerability()
        self.create_vulnerability()

    def test_fetch_most_vulnerable(self):
        api_url = reverse("api:fetch_most_vulnerable")
        data = {
            "target_id": int(self.domain.id),
            "scan_history_id": int(self.scan_history.id),
            "slug": self.project.slug,
            "limit": 10,
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["result"][0]["name"], self.subdomain.name)
        self.assertEqual(response.data["result"][0]["vuln_count"], 2)


class TestCVEDetails(BaseTestCase):
    """Tests for the CVE Details API."""

    @patch("requests.get")
    def test_get_cve_details(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "id": "CVE-2021-44228",
            "summary": "Log4j vulnerability",
        }
        api_url = reverse("api:cve_details")
        response = self.client.get(api_url, {"cve_id": "CVE-2021-44228"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["result"]["id"], "CVE-2021-44228")

    def test_get_cve_details_missing_id(self):
        api_url = reverse("api:cve_details")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["message"], "CVE ID not provided")


class TestAddReconNote(BaseTestCase):
    """Tests for the Add Recon Note API."""

    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_add_recon_note(self):
        api_url = reverse("api:addReconNote")
        data = {
            "subdomain_id": self.subdomain.id,
            "scan_history_id": self.scan_history.id,
            "title": "Test Note",
            "description": "This is a test note",
            "project": self.project.slug,
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    def test_add_recon_note_missing_data(self):
        api_url = reverse("api:addReconNote")
        data = {"title": "Test Note", "slug": "test-project"}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])


class TestToggleSubdomainImportantStatus(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_toggle_subdomain_important_status(self):
        api_url = reverse("api:toggle_subdomain")
        initial_status = self.subdomain.is_important
        response = self.client.post(api_url, {"subdomain_id": self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.subdomain.refresh_from_db()
        self.assertNotEqual(initial_status, self.subdomain.is_important)


class TestAddTarget(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    def test_add_target(self):
        api_url = reverse("api:addTarget")
        data = {
            "domain_name": "example.com",
            "h1_team_handle": "team_handle",
            "description": "Test description",
            "organization": "Test Org",
            "slug": self.project.slug,
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["domain_name"], self.domain.name)
        self.assertTrue(Domain.objects.filter(name=self.domain.name).exists())


class TestFetchSubscanResults(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_subscan()

    def test_fetch_subscan_results(self):
        api_url = reverse("api:fetch_subscan_results")
        response = self.client.get(api_url, {"subscan_id": self.subscans[0].id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("subscan", response.data)
        self.assertIn("result", response.data)


class TestListSubScans(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_subscan()

    def test_list_subscans(self):
        api_url = reverse("api:listSubScans")
        response = self.client.post(api_url, {"scan_history_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(len(response.data["results"]), 1)


class TestDeleteMultipleRows(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_subscan()
        self.create_subscan()

    def test_delete_multiple_rows(self):
        api_url = reverse("api:delete_rows")
        data = {
            "type": "subscan",
            "rows": [int(self.subscans[0].id), int(self.subscans[1].id)],
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertFalse(
            SubScan.objects.filter(
                id__in=[self.subscans[0].id, self.subscans[1].id]
            ).exists()
        )


class TestUpdateTool(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_installed_external_tool()

    @patch("api.views.run_command")
    def test_update_tool(self, mock_run_command):
        api_url = reverse("api:update_tool")
        response = self.client.get(api_url, {"tool_id": self.installed_external_tool.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_run_command.assert_called()
        mock_run_command.apply_async.assert_called_once()


class TestGetExternalToolCurrentVersion(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.tool = self.create_installed_external_tool()
        self.tool.version_lookup_command = "echo 'v1.0.0'"
        self.tool.version_match_regex = r"v\d+\.\d+\.\d+"
        self.tool.save()

    @patch("api.views.run_command")
    def test_get_external_tool_current_version(self, mock_run_command):
        mock_run_command.return_value = (None, "v1.0.0")
        url = reverse("api:external_tool_get_current_release")
        response = self.client.get(url, {"tool_id": self.tool.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["version_number"], "v1.0.0")
        self.assertEqual(response.data["tool_name"], self.tool.name)


class TestGithubToolCheckGetLatestRelease(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.tool = self.create_installed_external_tool()
        self.tool.github_url = "https://github.com/example/tool"
        self.tool.save()

    @patch("api.views.requests.get")
    def test_github_tool_check_get_latest_release(self, mock_get):
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


class TestScanStatus(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_scan_status(self):
        url = reverse("api:scan_status")
        response = self.client.get(url, {"project": self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("scans", response.data)
        self.assertIn("tasks", response.data)


class TestWhois(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    @patch("api.views.query_whois.apply_async")
    def test_whois(self, mock_apply_async):
        mock_apply_async.return_value.wait.return_value = {
            "status": True,
            "data": "Whois data",
        }
        url = reverse("api:whois")
        response = self.client.get(url, {"ip_domain": self.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["data"], "Whois data")


class TestReverseWhois(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    @patch("api.views.query_reverse_whois.apply_async")
    def test_reverse_whois(self, mock_apply_async):
        mock_apply_async.return_value.wait.return_value = {
            "status": True,
            "data": "Reverse Whois data",
        }
        url = reverse("api:reverse_whois")
        response = self.client.get(url, {"lookup_keyword": self.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["data"], "Reverse Whois data")


class TestDomainIPHistory(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    @patch("api.views.query_ip_history.apply_async")
    def test_domain_ip_history(self, mock_apply_async):
        mock_apply_async.return_value.wait.return_value = {
            "status": True,
            "data": "IP History data",
        }
        url = reverse("api:domain_ip_history")
        response = self.client.get(url, {"domain": self.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["data"], "IP History data")


class TestCMSDetector(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    @patch("api.views.run_cmseek.delay")
    def test_cms_detector(self, mock_run_cmseek):
        mock_run_cmseek.return_value.get.return_value = {
            "status": True,
            "cms": "WordPress",
        }
        url = reverse("api:cms_detector")
        response = self.client.get(url, {"url": self.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["cms"], "WordPress")


class TestIPToDomain(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()

    @patch("api.views.socket.gethostbyaddr")
    def test_ip_to_domain(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = (self.domain.name, [self.domain.name], [self.subdomain.ip_addresses.first().address])
        url = reverse("api:ip_to_domain")
        response = self.client.get(url, {"ip_address": self.subdomain.ip_addresses.first().address})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["ip_address"][0]["domain"], self.domain.name)


class TestVulnerabilityReport(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()
        self.create_endpoint()
        self.create_vulnerability()

    @patch("api.views.send_hackerone_report")
    def test_vulnerability_report(self, mock_send_report):
        mock_send_report.return_value = True
        url = reverse("api:vulnerability_report")
        response = self.client.get(url, {"vulnerability_id": self.vulnerabilities[0].id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])


class TestGetFileContents(BaseTestCase):
    @patch("api.views.os.path.exists")
    @patch("api.views.run_command")
    def test_get_file_contents(self, mock_run_command, mock_exists):
        mock_exists.return_value = True
        mock_run_command.return_value = (0, "test content")
        url = reverse("api:getFileContents")
        response = self.client.get(url, {"nuclei_config": True})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertGreaterEqual(len(response.data["content"]), 1)


class TestGfList(BaseTestCase):
    @patch("api.views.run_gf_list.delay")
    def test_gf_list(self, mock_run_gf_list):
        mock_run_gf_list.return_value.get.return_value = {
            "status": True,
            "output": ["pattern1", "pattern2"],
        }
        url = reverse("api:gf_list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, ["pattern1", "pattern2"])


class TestListTodoNotes(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()
        self.create_todo_note()

    def test_list_todo_notes(self):
        url = reverse("api:listTodoNotes")
        response = self.client.get(url, {"project": self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["notes"]), 1)
        self.assertEqual(response.data["notes"][0]["id"], self.todo_note.id)
        self.assertEqual(response.data["notes"][0]["title"], self.todo_note.title)
        self.assertEqual(
            response.data["notes"][0]["description"], self.todo_note.description
        )
        self.assertEqual(
            response.data["notes"][0]["project"], self.todo_note.project.id
        )
        self.assertEqual(
            response.data["notes"][0]["subdomain"], self.todo_note.subdomain.id
        )
        self.assertEqual(
            response.data["notes"][0]["scan_history"], self.todo_note.scan_history.id
        )


class TestListScanHistory(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_scan_history(self):
        url = reverse("api:listScanHistory")
        response = self.client.get(url, {"project": self.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], self.scan_history.id)


class TestListEngines(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_engines(self):
        url = reverse("api:listEngines")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("engines", response.data)
        self.assertGreaterEqual(len(response.data["engines"]), 1)


class TestListOrganizations(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_organizations(self):
        url = reverse("api:listOrganizations")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("organizations", response.data)
        self.assertEqual(len(response.data["organizations"]), 1)
        self.assertEqual(response.data["organizations"][0]["name"], self.organization.name)


class TestListTargetsInOrganization(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_targets_in_organization(self):
        url = reverse("api:queryTargetsInOrganization")
        response = self.client.get(url, {"organization_id": self.organization.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("organization", response.data)
        self.assertIn("domains", response.data)
        self.assertEqual(len(response.data["domains"]), 1)
        self.assertEqual(response.data["domains"][0]["name"], self.domain.name)


class TestListTargetsWithoutOrganization(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_targets_without_organization(self):
        url = reverse("api:queryTargetsWithoutOrganization")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("domains", response.data)
        self.assertEqual(len(response.data["domains"]), 1)
        self.assertEqual(response.data["domains"][0]["name"], 'vulnweb.com')


class TestVisualiseData(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_visualise_data(self):
        url = reverse("api:queryAllScanResultVisualise")
        response = self.client.get(url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["description"], self.domain.name)


class TestListTechnology(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_technology(self):
        url = reverse("api:listTechnologies")
        response = self.client.get(url, {"target_id": self.domain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("technologies", response.data)
        self.assertEqual(len(response.data["technologies"]), 1)
        self.assertEqual(response.data["technologies"][0]["name"], self.technology.name)


class TestListDorkTypes(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_dork_types(self):
        url = reverse("api:queryDorkTypes")
        response = self.client.get(url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("dorks", response.data)
        self.assertEqual(len(response.data["dorks"]), 1)
        self.assertEqual(response.data["dorks"][0]["type"], self.dork.type)


class TestListEmails(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_emails(self):
        url = reverse("api:queryEmails")
        response = self.client.get(url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("emails", response.data)
        self.assertEqual(len(response.data["emails"]), 1)
        self.assertEqual(response.data["emails"][0]["address"], self.email.address)


class TestListDorks(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_dorks(self):
        url = reverse("api:queryDorks")
        response = self.client.get(url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("dorks", response.data)
        self.assertIn("Test Dork", response.data["dorks"])
        self.assertEqual(len(response.data["dorks"]["Test Dork"]), 1)
        self.assertEqual(response.data["dorks"]["Test Dork"][0]["type"], self.dork.type)


class TestListEmployees(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_employees(self):
        url = reverse("api:queryEmployees")
        response = self.client.get(url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("employees", response.data)
        self.assertEqual(len(response.data["employees"]), 1)
        self.assertEqual(response.data["employees"][0]["name"], self.employee.name)


class TestListPorts(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_ports(self):
        url = reverse("api:listPorts")
        response = self.client.get(
            url,
            {
                "target_id": self.domain.id,
                "scan_id": self.scan_history.id,
                "ip_address": "1.1.1.1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("ports", response.data)
        self.assertGreaterEqual(len(response.data["ports"]), 1)
        self.assertEqual(response.data["ports"][0]["number"], 80)
        self.assertEqual(response.data["ports"][0]["service_name"], "http")

class TestListSubdomains(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_full()

    def test_list_subdomains(self):
        url = reverse("api:querySubdomains")
        response = self.client.get(url, {"target_id": self.domain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("subdomains", response.data)
        self.assertEqual(len(response.data["subdomains"]), 1)
        self.assertEqual(response.data["subdomains"][0]["name"], self.subdomain.name)

class TestListOsintUsers(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_metafinder_document()

    def test_list_osint_users(self):
        url = reverse("api:queryMetadata")
        response = self.client.get(url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("metadata", response.data)
        self.assertEqual(len(response.data["metadata"]), 1)
        self.assertEqual(response.data["metadata"][0]["author"], self.metafinder_document.author)

class TestListMetadata(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_project_base()
        self.create_metafinder_document()

    def test_list_metadata(self):
        url = reverse("api:queryMetadata")
        response = self.client.get(url, {"scan_id": self.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("metadata", response.data)
        self.assertEqual(len(response.data["metadata"]), 1)
        self.assertEqual(response.data["metadata"][0]["doc_name"], self.metafinder_document.doc_name)
        self.assertEqual(response.data["metadata"][0]["url"], self.metafinder_document.url)
        self.assertEqual(response.data["metadata"][0]["title"], self.metafinder_document.title)