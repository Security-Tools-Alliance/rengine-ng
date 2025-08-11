"""
This file contains the test cases 
"""

import logging
import json

from django.utils import timezone
from django.test import override_settings
from django.template.loader import get_template
from django.template import Template

from dashboard.models import Project, SearchHistory
from recon_note.models import TodoNote
from scanEngine.models import (
    EngineType,
    Hackerone,
    InstalledExternalTool,
    InterestingLookupModel,
    Proxy,
    VulnerabilityReportSetting,
    Wordlist,
)

from startScan.models import (
    Command,
    DirectoryFile,
    DirectoryScan,
    Dork,
    Email,
    EndPoint,
    Employee,
    IpAddress,
    ScanActivity,
    ScanHistory,
    SubScan,
    Subdomain,
    Technology,
    Vulnerability,
    Port,
    CountryISO,
    MetaFinderDocument,
)

from targetApp.models import (
    DNSRecord,
    Domain,
    DomainInfo,
    DomainRegistration,
    HistoricalIP,
    NameServer,
    Organization,
    Registrar,
    RelatedDomain,
    WhoisStatus,
)
__all__ = [
    'TestDataGenerator'
]

class TestDataGenerator:
    """
    Base test case for all API tests.
    Sets up common fixtures and mocks the user login process.
    """


    subscans = []
    vulnerabilities = []

    # Disable logging for tests
    logging.disable(logging.CRITICAL)


    def create_project_base(self):
        """Create a basic project setup with essential objects."""
        self.create_project()
        self.create_domain()
        self.create_scan_history()
        self.create_subdomain()
        self.create_endpoint()
        self.create_ip_address()
        self.create_port()

    def create_project_full(self):
        """Create a full project setup with all related objects."""
        self.create_project_base()
        self.create_vulnerability()
        self.create_directory_scan()
        self.create_directory_file()
        self.create_subscan()
        self.create_interesting_lookup_model()
        self.create_search_history()
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
        self.create_scan_activity()
        self.create_command()
        self.create_installed_external_tool()
        self.create_wordlist()
        self.create_proxy()
        self.create_hackerone()
        self.create_report_setting()
        self.create_external_tool()

    def create_project(self):
        """Create and return a test project."""
        self.project = Project.objects.create(
            name="Test Project",
            insert_date=timezone.now(),
            slug="test-project"
        )
        return self.project

    def create_domain(self):
        """Create and return a test domain."""
        self.domain = Domain.objects.create(
            name="example.com",
            project=self.project,
            insert_date=timezone.now()
        )
        return self.domain

    def create_scan_history(self):
        """Create and return a test scan history."""
        self.scan_history = ScanHistory.objects.create(
            domain=self.domain,
            start_scan_date=timezone.now(),
            scan_type_id=1,
            scan_status=2,
            tasks=[
                'fetch_url',
                'subdomain_discovery',
                'port_scan',
                'vulnerability_scan',
                'osint',
                'dir_file_fuzz',
                'screenshot',
                'waf_detection',
                'nuclei_scan',
                'endpoint_scan'
            ]
        )
        return self.scan_history

    def create_subdomain(self, name="admin.example.com"):
        """Create and return a test subdomain."""
        self.subdomain = Subdomain.objects.create(
            name=name,
            target_domain=self.domain,
            scan_history=self.scan_history,
        )
        return self.subdomain

    def create_endpoint(self, name="endpoint"):
        """Create and return a test endpoint."""
        self.endpoint = EndPoint.objects.create(
            target_domain=self.domain,
            subdomain=self.subdomain,
            scan_history=self.scan_history,
            discovered_date=timezone.now(),
            http_url=f"https://admin.example.com/{name}",
        )
        return self.endpoint

    def create_vulnerability(self):
        """Create and return a test vulnerability."""
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
        """Create and return a test directory scan."""
        self.directory_scan = DirectoryScan.objects.create(
            command_line="Test Command",
            scanned_date=timezone.now()
        )
        return self.directory_scan

    def create_directory_file(self):
        """Create and return a test directory file."""
        self.directory_file = DirectoryFile.objects.create(
            name="test.txt",
            url="https://example.com/test.txt"
        )
        return self.directory_file

    def create_subscan(self):
        """Create and return a test subscan."""
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
        """Create and return a test installed external tool."""
        self.installed_external_tool = InstalledExternalTool.objects.create(
            name="OneForAll",
            github_url="https://github.com/shmilylty/OneForAll",
            update_command="git pull",
            install_command="git clone https://github.com/shmilylty/OneForAll",
            github_clone_path="/home/rengine/tools/.github/OneForAll"
        )
        return self.installed_external_tool

    def create_todo_note(self):
        """Create and return a test todo note."""
        self.todo_note = TodoNote.objects.create(
            title="Test Note",
            description="Test Description",
            project=self.project,
            subdomain=self.subdomain,
            scan_history=self.scan_history,
        )
        return self.todo_note

    def create_search_history(self):
        """Create and return a test search history."""
        self.search_history = SearchHistory.objects.create(query="Test Query")
        return self.search_history

    def create_interesting_lookup_model(self):
        """Create and return a test interesting lookup model."""
        self.interesting_lookup_model = InterestingLookupModel.objects.create(
            keywords="admin",
            custom_type=True,
            title_lookup=True,
            url_lookup=True,
            condition_200_http_lookup=False,
        )
        return self.interesting_lookup_model

    def create_engine_type(self):
        """Create and return a test engine type."""
        self.engine_type = EngineType.objects.create(
            engine_name="Test Engine",
            yaml_configuration="http_crawl: {}",
            default_engine=True,
        )
        return self.engine_type

    def create_organization(self):
        """Create and return a test organization."""
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test Description",
            insert_date=timezone.now(),
            project=self.project,
        )
        self.organization.domains.add(self.domain)
        return self.organization

    def create_employee(self):
        """Create and return a test employee."""
        self.employee = Employee.objects.create(name="Test Employee")
        self.scan_history.employees.add(self.employee)
        return self.employee

    def create_email(self):
        """Create and return a test email."""
        self.email = Email.objects.create(
            address="test@example.com",
            password="password"
        )
        self.scan_history.emails.add(self.email)
        return self.email

    def create_dork(self):
        """Create and return a test dork."""
        self.dork = Dork.objects.create(type="Test Dork", url="https://example.com")
        self.scan_history.dorks.add(self.dork)
        return self.dork

    def create_domain_info(self):
        """Create and return a test domain info."""
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
        """Create and return a test WHOIS status."""
        self.whois_status = WhoisStatus.objects.create(
            name="clienttransferprohibited",
        )
        return self.whois_status

    def create_name_server(self):
        """Create and return a test name server."""
        self.name_server = NameServer.objects.create(
            name="Test Name Server",
        )
        return self.name_server

    def create_dns_record(self):
        """Create and return a test DNS record."""
        self.dns_record = DNSRecord.objects.create(
            name="Test DNS Record",
            type="a",
        )
        return self.dns_record

    def create_related_domain(self):
        """Create and return a test related domain."""
        self.related_domain = RelatedDomain.objects.create(
            name="test.com",
        )
        return self.related_domain

    def create_domain_registration(self):
        """Create and return a test domain registration."""
        self.domain_registration = DomainRegistration.objects.create(
            name="Test Domain Registration"
        )
        return self.domain_registration

    def create_registrar(self):
        """Create and return a test registrar."""
        self.registrar = Registrar.objects.create(
            name="Test Registrar",
        )
        return self.registrar

    def create_historical_ip(self):
        """Create and return a test historical IP."""
        self.historical_ip = HistoricalIP.objects.create(ip="127.0.0.1")
        return self.historical_ip

    def create_technology(self):
        """Create and return a test technology."""
        self.technology = Technology.objects.create(name="Test Technology")
        self.subdomain.technologies.add(self.technology)
        return self.technology

    def create_country_iso(self):
        """Create and return a test country ISO."""
        self.country_iso = CountryISO.objects.create(iso="US")
        return self.country_iso

    def create_ip_address(self):
        """Create and return a test IP address."""
        self.ip_address = IpAddress.objects.create(address="1.1.1.1")
        self.subdomain.ip_addresses.add(self.ip_address)
        return self.ip_address

    def create_port(self):
        """Create and return a test port."""
        self.port = Port.objects.create(
            number=80, service_name="http", description="open", is_uncommon=True
        )
        if hasattr(self, 'ip_address'):
            self.ip_address.ports.add(self.port)
        return self.port

    def create_metafinder_document(self):
        """Create and return a test MetaFinder document."""
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

    def create_scan_activity(self):
        """Create and return a test scan activity."""
        self.scan_activity = ScanActivity.objects.create(
            name="Test Activity",
            title="Test Type",
            time=timezone.now(),
            scan_of=self.scan_history,
            status=1
        )
        return self.scan_activity

    def create_command(self):
        """Create and return a test command."""
        self.command = Command.objects.create(
            command="test command",
            time=timezone.now(),
            scan_history=self.scan_history,
            activity=self.scan_activity
        )
        return self.command

    def create_wordlist(self):
        """
        Create a test wordlist.
        """
        self.wordlist = Wordlist.objects.create(name='Test Wordlist', short_name='test', count=100)
        return self.wordlist

    def create_proxy(self):
        """
        Create a test proxy.
        """
        self.proxy = Proxy.objects.create(use_proxy=True, proxies='127.0.0.1')
        return self.proxy

    def create_hackerone(self):
        """
        Create a test hackerone.
        """
        self.hackerone = Hackerone.objects.create(username='test', api_key='testkey')
        return self.hackerone

    def create_report_setting(self):
        """
        Create a test report setting.
        """
        self.report_setting = VulnerabilityReportSetting.objects.create(
            primary_color='#000000',
            secondary_color='#FFFFFF'
        )
        return self.report_setting

    def create_external_tool(self):
        """
        Create a test external tool.
        """
        self.external_tool = InstalledExternalTool.objects.create(
            name='Test Tool',
            github_url='https://github.com/test/tool')
        return self.external_tool

class TestValidation:

    def is_json(self, value):
        try:
            json.loads(value)
            return True
        except ValueError:
            return False

class MockTemplate:
    """
    mock_template is a decorator designed to mock a specific Django template during unit tests. 
    It temporarily overrides the template settings to return a mock template when the specified 
    template name is requested, allowing for controlled testing of views that rely on that template.
    Args:
        template_name (str): The name of the template to be mocked.

    Returns:
        function: A decorator that wraps the test function, applying the mock template settings.

    Examples:
        @mock_template('my_template.html')
        def test_my_view(self):
        ...
    """
    @staticmethod
    def mock_template(template_name):
        """
        Decorator to mock a specific Django template during unit tests.
        """
        def decorator(test_func):
            """
            Decorator function to wrap the test function and apply the mock template settings.
            """
            def wrapper(*args, **kwargs):
                with override_settings(TEMPLATES=[{
                    'BACKEND': 'django.template.backends.django.DjangoTemplates',
                    'DIRS': [],
                    'APP_DIRS': True,
                    'OPTIONS': {
                        'context_processors': [
                                'django.template.context_processors.debug',
                                'django.template.context_processors.request',
                                'django.contrib.auth.context_processors.auth',
                                'django.contrib.messages.context_processors.messages',
                            ],
                        },
                    }]):
                    original_get_template = get_template
                    def mock_get_template(name):
                        return Template('') if name == template_name else original_get_template(name)

                    get_template.patched = mock_get_template
                    try:
                        return test_func(*args, **kwargs)
                    finally:
                        del get_template.patched

            return wrapper

        return decorator
