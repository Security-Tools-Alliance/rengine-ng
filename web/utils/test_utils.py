"""
This file contains the test cases
"""

from datetime import timedelta
import json
import logging

from django.template import Template
from django.template.loader import get_template
from django.test import override_settings
from django.utils import timezone

from dashboard.models import Project, SearchHistory
from recon_note.models import TodoNote
from scanEngine.models import (
    EngineType,
    Hackerone,
    InterestingLookupModel,
    Proxy,
    VulnerabilityReportSetting,
    Wordlist,
)
from startScan.models import (
    Command,
    CountryISO,
    DirectoryFile,
    DirectoryScan,
    DNSRecord,
    Domain,
    DomainInfo,
    DomainRegistration,
    Dork,
    Email,
    Employee,
    EndPoint,
    HistoricalIP,
    IpAddress,
    MetaFinderDocument,
    NameServer,
    Port,
    Registrar,
    RelatedDomain,
    ScanActivity,
    ScanHistory,
    ScanSchedule,
    Subdomain,
    SubScan,
    Technology,
    Vulnerability,
    WhoisStatus,
)
from targetApp.models import Organization, Scope, Target


__all__ = ["TestDataGenerator"]


class TestDataGenerator:
    """
    Test data generator for creating test objects programmatically.
    Replaces Django fixtures with clean, maintainable object creation.
    """

    def __init__(self):
        # Lists must be instance-scoped to avoid leaking state across tests.
        self.subscans: list[SubScan] = []
        self.vulnerabilities: list[Vulnerability] = []

    # Disable logging for tests
    logging.disable(logging.CRITICAL)

    def create_project_base(self):
        """Create a basic project setup with essential objects."""
        # Create engine type FIRST to avoid foreign key issues
        self.create_engine_type()
        self.create_project()
        self.create_target()
        self.create_domain()
        self.create_scan_history()
        self.create_subdomain()
        self.create_endpoint()
        self.create_ip_address()
        self.create_port()

    def create_project_full(self):
        """Create a full project setup with all related objects."""
        # Start with engine type to ensure it exists for scan_history
        self.create_engine_type()
        self.create_project()
        self.create_target()
        self.create_domain()
        self.create_scan_history()
        self.create_subdomain()
        self.create_endpoint()

        # Create subscan before IP address so they can be linked properly
        self.create_subscan()
        self.create_ip_address()
        self.create_port()

        # Add full features
        self.create_vulnerability()
        self.create_directory_scan()
        self.create_directory_file()
        self.create_interesting_lookup_model()
        self.create_search_history()
        self.create_todo_note()
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
        self.create_wordlist()
        self.create_proxy()
        self.create_hackerone()
        self.create_report_setting()

    def create_project(self):
        """Create and return a test project."""
        import uuid

        unique_id = str(uuid.uuid4())[:8]
        self.project, created = Project.objects.get_or_create(
            slug=f"test-project-{unique_id}",
            defaults={
                "name": f"Test Project {unique_id}",
                "insert_date": timezone.now(),
            },
        )
        return self.project

    def create_target(self):
        """Create and return a test target (type host). Requires project to exist."""
        import uuid

        unique_id = str(uuid.uuid4())[:8]
        value = f"example-{unique_id}.com"
        self.target = Target.objects.create(
            project=self.project,
            value=value,
            target_type="host",
            insert_date=timezone.now(),
        )
        return self.target

    def create_domain(self, scan_history=None):
        """Create and return a test domain. Optionally linked to a scan (scan_history).
        Target must exist for create_scan_history; call create_target() after create_project().
        If target is missing, create_target() is called first.
        """
        import uuid

        if not getattr(self, "target", None):
            self.create_target()
        unique_id = str(uuid.uuid4())[:8]
        name = f"example-{unique_id}.com"
        self.domain = Domain.objects.create(
            name=name,
            insert_date=timezone.now(),
            scan_history=scan_history,
        )
        return self.domain

    def create_scan_history(self, is_legacy=False):
        """Create and return a test scan history.

        Args:
            is_legacy: If True, create a legacy scan with scan_type. If False, create a Secator scan without scan_type.
        """
        # All new scans are Secator scans by default (scan_type=None)
        scan_kwargs = {
            "start_scan_date": timezone.now(),
            "scan_status": 2,
            "is_legacy_scan": is_legacy,
        }
        scan_kwargs["target"] = getattr(self, "target", None)

        # Only assign scan_type for legacy scans
        if is_legacy:
            scan_type = getattr(self, "engine_type", None)
            if not scan_type:
                scan_type = self.create_engine_type()
            scan_kwargs["scan_type"] = scan_type

        scan_kwargs["tasks"] = [
            "fetch_url",
            "subdomain_discovery",
            "port_scan",
            "vulnerability_scan",
            "osint",
            "dir_file_fuzz",
            "screenshot",
            "waf_detection",
            "nuclei_scan",
            "endpoint_scan",
        ]

        self.scan_history = ScanHistory.objects.create(**scan_kwargs)
        if getattr(self, "domain", None) and not self.domain.scan_history_id:
            self.domain.scan_history = self.scan_history
            self.domain.save(update_fields=["scan_history_id"])
        return self.scan_history

    def create_subdomain(self, name=None, scan_history=None, domain=None, **kwargs):
        """Create and return a test subdomain with customizable parameters."""

        # Use provided values or defaults
        if name is None:
            # Use fixed name for consistent testing
            name = "admin.example.com"

        subdomain_data = {
            "name": name,
            "domain": domain or self.domain,
            "scan_history": scan_history or self.scan_history,
        }
        subdomain_data.update(kwargs)

        self.subdomain = Subdomain.objects.create(**subdomain_data)
        return self.subdomain

    def create_endpoint(self, name=None, http_url=None, subdomain=None, scan_history=None, domain=None, **kwargs):
        """Create and return a test endpoint with customizable parameters."""

        # Use provided values or defaults
        if name is None:
            # Use fixed name for consistent testing
            name = "endpoint"

        if http_url is None:
            subdomain_name = subdomain.name if subdomain else "admin.example.com"
            http_url = f"https://{subdomain_name}/{name}"

        endpoint_data = {
            "domain": domain or self.domain,
            "subdomain": subdomain or self.subdomain,
            "scan_history": scan_history or self.scan_history,
            "discovered_date": timezone.now(),
            "http_url": http_url,
        }
        endpoint_data.update(kwargs)

        self.endpoint = EndPoint.objects.create(**endpoint_data)
        return self.endpoint

    def create_vulnerability(self):
        """Create and return a test vulnerability."""
        self.vulnerabilities.append(
            Vulnerability.objects.create(
                name="Common Vulnerability",
                severity=1,
                discovered_date=timezone.now(),
                domain=self.domain,
                subdomain=self.subdomain,
                scan_history=self.scan_history,
                endpoint=self.endpoint,
            )
        )
        return self.vulnerabilities

    def create_directory_scan(self):
        """Create and return a test directory scan."""
        self.directory_scan = DirectoryScan.objects.create(command_line="Test Command", scanned_date=timezone.now())
        return self.directory_scan

    def create_directory_file(self, name="admin", url="https://example.com/admin", http_status=200, **kwargs):
        """Create and return a test directory file with comprehensive fuzzing data.

        Args:
            name (str): File/directory name (default: "admin")
            url (str): Full URL (default: "https://example.com/admin")
            http_status (int): HTTP status code (default: 200)
            **kwargs: Additional fields (length, words, lines, content_type)
        """
        # Set default values for fuzzing-specific fields
        defaults = {"length": 1024, "words": 50, "lines": 25, "content_type": "text/html"}
        defaults.update(kwargs)

        self.directory_file = DirectoryFile.objects.create(name=name, url=url, http_status=http_status, **defaults)
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
        import uuid

        unique_id = str(uuid.uuid4())[:8]
        self.organization, created = Organization.objects.get_or_create(
            name=f"Test Organization {unique_id}",
            defaults={
                "description": "Test Description",
                "insert_date": timezone.now(),
                "project": self.project,
            },
        )
        if created and getattr(self.domain, "scan_history_id", None) and self.domain.scan_history.target_id:
            self.organization.targets.add(self.domain.scan_history.target)
        return self.organization

    def create_scope(self, scope_type="engagement_external", **kwargs):
        """Create and return a test scope linked to an organization."""
        import uuid

        if not getattr(self, "organization", None):
            self.create_organization()

        unique_id = str(uuid.uuid4())[:8]
        defaults = {
            "organization": self.organization,
            "name": f"Test Scope {unique_id}",
            "scope_type": scope_type,
            "description": "Test scope description",
        }
        defaults.update(kwargs)
        self.scope = Scope.objects.create(**defaults)
        if getattr(self, "target", None):
            self.scope.targets.add(self.target)
        return self.scope

    def create_employee(self, name=None, username=None, designation=None, **kwargs):
        """Create and return a test employee with customizable parameters."""
        import uuid

        # Use provided values or defaults
        if name is None:
            unique_id = str(uuid.uuid4())[:8]
            name = f"employee-{unique_id}"

        # Generate username if not provided
        if username is None:
            username = f"user-{str(uuid.uuid4())[:8]}"

        employee_data = {
            "name": name,
            "username": username,  # ← S'assurer que username est bien défini
        }

        if designation:
            employee_data["designation"] = designation

        employee_data.update(kwargs)

        self.employee = Employee.objects.create(**employee_data)

        # Don't auto-add to scan_history, let tests do it explicitly
        return self.employee

    def create_exploit(self, name=None, **kwargs):
        """Create and return a test exploit."""
        import uuid

        from startScan.models import Exploit

        if name is None:
            unique_id = str(uuid.uuid4())[:8]
            name = f"exploit-{unique_id}"

        exploit_data = {
            "name": name,
            "discovered_date": timezone.now(),
        }
        exploit_data.update(kwargs)

        self.exploit = Exploit.objects.create(**exploit_data)
        return self.exploit

    def create_domain_info(self, **kwargs):
        """Create and return a test DomainInfo with customizable parameters."""
        from django.utils import timezone

        domain_info_data = {
            "domain": self.domain,
            "created": timezone.now(),
        }
        domain_info_data.update(kwargs)

        self.domain_info = DomainInfo.objects.create(**domain_info_data)
        return self.domain_info

    def create_email(self, address=None, **kwargs):
        """Create and return a test Email with customizable parameters."""
        import uuid

        if address is None:
            unique_id = str(uuid.uuid4())[:8]
            address = f"user-{unique_id}@example.com"

        email_data = {
            "address": address,
        }
        email_data.update(kwargs)

        self.email = Email.objects.create(**email_data)
        return self.email

    def create_dork(self):
        """Create and return a test dork."""
        self.dork = Dork.objects.create(type="Test Dork", url="https://example.com")
        self.scan_history.dorks.add(self.dork)
        return self.dork

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
        self.domain_registration = DomainRegistration.objects.create(name="Test Domain Registration")
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

    def create_ip_address(self, address=None, is_private=None, version=None, **kwargs):
        """Create and return a test IP address with customizable parameters."""
        import uuid

        # Use provided values or defaults
        if address is None:
            # Generate random IP for uniqueness
            unique_id = str(uuid.uuid4()).split("-")[0]
            address = f"192.168.{int(unique_id[:2], 16) % 256}.{int(unique_id[2:4], 16) % 256}"

        ip_data = {
            "address": address,
        }

        if is_private is not None:
            ip_data["is_private"] = is_private
        if version is not None:
            ip_data["version"] = version

        ip_data.update(kwargs)

        self.ip_address = IpAddress.objects.create(**ip_data)

        # Don't auto-add to subdomain, let tests do it explicitly
        return self.ip_address

    def create_port(self):
        """Create and return a test port."""
        self.port = Port.objects.create(
            number=80,
            service_name="http",
            description="open",
            is_uncommon=True,
            ip_address=self.ip_address if hasattr(self, "ip_address") else None,
        )
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
            domain=self.domain,
            subdomain=self.subdomain,
        )
        return self.metafinder_document

    def create_scan_activity(self):
        """Create and return a test scan activity."""
        self.scan_activity = ScanActivity.objects.create(
            name="Test Activity", title="Test Type", time=timezone.now(), scan_of=self.scan_history, status=1
        )
        return self.scan_activity

    def create_command(self):
        """Create and return a test command."""
        self.command = Command.objects.create(
            command="test command", time=timezone.now(), scan_history=self.scan_history, activity=self.scan_activity
        )
        return self.command

    def create_wordlist(self):
        """
        Create a test wordlist.
        """
        import uuid

        unique_id = str(uuid.uuid4())[:8]
        self.wordlist, created = Wordlist.objects.get_or_create(
            short_name=f"test-{unique_id}",
            defaults={
                "name": f"Test Wordlist {unique_id}",
                "count": 100,
            },
        )
        return self.wordlist

    def create_proxy(self):
        """
        Create a test proxy.
        """
        self.proxy = Proxy.objects.create(use_proxy=True, proxies="127.0.0.1")
        return self.proxy

    def create_hackerone(self):
        """
        Create a test hackerone.
        """
        self.hackerone = Hackerone.objects.create(username="test", api_key="testkey")
        return self.hackerone

    def create_report_setting(self):
        """
        Create a test report setting.
        """
        self.report_setting = VulnerabilityReportSetting.objects.create(
            primary_color="#000000", secondary_color="#FFFFFF"
        )
        return self.report_setting

    def create_minimal_auth_setup(self):
        """
        Create minimal auth setup instead of auth.json fixture.
        Creates essential permissions and a test user programmatically.
        """
        from django.contrib.auth import get_user_model

        User = get_user_model()  # noqa: N806

        # Create test user if not exists
        if not User.objects.filter(username="rengine").exists():
            self.test_user = User.objects.create_user(
                username="rengine",
                email="test@rengine.com",
                password="testpassword123",
                is_superuser=True,
                is_staff=True,
                is_active=True,
            )
        else:
            self.test_user = User.objects.get(username="rengine")

        return self.test_user

    def create_essential_scan_engine_setup(self):
        """
        Create essential scan engine setup instead of scanEngine.json fixture.
        Creates minimal EngineType objects needed for testing.
        """
        from scanEngine.models import EngineType

        # Create default engine type if not exists
        if not EngineType.objects.filter(engine_name="Test Engine").exists():
            self.default_engine = EngineType.objects.create(
                engine_name="Test Engine",
                yaml_configuration="""
subdomain_discovery: {
  'uses_tools': ['subfinder'],
  'enable_http_crawl': true,
  'threads': 10,
  'timeout': 5
}
http_crawl: {}
""",
                default_engine=True,
            )
        else:
            self.default_engine = EngineType.objects.filter(engine_name="Test Engine").first()

        return self.default_engine

    def create_minimal_celery_setup(self):
        """
        No-op: scan scheduling uses ScanSchedule and run_scheduled_scans (CRON).
        Kept for test compatibility; tests that need a schedule can create ScanSchedule explicitly.
        """
        self.test_interval = None
        return None

    def link_ip_to_subscans(self):
        """Link IP addresses to subscans for proper API filtering."""
        if hasattr(self, "ip_address") and hasattr(self, "subscans") and self.subscans:
            # Get fresh subscans from database to avoid stale references
            from startScan.models import SubScan

            fresh_subscans = SubScan.objects.filter(pk__in=[s.pk for s in self.subscans if s.pk])

            for subscan in fresh_subscans:
                # Only link if not already linked
                if not self.ip_address.ip_subscan_ids.filter(pk=subscan.pk).exists():
                    try:
                        self.ip_address.ip_subscan_ids.add(subscan)
                    except Exception:
                        # Ignore linking errors in test environment
                        pass

    def create_secator_workflow(self):
        """Create and return a test SecatorWorkflow."""
        import uuid

        from scanEngine.models import SecatorWorkflow

        unique_id = str(uuid.uuid4())[:8]
        self.secator_workflow = SecatorWorkflow.objects.create(
            name=f"Test Workflow {unique_id}",
            description="Test workflow for unit tests",
            yaml_configuration="tasks:\n  prompt: {}\n",
            is_active=True,
        )
        return self.secator_workflow

    def create_secator_task(self):
        """Create and return a test SecatorTask."""
        import uuid

        from scanEngine.models import SecatorTask

        unique_id = str(uuid.uuid4())[:8]
        self.secator_task = SecatorTask.objects.create(
            name=f"test_task_{unique_id}",
            task_type=f"test_task_{unique_id}",
            description="Test task for unit tests",
            is_active=True,
        )
        return self.secator_task

    def create_secator_scan(self):
        """Create and return a test SecatorScan."""
        from scanEngine.models import SecatorScan

        self.secator_scan, _created = SecatorScan.objects.get_or_create(
            name="domain",
            defaults={
                "description": "Domain scan",
                "scan_type": "internet",
                "scan_config_type": "builtin",
                "is_active": True,
            },
        )
        return self.secator_scan

    def build_scan_schedule(
        self,
        target,
        initiated_by,
        *,
        schedule_mode=ScanSchedule.SCHEDULE_MODE_PERIODIC,
        next_run=None,
        one_off=False,
        **overrides,
    ):
        """
        Build a valid ScanSchedule instance (unsaved) for tests.

        Centralizes required fields so tests do not break when model constraints
        change. Caller can mutate the instance then save() to test validation.
        """
        if next_run is None:
            next_run = timezone.now() + timedelta(days=1)
        kwargs = {
            "name": "Test schedule",
            "target": target,
            "initiated_by": initiated_by,
            "schedule_mode": schedule_mode,
            "next_run": next_run,
            "one_off": one_off,
            "enabled": True,
        }
        if schedule_mode == ScanSchedule.SCHEDULE_MODE_PERIODIC:
            kwargs["frequency_value"] = 30
            kwargs["frequency_type"] = ScanSchedule.FREQUENCY_MINUTES
        else:
            kwargs["scheduled_time"] = next_run
        kwargs.update(overrides)
        return ScanSchedule(**kwargs)

    def create_scan_schedule(
        self,
        target,
        initiated_by,
        *,
        schedule_mode=ScanSchedule.SCHEDULE_MODE_PERIODIC,
        next_run=None,
        one_off=False,
        **overrides,
    ):
        """
        Create and save a valid ScanSchedule for tests.

        Centralizes required fields so tests do not break when model constraints
        or migrations change. For unsaved instances (e.g. to test validation),
        use build_scan_schedule() instead.
        """
        schedule = self.build_scan_schedule(
            target,
            initiated_by,
            schedule_mode=schedule_mode,
            next_run=next_run,
            one_off=one_off,
            **overrides,
        )
        schedule.save()
        return schedule


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
                with override_settings(
                    TEMPLATES=[
                        {
                            "BACKEND": "django.template.backends.django.DjangoTemplates",
                            "DIRS": [],
                            "APP_DIRS": True,
                            "OPTIONS": {
                                "context_processors": [
                                    "django.template.context_processors.debug",
                                    "django.template.context_processors.request",
                                    "django.contrib.auth.context_processors.auth",
                                    "django.contrib.messages.context_processors.messages",
                                ],
                            },
                        }
                    ]
                ):
                    original_get_template = get_template

                    def mock_get_template(name):
                        return Template("") if name == template_name else original_get_template(name)

                    get_template.patched = mock_get_template
                    try:
                        return test_func(*args, **kwargs)
                    finally:
                        del get_template.patched

            return wrapper

        return decorator
