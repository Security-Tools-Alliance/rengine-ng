"""
Unit tests for on_delete constraints in startScan models.

Tests verify that CASCADE and SET NULL constraints work correctly,
ensuring no orphaned data remains and no deletion blocks occur.
"""

from django.contrib.auth.models import User
from django.utils import timezone

from recon_note.models import TodoNote
from scanEngine.models import EngineType
from startScan.models import (
    Certificate,
    Command,
    CountryISO,
    Employee,
    EndPoint,
    Exploit,
    IpAddress,
    MetaFinderDocument,
    Port,
    ScanActivity,
    ScanHistory,
    SecatorRunner,
    Subdomain,
    SubScan,
    Vulnerability,
)
from utils.test_base import BaseTestCase


class TestDomainCascadeDeletion(BaseTestCase):
    """Test that deleting a Domain cascades to all related objects."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_target_cascades_to_scan_history(self):
        """Test that deleting a target cascades to its scan histories (ScanHistory.target)."""
        target = self.data_generator.target
        scan_history = self.data_generator.scan_history

        scan_history_id = scan_history.id

        # Verify scan_history exists
        self.assertTrue(ScanHistory.objects.filter(id=scan_history_id).exists())

        # Delete target (CASCADE removes scan histories)
        target.delete()

        # Verify scan_history was deleted
        self.assertFalse(ScanHistory.objects.filter(id=scan_history_id).exists())

    def test_delete_domain_cascades_to_subdomains(self):
        """Test that deleting a domain deletes all associated subdomains."""
        domain = self.data_generator.domain
        subdomain = self.data_generator.create_subdomain()

        subdomain_id = subdomain.id

        # Verify subdomain exists
        self.assertTrue(Subdomain.objects.filter(id=subdomain_id).exists())

        # Delete domain
        domain.delete()

        # Verify subdomain was deleted
        self.assertFalse(Subdomain.objects.filter(id=subdomain_id).exists())

    def test_delete_domain_cascades_to_endpoints(self):
        """Test that deleting a domain deletes all associated endpoints."""
        domain = self.data_generator.domain
        endpoint = self.data_generator.create_endpoint()

        endpoint_id = endpoint.id

        # Verify endpoint exists
        self.assertTrue(EndPoint.objects.filter(id=endpoint_id).exists())

        # Delete domain
        domain.delete()

        # Verify endpoint was deleted
        self.assertFalse(EndPoint.objects.filter(id=endpoint_id).exists())

    def test_delete_domain_cascades_to_vulnerabilities(self):
        """Test that deleting a domain deletes all associated vulnerabilities."""
        domain = self.data_generator.domain
        # Create vulnerability explicitly to ensure it's linked to domain
        vulnerability = Vulnerability.objects.create(
            name="Test Vulnerability",
            severity=1,
            discovered_date=timezone.now(),
            domain=domain,
            subdomain=self.data_generator.subdomain,
            scan_history=self.data_generator.scan_history,
            endpoint=self.data_generator.endpoint,
        )

        vulnerability_id = vulnerability.id

        # Verify vulnerability exists
        self.assertTrue(Vulnerability.objects.filter(id=vulnerability_id).exists())

        # Delete domain
        domain.delete()

        # Verify vulnerability was deleted
        self.assertFalse(Vulnerability.objects.filter(id=vulnerability_id).exists())

    def test_delete_domain_cascades_to_metafinder_documents(self):
        """Test that deleting a domain deletes all associated MetaFinder documents."""
        domain = self.data_generator.domain
        metafinder_document = self.data_generator.create_metafinder_document()

        metafinder_document_id = metafinder_document.id

        # Verify metafinder_document exists
        self.assertTrue(MetaFinderDocument.objects.filter(id=metafinder_document_id).exists())

        # Delete domain
        domain.delete()

        # Verify metafinder_document was deleted
        self.assertFalse(MetaFinderDocument.objects.filter(id=metafinder_document_id).exists())

    def test_delete_domain_cascades_to_employees(self):
        """Test that deleting a domain deletes all associated employees."""
        domain = self.data_generator.domain
        employee = Employee.objects.create(
            name="Test Employee",
            username="testuser",
            domain=domain,
            scan_history=self.data_generator.scan_history,
        )

        employee_id = employee.id

        # Verify employee exists
        self.assertTrue(Employee.objects.filter(id=employee_id).exists())

        # Delete domain
        domain.delete()

        # Verify employee was deleted
        self.assertFalse(Employee.objects.filter(id=employee_id).exists())

    def test_delete_domain_cascades_to_exploits(self):
        """Test that deleting a domain deletes all associated exploits."""
        domain = self.data_generator.domain
        exploit = self.data_generator.create_exploit(domain=domain, scan_history=self.data_generator.scan_history)

        exploit_id = exploit.id

        # Verify exploit exists
        self.assertTrue(Exploit.objects.filter(id=exploit_id).exists())

        # Delete domain
        domain.delete()

        # Verify exploit was deleted
        self.assertFalse(Exploit.objects.filter(id=exploit_id).exists())

    def test_delete_domain_cascades_to_secator_runners(self):
        """Test that deleting a domain deletes all associated Secator runners."""
        domain = self.data_generator.domain
        secator_runner = SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="test_workflow",
            domain=domain,
            scan_history=self.data_generator.scan_history,
        )

        secator_runner_id = secator_runner.id

        # Verify secator_runner exists
        self.assertTrue(SecatorRunner.objects.filter(id=secator_runner_id).exists())

        # Delete domain
        domain.delete()

        # Verify secator_runner was deleted
        self.assertFalse(SecatorRunner.objects.filter(id=secator_runner_id).exists())

    def test_delete_domain_cascades_to_certificates(self):
        """Test that deleting a domain deletes all associated certificates."""
        domain = self.data_generator.domain
        ip_address = self.data_generator.create_ip_address()
        certificate = Certificate.objects.create(
            domain=domain,
            scan_history=self.data_generator.scan_history,
            subdomain=self.data_generator.subdomain,
            ip_address=ip_address,
        )

        certificate_id = certificate.id

        # Verify certificate exists
        self.assertTrue(Certificate.objects.filter(id=certificate_id).exists())

        # Delete domain
        domain.delete()

        # Verify certificate was deleted
        self.assertFalse(Certificate.objects.filter(id=certificate_id).exists())


class TestScanHistoryCascadeDeletion(BaseTestCase):
    """Test that deleting a ScanHistory cascades to all related objects."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_scan_history_cascades_to_subdomains(self):
        """Test that deleting a scan_history deletes all associated subdomains."""
        scan_history = self.data_generator.scan_history
        subdomain = self.data_generator.create_subdomain()

        subdomain_id = subdomain.id

        # Verify subdomain exists
        self.assertTrue(Subdomain.objects.filter(id=subdomain_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify subdomain was deleted
        self.assertFalse(Subdomain.objects.filter(id=subdomain_id).exists())

    def test_delete_scan_history_cascades_to_endpoints(self):
        """Test that deleting a scan_history deletes all associated endpoints."""
        scan_history = self.data_generator.scan_history
        endpoint = self.data_generator.create_endpoint()

        endpoint_id = endpoint.id

        # Verify endpoint exists
        self.assertTrue(EndPoint.objects.filter(id=endpoint_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify endpoint was deleted
        self.assertFalse(EndPoint.objects.filter(id=endpoint_id).exists())

    def test_delete_scan_history_cascades_to_vulnerabilities(self):
        """Test that deleting a scan_history deletes all associated vulnerabilities."""
        scan_history = self.data_generator.scan_history
        # Create vulnerability explicitly to ensure it's linked to scan_history
        vulnerability = Vulnerability.objects.create(
            name="Test Vulnerability",
            severity=1,
            discovered_date=timezone.now(),
            domain=self.data_generator.domain,
            subdomain=self.data_generator.subdomain,
            scan_history=scan_history,
            endpoint=self.data_generator.endpoint,
        )

        vulnerability_id = vulnerability.id

        # Verify vulnerability exists
        self.assertTrue(Vulnerability.objects.filter(id=vulnerability_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify vulnerability was deleted
        self.assertFalse(Vulnerability.objects.filter(id=vulnerability_id).exists())

    def test_delete_scan_history_cascades_to_scan_activities(self):
        """Test that deleting a scan_history deletes all associated scan activities."""
        scan_history = self.data_generator.scan_history
        scan_activity = self.data_generator.create_scan_activity()

        scan_activity_id = scan_activity.id

        # Verify scan_activity exists
        self.assertTrue(ScanActivity.objects.filter(id=scan_activity_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify scan_activity was deleted
        self.assertFalse(ScanActivity.objects.filter(id=scan_activity_id).exists())

    def test_delete_scan_history_cascades_to_commands(self):
        """Test that deleting a scan_history deletes all associated commands."""
        scan_history = self.data_generator.scan_history
        self.data_generator.create_scan_activity()
        command = self.data_generator.create_command()

        command_id = command.id

        # Verify command exists
        self.assertTrue(Command.objects.filter(id=command_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify command was deleted
        self.assertFalse(Command.objects.filter(id=command_id).exists())

    def test_delete_scan_history_cascades_to_metafinder_documents(self):
        """Test that deleting a scan_history deletes all associated MetaFinder documents."""
        scan_history = self.data_generator.scan_history
        metafinder_document = self.data_generator.create_metafinder_document()

        metafinder_document_id = metafinder_document.id

        # Verify metafinder_document exists
        self.assertTrue(MetaFinderDocument.objects.filter(id=metafinder_document_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify metafinder_document was deleted
        self.assertFalse(MetaFinderDocument.objects.filter(id=metafinder_document_id).exists())

    def test_delete_scan_history_cascades_to_employees(self):
        """Test that deleting a scan_history deletes all associated employees."""
        scan_history = self.data_generator.scan_history
        employee = Employee.objects.create(
            name="Test Employee",
            username="testuser",
            domain=self.data_generator.domain,
            scan_history=scan_history,
        )

        employee_id = employee.id

        # Verify employee exists
        self.assertTrue(Employee.objects.filter(id=employee_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify employee was deleted
        self.assertFalse(Employee.objects.filter(id=employee_id).exists())

    def test_delete_scan_history_cascades_to_exploits(self):
        """Test that deleting a scan_history deletes all associated exploits."""
        scan_history = self.data_generator.scan_history
        exploit = self.data_generator.create_exploit(domain=self.data_generator.domain, scan_history=scan_history)

        exploit_id = exploit.id

        # Verify exploit exists
        self.assertTrue(Exploit.objects.filter(id=exploit_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify exploit was deleted
        self.assertFalse(Exploit.objects.filter(id=exploit_id).exists())

    def test_delete_scan_history_cascades_to_secator_runners(self):
        """Test that deleting a scan_history deletes all associated Secator runners."""
        scan_history = self.data_generator.scan_history
        secator_runner = SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="test_workflow",
            domain=self.data_generator.domain,
            scan_history=scan_history,
        )

        secator_runner_id = secator_runner.id

        # Verify secator_runner exists
        self.assertTrue(SecatorRunner.objects.filter(id=secator_runner_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify secator_runner was deleted
        self.assertFalse(SecatorRunner.objects.filter(id=secator_runner_id).exists())

    def test_delete_scan_history_cascades_to_certificates(self):
        """Test that deleting a scan_history deletes all associated certificates."""
        scan_history = self.data_generator.scan_history
        ip_address = self.data_generator.create_ip_address()
        certificate = Certificate.objects.create(
            domain=self.data_generator.domain,
            scan_history=scan_history,
            subdomain=self.data_generator.subdomain,
            ip_address=ip_address,
        )

        certificate_id = certificate.id

        # Verify certificate exists
        self.assertTrue(Certificate.objects.filter(id=certificate_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify certificate was deleted
        self.assertFalse(Certificate.objects.filter(id=certificate_id).exists())

    def test_delete_scan_history_cascades_to_todo_notes(self):
        """Test that deleting a scan_history deletes all associated todo notes."""
        scan_history = self.data_generator.scan_history
        todo_note = self.data_generator.create_todo_note()

        todo_note_id = todo_note.id

        # Verify todo_note exists
        self.assertTrue(TodoNote.objects.filter(id=todo_note_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify todo_note was deleted
        self.assertFalse(TodoNote.objects.filter(id=todo_note_id).exists())


class TestSubdomainCascadeDeletion(BaseTestCase):
    """Test that deleting a Subdomain cascades to all related objects."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_subdomain_cascades_to_endpoints(self):
        """Test that deleting a subdomain deletes all associated endpoints."""
        subdomain = self.data_generator.create_subdomain()
        endpoint = self.data_generator.create_endpoint(subdomain=subdomain)

        endpoint_id = endpoint.id

        # Verify endpoint exists
        self.assertTrue(EndPoint.objects.filter(id=endpoint_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify endpoint was deleted
        self.assertFalse(EndPoint.objects.filter(id=endpoint_id).exists())

    def test_delete_subdomain_cascades_to_vulnerabilities(self):
        """Test that deleting a subdomain deletes all associated vulnerabilities."""
        subdomain = self.data_generator.create_subdomain()
        vulnerability = Vulnerability.objects.create(
            name="Test Vulnerability",
            severity=1,
            discovered_date=timezone.now(),
            domain=self.data_generator.domain,
            subdomain=subdomain,
            scan_history=self.data_generator.scan_history,
        )

        vulnerability_id = vulnerability.id

        # Verify vulnerability exists
        self.assertTrue(Vulnerability.objects.filter(id=vulnerability_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify vulnerability was deleted
        self.assertFalse(Vulnerability.objects.filter(id=vulnerability_id).exists())

    def test_delete_subdomain_cascades_to_metafinder_documents(self):
        """Test that deleting a subdomain deletes all associated MetaFinder documents."""
        subdomain = self.data_generator.create_subdomain()
        metafinder_document = MetaFinderDocument.objects.create(
            title="Test MetaFinder Document",
            url="https://example.com",
            author="Test Author",
            doc_name="test.pdf",
            creation_date=timezone.now(),
            modified_date=timezone.now(),
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
            subdomain=subdomain,
        )

        metafinder_document_id = metafinder_document.id

        # Verify metafinder_document exists
        self.assertTrue(MetaFinderDocument.objects.filter(id=metafinder_document_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify metafinder_document was deleted
        self.assertFalse(MetaFinderDocument.objects.filter(id=metafinder_document_id).exists())

    def test_delete_subdomain_cascades_to_employees(self):
        """Test that deleting a subdomain deletes all associated employees."""
        subdomain = self.data_generator.create_subdomain()
        employee = Employee.objects.create(
            name="Test Employee",
            username="testuser",
            domain=self.data_generator.domain,
            subdomain=subdomain,
            scan_history=self.data_generator.scan_history,
        )

        employee_id = employee.id

        # Verify employee exists
        self.assertTrue(Employee.objects.filter(id=employee_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify employee was deleted
        self.assertFalse(Employee.objects.filter(id=employee_id).exists())

    def test_delete_subdomain_cascades_to_exploits(self):
        """Test that deleting a subdomain deletes all associated exploits."""
        subdomain = self.data_generator.create_subdomain()
        exploit = self.data_generator.create_exploit(
            subdomain=subdomain,
            domain=self.data_generator.domain,
            scan_history=self.data_generator.scan_history,
        )

        exploit_id = exploit.id

        # Verify exploit exists
        self.assertTrue(Exploit.objects.filter(id=exploit_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify exploit was deleted
        self.assertFalse(Exploit.objects.filter(id=exploit_id).exists())

    def test_delete_subdomain_cascades_to_certificates(self):
        """Test that deleting a subdomain deletes all associated certificates."""
        subdomain = self.data_generator.create_subdomain()
        ip_address = self.data_generator.create_ip_address()
        certificate = Certificate.objects.create(
            domain=self.data_generator.domain,
            scan_history=self.data_generator.scan_history,
            subdomain=subdomain,
            ip_address=ip_address,
        )

        certificate_id = certificate.id

        # Verify certificate exists
        self.assertTrue(Certificate.objects.filter(id=certificate_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify certificate was deleted
        self.assertFalse(Certificate.objects.filter(id=certificate_id).exists())

    def test_delete_subdomain_cascades_to_todo_notes(self):
        """Test that deleting a subdomain deletes all associated todo notes."""
        subdomain = self.data_generator.create_subdomain()
        todo_note = TodoNote.objects.create(
            title="Test Note",
            description="Test Description",
            project=self.data_generator.project,
            subdomain=subdomain,
            scan_history=self.data_generator.scan_history,
        )

        todo_note_id = todo_note.id

        # Verify todo_note exists
        self.assertTrue(TodoNote.objects.filter(id=todo_note_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify todo_note was deleted
        self.assertFalse(TodoNote.objects.filter(id=todo_note_id).exists())


class TestEndPointCascadeDeletion(BaseTestCase):
    """Test that deleting an EndPoint cascades to all related objects."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_endpoint_cascades_to_vulnerabilities(self):
        """Test that deleting an endpoint deletes all associated vulnerabilities."""
        endpoint = self.data_generator.create_endpoint()
        vulnerability = Vulnerability.objects.create(
            name="Test Vulnerability",
            severity=1,
            discovered_date=timezone.now(),
            domain=self.data_generator.domain,
            subdomain=self.data_generator.subdomain,
            endpoint=endpoint,
            scan_history=self.data_generator.scan_history,
        )

        vulnerability_id = vulnerability.id

        # Verify vulnerability exists
        self.assertTrue(Vulnerability.objects.filter(id=vulnerability_id).exists())

        # Delete endpoint
        endpoint.delete()

        # Verify vulnerability was deleted
        self.assertFalse(Vulnerability.objects.filter(id=vulnerability_id).exists())

    def test_delete_endpoint_cascades_to_employees(self):
        """Test that deleting an endpoint deletes all associated employees."""
        endpoint = self.data_generator.create_endpoint()
        employee = Employee.objects.create(
            name="Test Employee",
            username="testuser",
            domain=self.data_generator.domain,
            subdomain=self.data_generator.subdomain,
            endpoint=endpoint,
            scan_history=self.data_generator.scan_history,
        )

        employee_id = employee.id

        # Verify employee exists
        self.assertTrue(Employee.objects.filter(id=employee_id).exists())

        # Delete endpoint
        endpoint.delete()

        # Verify employee was deleted
        self.assertFalse(Employee.objects.filter(id=employee_id).exists())

    def test_delete_endpoint_cascades_to_exploits(self):
        """Test that deleting an endpoint deletes all associated exploits."""
        endpoint = self.data_generator.create_endpoint()
        exploit = self.data_generator.create_exploit(
            endpoint=endpoint,
            domain=self.data_generator.domain,
            subdomain=self.data_generator.subdomain,
            scan_history=self.data_generator.scan_history,
        )

        exploit_id = exploit.id

        # Verify exploit exists
        self.assertTrue(Exploit.objects.filter(id=exploit_id).exists())

        # Delete endpoint
        endpoint.delete()

        # Verify exploit was deleted
        self.assertFalse(Exploit.objects.filter(id=exploit_id).exists())


class TestIpAddressCascadeDeletion(BaseTestCase):
    """Test that deleting an IpAddress cascades to all related objects."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_ip_address_cascades_to_ports(self):
        """Test that deleting an IP address deletes all associated ports."""
        ip_address = self.data_generator.create_ip_address()
        port = self.data_generator.create_port()
        port.ip_address = ip_address
        port.save()

        port_id = port.id

        # Verify port exists
        self.assertTrue(Port.objects.filter(id=port_id).exists())

        # Delete ip_address
        ip_address.delete()

        # Verify port was deleted
        self.assertFalse(Port.objects.filter(id=port_id).exists())

    def test_delete_ip_address_cascades_to_exploits(self):
        """Test that deleting an IP address deletes all associated exploits."""
        ip_address = self.data_generator.create_ip_address()
        exploit = self.data_generator.create_exploit(
            ip_address=ip_address,
            domain=self.data_generator.domain,
            scan_history=self.data_generator.scan_history,
        )

        exploit_id = exploit.id

        # Verify exploit exists
        self.assertTrue(Exploit.objects.filter(id=exploit_id).exists())

        # Delete ip_address
        ip_address.delete()

        # Verify exploit was deleted
        self.assertFalse(Exploit.objects.filter(id=exploit_id).exists())

    def test_delete_ip_address_cascades_to_certificates(self):
        """Test that deleting an IP address deletes all associated certificates."""
        ip_address = self.data_generator.create_ip_address()
        certificate = Certificate.objects.create(
            domain=self.data_generator.domain,
            scan_history=self.data_generator.scan_history,
            subdomain=self.data_generator.subdomain,
            ip_address=ip_address,
        )

        certificate_id = certificate.id

        # Verify certificate exists
        self.assertTrue(Certificate.objects.filter(id=certificate_id).exists())

        # Delete ip_address
        ip_address.delete()

        # Verify certificate was deleted
        self.assertFalse(Certificate.objects.filter(id=certificate_id).exists())


class TestUserSetNull(BaseTestCase):
    """Test that deleting a User sets related fields to NULL."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_user_cascades_to_scan_history_initiated_by(self):
        """Test that deleting a user deletes ScanHistory with initiated_by (CASCADE behavior in model)."""
        user = User.objects.create_user(username="testuser", email="test@example.com", password="testpass")
        scan_history = self.data_generator.scan_history
        scan_history.initiated_by = user
        scan_history.save()

        scan_history_id = scan_history.id
        user_id = user.id

        # Verify link exists
        scan_history.refresh_from_db()
        self.assertEqual(scan_history.initiated_by.id, user.id)

        # Delete user
        user.delete()

        # Verify user was deleted
        self.assertFalse(User.objects.filter(id=user_id).exists())

        # Verify scan_history was also deleted (CASCADE)
        self.assertFalse(ScanHistory.objects.filter(id=scan_history_id).exists())

    def test_delete_user_sets_scan_history_aborted_by_to_null(self):
        """Test that deleting a user sets ScanHistory.aborted_by to NULL."""
        user = User.objects.create_user(username="testuser2", email="test2@example.com", password="testpass")
        scan_history = self.data_generator.scan_history
        scan_history.aborted_by = user
        scan_history.save()

        # Verify link exists
        scan_history.refresh_from_db()
        self.assertEqual(scan_history.aborted_by.id, user.id)

        # Delete user
        user_id = user.id
        user.delete()

        # Verify user was deleted
        self.assertFalse(User.objects.filter(id=user_id).exists())

        # Verify scan_history.aborted_by is now NULL
        scan_history.refresh_from_db()
        self.assertIsNone(scan_history.aborted_by)


class TestEngineTypeSetNull(BaseTestCase):
    """Test that deleting an EngineType sets related fields to NULL."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_engine_type_cascades_to_scan_history(self):
        """Test that deleting an EngineType deletes ScanHistory with scan_type (CASCADE behavior in model)."""
        engine_type = self.data_generator.engine_type
        scan_history = self.data_generator.create_scan_history(is_legacy=True)

        scan_history_id = scan_history.id
        engine_type_id = engine_type.id

        # Verify link exists
        scan_history.refresh_from_db()
        self.assertEqual(scan_history.scan_type.id, engine_type.id)

        # Delete engine_type
        engine_type.delete()

        # Verify engine_type was deleted
        self.assertFalse(EngineType.objects.filter(id=engine_type_id).exists())

        # Verify scan_history was also deleted (CASCADE)
        self.assertFalse(ScanHistory.objects.filter(id=scan_history_id).exists())

    def test_delete_engine_type_cascades_to_subscan(self):
        """Test that deleting an EngineType deletes SubScan with engine (CASCADE behavior in model)."""
        engine_type = self.data_generator.engine_type
        subscan = self.data_generator.create_subscan()[0]
        subscan.engine = engine_type
        subscan.save()

        subscan_id = subscan.id
        engine_type_id = engine_type.id

        # Verify link exists
        subscan.refresh_from_db()
        self.assertEqual(subscan.engine.id, engine_type.id)

        # Delete engine_type
        engine_type.delete()

        # Verify engine_type was deleted
        self.assertFalse(EngineType.objects.filter(id=engine_type_id).exists())

        # Verify subscan was also deleted (CASCADE)
        self.assertFalse(SubScan.objects.filter(id=subscan_id).exists())


class TestCountryISOSetNull(BaseTestCase):
    """Test that deleting a CountryISO sets related fields to NULL."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_country_iso_cascades_to_ip_address(self):
        """Test that deleting a CountryISO deletes IpAddress with geo_iso (CASCADE behavior in model)."""
        country_iso = self.data_generator.create_country_iso()
        ip_address = self.data_generator.create_ip_address()
        ip_address.geo_iso = country_iso
        ip_address.save()

        ip_address_id = ip_address.id
        country_iso_id = country_iso.id

        # Verify link exists
        ip_address.refresh_from_db()
        self.assertEqual(ip_address.geo_iso.id, country_iso.id)

        # Delete country_iso
        country_iso.delete()

        # Verify country_iso was deleted
        self.assertFalse(CountryISO.objects.filter(id=country_iso_id).exists())

        # Verify ip_address was also deleted (CASCADE)
        self.assertFalse(IpAddress.objects.filter(id=ip_address_id).exists())
