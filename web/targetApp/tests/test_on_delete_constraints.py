"""
Unit tests for on_delete constraints in targetApp models.

Tests verify that CASCADE and SET NULL constraints work correctly,
ensuring no orphaned data remains and no deletion blocks occur.
"""

from django.utils import timezone

from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain, DomainInfo, DomainRegistration, Organization, Registrar
from utils.test_base import BaseTestCase


class TestProjectCascadeDeletion(BaseTestCase):
    """Test that deleting a Project cascades to all related objects."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_project_cascades_to_domains(self):
        """Test that deleting a project deletes all associated domains."""
        project = self.data_generator.project
        domain = self.data_generator.domain

        # Verify domain exists
        self.assertTrue(Domain.objects.filter(id=domain.id).exists())

        # Delete project
        project.delete()

        # Verify domain was deleted
        self.assertFalse(Domain.objects.filter(id=domain.id).exists())

    def test_delete_project_cascades_to_organizations(self):
        """Test that deleting a project deletes all associated organizations."""
        project = self.data_generator.project
        organization = self.data_generator.create_organization()

        # Verify organization exists
        self.assertTrue(Organization.objects.filter(id=organization.id).exists())

        # Delete project
        project.delete()

        # Verify organization was deleted
        self.assertFalse(Organization.objects.filter(id=organization.id).exists())

    def test_delete_project_cascades_to_domain_children(self):
        """Test that deleting a project deletes all children of domains."""
        project = self.data_generator.project
        domain = self.data_generator.domain

        # Create scan history and subdomain linked to domain
        scan_history = self.data_generator.create_scan_history()
        subdomain = self.data_generator.create_subdomain()

        scan_history_id = scan_history.id
        subdomain_id = subdomain.id

        # Verify children exist
        self.assertTrue(ScanHistory.objects.filter(id=scan_history_id).exists())
        self.assertTrue(Subdomain.objects.filter(id=subdomain_id).exists())

        # Delete project
        project.delete()

        # Verify domain and all children were deleted
        self.assertFalse(Domain.objects.filter(id=domain.id).exists())
        self.assertFalse(ScanHistory.objects.filter(id=scan_history_id).exists())
        self.assertFalse(Subdomain.objects.filter(id=subdomain_id).exists())

    def test_delete_project_with_multiple_domains(self):
        """Test that deleting a project deletes all domains and their children."""
        project = self.data_generator.project

        # Create multiple domains
        domain1 = self.data_generator.create_domain()
        domain2 = Domain.objects.create(name="example2.com", project=project, insert_date=timezone.now())

        # Create children for each domain
        scan_history1 = ScanHistory.objects.create(domain=domain1, start_scan_date=timezone.now(), scan_status=2)
        scan_history2 = ScanHistory.objects.create(domain=domain2, start_scan_date=timezone.now(), scan_status=2)

        domain1_id = domain1.id
        domain2_id = domain2.id
        scan_history1_id = scan_history1.id
        scan_history2_id = scan_history2.id

        # Delete project
        project.delete()

        # Verify all domains and children were deleted
        self.assertFalse(Domain.objects.filter(id=domain1_id).exists())
        self.assertFalse(Domain.objects.filter(id=domain2_id).exists())
        self.assertFalse(ScanHistory.objects.filter(id=scan_history1_id).exists())
        self.assertFalse(ScanHistory.objects.filter(id=scan_history2_id).exists())


class TestDomainInfoCascadeDeletion(BaseTestCase):
    """Test that deleting DomainInfo cascades to Domain (CASCADE behavior)."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()
        # Create domain_info directly since DomainInfo no longer has domain FK
        self.domain_info = DomainInfo.objects.create()

    def test_delete_domain_info_cascades_to_domain(self):
        """Test that deleting DomainInfo deletes Domain (CASCADE behavior in model)."""
        domain = self.data_generator.domain
        domain_info = self.domain_info

        # Link domain to domain_info
        domain.domain_info = domain_info
        domain.save()

        domain_id = domain.id
        domain_info_id = domain_info.id

        # Verify link exists
        domain.refresh_from_db()
        self.assertEqual(domain.domain_info.id, domain_info.id)

        # Delete domain_info
        domain_info.delete()

        # Verify domain_info was deleted
        self.assertFalse(DomainInfo.objects.filter(id=domain_info_id).exists())

        # Verify domain was also deleted (CASCADE)
        self.assertFalse(Domain.objects.filter(id=domain_id).exists())


class TestDomainInfoRelationsCascadeDeletion(BaseTestCase):
    """Test that deleting Registrar/DomainRegistration cascades to DomainInfo (CASCADE behavior)."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()
        # Create domain_info directly since DomainInfo no longer has domain FK
        self.domain_info = DomainInfo.objects.create()
        self.registrar = self.data_generator.create_registrar()
        self.domain_registration = self.data_generator.create_domain_registration()

    def test_delete_registrar_cascades_to_domain_info(self):
        """Test that deleting Registrar deletes DomainInfo (CASCADE behavior in model)."""
        domain_info = self.domain_info
        registrar = self.registrar

        # Link domain_info to registrar
        domain_info.registrar = registrar
        domain_info.save()

        domain_info_id = domain_info.id
        registrar_id = registrar.id

        # Verify link exists
        domain_info.refresh_from_db()
        self.assertEqual(domain_info.registrar.id, registrar.id)

        # Delete registrar
        registrar.delete()

        # Verify registrar was deleted
        self.assertFalse(Registrar.objects.filter(id=registrar_id).exists())

        # Verify domain_info was also deleted (CASCADE)
        self.assertFalse(DomainInfo.objects.filter(id=domain_info_id).exists())

    def test_delete_domain_registration_cascades_to_domain_info_registrant(self):
        """Test that deleting DomainRegistration deletes DomainInfo with registrant (CASCADE)."""
        domain_info = DomainInfo.objects.create()
        domain_registration = self.domain_registration

        # Link domain_info to registrant
        domain_info.registrant = domain_registration
        domain_info.save()

        domain_info_id = domain_info.id
        domain_registration_id = domain_registration.id

        # Verify link exists
        domain_info.refresh_from_db()
        self.assertEqual(domain_info.registrant.id, domain_registration.id)

        # Delete domain_registration
        domain_registration.delete()

        # Verify domain_registration was deleted
        self.assertFalse(DomainRegistration.objects.filter(id=domain_registration_id).exists())

        # Verify domain_info was also deleted (CASCADE)
        self.assertFalse(DomainInfo.objects.filter(id=domain_info_id).exists())

    def test_delete_domain_registration_cascades_to_domain_info_admin(self):
        """Test that deleting DomainRegistration deletes DomainInfo with admin (CASCADE)."""
        domain_info = DomainInfo.objects.create()
        domain_registration = self.domain_registration

        # Link domain_info to admin
        domain_info.admin = domain_registration
        domain_info.save()

        domain_info_id = domain_info.id
        domain_registration_id = domain_registration.id

        # Verify link exists
        domain_info.refresh_from_db()
        self.assertEqual(domain_info.admin.id, domain_registration.id)

        # Delete domain_registration
        domain_registration.delete()

        # Verify domain_registration was deleted
        self.assertFalse(DomainRegistration.objects.filter(id=domain_registration_id).exists())

        # Verify domain_info was also deleted (CASCADE)
        self.assertFalse(DomainInfo.objects.filter(id=domain_info_id).exists())

    def test_delete_domain_registration_cascades_to_domain_info_tech(self):
        """Test that deleting DomainRegistration deletes DomainInfo with tech (CASCADE)."""
        domain_info = DomainInfo.objects.create()
        domain_registration = self.domain_registration

        # Link domain_info to tech
        domain_info.tech = domain_registration
        domain_info.save()

        domain_info_id = domain_info.id
        domain_registration_id = domain_registration.id

        # Verify link exists
        domain_info.refresh_from_db()
        self.assertEqual(domain_info.tech.id, domain_registration.id)

        # Delete domain_registration
        domain_registration.delete()

        # Verify domain_registration was deleted
        self.assertFalse(DomainRegistration.objects.filter(id=domain_registration_id).exists())

        # Verify domain_info was also deleted (CASCADE)
        self.assertFalse(DomainInfo.objects.filter(id=domain_info_id).exists())
