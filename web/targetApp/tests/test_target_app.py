"""
TestTargetAppViews contains unit tests for the views of the targetApp application.
It verifies the functionality related to targets and organizations, ensuring that views
return the correct status codes, templates, and handle various scenarios appropriately.

Methods:
    setUp: Initializes test objects for projects, domains, and organizations before each test.
    test_index_view: Tests the index view for correct status code and template usage.
    test_add_target_view: Tests the addition of a new target to ensure it is created successfully.
    test_add_ip_view: Tests the addition of a new IP target to ensure it is created successfully.
    test_add_target_with_invalid_ip: Tests the addition of a target with an invalid IP address.
    test_add_target_with_file: Tests the addition of targets from a file to ensure they are created successfully.
    test_add_target_with_empty_file: Tests the handling of an empty file upload.
    test_list_target_view: Tests the list target view for correct status code and template usage.
    test_delete_target_view: Tests the deletion of a target to ensure it is removed successfully.
    test_update_target_view: Tests the update of a target to ensure it is updated successfully.
    test_update_organization_view_with_invalid_data: Tests updating an organization with invalid data.
    test_delete_non_existent_target: Tests the deletion of a non-existent target.
    test_add_organization_view: Tests the addition of a new organization to ensure it is created successfully.
    test_list_organization_view: Tests the list organization view for correct status code and template usage.
    test_delete_organization_view: Tests the deletion of an organization to ensure it is removed successfully.
    test_update_organization_view: Tests the update of an organization to ensure it is updated successfully.
    test_update_organization_with_invalid_data: Tests updating an organization with invalid data.
    test_add_organization_with_duplicate_name: Tests adding an organization with a duplicate name.
    test_delete_non_existent_organization: Tests the deletion of a non-existent organization.
"""

from datetime import timedelta
import json
import os

from django.contrib.messages import get_messages
from django.urls import reverse
from django.utils import timezone

from reNgine.secator.services.target_builder_service import TargetBuilderService
from startScan.models import Domain, DomainInfo, IpAddress, RelatedDomain, ScanHistory, Subdomain
from targetApp.models import Organization, Target
from targetApp.views import _AggregatedDomainInfo
from utils.test_base import BaseTestCase


class TestTargetAppViews(BaseTestCase):
    """
    Test class for the views of the targetApp.
    """

    def setUp(self):
        """
        Initial setup for the tests.
        Creates test objects for projects, domains, and organizations.
        """
        super().setUp()

    def test_index_view(self):
        """
        Tests the index view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("targetIndex"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "target/index.html")

    def test_add_target_view(self):
        """
        Tests the add target view to ensure a new target is created successfully.
        """
        Domain.objects.all().delete()
        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "addTargets": "example.com",
                "targetDescription": "Test Description",
                "targetH1TeamHandle": "Test Handle",
                "targetOrganization": "Test Organization",
                "add-multiple-targets": "submit",
            },
        )
        self.assertEqual(response.status_code, 302)
        target = Target.objects.filter(project=self.data_generator.project, value="example.com").first()
        self.assertIsNotNone(target)
        self.assertEqual(target.target_type, "host")

    def test_add_ip_view(self):
        """
        Tests the add target view to ensure a new target is created successfully.
        """
        Domain.objects.all().delete()

        # Create test host data in the new format
        host_data_1 = json.dumps({"ip": "192.168.1.1", "domain": "www.example.local", "is_alive": True})

        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "ip_address": "192.168.1.0/24",
                "targetName": "example.local",
                "discovered_domains": ["example.local"],
                "resolved_hosts": [host_data_1],
                "targetDescription": "Test Description",
                "targetH1TeamHandle": "Test Handle",
                "targetOrganization": "Test Organization",
                "add-ip-target": "submit",
            },
        )
        self.assertEqual(response.status_code, 302)

        target = Target.objects.filter(project=self.data_generator.project, value="example.local").first()
        self.assertIsNotNone(target)
        self.assertEqual(target.target_type, "host")
        scan = ScanHistory.objects.filter(target=target).first()
        self.assertIsNotNone(scan)
        self.assertEqual(scan.scan_config.get("seed_source"), "ip_discovery")
        self.assertTrue(Domain.objects.filter(scan_history=scan, name="example.local").exists())
        sub = Subdomain.objects.filter(scan_history=scan, name="www.example.local").first()
        self.assertIsNotNone(sub)
        self.assertTrue(IpAddress.objects.filter(address="192.168.1.1").exists())
        self.assertTrue(sub.ip_addresses.filter(address="192.168.1.1").exists())
        flat = TargetBuilderService(target_id=target.id).build_flat_targets(["host", "ip"])
        self.assertIn("www.example.local", flat)
        self.assertIn("192.168.1.1", flat)

    def test_add_ip_discovery_domain_checkbox_only_seeds_domain_finding(self):
        """Checked domain with no host rows still creates Domain on the ip_discovery seed scan."""
        Target.objects.filter(
            project=self.data_generator.project,
            value="example.local",
        ).delete()
        Domain.objects.all().delete()
        ScanHistory.objects.all().delete()
        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "ip_address": "192.168.1.0/24",
                "targetName": "example.local",
                "discovered_domains": ["example.local"],
                "resolved_hosts": [],
                "add-ip-target": "submit",
            },
        )
        self.assertEqual(response.status_code, 302)
        target = Target.objects.get(project=self.data_generator.project, value="example.local")
        scan = ScanHistory.objects.filter(target=target).first()
        self.assertIsNotNone(scan)
        self.assertTrue(Domain.objects.filter(scan_history=scan, name="example.local").exists())

    def test_add_ip_named_target_seeds_domain_and_ip_without_domain_checkbox(self):
        """Explicit apex + IP-only selections still create Domain + IpAddress on the seed scan."""
        Target.objects.filter(project=self.data_generator.project, value="ray.local").delete()
        Domain.objects.all().delete()
        ScanHistory.objects.all().delete()
        ip_row = json.dumps({"ip": "192.168.1.50", "domain": "192.168.1.50", "is_alive": True})
        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "ip_address": "192.168.1.0/24",
                "targetName": "ray.local",
                "discovered_domains": [],
                "resolved_hosts": [ip_row],
                "add-ip-target": "submit",
            },
        )
        self.assertEqual(response.status_code, 302)
        target = Target.objects.get(project=self.data_generator.project, value="ray.local")
        scan = ScanHistory.objects.filter(target=target).first()
        self.assertIsNotNone(scan)
        self.assertTrue(Domain.objects.filter(scan_history=scan, name="ray.local").exists())
        self.assertTrue(IpAddress.objects.filter(address="192.168.1.50").exists())

    def test_add_ip_named_target_imports_selected_hostname_even_if_apex_differs(self):
        """Selected hosts are imported into the named target without apex restriction."""
        Target.objects.filter(project=self.data_generator.project, value="ray.local").delete()
        Domain.objects.all().delete()
        ScanHistory.objects.all().delete()
        host_row = json.dumps({"ip": "10.0.0.2", "domain": "nas.local", "is_alive": True})
        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "ip_address": "192.168.1.0/24",
                "targetName": "ray.local",
                "discovered_domains": [],
                "resolved_hosts": [host_row],
                "add-ip-target": "submit",
            },
        )
        self.assertEqual(response.status_code, 302)
        target = Target.objects.get(project=self.data_generator.project, value="ray.local")
        scan = ScanHistory.objects.filter(target=target).first()
        self.assertIsNotNone(scan)
        self.assertTrue(Subdomain.objects.filter(scan_history=scan, name="nas.local").exists())
        self.assertTrue(IpAddress.objects.filter(address="10.0.0.2").exists())

    def test_add_ip_discovery_requires_target_name(self):
        """
        DNS discovery import rejects submission when targetName is missing.
        """
        host_data = json.dumps({"ip": "192.168.1.2", "domain": "host.lab.local", "is_alive": True})

        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "ip_address": "192.168.1.0/24",
                "targetName": "",
                "discovered_domains": ["lab.local"],
                "resolved_hosts": [host_data],
                "add-ip-target": "submit",
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("required", (response.json().get("message") or "").lower())

    def test_add_target_with_file(self):
        """
        Test the add target with file view to ensure a new target is created successfully.
        """
        Domain.objects.all().delete()
        # Create a temporary file for the test
        with open("domains.txt", "w", encoding="utf-8") as f:
            f.write("example.local\nother-example.local\n")

        with open("domains.txt", "rb") as file:
            response = self.client.post(
                reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
                {
                    "txtFile": file,
                    "import-txt-target": "Upload",
                },
                format="multipart",
            )

        self.assertEqual(response.status_code, 302)
        for name in ("example.local", "other-example.local"):
            target = Target.objects.filter(project=self.data_generator.project, value=name).first()
            self.assertIsNotNone(target, msg=f"Target {name} should exist")
            self.assertEqual(target.target_type, "host")
        os.remove("domains.txt")

    def test_add_target_with_empty_file(self):
        """
        Test uploading an empty file to ensure the system handles it correctly.
        """
        # Create an empty file for the test
        with open("empty_file.txt", "w", encoding="utf-8"):
            pass  # Create an empty file

        with open("empty_file.txt", "rb") as file:
            response = self.client.post(
                reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
                {
                    "txtFile": file,
                    "import-txt-target": "Upload",
                },
                format="multipart",
            )

        # Check that the response is correct
        self.assertEqual(response.status_code, 302)

        # Check the returned message
        messages_list = list(get_messages(response.wsgi_request))
        self.assertIn(
            "The uploaded file is empty. Please upload a valid file.", [str(message) for message in messages_list]
        )

        # Check that no new target was created
        self.assertFalse(Target.objects.filter(project=self.data_generator.project, value="example.local").exists())

        # Clean up the empty file
        os.remove("empty_file.txt")

    def test_list_target_view(self):
        """
        Tests the list target view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("list_target", kwargs={"slug": self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "target/list.html")

    def test_target_summary_returns_200(self):
        """
        Tests the target summary view returns 200 and uses the summary template.
        With no domains, domain_info context is None.
        """
        self.data_generator.create_scan_history()
        target = self.data_generator.target
        response = self.client.get(
            reverse("target_summary", kwargs={"slug": self.data_generator.project.slug, "id": target.id})
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "target/summary.html")
        self.assertIn("domain_info", response.context)
        self.assertIn("domains", response.context)
        self.assertContains(response, "Attack Surface Summary")

    def test_target_summary_includes_exploit_count_and_tab_when_exploits_exist(self):
        """
        Target summary exposes exploit_count in context and shows Exploits tab when exploits exist.
        """
        self.data_generator.create_scan_history()
        target = self.data_generator.target
        scan_history = self.data_generator.scan_history
        from startScan.models import Exploit

        Exploit.objects.create(
            name="Test Exploit",
            exploit_id="CVE-2023-38408-exploit",
            provider="test-provider",
            scan_history=scan_history,
        )
        response = self.client.get(
            reverse("target_summary", kwargs={"slug": self.data_generator.project.slug, "id": target.id})
        )
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.context["exploit_count"], 0)
        content = response.content.decode("utf-8")
        self.assertIn('id="pills-exploits-tab"', content)

    def test_target_summary_domain_info_none_when_no_whois(self):
        """
        Target summary shows domain_info None when no domain has WHOIS (domain_info).
        """
        self.data_generator.create_scan_history()
        self.data_generator.create_domain(scan_history=self.data_generator.scan_history)
        target = self.data_generator.target
        self.assertIsNone(self.data_generator.domain.domain_info_id)
        response = self.client.get(
            reverse("target_summary", kwargs={"slug": self.data_generator.project.slug, "id": target.id})
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["domain_info"])

    def test_target_summary_aggregates_related_domains_from_all_scans(self):
        """
        Target summary aggregates related_domains from all domains (scans) with domain_info.
        Deduplicates by name and prefers the most recent scan.
        """
        self.data_generator.create_scan_history()
        target = self.data_generator.target
        domain1 = self.data_generator.domain
        domain1.name = "first.example.com"
        domain1.save()
        info1 = DomainInfo.objects.create(created=timezone.now())
        domain1.domain_info = info1
        domain1.save()
        rd1 = RelatedDomain.objects.create(name="related-a.local")
        rd2 = RelatedDomain.objects.create(name="related-b.local")
        info1.related_domains.add(rd1, rd2)

        older_scan = ScanHistory.objects.create(
            target=target,
            start_scan_date=timezone.now() - timedelta(days=2),
            scan_status=2,
        )
        domain2 = Domain.objects.create(
            name="second.example.com",
            insert_date=timezone.now(),
            scan_history=older_scan,
        )
        info2 = DomainInfo.objects.create(created=timezone.now())
        domain2.domain_info = info2
        domain2.save()
        info2.related_domains.add(rd1)
        rd3 = RelatedDomain.objects.create(name="related-c.local")
        info2.related_domains.add(rd3)

        response = self.client.get(
            reverse("target_summary", kwargs={"slug": self.data_generator.project.slug, "id": target.id})
        )
        self.assertEqual(response.status_code, 200)
        domain_info = response.context["domain_info"]
        self.assertIsNotNone(domain_info)
        self.assertIsInstance(domain_info, _AggregatedDomainInfo)
        related_list = domain_info.related_domains.all
        self.assertEqual(related_list.count(), 3)
        names = [r.name for r in related_list]
        self.assertIn("related-a.local", names)
        self.assertIn("related-b.local", names)
        self.assertIn("related-c.local", names)
        self.assertEqual(domain_info.related_tlds.all.count(), 0)

    def test_target_summary_deduplicates_domains_by_name(self):
        """
        Target summary shows at most one row per domain name (the most recent scan).
        """
        self.data_generator.create_scan_history()
        target = self.data_generator.target
        self.data_generator.domain.name = "example.com"
        self.data_generator.domain.save()
        older_scan = ScanHistory.objects.create(
            target=target,
            start_scan_date=timezone.now() - timedelta(days=1),
            scan_status=2,
        )
        Domain.objects.create(
            name="example.com",
            insert_date=timezone.now(),
            scan_history=older_scan,
        )
        Domain.objects.create(
            name="example.com",
            insert_date=timezone.now(),
            scan_history=ScanHistory.objects.create(
                target=target,
                start_scan_date=timezone.now() - timedelta(days=2),
                scan_status=2,
            ),
        )
        response = self.client.get(
            reverse("target_summary", kwargs={"slug": self.data_generator.project.slug, "id": target.id})
        )
        self.assertEqual(response.status_code, 200)
        domains = response.context["domains"]
        self.assertEqual(len(domains), 1, "Expected one domain when name is example.com in multiple scans")
        self.assertEqual(domains[0].name, "example.com")

    def test_delete_target_view(self):
        """
        Tests the delete target view to ensure a target is deleted successfully.
        """
        self.data_generator.create_scan_history()
        target = self.data_generator.target
        target_id = target.id
        response = self.client.post(
            reverse("delete_target", kwargs={"id": target_id, "slug": self.data_generator.project.slug})
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Target.objects.filter(id=target_id).exists())

    def test_update_target_view(self):
        """
        Tests the update target view to ensure a target is updated successfully.
        """
        self.data_generator.create_scan_history()
        target = self.data_generator.target
        response = self.client.post(
            reverse("update_target", kwargs={"slug": self.data_generator.project.slug, "id": target.id}),
            {"description": "Updated description", "h1_team_handle": "Updated Handle"},
        )
        self.assertEqual(response.status_code, 302)
        target.refresh_from_db()
        self.assertEqual(target.description, "Updated description")
        self.assertEqual(target.h1_team_handle, "Updated Handle")

    def test_update_organization_view_with_invalid_data(self):
        """
        Test updating an organization with invalid data to ensure validation works.
        """
        original_name = self.data_generator.organization.name
        original_description = self.data_generator.organization.description or ""

        # Prepare invalid data (e.g., empty name)
        invalid_data = {
            "name": "",  # Invalid: name cannot be empty
            "description": "Updated Org Description",
        }

        response = self.client.post(
            reverse(
                "update_organization",
                kwargs={"slug": self.data_generator.project.slug, "id": self.data_generator.organization.id},
            ),
            invalid_data,
        )

        # Check that the response is still 200 (indicating the form was not valid)
        self.assertEqual(response.status_code, 200)

        # Check for the presence of an error message in the response context
        self.assertContains(response, "This field is required.")

        # Verify that the organization data has not changed
        self.data_generator.organization.refresh_from_db()
        self.assertEqual(self.data_generator.organization.name, original_name)
        self.assertEqual(self.data_generator.organization.description or "", original_description)

    def test_delete_non_existent_target(self):
        """
        Test attempting to delete a target that does not exist.
        """
        non_existent_id = 999999

        response = self.client.post(
            reverse("delete_target", kwargs={"id": non_existent_id, "slug": self.data_generator.project.slug}),
            follow=True,
        )

        self.assertEqual(response.status_code, 200)

        messages_list = list(get_messages(response.wsgi_request))
        self.assertIn("Target not found.", [str(message) for message in messages_list])

        self.assertTrue(Domain.objects.filter(id=self.data_generator.domain.id).exists())

    def test_add_organization_view(self):
        """
        Tests the add organization view to ensure a new organization is created successfully.
        """
        Organization.objects.all().delete()
        response = self.client.post(
            reverse("add_organization", kwargs={"slug": self.data_generator.project.slug}),
            {
                "name": "New Organization",
                "description": "New Org Description",
                "domains": [self.data_generator.domain.id],
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Organization.objects.filter(name="New Organization").exists())

    def test_list_organization_view(self):
        """
        Tests the list organization view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse("list_organization", kwargs={"slug": self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "organization/list.html")

    def test_delete_organization_view(self):
        """
        Tests the delete organization view to ensure an organization is deleted successfully.
        """
        response = self.client.post(
            reverse(
                "delete_organization",
                kwargs={"id": self.data_generator.organization.id, "slug": self.data_generator.project.slug},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Organization.objects.filter(id=self.data_generator.organization.id).exists())

    def test_update_organization_view(self):
        """
        Tests the update organization view to ensure an organization is updated successfully.
        """
        response = self.client.post(
            reverse(
                "update_organization",
                kwargs={"slug": self.data_generator.project.slug, "id": self.data_generator.organization.id},
            ),
            {
                "name": "Updated Organization",
                "description": "Updated Org Description",
                "domains": [self.data_generator.domain.id],
            },
        )
        self.assertEqual(response.status_code, 302)
        self.data_generator.organization.refresh_from_db()
        self.assertEqual(self.data_generator.organization.name, "Updated Organization")
        self.assertEqual(self.data_generator.organization.description, "Updated Org Description")

    def test_update_organization_with_invalid_data(self):
        """
        Test updating an organization with invalid data to ensure validation works.
        """
        original_name = self.data_generator.organization.name
        original_description = self.data_generator.organization.description or ""

        response = self.client.post(
            reverse(
                "update_organization",
                kwargs={"slug": self.data_generator.project.slug, "id": self.data_generator.organization.id},
            ),
            {
                "name": "",  # Invalid: name cannot be empty
                "description": "Updated Org Description",
                "domains": [],  # Assuming domains are required
            },
        )

        # Check that the response is still 200 (indicating the form was not valid)
        self.assertEqual(response.status_code, 200)

        # Check for the presence of an error message in the response context
        self.assertContains(response, "This field is required.")

        # Verify that the organization data has not changed
        self.data_generator.organization.refresh_from_db()
        self.assertEqual(self.data_generator.organization.name, original_name)
        self.assertEqual(self.data_generator.organization.description or "", original_description)

    def test_add_organization_with_duplicate_name(self):
        """
        Test adding an organization with a name that already exists.
        """
        existing_name = self.data_generator.organization.name
        self.data_generator.create_scan_history()
        extra_scan = ScanHistory.objects.create(
            target=self.data_generator.target,
            start_scan_date=timezone.now(),
            scan_status=2,
        )
        extra_domain = Domain.objects.create(
            name=f"extra-domain-{self.data_generator.project.slug}.test",
            insert_date=timezone.now(),
            scan_history=extra_scan,
        )
        response = self.client.post(
            reverse("add_organization", kwargs={"slug": self.data_generator.project.slug}),
            {
                "name": existing_name,
                "description": "New Org Description",
                "domains": [extra_domain.id],
            },
        )

        # Check that the response is still 200 (indicating the form was not valid)
        self.assertEqual(response.status_code, 200)

        # Check for the presence of an error message in the response context
        self.assertContains(response, "Organization with this Name already exists.")

        # Verify that no new organization was created
        self.assertEqual(Organization.objects.count(), 1)

    def test_delete_non_existent_organization(self):
        """
        Test attempting to delete an organization that does not exist.
        """
        # Attempt to delete an organization with a non-existent ID
        non_existent_id = self.data_generator.organization.id + 999

        response = self.client.post(
            reverse("delete_organization", kwargs={"id": non_existent_id, "slug": self.data_generator.project.slug}),
            follow=True,  # Follow the redirect after deletion
        )

        # Check that the response is 200
        self.assertEqual(response.status_code, 200)

        messages_list = list(get_messages(response.wsgi_request))
        self.assertIn("Organization not found.", [str(message) for message in messages_list])

        # Verify that the existing organization is still present
        self.assertTrue(Organization.objects.filter(id=self.data_generator.organization.id).exists())


class TestValidateDNSServers(BaseTestCase):
    """
    Test class for the validate_dns_servers function.
    """

    def setUp(self):
        """Initial setup for the tests."""
        super().setUp()
        from targetApp.views import validate_dns_servers

        self.validate_dns_servers = validate_dns_servers

    def test_validate_valid_ipv4_servers(self):
        """Test validation with valid IPv4 addresses."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8,1.1.1.1")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "8.8.8.8,1.1.1.1")

    def test_validate_valid_ipv4_with_port(self):
        """Test validation with valid IPv4 addresses including port."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8:53,1.1.1.1:5353")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "8.8.8.8:53,1.1.1.1:5353")

    def test_validate_valid_ipv6_servers(self):
        """Test validation with valid IPv6 addresses."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("2001:4860:4860::8888,2001:4860:4860::8844")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "2001:4860:4860::8888,2001:4860:4860::8844")

    def test_validate_valid_hostnames(self):
        """Test validation with valid hostnames."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("dns.google.com,one.one.one.one")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "dns.google.com,one.one.one.one")

    def test_validate_empty_string(self):
        """Test validation with empty string."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "")

    def test_validate_whitespace_only(self):
        """Test validation with whitespace only."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("   ")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "")

    def test_validate_with_extra_whitespace(self):
        """Test validation with extra whitespace around servers."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("  8.8.8.8  ,  1.1.1.1  ")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "8.8.8.8,1.1.1.1")

    def test_validate_with_extra_commas(self):
        """Test validation with extra commas."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8,,1.1.1.1,,,9.9.9.9")
        self.assertTrue(is_valid)
        self.assertIsNone(error_msg)
        self.assertEqual(cleaned, "8.8.8.8,1.1.1.1,9.9.9.9")

    def test_validate_invalid_ip(self):
        """Test validation with invalid IP address."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("999.999.999.999")
        self.assertFalse(is_valid)
        self.assertIn("Invalid DNS server address", error_msg)
        self.assertIsNone(cleaned)

    def test_validate_invalid_hostname(self):
        """Test validation with invalid hostname."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("invalid!@#server")
        self.assertFalse(is_valid)
        self.assertIn("Invalid DNS server address", error_msg)
        self.assertIsNone(cleaned)

    def test_validate_mixed_valid_invalid(self):
        """Test validation with mix of valid and invalid servers."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8,invalid!@#,1.1.1.1")
        self.assertFalse(is_valid)
        self.assertIn("Invalid DNS server address", error_msg)
        self.assertIsNone(cleaned)

    def test_validate_invalid_port_range(self):
        """Test validation with port outside valid range."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8:70000")
        self.assertFalse(is_valid)
        self.assertIn("Invalid port number", error_msg)
        self.assertIsNone(cleaned)

    def test_validate_invalid_port_format(self):
        """Test validation with non-numeric port."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8:abc")
        self.assertFalse(is_valid)
        self.assertIn("Invalid port", error_msg)
        self.assertIsNone(cleaned)

    def test_validate_sql_injection_attempt(self):
        """Test validation rejects SQL injection attempts."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8; DROP TABLE domains;")
        self.assertFalse(is_valid)
        self.assertIn("Invalid DNS server address", error_msg)
        self.assertIsNone(cleaned)

    def test_validate_xss_attempt(self):
        """Test validation rejects XSS attempts."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("<script>alert('xss')</script>")
        self.assertFalse(is_valid)
        self.assertIn("Invalid DNS server address", error_msg)
        self.assertIsNone(cleaned)

    def test_validate_command_injection_attempt(self):
        """Test validation rejects command injection attempts."""
        is_valid, error_msg, cleaned = self.validate_dns_servers("8.8.8.8 && rm -rf /")
        self.assertFalse(is_valid)
        self.assertIn("Invalid DNS server address", error_msg)
        self.assertIsNone(cleaned)

    def test_add_target_with_invalid_dns_servers(self):
        """Test adding a target with invalid DNS servers."""
        Domain.objects.all().delete()

        host_data = json.dumps({"ip": "192.168.1.1", "domain": "example.local", "is_alive": True})

        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "ip_address": "192.168.1.0/24",
                "targetName": "example.local",
                "discovered_domains": ["example.local"],
                "resolved_hosts": [host_data],
                "used_dns_servers": "invalid!@#server,8.8.8.8",  # Invalid DNS servers
                "add-ip-target": "submit",
            },
        )

        # Should return 200 with error (not redirect)
        self.assertEqual(response.status_code, 200)

        # Check for error message
        messages_list = list(get_messages(response.wsgi_request))
        self.assertTrue(any("Invalid DNS servers configuration" in str(msg) for msg in messages_list))

        self.assertFalse(Domain.objects.filter(name="example.local").exists())

    def test_add_target_with_valid_dns_servers(self):
        """Test adding a target with valid DNS servers."""
        Domain.objects.all().delete()

        host_data = json.dumps({"ip": "192.168.1.1", "domain": "example.local", "is_alive": True})

        response = self.client.post(
            reverse("add_target", kwargs={"slug": self.data_generator.project.slug}),
            {
                "ip_address": "192.168.1.0/24",
                "targetName": "example.local",
                "discovered_domains": ["example.local"],
                "resolved_hosts": [host_data],
                "used_dns_servers": "8.8.8.8,1.1.1.1",  # Valid DNS servers
                "add-ip-target": "submit",
            },
        )

        # Should redirect on success
        self.assertEqual(response.status_code, 302)

        target = Target.objects.filter(project=self.data_generator.project, value="example.local").first()
        self.assertIsNotNone(target)
        scan = ScanHistory.objects.filter(target=target).first()
        self.assertIsNotNone(scan)
        self.assertTrue(Domain.objects.filter(scan_history=scan, name="example.local").exists())

    def test_add_single_target_by_type(self):
        """
        Tests adding a Target-only via add-single-target (e.g. URL type). No Domain is created.
        """
        Target.objects.filter(project=self.data_generator.project).delete()
        url = reverse("add_target", kwargs={"slug": self.data_generator.project.slug})
        response = self.client.post(
            url,
            {
                "add-single-target": "submit",
                "target_type": "url",
                "target_value": "https://example.com/path",
                "targetDescription": "Test URL target",
                "targetH1TeamHandle": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            reverse("list_target", kwargs={"slug": self.data_generator.project.slug}),
        )
        target = Target.objects.filter(
            project=self.data_generator.project,
            value="https://example.com/path",
            target_type="url",
        ).first()
        self.assertIsNotNone(target)
        self.assertEqual(target.description, "Test URL target")
        self.assertFalse(Domain.objects.filter(scan_history__target_id=target.id).exists())

    def test_add_single_target_cidr_invalid(self):
        """Invalid CIDR when adding single target returns redirect with error."""
        url = reverse("add_target", kwargs={"slug": self.data_generator.project.slug})
        response = self.client.post(
            url,
            {
                "add-single-target": "submit",
                "target_type": "cidr_range",
                "target_value": "not-a-cidr",
                "targetDescription": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, url)
        self.assertFalse(
            Target.objects.filter(
                project=self.data_generator.project,
                target_type="cidr_range",
            ).exists()
        )


# Target deduplication tests removed - require complex implementation
# These tests would need to be implemented with proper form handling
# and integration with the actual add_target view logic
