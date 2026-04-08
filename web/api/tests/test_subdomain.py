"""
This file contains the test cases for the API views.
"""

from datetime import timedelta

from django.urls import reverse
from rest_framework import status

from startScan.models import EndPoint, IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.constants import TARGET_TYPE_HOST
from targetApp.models import Target
from utils.test_base import BaseTestCase


class TestQueryInterestingSubdomains(BaseTestCase):
    """Tests for querying interesting subdomains."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_interesting_lookup_model()

    def test_query_interesting_subdomains(self):
        """Test querying interesting subdomains for a given scan."""
        api_url = reverse("api:queryInterestingSubdomains")
        response = self.client.get(api_url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("admin.example.com", [sub["name"] for sub in response.data])

    def test_query_interesting_subdomains_by_target_id_success(self):
        """Test querying interesting subdomains by target_id when target has a domain."""
        api_url = reverse("api:queryInterestingSubdomains")
        response = self.client.get(api_url, {"target_id": self.data_generator.target.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("admin.example.com", [sub["name"] for sub in response.data])

    def test_query_interesting_subdomains_by_target_id_no_scans_returns_empty(self):
        """Test that empty list is returned when target_id has no scans."""
        target_no_scans = Target.objects.create(
            value="noscans.example.com",
            project=self.data_generator.project,
            target_type=TARGET_TYPE_HOST,
        )
        api_url = reverse("api:queryInterestingSubdomains")
        response = self.client.get(api_url, {"target_id": target_no_scans.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])


class TestDeleteSubdomain(BaseTestCase):
    """Tests for deleting subdomains."""

    def setUp(self):
        super().setUp()

    def test_delete_subdomain(self):
        """Test deleting a subdomain."""
        api_url = reverse("api:delete_subdomain")
        data = {"subdomain_ids": [str(self.data_generator.subdomain.id)]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertFalse(Subdomain.objects.filter(id=self.data_generator.subdomain.id).exists())

    def test_delete_nonexistent_subdomain(self):
        """Test deleting a non-existent subdomain."""
        api_url = reverse("api:delete_subdomain")
        data = {"subdomain_ids": ["nonexistent_id"]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestListSubdomains(BaseTestCase):
    """Test case for listing subdomains."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_subdomains(self):
        """Test listing subdomains for a target."""
        url = reverse("api:querySubdomains")
        response = self.client.get(url, {"target_id": self.data_generator.target.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("subdomains", response.data)
        self.assertGreaterEqual(len(response.data["subdomains"]), 1)
        self.assertEqual(response.data["subdomains"][0]["name"], self.data_generator.subdomain.name)

    def test_query_subdomains_datatables_port_filter_services_for_request_port(self):
        """Port-filtered ListSubdomains exposes merged service names for that port (port modal)."""
        url = reverse("api:querySubdomains")
        dg = self.data_generator
        subdomain = dg.subdomain
        ip = IpAddress.objects.create(address="203.0.113.190")
        subdomain.ip_addresses.add(ip)
        Port.objects.create(number=9000, ip_address=ip, service_name="jetty")
        response = self.client.get(
            url,
            {
                "scan_id": dg.scan_history.id,
                "project": dg.project.slug,
                "port": "9000",
                "start": "0",
                "length": "50",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = next((x for x in response.data["data"] if x["id"] == subdomain.id), None)
        self.assertIsNotNone(row)
        self.assertEqual(row.get("services_for_request_port"), "jetty")


class TestSubdomainsViewSet(BaseTestCase):
    """Test case for subdomains viewset."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_subdomains_viewset(self):
        """Test retrieving subdomains for a scan."""
        url = reverse("api:subdomains-list")
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.subdomain.name)


class TestSubdomainChangesViewSet(BaseTestCase):
    """Test case for subdomain changes viewset."""

    def setUp(self):
        """Set up test environment: current scan, previous scan (same target), and one subdomain in current only."""
        super().setUp()
        self.data_generator.create_scan_history()
        current_scan = self.data_generator.scan_history
        self.data_generator.domain.scan_history = current_scan
        self.data_generator.domain.save(update_fields=["scan_history_id"])
        self.data_generator.create_subdomain("admin1.example.com")
        # SubdomainChangesViewSet needs 2 scans (current + previous) to compute "added"
        ScanHistory.objects.create(
            target=current_scan.target,
            start_scan_date=current_scan.start_scan_date - timedelta(days=1),
            scan_status=2,
            tasks=current_scan.tasks,
        )

    def test_subdomain_changes_viewset(self):
        """Test retrieving subdomain changes for a scan."""
        url = reverse("api:subdomain-changes-list")
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id, "changes": "added"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.subdomain.name)
        self.assertEqual(response.data["results"][0]["change"], "added")


class TestToggleSubdomainImportantStatus(BaseTestCase):
    """Test case for toggling subdomain important status."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_toggle_subdomain_important_status(self):
        """Test toggling the important status of a subdomain."""
        api_url = reverse("api:toggle_subdomain")
        initial_status = self.data_generator.subdomain.is_important
        response = self.client.post(api_url, {"subdomain_id": self.data_generator.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.data_generator.subdomain.refresh_from_db()
        self.assertNotEqual(initial_status, self.data_generator.subdomain.is_important)


class TestSubdomainDatatableViewSet(BaseTestCase):
    """Tests for the Subdomain Datatable ViewSet API."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_subdomains(self):
        """Test listing subdomains (no start/length: paginated response with results)."""
        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(api_url, {"project": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.subdomain.name)

    def test_list_subdomains_by_domain(self):
        """Test listing subdomains by target (target_id filters by Target, not Domain)."""
        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "target_id": self.data_generator.target.id,
                "project": self.data_generator.project.slug,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.subdomain.name)

    def test_list_subdomains_by_scan_id(self):
        """Test listing subdomains by scan_id returns results with expected fields."""
        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "scan_id": self.data_generator.scan_history.id,
                "project": self.data_generator.project.slug,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertIn("name", response.data["results"][0])
        self.assertIn("is_interesting", response.data["results"][0])

    def test_datatable_advanced_search_name_equals(self):
        """DataTables search[value] supports field=value syntax for subdomains."""
        self.data_generator.create_subdomain(name="api-dev.example.invalid")
        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "start": "0",
                "length": "10",
                "draw": "1",
                "search[value]": "name=api-dev.example.invalid",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("data", response.data)
        returned_names = [row.get("name") for row in response.data["data"]]
        self.assertIn("api-dev.example.invalid", returned_names)

    def test_datatable_advanced_search_invalid_paren_ignored(self):
        """Unmatched parenthesis is ignored (no filter change vs unparseable)."""
        api_url = reverse("api:subdomain-datatable-list")
        baseline = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "start": "0",
                "length": "50",
                "draw": "1",
            },
        )
        bad = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "start": "0",
                "length": "50",
                "draw": "1",
                "search[value]": "(name=test",
            },
        )
        self.assertEqual(baseline.status_code, status.HTTP_200_OK)
        self.assertEqual(bad.status_code, status.HTTP_200_OK)
        self.assertEqual(baseline.data.get("recordsFiltered"), bad.data.get("recordsFiltered"))

    def test_datatable_uses_default_endpoints_for_technology_payload(self):
        """Subdomain DataTables row exposes endpoint-derived technologies grouped by port."""
        subdomain = self.data_generator.subdomain
        ip = IpAddress.objects.create(address="203.0.113.140")
        subdomain.ip_addresses.add(ip)
        port = Port.objects.create(number=8443, ip_address=ip, service_name="https-alt")
        tech = Technology.objects.create(name="Caddy")
        endpoint = EndPoint.objects.create(
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
            subdomain=subdomain,
            http_url=f"https://{subdomain.name}:8443/",
            is_default=True,
            port=port,
            content_type="text/html",
            webserver="caddy",
        )
        endpoint.techs.add(tech)

        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "scan_id": self.data_generator.scan_history.id,
                "project": self.data_generator.project.slug,
                "start": "0",
                "length": "20",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = next((x for x in response.data["data"] if x["id"] == subdomain.id), None)
        self.assertIsNotNone(row)
        self.assertIn("endpoint_defaults_by_port", row)
        self.assertTrue(any(item.get("port") == 8443 for item in row["endpoint_defaults_by_port"]))
        tech_names = {t.get("name") for t in row.get("technologies", [])}
        self.assertIn("Caddy", tech_names)

    def test_datatable_falls_back_to_subdomain_technologies_without_default_endpoint(self):
        """When no default endpoint exists, DataTables technologies fallback to SubdomainTechnology links."""
        subdomain = self.data_generator.subdomain
        tech = Technology.objects.create(name="Nginx")
        subdomain.technologies.add(tech)
        EndPoint.objects.filter(subdomain=subdomain, scan_history=self.data_generator.scan_history).delete()

        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "scan_id": self.data_generator.scan_history.id,
                "project": self.data_generator.project.slug,
                "start": "0",
                "length": "20",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = next((x for x in response.data["data"] if x["id"] == subdomain.id), None)
        self.assertIsNotNone(row)
        self.assertEqual(row.get("endpoint_defaults_by_port"), [])
        tech_names = {t.get("name") for t in row.get("technologies", [])}
        self.assertIn("Nginx", tech_names)


class TestInterestingSubdomainViewSet(BaseTestCase):
    """Test case for the Interesting Subdomain ViewSet API."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_interesting_lookup_model()

    def test_list_interesting_subdomains(self):
        """Test listing interesting subdomains."""
        api_url = reverse("api:interesting-subdomains-list")
        response = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "scan_id": self.data_generator.scan_history.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.subdomain.name)

    def test_list_interesting_subdomains_by_domain(self):
        """Test listing interesting subdomains by target (target_id) and scan_id."""
        api_url = reverse("api:interesting-subdomains-list")
        response = self.client.get(
            api_url,
            {
                "target_id": self.data_generator.target.id,
                "project": self.data_generator.project.slug,
                "scan_id": self.data_generator.scan_history.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.subdomain.name)

    def test_list_interesting_subdomains_by_target_id_only(self):
        """Test listing interesting subdomains filtered by target_id only (target summary context)."""
        api_url = reverse("api:interesting-subdomains-list")
        response = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "target_id": self.data_generator.target.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.subdomain.name)

    def test_list_interesting_subdomains_datatables_format(self):
        """Test that list with start/length returns DataTables server-side format."""
        api_url = reverse("api:interesting-subdomains-list")
        response = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "scan_id": self.data_generator.scan_history.id,
                "start": "0",
                "length": "10",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("recordsTotal", response.data)
        self.assertIn("recordsFiltered", response.data)
        self.assertIn("data", response.data)
        self.assertIn("draw", response.data)
        self.assertIsInstance(response.data["data"], list)
        self.assertGreaterEqual(response.data["recordsTotal"], 1)
        self.assertGreaterEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0]["name"], self.data_generator.subdomain.name)
