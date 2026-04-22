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

    def test_query_subdomains_tech_param_matches_endpoint_only_tech_secator(self):
        """tech= filter includes Secator subdomains where the name matches only via EndPoint.techs."""
        dg = self.data_generator
        scan = dg.scan_history
        self.assertFalse(getattr(scan, "is_legacy_scan", True))
        subdomain = dg.subdomain
        host = subdomain.name
        tech = Technology.objects.create(name="EpOnlyTechFilter", scan_history=scan, value="", category="")
        ep = dg.create_endpoint(
            http_url=f"https://{host}/path-only",
            scan_history=scan,
            domain=dg.domain,
            subdomain=subdomain,
            is_default=False,
        )
        ep.techs.add(tech)

        url = reverse("api:querySubdomains")
        response = self.client.get(
            url,
            {
                "scan_id": scan.id,
                "project": dg.project.slug,
                "tech": "EpOnlyTechFilter",
                "start": "0",
                "length": "50",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        names = [row.get("name") for row in response.data.get("data", [])]
        self.assertIn(host, names)

    def test_query_subdomains_keeps_latest_row_per_name(self):
        """ListSubdomains keeps one row per name and selects the latest scan row."""
        current_scan = self.data_generator.scan_history
        target = self.data_generator.target
        project_slug = self.data_generator.project.slug
        shared_name = "dup-host.example.com"

        older_scan = ScanHistory.objects.create(
            target=target,
            start_scan_date=current_scan.start_scan_date - timedelta(days=2),
            scan_status=2,
            tasks=current_scan.tasks,
            is_legacy_scan=False,
        )
        newer_scan = ScanHistory.objects.create(
            target=target,
            start_scan_date=current_scan.start_scan_date + timedelta(days=1),
            scan_status=2,
            tasks=current_scan.tasks,
            is_legacy_scan=False,
        )
        older_domain = self.data_generator.create_domain(scan_history=older_scan)
        newer_domain = self.data_generator.create_domain(scan_history=newer_scan)
        older_subdomain = self.data_generator.create_subdomain(
            name=shared_name,
            scan_history=older_scan,
            domain=older_domain,
        )
        newer_subdomain = self.data_generator.create_subdomain(
            name=shared_name,
            scan_history=newer_scan,
            domain=newer_domain,
        )

        url = reverse("api:querySubdomains")
        response = self.client.get(
            url,
            {
                "target_id": target.id,
                "project": project_slug,
                "start": "0",
                "length": "200",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = [row for row in response.data.get("data", []) if row.get("name") == shared_name]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], newer_subdomain.id)
        self.assertNotEqual(rows[0]["id"], older_subdomain.id)

    def test_query_subdomains_scan_scope_does_not_mix_endpoint_technologies(self):
        """Subdomain technologies from endpoint aggregation stay scoped to the requested scan row."""
        dg = self.data_generator
        scan = dg.scan_history
        domain = dg.domain
        subdomain = dg.create_subdomain(
            name="scope-tech.example.com",
            scan_history=scan,
            domain=domain,
        )
        local_endpoint = dg.create_endpoint(
            http_url="https://scope-tech.example.com/",
            scan_history=scan,
            domain=domain,
            subdomain=subdomain,
        )
        local_tech = Technology.objects.create(scan_history=scan, name="local-tech", value="", category="")
        local_endpoint.techs.add(local_tech)

        other_scan = ScanHistory.objects.create(
            target=scan.target,
            start_scan_date=scan.start_scan_date + timedelta(days=3),
            scan_status=2,
            tasks=scan.tasks,
            is_legacy_scan=False,
        )
        other_domain = dg.create_domain(scan_history=other_scan)
        other_subdomain = dg.create_subdomain(
            name="scope-tech.example.com",
            scan_history=other_scan,
            domain=other_domain,
        )
        other_endpoint = dg.create_endpoint(
            http_url="https://scope-tech.example.com/other",
            scan_history=other_scan,
            domain=other_domain,
            subdomain=other_subdomain,
        )
        foreign_tech = Technology.objects.create(scan_history=other_scan, name="foreign-tech", value="", category="")
        other_endpoint.techs.add(foreign_tech)

        url = reverse("api:querySubdomains")
        response = self.client.get(
            url,
            {
                "scan_id": scan.id,
                "project": dg.project.slug,
                "start": "0",
                "length": "50",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = next((item for item in response.data.get("data", []) if item.get("id") == subdomain.id), None)
        self.assertIsNotNone(row)
        tech_names = {item.get("name") for item in (row.get("technologies") or [])}
        self.assertIn("local-tech", tech_names)
        self.assertNotIn("foreign-tech", tech_names)

    def test_query_subdomains_nonlegacy_without_endpoint_techs_skips_m2m_fallback(self):
        """For non-legacy scans, technologies come from endpoints only (no M2M fallback)."""
        dg = self.data_generator
        scan = dg.scan_history
        subdomain = dg.create_subdomain(
            name="no-endpoint-tech.example.com",
            scan_history=scan,
            domain=dg.domain,
        )
        stale_m2m_tech = Technology.objects.create(scan_history=scan, name="stale-m2m-tech", value="", category="")
        subdomain.technologies.add(stale_m2m_tech)

        url = reverse("api:querySubdomains")
        response = self.client.get(
            url,
            {
                "scan_id": scan.id,
                "project": dg.project.slug,
                "start": "0",
                "length": "50",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = next((item for item in response.data.get("data", []) if item.get("id") == subdomain.id), None)
        self.assertIsNotNone(row)
        self.assertEqual(row.get("technologies"), [])


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
        tech = Technology.objects.create(name="Caddy", scan_history=self.data_generator.scan_history)
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

    def test_datatable_secator_technologies_aggregate_all_endpoints(self):
        """Secator: flat technologies list unions techs from all endpoints for the subdomain, not only defaults."""
        dg = self.data_generator
        scan = dg.scan_history
        self.assertFalse(getattr(scan, "is_legacy_scan", True))
        domain = dg.domain
        subdomain = dg.subdomain
        host = subdomain.name
        tech_default = Technology.objects.create(name="FromDefaultEp", scan_history=scan, value="", category="")
        tech_other = Technology.objects.create(name="FromOtherEp", scan_history=scan, value="", category="")
        ep_default = dg.create_endpoint(
            http_url=f"https://{host}/",
            scan_history=scan,
            domain=domain,
            subdomain=subdomain,
            is_default=True,
        )
        ep_other = dg.create_endpoint(
            http_url=f"https://{host}/admin/extra",
            scan_history=scan,
            domain=domain,
            subdomain=subdomain,
            is_default=False,
        )
        ep_default.techs.add(tech_default)
        ep_other.techs.add(tech_other)

        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "scan_id": scan.id,
                "project": dg.project.slug,
                "start": "0",
                "length": "50",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = next((x for x in response.data["data"] if x["id"] == subdomain.id), None)
        self.assertIsNotNone(row)
        tech_names = {t.get("name") for t in row.get("technologies", [])}
        self.assertIn("FromDefaultEp", tech_names)
        self.assertIn("FromOtherEp", tech_names)

    def test_datatable_falls_back_to_subdomain_technologies_without_default_endpoint(self):
        """Legacy scans: when no default endpoint exists, technologies fall back to SubdomainTechnology M2M."""
        dg = self.data_generator
        legacy_scan = dg.create_scan_history(is_legacy=True)
        dg.domain.scan_history = legacy_scan
        dg.domain.save(update_fields=["scan_history_id"])
        subdomain = dg.create_subdomain(
            name="legacy-no-default.example.invalid",
            scan_history=legacy_scan,
            domain=dg.domain,
        )
        tech = Technology.objects.create(name="Nginx", scan_history=legacy_scan)
        subdomain.technologies.add(tech)
        EndPoint.objects.filter(subdomain=subdomain, scan_history=legacy_scan).delete()

        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "scan_id": legacy_scan.id,
                "project": dg.project.slug,
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
