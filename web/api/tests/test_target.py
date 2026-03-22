"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from reNgine.services.scan_finding_metrics import get_ip_metrics_for_target
from startScan.models import Domain, EndPoint, IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Organization, Scope, Target
from utils.test_base import BaseTestCase


class TestAddTarget(BaseTestCase):
    """Test case for adding a target."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project()

    def test_add_target(self):
        """Test adding a new target."""
        api_url = reverse("api:addTarget")
        data = {
            "domain_name": "example.com",
            "h1_team_handle": "team_handle",
            "description": "Test description",
            "organization": "Test Org",
            "slug": self.data_generator.project.slug,
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["domain_name"], "example.com")
        self.assertIn("target_id", response.data)
        self.assertIn("initiate_scan_url", response.data)
        self.assertIn(f"/target/start/{response.data['target_id']}", response.data["initiate_scan_url"])
        self.assertTrue(Target.objects.filter(project=self.data_generator.project, value="example.com").exists())

        # Test adding duplicate target
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])


class TestListTargetsDatatableViewSet(BaseTestCase):
    """Tests for the List Targets Datatable API."""

    def setUp(self):
        super().setUp()

    def test_list_targets(self):
        """Test listing targets (API returns Target model; name is alias for value)."""
        api_url = reverse("api:targets-list")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"],
            self.data_generator.target.value,
        )

    def test_list_targets_with_slug(self):
        """Test listing targets with project slug."""
        api_url = reverse("api:targets-list")
        response = self.client.get(api_url, {"slug": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"],
            self.data_generator.target.value,
        )

    def test_list_targets_datatable_ip_counts_match_get_ip_metrics_for_target(self) -> None:
        """Target list DataTable exposes centralized per-target IP counts."""
        target = self.data_generator.target
        scan = self.data_generator.scan_history
        sub = self.data_generator.create_subdomain(scan_history=scan, domain=self.data_generator.domain)
        ip = IpAddress.objects.create(address="192.0.2.99", version=4, alive=True)
        sub.ip_addresses.add(ip)
        expected_total, expected_alive = get_ip_metrics_for_target(target.id)

        api_url = reverse("api:targets-list")
        response = self.client.get(
            api_url,
            {
                "slug": self.data_generator.project.slug,
                "start": 0,
                "length": 50,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        row = next((r for r in rows if r.get("id") == target.id), None)
        self.assertIsNotNone(row, msg="Expected target row in DataTable response")
        self.assertEqual(row.get("ip_address_count"), expected_total)
        self.assertEqual(row.get("ip_alive_count"), expected_alive)

    def test_list_targets_order_by_name_asc(self):
        """List targets with order column 2 (value) ascending uses centralised map."""
        project = self.data_generator.project
        Target.objects.filter(project=project).delete()
        for val in ("zzz-target.local", "aaa-target.local", "mmm-target.local"):
            Target.objects.create(
                project=project,
                value=val,
                target_type="host",
                insert_date=timezone.now(),
            )
        api_url = reverse("api:targets-list")
        response = self.client.get(
            api_url,
            {"slug": project.slug, "order[0][column]": "2", "order[0][dir]": "asc"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        names = [r["name"] for r in response.data["results"]]
        self.assertEqual(names, ["aaa-target.local", "mmm-target.local", "zzz-target.local"])

    def test_list_targets_order_by_start_scan_date_nulls_last(self):
        """List targets with order column 6 (start_scan_date) uses nulls_last."""
        project = self.data_generator.project
        Target.objects.filter(project=project).delete()
        older = timezone.now() - timezone.timedelta(days=2)
        newer = timezone.now() - timezone.timedelta(days=1)
        Target.objects.create(
            project=project,
            value="null-date.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        t_old = Target.objects.create(
            project=project,
            value="old-scan.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        t_new = Target.objects.create(
            project=project,
            value="new-scan.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        # Attach ScanHistory rows so ordering uses real scan dates.
        ScanHistory.objects.create(target=t_old, start_scan_date=older)
        ScanHistory.objects.create(target=t_new, start_scan_date=newer)
        api_url = reverse("api:targets-list")
        response_asc = self.client.get(
            api_url,
            {"slug": project.slug, "order[0][column]": "6", "order[0][dir]": "asc"},
        )
        self.assertEqual(response_asc.status_code, status.HTTP_200_OK)
        names_asc = [r["name"] for r in response_asc.data["results"]]
        self.assertIn("null-date.local", names_asc)
        self.assertIn("old-scan.local", names_asc)
        self.assertIn("new-scan.local", names_asc)
        idx_old = names_asc.index("old-scan.local")
        idx_new = names_asc.index("new-scan.local")
        idx_null = names_asc.index("null-date.local")
        self.assertLess(idx_old, idx_new, "asc: older date before newer")
        self.assertLess(idx_new, idx_null, "asc: nulls last")

        response_desc = self.client.get(
            api_url,
            {"slug": project.slug, "order[0][column]": "6", "order[0][dir]": "desc"},
        )
        self.assertEqual(response_desc.status_code, status.HTTP_200_OK)
        names_desc = [r["name"] for r in response_desc.data["results"]]
        idx_null_d = names_desc.index("null-date.local")
        idx_new_d = names_desc.index("new-scan.local")
        idx_old_d = names_desc.index("old-scan.local")
        self.assertLess(idx_new_d, idx_old_d, "desc: newer before older")
        self.assertLess(idx_old_d, idx_null_d, "desc: nulls last")

    def test_list_targets_filter_has_scan(self):
        """List targets with filter_has_scan returns only scanned or never-scanned targets."""
        project = self.data_generator.create_project()
        Target.objects.filter(project=project).delete()
        Target.objects.create(
            project=project,
            value="never-scanned.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        t_scanned = Target.objects.create(
            project=project,
            value="scanned.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        ScanHistory.objects.create(
            target=t_scanned,
            start_scan_date=timezone.now(),
            scan_status=3,
        )
        api_url = reverse("api:targets-list")
        base = {"slug": project.slug}
        response_all = self.client.get(api_url, base)
        self.assertEqual(response_all.status_code, status.HTTP_200_OK)
        names_all = [r["name"] for r in response_all.data["results"]]
        self.assertIn("never-scanned.local", names_all)
        self.assertIn("scanned.local", names_all)

        response_scanned = self.client.get(api_url, {**base, "filter_has_scan": "scanned"})
        self.assertEqual(response_scanned.status_code, status.HTTP_200_OK)
        names_scanned = [r["name"] for r in response_scanned.data["results"]]
        self.assertEqual(sorted(names_scanned), ["scanned.local"])

        response_never = self.client.get(api_url, {**base, "filter_has_scan": "never"})
        self.assertEqual(response_never.status_code, status.HTTP_200_OK)
        names_never = [r["name"] for r in response_never.data["results"]]
        self.assertEqual(sorted(names_never), ["never-scanned.local"])

    def test_list_targets_includes_scope_group(self):
        """List targets response includes scope_group (first scope name or 'No scope')."""
        self.data_generator.create_project()
        self.data_generator.create_target()
        api_url = reverse("api:targets-list")
        response = self.client.get(api_url, {"slug": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        first = response.data["results"][0]
        self.assertIn("scope_group", first)
        self.assertEqual(first["scope_group"], "No scope")

        self.data_generator.create_organization()
        self.data_generator.create_scope(name="TestScopeAlpha")
        response2 = self.client.get(api_url, {"slug": self.data_generator.project.slug})
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        by_name = {r["name"]: r for r in response2.data["results"]}
        self.assertIn(self.data_generator.target.value, by_name)
        self.assertEqual(by_name[self.data_generator.target.value]["scope_group"], "TestScopeAlpha")

    def test_list_targets_order_by_scope_group_column_14(self):
        """List targets with order column 14 (scope_group_name) uses annotation."""
        from targetApp.models import Organization, Scope

        project = self.data_generator.create_project()
        Target.objects.filter(project=project).delete()
        org = Organization.objects.create(name="TestOrgScope", insert_date=timezone.now())
        Target.objects.create(
            project=project,
            value="no-scope.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        scope_a = Scope.objects.create(
            organization=org,
            name="A-scope",
            scope_type="engagement_external",
            description="",
        )
        scope_b = Scope.objects.create(
            organization=org,
            name="B-scope",
            scope_type="engagement_external",
            description="",
        )
        target_a = Target.objects.create(
            project=project,
            value="a-scope.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        target_b = Target.objects.create(
            project=project,
            value="b-scope.local",
            target_type="host",
            insert_date=timezone.now(),
        )
        scope_a.targets.add(target_a)
        scope_b.targets.add(target_b)
        api_url = reverse("api:targets-list")
        response = self.client.get(
            api_url,
            {"slug": project.slug, "order[0][column]": "14", "order[0][dir]": "asc"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        scope_groups = [r["scope_group"] for r in response.data["results"]]
        self.assertEqual(scope_groups, ["A-scope", "B-scope", "No scope"])

    def test_list_targets_aggregated_counts(self):
        """List targets returns aggregated domain/subdomain/endpoint/vulnerability counts across all scan history."""
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_scan_history()
        self.data_generator.create_domain(scan_history=self.data_generator.scan_history)
        self.data_generator.domain.name = "agg-target.local"
        self.data_generator.domain.save(update_fields=["name"])
        self.data_generator.create_subdomain(
            name="sub1.agg-target.local",
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
        )
        self.data_generator.create_endpoint(
            http_url="https://sub1.agg-target.local/path1",
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
            subdomain=self.data_generator.subdomain,
        )
        self.data_generator.create_vulnerability()

        scan2 = ScanHistory.objects.create(
            target=self.data_generator.target,
            start_scan_date=timezone.now(),
            scan_status=2,
            tasks=["subdomain_discovery"],
        )
        Domain.objects.create(
            name="agg-target.local",
            insert_date=timezone.now(),
            scan_history=scan2,
        )
        domain_other = Domain.objects.create(
            name="other.agg-target.local",
            insert_date=timezone.now(),
            scan_history=scan2,
        )
        sub2 = Subdomain.objects.create(
            name="sub2.agg-target.local",
            scan_history=scan2,
            domain=domain_other,
        )
        EndPoint.objects.create(
            http_url="https://sub2.agg-target.local/path2",
            scan_history=scan2,
            domain=domain_other,
            subdomain=sub2,
            discovered_date=timezone.now(),
        )
        Vulnerability.objects.create(
            name="Vuln 2",
            severity=1,
            discovered_date=timezone.now(),
            scan_history=scan2,
            domain=domain_other,
            subdomain=sub2,
        )

        api_url = reverse("api:targets-list")
        response = self.client.get(api_url, {"slug": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        by_name = {r["name"]: r for r in response.data["results"]}
        self.assertIn(
            self.data_generator.target.value,
            by_name,
            "Target must appear in list",
        )
        row = by_name[self.data_generator.target.value]
        self.assertIn("domain_count", row)
        self.assertIn("subdomain_count", row)
        self.assertIn("endpoint_count", row)
        self.assertIn("vulnerability_count", row)
        self.assertEqual(row["domain_count"], 2, "Distinct domain names: agg-target.local, other.agg-target.local")
        self.assertEqual(row["subdomain_count"], 2, "Distinct subdomain names across scans")
        self.assertEqual(row["endpoint_count"], 2, "Distinct endpoint URLs across scans")
        self.assertEqual(row["vulnerability_count"], 2, "Total vulnerabilities across scans")


class TestListScopesApi(BaseTestCase):
    """Tests for ListScopes API used by target list filter dropdown."""

    def test_list_scopes_returns_scopes_linked_to_project_targets(self):
        project = self.data_generator.project
        target = self.data_generator.target
        org = Organization.objects.create(
            name="Scope API Org",
            description="",
            insert_date=timezone.now(),
            project=None,
        )
        scope = Scope.objects.create(
            organization=org,
            name="ScopeFromTargetLink",
            scope_type="engagement_external",
            description="",
        )
        scope.targets.add(target)

        api_url = reverse("api:listScopes")
        response = self.client.get(api_url, {"project": project.slug})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        names = [item["name"] for item in response.data.get("scopes", [])]
        self.assertIn("ScopeFromTargetLink", names)
