"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from targetApp.models import Target
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
            start_scan_date=None,
        )
        Target.objects.create(
            project=project,
            value="old-scan.local",
            target_type="host",
            insert_date=timezone.now(),
            start_scan_date=older,
        )
        Target.objects.create(
            project=project,
            value="new-scan.local",
            target_type="host",
            insert_date=timezone.now(),
            start_scan_date=newer,
        )
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
