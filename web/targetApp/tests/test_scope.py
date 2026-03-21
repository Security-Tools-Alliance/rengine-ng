"""
Tests for the Scope model and views.
"""

import json

from django.db import IntegrityError
from django.urls import reverse
from django.utils import timezone

from scanEngine.models import SecatorWorker
from targetApp.constants import (
    SCOPE_TYPE_BUG_BOUNTY,
    SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
    TARGET_TYPE_CIDR_RANGE,
    TARGET_TYPE_URL,
)
from targetApp.models import Organization, Scope, Target
from utils.test_base import BaseTestCase


class ScopeModelTest(BaseTestCase):
    """Tests for the Scope model."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_create_scope(self):
        scope = self.data_generator.create_scope()
        self.assertIsNotNone(scope.pk)
        self.assertEqual(scope.organization, self.data_generator.organization)
        self.assertEqual(scope.scope_type, SCOPE_TYPE_ENGAGEMENT_EXTERNAL)

    def test_scope_str(self):
        scope = self.data_generator.create_scope(name="Test Scope Alpha")
        self.assertIn("Test Scope Alpha", str(scope))
        self.assertIn("External Engagement", str(scope))

    def test_unique_constraint_org_name(self):
        org = self.data_generator.organization
        Scope.objects.create(
            organization=org,
            name="Unique Name",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
        )
        with self.assertRaises(IntegrityError):
            Scope.objects.create(
                organization=org,
                name="Unique Name",
                scope_type=SCOPE_TYPE_BUG_BOUNTY,
            )

    def test_scope_m2m_targets(self):
        scope = self.data_generator.create_scope()
        target = self.data_generator.target
        scope.targets.add(target)
        self.assertIn(target, scope.targets.all())
        self.assertIn(scope, target.scopes.all())

    def test_scope_m2m_workers(self):
        scope = self.data_generator.create_scope()
        self.assertEqual(scope.workers.count(), 0)

    def test_scope_optional_fields_null(self):
        scope = Scope.objects.create(
            organization=self.data_generator.organization,
            name="Minimal Scope",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
        )
        self.assertIsNone(scope.scan_config)
        self.assertIsNone(scope.start_date)
        self.assertIsNone(scope.end_date)

    def test_cascade_delete_organization(self):
        scope = self.data_generator.create_scope()
        scope_id = scope.pk
        self.data_generator.organization.delete()
        self.assertFalse(Scope.objects.filter(pk=scope_id).exists())

    def test_target_scan_config_field(self):
        target = self.data_generator.target
        target.scan_config = {"threads": 10, "proxy": "socks5://10.0.0.1:1080"}
        target.save()
        target.refresh_from_db()
        self.assertEqual(target.scan_config["threads"], 10)
        self.assertEqual(target.scan_config["proxy"], "socks5://10.0.0.1:1080")

    def test_scope_save_normalizes_allowed_finding_hosts(self):
        scope = Scope(
            organization=self.data_generator.organization,
            name="Normalize Test",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
            allowed_finding_hosts=["  Host.Example.COM  ", "host.example.com", "192.168.1.1"],
        )
        scope.save()
        scope.refresh_from_db()
        self.assertEqual(scope.allowed_finding_hosts, ["host.example.com", "192.168.1.1"])

    def test_scope_save_non_list_allowed_finding_hosts_becomes_empty_list(self):
        scope = Scope(
            organization=self.data_generator.organization,
            name="Non-list Test",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
        )
        scope.allowed_finding_hosts = {"invalid": "dict"}
        scope.save()
        scope.refresh_from_db()
        self.assertEqual(scope.allowed_finding_hosts, [])

    def test_scope_save_legacy_string_allowed_finding_hosts_converted(self):
        scope = Scope(
            organization=self.data_generator.organization,
            name="Legacy String Test",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
        )
        scope.allowed_finding_hosts = "host1.example.com, host2.example.com\n  host3.example.com  "
        scope.save()
        scope.refresh_from_db()
        self.assertEqual(
            scope.allowed_finding_hosts,
            ["host1.example.com", "host2.example.com", "host3.example.com"],
        )


class ScopeViewsTest(BaseTestCase):
    """Tests for the Scope CRUD views."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()
        self.slug = self.data_generator.project.slug

    def test_list_scope_view(self):
        self.data_generator.create_scope()
        response = self.client.get(reverse("list_scope", kwargs={"slug": self.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scope/list.html")
        self.assertTrue(len(response.context["scopes"]) >= 1)

    def test_list_scope_empty(self):
        response = self.client.get(reverse("list_scope", kwargs={"slug": self.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["scopes"].count(), 0)

    def test_add_scope_get(self):
        response = self.client.get(reverse("add_scope", kwargs={"slug": self.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scope/add.html")

    def test_add_scope_post_valid(self):
        org = self.data_generator.organization
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "name": "New Test Scope",
                "scope_type": SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Scope.objects.filter(name="New Test Scope").exists())

    def test_add_scope_post_invalid_missing_name(self):
        org = self.data_generator.organization
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "scope_type": SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("name", response.context["form"].errors)
        self.assertFalse(
            Scope.objects.filter(
                organization=org,
                scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
            ).exists()
        )

    def test_add_scope_with_dates(self):
        org = self.data_generator.organization
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "name": "Dated Scope",
                "scope_type": SCOPE_TYPE_BUG_BOUNTY,
                "start_date": "2025-01-01",
                "end_date": "2025-12-31",
            },
        )
        self.assertEqual(response.status_code, 302)
        scope = Scope.objects.get(name="Dated Scope")
        self.assertIsNotNone(scope.start_date)
        self.assertIsNotNone(scope.end_date)

    def test_add_scope_invalid_dates(self):
        org = self.data_generator.organization
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "name": "Bad Dates Scope",
                "scope_type": SCOPE_TYPE_BUG_BOUNTY,
                "start_date": "2025-12-31",
                "end_date": "2025-01-01",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Scope.objects.filter(name="Bad Dates Scope").exists())

    def test_update_scope_get(self):
        scope = self.data_generator.create_scope()
        response = self.client.get(reverse("update_scope", kwargs={"slug": self.slug, "id": scope.id}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scope/update.html")

    def test_update_scope_post(self):
        scope = self.data_generator.create_scope()
        org = self.data_generator.organization
        response = self.client.post(
            reverse("update_scope", kwargs={"slug": self.slug, "id": scope.id}),
            {
                "organization": org.id,
                "name": "Updated Name",
                "scope_type": SCOPE_TYPE_BUG_BOUNTY,
            },
        )
        self.assertEqual(response.status_code, 302)
        scope.refresh_from_db()
        self.assertEqual(scope.name, "Updated Name")
        self.assertEqual(scope.scope_type, SCOPE_TYPE_BUG_BOUNTY)

    def test_update_scope_post_persists_default_worker(self):
        """default_worker must bind from POST (same name as Advanced Configuration worker select)."""
        worker_a = SecatorWorker.objects.create(
            name="scope-form-worker-a",
            ssh_host="192.0.2.20",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        worker_b = SecatorWorker.objects.create(
            name="scope-form-worker-b",
            ssh_host="192.0.2.21",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.workers.set([worker_a, worker_b])
        scope.allow_local_worker = True
        scope.default_worker = None
        scope.save()
        org = scope.organization
        response = self.client.post(
            reverse("update_scope", kwargs={"slug": self.slug, "id": scope.id}),
            {
                "organization": org.id,
                "name": scope.name,
                "scope_type": scope.scope_type,
                "allow_local_worker": "on",
                "workers": [worker_a.id, worker_b.id],
                "default_worker": str(worker_b.id),
            },
        )
        self.assertEqual(response.status_code, 302)
        scope.refresh_from_db()
        self.assertEqual(scope.default_worker_id, worker_b.id)

    def test_scope_normalize_invalid_json_returns_400(self):
        url = reverse("scope_normalize", kwargs={"slug": self.slug})
        response = self.client.post(
            url,
            data="not valid json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data.get("error"), "Invalid JSON body")

    def test_scope_normalize_apply_invalid_json_returns_400(self):
        url = reverse("scope_normalize_apply", kwargs={"slug": self.slug})
        response = self.client.post(
            url,
            data="not valid json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data.get("error"), "Invalid JSON body")

    def test_delete_scope_post(self):
        scope = self.data_generator.create_scope()
        scope_id = scope.pk
        response = self.client.post(reverse("delete_scope", kwargs={"slug": self.slug, "id": scope_id}))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "true")
        self.assertFalse(Scope.objects.filter(pk=scope_id).exists())

    def test_delete_scope_get_fails(self):
        scope = self.data_generator.create_scope()
        response = self.client.get(reverse("delete_scope", kwargs={"slug": self.slug, "id": scope.id}))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "false")
        self.assertTrue(Scope.objects.filter(pk=scope.pk).exists())

    def test_delete_nonexistent_scope(self):
        response = self.client.post(reverse("delete_scope", kwargs={"slug": self.slug, "id": 99999}))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "false")

    def test_scope_detail_view(self):
        scope = self.data_generator.create_scope()
        response = self.client.get(reverse("scope_detail", kwargs={"slug": self.slug, "id": scope.id}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scope/detail.html")
        self.assertEqual(response.context["scope"].pk, scope.pk)

    def test_scope_detail_wrong_project(self):
        from dashboard.models import Project

        other_project = Project.objects.create(name="Other Project", slug="other-project", insert_date=timezone.now())
        other_org = Organization.objects.create(
            name="Other Org",
            project=other_project,
            insert_date=timezone.now(),
        )
        other_scope = Scope.objects.create(
            organization=other_org,
            name="Other Scope",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
        )
        response = self.client.get(reverse("scope_detail", kwargs={"slug": self.slug, "id": other_scope.id}))
        self.assertEqual(response.status_code, 404)

    def test_add_scope_with_targets(self):
        org = self.data_generator.organization
        target = self.data_generator.target
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "name": "Scope With Targets",
                "scope_type": SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
                "targets": [target.id],
            },
        )
        self.assertEqual(response.status_code, 302)
        scope = Scope.objects.get(name="Scope With Targets")
        self.assertIn(target, scope.targets.all())

    def test_add_scope_with_pending_normalizer_targets_creates_targets_on_save(self):
        """Saving a scope with pending_normalizer_targets creates those targets and adds them to the scope."""
        org = self.data_generator.organization
        project = org.project
        pending = json.dumps(
            {
                "domain_targets": ["pending-domain.example.com", "other-root.org"],
                "ip_targets": ["10.9.8.7"],
            }
        )
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "name": "Scope With Pending Targets",
                "scope_type": SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
                "pending_normalizer_targets": pending,
            },
        )
        self.assertEqual(response.status_code, 302)
        scope = Scope.objects.get(name="Scope With Pending Targets")
        scope_target_ids = list(scope.targets.values_list("id", flat=True))
        self.assertEqual(len(scope_target_ids), 3)
        host_targets = Target.objects.filter(project=project, target_type="host").values_list("value", flat=True)
        self.assertIn("pending-domain.example.com", host_targets)
        self.assertIn("other-root.org", host_targets)
        ip_targets = Target.objects.filter(project=project, target_type="ip").values_list("value", flat=True)
        self.assertIn("10.9.8.7", ip_targets)

    def test_add_scope_with_pending_cidr_and_url_targets(self):
        """pending_normalizer_targets may include cidr_targets and url_targets (scope normalizer JSON)."""
        org = self.data_generator.organization
        project = org.project
        pending = json.dumps(
            {
                "domain_targets": [],
                "ip_targets": [],
                "cidr_targets": ["10.10.0.0/16"],
                "url_targets": ["https://app.pending-scope.example.com/api"],
            }
        )
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "name": "Scope Pending CIDR URL",
                "scope_type": SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
                "pending_normalizer_targets": pending,
            },
        )
        self.assertEqual(response.status_code, 302)
        scope = Scope.objects.get(name="Scope Pending CIDR URL")
        self.assertEqual(scope.targets.count(), 2)
        self.assertTrue(scope.targets.filter(value="10.10.0.0/16", target_type=TARGET_TYPE_CIDR_RANGE).exists())
        self.assertTrue(
            scope.targets.filter(
                value="https://app.pending-scope.example.com/api",
                target_type=TARGET_TYPE_URL,
            ).exists()
        )
        self.assertTrue(Target.objects.filter(project=project, value="10.10.0.0/16").exists())

    def test_update_scope_with_pending_normalizer_targets_creates_targets_on_save(self):
        """Updating a scope with pending_normalizer_targets creates those targets and adds them to the scope."""
        scope = self.data_generator.create_scope(name="To Update")
        org = scope.organization
        project = org.project
        pending = json.dumps(
            {
                "domain_targets": ["update-domain.example.com"],
                "ip_targets": [],
            }
        )
        response = self.client.post(
            reverse("update_scope", kwargs={"slug": self.slug, "id": scope.id}),
            {
                "organization": org.id,
                "name": scope.name,
                "scope_type": scope.scope_type,
                "pending_normalizer_targets": pending,
            },
        )
        self.assertEqual(response.status_code, 302)
        scope.refresh_from_db()
        self.assertEqual(scope.targets.filter(value="update-domain.example.com").count(), 1)
        self.assertTrue(Target.objects.filter(project=project, value="update-domain.example.com").exists())

    def test_add_scope_with_scan_params(self):
        org = self.data_generator.organization
        response = self.client.post(
            reverse("add_scope", kwargs={"slug": self.slug}),
            {
                "organization": org.id,
                "name": "Parameterized Scope",
                "scope_type": SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
                "threads": 10,
                "rate_limit": 50,
                "timeout": 30,
                "proxy": "http://10.0.0.2:8080",
            },
        )
        self.assertEqual(response.status_code, 302)
        scope = Scope.objects.get(name="Parameterized Scope")
        self.assertEqual(scope.scan_config["threads"], 10)
        self.assertEqual(scope.scan_config["rate_limit"], 50)
        self.assertEqual(scope.scan_config["timeout"], 30)
        self.assertEqual(scope.scan_config["proxy"], "http://10.0.0.2:8080")

    def test_scope_filtered_by_project(self):
        """Scopes from other projects should not appear in the list."""
        from dashboard.models import Project

        other_project = Project.objects.create(
            name="Isolated Project", slug="isolated-project", insert_date=timezone.now()
        )
        other_org = Organization.objects.create(
            name="Isolated Org",
            project=other_project,
            insert_date=timezone.now(),
        )
        Scope.objects.create(
            organization=other_org,
            name="Isolated Scope",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
        )
        self.data_generator.create_scope(name="My Scope")

        response = self.client.get(reverse("list_scope", kwargs={"slug": self.slug}))
        scope_names = [s.name for s in response.context["scopes"]]
        self.assertIn("My Scope", scope_names)
        self.assertNotIn("Isolated Scope", scope_names)
