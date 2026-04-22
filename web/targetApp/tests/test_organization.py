"""
Tests for the Organization model, including get_targets() (legacy vs scope-based),
organization dashboard view, and organization dashboard service.
"""

from django.urls import reverse
from django.utils import timezone

from dashboard.models import Project
from targetApp.constants import SCOPE_TYPE_ENGAGEMENT_EXTERNAL
from targetApp.models import Organization, Scope, Target
from targetApp.services.organization_dashboard import get_organization_dashboard_data
from utils.test_base import BaseTestCase


class OrganizationGetTargetsTest(BaseTestCase):
    """Tests for Organization.get_targets() (union of direct legacy targets and scope targets)."""

    def setUp(self) -> None:
        super().setUp()
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()

    def test_get_targets_empty_when_no_direct_and_no_scopes(self) -> None:
        """get_targets returns empty when org has no direct targets and no scopes."""
        org = self.data_generator.create_organization()
        org.targets.clear()
        result = list(org.get_targets())
        self.assertEqual(result, [])

    def test_get_targets_returns_scope_targets_when_no_direct(self) -> None:
        """get_targets returns targets from scopes when org has no direct targets."""
        org = self.data_generator.create_organization()
        org.targets.clear()
        scope = self.data_generator.create_scope()
        scope.targets.add(self.data_generator.target)
        result = list(org.get_targets())
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.data_generator.target)

    def test_get_targets_returns_direct_targets_when_legacy(self) -> None:
        """get_targets returns direct (legacy) targets when org has them."""
        org = self.data_generator.create_organization()
        self.data_generator.organization.targets.add(self.data_generator.target)
        result = list(org.get_targets())
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.data_generator.target)

    def test_get_targets_returns_union_when_both_direct_and_scope_targets(self) -> None:
        """get_targets returns union of direct and scope targets without duplicates."""
        org = self.data_generator.create_organization()
        org.targets.add(self.data_generator.target)
        target_b = Target.objects.create(
            project=self.data_generator.project,
            value="other.example.com",
            target_type="host",
            insert_date=self.data_generator.target.insert_date,
        )
        scope = Scope.objects.create(
            organization=org,
            name="Scope With Second Target",
            scope_type=SCOPE_TYPE_ENGAGEMENT_EXTERNAL,
        )
        scope.targets.add(target_b)
        result = list(org.get_targets())
        self.assertEqual(len(result), 2)
        result_ids = {t.id for t in result}
        self.assertEqual(result_ids, {self.data_generator.target.id, target_b.id})

    def test_get_targets_deduplicates_when_target_in_both_org_and_scope(self) -> None:
        """get_targets returns each target once when same target is on org and on a scope."""
        org = self.data_generator.create_organization()
        org.targets.add(self.data_generator.target)
        scope = self.data_generator.create_scope()
        scope.targets.add(self.data_generator.target)
        result = list(org.get_targets())
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.data_generator.target)


class OrganizationDashboardViewTest(BaseTestCase):
    """Tests for the organization dashboard view."""

    def setUp(self) -> None:
        super().setUp()
        self.data_generator.create_organization()
        self.slug = self.data_generator.project.slug

    def test_organization_dashboard_returns_200_when_org_belongs_to_project(self) -> None:
        """Dashboard returns 200 and uses dashboard template when org belongs to project."""
        org = self.data_generator.organization
        response = self.client.get(
            reverse(
                "organization_dashboard",
                kwargs={"slug": self.slug, "organization_id": org.id},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "organization/dashboard.html")
        self.assertEqual(response.context["organization"].id, org.id)
        self.assertIn("scopes_data", response.context)
        self.assertIn("target_count", response.context)

    def test_organization_dashboard_returns_404_when_organization_does_not_exist(self) -> None:
        """Dashboard returns 404 when organization_id does not exist."""
        response = self.client.get(
            reverse(
                "organization_dashboard",
                kwargs={"slug": self.slug, "organization_id": 99999},
            )
        )
        self.assertEqual(response.status_code, 404)

    def test_organization_dashboard_returns_404_when_org_belongs_to_other_project(self) -> None:
        """Dashboard returns 404 when organization belongs to another project."""
        other_project = Project.objects.create(
            name="Other Project",
            slug="other-project-slug-xyz",
            insert_date=timezone.now(),
        )
        other_project.users.add(self.user)
        other_org = Organization.objects.create(
            name="Other Project Org",
            insert_date=self.data_generator.organization.insert_date,
            project=other_project,
        )
        response = self.client.get(
            reverse(
                "organization_dashboard",
                kwargs={"slug": self.slug, "organization_id": other_org.id},
            )
        )
        self.assertEqual(response.status_code, 404)


class OrganizationDashboardServiceTest(BaseTestCase):
    """Tests for get_organization_dashboard_data service."""

    def setUp(self) -> None:
        super().setUp()
        self.data_generator.create_organization()

    def test_service_returns_empty_counts_when_org_has_no_targets(self) -> None:
        """When organization has no targets, counts are zero and feeds empty."""
        org = self.data_generator.organization
        org.targets.clear()
        for scope in org.scopes.all():
            scope.targets.clear()
        data = get_organization_dashboard_data(org)
        self.assertEqual(data["target_count"], 0)
        self.assertEqual(data["domain_count"], 0)
        self.assertEqual(data["subdomain_count"], 0)
        self.assertEqual(data["endpoint_count"], 0)
        self.assertEqual(data["total_vul_count"], 0)
        self.assertEqual(len(data["activity_feed"]), 0)
        self.assertEqual(len(data["vulnerability_feed"]), 0)
        self.assertEqual(len(data["targets_in_last_week"]), 7)

    def test_service_returns_scope_count_and_scopes_data(self) -> None:
        """Service includes scope_count and scopes_data from organization scopes."""
        org = self.data_generator.organization
        scope = self.data_generator.create_scope(name="Dashboard Test Scope")
        scope.targets.add(self.data_generator.target)
        data = get_organization_dashboard_data(org)
        self.assertGreaterEqual(data["scope_count"], 1)
        self.assertGreaterEqual(len(data["scopes_data"]), 1)
        scope_names = [s["name"] for s in data["scopes_data"]]
        self.assertIn("Dashboard Test Scope", scope_names)
