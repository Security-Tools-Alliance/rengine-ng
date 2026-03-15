"""
Tests for the Organization model, including get_targets() (legacy vs scope-based).
"""

from targetApp.constants import SCOPE_TYPE_ENGAGEMENT_EXTERNAL
from targetApp.models import Organization, Scope, Target
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
