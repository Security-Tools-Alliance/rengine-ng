"""
Tests for custom managers: Target.for_project, Organization.for_project, SecatorWorker.active.
"""

from scanEngine.models import SecatorWorker
from targetApp.models import Organization, Target
from utils.test_base import BaseTestCase


class TargetManagerTest(BaseTestCase):
    """Tests for Target.objects.for_project."""

    def test_for_project_by_slug_includes_project_targets(self):
        self.data_generator.create_organization()
        target = self.data_generator.target
        slug = self.data_generator.project.slug
        qs = Target.objects.for_project(slug)
        self.assertIn(target, qs)
        self.assertGreaterEqual(qs.count(), 1)

    def test_for_project_by_instance_includes_project_targets(self):
        self.data_generator.create_organization()
        target = self.data_generator.target
        project = self.data_generator.project
        qs = Target.objects.for_project(project)
        self.assertIn(target, qs)

    def test_for_project_by_invalid_slug_returns_empty(self):
        qs = Target.objects.for_project("nonexistent-slug-xyz")
        self.assertEqual(qs.count(), 0)


class OrganizationManagerTest(BaseTestCase):
    """Tests for Organization.objects.for_project."""

    def test_for_project_by_slug_includes_project_organizations(self):
        self.data_generator.create_organization()
        org = self.data_generator.organization
        slug = self.data_generator.project.slug
        qs = Organization.objects.for_project(slug)
        self.assertIn(org, qs)
        self.assertGreaterEqual(qs.count(), 1)

    def test_for_project_by_instance_includes_project_organizations(self):
        self.data_generator.create_organization()
        org = self.data_generator.organization
        project = self.data_generator.project
        qs = Organization.objects.for_project(project)
        self.assertIn(org, qs)

    def test_for_project_by_invalid_slug_returns_empty(self):
        qs = Organization.objects.for_project("nonexistent-slug-xyz")
        self.assertEqual(qs.count(), 0)


class SecatorWorkerManagerTest(BaseTestCase):
    """Tests for SecatorWorker.objects.active."""

    def test_active_returns_only_active_workers(self):
        active_worker = SecatorWorker.objects.create(
            name="active-worker-manager-test",
            ssh_host="192.0.2.1",
            ssh_port=22,
            ssh_user="deploy",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            is_active=True,
        )
        inactive_worker = SecatorWorker.objects.create(
            name="inactive-worker-manager-test",
            ssh_host="192.0.2.2",
            ssh_port=22,
            ssh_user="deploy",
            ssh_auth_type=SecatorWorker.AUTH_KEY,
            deploy_path="/opt/w",
            is_active=False,
        )
        active_qs = SecatorWorker.objects.active()
        self.assertIn(active_worker, active_qs)
        self.assertNotIn(inactive_worker, active_qs)
        self.assertEqual(active_qs.filter(pk=inactive_worker.pk).count(), 0)
