"""
Tests for dashboard.context_processors (project context and datatable_action_urls).
"""

from unittest.mock import patch

from django.test import RequestFactory, TestCase

from dashboard.context_processors import project_context


class TestProjectContextProcessor(TestCase):
    """Test project_context processor."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_datatable_action_urls_in_context_when_current_project_set(self):
        """When request.current_project is set, context includes datatable_action_urls."""
        request = self.factory.get("/")
        request.user = type("User", (), {"is_authenticated": True})()
        request.current_project = type("Obj", (), {"slug": "test-project-slug"})()

        with patch("dashboard.context_processors.get_user_projects", return_value=[]):
            context = project_context(request)

        self.assertIn("datatable_action_urls", context)
        urls = context["datatable_action_urls"]
        self.assertIn("subdomain", urls)
        self.assertIn("vulnerability", urls)
        self.assertIn("target", urls)
        self.assertIn("targetSummaryBase", urls["target"])

    def test_no_datatable_action_urls_when_current_project_none(self):
        """When current_project is None and no projects, context has no datatable_action_urls."""
        request = self.factory.get("/")
        request.user = type("User", (), {"is_authenticated": True})()
        request.current_project = None

        with patch("dashboard.context_processors.get_user_projects", return_value=[]):
            context = project_context(request)

        self.assertNotIn("datatable_action_urls", context)
