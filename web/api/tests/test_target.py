"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status
from targetApp.models import Domain
from .test_base import BaseTestCase

class TestAddTarget(BaseTestCase):
    """Test case for adding a target."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_base()

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
        self.assertEqual(response.data["domain_name"], self.data_generator.domain.name)
        self.assertTrue(
            Domain.objects.filter(name=self.data_generator.domain.name).exists()
        )

class TestListTargetsDatatableViewSet(BaseTestCase):
    """Tests for the List Targets Datatable API."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_project_base()

    def test_list_targets(self):
        """Test listing targets."""
        api_url = reverse("api:targets-list")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.domain.name
        )

    def test_list_targets_with_slug(self):
        """Test listing targets with project slug."""
        api_url = reverse("api:targets-list")
        response = self.client.get(api_url, {"slug": "test-project"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.domain.name
        )

