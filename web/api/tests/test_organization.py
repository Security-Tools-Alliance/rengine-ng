"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status
from utils.test_base import BaseTestCase
from targetApp.models import Organization

__all__ = [
    'TestListOrganizations',
    'TestListTargetsInOrganization',
    'TestListTargetsWithoutOrganization'
]

class TestListOrganizations(BaseTestCase):
    """Test case for listing organizations."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_empty_organizations(self):
        """Test listing organizations when the database is empty."""
        Organization.objects.all().delete()
        url = reverse("api:listOrganizations")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['organizations']), 0)

    def test_list_organizations(self):
        """Test listing all organizations."""
        url = reverse("api:listOrganizations")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("organizations", response.data)
        self.assertGreaterEqual(len(response.data["organizations"]), 1)
        self.assertEqual(
            response.data["organizations"][0]["name"],
            self.data_generator.organization.name,
        )

class TestListTargetsInOrganization(BaseTestCase):
    """Test case for listing targets in an organization."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_targets_in_organization(self):
        """Test listing targets for a specific organization."""
        url = reverse("api:queryTargetsInOrganization")
        response = self.client.get(
            url, {"organization_id": self.data_generator.organization.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("organization", response.data)
        self.assertIn("domains", response.data)
        self.assertGreaterEqual(len(response.data["domains"]), 1)
        self.assertEqual(
            response.data["domains"][0]["name"], self.data_generator.domain.name
        )

class TestListTargetsWithoutOrganization(BaseTestCase):
    """Test case for listing targets without an organization."""

    def setUp(self):
        """Set up test environment."""
        # Use minimal setup to avoid auto-creating organization
        self.use_minimal_setup = True
        super().setUp()
        # Create a domain manually without associating it to an organization
        self.data_generator.create_project()
        self.data_generator.create_domain()

    def test_list_targets_without_organization(self):
        """Test listing targets that are not associated with any organization."""
        url = reverse("api:queryTargetsWithoutOrganization")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("domains", response.data)
        self.assertGreaterEqual(len(response.data["domains"]), 1)
        # Use the domain name that was actually created
        self.assertEqual(response.data["domains"][0]["name"], self.data_generator.domain.name)
