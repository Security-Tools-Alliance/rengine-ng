"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status
from .test_base import BaseTestCase


class TestListOrganizations(BaseTestCase):
    """Test case for listing organizations."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_full()

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
        self.data_generator.create_project_full()

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
        super().setUp()
        self.data_generator.create_project_full()

    def test_list_targets_without_organization(self):
        """Test listing targets that are not associated with any organization."""
        url = reverse("api:queryTargetsWithoutOrganization")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("domains", response.data)
        self.assertGreaterEqual(len(response.data["domains"]), 1)
        self.assertEqual(response.data["domains"][0]["name"], "vulnweb.com")

