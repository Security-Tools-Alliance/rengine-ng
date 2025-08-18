"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status
from utils.test_base import BaseTestCase

__all__ = [
    'TestListDorkTypes',
    'TestListEmails',
    'TestListDorks',
    'TestListEmployees',
    'TestListOsintUsers',
    'TestListMetadata'
]

class TestListDorkTypes(BaseTestCase):
    """Test case for listing dork types."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_dork_types(self):
        """Test listing dork types for a scan."""
        url = reverse("api:queryDorkTypes")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("dorks", response.data)
        self.assertGreaterEqual(len(response.data["dorks"]), 1)
        self.assertEqual(
            response.data["dorks"][0]["type"], self.data_generator.dork.type
        )

class TestListEmails(BaseTestCase):
    """Test case for listing emails."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_emails(self):
        """Test listing emails for a scan."""
        url = reverse("api:queryEmails")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("emails", response.data)
        self.assertGreaterEqual(len(response.data["emails"]), 1)
        self.assertEqual(
            response.data["emails"][0]["address"], self.data_generator.email.address
        )

class TestListDorks(BaseTestCase):
    """Test case for listing dorks."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_dorks(self):
        """Test listing dorks for a scan."""
        url = reverse("api:queryDorks")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("dorks", response.data)
        self.assertIn("Test Dork", response.data["dorks"])
        self.assertGreaterEqual(len(response.data["dorks"]["Test Dork"]), 1)
        self.assertEqual(
            response.data["dorks"]["Test Dork"][0]["type"],
            self.data_generator.dork.type,
        )

class TestListEmployees(BaseTestCase):
    """Test case for listing employees."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_employees(self):
        """Test listing employees for a scan."""
        url = reverse("api:queryEmployees")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("employees", response.data)
        self.assertGreaterEqual(len(response.data["employees"]), 1)
        self.assertEqual(
            response.data["employees"][0]["name"], self.data_generator.employee.name
        )

class TestListOsintUsers(BaseTestCase):
    """Test case for listing OSINT users."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_metafinder_document()

    def test_list_osint_users(self):
        """Test listing OSINT users for a scan."""
        url = reverse("api:queryMetadata")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("metadata", response.data)
        self.assertGreaterEqual(len(response.data["metadata"]), 1)
        self.assertEqual(
            response.data["metadata"][0]["author"],
            self.data_generator.metafinder_document.author,
        )

class TestListMetadata(BaseTestCase):
    """Test case for listing metadata."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_metafinder_document()

    def test_list_metadata(self):
        """Test listing metadata for a scan."""
        url = reverse("api:queryMetadata")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("metadata", response.data)
        self.assertGreaterEqual(len(response.data["metadata"]), 1)
        self.assertEqual(
            response.data["metadata"][0]["doc_name"],
            self.data_generator.metafinder_document.doc_name,
        )
        self.assertEqual(
            response.data["metadata"][0]["url"],
            self.data_generator.metafinder_document.url,
        )
        self.assertEqual(
            response.data["metadata"][0]["title"],
            self.data_generator.metafinder_document.title,
        )
