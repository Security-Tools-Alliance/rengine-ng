"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status
from startScan.models import Subdomain
from utils.test_base import BaseTestCase

__all__ = [
    'TestQueryInterestingSubdomains',
    'TestDeleteSubdomain',
    'TestListSubdomains',
    'TestSubdomainsViewSet',
    'TestSubdomainChangesViewSet',
    'TestToggleSubdomainImportantStatus',
    'TestSubdomainDatatableViewSet',
    'TestInterestingSubdomainViewSet'
]

class TestQueryInterestingSubdomains(BaseTestCase):
    """Tests for querying interesting subdomains."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_interesting_lookup_model()

    def test_query_interesting_subdomains(self):
        """Test querying interesting subdomains for a given sca
        n."""
        api_url = reverse("api:queryInterestingSubdomains")
        response = self.client.get(
            api_url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("admin.example.com", [sub["name"] for sub in response.data])

class TestDeleteSubdomain(BaseTestCase):
    """Tests for deleting subdomains."""

    def setUp(self):
        super().setUp()

    def test_delete_subdomain(self):
        """Test deleting a subdomain."""
        api_url = reverse("api:delete_subdomain")
        data = {"subdomain_ids": [str(self.data_generator.subdomain.id)]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertFalse(
            Subdomain.objects.filter(id=self.data_generator.subdomain.id).exists()
        )

    def test_delete_nonexistent_subdomain(self):
        """Test deleting a non-existent subdomain."""
        api_url = reverse("api:delete_subdomain")
        data = {"subdomain_ids": ["nonexistent_id"]}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class TestListSubdomains(BaseTestCase):
    """Test case for listing subdomains."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_subdomains(self):
        """Test listing subdomains for a target."""
        url = reverse("api:querySubdomains")
        response = self.client.get(url, {"target_id": self.data_generator.domain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("subdomains", response.data)
        self.assertGreaterEqual(len(response.data["subdomains"]), 1)
        self.assertEqual(
            response.data["subdomains"][0]["name"], self.data_generator.subdomain.name
        )

class TestSubdomainsViewSet(BaseTestCase):
    """Test case for subdomains viewset."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_subdomains_viewset(self):
        """Test retrieving subdomains for a scan."""
        url = reverse("api:subdomains-list")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.subdomain.name
        )

class TestSubdomainChangesViewSet(BaseTestCase):
    """Test case for subdomain changes viewset."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain("admin1.example.com")

    def test_subdomain_changes_viewset(self):
        """Test retrieving subdomain changes for a scan."""
        url = reverse("api:subdomain-changes-list")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id, "changes": "added"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.subdomain.name
        )
        self.assertEqual(response.data["results"][0]["change"], "added")

class TestToggleSubdomainImportantStatus(BaseTestCase):
    """Test case for toggling subdomain important status."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_toggle_subdomain_important_status(self):
        """Test toggling the important status of a subdomain."""
        api_url = reverse("api:toggle_subdomain")
        initial_status = self.data_generator.subdomain.is_important
        response = self.client.post(
            api_url, {"subdomain_id": self.data_generator.subdomain.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.data_generator.subdomain.refresh_from_db()
        self.assertNotEqual(initial_status, self.data_generator.subdomain.is_important)

class TestSubdomainDatatableViewSet(BaseTestCase):
    """Tests for the Subdomain Datatable ViewSet API."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_subdomains(self):
        """Test listing subdomains."""
        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url, {"project": self.data_generator.project.slug}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.subdomain.name
        )

    def test_list_subdomains_by_domain(self):
        """Test listing subdomains by domain."""
        api_url = reverse("api:subdomain-datatable-list")
        response = self.client.get(
            api_url,
            {
                "target_id": self.data_generator.domain.id,
                "project": self.data_generator.project.slug,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.subdomain.name
        )

class TestInterestingSubdomainViewSet(BaseTestCase):
    """Test case for the Interesting Subdomain ViewSet API."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_interesting_lookup_model()

    def test_list_interesting_subdomains(self):
        """Test listing interesting subdomains."""
        api_url = reverse("api:interesting-subdomains-list")
        response = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "scan_id": self.data_generator.scan_history.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.subdomain.name
        )

    def test_list_interesting_subdomains_by_domain(self):
        """Test listing interesting subdomains by domain."""
        api_url = reverse("api:interesting-subdomains-list")
        response = self.client.get(
            api_url,
            {
                "target_id": self.data_generator.domain.id,
                "project": self.data_generator.project.slug,
                "scan_id": self.data_generator.scan_history.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.subdomain.name
        )
