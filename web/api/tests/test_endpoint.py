"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status
from utils.test_base import BaseTestCase

__all__ = [
    'TestEndPointViewSet',
    'TestEndPointChangesViewSet',
    'TestInterestingEndpointViewSet'
]

class TestEndPointViewSet(BaseTestCase):
    """Test case for the EndPoint ViewSet API."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_endpoint()

    def test_list_endpoints(self):
        """Test listing endpoints."""
        api_url = reverse("api:endpoints-list")
        response = self.client.get(
            api_url,
            {
                "project": self.data_generator.project.slug,
                "scan_id": self.data_generator.scan_history.id,
                "subdomain_id": self.data_generator.subdomain.id,
                "target_id": self.data_generator.domain.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.data_generator.endpoint.http_url,
        )

    def test_list_endpoints_by_subdomain(self):
        """Test listing endpoints by subdomain."""
        api_url = reverse("api:endpoints-list")
        response = self.client.get(
            api_url,
            {
                "subdomain_id": self.data_generator.subdomain.id,
                "scan_id": self.data_generator.scan_history.id,
                "project": self.data_generator.project.slug,
                "target_id": self.data_generator.domain.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.data_generator.endpoint.http_url,
        )

class TestEndPointChangesViewSet(BaseTestCase):
    """Test case for endpoint changes viewset."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_endpoint()
        self.data_generator.create_scan_history()
        self.data_generator.create_endpoint(name="endpoint2")

    def test_endpoint_changes_viewset(self):
        """Test the EndPoint Changes ViewSet."""
        url = reverse("api:endpoint-changes-list")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id, "changes": "added"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.data_generator.endpoint.http_url,
        )
        self.assertEqual(response.data["results"][0]["change"], "added")

class TestInterestingEndpointViewSet(BaseTestCase):
    """Test case for interesting endpoint viewset."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_endpoint()

    def test_interesting_endpoint_viewset(self):
        """Test retrieving interesting endpoints for a scan."""
        url = reverse("api:interesting-endpoints-list")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.data_generator.endpoint.http_url,
        )

