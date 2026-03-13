"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status

from reNgine.utilities.endpoint import get_interesting_endpoints
from utils.test_base import BaseTestCase


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
                "target_id": self.data_generator.target.id,
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
                "target_id": self.data_generator.target.id,
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
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id, "changes": "added"})
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
        self.data_generator.create_interesting_lookup_model()
        self.data_generator.create_endpoint()

    def test_interesting_endpoint_viewset(self):
        """Test retrieving interesting endpoints for a scan."""
        url = reverse("api:interesting-endpoints-list")
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.data_generator.endpoint.http_url,
        )

    def test_interesting_endpoint_viewset_by_target_id(self):
        """Test retrieving interesting endpoints filtered by target_id (target summary context)."""
        url = reverse("api:interesting-endpoints-list")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "target_id": self.data_generator.target.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["http_url"],
            self.data_generator.endpoint.http_url,
        )

    def test_interesting_endpoint_viewset_datatables_format(self):
        """Test that list with start/length returns DataTables server-side format."""
        url = reverse("api:interesting-endpoints-list")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "scan_id": self.data_generator.scan_history.id,
                "start": "0",
                "length": "10",
                "draw": "1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("recordsTotal", response.data)
        self.assertIn("recordsFiltered", response.data)
        self.assertIn("data", response.data)
        self.assertIn("draw", response.data)
        self.assertIsInstance(response.data["data"], list)
        self.assertGreaterEqual(response.data["recordsTotal"], 1)
        self.assertGreaterEqual(len(response.data["data"]), 1)
        self.assertEqual(
            response.data["data"][0]["http_url"],
            self.data_generator.endpoint.http_url,
        )

    def test_interesting_endpoint_viewset_no_scope_returns_empty(self):
        """Test that list without scan_id or target_id returns empty results (no ValueError)."""
        url = reverse("api:interesting-endpoints-list")
        response = self.client.get(url, {"project": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), 0)


class TestGetInterestingEndpointsUtility(BaseTestCase):
    """Test get_interesting_endpoints validation (exactly one of scan_history, target_id, target)."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_interesting_lookup_model()
        self.data_generator.create_endpoint()

    def test_raises_when_no_filter_provided(self):
        """Calling with no args raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            get_interesting_endpoints()
        self.assertIn("exactly one", str(ctx.exception))

    def test_raises_when_multiple_filters_provided(self):
        """Calling with scan_history and target_id raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            get_interesting_endpoints(
                scan_history=self.data_generator.scan_history.id,
                target_id=self.data_generator.target.id,
            )
        self.assertIn("multiple filters", str(ctx.exception))

    def test_raises_when_scan_history_and_target_provided(self):
        """Calling with scan_history and target (legacy) raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            get_interesting_endpoints(
                scan_history=self.data_generator.scan_history.id,
                target=self.data_generator.domain.id,
            )
        self.assertIn("multiple filters", str(ctx.exception))
