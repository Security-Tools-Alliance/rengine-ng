"""
This file contains the test cases for the API views.
"""

from django.urls import reverse
from rest_framework import status
from utils.test_base import BaseTestCase

__all__ = [
    'TestSearchHistoryView',
    'TestUniversalSearch'
]

class TestSearchHistoryView(BaseTestCase):
    """Tests for the Search History API."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_search_history()

    def test_get_search_history(self):
        """Test retrieving search history."""
        api_url = reverse("api:search_history")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["query"],
            self.data_generator.search_history.query,
        )

class TestUniversalSearch(BaseTestCase):
    """Test case for the Universal Search API."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_endpoint()
        self.data_generator.create_vulnerability()

    def test_universal_search(self):
        """Test the universal search functionality."""
        api_url = reverse("api:search")
        response = self.client.get(api_url, {"query": "admin"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn(
            "admin.example.com",
            [sub["name"] for sub in response.data["results"]["subdomains"]],
        )
        self.assertIn(
            "https://admin.example.com/endpoint",
            [ep["http_url"] for ep in response.data["results"]["endpoints"]],
        )

    def test_universal_search_no_query(self):
        """Test the universal search with no query parameter."""
        api_url = reverse("api:search")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])
        self.assertEqual(response.data["message"], "No query parameter provided!")

    def test_universal_search_with_special_characters(self):  
        """Test the universal search functionality with special characters."""
        api_url = reverse("api:search")
        special_query = "admin'; DROP TABLE users;--"
        response = self.client.get(api_url, {"query": special_query})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])
        self.assertNotIn("users", response.data["results"])
