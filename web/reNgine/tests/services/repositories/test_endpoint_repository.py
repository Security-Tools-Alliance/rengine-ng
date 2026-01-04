"""
Unit tests for EndpointRepository.
Tests the is_default logic for endpoints.
"""

from reNgine.services.repositories.endpoint_repository import EndpointRepository
from startScan.models import EndPoint, ScanHistory, Subdomain
from utils.test_base import BaseTestCase


class EndpointRepositoryIsDefaultTestCase(BaseTestCase):
    """Test cases for is_default endpoint logic."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.repository = EndpointRepository()

        # Use the data_generator from BaseTestCase which already has domain, engine_type, etc.
        # Create a Secator scan (is_legacy_scan=False, scan_type=None)
        self.scan_history = ScanHistory.objects.create(
            domain=self.data_generator.domain,
            start_scan_date=self.data_generator.scan_history.start_scan_date,
            is_legacy_scan=False,
        )

        # Create a subdomain
        self.subdomain = Subdomain.objects.create(
            name="test.example.com",
            scan_history=self.scan_history,
            target_domain=self.data_generator.domain,
        )

    def test_first_endpoint_becomes_default(self):
        """Test that the first endpoint for a subdomain becomes is_default=True."""
        # Create first endpoint via Secator
        # Note: The URL hostname must match the subdomain name for association
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "title": "Test Page",
            "content_length": 1000,
        }

        endpoint = self.repository.save_from_secator(item, self.scan_history.id, self.data_generator.domain.id)

        self.assertIsNotNone(endpoint, "Endpoint should be created")

        # Refresh from database
        endpoint.refresh_from_db()

        # Assert it's marked as default
        self.assertTrue(endpoint.is_default, "First endpoint should be marked as default")
        self.assertIsNotNone(endpoint.subdomain, "Endpoint should be associated with subdomain")
        if endpoint.subdomain:
            self.assertEqual(endpoint.subdomain.name, "test.example.com")

    def test_second_endpoint_not_default(self):
        """Test that a second endpoint does not become default if one already exists."""
        # Create first endpoint
        item1 = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "title": "Test Page",
        }
        endpoint1 = self.repository.save_from_secator(item1, self.scan_history.id, self.data_generator.domain.id)
        endpoint1.refresh_from_db()

        # Verify first is default
        self.assertTrue(endpoint1.is_default)

        # Create second endpoint
        item2 = {
            "url": "https://test.example.com/api",
            "status_code": 200,
            "title": "API Page",
        }
        endpoint2 = self.repository.save_from_secator(item2, self.scan_history.id, self.data_generator.domain.id)
        endpoint2.refresh_from_db()

        # Assert second is NOT default
        self.assertFalse(endpoint2.is_default, "Second endpoint should not be marked as default")

        # Verify first is still default
        endpoint1.refresh_from_db()
        self.assertTrue(endpoint1.is_default, "First endpoint should remain default")

    def test_only_one_default_per_subdomain(self):
        """Test that only one endpoint can be default per subdomain."""
        # Create multiple endpoints
        urls = [
            "https://test.example.com/",
            "https://test.example.com/page1",
            "https://test.example.com/page2",
        ]

        endpoints = []
        for url in urls:
            item = {
                "url": url,
                "status_code": 200,
            }
            endpoint = self.repository.save_from_secator(item, self.scan_history.id, self.data_generator.domain.id)
            endpoint.refresh_from_db()
            endpoints.append(endpoint)

        # Count default endpoints for this subdomain
        default_count = EndPoint.objects.filter(subdomain=self.subdomain, is_default=True).count()

        self.assertEqual(default_count, 1, "Only one endpoint should be marked as default per subdomain")

        # Verify it's the first one
        self.assertTrue(endpoints[0].is_default)
        self.assertFalse(endpoints[1].is_default)
        self.assertFalse(endpoints[2].is_default)

    def test_process_secator_endpoint_item_valid(self):
        """Test _process_secator_endpoint_item with valid data."""
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "title": "Test Page",
            "content_length": 1000,
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.domain.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.http_url, "https://test.example.com/")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.page_title, "Test Page")
        self.assertEqual(result.content_length, 1000)

    def test_process_secator_endpoint_item_missing_url(self):
        """Test _process_secator_endpoint_item with missing URL."""
        item = {
            "status_code": 200,
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.domain.id
        )

        self.assertIsNone(result)

    def test_process_secator_endpoint_item_invalid_url(self):
        """Test _process_secator_endpoint_item with invalid URL."""
        item = {
            "url": "not-a-valid-url",
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.domain.id
        )

        self.assertIsNone(result)

    def test_process_secator_endpoint_item_with_response_time_ms(self):
        """Test _process_secator_endpoint_item with response time in milliseconds."""
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "time": "1500ms",
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.domain.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.response_time, 1.5)  # 1500ms = 1.5s

    def test_process_secator_endpoint_item_with_response_time_seconds(self):
        """Test _process_secator_endpoint_item with response time in seconds."""
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "time": 1.5,
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.domain.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.response_time, 1.5)

    def test_create_endpoints_in_bulk_valid(self):
        """Test _create_endpoints_in_bulk with valid data."""
        endpoints_data = [
            {
                "http_url": "https://test.example.com/page1",
                "http_status": 200,
                "page_title": "Page 1",
            },
            {
                "http_url": "https://test.example.com/page2",
                "http_status": 404,
                "page_title": "Page 2",
            },
        ]

        result = self.repository._create_endpoints_in_bulk(
            self.scan_history.id, self.data_generator.domain.id, endpoints_data
        )

        self.assertEqual(len(result), 2)
        created_urls = [ep.http_url for ep in result]
        self.assertIn("https://test.example.com/page1", created_urls)
        self.assertIn("https://test.example.com/page2", created_urls)

    def test_create_endpoints_in_bulk_empty_list(self):
        """Test _create_endpoints_in_bulk with empty list."""
        result = self.repository._create_endpoints_in_bulk(self.scan_history.id, self.data_generator.domain.id, [])

        self.assertEqual(result, [])

    def test_create_endpoints_in_bulk_invalid_urls(self):
        """Test _create_endpoints_in_bulk with invalid URLs."""
        endpoints_data = [
            {"http_url": "not-a-valid-url", "http_status": 200},
            {"http_url": "also-invalid", "http_status": 200},
        ]

        result = self.repository._create_endpoints_in_bulk(
            self.scan_history.id, self.data_generator.domain.id, endpoints_data
        )

        self.assertEqual(result, [])

    def test_process_secator_endpoint_item_with_secator_fields(self):
        """Test _process_secator_endpoint_item with new Secator fields."""
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "is_directory": True,
            "stored_response_path": "/path/to/response.json",
            "confidence": "high",
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.domain.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.is_directory, True)
        self.assertEqual(result.stored_response_path, "/path/to/response.json")
        self.assertEqual(result.confidence, "high")
