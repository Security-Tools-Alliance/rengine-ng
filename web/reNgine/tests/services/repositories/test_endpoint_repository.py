"""
Unit tests for EndpointRepository.
Tests the is_default logic for endpoints.
"""

from django.utils import timezone

from reNgine.services.repositories.endpoint_repository import EndpointRepository
from startScan.models import DirectoryScan, EndPoint, ScanHistory, Subdomain, SubScan
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

    def _save_secator_endpoint(self, url: str, **overrides):
        item = {"url": url, "status_code": 200} | overrides
        return self.repository.save_from_secator(item, self.scan_history.id, self.data_generator.domain.id)

    def test_first_endpoint_becomes_default(self):
        """Test that the first endpoint for a subdomain becomes is_default=True."""
        # Create first endpoint via Secator
        # Note: The URL hostname must match the subdomain name for association
        endpoint = self._save_secator_endpoint(
            "https://test.example.com/",
            title="Test Page",
            content_length=1000,
        )

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
        endpoint1 = self._save_secator_endpoint("https://test.example.com/", title="Test Page")
        endpoint1.refresh_from_db()

        # Verify first is default
        self.assertTrue(endpoint1.is_default)

        # Create second endpoint
        endpoint2 = self._save_secator_endpoint("https://test.example.com/api", title="API Page")
        endpoint2.refresh_from_db()

        # Assert second is NOT default
        self.assertFalse(endpoint2.is_default, "Second endpoint should not be marked as default")

        # Verify first is still default
        endpoint1.refresh_from_db()
        self.assertTrue(endpoint1.is_default, "First endpoint should remain default")

    def test_only_one_default_per_subdomain(self):
        """Test that only one endpoint can be default per subdomain when all share the same port."""
        # Create multiple endpoints (all port 443)
        urls = [
            "https://test.example.com/",
            "https://test.example.com/page1",
            "https://test.example.com/page2",
        ]

        endpoints = []
        for url in urls:
            endpoint = self._save_secator_endpoint(url)
            endpoint.refresh_from_db()
            endpoints.append(endpoint)

        # Count default endpoints for this subdomain
        default_count = EndPoint.objects.filter(subdomain=self.subdomain, is_default=True).count()

        self.assertEqual(default_count, 1, "Only one endpoint should be marked as default per subdomain (same port)")

        # Verify it's the first one
        self.assertTrue(endpoints[0].is_default)
        self.assertFalse(endpoints[1].is_default)
        self.assertFalse(endpoints[2].is_default)

    def test_first_per_port_gets_default(self):
        """Test that the first endpoint per (subdomain, port) becomes default; different ports each get one."""
        # First endpoint on port 443
        ep443_1 = self._save_secator_endpoint("https://test.example.com/")
        ep443_1.refresh_from_db()
        self.assertTrue(ep443_1.is_default)

        # First endpoint on port 80 (different port)
        ep80_1 = self._save_secator_endpoint("http://test.example.com/")
        ep80_1.refresh_from_db()
        self.assertTrue(ep80_1.is_default, "First endpoint on port 80 should be default")

        # Second endpoint on port 443 should not become default
        ep443_2 = self._save_secator_endpoint("https://test.example.com/api")
        ep443_2.refresh_from_db()
        self.assertFalse(ep443_2.is_default, "Second endpoint on port 443 should not override default")

        ep443_1.refresh_from_db()
        ep80_1.refresh_from_db()
        self.assertTrue(ep443_1.is_default)
        self.assertTrue(ep80_1.is_default)
        self.assertEqual(EndPoint.objects.filter(subdomain=self.subdomain, is_default=True).count(), 2)

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

    def test_subdomain_created_and_associated_when_missing(self):
        """Test that a missing subdomain is created and linked to the endpoint."""
        missing_hostname = "missing.example.com"
        self.assertFalse(
            Subdomain.objects.filter(name=missing_hostname, scan_history=self.scan_history).exists(),
            "Precondition failed: subdomain should not exist before creating endpoint",
        )

        endpoint = self._save_secator_endpoint(f"https://{missing_hostname}/", title="Missing Host")
        self.assertIsNotNone(endpoint, "Endpoint should be created")

        endpoint.refresh_from_db()
        self.assertIsNotNone(endpoint.subdomain, "Endpoint should be associated with a subdomain")
        if endpoint.subdomain:
            self.assertEqual(endpoint.subdomain.name, missing_hostname)
            self.assertEqual(endpoint.subdomain.scan_history, self.scan_history)

        created_subdomain = Subdomain.objects.get(name=missing_hostname, scan_history=self.scan_history)
        self.assertEqual(endpoint.subdomain_id, created_subdomain.id)

    def test_save_from_secator_directory_links_dir_subscan_ids(self):
        """When saving a directory URL from Secator with subscan_id, DirectoryScan and dir_subscan_ids are populated."""
        subscan = SubScan.objects.create(
            start_scan_date=timezone.now(),
            scan_history=self.scan_history,
            subdomain=self.subdomain,
            status=1,
        )
        item = {
            "url": "https://test.example.com/admin/",
            "status_code": 200,
            "is_directory": True,
            "content_length": 1024,
            "words": 50,
            "lines": 10,
            "content_type": "text/html",
        }
        rengine_context = {"subscan_id": subscan.id}

        result = self.repository.save_from_secator(
            item,
            self.scan_history.id,
            self.data_generator.domain.id,
            rengine_context=rengine_context,
        )

        self.assertIsNotNone(result)
        self.assertTrue(result.is_directory)

        dir_scans = DirectoryScan.objects.filter(dir_subscan_ids=subscan)
        self.assertEqual(dir_scans.count(), 1)
        directory_scan = dir_scans.first()
        self.assertIn(subscan, directory_scan.dir_subscan_ids.all())
        self.assertEqual(directory_scan.directory_files.count(), 1)
        directory_file = directory_scan.directory_files.first()
        self.assertEqual(directory_file.url, "https://test.example.com/admin/")
        self.assertEqual(directory_file.http_status, 200)
        self.assertEqual(directory_file.name, "admin")

        self.subdomain.refresh_from_db()
        self.assertIn(directory_scan, self.subdomain.directories.all())
