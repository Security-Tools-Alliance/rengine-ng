"""
Unit tests for Subdomain display properties.
Tests that display_* properties return correct values for Secator vs legacy scans.
"""

from reNgine.services.repositories.endpoint_repository import EndpointRepository
from startScan.models import ScanHistory, Subdomain
from utils.test_base import BaseTestCase


class SubdomainDisplayPropertiesTestCase(BaseTestCase):
    """Test cases for Subdomain display_* properties."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.repository = EndpointRepository()

        # Use the data_generator from BaseTestCase which already has domain, engine_type, etc.
        # Create a Secator scan (scan_type=None for Secator scans)
        self.secator_scan = ScanHistory.objects.create(
            domain=self.data_generator.domain,
            start_scan_date=self.data_generator.scan_history.start_scan_date,
            is_legacy_scan=False,
        )

        # Create a legacy scan
        self.legacy_scan = ScanHistory.objects.create(
            domain=self.data_generator.domain,
            scan_type=self.data_generator.engine_type,
            start_scan_date=self.data_generator.scan_history.start_scan_date,
            is_legacy_scan=True,
        )

        # Create subdomains
        self.secator_subdomain = Subdomain.objects.create(
            name="secator.example.com",
            scan_history=self.secator_scan,
            target_domain=self.data_generator.domain,
            http_status=404,
            page_title="Subdomain Title",
            content_length=500,
            response_time=0.5,
        )

        self.legacy_subdomain = Subdomain.objects.create(
            name="legacy.example.com",
            scan_history=self.legacy_scan,
            target_domain=self.data_generator.domain,
            http_status=404,
            page_title="Subdomain Title",
            content_length=500,
            response_time=0.5,
        )

    def test_secator_scan_uses_default_endpoint_values(self):
        """Test that Secator scans use default endpoint values."""
        # Create default endpoint for Secator subdomain
        item = {
            "url": "https://secator.example.com/",
            "status_code": 200,
            "title": "Endpoint Title",
            "content_length": 1000,
            "time": 1.5,
        }

        endpoint = self.repository.save_from_secator(item, self.secator_scan.id, self.data_generator.domain.id)
        endpoint.refresh_from_db()

        # Verify endpoint is default
        self.assertTrue(endpoint.is_default)

        # Refresh subdomain
        self.secator_subdomain.refresh_from_db()

        # Check display properties return endpoint values
        self.assertEqual(
            self.secator_subdomain.display_http_status,
            200,
            "Should return endpoint http_status for Secator scan",
        )
        self.assertEqual(
            self.secator_subdomain.display_page_title,
            "Endpoint Title",
            "Should return endpoint page_title for Secator scan",
        )
        self.assertEqual(
            self.secator_subdomain.display_content_length,
            1000,
            "Should return endpoint content_length for Secator scan",
        )
        self.assertEqual(
            self.secator_subdomain.display_response_time,
            1.5,
            "Should return endpoint response_time for Secator scan",
        )

    def test_legacy_scan_uses_subdomain_values(self):
        """Test that legacy scans use subdomain values."""
        # Create endpoint for legacy subdomain (should not affect display)
        item = {
            "url": "https://legacy.example.com/",
            "status_code": 200,
            "title": "Endpoint Title",
        }

        endpoint = self.repository.save_from_secator(item, self.legacy_scan.id, self.data_generator.domain.id)
        endpoint.refresh_from_db()

        # Refresh subdomain
        self.legacy_subdomain.refresh_from_db()

        # Check display properties return subdomain values (not endpoint)
        self.assertEqual(
            self.legacy_subdomain.display_http_status,
            404,
            "Should return subdomain http_status for legacy scan",
        )
        self.assertEqual(
            self.legacy_subdomain.display_page_title,
            "Subdomain Title",
            "Should return subdomain page_title for legacy scan",
        )
        self.assertEqual(
            self.legacy_subdomain.display_content_length,
            500,
            "Should return subdomain content_length for legacy scan",
        )
        self.assertEqual(
            self.legacy_subdomain.display_response_time,
            0.5,
            "Should return subdomain response_time for legacy scan",
        )

    def test_secator_scan_without_default_endpoint_uses_subdomain_values(self):
        """Test that Secator scans without default endpoint fall back to subdomain values."""
        # Don't create any endpoint

        # Refresh subdomain
        self.secator_subdomain.refresh_from_db()

        # Check display properties return subdomain values (no default endpoint)
        self.assertEqual(
            self.secator_subdomain.display_http_status,
            404,
            "Should return subdomain http_status when no default endpoint",
        )
        self.assertEqual(
            self.secator_subdomain.display_page_title,
            "Subdomain Title",
            "Should return subdomain page_title when no default endpoint",
        )
