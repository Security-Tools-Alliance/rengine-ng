"""
Tests for DatabaseHooks filtering functionality.
"""

from unittest.mock import patch

from django.utils import timezone

from reNgine.definitions import RUNNING_TASK
from reNgine.secator.hooks.database_hooks import DatabaseHooks
from scanEngine.models import EngineType
from startScan.models import Domain, ScanHistory
from utils.test_base import BaseTestCase


class TestDatabaseHooksFiltering(BaseTestCase):
    """Test DatabaseHooks filtering functionality."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create test domain and scan
        self.domain = Domain.objects.create(name="example.com")

        # Create engine type for scan history
        self.engine_type = EngineType.objects.create(
            engine_name="Test Engine",
            yaml_configuration="{}",
            default_engine=True,
        )

        # Create a Secator scan (all new scans are Secator, scan_type=None)
        self.scan_history = ScanHistory.objects.create(
            domain=self.domain, scan_status=RUNNING_TASK, start_scan_date=timezone.now(), is_legacy_scan=False
        )

        # Create hooks instance
        self.hooks = DatabaseHooks(
            scan_history_id=self.scan_history.id,
            domain_id=self.domain.id,
            rengine_context={
                "out_of_scope_subdomains": ["out.example.com", "excluded.example.com"],
                "url_filter": "admin|login|api",
                "scan_existing_elements": False,
            },
        )

    def test_should_filter_item_out_of_scope_subdomain(self):
        """Test filtering out-of-scope subdomains."""
        # Test out-of-scope subdomain
        out_of_scope_item = {
            "_type": "subdomain",
            "target": "out.example.com",
            "host": "out.example.com",
        }

        result = self.hooks._should_filter_item(out_of_scope_item)
        self.assertTrue(result, "Out-of-scope subdomain should be filtered")

    def test_should_filter_item_url_filter(self):
        """Test filtering URLs based on url_filter."""
        # Test URL that matches filter
        filtered_url_item = {
            "_type": "url",
            "target": "https://example.com/admin",
            "url": "https://example.com/admin",
        }

        result = self.hooks._should_filter_item(filtered_url_item)
        self.assertTrue(result, "URL matching filter should be filtered")

    def test_should_not_filter_valid_subdomain(self):
        """Test that valid subdomains are not filtered."""
        # Test valid subdomain
        valid_subdomain_item = {
            "_type": "subdomain",
            "target": "www.example.com",
            "host": "www.example.com",
        }

        result = self.hooks._should_filter_item(valid_subdomain_item)
        self.assertFalse(result, "Valid subdomain should not be filtered")

    def test_should_not_filter_valid_url(self):
        """Test that valid URLs are not filtered."""
        # Test valid URL
        valid_url_item = {
            "_type": "url",
            "target": "https://example.com/page",
            "url": "https://example.com/page",
        }

        result = self.hooks._should_filter_item(valid_url_item)
        self.assertFalse(result, "Valid URL should not be filtered")

    def test_should_not_filter_non_subdomain_url_items(self):
        """Test that non-subdomain/URL items are not filtered."""
        # Test IP item
        ip_item = {
            "_type": "ip",
            "target": "192.168.1.1",
            "ip": "192.168.1.1",
        }

        result = self.hooks._should_filter_item(ip_item)
        self.assertFalse(result, "IP items should not be filtered")

        # Test port item
        port_item = {
            "_type": "port",
            "target": "192.168.1.1:80",
            "port": 80,
        }

        result = self.hooks._should_filter_item(port_item)
        self.assertFalse(result, "Port items should not be filtered")

    def test_should_filter_item_case_insensitive(self):
        """Test that filtering is case insensitive."""
        # Test case insensitive out-of-scope
        out_of_scope_item = {
            "_type": "subdomain",
            "target": "OUT.EXAMPLE.COM",
            "host": "OUT.EXAMPLE.COM",
        }

        result = self.hooks._should_filter_item(out_of_scope_item)
        self.assertTrue(result, "Case insensitive out-of-scope should be filtered")

        # Test case insensitive URL filter
        filtered_url_item = {
            "_type": "url",
            "target": "https://example.com/ADMIN",
            "url": "https://example.com/ADMIN",
        }

        result = self.hooks._should_filter_item(filtered_url_item)
        self.assertTrue(result, "Case insensitive URL filter should work")

    def test_should_filter_item_multiple_patterns(self):
        """Test filtering with multiple patterns."""
        # Test URL matching multiple patterns
        filtered_url_item = {
            "_type": "url",
            "target": "https://example.com/api/login",
            "url": "https://example.com/api/login",
        }

        result = self.hooks._should_filter_item(filtered_url_item)
        self.assertTrue(result, "URL matching multiple patterns should be filtered")

    def test_should_filter_item_empty_context(self):
        """Test filtering with empty context."""
        hooks_empty = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id, rengine_context={})

        # Test that items are not filtered with empty context
        subdomain_item = {
            "_type": "subdomain",
            "target": "any.example.com",
            "host": "any.example.com",
        }

        result = hooks_empty._should_filter_item(subdomain_item)
        self.assertFalse(result, "Items should not be filtered with empty context")

    def test_should_filter_item_none_context(self):
        """Test filtering with None context."""
        hooks_none = DatabaseHooks(scan_history_id=self.scan_history.id, domain_id=self.domain.id, rengine_context=None)

        # Test that items are not filtered with None context
        subdomain_item = {
            "_type": "subdomain",
            "target": "any.example.com",
            "host": "any.example.com",
        }

        result = hooks_none._should_filter_item(subdomain_item)
        self.assertFalse(result, "Items should not be filtered with None context")

    def test_on_item_filtering_integration(self):
        """Test on_item method with filtering."""
        # Mock the repository methods
        with patch.object(self.hooks.subdomain_repo, "save_from_secator") as mock_save:
            # Test that filtered items are not saved
            out_of_scope_item = {
                "_type": "subdomain",
                "target": "out.example.com",
                "host": "out.example.com",
            }

            result = self.hooks.on_item(out_of_scope_item)

            # Should return the item but not save it
            self.assertEqual(result, out_of_scope_item)
            mock_save.assert_not_called()

    def test_on_item_saving_integration(self):
        """Test on_item method with saving."""
        # Mock the repository methods
        with patch.object(self.hooks.subdomain_repo, "save_from_secator") as mock_save:
            # Test that valid items are saved
            valid_subdomain_item = {
                "_type": "subdomain",
                "target": "www.example.com",
                "host": "www.example.com",
            }

            result = self.hooks.on_item(valid_subdomain_item)

            # Should return the item and save it
            self.assertEqual(result, valid_subdomain_item)
            mock_save.assert_called_once_with(
                valid_subdomain_item, self.scan_history.id, self.domain.id, rengine_context=self.hooks.rengine_context
            )
