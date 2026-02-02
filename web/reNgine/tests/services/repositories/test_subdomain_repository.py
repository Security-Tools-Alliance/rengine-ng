"""
Tests for Subdomain repository functionality.
"""

from django.utils import timezone

from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from startScan.models import Subdomain, SubScan
from utils.test_base import BaseTestCase


class TestSubdomainRepository(BaseTestCase):
    """Test cases for SubdomainRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.subdomain_repo = SubdomainRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def test_save_from_secator_valid_subdomain(self):
        """Test saving valid subdomain from Secator."""
        item = {
            "_type": "subdomain",
            "host": "test.example.com",
            "verified": True,
            "sources": ["subfinder", "amass"],
        }

        result = self.subdomain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "test.example.com")
        self.assertTrue(result.verified)
        self.assertEqual(result.sources, ["subfinder", "amass"])

    def test_save_from_secator_missing_name(self):
        """Test handling missing subdomain name."""
        item = {
            "_type": "subdomain",
            "verified": True,
        }

        result = self.subdomain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_invalid_domain(self):
        """Test handling invalid subdomain name."""
        item = {
            "_type": "subdomain",
            "host": "invalid..domain..name",
        }

        result = self.subdomain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_with_extra_data(self):
        """Test saving subdomain with extra_data mapping."""
        item = {
            "_type": "subdomain",
            "host": "test.example.com",
            "extra_data": {
                "http_url": "https://test.example.com",
                "http_status": 200,
                "page_title": "Test Page",
                "content_length": 1000,
                "webserver": "nginx",
                "response_time": 0.5,
            },
        }

        result = self.subdomain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.http_url, "https://test.example.com")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.page_title, "Test Page")
        self.assertEqual(result.content_length, 1000)
        self.assertEqual(result.webserver, "nginx")
        self.assertEqual(result.response_time, 0.5)

    def test_save_from_secator_with_imported_flag(self):
        """Test saving subdomain with imported flag from context."""
        rengine_context = {
            "imported_subdomains": ["test.example.com", "other.example.com"],
        }

        item = {
            "_type": "subdomain",
            "host": "test.example.com",
        }

        result = self.subdomain_repo.save_from_secator(
            item, self.scan_history.id, self.domain.id, rengine_context=rengine_context
        )

        self.assertIsNotNone(result)
        self.assertTrue(result.is_imported_subdomain)

    def test_save_from_secator_without_imported_flag(self):
        """Test saving subdomain without imported flag."""
        item = {
            "_type": "subdomain",
            "host": "test.example.com",
        }

        result = self.subdomain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertFalse(result.is_imported_subdomain)

    def test_save_from_secator_with_subscan_id_links_subdomain_subscan_ids(self):
        """When saving subdomain from Secator with subscan_id, subdomain is added to subscan.subdomain_subscan_ids."""
        existing_subdomain = Subdomain.objects.create(
            name="existing.example.com",
            scan_history=self.scan_history,
            target_domain=self.domain,
        )
        subscan = SubScan.objects.create(
            start_scan_date=timezone.now(),
            scan_history=self.scan_history,
            subdomain=existing_subdomain,
            status=1,
        )
        rengine_context = {"subscan_id": subscan.id}
        item = {"_type": "subdomain", "host": "subscan-link.example.com"}

        result = self.subdomain_repo.save_from_secator(
            item, self.scan_history.id, self.domain.id, rengine_context=rengine_context
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "subscan-link.example.com")
        subscan.refresh_from_db()
        self.assertIn(result, subscan.subdomain_subscan_ids.all())

    def test_map_extra_data_to_subdomain_fields(self):
        """Test _map_extra_data_to_subdomain_fields method."""
        extra_data = {
            "http_url": "https://test.example.com",
            "http_status": 200,
            "content_type": "text/html",
            "content_length": 1000,
            "page_title": "Test Page",
            "webserver": "nginx",
            "response_time": 0.5,
        }

        defaults = {}
        self.subdomain_repo._map_extra_data_to_subdomain_fields(extra_data, defaults)

        self.assertEqual(defaults["http_url"], "https://test.example.com")
        self.assertEqual(defaults["http_status"], 200)
        self.assertEqual(defaults["content_type"], "text/html")
        self.assertEqual(defaults["content_length"], 1000)
        self.assertEqual(defaults["page_title"], "Test Page")
        self.assertEqual(defaults["webserver"], "nginx")
        self.assertEqual(defaults["response_time"], 0.5)

    def test_map_extra_data_to_subdomain_fields_partial(self):
        """Test _map_extra_data_to_subdomain_fields with partial data."""
        extra_data = {
            "http_url": "https://test.example.com",
            "http_status": 200,
        }

        defaults = {}
        self.subdomain_repo._map_extra_data_to_subdomain_fields(extra_data, defaults)

        self.assertEqual(defaults["http_url"], "https://test.example.com")
        self.assertEqual(defaults["http_status"], 200)
        self.assertNotIn("page_title", defaults)

    def test_map_extra_data_to_subdomain_fields_empty(self):
        """Test _map_extra_data_to_subdomain_fields with empty data."""
        extra_data = {}

        defaults = {}
        self.subdomain_repo._map_extra_data_to_subdomain_fields(extra_data, defaults)

        self.assertEqual(defaults, {})

    def test_map_extra_data_to_subdomain_fields_new_fields(self):
        """Test _map_extra_data_to_subdomain_fields with new fields (cname, is_cdn, cdn_name, http_header_path)."""
        extra_data = {
            "cname": "cdn.example.com",
            "is_cdn": True,
            "cdn_name": "Cloudflare",
            "http_header_path": "/path/to/headers.json",
        }

        defaults = {}
        self.subdomain_repo._map_extra_data_to_subdomain_fields(extra_data, defaults)

        self.assertEqual(defaults["cname"], "cdn.example.com")
        self.assertEqual(defaults["is_cdn"], True)
        self.assertEqual(defaults["cdn_name"], "Cloudflare")
        self.assertEqual(defaults["http_header_path"], "/path/to/headers.json")

    def test_process_secator_subdomain_item_valid(self):
        """Test _process_secator_subdomain_item with valid data."""
        item = {
            "host": "test.example.com",
            "verified": True,
            "sources": ["subfinder"],
        }

        result = self.subdomain_repo._process_secator_subdomain_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "test.example.com")
        self.assertTrue(result.verified)

    def test_process_secator_subdomain_item_missing_name(self):
        """Test _process_secator_subdomain_item with missing name."""
        item = {
            "verified": True,
        }

        result = self.subdomain_repo._process_secator_subdomain_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_process_secator_subdomain_item_invalid_domain(self):
        """Test _process_secator_subdomain_item with invalid domain."""
        item = {
            "host": "invalid..domain",
        }

        result = self.subdomain_repo._process_secator_subdomain_item(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_bulk_create_subdomains(self):
        """Test bulk creation of subdomains."""
        subdomain_names = ["test1.example.com", "test2.example.com", "test3.example.com"]

        result = self.subdomain_repo.bulk_create(subdomain_names, self.scan_history.id, self.domain.id)

        self.assertEqual(len(result), 3)
        created_names = [sub.name for sub in result]
        for name in subdomain_names:
            self.assertIn(name, created_names)

    def test_bulk_create_mixed_subdomains(self):
        """Test bulk creation with mixed valid/invalid subdomains."""
        subdomain_names = [
            "test1.example.com",
            "invalid..domain",
            "test2.example.com",
        ]

        result = self.subdomain_repo.bulk_create(subdomain_names, self.scan_history.id, self.domain.id)

        # Should only create valid subdomains
        self.assertEqual(len(result), 2)
        created_names = [sub.name for sub in result]
        self.assertIn("test1.example.com", created_names)
        self.assertIn("test2.example.com", created_names)

    def test_bulk_create_empty_list(self):
        """Test bulk creation with empty list."""
        result = self.subdomain_repo.bulk_create([], self.scan_history.id, self.domain.id)

        self.assertEqual(result, [])

    def test_get_or_create_existing_subdomain(self):
        """Test get_or_create with existing subdomain."""
        subdomain1, created1 = self.subdomain_repo.get_or_create(
            "test.example.com", self.scan_history.id, self.domain.id
        )
        self.assertTrue(created1)

        subdomain2, created2 = self.subdomain_repo.get_or_create(
            "test.example.com", self.scan_history.id, self.domain.id
        )
        self.assertFalse(created2)
        self.assertEqual(subdomain1.id, subdomain2.id)

    def test_get_or_create_new_subdomain(self):
        """Test get_or_create with new subdomain."""
        subdomain, created = self.subdomain_repo.get_or_create("new.example.com", self.scan_history.id, self.domain.id)

        self.assertIsNotNone(subdomain)
        self.assertTrue(created)
        self.assertEqual(subdomain.name, "new.example.com")
