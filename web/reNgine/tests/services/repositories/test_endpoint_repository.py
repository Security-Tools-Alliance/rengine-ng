"""
Unit tests for EndpointRepository.
Tests the is_default logic for endpoints.
"""

from django.test import override_settings
from django.utils import timezone

from reNgine.services.repositories.endpoint_repository import EndpointRepository
from startScan.models import DirectoryScan, EndPoint, Subdomain, SubScan
from utils.test_base import BaseTestCase


class EndpointRepositoryHttpStatusBreakdownTestCase(BaseTestCase):
    """Tests for get_http_status_breakdown (scan and domain)."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.repository = EndpointRepository()

    def test_legacy_scan_returns_subdomain_breakdown(self):
        """Legacy scan uses Subdomain.http_status."""
        self.data_generator.create_scan_history(is_legacy=True)
        self.data_generator.create_subdomain(http_status=200)
        self.data_generator.create_subdomain(name="api.example.com", http_status=200)
        self.data_generator.create_subdomain(name="www.example.com", http_status=404)
        result = self.repository.get_http_status_breakdown(self.data_generator.scan_history)
        by_status = {r["http_status"]: r["http_status__count"] for r in result}
        self.assertEqual(by_status.get(200), 2)
        self.assertEqual(by_status.get(404), 1)

    def test_legacy_scan_empty_when_no_http_status(self):
        """Legacy scan with all http_status=0 returns empty list."""
        self.data_generator.create_scan_history(is_legacy=True)
        self.data_generator.create_subdomain()
        result = self.repository.get_http_status_breakdown(self.data_generator.scan_history)
        self.assertEqual(result, [])

    def test_secator_scan_returns_default_endpoint_breakdown(self):
        """Secator scan uses EndPoint (is_default=True) http_status."""
        self.data_generator.create_scan_history(is_legacy=False)
        self.data_generator.create_subdomain()
        self.data_generator.create_endpoint(is_default=True, http_status=200)
        sub2 = self.data_generator.create_subdomain(name="api.example.com")
        self.data_generator.create_endpoint(subdomain=sub2, name="ep2", http_status=301, is_default=True)
        result = self.repository.get_http_status_breakdown(self.data_generator.scan_history)
        by_status = {r["http_status"]: r["http_status__count"] for r in result}
        self.assertEqual(by_status.get(200), 1)
        self.assertEqual(by_status.get(301), 1)

    def test_secator_scan_ignores_non_default_endpoints(self):
        """Secator breakdown only counts is_default=True endpoints."""
        self.data_generator.create_scan_history(is_legacy=False)
        self.data_generator.create_subdomain()
        self.data_generator.create_endpoint(is_default=True, http_status=200)
        self.data_generator.create_endpoint(name="ep2", http_status=404, is_default=False)
        result = self.repository.get_http_status_breakdown(self.data_generator.scan_history)
        by_status = {r["http_status"]: r["http_status__count"] for r in result}
        self.assertEqual(by_status.get(200), 1)
        self.assertNotIn(404, by_status)

    def test_secator_scan_empty_when_no_default_endpoints(self):
        """Secator scan with no default endpoints with status returns empty."""
        self.data_generator.create_scan_history(is_legacy=False)
        self.data_generator.create_subdomain()
        self.data_generator.create_endpoint(http_status=0)
        result = self.repository.get_http_status_breakdown(self.data_generator.scan_history)
        self.assertEqual(result, [])

    def test_domain_merges_legacy_subdomains_and_secator_endpoints(self):
        """Domain breakdown merges Subdomain and default EndPoint counts."""
        self.data_generator.create_scan_history(is_legacy=True)
        self.data_generator.create_domain(scan_history=self.data_generator.scan_history)
        self.data_generator.create_subdomain(http_status=200)
        self.data_generator.create_subdomain(name="api.example.com", http_status=404)
        scan_secator = self.data_generator.create_scan_history(is_legacy=False)
        sub_sec = self.data_generator.create_subdomain(name="www.example.com", scan_history=scan_secator)
        self.data_generator.create_endpoint(
            subdomain=sub_sec,
            scan_history=scan_secator,
            name="ep1",
            is_default=True,
            http_status=200,
        )
        result = self.repository.get_http_status_breakdown(self.data_generator.domain)
        by_status = {r["http_status"]: r["http_status__count"] for r in result}
        self.assertEqual(by_status.get(200), 2)
        self.assertEqual(by_status.get(404), 1)

    def test_domain_returns_sorted_by_http_status(self):
        """Result is sorted by http_status for stable chart order."""
        self.data_generator.create_scan_history(is_legacy=True)
        self.data_generator.create_domain(scan_history=self.data_generator.scan_history)
        self.data_generator.create_subdomain(http_status=404)
        self.data_generator.create_subdomain(name="api.example.com", http_status=200)
        result = self.repository.get_http_status_breakdown(self.data_generator.domain)
        self.assertEqual([r["http_status"] for r in result], [200, 404])

    def test_domain_empty_returns_empty_list(self):
        """Domain with no subdomains/endpoints with status returns empty."""
        self.data_generator.create_scan_history(is_legacy=True)
        self.data_generator.create_domain(scan_history=self.data_generator.scan_history)
        domain = self.data_generator.domain
        Subdomain.objects.filter(scan_history=self.data_generator.scan_history).delete()
        EndPoint.objects.filter(scan_history=self.data_generator.scan_history).delete()
        result = self.repository.get_http_status_breakdown(domain)
        self.assertEqual(result, [])

    def test_domain_same_subdomain_legacy_and_secator_counted_once(self):
        """Domain: subdomain present in legacy and Secator (default endpoint) counts only once."""
        self.data_generator.create_scan_history(is_legacy=True)
        self.data_generator.create_domain(scan_history=self.data_generator.scan_history)
        self.data_generator.create_subdomain(name="www.example.com", http_status=200)
        scan_secator = self.data_generator.create_scan_history(is_legacy=False)
        sub_sec = self.data_generator.create_subdomain(name="www.example.com", scan_history=scan_secator)
        self.data_generator.create_endpoint(
            subdomain=sub_sec,
            scan_history=scan_secator,
            name="ep_www",
            is_default=True,
            http_status=200,
        )
        result = self.repository.get_http_status_breakdown(self.data_generator.domain)
        by_status = {r["http_status"]: r["http_status__count"] for r in result}
        self.assertEqual(by_status.get(200), 1)


class EndpointRepositoryIsDefaultTestCase(BaseTestCase):
    """Test cases for is_default endpoint logic."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.repository = EndpointRepository()

        # Create a Secator scan, then domain linked to it (needed for _create_endpoints_in_bulk domain_id)
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

        # Create a subdomain
        self.subdomain = Subdomain.objects.create(
            name="test.example.com",
            scan_history=self.scan_history,
            domain=self.domain,
        )

    def _save_secator_endpoint(self, url: str, **overrides):
        item = {"url": url, "status_code": 200} | overrides
        return self.repository.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

    def test_endpoint_with_ip_url_gets_subdomain(self):
        """Endpoint with IP URL (CIDR-style scan) is associated with a subdomain named after the IP."""
        endpoint = self._save_secator_endpoint("http://192.168.1.1/", status_code=200)
        self.assertIsNotNone(endpoint, "Endpoint should be created")
        endpoint.refresh_from_db()
        self.assertIsNotNone(
            endpoint.subdomain_id,
            "Endpoint with IP host should be linked to a subdomain (get_or_create_from_host)",
        )
        self.assertEqual(endpoint.subdomain.name, "192.168.1.1")

    def test_associate_with_subdomain_uses_hostname_override_when_url_has_no_host(self):
        """When URL has no hostname, item['host'] (hostname_override) is used for subdomain association."""
        endpoint = self._save_secator_endpoint("https://test.example.com/")
        self.assertIsNotNone(endpoint)
        endpoint.subdomain = None
        endpoint.save(update_fields=["subdomain"])
        self.repository._associate_with_subdomain(
            endpoint,
            "http:///",
            self.scan_history.id,
            hostname_override="override.example.com",
        )
        endpoint.refresh_from_db()
        self.assertIsNotNone(endpoint.subdomain_id)
        self.assertEqual(endpoint.subdomain.name, "override.example.com")

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
            item, self.scan_history.id, self.data_generator.target.id
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
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNone(result)

    def test_process_secator_endpoint_item_invalid_url(self):
        """Test _process_secator_endpoint_item with invalid URL."""
        item = {
            "url": "not-a-valid-url",
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.target.id
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
            item, self.scan_history.id, self.data_generator.target.id
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
            item, self.scan_history.id, self.data_generator.target.id
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

        result = self.repository._create_endpoints_in_bulk(self.scan_history.id, self.domain.id, endpoints_data)

        self.assertEqual(len(result), 2)
        created_urls = [ep.http_url for ep in result]
        self.assertIn("https://test.example.com/page1", created_urls)
        self.assertIn("https://test.example.com/page2", created_urls)

    def test_create_endpoints_in_bulk_empty_list(self):
        """Test _create_endpoints_in_bulk with empty list."""
        result = self.repository._create_endpoints_in_bulk(self.scan_history.id, self.domain.id, [])

        self.assertEqual(result, [])

    def test_create_endpoints_in_bulk_invalid_urls(self):
        """Test _create_endpoints_in_bulk with invalid URLs."""
        endpoints_data = [
            {"http_url": "not-a-valid-url", "http_status": 200},
            {"http_url": "also-invalid", "http_status": 200},
        ]

        result = self.repository._create_endpoints_in_bulk(self.scan_history.id, self.domain.id, endpoints_data)

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
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.is_directory, True)
        self.assertEqual(result.stored_response_path, "/path/to/response.json")
        self.assertEqual(result.confidence, "high")

    def test_save_from_secator_persists_screenshot_stored_response_and_headers(self):
        """Secator Url screenshot_path, stored_response_path, response_headers and request_headers are persisted."""
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "title": "Home",
            "screenshot_path": "/reports/example/screenshot.png",
            "stored_response_path": "/reports/example/response.html",
            "response_headers": {"Content-Type": "text/html", "X-Frame-Options": "DENY"},
            "request_headers": {"User-Agent": "Secator/1.0", "Accept": "text/html"},
        }

        result = self.repository.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        result.refresh_from_db()
        self.assertEqual(result.screenshot_path, "/reports/example/screenshot.png")
        self.assertEqual(result.stored_response_path, "/reports/example/response.html")
        self.assertIsNotNone(result.headers)
        self.assertEqual(result.headers.get("response"), item["response_headers"])
        self.assertEqual(result.headers.get("request"), item["request_headers"])

    @override_settings(SECATOR_REPORTS_PREFIX="/home/secator/.secator/reports")
    def test_save_from_secator_strips_secator_reports_prefix(self):
        """screenshot_path and stored_response_path are stored without /home/secator/.secator/reports prefix."""
        full_screenshot = "/home/secator/.secator/reports/example/example.com/tasks/200/.outputs/screenshot/foo.png"
        full_response = "/home/secator/.secator/reports/example/example.com/tasks/200/.outputs/response.html"
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "screenshot_path": full_screenshot,
            "stored_response_path": full_response,
        }
        result = self.repository.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        result.refresh_from_db()
        self.assertEqual(result.screenshot_path, "example/example.com/tasks/200/.outputs/screenshot/foo.png")
        self.assertEqual(result.stored_response_path, "example/example.com/tasks/200/.outputs/response.html")

    def test_build_secator_endpoint_defaults_truncates_long_paths(self):
        """Long screenshot_path and stored_response_path are truncated to 1000 chars."""
        long_path = "a" * 1500
        item = {
            "url": "https://test.example.com/",
            "status_code": 200,
            "screenshot_path": long_path,
            "stored_response_path": long_path,
        }
        domain = self.data_generator.domain
        defaults = self.repository._build_secator_endpoint_defaults(item, domain)

        self.assertEqual(len(defaults["screenshot_path"]), 1000)
        self.assertEqual(defaults["screenshot_path"], long_path[:1000])
        self.assertEqual(len(defaults["stored_response_path"]), 1000)
        self.assertEqual(defaults["stored_response_path"], long_path[:1000])

    def test_process_secator_endpoint_item_sets_source_from_finding(self):
        """Test _process_secator_endpoint_item sets source from _source (Secator task)."""
        item = {
            "url": "https://test.example.com/",
            "status_code": 301,
            "title": "301 Moved Permanently",
            "_source": "httpx_tls",
            "_context": {
                "node_id": "subdomain_recon.httpx/tls",
                "task_id": "2042",
            },
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.source, "httpx_tls")

    def test_process_secator_endpoint_item_source_fallback_to_node_id(self):
        """Test _process_secator_endpoint_item uses _context.node_id when _source is missing."""
        item = {
            "url": "https://test.example.com/api",
            "status_code": 200,
            "_context": {"node_id": "subdomain_recon.httpx/tls"},
        }

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.source, "subdomain_recon.httpx/tls")

    def test_process_secator_endpoint_item_source_none_when_absent(self):
        """Test _process_secator_endpoint_item leaves source None when no _source or _context.node_id."""
        item = {"url": "https://test.example.com/", "status_code": 200}

        result = self.repository._process_secator_endpoint_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNotNone(result)
        self.assertIsNone(result.source)

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
            self.data_generator.target.id,
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


class EndpointRepositoryIpEndpointTestCase(BaseTestCase):
    """Tests for IP-based endpoint creation."""

    def setUp(self) -> None:
        super().setUp()
        self.repository = EndpointRepository()
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

    def test_create_endpoint_for_ip_creates_endpoint_for_valid_ip(self) -> None:
        """create_endpoint_for_ip creates an endpoint for a valid IP address."""
        ip = "192.0.2.1"
        endpoint = self.repository.create_endpoint_for_ip(ip, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(endpoint)
        endpoint.refresh_from_db()
        self.assertEqual(endpoint.http_url, f"http://{ip}")
        self.assertEqual(endpoint.scan_history_id, self.scan_history.id)
        self.assertEqual(endpoint.domain_id, self.domain.id)

    def test_create_endpoint_for_ip_invalid_ip_returns_none(self) -> None:
        """create_endpoint_for_ip returns None and does not create endpoint for invalid IP."""
        ip = "not-an-ip"
        result = self.repository.create_endpoint_for_ip(ip, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)
        self.assertFalse(EndPoint.objects.filter(scan_history=self.scan_history, http_url__contains=ip).exists())

    def test_create_endpoint_for_ip_reuses_existing_when_duplicates_present(self) -> None:
        """
        create_endpoint_for_ip must not raise when multiple endpoints already exist
        for the same (scan_history, http_url); it should reuse one of them.
        """
        ip = "198.51.100.42"
        http_url = f"http://{ip}"
        EndPoint.objects.create(
            http_url=http_url,
            scan_history=self.scan_history,
            domain=self.domain,
            http_status=0,
            discovered_date=timezone.now(),
        )
        EndPoint.objects.create(
            http_url=http_url,
            scan_history=self.scan_history,
            domain=self.domain,
            http_status=0,
            discovered_date=timezone.now(),
        )

        endpoint = self.repository.create_endpoint_for_ip(ip, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(endpoint)
        self.assertIn(endpoint.id, list(EndPoint.objects.filter(http_url=http_url).values_list("id", flat=True)))
        self.assertEqual(
            EndPoint.objects.filter(http_url=http_url, scan_history=self.scan_history).count(),
            2,
        )
