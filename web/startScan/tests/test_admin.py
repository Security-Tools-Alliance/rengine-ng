"""
Unit tests for startScan admin module.
"""

from api.scan_file import build_scan_file_url
from startScan.admin import EndPointAdmin
from startScan.models import EndPoint
from utils.test_base import BaseTestCase


class EndPointAdminOpenLinksTestCase(BaseTestCase):
    """Tests for EndPointAdmin screenshot and stored_response open links."""

    def setUp(self):
        super().setUp()
        self.admin = EndPointAdmin(EndPoint, None)

    def test_screenshot_open_link_returns_empty_when_no_path(self):
        self.data_generator.create_scan_history(is_legacy=False)
        self.data_generator.create_subdomain()
        endpoint = self.data_generator.create_endpoint(screenshot_path="")
        self.assertEqual(self.admin.screenshot_open_link(endpoint), "")

    def test_screenshot_open_link_returns_link_when_path_set(self):
        self.data_generator.create_scan_history(is_legacy=False)
        self.data_generator.create_subdomain()
        rel_path = "project/domain/screenshots/page.png"
        endpoint = self.data_generator.create_endpoint(screenshot_path=rel_path)
        result = self.admin.screenshot_open_link(endpoint)
        self.assertIn("Open", result)
        expected_url = build_scan_file_url(rel_path)
        self.assertIn(expected_url, result)
        self.assertIn('target="_blank"', result)

    def test_stored_response_open_link_returns_empty_when_no_path(self):
        self.data_generator.create_scan_history(is_legacy=False)
        self.data_generator.create_subdomain()
        endpoint = self.data_generator.create_endpoint(stored_response_path="")
        self.assertEqual(self.admin.stored_response_open_link(endpoint), "")

    def test_stored_response_open_link_returns_link_when_path_set(self):
        self.data_generator.create_scan_history(is_legacy=False)
        self.data_generator.create_subdomain()
        rel_path = "project/domain/responses/response.html"
        endpoint = self.data_generator.create_endpoint(stored_response_path=rel_path)
        result = self.admin.stored_response_open_link(endpoint)
        self.assertIn("Open", result)
        expected_url = build_scan_file_url(rel_path)
        self.assertIn(expected_url, result)
        self.assertIn('target="_blank"', result)
