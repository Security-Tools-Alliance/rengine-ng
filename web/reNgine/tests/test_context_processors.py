"""
Tests for context processors
"""

from unittest.mock import Mock, patch

from django.core.cache import cache
from django.test import RequestFactory, TestCase

from reNgine import context_processors as context_processors_module
from reNgine import settings
from reNgine.context_processors import (
    EXTERNAL_IP_CACHE_KEY,
    _get_cached_external_ip,
    _get_external_ip_with_fallback,
    clear_external_ip_in_process_cache,
    misc,
    version,
)


class TestContextProcessors(TestCase):
    """Test cases for context processors"""

    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        cache.clear()
        clear_external_ip_in_process_cache()

    def tearDown(self):
        """Clean up after tests"""
        cache.clear()

    def test_version_context_processor(self):
        """Test version context processor returns correct version"""
        request = self.factory.get("/")
        context = version(request)

        self.assertIn("RENGINE_CURRENT_VERSION", context)
        self.assertEqual(context["RENGINE_CURRENT_VERSION"], settings.RENGINE_CURRENT_VERSION)

    @patch("reNgine.context_processors.requests.get")
    def test_get_external_ip_with_fallback_success_first_service(self, mock_get):
        """Test successful IP retrieval from first service"""
        # Mock successful response from AWS
        mock_response = Mock()
        mock_response.text = "203.0.113.1"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        result = _get_external_ip_with_fallback()

        self.assertEqual(result, "203.0.113.1")
        mock_get.assert_called_once_with("https://checkip.amazonaws.com", timeout=5)

    @patch("reNgine.context_processors.requests.get")
    def test_get_external_ip_with_fallback_success_second_service(self, mock_get):
        """Test successful IP retrieval from second service after first fails"""
        # Mock first service failure, second service success
        mock_response_fail = Mock()
        mock_response_fail.raise_for_status.side_effect = Exception("Connection failed")

        mock_response_success = Mock()
        mock_response_success.text = "203.0.113.2"
        mock_response_success.raise_for_status.return_value = None

        mock_get.side_effect = [mock_response_fail, mock_response_success]

        result = _get_external_ip_with_fallback()

        self.assertEqual(result, "203.0.113.2")
        self.assertEqual(mock_get.call_count, 2)

    @patch("reNgine.context_processors.requests.get")
    def test_get_external_ip_with_fallback_httpbin_service(self, mock_get):
        """Test successful IP retrieval from httpbin service with JSON response"""
        # Mock httpbin response
        mock_response = Mock()
        mock_response.text = '{"origin": "203.0.113.3, 203.0.113.4"}'
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        # Mock the first 3 services to fail
        def side_effect(*args, **kwargs):
            if mock_get.call_count <= 3:
                raise Exception("Service unavailable")
            return mock_response

        mock_get.side_effect = side_effect

        result = _get_external_ip_with_fallback()

        self.assertEqual(result, "203.0.113.3")

    @patch("reNgine.context_processors.requests.get")
    def test_get_external_ip_with_fallback_invalid_ip_format(self, mock_get):
        """Test handling of invalid IP format from service"""
        # Mock response with invalid IP format
        mock_response = Mock()
        mock_response.text = "invalid-ip-format"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        result = _get_external_ip_with_fallback()

        self.assertEqual(result, "Unable to retrieve IP")

    @patch("reNgine.context_processors.requests.get")
    def test_get_external_ip_with_fallback_all_services_fail(self, mock_get):
        """Test handling when all IP services fail"""
        # Mock all services to fail
        mock_get.side_effect = Exception("All services failed")

        result = _get_external_ip_with_fallback()

        self.assertEqual(result, "Unable to retrieve IP")
        self.assertEqual(mock_get.call_count, 5)  # All 5 services tried

    @patch("reNgine.context_processors.cache.get")
    def test_misc_context_processor_with_cache_hit(self, mock_cache_get):
        """Test misc context processor when IP is in Django cache"""
        mock_cache_get.return_value = "203.0.113.5"

        request = self.factory.get("/")
        context = misc(request)

        self.assertEqual(context["external_ip"], "203.0.113.5")
        mock_cache_get.assert_called_once_with(EXTERNAL_IP_CACHE_KEY)

    @patch("reNgine.context_processors._is_dummy_cache", return_value=True)
    @patch("reNgine.context_processors._get_external_ip_with_fallback")
    def test_get_cached_external_ip_uses_in_process_cache(self, mock_get_ip, _mock_dummy):
        """Test that in-process cache avoids calling fetch when DummyCache is used."""
        mock_get_ip.return_value = "203.0.113.10"
        context_processors_module._cached_external_ip_value = "203.0.113.10"
        context_processors_module._cached_external_ip_expires_at = 1e12

        result = _get_cached_external_ip()

        self.assertEqual(result, "203.0.113.10")
        mock_get_ip.assert_not_called()

    @patch("reNgine.context_processors._get_external_ip_with_fallback")
    def test_misc_context_processor_with_cache_miss_success(self, mock_get_ip):
        """Test misc context processor when IP is not in cache and retrieval succeeds"""
        mock_get_ip.return_value = "203.0.113.6"

        request = self.factory.get("/")
        context = misc(request)

        self.assertEqual(context["external_ip"], "203.0.113.6")
        mock_get_ip.assert_called_once()

    @patch("reNgine.context_processors._get_external_ip_with_fallback")
    def test_misc_context_processor_with_cache_miss_failure(self, mock_get_ip):
        """Test misc context processor when IP is not in cache and retrieval fails"""
        mock_get_ip.return_value = "Unable to retrieve IP"

        request = self.factory.get("/")
        context = misc(request)

        self.assertEqual(context["external_ip"], "Unable to retrieve IP")
        mock_get_ip.assert_called_once()

    def test_misc_context_processor_request_object(self):
        """Test that misc context processor accepts request object"""
        request = self.factory.get("/")

        # Should not raise any exception
        context = misc(request)

        self.assertIn("external_ip", context)
