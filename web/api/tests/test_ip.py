"""
This file contains the test cases for the API views.
"""

from unittest.mock import MagicMock, patch

from django.urls import reverse
from rest_framework import status

from utils.test_base import BaseTestCase


class TestIpAddressViewSet(BaseTestCase):
    """Test case for IP address viewset."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_ip_address_viewset(self):
        """Test retrieving IP addresses for a scan."""
        url = reverse("api:ip-addresses-list")
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(
            response.data["results"][0]["ip_addresses"][0]["address"],
            self.data_generator.ip_address.address,
        )


class TestIPToDomain(BaseTestCase):
    """Test case for IP to domain resolution."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("reNgine.tasks.dns.ip_range_discovery.delay")
    def test_ip_to_domain(self, mock_task):
        """Test resolving an IP address to a domain name."""
        # Mock the Celery task
        mock_task_result = MagicMock()
        mock_task_result.id = "test-task-id"
        mock_task_result.get.return_value = {
            "status": True,
            "ip_address": [{"ip": "8.8.8.8", "domain": "dns.google"}],
            "discovered_domains": ["dns.google"],
            "total_hosts": 1,
            "ping_required": True,
        }
        mock_task.return_value = mock_task_result

        url = reverse("api:ip_to_domain")
        response = self.client.get(url, {"ip_address": "8.8.8.8"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["total_hosts"], 1)
        self.assertTrue(response.data["ping_required"])
        mock_task.assert_called_once()

    @patch("reNgine.tasks.dns.ip_range_discovery.delay")
    def test_ip_to_domain_failure(self, mock_task):
        """Test IP to domain resolution when it fails."""
        # Mock the Celery task to return failure
        mock_task_result = MagicMock()
        mock_task_result.id = "test-task-id"
        mock_task_result.get.return_value = {
            "status": True,
            "ip_address": [{"ip": "192.0.2.1", "domain": "192.0.2.1"}],
            "discovered_domains": [],
            "total_hosts": 1,
            "ping_required": True,
        }
        mock_task.return_value = mock_task_result

        url = reverse("api:ip_to_domain")
        response = self.client.get(url, {"ip_address": "192.0.2.1"})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["ip_address"][0]["domain"], "192.0.2.1")

    @patch("reNgine.tasks.dns.ip_range_discovery.delay")
    def test_ip_to_domain_multiple(self, mock_task):
        """Test IP to domain resolution with multiple domains."""
        # Mock the Celery task
        mock_task_result = MagicMock()
        mock_task_result.id = "test-task-id"
        mock_task_result.get.return_value = {
            "status": True,
            "ip_address": [{"ip": "192.0.2.1", "domain": "example.com", "domains": ["example.com", "example.org"]}],
            "discovered_domains": ["example.com", "example.org"],
            "total_hosts": 1,
            "ping_required": True,
        }
        mock_task.return_value = mock_task_result

        url = reverse("api:ip_to_domain")
        response = self.client.get(url, {"ip_address": "192.0.2.1"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("domains", response.data["ip_address"][0])
        self.assertEqual(response.data["ip_address"][0]["domains"], ["example.com", "example.org"])


class TestDomainIPHistory(BaseTestCase):
    """Test case for domain IP history lookup."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("api.views.query_ip_history.apply_async")
    def test_domain_ip_history(self, mock_apply_async):
        """Test domain IP history lookup."""
        mock_apply_async.return_value.wait.return_value = {
            "status": True,
            "data": "IP History data",
        }
        url = reverse("api:domain_ip_history")
        response = self.client.get(url, {"domain": self.data_generator.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["data"], "IP History data")


class TestListIPs(BaseTestCase):
    """Test case for listing IP addresses."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_ips(self):
        """Test listing IP addresses for a target."""
        url = reverse("api:listIPs")
        response = self.client.get(url, {"target_id": self.data_generator.domain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("ips", response.data)
        self.assertGreaterEqual(len(response.data["ips"]), 1)
        self.assertEqual(response.data["ips"][0]["address"], self.data_generator.ip_address.address)


class TestListPorts(BaseTestCase):
    """Test case for listing ports."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        # Link IP to subscans for API filtering to work properly
        self.data_generator.link_ip_to_subscans()

    def test_list_ports(self):
        """Test listing ports for a target and scan."""
        url = reverse("api:listPorts")
        response = self.client.get(
            url,
            {
                "target_id": self.data_generator.domain.id,
                "scan_id": self.data_generator.scan_history.id,
                "ip_address": "1.1.1.1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("ports", response.data)
        self.assertGreaterEqual(len(response.data["ports"]), 1)
        self.assertEqual(response.data["ports"][0]["number"], 80)
        self.assertEqual(response.data["ports"][0]["service_name"], "http")


class TestWhois(BaseTestCase):
    """Test case for WHOIS lookup."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("api.views.query_whois.apply_async")
    def test_whois(self, mock_apply_async):
        """Test WHOIS lookup for a domain."""
        mock_apply_async.return_value.wait.return_value = {
            "status": True,
            "data": "Whois data",
        }
        url = reverse("api:whois")
        response = self.client.get(url, {"ip_domain": self.data_generator.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["data"], "Whois data")


class TestReverseWhois(BaseTestCase):
    """Test case for Reverse WHOIS lookup."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("api.views.query_reverse_whois.apply_async")
    def test_reverse_whois(self, mock_apply_async):
        """Test Reverse WHOIS lookup for a domain."""
        mock_apply_async.return_value.wait.return_value = {
            "status": True,
            "data": "Reverse Whois data",
        }
        url = reverse("api:reverse_whois")
        response = self.client.get(url, {"lookup_keyword": self.data_generator.domain.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["data"], "Reverse Whois data")
