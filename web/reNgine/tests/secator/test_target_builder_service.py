"""
Unit tests for TargetBuilderService.
"""

from reNgine.secator.services.target_builder_service import TargetBuilderService
from utils.test_base import BaseTestCase


class TestTargetBuilderService(BaseTestCase):
    """Test cases for TargetBuilderService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.domain = self.data_generator.domain
        self.subdomain = self.data_generator.subdomain
        self.data_generator.create_endpoint(
            http_url=f"https://{self.subdomain.name}/",
            is_default=True,
            http_status=200,
        )

    def test_build_targets_for_type_url_returns_default_endpoints(self):
        """build_targets_for_type('url') returns default endpoint http_urls."""
        service = TargetBuilderService(domain_id=self.domain.id)
        result = service.build_targets_for_type("url")
        self.assertIn(f"https://{self.subdomain.name}/", result)

    def test_build_targets_for_type_url_with_subdomain_ids(self):
        """build_targets_for_type('url') with subdomain_ids filters to those subdomains."""
        service = TargetBuilderService(
            domain_id=self.domain.id,
            subdomain_ids=[self.subdomain.id],
        )
        result = service.build_targets_for_type("url")
        self.assertIn(f"https://{self.subdomain.name}/", result)

    def test_build_targets_for_type_host_includes_domain_and_subdomains(self):
        """build_targets_for_type('host') returns domain name and subdomain names."""
        service = TargetBuilderService(domain_id=self.domain.id)
        result = service.build_targets_for_type("host")
        self.assertIn(self.domain.name, result)
        self.assertIn(self.subdomain.name, result)

    def test_build_targets_for_type_host_with_subdomain_ids_returns_only_selected(self):
        """build_targets_for_type('host') with subdomain_ids returns only selected subdomain names."""
        service = TargetBuilderService(
            domain_id=self.domain.id,
            subdomain_ids=[self.subdomain.id],
        )
        result = service.build_targets_for_type("host")
        self.assertEqual(result, [self.subdomain.name])

    def test_build_targets_for_type_host_port_returns_alive_default_endpoints(self):
        """build_targets_for_type('host:port') returns host:port for alive default endpoints."""
        service = TargetBuilderService(domain_id=self.domain.id)
        result = service.build_targets_for_type("host:port")
        self.assertIsInstance(result, list)
        for item in result:
            self.assertIn(":", item)

    def test_build_targets_for_type_ip_returns_ip_addresses(self):
        """build_targets_for_type('ip') returns IPs linked to domain subdomains."""
        ip_obj = self.data_generator.create_ip_address(address="10.0.0.1")
        self.subdomain.ip_addresses.add(ip_obj)
        service = TargetBuilderService(domain_id=self.domain.id)
        result = service.build_targets_for_type("ip")
        self.assertIn("10.0.0.1", result)

    def test_build_targets_for_type_ip_with_subdomain_ids_returns_only_selected_ips(self):
        """build_targets_for_type('ip') with subdomain_ids returns IPs only for selected subdomains."""
        ip1 = self.data_generator.create_ip_address(address="10.0.0.1")
        self.subdomain.ip_addresses.add(ip1)
        subdomain2 = self.data_generator.create_subdomain(name=f"other.{self.domain.name}", target_domain=self.domain)
        ip2 = self.data_generator.create_ip_address(address="10.0.0.2")
        subdomain2.ip_addresses.add(ip2)
        service = TargetBuilderService(
            domain_id=self.domain.id,
            subdomain_ids=[self.subdomain.id],
        )
        result = service.build_targets_for_type("ip")
        self.assertIn("10.0.0.1", result)
        self.assertNotIn("10.0.0.2", result)

    def test_build_targets_for_type_unknown_returns_empty(self):
        """build_targets_for_type with unknown type returns empty list."""
        service = TargetBuilderService(domain_id=self.domain.id)
        result = service.build_targets_for_type("unknown_type")
        self.assertEqual(result, [])

    def test_build_targets_by_type_returns_dict_per_type(self):
        """build_targets_by_type returns dict mapping each input_type to target list."""
        service = TargetBuilderService(domain_id=self.domain.id)
        result = service.build_targets_by_type(["url", "host"])
        self.assertIn("url", result)
        self.assertIn("host", result)
        self.assertIsInstance(result["url"], list)
        self.assertIsInstance(result["host"], list)

    def test_build_flat_targets_deduplicates(self):
        """build_flat_targets returns flat list without duplicates."""
        service = TargetBuilderService(domain_id=self.domain.id)
        result = service.build_flat_targets(["url", "host"])
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), len(set(result)))
