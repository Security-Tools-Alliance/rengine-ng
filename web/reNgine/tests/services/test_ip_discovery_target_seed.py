"""Tests for ip_discovery_target_seed helpers."""

from reNgine.services.ip_discovery_target_seed import (
    compute_total_processed,
    fqdn_under_declared_apex,
    normalize_apex_for_target,
)
from utils.test_base import BaseTestCase


class IpDiscoveryTargetSeedHelpersTest(BaseTestCase):
    def test_normalize_apex_for_target_strips_and_lowers(self) -> None:
        self.assertEqual(normalize_apex_for_target("  WWW.EXAMPLE.TEST. "), "example.test")

    def test_normalize_apex_for_target_rejects_garbage(self) -> None:
        self.assertIsNone(normalize_apex_for_target("not a domain !!!"))
        self.assertIsNone(normalize_apex_for_target(""))

    def test_compute_total_processed_idempotent_selection(self) -> None:
        stats = {
            "domains_created": 0,
            "domains_existing": 1,
            "subdomains_created": 0,
            "subdomains_existing": 0,
            "ips_created": 0,
            "ips_existing": 0,
        }
        self.assertEqual(compute_total_processed(False, stats, True), 1)

    def test_fqdn_under_declared_apex_suffix_and_reject_foreign(self) -> None:
        self.assertTrue(fqdn_under_declared_apex("host.ray.local", "ray.local"))
        self.assertTrue(fqdn_under_declared_apex("ray.local", "ray.local"))
        self.assertFalse(fqdn_under_declared_apex("nas.local", "ray.local"))
        self.assertFalse(fqdn_under_declared_apex("evil-ray.local", "ray.local"))
