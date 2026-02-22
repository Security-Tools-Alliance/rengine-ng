"""
Tests for reNgine.utilities.domain (normalize, resolve, display name).
"""

from unittest.mock import MagicMock

from reNgine.utilities.domain import (
    get_domain_for_scan_by_name,
    get_or_create_domain_for_target,
    get_scan_display_name,
    normalize_domain_name,
    resolve_domain_for_scan,
)
from startScan.models import Domain
from utils.test_base import BaseTestCase


class TestNormalizeDomainName(BaseTestCase):
    """Tests for normalize_domain_name."""

    def test_normalize_returns_lower_stripped_trailing_dot_removed(self):
        self.assertEqual(normalize_domain_name("  Example.COM.  "), "example.com")
        self.assertEqual(normalize_domain_name("example.com."), "example.com")

    def test_normalize_empty_returns_none(self):
        self.assertIsNone(normalize_domain_name(""))
        self.assertIsNone(normalize_domain_name("   "))
        self.assertIsNone(normalize_domain_name("."))
        self.assertIsNone(normalize_domain_name(None))

    def test_normalize_strips_trailing_dot(self):
        self.assertEqual(normalize_domain_name("sub.example.com."), "sub.example.com")

    def test_normalize_returns_none_for_non_string_inputs(self):
        self.assertIsNone(normalize_domain_name(123))
        self.assertIsNone(normalize_domain_name(0))
        self.assertIsNone(normalize_domain_name(True))
        self.assertIsNone(normalize_domain_name(["example.com"]))

    def test_normalize_preserves_idn_unicode_domains(self):
        self.assertEqual(normalize_domain_name("Bücher.DE"), "bücher.de")
        self.assertEqual(normalize_domain_name("  Ëxample.ORG.  "), "ëxample.org")

    def test_normalize_preserves_punycode(self):
        self.assertEqual(normalize_domain_name("xn--d1acpjx3f.xn--p1ai"), "xn--d1acpjx3f.xn--p1ai")
        self.assertEqual(normalize_domain_name("  XN--D1ACPJX3F.XN--P1AI.  "), "xn--d1acpjx3f.xn--p1ai")


class TestGetDomainForScanByName(BaseTestCase):
    """Tests for get_domain_for_scan_by_name (read-only lookup)."""

    def test_returns_domain_when_exists(self):
        scan = self.data_generator.scan_history
        domain = self.data_generator.create_domain(scan_history=scan)
        found = get_domain_for_scan_by_name(scan.id, domain.name)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, domain.id)

    def test_returns_none_for_empty_name(self):
        scan = self.data_generator.scan_history
        self.assertIsNone(get_domain_for_scan_by_name(scan.id, ""))
        self.assertIsNone(get_domain_for_scan_by_name(scan.id, "   "))

    def test_returns_none_when_no_match(self):
        scan = self.data_generator.scan_history
        self.assertIsNone(get_domain_for_scan_by_name(scan.id, "nonexistent.example.com"))

    def test_is_scoped_to_scan_history(self):
        scan_a = self.data_generator.scan_history
        scan_b = self.data_generator.create_scan_history()
        domain = self.data_generator.create_domain(scan_history=scan_a)
        self.assertIsNone(get_domain_for_scan_by_name(scan_b.id, domain.name))


class TestGetOrCreateDomainForTarget(BaseTestCase):
    """Tests for get_or_create_domain_for_target."""

    def test_creates_domain_when_missing(self):
        scan = self.data_generator.scan_history
        name = "new-target.example.com"
        domain = get_or_create_domain_for_target(scan.id, name)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, name)
        self.assertEqual(domain.scan_history_id, scan.id)

    def test_returns_existing_domain(self):
        scan = self.data_generator.scan_history
        existing = self.data_generator.create_domain(scan_history=scan)
        domain = get_or_create_domain_for_target(scan.id, existing.name)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.id, existing.id)

    def test_normalizes_name(self):
        scan = self.data_generator.scan_history
        domain = get_or_create_domain_for_target(scan.id, "  UPPER.example.com.  ")
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, "upper.example.com")

    def test_returns_none_for_empty_and_does_not_create(self):
        scan = self.data_generator.scan_history
        initial_count = Domain.objects.filter(scan_history_id=scan.id).count()
        self.assertIsNone(get_or_create_domain_for_target(scan.id, ""))
        self.assertIsNone(get_or_create_domain_for_target(scan.id, "   "))
        self.assertEqual(Domain.objects.filter(scan_history_id=scan.id).count(), initial_count)

    def test_returns_none_for_none_and_does_not_create(self):
        scan = self.data_generator.scan_history
        initial_count = Domain.objects.filter(scan_history_id=scan.id).count()
        self.assertIsNone(get_or_create_domain_for_target(scan.id, None))
        self.assertEqual(Domain.objects.filter(scan_history_id=scan.id).count(), initial_count)


class TestResolveDomainForScan(BaseTestCase):
    """Tests for resolve_domain_for_scan (centralized resolution with TLD extraction)."""

    def test_extracts_tld_from_subdomain(self):
        scan = self.data_generator.scan_history
        domain = resolve_domain_for_scan(scan.id, "www.example.com", create=True)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, "example.com")

    def test_extracts_tld_from_deep_subdomain(self):
        scan = self.data_generator.scan_history
        domain = resolve_domain_for_scan(scan.id, "api.v2.staging.example.co.uk", create=True)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, "example.co.uk")

    def test_keeps_bare_tld_unchanged(self):
        scan = self.data_generator.scan_history
        domain = resolve_domain_for_scan(scan.id, "example.com", create=True)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, "example.com")

    def test_ip_address_falls_through_as_is(self):
        scan = self.data_generator.scan_history
        domain = resolve_domain_for_scan(scan.id, "192.168.1.1", create=True)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, "192.168.1.1")

    def test_skips_empty_candidates(self):
        scan = self.data_generator.scan_history
        domain = resolve_domain_for_scan(scan.id, "  ", "", "blog.example.org", create=True)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, "example.org")

    def test_tries_candidates_in_order_tld_extracted(self):
        scan = self.data_generator.scan_history
        domain = resolve_domain_for_scan(scan.id, "www.first-domain.com", "api.second-domain.com", create=True)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.name, "first-domain.com")

    def test_returns_none_when_no_valid_candidate(self):
        scan = self.data_generator.scan_history
        domain = resolve_domain_for_scan(scan.id, "", "  ", create=True)
        self.assertIsNone(domain)

    def test_log_failure_called_when_none(self):
        scan = self.data_generator.scan_history
        logger = MagicMock()
        resolve_domain_for_scan(
            scan.id,
            "",
            create=True,
            log_failure={"logger": logger, "prefix": "[TEST]", "extra": "target_id=1"},
        )
        logger.log_line.assert_called_once()
        call_args = logger.log_line.call_args
        self.assertIn("Could not resolve domain", call_args[0][2])

    def test_log_failure_without_extra(self):
        scan = self.data_generator.scan_history
        logger = MagicMock()
        resolve_domain_for_scan(
            scan.id,
            "",
            create=True,
            log_failure={"logger": logger, "prefix": "[TEST]"},
        )
        logger.log_line.assert_called_once()
        call_args = logger.log_line.call_args
        self.assertIn(str(scan.id), call_args[0][2])

    def test_create_false_only_looks_up_tld(self):
        scan = self.data_generator.scan_history
        self.assertIsNone(resolve_domain_for_scan(scan.id, "www.lookup-only.com", create=False))
        resolve_domain_for_scan(scan.id, "lookup-only.com", create=True)
        found = resolve_domain_for_scan(scan.id, "www.lookup-only.com", create=False)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "lookup-only.com")

    def test_reuses_existing_domain_with_extracted_tld(self):
        scan = self.data_generator.scan_history
        existing = get_or_create_domain_for_target(scan.id, "example.net")
        domain = resolve_domain_for_scan(scan.id, "blog.example.net", create=True)
        self.assertIsNotNone(domain)
        self.assertEqual(domain.id, existing.id)
        self.assertEqual(domain.name, "example.net")

    def test_different_subdomains_same_tld_reuse_domain(self):
        scan = self.data_generator.scan_history
        d1 = resolve_domain_for_scan(scan.id, "www.example.com", create=True)
        d2 = resolve_domain_for_scan(scan.id, "api.example.com", create=True)
        self.assertEqual(d1.id, d2.id)
        self.assertEqual(d1.name, "example.com")


class TestGetScanDisplayName(BaseTestCase):
    """Tests for get_scan_display_name."""

    def test_returns_target_value_stripped(self):
        self.assertEqual(get_scan_display_name(" target.example.com "), "target.example.com")

    def test_returns_empty_string_when_empty(self):
        self.assertEqual(get_scan_display_name(""), "")
        self.assertEqual(get_scan_display_name("   "), "")

    def test_returns_empty_string_when_none(self):
        self.assertEqual(get_scan_display_name(None), "")
