"""
Tests for reNgine.utilities.url (is_acceptable_subdomain_name, is_apex_domain, and related).
"""

from reNgine.utilities.url import is_acceptable_subdomain_name, is_apex_domain
from utils.test_base import BaseTestCase


class TestIsAcceptableSubdomainName(BaseTestCase):
    """Tests for is_acceptable_subdomain_name (hostname or IP for Subdomain creation)."""

    def test_accepts_standard_fqdn(self):
        self.assertTrue(is_acceptable_subdomain_name("example.com"))
        self.assertTrue(is_acceptable_subdomain_name("sub.example.com"))
        self.assertTrue(is_acceptable_subdomain_name("api.example.co.uk"))

    def test_accepts_ipv4(self):
        self.assertTrue(is_acceptable_subdomain_name("192.168.1.1"))
        self.assertTrue(is_acceptable_subdomain_name("10.0.0.1"))
        self.assertTrue(is_acceptable_subdomain_name("0.0.0.0"))

    def test_accepts_ipv6(self):
        self.assertTrue(is_acceptable_subdomain_name("::1"))
        self.assertTrue(is_acceptable_subdomain_name("2001:db8::1"))
        self.assertTrue(is_acceptable_subdomain_name("fe80::1"))

    def test_accepts_local_tlds(self):
        self.assertTrue(is_acceptable_subdomain_name("host.lan"))
        self.assertTrue(is_acceptable_subdomain_name("printer.local"))
        self.assertTrue(is_acceptable_subdomain_name("rengine.local"))
        self.assertTrue(is_acceptable_subdomain_name("ownfoil.lan"))

    def test_rejects_empty_or_invalid(self):
        self.assertFalse(is_acceptable_subdomain_name(""))
        self.assertFalse(is_acceptable_subdomain_name("   "))
        self.assertFalse(is_acceptable_subdomain_name(None))
        self.assertFalse(is_acceptable_subdomain_name("invalid..domain..name"))
        self.assertFalse(is_acceptable_subdomain_name("256.256.256.256"))


class TestIsApexDomain(BaseTestCase):
    """Tests for is_apex_domain (tldextract-based apex/registered domain detection)."""

    def test_apex_single_label_tld(self):
        self.assertTrue(is_apex_domain("example.com"))
        self.assertTrue(is_apex_domain("test.org"))

    def test_apex_multi_part_tld(self):
        self.assertTrue(is_apex_domain("example.co.uk"))
        self.assertTrue(is_apex_domain("example.com.au"))

    def test_not_apex_has_subdomain(self):
        self.assertFalse(is_apex_domain("www.example.com"))
        self.assertFalse(is_apex_domain("mail.example.co.uk"))
        self.assertFalse(is_apex_domain("api.test.org"))

    def test_rejects_empty_or_invalid(self):
        self.assertFalse(is_apex_domain(""))
        self.assertFalse(is_apex_domain("   "))
        self.assertFalse(is_apex_domain(None))
