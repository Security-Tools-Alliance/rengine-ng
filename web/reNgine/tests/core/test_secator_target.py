"""
Tests for Secator target value parsing (parse_secator_target_value).
"""

from django.test import TestCase

from reNgine.core.secator_target import parse_secator_target_value


class TestParseSecatorTargetValue(TestCase):
    """Test parse_secator_target_value accepts only url, host:port, ip."""

    def test_empty_or_none_returns_invalid(self):
        """Empty or None value is invalid."""
        self.assertFalse(parse_secator_target_value(None).is_valid)
        self.assertFalse(parse_secator_target_value("").is_valid)
        self.assertFalse(parse_secator_target_value("   ").is_valid)

    def test_full_http_url_valid(self):
        """Full http/https URL is valid (kind=url)."""
        p = parse_secator_target_value("https://example.com/path")
        self.assertTrue(p.is_valid)
        self.assertEqual(p.kind, "url")
        self.assertEqual(p.url_normalized, "https://example.com/path")
        self.assertEqual(p.host, "example.com")
        self.assertIsNone(p.port)
        self.assertIsNone(p.ip)

        p2 = parse_secator_target_value("http://192.168.1.1:8080/")
        self.assertTrue(p2.is_valid)
        self.assertEqual(p2.kind, "url")
        self.assertEqual(p2.host, "192.168.1.1")
        self.assertEqual(p2.port, 8080)
        self.assertEqual(p2.ip, "192.168.1.1")

    def test_host_port_valid(self):
        """host:port (hostname or IP) is valid (kind=host_port)."""
        p = parse_secator_target_value("example.com:443")
        self.assertTrue(p.is_valid)
        self.assertEqual(p.kind, "host_port")
        self.assertEqual(p.host, "example.com")
        self.assertEqual(p.port, 443)
        self.assertIsNone(p.ip)

        p2 = parse_secator_target_value("192.168.1.1:8080")
        self.assertTrue(p2.is_valid)
        self.assertEqual(p2.kind, "host_port")
        self.assertEqual(p2.host, "192.168.1.1")
        self.assertEqual(p2.port, 8080)
        self.assertEqual(p2.ip, "192.168.1.1")

    def test_bare_ip_valid(self):
        """Bare IPv4 or IPv6 is valid (kind=ip)."""
        p = parse_secator_target_value("192.168.1.1")
        self.assertTrue(p.is_valid)
        self.assertEqual(p.kind, "ip")
        self.assertEqual(p.host, "192.168.1.1")
        self.assertEqual(p.ip, "192.168.1.1")
        self.assertIsNone(p.port)

        p2 = parse_secator_target_value("::1")
        self.assertTrue(p2.is_valid)
        self.assertEqual(p2.kind, "ip")
        self.assertEqual(p2.ip, "::1")

    def test_invalid_not_treated(self):
        """Values that are not url, host:port, or ip are invalid."""
        self.assertFalse(parse_secator_target_value("/relative/path").is_valid)
        self.assertFalse(parse_secator_target_value("javascript:alert(1)").is_valid)
        self.assertFalse(parse_secator_target_value("not-a-valid-ip-or-url").is_valid)
        self.assertFalse(parse_secator_target_value("example.com").is_valid)  # no port, not IP
        self.assertFalse(parse_secator_target_value(":443").is_valid)
        self.assertFalse(parse_secator_target_value("host:99999").is_valid)  # port out of range
