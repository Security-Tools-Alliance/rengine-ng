"""Tests for reNgine.core.ip_literal."""

from django.test import TestCase

from reNgine.core.ip_literal import is_ip_literal_text, normalize_ip_address_text


class IpLiteralTestCase(TestCase):
    def test_normalize_ipv4_strips_whitespace(self) -> None:
        self.assertEqual(normalize_ip_address_text("  192.168.0.1  "), "192.168.0.1")

    def test_normalize_ipv6(self) -> None:
        self.assertEqual(normalize_ip_address_text("2001:db8::1"), "2001:db8::1")

    def test_normalize_rejects_invalid(self) -> None:
        self.assertIsNone(normalize_ip_address_text(""))
        self.assertIsNone(normalize_ip_address_text("   "))
        self.assertIsNone(normalize_ip_address_text("not.an.ip"))
        self.assertIsNone(normalize_ip_address_text(None))

    def test_is_ip_literal_matches_normalize(self) -> None:
        self.assertTrue(is_ip_literal_text("10.0.0.1"))
        self.assertTrue(is_ip_literal_text(" ::1 "))
        self.assertFalse(is_ip_literal_text("example.com"))
