"""
Tests for core validators.
"""

from django.test import TestCase

from reNgine.core.validators import (
    is_valid_cidr,
    is_valid_domain,
    is_valid_email,
    is_valid_ip,
    is_valid_port,
    is_valid_url,
    sanitize_filename,
    validate_severity,
)


class TestValidators(TestCase):
    """Test validator functions."""

    def test_is_valid_domain(self):
        """Test domain validation."""
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("sub.example.com"))
        # Internationalized domain name (IDN)
        self.assertTrue(is_valid_domain("münich.com"))
        # Punycode representation of IDN
        self.assertTrue(is_valid_domain("xn--mnich-kva.com"))
        self.assertFalse(is_valid_domain("invalid domain"))
        self.assertFalse(is_valid_domain(""))

    def test_is_valid_url(self):
        """Test URL validation."""
        self.assertTrue(is_valid_url("https://example.com"))
        self.assertTrue(is_valid_url("http://example.com/path"))
        # Edge-case URLs
        self.assertTrue(is_valid_url("ftp://example.com/resource"))  # uncommon scheme
        self.assertTrue(is_valid_url("http://example.com:8080"))  # uncommon port
        self.assertTrue(is_valid_url("https://example.com/path?query=param"))  # query parameters
        self.assertTrue(is_valid_url("https://example.com/path#fragment"))  # fragment
        self.assertTrue(is_valid_url("custom-scheme://host/resource"))  # custom scheme
        self.assertFalse(is_valid_url("not a url"))
        self.assertFalse(is_valid_url(""))

    def test_is_valid_ip(self):
        """Test IP validation."""
        # IPv4 valid
        self.assertTrue(is_valid_ip("192.168.1.1"))
        # IPv6 valid
        self.assertTrue(is_valid_ip("::1"))
        # IPv6 shorthand notation
        self.assertTrue(is_valid_ip("2001:db8::1"))
        # Reserved IPv4 (should be valid as an IP, but may be reserved for special use)
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertTrue(is_valid_ip("255.255.255.255"))
        # Invalid IPv4
        self.assertFalse(is_valid_ip("256.256.256.256"))
        # Invalid IPv6
        self.assertFalse(is_valid_ip("2001:db8:::1"))
        # Empty string
        self.assertFalse(is_valid_ip(""))

    def test_is_valid_email(self):
        """Test email validation."""
        # Standard email
        self.assertTrue(is_valid_email("test@example.com"))
        # Subdomain
        self.assertTrue(is_valid_email("user@mail.sub.example.co.uk"))
        # Plus sign
        self.assertTrue(is_valid_email("firstname.lastname+tag@gmail.com"))
        # Unusual TLD
        self.assertTrue(is_valid_email("user@domain.technology"))
        # Leading/trailing whitespace (should be invalid)
        self.assertFalse(is_valid_email("  test@example.com"))
        self.assertFalse(is_valid_email("test@example.com  "))
        # Unicode characters (should be invalid for most validators)
        self.assertFalse(is_valid_email("tést@exámple.com"))
        # Invalid email
        self.assertFalse(is_valid_email("invalid"))
        self.assertFalse(is_valid_email(""))

    def test_is_valid_port(self):
        """Test port validation."""
        self.assertTrue(is_valid_port(80))
        self.assertTrue(is_valid_port("443"))
        self.assertTrue(is_valid_port(65535))
        self.assertFalse(is_valid_port(0))
        self.assertFalse(is_valid_port(65536))
        self.assertFalse(is_valid_port("invalid"))
        # Additional tests for negative, floating point, and non-integer values
        self.assertFalse(is_valid_port(-1))
        self.assertFalse(is_valid_port("-22"))
        self.assertFalse(is_valid_port(3.14))
        self.assertFalse(is_valid_port("8080.5"))
        self.assertFalse(is_valid_port(None))

    def test_is_valid_cidr(self):
        """Test CIDR validation."""
        # Valid IPv4 CIDR
        self.assertTrue(is_valid_cidr("192.168.1.0/24"))
        self.assertTrue(is_valid_cidr("10.0.0.0/8"))
        self.assertTrue(is_valid_cidr("0.0.0.0/0"))
        self.assertTrue(is_valid_cidr("255.255.255.255/32"))

        # Valid IPv6 CIDR
        self.assertTrue(is_valid_cidr("2001:db8::/32"))
        self.assertTrue(is_valid_cidr("::/0"))
        self.assertTrue(is_valid_cidr("2001:db8:85a3::8a2e:370:7334/64"))

        # Invalid CIDR - prefix too large
        self.assertFalse(is_valid_cidr("192.168.1.0/33"))
        self.assertFalse(is_valid_cidr("2001:db8::/129"))

        # Invalid CIDR - invalid IP addresses
        self.assertFalse(is_valid_cidr("999.999.999.999/24"))
        self.assertFalse(is_valid_cidr("256.256.256.256/8"))
        self.assertFalse(is_valid_cidr("192.168.1.256/24"))

        # Invalid CIDR - malformed
        self.assertFalse(is_valid_cidr("invalid"))
        self.assertFalse(is_valid_cidr("192.168.1.0"))
        self.assertFalse(is_valid_cidr("192.168.1.0/"))
        self.assertFalse(is_valid_cidr("/24"))
        self.assertFalse(is_valid_cidr(""))
        self.assertFalse(is_valid_cidr("192.168.1.0/abc"))

    def test_sanitize_filename(self):
        """Test filename sanitization."""
        self.assertEqual(sanitize_filename("test.txt"), "test.txt")
        self.assertEqual(sanitize_filename("test/file.txt"), "test_file.txt")
        self.assertEqual(sanitize_filename("test<>file.txt"), "test__file.txt")
        self.assertEqual(sanitize_filename(""), "unnamed")
        # Unicode characters should be preserved if allowed by the sanitizer
        self.assertEqual(sanitize_filename("тест.txt"), "тест.txt")
        self.assertEqual(sanitize_filename("文件.txt"), "文件.txt")
        # Leading/trailing whitespace should be handled
        self.assertEqual(sanitize_filename("  test.txt  "), "test.txt")
        self.assertEqual(sanitize_filename("\ttest.txt\n"), "test.txt")
        # Only special characters should result in 'unnamed' or sanitized output
        self.assertEqual(sanitize_filename("////"), "____")  # Replaced with underscores
        self.assertEqual(sanitize_filename("<>"), "__")  # Replaced with underscores
        self.assertEqual(sanitize_filename("   "), "unnamed")  # Whitespace becomes unnamed
        # Mixed unicode and special characters
        self.assertEqual(sanitize_filename("файл<>.txt"), "файл__.txt")
        self.assertEqual(sanitize_filename("  文件/<>.txt  "), "文件___.txt")  # / becomes _ too

    def test_validate_severity(self):
        """Test severity validation."""
        # Test basic valid severities
        self.assertEqual(validate_severity("critical"), "critical")
        self.assertEqual(validate_severity("high"), "high")
        self.assertEqual(validate_severity("medium"), "medium")
        self.assertEqual(validate_severity("low"), "low")
        self.assertEqual(validate_severity("info"), "info")
        self.assertEqual(validate_severity("unknown"), "unknown")
        
        # Test case variations
        self.assertEqual(validate_severity("CRITICAL"), "critical")
        self.assertEqual(validate_severity("HIGH"), "high")
        self.assertEqual(validate_severity("Medium"), "medium")
        self.assertEqual(validate_severity("LOW"), "low")
        self.assertEqual(validate_severity("INFO"), "info")
        self.assertEqual(validate_severity("UNKNOWN"), "unknown")
        
        # Test mixed case
        self.assertEqual(validate_severity("CrItIcAl"), "critical")
        self.assertEqual(validate_severity("HiGh"), "high")
        self.assertEqual(validate_severity("MeDiUm"), "medium")
        self.assertEqual(validate_severity("LoW"), "low")
        self.assertEqual(validate_severity("InFo"), "info")
        self.assertEqual(validate_severity("UnKnOwN"), "unknown")
        
        # Test whitespace variations
        self.assertEqual(validate_severity(" critical "), "critical")
        self.assertEqual(validate_severity("  high  "), "high")
        self.assertEqual(validate_severity("\tmedium\t"), "medium")
        self.assertEqual(validate_severity("\nlow\n"), "low")
        self.assertEqual(validate_severity(" info "), "info")
        self.assertEqual(validate_severity(" unknown "), "unknown")
        
        # Test mixed case with whitespace
        self.assertEqual(validate_severity(" Critical "), "critical")
        self.assertEqual(validate_severity("  HIGH  "), "high")
        self.assertEqual(validate_severity("\tMedium\t"), "medium")
        self.assertEqual(validate_severity("\nLOW\n"), "low")
        self.assertEqual(validate_severity(" INFO "), "info")
        self.assertEqual(validate_severity(" UNKNOWN "), "unknown")
        
        # Test complex mixed case with whitespace
        self.assertEqual(validate_severity(" CrItIcAl "), "critical")
        self.assertEqual(validate_severity("  HiGh  "), "high")
        self.assertEqual(validate_severity("\tMeDiUm\t"), "medium")
        self.assertEqual(validate_severity("\nLoW\n"), "low")
        self.assertEqual(validate_severity(" InFo "), "info")
        self.assertEqual(validate_severity(" UnKnOwN "), "unknown")
        
        # Test invalid cases
        self.assertIsNone(validate_severity("invalid"))
        self.assertIsNone(validate_severity(""))
        self.assertIsNone(validate_severity(None))
        self.assertIsNone(validate_severity(" "))
        self.assertIsNone(validate_severity("  "))
        self.assertIsNone(validate_severity("\t"))
        self.assertIsNone(validate_severity("\n"))
        self.assertIsNone(validate_severity("criticality"))  # Partial match
        self.assertIsNone(validate_severity("high-level"))  # Contains valid but not exact
        self.assertIsNone(validate_severity("medium_risk"))  # Contains valid but not exact

