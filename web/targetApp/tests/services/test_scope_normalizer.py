"""Tests for scope normalizer (parse_scope_raw_input, strip_trailing_port)."""

from targetApp.services.scope_normalizer import parse_scope_raw_input, strip_trailing_port
from utils.test_base import BaseTestCase


class StripTrailingPortTest(BaseTestCase):
    """Tests for strip_trailing_port helper."""

    def test_empty_returns_empty(self) -> None:
        self.assertEqual(strip_trailing_port(""), "")
        self.assertEqual(strip_trailing_port("   "), "   ")

    def test_no_port_unchanged(self) -> None:
        self.assertEqual(strip_trailing_port("example.com"), "example.com")
        self.assertEqual(strip_trailing_port("sub.example.com"), "sub.example.com")

    def test_host_port_stripped(self) -> None:
        self.assertEqual(strip_trailing_port("example.com:443"), "example.com")
        self.assertEqual(strip_trailing_port("api.example.com:8080"), "api.example.com")

    def test_ip_port_stripped(self) -> None:
        self.assertEqual(strip_trailing_port("10.0.0.1:8080"), "10.0.0.1")

    def test_ipv6_bracketed_port_stripped(self) -> None:
        self.assertEqual(strip_trailing_port("[::1]:443"), "::1")
        self.assertEqual(strip_trailing_port("[2001:db8::1]:80"), "2001:db8::1")

    def test_ipv6_no_port_unchanged(self) -> None:
        self.assertEqual(strip_trailing_port("[::1]"), "[::1]")
        self.assertEqual(strip_trailing_port("2001:db8::1"), "2001:db8::1")

    def test_host_with_colon_no_digit_port_unchanged(self) -> None:
        self.assertEqual(strip_trailing_port("2001:db8::1"), "2001:db8::1")


class ScopeNormalizerParseTest(BaseTestCase):
    """Tests for parse_scope_raw_input."""

    def test_empty_string_returns_empty_lists(self) -> None:
        result = parse_scope_raw_input("")
        self.assertEqual(result.domain_targets, ())
        self.assertEqual(result.ip_targets, ())
        self.assertEqual(result.allowed_finding_hosts, ())

    def test_none_and_whitespace_only_returns_empty(self) -> None:
        for raw in (None, "   ", "\n\n", "\t"):
            result = parse_scope_raw_input(raw)  # type: ignore[arg-type]
            self.assertEqual(result.domain_targets, ())
            self.assertEqual(result.ip_targets, ())
            self.assertEqual(result.allowed_finding_hosts, ())

    def test_single_domain_extracts_root_and_host(self) -> None:
        result = parse_scope_raw_input("sub.example.com")
        self.assertEqual(result.domain_targets, ("example.com",))
        self.assertEqual(result.allowed_finding_hosts, ("sub.example.com",))
        self.assertEqual(result.ip_targets, ())

    def test_comma_separated_domains_deduplicates_roots(self) -> None:
        result = parse_scope_raw_input("a.example.com, b.example.com, c.other.com")
        self.assertCountEqual(result.domain_targets, ("example.com", "other.com"))
        self.assertCountEqual(
            result.allowed_finding_hosts,
            ("a.example.com", "b.example.com", "c.other.com"),
        )
        self.assertEqual(result.ip_targets, ())

    def test_newline_separated_same_as_comma(self) -> None:
        result = parse_scope_raw_input("sub1.example.com\nsub2.example.com")
        self.assertEqual(result.domain_targets, ("example.com",))
        self.assertCountEqual(
            result.allowed_finding_hosts,
            ("sub1.example.com", "sub2.example.com"),
        )

    def test_mixed_comma_newline_deduplicates(self) -> None:
        result = parse_scope_raw_input("x.example.com, y.example.com\nx.example.com")
        self.assertEqual(result.domain_targets, ("example.com",))
        self.assertEqual(result.allowed_finding_hosts, ("x.example.com", "y.example.com"))

    def test_valid_ip_in_ip_targets_and_allowed_hosts(self) -> None:
        result = parse_scope_raw_input("192.168.1.1")
        self.assertEqual(result.domain_targets, ())
        self.assertEqual(result.ip_targets, ("192.168.1.1",))
        self.assertEqual(result.allowed_finding_hosts, ("192.168.1.1",))

    def test_mixed_domains_and_ips(self) -> None:
        result = parse_scope_raw_input("api.example.com\n10.0.0.1\nwww.example.com")
        self.assertCountEqual(result.domain_targets, ("example.com",))
        self.assertEqual(result.ip_targets, ("10.0.0.1",))
        self.assertCountEqual(
            result.allowed_finding_hosts,
            ("api.example.com", "10.0.0.1", "www.example.com"),
        )

    def test_user_example_two_root_domains(self) -> None:
        raw = "ennov8dev.domain-example.com, carlprodamericas.novocol.com, itsupport.domain-example.com, ennov.novocol.com, ennov.domain-example.com"
        result = parse_scope_raw_input(raw)
        self.assertCountEqual(result.domain_targets, ("domain-example.com", "novocol.com"))
        self.assertIn("ennov8dev.domain-example.com", result.allowed_finding_hosts)
        self.assertIn("carlprodamericas.novocol.com", result.allowed_finding_hosts)
        self.assertIn("itsupport.domain-example.com", result.allowed_finding_hosts)
        self.assertIn("ennov.novocol.com", result.allowed_finding_hosts)
        self.assertIn("ennov.domain-example.com", result.allowed_finding_hosts)
        self.assertEqual(len(result.allowed_finding_hosts), 5)
        self.assertEqual(result.ip_targets, ())

    def test_strip_and_lower(self) -> None:
        result = parse_scope_raw_input("  SUB.Example.COM  ")
        self.assertEqual(result.domain_targets, ("example.com",))
        self.assertEqual(result.allowed_finding_hosts, ("sub.example.com",))

    def test_host_port_stripped_before_validation(self) -> None:
        result = parse_scope_raw_input("example.com:443")
        self.assertEqual(result.domain_targets, ("example.com",))
        self.assertEqual(result.allowed_finding_hosts, ("example.com",))
        self.assertEqual(result.ip_targets, ())

    def test_ip_port_stripped_before_validation(self) -> None:
        result = parse_scope_raw_input("10.0.0.1:8080")
        self.assertEqual(result.domain_targets, ())
        self.assertEqual(result.ip_targets, ("10.0.0.1",))
        self.assertEqual(result.allowed_finding_hosts, ("10.0.0.1",))

    def test_host_port_with_whitespace_normalized(self) -> None:
        result = parse_scope_raw_input("  api.example.com:443  ")
        self.assertEqual(result.domain_targets, ("example.com",))
        self.assertEqual(result.allowed_finding_hosts, ("api.example.com",))

    def test_ipv6_bracketed_with_port_stripped(self) -> None:
        result = parse_scope_raw_input("[::1]:443")
        self.assertEqual(result.domain_targets, ())
        self.assertEqual(result.ip_targets, ("::1",))
        self.assertEqual(result.allowed_finding_hosts, ("::1",))

    def test_bare_ipv6_without_port_unchanged(self) -> None:
        result = parse_scope_raw_input("2001:db8::1")
        self.assertEqual(result.domain_targets, ())
        self.assertEqual(result.ip_targets, ("2001:db8::1",))
        self.assertEqual(result.allowed_finding_hosts, ("2001:db8::1",))
