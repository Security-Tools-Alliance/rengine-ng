"""
Unit tests for Secator tag routing (get_tag_handler, is_tag_ignored, dispatch_secator_tag).
"""

from unittest.mock import MagicMock

from reNgine.secator.tag_routing import (
    TAG_IGNORED,
    dispatch_secator_tag,
    get_tag_handler,
    is_tag_ignored,
)
from utils.test_base import BaseTestCase


class TestTagRoutingHandlers(BaseTestCase):
    """Test get_tag_handler and is_tag_ignored."""

    def test_get_tag_handler_whois(self):
        """Handler for (info, whois) is registered."""
        handler = get_tag_handler("info", "whois")
        self.assertIsNotNone(handler)
        self.assertTrue(callable(handler))

    def test_get_tag_handler_url_pattern_any_name(self):
        """Handler for (url_pattern, *) is registered (category-only)."""
        handler = get_tag_handler("url_pattern", "xss")
        self.assertIsNotNone(handler)
        handler = get_tag_handler("url_pattern", "idor")
        self.assertIsNotNone(handler)

    def test_get_tag_handler_asn(self):
        """Handler for (info, asn) is registered."""
        handler = get_tag_handler("info", "asn")
        self.assertIsNotNone(handler)

    def test_get_tag_handler_secret_any_name(self):
        """Handler for (secret, *) is registered (category-only)."""
        handler = get_tag_handler("secret", "aws_access_key")
        self.assertIsNotNone(handler)
        self.assertTrue(callable(handler))
        handler = get_tag_handler("secret", "generic_api_key")
        self.assertIsNotNone(handler)

    def test_get_tag_handler_unknown_returns_none(self):
        """Unknown (category, name) returns None (fallback to Technology)."""
        self.assertIsNone(get_tag_handler("unknown_cat", "unknown_name"))
        self.assertIsNone(get_tag_handler("info", "unknown_name"))

    def test_is_tag_ignored_netdetect(self):
        """net_interface and net_cidr are ignored."""
        self.assertTrue(is_tag_ignored("info", "net_interface"))
        self.assertTrue(is_tag_ignored("info", "net_cidr"))

    def test_is_tag_ignored_prompt(self):
        """user_input (prompt) is ignored."""
        self.assertTrue(is_tag_ignored("info", "user_input"))

    def test_is_tag_not_ignored_whois(self):
        """whois is not ignored."""
        self.assertFalse(is_tag_ignored("info", "whois"))

    def test_tag_ignored_set_content(self):
        """TAG_IGNORED contains expected pairs."""
        self.assertIn(("info", "net_interface"), TAG_IGNORED)
        self.assertIn(("info", "net_cidr"), TAG_IGNORED)
        self.assertIn(("info", "user_input"), TAG_IGNORED)


class TestDispatchSecatorTag(BaseTestCase):
    """Test dispatch_secator_tag outcomes (ignored, success, error, fallback)."""

    def _validate_ok(self, scan_history_id, target_id):
        return (True, None, MagicMock(), self.data_generator.target)

    def test_dispatch_returns_ignored_for_net_interface(self):
        """Ignored tag returns ('ignored', synthetic_id)."""
        result = dispatch_secator_tag(
            {"category": "info", "name": "net_interface", "match": "eth0", "value": "eth0"},
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "ignored")
        self.assertIsInstance(result[1], str)
        self.assertIn("tag_ignored", result[1])

    def test_dispatch_returns_fallback_for_unknown_tag(self):
        """Unknown (category, name) returns ('fallback',)."""
        result = dispatch_secator_tag(
            {"category": "other", "name": "other_tag", "match": "x", "value": "y"},
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "fallback")

    def test_dispatch_whois_success_returns_success(self):
        """Whois tag with valid context returns success and DomainInfo (domain created if needed)."""
        finding_data = {
            "category": "info",
            "name": "whois",
            "match": "example.com",
            "value": "raw whois text",
        }
        result = dispatch_secator_tag(
            finding_data,
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "success")
        self.assertIsNotNone(result[1])
        self.assertIsNotNone(getattr(result[1], "id", None))

    def test_dispatch_secret_success_returns_secret(self):
        """Secret tag with valid context returns success and Secret instance."""
        finding_data = {
            "category": "secret",
            "name": "aws_access_key",
            "match": "file.go:10:5",
            "value": "AKIAIOSFODNN7EXAMPLE",
            "_context": {
                "scan_history_id": self.data_generator.scan_history.id,
                "target_id": self.data_generator.target.id,
            },
        }
        result = dispatch_secator_tag(
            finding_data,
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "success")
        self.assertIsNotNone(result[1])
        from startScan.models import Secret

        self.assertIsInstance(result[1], Secret)
        self.assertEqual(result[1].rule_name, "aws_access_key")
        self.assertEqual(result[1].value, "AKIAIOSFODNN7EXAMPLE")

    def test_dispatch_whois_out_of_scope_returns_skipped(self):
        """Whois tag with domain out of scope (restrict_findings_to_target) returns ('skipped', synthetic_id)."""
        self.data_generator.create_organization()
        self.data_generator.create_scope(restrict_findings_to_target=True, allowed_finding_domains=[])
        target = self.data_generator.target
        scan_history = self.data_generator.create_scan_history()

        def validate_ok(sh_id, t_id):
            return (True, None, MagicMock(), target)

        finding_data = {
            "category": "info",
            "name": "whois",
            "match": "out-of-scope-unrelated.com",
            "value": "raw whois text",
        }
        result = dispatch_secator_tag(
            finding_data,
            scan_history.id,
            target.id,
            validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "skipped")
        self.assertIsInstance(result[1], str)
        self.assertIn("skipped_scope", result[1])
