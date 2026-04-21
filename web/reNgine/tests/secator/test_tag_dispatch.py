"""
Unit tests for Secator tag dispatch (get_tag_handler, is_tag_ignored, dispatch_secator_tag, Nuclei branch).
"""

from unittest.mock import MagicMock, patch

from reNgine.secator.tag_dispatch import (
    TAG_IGNORED,
    dispatch_secator_tag,
    get_tag_handler,
    is_registered_ignored_tag_pair,
    is_tag_ignored,
)
from reNgine.secator.tag_dispatch import nuclei as nuclei_mod
from reNgine.secator.tag_dispatch.handlers import handle_url_pattern_tag
from startScan.models import DNSRecord, Technology
from utils.test_base import BaseTestCase


class TestTagDispatchHandlers(BaseTestCase):
    """Test get_tag_handler, ignore registration, and source-aware ``is_tag_ignored``."""

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
        """Unknown (category, name) returns None (fallback or Nuclei branch)."""
        self.assertIsNone(get_tag_handler("unknown_cat", "unknown_name"))
        self.assertIsNone(get_tag_handler("info", "unknown_name"))

    def test_is_registered_ignored_tag_pair_netdetect(self):
        """net_interface and net_cidr are registered as ignorable (Secator netdetect)."""
        self.assertTrue(is_registered_ignored_tag_pair("info", "net_interface"))
        self.assertTrue(is_registered_ignored_tag_pair("info", "net_cidr"))

    def test_is_registered_ignored_tag_pair_prompt(self):
        """user_input is registered as ignorable (Secator prompt)."""
        self.assertTrue(is_registered_ignored_tag_pair("info", "user_input"))

    def test_is_tag_ignored_requires_matching_source(self):
        """Ignore rules with allowed_sources apply only when _source matches."""
        base = {"category": "info", "name": "net_interface", "match": "eth0", "value": "eth0"}
        self.assertFalse(is_tag_ignored({**base}))
        self.assertTrue(is_tag_ignored({**base, "_source": "netdetect"}))
        self.assertTrue(is_tag_ignored({**base, "_source": "NetDetect"}))

    def test_is_tag_not_ignored_whois(self):
        """whois is not a registered ignored pair."""
        self.assertFalse(is_registered_ignored_tag_pair("info", "whois"))

    def test_tag_ignored_set_content(self):
        """TAG_IGNORED contains expected pairs."""
        self.assertIn(("info", "net_interface"), TAG_IGNORED)
        self.assertIn(("info", "net_cidr"), TAG_IGNORED)
        self.assertIn(("info", "user_input"), TAG_IGNORED)


class TestNucleiTagClassification(BaseTestCase):
    """Unit tests for Nuclei tag classification helpers."""

    def test_is_nuclei_tag_true_when_source_nuclei(self):
        self.assertTrue(nuclei_mod.is_nuclei_tag({"_source": "nuclei", "category": "info", "name": "x"}))

    def test_is_nuclei_tag_false_other_source(self):
        self.assertFalse(nuclei_mod.is_nuclei_tag({"_source": "wappalyzer", "category": "info", "name": "x"}))

    def test_is_nuclei_technology_tag_allowlist_intersection(self):
        payload = {
            "_source": "nuclei",
            "extra_data": {"tags": ["tech", "discovery"]},
            "name": "tpl-id",
        }
        self.assertTrue(nuclei_mod.is_nuclei_technology_tag(payload))

    def test_is_nuclei_technology_tag_false_without_allowlist_tag(self):
        payload = {
            "_source": "nuclei",
            "extra_data": {"tags": ["misconfig", "http"]},
            "name": "http-missing-security-headers",
        }
        self.assertFalse(nuclei_mod.is_nuclei_technology_tag(payload))

    def test_build_nuclei_technology_item_uses_value_first_line(self):
        payload = {
            "_source": "nuclei",
            "name": "wappalyzer-nginx",
            "value": "Nginx\n1.18",
            "extra_data": {"tags": ["tech"], "template_id": "wappalyzer-nginx"},
        }
        item = nuclei_mod.build_nuclei_technology_item(payload)
        self.assertEqual(item["name"], "Nginx")

    def test_build_nuclei_technology_item_falls_back_to_template_id(self):
        payload = {
            "_source": "nuclei",
            "name": "wappalyzer-nginx",
            "value": "",
            "extra_data": {"tags": ["tech"], "template_id": "wappalyzer-nginx", "data": []},
        }
        item = nuclei_mod.build_nuclei_technology_item(payload)
        self.assertEqual(item["name"], "wappalyzer-nginx")

    def test_should_route_dns_when_extra_type_dns(self):
        self.assertTrue(
            nuclei_mod.should_route_nuclei_tag_to_dns_record(
                {"extra_data": {"type": "dns", "template_id": "spf-record-detect"}},
            )
        )

    def test_should_route_dns_when_nuclei_and_dns_tag(self):
        self.assertTrue(
            nuclei_mod.should_route_nuclei_tag_to_dns_record(
                {
                    "_source": "nuclei",
                    "extra_data": {"tags": ["dns", "discovery"], "template_id": "nameserver-fingerprint"},
                },
            )
        )

    def test_should_not_route_dns_without_type_or_nuclei_dns_tag(self):
        self.assertFalse(
            nuclei_mod.should_route_nuclei_tag_to_dns_record(
                {"_source": "nuclei", "extra_data": {"tags": ["http", "misconfig"]}},
            )
        )

    def test_infer_nuclei_dns_record_type_from_template_id(self):
        base = {"_source": "nuclei", "extra_data": {"type": "dns"}}
        self.assertEqual(
            nuclei_mod.infer_nuclei_dns_record_type({**base, "name": "mx-fingerprint"}),
            "MX",
        )
        self.assertEqual(
            nuclei_mod.infer_nuclei_dns_record_type(
                {**base, "name": "x", "extra_data": {**base["extra_data"], "template_id": "caa-fingerprint"}}
            ),
            "CAA",
        )

    def test_build_nuclei_dns_record_item_record_shape(self):
        item = nuclei_mod.build_nuclei_dns_record_item(
            {
                "match": "dns.example.com",
                "value": "v=spf1 -all",
                "_source": "nuclei",
                "extra_data": {
                    "type": "dns",
                    "tags": ["dns", "spf"],
                    "template_id": "spf-record-detect",
                    "data": ["v=spf1 -all"],
                },
            }
        )
        self.assertEqual(item["_type"], "record")
        self.assertEqual(item["name"], "dns.example.com")
        self.assertEqual(item["type"], "TXT")
        self.assertEqual(item["host"], "v=spf1 -all")
        self.assertEqual(item["_source"], "nuclei")


class TestDispatchSecatorTag(BaseTestCase):
    """Test dispatch_secator_tag outcomes (ignored, success, error, fallback)."""

    def _validate_ok(self, scan_history_id, target_id):
        return (True, None, MagicMock(), self.data_generator.target)

    def test_dispatch_returns_ignored_for_net_interface(self):
        """Ignored tag from Secator netdetect returns ('ignored', synthetic_id)."""
        result = dispatch_secator_tag(
            {
                "category": "info",
                "name": "net_interface",
                "match": "eth0",
                "value": "eth0",
                "_source": "netdetect",
            },
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "ignored")
        self.assertIsInstance(result[1], str)
        self.assertIn("tag_ignored", result[1])

    def test_dispatch_net_interface_without_secator_source_is_not_ignored(self):
        """Same category/name without matching _source is not ignored (no accidental suppression)."""
        result = dispatch_secator_tag(
            {"category": "info", "name": "net_interface", "match": "eth0", "value": "eth0"},
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "fallback")

    def test_dispatch_returns_fallback_for_unknown_tag(self):
        """Unknown (category, name) without Nuclei source returns ('fallback',)."""
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

    def test_dispatch_nuclei_non_tech_returns_ignored(self):
        """Nuclei tag without technology allowlist tags is not persisted as Technology."""
        result = dispatch_secator_tag(
            {
                "category": "info",
                "name": "http-missing-security-headers",
                "match": "https://disc.example.com/",
                "_source": "nuclei",
                "extra_data": {"tags": ["misconfig", "http"], "template_id": "http-missing-security-headers"},
            },
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "ignored")
        self.assertIsInstance(result[1], str)
        self.assertIn("nuclei_non_tech", result[1])

    def test_dispatch_nuclei_tech_saves_technology(self):
        """Nuclei tag with tech tags persists Technology with name from extracted value."""
        host = "nuclei-tech.example.com"
        self.data_generator.create_subdomain(name=host)
        result = dispatch_secator_tag(
            {
                "category": "info",
                "name": "wappalyzer-fake-tpl",
                "match": host,
                "value": "TestProduct",
                "_source": "nuclei",
                "extra_data": {"tags": ["tech", "wappalyzer"], "template_id": "wappalyzer-fake-tpl"},
            },
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "success")
        self.assertIsInstance(result[1], Technology)
        self.assertEqual(result[1].name, "TestProduct")

    def test_dispatch_nuclei_dns_saves_dns_record(self):
        """Nuclei DNS templates persist as DNSRecord via DnsRepository (not Technology)."""
        domain = self.data_generator.create_domain()
        domain.name = self.data_generator.target.value
        domain.save(update_fields=["name"])
        domain_info = self.data_generator.create_domain_info()
        domain.domain_info = domain_info
        domain.save()

        target_host = (self.data_generator.target.value or "").strip()
        result = dispatch_secator_tag(
            {
                "category": "info",
                "name": "spf-record-detect",
                "match": target_host,
                "value": "v=spf1 -all",
                "_source": "nuclei",
                "extra_data": {
                    "type": "dns",
                    "tags": ["dns", "spf", "discovery"],
                    "template_id": "spf-record-detect",
                    "data": ["v=spf1 -all"],
                },
            },
            self.data_generator.scan_history.id,
            self.data_generator.target.id,
            self._validate_ok,
            is_update=False,
        )
        self.assertEqual(result[0], "success")
        self.assertIsInstance(result[1], DNSRecord)
        self.assertEqual(result[1].type, "TXT")
        self.assertEqual(result[1].name, target_host)

    def test_dispatch_propagates_handler_error_status(self):
        """When a tag handler returns a specific HTTP status, dispatch must not replace it."""

        def fake_handler(_data, _sh_id, _t_id):
            return (None, 404)

        def validate_ok(sh_id, t_id):
            return (True, None, MagicMock(), self.data_generator.target)

        with patch("reNgine.secator.tag_dispatch.dispatch.get_tag_handler", return_value=fake_handler):
            result = dispatch_secator_tag(
                {"category": "url_pattern", "name": "xss", "match": "https://a.example/", "value": ""},
                self.data_generator.scan_history.id,
                self.data_generator.target.id,
                validate_ok,
                is_update=True,
            )
        self.assertEqual(result[0], "error")
        self.assertEqual(result[1], 404)
        self.assertIn("url_pattern", result[2])
        self.assertIn("xss", result[2])

    @patch("reNgine.services.repositories.endpoint_repository.EndpointRepository")
    def test_handle_url_pattern_coerces_non_string_match_and_name(self, mock_repo_class):
        """Non-string match/value/name must not raise when coerced for repository call."""
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        saved = object()
        mock_repo.add_gf_pattern_from_secator_tag.return_value = saved

        obj, err = handle_url_pattern_tag(
            {"match": 443, "name": ["n1", "n2"], "category": "url_pattern"},
            1,
            2,
        )
        self.assertIs(obj, saved)
        self.assertIsNone(err)
        mock_repo.add_gf_pattern_from_secator_tag.assert_called_once_with(1, 2, "443", "['n1', 'n2']")

    @patch("reNgine.services.repositories.endpoint_repository.EndpointRepository")
    def test_handle_url_pattern_numeric_zero_skips_to_value(self, mock_repo_class):
        """Integer 0 in match must follow Python ``or`` semantics and fall through to value."""
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        mock_repo.add_gf_pattern_from_secator_tag.return_value = object()
        handle_url_pattern_tag(
            {"match": 0, "value": "https://scan.example/path", "name": "xss", "category": "url_pattern"},
            1,
            2,
        )
        mock_repo.add_gf_pattern_from_secator_tag.assert_called_once_with(
            1,
            2,
            "https://scan.example/path",
            "xss",
        )
