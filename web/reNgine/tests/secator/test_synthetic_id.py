"""
Tests for synthetic_id_skipped_scope (centralized skipped-scope ID generation).
"""

import unittest

from reNgine.secator.synthetic_id import synthetic_id_skipped_scope


class TestSyntheticIdSkippedScope(unittest.TestCase):
    """Tests for synthetic_id_skipped_scope format and centralization."""

    def test_generic_finding_format(self):
        """Generic finding (e.g. certificate, record) uses skipped_scope_<type>_<ts>."""
        sid = synthetic_id_skipped_scope("certificate")
        self.assertTrue(sid.startswith("skipped_scope_certificate_"))
        parts = sid.split("_")
        self.assertGreaterEqual(len(parts), 4)
        self.assertEqual(parts[0], "skipped")
        self.assertEqual(parts[1], "scope")
        self.assertEqual(parts[2], "certificate")
        self.assertTrue(parts[-1].isdigit(), "last segment must be timestamp ms")

    def test_tag_finding_format(self):
        """Tag finding uses skipped_scope_tag_<category>_<name>_<ts>."""
        sid = synthetic_id_skipped_scope("tag", tag_category="info", tag_name="whois")
        self.assertTrue(sid.startswith("skipped_scope_tag_info_whois_"))
        parts = sid.split("_")
        self.assertGreaterEqual(len(parts), 5)
        self.assertEqual(parts[0], "skipped")
        self.assertEqual(parts[1], "scope")
        self.assertEqual(parts[2], "tag")
        self.assertEqual(parts[3], "info")
        self.assertEqual(parts[4], "whois")
        self.assertTrue(parts[-1].isdigit(), "last segment must be timestamp ms")

    def test_common_prefix_for_parsing(self):
        """All IDs share prefix skipped_scope_ for downstream parsing."""
        sid_gen = synthetic_id_skipped_scope("subdomain")
        sid_tag = synthetic_id_skipped_scope("tag", tag_category="info", tag_name="asn")
        self.assertTrue(sid_gen.startswith("skipped_scope_"))
        self.assertTrue(sid_tag.startswith("skipped_scope_"))

    def test_timestamp_is_numeric_ms(self):
        """Timestamp segment is numeric (milliseconds since epoch)."""
        sid = synthetic_id_skipped_scope("record")
        ts_part = sid.split("_")[-1]
        self.assertTrue(ts_part.isdigit(), "timestamp must be digits")
        self.assertGreater(int(ts_part), 0)
