"""Tests for shared endpoint ingestion log suffix formatting."""

from reNgine.utilities.endpoint_ingest_logging import format_endpoint_host_unresolved_suffix
from utils.test_base import BaseTestCase


class FormatEndpointHostUnresolvedSuffixTest(BaseTestCase):
    def test_includes_hostname_override_when_provided(self) -> None:
        s = format_endpoint_host_unresolved_suffix(
            9,
            "https://a.example/x",
            hostname_override="b.example",
            reason="resolver_exception",
        )
        self.assertIn("scan_id=9", s)
        self.assertIn("hostname_override=b.example", s)
        self.assertIn("reason=resolver_exception", s)
        self.assertIn("url=", s)

    def test_omits_hostname_override_key_when_not_passed(self) -> None:
        s = format_endpoint_host_unresolved_suffix(1, "http://x/", reason="ip_row_not_created")
        self.assertNotIn("hostname_override", s)
        self.assertIn("reason=ip_row_not_created", s)
