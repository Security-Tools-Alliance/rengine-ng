"""Tests for Secator hook payload source extraction helpers."""

from reNgine.secator.source_extraction import extract_secator_tool_source, merge_subdomain_sources_from_item
from utils.test_base import BaseTestCase


class TestSourceExtraction(BaseTestCase):
    """Unit tests for extract_secator_tool_source and merge_subdomain_sources_from_item."""

    def test_extract_prefers_provider_when_present(self) -> None:
        item = {"provider": "nuclei", "_source": "httpx", "_context": {"runner_name": "r"}}
        self.assertEqual(extract_secator_tool_source(item), "nuclei")

    def test_extract_uses_source_when_no_provider(self) -> None:
        item = {"_source": "dnsx"}
        self.assertEqual(extract_secator_tool_source(item, include_provider=False), "dnsx")

    def test_extract_falls_back_to_context_runner_name(self) -> None:
        item = {"_context": {"runner_name": "workflow_recon"}}
        self.assertEqual(extract_secator_tool_source(item, include_provider=False), "workflow_recon")

    def test_extract_truncates_to_max_length(self) -> None:
        long_src = "x" * 250
        item = {"_source": long_src}
        out = extract_secator_tool_source(item, include_provider=False, max_length=200)
        self.assertEqual(len(out or ""), 200)

    def test_extract_non_dict_returns_none(self) -> None:
        self.assertIsNone(extract_secator_tool_source("not-a-dict"))  # type: ignore[arg-type]

    def test_merge_subdomain_sources_appends_underscore_source(self) -> None:
        item = {"_source": "httpx"}
        merged = merge_subdomain_sources_from_item(["subfinder"], item)
        self.assertEqual(merged, ["subfinder", "httpx"])

    def test_merge_subdomain_sources_skips_duplicate_underscore_source(self) -> None:
        item = {"_source": "amass"}
        merged = merge_subdomain_sources_from_item(["amass", "subfinder"], item)
        self.assertEqual(merged, ["amass", "subfinder"])
