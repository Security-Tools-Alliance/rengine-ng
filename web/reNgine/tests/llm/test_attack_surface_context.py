"""Tests for aggregate LLM attack-surface context builders."""

from unittest.mock import patch

from utils.test_base import BaseTestCase


class AttackSurfaceContextBuilderTests(BaseTestCase):
    def test_build_context_for_target_includes_header_and_target_id(self) -> None:
        from reNgine.llm.attack_surface_context import build_context_for_target

        target = self.data_generator.target
        text = build_context_for_target(target)
        self.assertIn("Analysis level: single Target", text)
        self.assertIn("Target id=%s" % (target.id,), text)
        self.assertIn("=== SUBDOMAINS ===", text)

    def test_subdomain_list_truncation_notice_when_cap_exceeded(self) -> None:
        from reNgine.llm.attack_surface_context import build_context_for_target

        self.data_generator.create_subdomain(name="extra.anon.example.com")
        with patch("reNgine.llm.attack_surface_context.MAX_SUBDOMAINS_IN_CONTEXT", 1):
            text = build_context_for_target(self.data_generator.target)
        self.assertIn("more subdomains exist", text)
        self.assertIn("truncated", text.lower())
