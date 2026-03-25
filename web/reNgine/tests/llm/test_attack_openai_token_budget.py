from unittest.mock import patch

from django.test import SimpleTestCase

from reNgine.llm.config import (
    DEFAULT_OPENAI_MAX_TOKENS_AGGREGATE,
    DEFAULT_OPENAI_MAX_TOKENS_SCAN_HISTORY,
    LLM_CONFIG,
)
from reNgine.llm.llm import LLMAttackSuggestionGenerator
from reNgine.llm.validators import LLMProvider


class AttackOpenAiTokenBudgetTests(SimpleTestCase):
    def _make_generator(self) -> LLMAttackSuggestionGenerator:
        # Avoid DB access by forcing a model name.
        with (
            patch("reNgine.llm.llm.get_default_llm_model", return_value="gpt-4"),
            patch("reNgine.llm.llm.get_open_ai_key", return_value=None),
        ):
            return LLMAttackSuggestionGenerator(provider=LLMProvider.OPENAI)

    def test_target_uses_aggregate_max_tokens(self) -> None:
        gen = self._make_generator()
        allowed = gen._build_attack_openai_chat_kwargs("target")

        openai_cfg = LLM_CONFIG["providers"]["openai"]
        expected = openai_cfg.get("max_tokens_aggregate", DEFAULT_OPENAI_MAX_TOKENS_AGGREGATE)
        self.assertEqual(allowed.get("max_tokens"), expected)

    def test_scan_history_uses_dedicated_scan_history_max_tokens(self) -> None:
        gen = self._make_generator()
        allowed = gen._build_attack_openai_chat_kwargs("scan_history")

        openai_cfg = LLM_CONFIG["providers"]["openai"]
        expected = openai_cfg.get("max_tokens_scan_history", DEFAULT_OPENAI_MAX_TOKENS_SCAN_HISTORY)
        self.assertEqual(allowed.get("max_tokens"), expected)

    def test_asset_uses_provider_default_max_tokens(self) -> None:
        gen = self._make_generator()
        allowed = gen._build_attack_openai_chat_kwargs("asset")

        openai_cfg = LLM_CONFIG["providers"]["openai"]
        expected = openai_cfg.get("max_tokens")
        self.assertEqual(allowed.get("max_tokens"), expected)
