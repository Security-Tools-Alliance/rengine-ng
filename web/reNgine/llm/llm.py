from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from langchain_ollama import OllamaLLM as Ollama
import openai

from reNgine.llm.config import (
    ATTACK_SUGGESTION_LLM_SYSTEM_PROMPT,
    DEFAULT_OPENAI_MAX_TOKENS_AGGREGATE,
    LLM_CONFIG,
)
from reNgine.llm.utils import get_default_llm_model
from reNgine.llm.validators import LLMProvider, LLMResponse
from reNgine.utilities.error import get_safe_user_message
from reNgine.utilities.external import get_open_ai_key
from reNgine.utilities.logger import get_module_logger


PREFIX_LLM = "[LLM]"
logger = get_module_logger(__name__)

# OpenAI aggregate prompts (target / scope / organization) use max_tokens_aggregate.
ATTACK_PROMPT_KEYS_OPENAI_AGGREGATE = frozenset({"target", "scope", "organization"})


class BaseLLMGenerator(ABC):
    """Base class for LLM generators with common functionality"""

    def __init__(self, provider: Optional[LLMProvider] = None):
        """Initialize the LLM generator with optional provider"""
        self.api_key = get_open_ai_key()
        self.config = LLM_CONFIG
        self.model_name = self._get_model_name()
        self.provider = provider or self._get_default_provider()
        self.ollama = None

        if self.provider == LLMProvider.OLLAMA:
            self._setup_ollama()

    @abstractmethod
    def _get_model_name(self) -> str:
        """Get the model name to use"""
        pass

    @abstractmethod
    def _get_default_provider(self) -> LLMProvider:
        """Get the default provider based on configuration"""
        pass

    def _setup_ollama(self) -> None:
        """Setup Ollama client with configuration"""
        ollama_config = self.config["providers"]["ollama"]
        self.ollama = Ollama(base_url=ollama_config["url"], model=self.model_name, timeout=ollama_config["timeout"])

    def _validate_input(self, input_data: str, model_name: str = None) -> str:
        """Validate input data using Pydantic model"""
        if not input_data or not isinstance(input_data, str):
            raise ValueError("Input data must be a non-empty string")

        # Additional model validation if provided
        if model_name and not isinstance(model_name, str):
            raise ValueError("Model name must be a string")

        return input_data


class LLMVulnerabilityReportGenerator(BaseLLMGenerator):
    """Generator for vulnerability reports using LLM"""

    def _get_model_name(self) -> str:
        """Get model name from database or default"""
        return get_default_llm_model()

    def _get_default_provider(self) -> LLMProvider:
        """Get default provider based on model requirements"""
        model_name = self._get_model_name()
        if model_name in self.config["providers"]["openai"]["models"]:
            return LLMProvider.OPENAI
        return LLMProvider.OLLAMA

    def _get_provider_config(self) -> Dict[str, Any]:
        """Get provider specific configuration"""
        provider_key = self.provider.value
        return self.config["providers"][provider_key]

    def _validate_input(self, input_data: str, model_name: str = None) -> str:
        """Validate the input data and model name"""
        if not input_data or not isinstance(input_data, str):
            raise ValueError("Input data must be a non-empty string")

        # Additional model validation if provided
        if model_name and not isinstance(model_name, str):
            raise ValueError("Model name must be a string")

        return input_data

    def get_vulnerability_report(self, description: str, model_name: str = None) -> dict:
        """
        Generate vulnerability report using LLM by asking specific questions for each section

        Args:
            description: Raw vulnerability description
            model_name: Optional model name to use

        Returns:
            dict: Response containing structured data
        """
        try:
            validated_input = self._validate_input(description, model_name)
            vulnerability_prompt = LLM_CONFIG["prompts"]["vulnerability"]
            context = vulnerability_prompt["context"]

            # Generate each section separately
            technical = self._get_section_response(validated_input, context + vulnerability_prompt["technical"])
            impact = self._get_section_response(validated_input, context + vulnerability_prompt["impact"])
            remediation = self._get_section_response(validated_input, context + vulnerability_prompt["remediation"])
            references = self._get_section_response(validated_input, context + vulnerability_prompt["references"])

            # Combine sections into a single response
            response = {
                "description": technical,
                "impact": impact,
                "remediation": remediation,
                "references": references,
            }

            logger.log_line(
                PREFIX_LLM,
                "VULN_REPORT",
                "Response: %s" % (response,),
                level="debug",
            )
            return LLMResponse(status=True, **response).to_dict()

        except Exception as e:
            logger.log_line(
                PREFIX_LLM,
                "VULN_REPORT",
                "Error in get_vulnerability_report: %s" % (e,),
                level="error",
                exc_info=True,
            )
            return LLMResponse(status=False, error=str(e)).to_dict()

    def _get_section_response(self, input_data: str, prompt: str) -> str:
        """
        Get response for a specific section using LLM

        Args:
            input_data: Validated input data
            prompt: Specific prompt for the section

        Returns:
            str: Response content for the section
        """
        try:
            if self.provider == LLMProvider.OLLAMA:
                response_content = self._get_ollama_response(prompt, input_data)
            else:
                response_content = self._get_openai_response(prompt, input_data, model_name=None)

            # Clean and return the response
            return response_content.strip()

        except Exception as e:
            logger.log_line(
                PREFIX_LLM,
                "SECTION_RESPONSE",
                "Error in _get_section_response: %s" % (e,),
                level="error",
            )
            return ""

    def _get_ollama_response(self, prompt: str, description: str) -> str:
        """Get response from Ollama"""
        prompt = "%s\nUser: %s" % (prompt, description)
        logger.log_line(PREFIX_LLM, "OLLAMA", "Ollama Prompt: %s" % (prompt,), level="debug")
        response = self.ollama(prompt)
        logger.log_line(PREFIX_LLM, "OLLAMA", "Ollama Response: %s" % (response,), level="debug")
        return str(response) if response is not None else ""

    def _get_openai_response(self, prompt: str, description: str, model_name: str = None) -> str:
        """Get response from OpenAI"""
        if not self.api_key:
            raise ValueError("OpenAI API Key not set")

        openai.api_key = self.api_key

        # Only forward supported OpenAI parameters
        provider_config = self._get_provider_config()
        openai_supported_kwargs = {}
        for key in ["max_tokens", "temperature"]:
            if key in provider_config:
                openai_supported_kwargs[key] = provider_config[key]

        response = openai.ChatCompletion.create(
            model=model_name or self.model_name,
            messages=[{"role": "system", "content": prompt}, {"role": "user", "content": description}],
            **openai_supported_kwargs,
        )
        return response["choices"][0]["message"]["content"]


class LLMAttackSuggestionGenerator(BaseLLMGenerator):
    """Generator for attack suggestions using LLM"""

    def _get_model_name(self) -> str:
        """Get model name from database or default"""
        return get_default_llm_model()

    def _get_default_provider(self) -> LLMProvider:
        """Get default provider based on model requirements"""
        model_name = self._get_model_name()
        if model_name in self.config["providers"]["openai"]["models"]:
            return LLMProvider.OPENAI
        return LLMProvider.OLLAMA

    def _get_provider_config(self) -> Dict[str, Any]:
        """Get provider specific configuration"""
        provider_key = self.provider.value
        return self.config["providers"][provider_key]

    def _validate_input(self, input_data: str, model_name: str = None) -> str:
        """Validate the input data and model name"""
        if not input_data or not isinstance(input_data, str):
            raise ValueError("Input data must be a non-empty string")

        # Additional model validation if provided
        if model_name and not isinstance(model_name, str):
            raise ValueError("Model name must be a string")

        return input_data

    def _attack_prompt_asset_fallback(self, attack_cfg: dict) -> str:
        raw = attack_cfg.get("asset")
        if isinstance(raw, str) and raw.strip():
            return raw
        logger.log_line(
            PREFIX_LLM,
            "ATTACK_PROMPT",
            "LLM attack prompts config missing or empty 'asset' key; using built-in default.",
            level="error",
        )
        return ATTACK_SUGGESTION_LLM_SYSTEM_PROMPT

    def _resolve_attack_system_prompt(self, prompt_key: str) -> str:
        attack_cfg = self.config["prompts"]["attack"]
        if isinstance(attack_cfg, str) and attack_cfg.strip():
            return attack_cfg
        if not isinstance(attack_cfg, dict) or not attack_cfg:
            logger.log_line(
                PREFIX_LLM,
                "ATTACK_PROMPT",
                "Invalid or empty attack prompts config; using built-in default.",
                level="warning",
            )
            return ATTACK_SUGGESTION_LLM_SYSTEM_PROMPT
        asset_default = self._attack_prompt_asset_fallback(attack_cfg)
        if prompt_key not in attack_cfg:
            logger.log_line(
                PREFIX_LLM,
                "ATTACK_PROMPT",
                "Unknown attack prompt_key %s; known keys: %s. Using asset prompt."
                % (prompt_key, ", ".join(sorted(attack_cfg.keys()))),
                level="warning",
            )
            return asset_default
        chosen = attack_cfg[prompt_key]
        if isinstance(chosen, str) and chosen.strip():
            return chosen
        return asset_default

    def get_attack_suggestion(
        self,
        input_data: str,
        model_name: str | None = None,
        *,
        prompt_key: str = "asset",
    ) -> dict:
        """
        Generate attack suggestions using LLM

        Args:
            input_data: Reconnaissance data
            model_name: Optional OpenAI model override
            prompt_key: One of asset, target, scope, organization (system prompt selection)

        Returns:
            dict: Response containing status and description
        """
        try:
            validated_input = self._validate_input(input_data, model_name)

            if self.provider == LLMProvider.OLLAMA:
                system_prompt = self._resolve_attack_system_prompt(prompt_key)
                response_content = self._get_ollama_response(validated_input, system_prompt)
            else:
                openai_system_prompt, openai_chat_kwargs = self._attack_openai_prompt_and_chat_kwargs(prompt_key)
                response_content = self._get_openai_response(
                    validated_input,
                    model_name,
                    openai_system_prompt,
                    openai_chat_kwargs,
                )

            return {"status": True, "description": response_content, "input": input_data, "model_name": model_name}

        except Exception as e:
            logger.log_line(
                PREFIX_LLM,
                "ATTACK_SUGGESTION",
                "Error in get_attack_suggestion: %s" % (e,),
                level="error",
                exc_info=True,
            )
            return {
                "status": False,
                "error": get_safe_user_message(e, None),
                "input": input_data,
                "model_name": model_name,
            }

    def _get_ollama_response(self, description: str, system_prompt: str) -> str:
        """Get response from Ollama"""
        prompt = "%s\nUser: %s" % (system_prompt, description)
        return self.ollama(prompt)

    def _attack_openai_prompt_and_chat_kwargs(self, prompt_key: str) -> tuple[str, Dict[str, Any]]:
        """Resolve system prompt and OpenAI ``ChatCompletion`` kwargs for ``prompt_key`` together."""
        return (
            self._resolve_attack_system_prompt(prompt_key),
            self._build_attack_openai_chat_kwargs(prompt_key),
        )

    def _build_attack_openai_chat_kwargs(self, prompt_key: str) -> Dict[str, Any]:
        raw = dict(self._get_provider_config())
        raw.pop("max_tokens_aggregate", None)
        allowed: Dict[str, Any] = {}
        for key in ("max_tokens", "temperature"):
            if key in raw:
                allowed[key] = raw[key]
        if prompt_key in ATTACK_PROMPT_KEYS_OPENAI_AGGREGATE:
            openai_cfg = self.config["providers"]["openai"]
            allowed["max_tokens"] = openai_cfg.get("max_tokens_aggregate", DEFAULT_OPENAI_MAX_TOKENS_AGGREGATE)
        return allowed

    def _get_openai_response(
        self,
        description: str,
        model_name: str,
        system_prompt: str,
        openai_chat_kwargs: Dict[str, Any],
    ) -> str:
        """Get response from OpenAI"""
        if not self.api_key:
            raise ValueError("OpenAI API Key not set")

        openai.api_key = self.api_key

        response = openai.ChatCompletion.create(
            model=model_name or self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": description},
            ],
            **openai_chat_kwargs,
        )
        return response["choices"][0]["message"]["content"]
