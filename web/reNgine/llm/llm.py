from typing import Optional, Dict, Any
import logging
from abc import ABC, abstractmethod
import openai
from langchain_community.llms import Ollama
from reNgine.llm.config import LLM_CONFIG
from reNgine.llm.utils import get_default_llm_model
from reNgine.llm.validators import LLMProvider, LLMResponse
from reNgine.common_func import get_open_ai_key

logger = logging.getLogger(__name__)

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
        ollama_config = self.config['providers']['ollama']
        self.ollama = Ollama(
            base_url=ollama_config['url'],
            model=self.model_name,
            timeout=ollama_config['timeout']
        )

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
        if model_name in self.config['providers']['openai']['models']:
            return LLMProvider.OPENAI
        return LLMProvider.OLLAMA

    def _get_provider_config(self) -> Dict[str, Any]:
        """Get provider specific configuration"""
        provider_key = self.provider.value
        return self.config['providers'][provider_key]

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
            vulnerability_prompt = LLM_CONFIG['prompts']['vulnerability']
            context = vulnerability_prompt['context']
            
            # Generate each section separately
            technical = self._get_section_response(validated_input, context + vulnerability_prompt['technical'])
            impact = self._get_section_response(validated_input, context + vulnerability_prompt['impact'])
            remediation = self._get_section_response(validated_input, context + vulnerability_prompt['remediation'])
            references = self._get_section_response(validated_input, context + vulnerability_prompt['references'])
            
            # Combine sections into a single response
            response = {
                "description": technical,
                "impact": impact,
                "remediation": remediation,
                "references": references
            }
            
            logger.debug(f'Response: {response}')
            return LLMResponse(
                status=True,
                **response
            ).to_dict()

        except Exception as e:
            logger.error(f"Error in get_vulnerability_report: {str(e)}", exc_info=True)
            return LLMResponse(
                status=False,
                error=str(e)
            ).to_dict()

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
            logger.error(f"Error in _get_section_response: {str(e)}")
            return ""

    def _get_ollama_response(self, prompt: str, description: str) -> str:
        """Get response from Ollama"""
        prompt = f"{prompt}\nUser: {description}"
        logger.debug(f'Ollama Prompt: {prompt}')
        response = self.ollama(prompt)
        logger.debug(f'Ollama Response: {response}')
        return str(response) if response is not None else ""

    def _get_openai_response(self, prompt: str, description: str, model_name: str = None) -> str:
        """Get response from OpenAI"""
        if not self.api_key:
            raise ValueError("OpenAI API Key not set")

        openai.api_key = self.api_key
        
        response = openai.ChatCompletion.create(
            model=model_name or self.model_name,
            messages=[
                {'role': 'system', 'content': prompt},
                {'role': 'user', 'content': description}
            ],
            **self._get_provider_config()
        )
        return response['choices'][0]['message']['content']

class LLMAttackSuggestionGenerator(BaseLLMGenerator):
    """Generator for attack suggestions using LLM"""

    def _get_model_name(self) -> str:
        """Get model name from database or default"""
        return get_default_llm_model()

    def _get_default_provider(self) -> LLMProvider:
        """Get default provider based on model requirements"""
        model_name = self._get_model_name()
        if model_name in self.config['providers']['openai']['models']:
            return LLMProvider.OPENAI
        return LLMProvider.OLLAMA

    def _get_provider_config(self) -> Dict[str, Any]:
        """Get provider specific configuration"""
        provider_key = self.provider.value
        return self.config['providers'][provider_key]

    def _validate_input(self, input_data: str, model_name: str = None) -> str:
        """Validate the input data and model name"""
        if not input_data or not isinstance(input_data, str):
            raise ValueError("Input data must be a non-empty string")
            
        # Additional model validation if provided
        if model_name and not isinstance(model_name, str):
            raise ValueError("Model name must be a string")
            
        return input_data

    def get_attack_suggestion(self, input_data: str, model_name: str = None) -> dict:
        """
        Generate attack suggestions using LLM
        
        Args:
            input_data: Reconnaissance data
            
        Returns:
            dict: Response containing status and description
        """
        try:
            # Validate both input data and model name
            validated_input = self._validate_input(input_data, model_name)
            
            # Get response from appropriate provider
            if self.provider == LLMProvider.OLLAMA:
                response_content = self._get_ollama_response(validated_input)
            else: 
                response_content = self._get_openai_response(validated_input, model_name)

            return {
                'status': True,
                'description': response_content,
                'input': input_data,
                'model_name': model_name
            }

        except Exception as e:
            logger.error(f"Error in get_attack_suggestion: {str(e)}", exc_info=True)
            return {
                'status': False,
                'error': str(e),
                'input': input_data,
                'model_name': model_name
            }

    def _get_ollama_response(self, description: str) -> str:
        """Get response from Ollama"""
        prompt = f"{self.config['prompts']['attack']}\nUser: {description}"
        return self.ollama(prompt)

    def _get_openai_response(self, description: str, model_name: str) -> str:
        """Get response from OpenAI"""
        if not self.api_key:
            raise ValueError("OpenAI API Key not set")

        openai.api_key = self.api_key
        
        response = openai.ChatCompletion.create(
            model=model_name,
            messages=[
                {'role': 'system', 'content': self.config['prompts']['attack']},
                {'role': 'user', 'content': description}
            ],
            **self._get_provider_config()
        )
        return response['choices'][0]['message']['content']
