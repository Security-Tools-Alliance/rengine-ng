from unittest.mock import patch
from django.test import TestCase
from rest_framework import status
from django.urls import reverse

from reNgine.llm.config import MODEL_REQUIREMENTS
from reNgine.llm.llm import LLMVulnerabilityReportGenerator, LLMAttackSuggestionGenerator
from reNgine.llm.validators import LLMProvider
from utils.test_base import BaseTestCase


class TestLLMBase(BaseTestCase):
    """Base test class for LLM functionality."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_project_base()
        self.mock_llm_response = {
            "status": True,
            "description": "Test vulnerability description",
            "impact": "Test impact description",
            "remediation": "Test remediation steps",
            "references": ["https://test.com/ref1", "https://test.com/ref2"]
        }


class TestLLMVulnerabilityReport(TestLLMBase):
    """Test cases for LLM Vulnerability Report Generator."""

    def setUp(self):
        super().setUp()
        self.generator = LLMVulnerabilityReportGenerator()

    @patch('reNgine.llm.llm.LLMVulnerabilityReportGenerator._get_openai_response')
    def test_get_vulnerability_report_success(self, mock_get_response):
        """Test successful vulnerability report generation."""
        mock_get_response.return_value = "Test section content"
        
        response = self.generator.get_vulnerability_report("Test input")
        self.assertTrue(response["status"])
        self.assertIsNotNone(response["description"])
        self.assertIsNotNone(response["impact"])
        self.assertIsNotNone(response["remediation"])
        self.assertIsNotNone(response["references"])

    def test_validate_input_success(self):
        """Test input validation success."""
        input_data = "Detailed vulnerability description for testing"
        validated = self.generator._validate_input(input_data)
        self.assertEqual(validated, input_data)

    @patch('reNgine.llm.llm.LLMVulnerabilityReportGenerator._get_section_response')
    def test_get_vulnerability_report_failure(self, mock_get_section):
        """Test vulnerability report generation failure."""
        # Mock section response to raise an exception
        mock_get_section.side_effect = Exception("API Error")
        
        response = self.generator.get_vulnerability_report("Test input")
        self.assertFalse(response["status"])
        self.assertIsNotNone(response["error"])
        self.assertEqual(response["error"], "API Error")


class TestLLMAttackSuggestion(TestLLMBase):
    """Test cases for LLM Attack Suggestion Generator."""

    def setUp(self):
        super().setUp()
        self.generator = LLMAttackSuggestionGenerator()

    @patch('reNgine.llm.llm.LLMAttackSuggestionGenerator.get_attack_suggestion')
    def test_get_attack_suggestion_success(self, mock_get_suggestion):
        """Test successful attack suggestion generation."""
        mock_suggestion = "Test attack suggestion"
        mock_get_suggestion.return_value = {
            "status": True,
            "description": mock_suggestion,
            "input": "Test input",
            "model_name": None
        }
        
        api_url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            api_url,
            {"subdomain_id": self.data_generator.subdomain.id}
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        # Check if the suggestion is part of the formatted HTML response
        self.assertIn(mock_suggestion, response.data["description"])

    def test_validate_input_success(self):
        """Test input validation success."""
        input_data = "Detailed reconnaissance data for testing"
        validated = self.generator._validate_input(input_data)
        self.assertEqual(validated, input_data)

    @patch('reNgine.llm.llm.LLMAttackSuggestionGenerator._get_openai_response')
    def test_get_attack_suggestion_failure(self, mock_get_response):
        """Test attack suggestion generation failure."""
        mock_get_response.side_effect = Exception("API Error")
        
        response = self.generator.get_attack_suggestion("Test input")
        self.assertFalse(response["status"])
        self.assertIsNotNone(response["error"])

    def test_get_provider_config(self):
        """Test provider configuration retrieval"""
        generator = LLMAttackSuggestionGenerator(provider=LLMProvider.OLLAMA)
        config = generator._get_provider_config()
        self.assertIn('default_model', config)
        self.assertIn('models', config)
        self.assertIn('timeout', config)

    def test_model_capabilities(self):
        """Test model capabilities access"""
        generator = LLMAttackSuggestionGenerator()
        model_name = generator._get_model_name()
        self.assertIn(model_name, MODEL_REQUIREMENTS)
        self.assertIn('provider', MODEL_REQUIREMENTS[model_name])


class TestLLMProviders(TestCase):
    """Test cases for LLM providers configuration."""

    def test_openai_provider_config(self):
        """Test OpenAI provider configuration."""
        generator = LLMVulnerabilityReportGenerator(provider=LLMProvider.OPENAI)
        self.assertEqual(generator.provider, LLMProvider.OPENAI)
        self.assertIsNone(generator.ollama)

    def test_ollama_provider_config(self):
        """Test Ollama provider configuration."""
        generator = LLMVulnerabilityReportGenerator(provider=LLMProvider.OLLAMA)
        self.assertEqual(generator.provider, LLMProvider.OLLAMA)
        self.assertIsNotNone(generator.ollama) 