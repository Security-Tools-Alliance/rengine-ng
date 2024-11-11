from django.contrib import messages
from dashboard.models import OllamaSettings
from reNgine.llm.config import LLM_CONFIG
import logging
import re

logger = logging.getLogger(__name__)

def get_default_llm_model():
    """
    Get the default LLM model from database or fallback to default
    Returns the model name as string
    """
    try:
        ollama_settings = OllamaSettings.objects.first()
        if ollama_settings and ollama_settings.selected_model:
            return ollama_settings.selected_model
    except Exception as e:
        logger.error(f"Error while retrieving default LLM model: {e}")
    
    # Fallback to default model from config based on provider
    try:
        if ollama_settings and ollama_settings.use_ollama:
            return LLM_CONFIG['providers']['ollama']['default_model']
        return LLM_CONFIG['providers']['openai']['default_model']
    except Exception as e:
        logger.error(f"Error while getting default model from config: {e}")
        return 'gpt-3.5-turbo'  # Ultimate fallback

def validate_llm_model(request, model_name):
    """Check if LLM model exists and is available"""
    try:
        # Check if model exists in LLMToolkit
        if not LLMToolkit.is_model_available(model_name):
            messages.info(
                request,
                f"Model {model_name} is not available. "
                f'<a href="/llm/settings/">Configure your LLM models here</a>.',
                extra_tags='safe'
            )
            return False
        return True
    except Exception as e:
        logger.error(f"Error while validating LLM model: {e}")
        return False 
    
class RegexPatterns:
	"""Regular expression patterns for parsing LLM responses"""
	
	VULN_DESCRIPTION = re.compile(
		r"[Vv]ulnerability [Dd]escription:(.*?)(?:\n\n[Ii]mpact:|$)",
		re.DOTALL
	)
	
	IMPACT = re.compile(
		r"[Ii]mpact:(.*?)(?:\n\n[Rr]emediation:|$)",
		re.DOTALL
	)
	
	REMEDIATION = re.compile(
		r"[Rr]emediation:(.*?)(?:\n\n[Rr]eferences:|$)",
		re.DOTALL
	)
	
	URL = re.compile(r'https?://\S+')

	# Add other patterns if needed
	CVE = re.compile(r'CVE-\d{4}-\d{4,7}')
	CVSS = re.compile(r'CVSS:3\.\d/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]')
