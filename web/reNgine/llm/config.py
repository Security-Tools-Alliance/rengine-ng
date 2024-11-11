from typing import Dict, Any

###############################################################################
# OLLAMA DEFINITIONS
###############################################################################

OLLAMA_INSTANCE = 'http://ollama:11434'

###############################################################################
# LLM SYSTEM PROMPTS
###############################################################################

VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE = """
You are an expert penetration tester specializing in web application security assessments. Your task is to analyze the following vulnerability information:
    - Vulnerability title
    - Vulnerable URL
    - Vulnerability description

Required report sections (separate each with \n\n):

1. TECHNICAL DESCRIPTION
    - Detailed technical explanation of the vulnerability
    - Associated CVE IDs and CVSS scores if applicable
    - Attack vectors and exploitation methods
    - Any prerequisites or conditions required for exploitation

2. BUSINESS IMPACT
    - Direct security implications
    - Potential business consequences
    - Data exposure risks
    - Compliance implications

3. REMEDIATION STEPS
    - Provide specific, actionable remediation steps
    - Include code examples where relevant
    - List configuration changes if needed
    - Suggest security controls to prevent similar issues
    Format: Each step prefixed with "- " on a new line

4. REFERENCES
    - Only include validated HTTP/HTTPS URLs
    - Focus on official documentation, security advisories, and research papers
    - Include relevant CVE details and exploit databases
    Format: Each reference prefixed with "- " on a new line

Keep the tone technical and professional. Focus on actionable insights. Avoid generic statements.
"""

ATTACK_SUGGESTION_LLM_SYSTEM_PROMPT = """
You are an advanced penetration tester specializing in web application security. Based on the reconnaissance data provided:
    - Subdomain Name
    - Page Title
    - Open Ports
    - HTTP Status
    - Technologies Stack
    - Content Type
    - Web Server
    - Content Length

Provide a structured analysis in the following format:

1. ATTACK SURFACE ANALYSIS
    - Enumerate potential entry points
    - Identify technology-specific vulnerabilities
    - List version-specific known vulnerabilities
    - Map attack surface to MITRE ATT&CK framework where applicable

2. PRIORITIZED ATTACK VECTORS
    For each suggested attack:
        - Attack name and classification
        - Technical rationale based on observed data
        - Specific exploitation methodology
        - Success probability assessment
        - Potential impact rating

3. RELEVANT SECURITY CONTEXT
    - CVE IDs with CVSS scores
    - Existing proof-of-concept exploits
    - Recent security advisories
    - Relevant threat intelligence
    Only include verified HTTP/HTTPS URLs

Focus on actionable, evidence-based suggestions. Prioritize attacks based on feasibility and impact.
Avoid theoretical attacks without supporting evidence from the reconnaissance data.
"""

###############################################################################
# LLM CONFIGURATION
###############################################################################

LLM_CONFIG: Dict[str, Any] = {
    'providers': {
        'openai': {
            'default_model': 'gpt-4-turbo-preview',
            'models': [
                'gpt-4-turbo-preview',
                'gpt-4',
                'gpt-3.5-turbo'
            ],
            'api_version': '2024-02-15',
            'max_tokens': 2000,
            'temperature': 0.7,
        },
        'ollama': {
            'default_model': 'llama2',
            'models': [
                'llama2',
                'mistral',
                'codellama',
                'gemma'
            ],
            'timeout': 30,
            'max_retries': 3,
        }
    },
    'ollama_url': OLLAMA_INSTANCE,
    'timeout': 30,
    'max_retries': 3,
    'prompts': {
        'vulnerability': VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE,
        'attack': ATTACK_SUGGESTION_LLM_SYSTEM_PROMPT
    }
}

###############################################################################
# DEFAULT GPT MODELS
###############################################################################

DEFAULT_GPT_MODELS = [
    {
        'name': 'gpt-3',
        'model': 'gpt-3',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~175B',
        }
    },
    {
        'name': 'gpt-3.5-turbo',
        'model': 'gpt-3.5-turbo',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~7B',
        }
    },
    {
        'name': 'gpt-4',
        'model': 'gpt-4',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~1.7T',
        }
    },
	{
        'name': 'gpt-4-turbo',
        'model': 'gpt-4',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~1.7T',
        }
    }
]

###############################################################################
# MODEL CAPABILITIES
###############################################################################

MODEL_REQUIREMENTS = {
    # OpenAI Models
    'gpt-3': {
        'min_tokens': 64,
        'max_tokens': 2048,
        'supports_functions': True,
        'best_for': ['basic_analysis', 'general_purpose'],
        'provider': 'openai'
    },
    'gpt-3.5-turbo': {
        'min_tokens': 64,
        'max_tokens': 4096,
        'supports_functions': True,
        'best_for': ['quick_analysis', 'basic_suggestions', 'cost_effective'],
        'provider': 'openai'
    },
    'gpt-4': {
        'min_tokens': 128,
        'max_tokens': 8192,
        'supports_functions': True,
        'best_for': ['deep_analysis', 'complex_reasoning', 'advanced_security'],
        'provider': 'openai'
    },
    'gpt-4-turbo': {
        'min_tokens': 128,
        'max_tokens': 128000,
        'supports_functions': True,
        'best_for': ['complex_analysis', 'technical_details', 'latest_capabilities'],
        'provider': 'openai'
    },

    # Llama Family Models
    'llama2': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['local_processing', 'privacy_focused', 'balanced_performance'],
        'provider': 'ollama'
    },
    'llama2-uncensored': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['unfiltered_analysis', 'security_research', 'red_teaming'],
        'provider': 'ollama'
    },
    'llama3': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['advanced_reasoning', 'improved_context', 'technical_analysis'],
        'provider': 'ollama'
    },
    'llama3.1': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['enhanced_comprehension', 'security_assessment', 'detailed_analysis'],
        'provider': 'ollama'
    },
    'llama3.2': {
        'min_tokens': 64,
        'max_tokens': 16384,
        'supports_functions': False,
        'best_for': ['long_context', 'complex_security_analysis', 'advanced_reasoning'],
        'provider': 'ollama'
    },

    # Other Specialized Models
    'mistral': {
        'min_tokens': 32,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['efficient_processing', 'technical_analysis', 'good_performance_ratio'],
        'provider': 'ollama'
    },
    'mistral-medium': {
        'min_tokens': 32,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['balanced_analysis', 'improved_accuracy', 'technical_tasks'],
        'provider': 'ollama'
    },
    'mistral-large': {
        'min_tokens': 64,
        'max_tokens': 16384,
        'supports_functions': False,
        'best_for': ['deep_technical_analysis', 'complex_reasoning', 'high_accuracy'],
        'provider': 'ollama'
    },
    'codellama': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['code_analysis', 'vulnerability_assessment', 'technical_details'],
        'provider': 'ollama'
    },
    'qwen2.5': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['multilingual_analysis', 'efficient_processing', 'technical_understanding'],
        'provider': 'ollama'
    },
    'gemma': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['lightweight_analysis', 'quick_assessment', 'general_tasks'],
        'provider': 'ollama'
    },
    'solar': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['creative_analysis', 'unique_perspectives', 'alternative_approaches'],
        'provider': 'ollama'
    },
    'yi': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['comprehensive_analysis', 'detailed_explanations', 'technical_depth'],
        'provider': 'ollama'
    }
}