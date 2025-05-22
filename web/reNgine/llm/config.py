from typing import Dict, Any
from reNgine.definitions import OLLAMA_INSTANCE

###############################################################################
# OLLAMA DEFINITIONS
###############################################################################

###############################################################################
# LLM SYSTEM PROMPTS
###############################################################################

VULNERABILITY_CONTEXT = """
You are an expert penetration tester specializing in web application security assessments. Your task is to analyze the following vulnerability information:
    - Vulnerability title
    - Vulnerable URL
    - Vulnerability description

Keep the tone technical and professional. Focus on actionable insights. Avoid generic statements.
"""

VULNERABILITY_TECHNICAL_DESCRIPTION_PROMPT = """
Provide a detailed technical description of the vulnerability, including:
    - Detailed technical explanation
    - Associated CVE IDs and CVSS scores if applicable
    - Attack vectors and exploitation methods
    - Any prerequisites or conditions required for exploitation
I don't want to see any other information in the response.
"""

VULNERABILITY_BUSINESS_IMPACT_PROMPT = """
Describe the business impact of this vulnerability, including:
    - Direct security implications
    - Potential business consequences
    - Data exposure risks
    - Compliance implications
I don't want to see any other information in the response.
"""

VULNERABILITY_REMEDIATION_STEPS_PROMPT = """
List the remediation steps for this vulnerability, including:
    - Specific, actionable steps
    - Code examples where relevant
    - Configuration changes if needed
    - Security controls to prevent similar issues
    Format: Each step prefixed with "- " on a new line
I don't want to see any other information in the response.
"""

VULNERABILITY_REFERENCES_PROMPT = """
Provide references related to this vulnerability, focusing on:
    - Validated HTTP/HTTPS URLs
    - Official documentation, security advisories, and research papers
    - Relevant CVE details and exploit databases
    Format: Each reference prefixed with "- " on a new line
I don't want to see any other information in the response.
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
            'default_model': 'gpt-4',
            'models': [
                'gpt-4-turbo',
                'gpt-4',
                'gpt-3.5-turbo',
                'gpt-3'
            ],
            'api_version': '2024-02-15',
            'max_tokens': 2000,
            'temperature': 0.7,
        },
        'ollama': {
            'url': OLLAMA_INSTANCE,
            'default_model': 'llama2',
            'models': [
                'llama2',
                'mistral',
                'codellama',
                'gemma'
            ],
            'timeout': 120,
            'max_retries': 3,
        }
    },
    'prompts': {
        'vulnerability': {
            'context': VULNERABILITY_CONTEXT,
            'technical': VULNERABILITY_TECHNICAL_DESCRIPTION_PROMPT,
            'impact': VULNERABILITY_BUSINESS_IMPACT_PROMPT,
            'remediation': VULNERABILITY_REMEDIATION_STEPS_PROMPT,
            'references': VULNERABILITY_REFERENCES_PROMPT,
        },
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
        'best_for': ['Basic analysis', 'General purpose tasks'],
        'provider': 'openai'
    },
    'gpt-3.5-turbo': {
        'min_tokens': 64,
        'max_tokens': 4096,
        'supports_functions': True,
        'best_for': ['Quick analysis', 'Basic suggestions', 'Cost effective solutions'],
        'provider': 'openai'
    },
    'gpt-4': {
        'min_tokens': 128,
        'max_tokens': 8192,
        'supports_functions': True,
        'best_for': ['Deep security analysis', 'Complex reasoning', 'Advanced security tasks'],
        'provider': 'openai'
    },
    'gpt-4-turbo': {
        'min_tokens': 128,
        'max_tokens': 128000,
        'supports_functions': True,
        'best_for': ['Complex analysis', 'Technical details', 'Latest AI capabilities'],
        'provider': 'openai'
    },

    # Llama Family Models
    'llama2': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['Local processing', 'Privacy focused tasks', 'Balanced performance'],
        'provider': 'ollama'
    },
    'llama2-uncensored': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['Unfiltered analysis', 'Security research', 'Red team operations'],
        'provider': 'ollama'
    },
    'llama3': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['Advanced reasoning', 'Improved context', 'Technical analysis'],
        'provider': 'ollama'
    },
    'llama3.1': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['Enhanced comprehension', 'Security assessment', 'Detailed analysis'],
        'provider': 'ollama'
    },
    'llama3.2': {
        'min_tokens': 64,
        'max_tokens': 16384,
        'supports_functions': False,
        'best_for': ['Long context', 'Complex security analysis', 'Advanced reasoning'],
        'provider': 'ollama'
    },

    # Other Specialized Models
    'mistral': {
        'min_tokens': 32,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['Efficient processing', 'Technical analysis', 'Performance optimization'],
        'provider': 'ollama'
    },
    'mistral-medium': {
        'min_tokens': 32,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['Balanced analysis', 'Improved accuracy', 'Technical tasks'],
        'provider': 'ollama'
    },
    'mistral-large': {
        'min_tokens': 64,
        'max_tokens': 16384,
        'supports_functions': False,
        'best_for': ['Deep technical analysis', 'Complex reasoning', 'High accuracy'],
        'provider': 'ollama'
    },
    'codellama': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['Code analysis', 'Vulnerability assessment', 'Technical documentation'],
        'provider': 'ollama'
    },
    'qwen2.5': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['Multilingual analysis', 'Efficient processing', 'Technical understanding'],
        'provider': 'ollama'
    },
    'gemma': {
        'min_tokens': 32,
        'max_tokens': 4096,
        'supports_functions': False,
        'best_for': ['Lightweight analysis', 'Quick assessment', 'General tasks'],
        'provider': 'ollama'
    },
    'solar': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['Creative analysis', 'Unique perspectives', 'Alternative approaches'],
        'provider': 'ollama'
    },
    'yi': {
        'min_tokens': 64,
        'max_tokens': 8192,
        'supports_functions': False,
        'best_for': ['Comprehensive analysis', 'Detailed explanations', 'Technical depth'],
        'provider': 'ollama'
    }
}

###############################################################################
# RECOMMENDED MODELS
###############################################################################

RECOMMENDED_MODELS = {
    'llama2-uncensored': {
        'name': 'llama2-uncensored',
        'description': 'Optimized for security research and penetration testing, unrestricted responses',
        'tags': ['7b', '70b'],
        'size_options': {
            '7b': '~4GB RAM',
            '70b': '~35GB RAM'
        }
    },
    'llama3.1': {
        'name': 'llama3.1',
        'description': 'Advanced model with enhanced security analysis capabilities and better context understanding',
        'tags': ['8b', '70b', '405b'],
        'size_options': {
            '8b': '~4GB RAM',
            '70b': '~35GB RAM',
            '405b': '~200GB RAM'
        }
    },
    'llama3.2': {
        'name': 'llama3.2',
        'description': 'Latest LLaMA model with improved reasoning for complex security scenarios and vulnerability analysis',
        'tags': ['1b', '3b'],
        'size_options': {
            '1b': '~1GB RAM',
            '3b': '~2GB RAM'
        }
    },
    'codellama': {
        'name': 'codellama',
        'description': 'Specialized for code analysis, vulnerability assessment, and secure coding practices',
        'tags': ['7b', '13b', '34b', '70b'],
        'size_options': {
            '7b': '~4GB RAM',
            '13b': '~8GB RAM',
            '34b': '~18GB RAM',
            '70b': '~35GB RAM'
        }
    },
    'mistral': {
        'name': 'mistral',
        'description': 'Excellent for technical security analysis and threat modeling',
        'tags': ['7b'],
        'size_options': {
            '7b': '~4GB RAM'
        }
    },
    'dolphin-phi': {
        'name': 'dolphin-phi',
        'description': 'Fast and efficient for real-time security analysis, good balance of performance and accuracy',
        'tags': ['2.7b'],
        'size_options': {
            '2.7b': '~2GB RAM'
        }
    },
    'openchat': {
        'name': 'openchat',
        'description': 'Strong reasoning capabilities for complex security scenarios and attack chain analysis',
        'tags': ['7b'],
        'size_options': {
            '7b': '~4GB RAM'
        }
    },
    'solar': {
        'name': 'solar',
        'description': 'Advanced reasoning for security implications and vulnerability impact assessment',
        'tags': ['10.7b'],
        'size_options': {
            '10.7b': '~6GB RAM'
        }
    }
}

LLM_CONFIG['providers']['ollama']['recommended_models'] = RECOMMENDED_MODELS