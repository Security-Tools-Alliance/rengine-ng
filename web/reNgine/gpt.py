import openai
import re
from reNgine.utils.api import get_open_ai_key
from reNgine.utils.utils import extract_between
from reNgine.definitions import (
    VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE,
    ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT,
    OLLAMA_INSTANCE,
)
from langchain_community.llms import Ollama

from dashboard.models import OllamaSettings
from reNgine.utils.logger import default_logger as logger


class GPTVulnerabilityReportGenerator:

	def __init__(self):
		selected_model = OllamaSettings.objects.first()
		self.model_name = selected_model.selected_model if selected_model else 'gpt-3.5-turbo'
		self.use_ollama = selected_model.use_ollama if selected_model else False
		self.openai_api_key = None
		self.ollama = None
	
	def get_vulnerability_description(self, description):
		"""Generate Vulnerability Description using GPT.

		Args:
			description (str): Vulnerability Description message to pass to GPT.

		Returns:
			(dict) of {
				'description': (str)
				'impact': (str),
				'remediation': (str),
				'references': (list) of urls
			}
		"""
		print(f"Generating Vulnerability Description for: {description}")
		if self.use_ollama:
			prompt = VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE + "\nUser: " + description
			self.ollama = Ollama(
				base_url=OLLAMA_INSTANCE, 
				model=self.model_name
			)
			response_content = self.ollama(prompt)
		else:
			openai_api_key = get_open_ai_key()
			if not openai_api_key:
				return {
					'status': False,
					'error': 'OpenAI API Key not set'
				}
			try:
				openai.api_key = openai_api_key
				gpt_response = openai.ChatCompletion.create(
				model=self.model_name,
				messages=[
						{'role': 'system', 'content': VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE},
						{'role': 'user', 'content': description}
					]
				)

				response_content = gpt_response['choices'][0]['message']['content']
			except Exception as e:
				return {
					'status': False,
					'error': str(e)
				}
		vuln_description_pattern = re.compile(
			r"[Vv]ulnerability [Dd]escription:(.*?)(?:\n\n[Ii]mpact:|$)",
			re.DOTALL
		)
		impact_pattern = re.compile(
			r"[Ii]mpact:(.*?)(?:\n\n[Rr]emediation:|$)",
			re.DOTALL
		)
		remediation_pattern = re.compile(
			r"[Rr]emediation:(.*?)(?:\n\n[Rr]eferences:|$)",
			re.DOTALL
		)

		description_section = extract_between(response_content, vuln_description_pattern)
		impact_section = extract_between(response_content, impact_pattern)
		remediation_section = extract_between(response_content, remediation_pattern)
		references_start_index = response_content.find("References:")
		references_section = response_content[references_start_index + len("References:"):].strip()

		url_pattern = re.compile(r'https://\S+')
		urls = url_pattern.findall(references_section)

		return {
			'status': True,
			'description': description_section,
			'impact': impact_section,
			'remediation': remediation_section,
			'references': urls,
		}

class GPTAttackSuggestionGenerator:

	def __init__(self):
		self.api_key = get_open_ai_key()
		self.model_name = 'gpt-3.5-turbo'
		if not self.api_key:
			self.ollama = Ollama(base_url='http://ollama:11434', model="llama2-uncensored")

	def get_attack_suggestion(self, input):
		'''
			input (str): input for gpt
		'''
		try:
			if not self.api_key:
				prompt = ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT + "\nUser: " + input
				response_content = self.ollama(prompt)
			else:
				openai.api_key = self.api_key
				gpt_response = openai.ChatCompletion.create(
				model=self.model_name,
				messages=[
						{'role': 'system', 'content': ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT},
						{'role': 'user', 'content': input}
					]
				)
				response_content = gpt_response['choices'][0]['message']['content']

			return {
				'status': True,
				'description': response_content,
				'input': input
			}
		except ValueError as e:
			logger.exception(f"Error in get_attack_suggestion: {str(e)}")
			return {
				'status': False,
				'error': "An error occurred while processing your request.",
				'input': input
			}
