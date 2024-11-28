import os
import re
from pathlib import Path
from typing import List, Union
from celery.utils.log import get_task_logger, ColorFormatter
from celery._state import get_current_task

logger = get_task_logger(__name__)

def is_safe_path(basedir, path, follow_symlinks=True):
	# Source: https://security.openstack.org/guidelines/dg_using-file-paths.html
	# resolves symbolic links
	if follow_symlinks:
		matchpath = os.path.realpath(path)
	else:
		matchpath = os.path.abspath(path)
	return basedir == os.path.commonpath((basedir, matchpath))


# Source: https://stackoverflow.com/a/10408992
def remove_lead_and_trail_slash(s):
	if s.startswith('/'):
		s = s[1:]
	if s.endswith('/'):
		s = s[:-1]
	return s


def get_time_taken(latest, earlier):
	duration = latest - earlier
	days, seconds = duration.days, duration.seconds
	hours = days * 24 + seconds // 3600
	minutes = (seconds % 3600) // 60
	seconds = seconds % 60
	if not hours and not minutes:
		return f'{seconds} seconds'
	elif not hours:
		return f'{minutes} minutes'
	elif not minutes:
		return f'{hours} hours'
	return f'{hours} hours {minutes} minutes'

# Check if value is a simple string, a string with commas, a list [], a tuple (), a set {} and return an iterable
def return_iterable(string):
	if not isinstance(string, (list, tuple)):
		string = [string]

	return string


# Logging formatters

class RengineTaskFormatter(ColorFormatter):

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		try:
			self.get_current_task = get_current_task
		except ImportError:
			self.get_current_task = lambda: None

	def format(self, record):
		task = self.get_current_task()
		if task and task.request:
			task_name = '/'.join(task.name.replace('tasks.', '').split('.'))
			record.__dict__.update(task_id=task.request.id,
								   task_name=task_name)
		else:
			record.__dict__.setdefault('task_name', f'{record.module}.{record.funcName}')
			record.__dict__.setdefault('task_id', '')
		return super().format(record)


def get_gpt_vuln_input_description(title, path):
	vulnerability_description = ''
	vulnerability_description += f'Vulnerability Title: {title}'
	# gpt gives concise vulnerability description when a vulnerable URL is provided
	vulnerability_description += f'\nVulnerable URL: {path}'

	return vulnerability_description


def replace_nulls(obj):
	if isinstance(obj, str):
		return obj.replace("\x00", "")
	elif isinstance(obj, list):
		return [replace_nulls(item) for item in obj]
	elif isinstance(obj, dict):
		return {key: replace_nulls(value) for key, value in obj.items()}
	else:
		return obj


class SafePath:
	"""Utility class for safe path handling and directory creation."""
	
	@staticmethod
	def sanitize_component(component: str) -> str:
		"""Sanitize a path component to prevent directory traversal.
		
		Args:
			component (str): Path component to sanitize
			
		Returns:
			str: Sanitized path component
		"""
		# Remove any non-alphanumeric chars except safe ones
		return re.sub(r'[^a-zA-Z0-9\-\_\.]', '_', str(component))

	@classmethod
	def create_safe_path(
		cls,
		base_dir: Union[str, Path],
		components: List[str],
		create_dir: bool = True,
		mode: int = 0o755
	) -> str:
		"""Create a safe path within the base directory.
		
		Args:
			base_dir (str|Path): Base directory
			components (list): List of path components
			create_dir (bool): Whether to create the directory
			mode (int): Directory permissions if created
			
		Returns:
			str: Safe path object
			
		Raises:
			ValueError: If path would be outside base directory
			OSError: If directory creation fails
		"""
		try:
			# Convert to Path objects
			base_path = Path(base_dir).resolve()
			
			# Sanitize all components
			safe_components = [cls.sanitize_component(c) for c in components]
			
			# Build full path
			full_path = base_path.joinpath(*safe_components)
			
			# Resolve to absolute path
			abs_path = full_path.resolve()
			
			# Check if path is within base directory
			if not str(abs_path).startswith(str(base_path)):
				raise ValueError(
					f"Invalid path: {abs_path} is outside base directory {base_path}"
				)
			
			# Create directory if requested
			if create_dir:
				abs_path.mkdir(parents=True, mode=mode, exist_ok=True)
				logger.debug(f"Created directory: {abs_path}")
				
			return str(abs_path)
			
		except Exception as e:
			logger.error(f"Error creating safe path: {str(e)}")
			raise

	@classmethod
	def is_safe_path(cls, base_dir: Union[str, Path], path: Union[str, Path], follow_symlinks: bool = True) -> bool:
		"""Enhanced version of is_safe_path that uses pathlib.
		Maintains compatibility with existing code while adding more security."""
		try:
			base_path = Path(base_dir).resolve()
			check_path = Path(path)
			
			if follow_symlinks:
				check_path = check_path.resolve()
			else:
				check_path = check_path.absolute()
				
			return str(check_path).startswith(str(base_path))
		except Exception:
			return False
