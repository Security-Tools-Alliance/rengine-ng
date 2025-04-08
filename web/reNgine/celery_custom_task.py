import os
import json

from celery import Task
from celery.worker.request import Request
from django.utils import timezone
from redis import Redis

from reNgine.definitions import (
    CELERY_TASK_STATUS_MAP,
    FAILED_TASK,
    RUNNING_TASK,
    SUCCESS_TASK,
)
from reNgine.settings import (
    COMMAND_EXECUTOR_DRY_RUN,
    RENGINE_CACHE_ENABLED,
    RENGINE_RECORD_ENABLED,
    RENGINE_RAISE_ON_ERROR,
    RENGINE_RESULTS,
)
from reNgine.utils.formatters import (
	fmt_traceback,
	get_output_file_name,
	get_task_cache_key,
	get_traceback_path
)
from reNgine.utils.debug import debug
from reNgine.utils.logger import default_logger as logger

from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, SubScan

cache = None
if 'CELERY_BROKER' in os.environ:
	cache = Redis.from_url(os.environ['CELERY_BROKER'])


class RengineRequest(Request):
	success_msg = ''
	retry_msg = ''


class RengineTask(Task):
	"""A Celery task that is tracked by reNgine. Save task output files and
	tracebacks to RENGINE_RESULTS.

	The custom task meta-options are toggleable through environment variables:

	RENGINE_RECORD_ENABLED:
	- Create / update ScanActivity object to track statuses.
	- Send notifications before and after each task (start / end).
	- Send traceback file to reNgine's Discord channel if an exception happened.

	RENGINE_CACHE_ENABLED:
	- Get result from cache if it exists.
	- Set result to cache after a task if no exceptions occured.

	RENGINE_RAISE_ON_ERROR:
	- Raise the actual exception when task fails instead of just logging it.

	DRY_RUN mode:
	- When ctx['dry_run'] is True, the task will generate mock results instead of running
	  the actual command.
	"""
	Request = RengineRequest

	@property
	def status_str(self):
		return CELERY_TASK_STATUS_MAP.get(self.status)

	def __call__(self, *args, **kwargs):
		#debug()

		self.result = None
		self.status = RUNNING_TASK
		self.error = None
		self.traceback = None

		try:
			self.initialize_task(*args, **kwargs)
		except Exception as exc:
			self._handle_exception(exc, context="task initialization")
			return self.traceback

		# Check if the task should be executed in the current engine
		if not self.check_engine_compatibility_and_create_activity():
			return None

		# Handle dry run mode if enabled
		if COMMAND_EXECUTOR_DRY_RUN:
			self.handle_dry_run(*args, **kwargs)

		# Check cache for previous results
		if RENGINE_CACHE_ENABLED:
			if cached_result := self.get_from_cache(*args, **kwargs):
				return cached_result

		# Execute task, catch exceptions and update ScanActivity object after
		# task has finished running.
		try:
			self.result = self.run(*args, **kwargs)
			self.status = SUCCESS_TASK

		except Exception as exc:
			# Use common exception handler for task execution errors
			self._handle_exception(exc, context="task execution")

		finally:
			self.write_results()

			if RENGINE_RECORD_ENABLED and self.track:
				if self.domain:
					msg = f'Task {self.task_name} for {self.subdomain.name if self.subdomain else self.domain.name} status is {self.status_str}'
				else:
					msg = f'Task {self.task_name} status is {self.status_str}'
				msg += f' | Error: {self.error}' if self.error else ''
				logger.info(msg)
				self.db_update_scan_activity()

		# Set task result in cache if task was successful
		if RENGINE_CACHE_ENABLED and self.status == SUCCESS_TASK and self.result:
			from reNgine.utils.cache import set_to_cache
			set_to_cache(self.cache_key, self.result)

		return self.result

	def write_results(self):
		if not self.result:
			return False
		is_json_results = isinstance(self.result, (dict, list))
		if not self.output_path:
			return False
		if not os.path.exists(self.output_path):
			with open(self.output_path, 'w') as f:
				if is_json_results:
					json.dump(self.result, f, indent=4)
				else:
					f.write(self.result)
			logger.info(f'Wrote {self.task_name} results to {self.output_path}')

	def create_scan_activity(self):
		if not self.track:
			return
		celery_id = self.request.id
		self.activity = ScanActivity(
			name=self.task_name,
			title=self.description,
			time=timezone.now(),
			status=RUNNING_TASK,
			celery_id=celery_id)
		self.activity.save()
		self.activity_id = self.activity.id
		if self.scan:
			self.activity.scan_of = self.scan
			self.activity.save()
			self.scan.celery_ids.append(celery_id)
			self.scan.save()
		if self.subscan:
			self.subscan.celery_ids.append(celery_id)
			self.subscan.save()

		# Send notification
		self.notify()

	def db_update_scan_activity(self):
		if not self.track:
			return

		# Trim error before saving to DB
		error_message = self.error
		if self.error and len(self.error) > 300:
			error_message = f'{self.error[:288]}...[trimmed]'

		self.activity.status = self.status
		self.activity.error_message = error_message
		self.activity.traceback = self.traceback
		self.activity.time = timezone.now()
		self.activity.save()
		self.notify()

	def notify(self, name=None, severity=None, fields=None, add_meta_info=True):
		if fields is None:
			fields = {}
		from reNgine.tasks.notification import send_task_notif
		return send_task_notif.delay(
			name or self.task_name,
			status=self.status_str,
			result=self.result,
			traceback=self.traceback,
			output_path=self.output_path,
			scan_history_id=self.scan_id,
			engine_id=self.engine_id,
			subscan_id=self.subscan_id,
			severity=severity,
			add_meta_info=add_meta_info,
			update_fields=fields)

	def get_from_cache(self, *args, **kwargs):
		"""Get task result from cache if RENGINE_CACHE_ENABLED is True.
		
		Returns:
			dict/list/None: Cached result if found and valid, None otherwise
		"""
		from reNgine.utils.cache import check_task_cache
		
		cached_result, self.cache_key = check_task_cache(self.name, *args, **kwargs)
		
		if cached_result:
			self.status = SUCCESS_TASK
			if RENGINE_RECORD_ENABLED and self.track:
				self._update_scan_activity()
			return cached_result
		return None

	def mock_generator(self, *args, **kwargs):
		"""Generate mock result for dry_run mode based on task type."""
		from reNgine.utils.mock_datas import MockData

		# Extract domain from kwargs if available
		ctx = kwargs.get('ctx', {})
		if domain_name := kwargs.get('domain', None):
			ctx['domain_name'] = domain_name

		results_dir = ctx.get('results_dir', '/tmp')

		# Initialize MockData with enhanced context
		mock_data = MockData(context=ctx)

		# Get specific mock data for this task
		return mock_data.get_mock_for_task(
			task_name=self.task_name,
			args=args,
			kwargs=kwargs,
			results_dir=results_dir,
			ctx=ctx
		)

	def initialize_task(self, *args, **kwargs):
		"""Initialize task-specific configurations before execution.
		
		This method handles the initialization of task properties based on arguments
		and context. It extracts relevant information from context, sets up paths,
		and loads related database objects.
		
		Args:
			*args: Variable positional arguments passed to the task
			**kwargs: Variable keyword arguments passed to the task, including 'ctx'
		"""
		# Get task info
		self.task_name = self.name.split('.')[-1]
		self.description = kwargs.get('description') or ' '.join(self.task_name.split('_')).capitalize()

		# Get reNgine context
		ctx = kwargs.get('ctx', {})
		self.track = ctx.pop('track', True)
		self.scan_id = ctx.get('scan_history_id')
		self.subscan_id = ctx.get('subscan_id')
		self.engine_id = ctx.get('engine_id')
		self.filename = ctx.get('filename')
		self.url_filter = ctx.get('url_filter', '')
		self.results_dir = ctx.get('results_dir', RENGINE_RESULTS)
		self.yaml_configuration = ctx.get('yaml_configuration', {})
		self.out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
		self.history_file = f'{self.results_dir}/commands.txt'
		
		# Load database objects
		self.scan = ScanHistory.objects.filter(pk=self.scan_id).first()
		self.subscan = SubScan.objects.filter(pk=self.subscan_id).first()
		self.engine = EngineType.objects.filter(pk=self.engine_id).first()
		self.domain = self.scan.domain if self.scan else None
		self.domain_id = self.domain.id if self.domain else None
		self.subdomain = self.subscan.subdomain if self.subscan else None
		self.subdomain_id = self.subdomain.id if self.subdomain else None
		self.activity_id = None

		# Set file paths
		if not self.filename:
			self.filename = get_output_file_name(
				self.scan_id,
				self.subscan_id,
				f'{self.task_name}.txt')
			if self.task_name == 'screenshot':
				self.filename = 'Requests.csv'
		self.output_path = f'{self.results_dir}/{self.filename}'

	def get_mock_path(self):
		"""Get the path to the mock data file for this task.
		
		Returns:
			str: Path to the mock data file for this task
		"""
		# Define standard location for mock files
		mock_base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'mocks')

		# Task-specific mock file based on task name
		mock_filename = f"{self.task_name}.json"

		# Check specific mock path for this scan if available
		if self.scan_id:
			scan_specific_path = os.path.join(
				mock_base_dir, 
				f"scan_{self.scan_id}", 
				mock_filename
			)
			if os.path.exists(scan_specific_path):
				return scan_specific_path

		return os.path.join(mock_base_dir, mock_filename)

	def write_traceback(self):
		"""Write the traceback to a file when an exception occurs.
		
		Returns:
			bool: True if traceback was written, False otherwise
		"""
		if not self.traceback:
			return False
		
		if not self.output_path:
			return False
		
		# Create directory if it doesn't exist
		os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
		
		# Write traceback to file
		with open(self.output_path, 'w') as f:
			f.write(self.traceback)
		
		logger.info(f'Wrote traceback for {self.task_name} to {self.output_path}')
		return True

	def _update_scan_activity(self):
		target = self.subdomain.name if self.subdomain else self.domain.name if self.domain else None
		msg = f'Task {self.task_name}'
		if target:
			msg += f' for {target}'
		msg += ' status is SUCCESS (CACHED)'
		logger.info(msg)
		self.db_update_scan_activity()

	def _handle_exception(self,exc, context="task execution"):
		"""Handle exceptions consistently across the task lifecycle"""
		self.status = FAILED_TASK
		self.error = repr(exc)
		self.traceback = fmt_traceback(exc)
		self.result = self.traceback
		self.output_path = get_traceback_path(
			self.task_name,
			self.results_dir,
			self.scan_id,
			self.subscan_id)
		os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
		
		# Log error with context for better debugging
		logger.exception(f"Error during {context} in {self.task_name}: {str(exc)}\n{self.traceback}")
		
		if RENGINE_RAISE_ON_ERROR:
			raise exc

	def check_engine_compatibility_and_create_activity(self):
		"""
		Check if the task should be executed in the current engine and creates a ScanActivity if needed.
		
		This method handles the following:
		1. Checks if the task is compatible with the current engine
		2. Skips execution if the task is not part of the engine's tasks
		3. Creates ScanActivity record and sends notifications
		
		Returns:
			bool: False if task should be skipped, True otherwise
		"""
		if not RENGINE_RECORD_ENABLED:
			return True
		
		if self.engine:  # Check engine compatibility
			# Define dependent tasks that can run as part of other main tasks
			dependent_tasks = {
				'dalfox_scan': 'vulnerability_scan',
				'crlfuzz_scan': 'vulnerability_scan',
				'nuclei_scan': 'vulnerability_scan',
				'nuclei_individual_severity_module': 'vulnerability_scan',
				's3scanner': 'vulnerability_scan',
			}
			
			# Exempted tasks that can always run
			exempted_tasks = [
				'http_crawl',
				'scan_http_ports',
				'run_nmap',
				'nmap'
			]
			
			# Skip if task is not part of engine and not exempted
			if (
				self.track and 
				self.task_name not in self.engine.tasks and 
				dependent_tasks.get(self.task_name) not in self.engine.tasks and
				self.task_name.lower() not in exempted_tasks
			):
				logger.debug(f'Task {self.task_name} is not part of engine "{self.engine.engine_name}" tasks. Skipping.')
				return False

		# Create ScanActivity for this task and send start scan notifs
		if self.track:
			target_name = None
			if self.domain:
				target_name = self.subdomain.name if self.subdomain else self.domain.name
				logger.info(f'Task {self.task_name} for {target_name} is RUNNING')
			else:
				logger.info(f'Task {self.task_name} is RUNNING')
			self.create_scan_activity()
		
		return True

	def handle_dry_run(self, *args, **kwargs):
		"""
		Handle task execution in DRY RUN mode.
		
		This method attempts to generate mock results for a task in the following order:
		1. Look for a mock file specific to this task
		2. Use the mock_generator method if available
		3. Fall back to regular task execution if mock generation fails
		
		Args:
			*args: Variable positional arguments passed to the task
			**kwargs: Variable keyword arguments passed to the task
			
		Returns:
			dict/list: Mock result if successfully generated
			None: If mock generation fails and should fall back to regular execution
			traceback: If a critical error occurred during dry run
		"""
		try:
			logger.info(f'Running task {self.task_name} in DRY RUN mode with MOCKS')
			
			# Try to find an appropriate mock result file
			# mock_path = self.get_mock_path()
			# if os.path.exists(mock_path):
			# 	try:
			# 		with open(mock_path, 'r') as f:
			# 			mock_data = f.read()
			# 			self.result = json.loads(mock_data)
			# 			self.status = SUCCESS_TASK
			# 			logger.info(f'Using mock data from {mock_path}')
			# 			return self.result
			# 	except json.JSONDecodeError as e:
			# 		logger.warning(f"Invalid JSON in mock file {mock_path}: {str(e)}")
			# 	except Exception as e:
			# 		logger.warning(f"Error reading mock file {mock_path}: {str(e)}")
			
			# No mock file or error reading it, try mock generator
			if hasattr(self, 'mock_generator'):
				try:
					logger.info(f'🧪 Generating mock result for {self.task_name}')
					self.result = self.mock_generator(*args, **kwargs)
					self.status = SUCCESS_TASK
					
					# Optionally save the generated mock for future use
					# if self.result and not os.path.exists(mock_path):
					# 	try:
					# 		os.makedirs(os.path.dirname(mock_path), exist_ok=True)
					# 		with open(mock_path, 'w') as f:
					# 			json.dump(self.result, f, indent=4)
					# 		logger.debug(f'Saved generated mock to {mock_path}')
					# 	except Exception as e:
					# 		logger.debug(f'Could not save mock to {mock_path}: {str(e)}')
					
					return self.result
				except Exception as e:
					# Log but continue with normal execution as fallback
					logger.exception(f"Error generating mock result for {self.task_name}: {str(e)}")
					logger.debug(fmt_traceback(e))
					return None
			
			# No mock generator available
			logger.info(f'No mock generator available for {self.task_name}, falling back to regular execution')
			return None
			
		except Exception as e:
			# Handle critical errors during dry run process
			self._handle_exception(e, context="dry run execution")
			return self.traceback

def check_task_cache(task_name, *args, **kwargs):
	"""Check if a task result exists in cache.
	
	This function is used by both individual tasks and grouped tasks
	to avoid code duplication and ensure consistent caching behavior.
	
	Args:
		task_name: Name of the task
		*args: Task args
		**kwargs: Task kwargs
		
	Returns:
		tuple: (cached_result, cache_key) - both None if cache disabled or miss
	"""
	if not RENGINE_CACHE_ENABLED:
		return None, None
		
	cache_key = get_task_cache_key(task_name, *args, **kwargs)
	result = cache.get(cache_key)
	
	if result and result != b'null':
		try:
			return json.loads(result), cache_key
		except json.JSONDecodeError:
			logger.warning(f"Invalid JSON in cache for key {cache_key}")
			
	return None, cache_key
