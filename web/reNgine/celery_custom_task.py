import json
import os
import threading

from celery import Task
from celery.utils.log import get_task_logger
from celery.worker.request import Request
from django.utils import timezone
from redis import Redis
from reNgine.utilities.misc import fmt_traceback, get_traceback_path
from reNgine.utilities.notification import get_output_file_name
from reNgine.utilities.database import get_task_cache_key
from reNgine.definitions import (
	CELERY_TASK_STATUS_MAP,
	FAILED_TASK,
	RUNNING_TASK,
	SUCCESS_TASK
)
from reNgine.settings import (
	RENGINE_CACHE_ENABLED,
	RENGINE_RECORD_ENABLED,
	RENGINE_RAISE_ON_ERROR,
	RENGINE_RESULTS
)
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, SubScan

logger = get_task_logger(__name__)

cache = None
if 'CELERY_BROKER' in os.environ:
	cache = Redis.from_url(os.environ['CELERY_BROKER'])


class TaskContext:
	"""Isolated context class to prevent context pollution between concurrent tasks"""
	
	def __init__(self, ctx=None, request=None, task_name=None, description=None):
		"""Initialize task context with isolated variables"""
		if ctx is None:
			ctx = {}
			
		# Core task info
		self.task_name = task_name
		self.description = description
		self.request = request
		
		# Execution state
		self.result = None
		self.error = None
		self.traceback = None
		self.output_path = None
		self.status = RUNNING_TASK
		
		# Context variables from ctx parameter
		self.track = ctx.get('track', True)
		self.scan_id = ctx.get('scan_history_id')
		self.subscan_id = ctx.get('subscan_id') 
		self.engine_id = ctx.get('engine_id')
		self.filename = ctx.get('filename')
		self.url_filter = ctx.get('url_filter', '')
		self.results_dir = ctx.get('results_dir', RENGINE_RESULTS)
		self.yaml_configuration = ctx.get('yaml_configuration', {})
		self.out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
		
		# Derived paths
		self.history_file = f'{self.results_dir}/commands.txt'
		
		# Database objects - initialized separately for thread safety
		self.scan = None
		self.subscan = None
		self.engine = None
		self.domain = None
		self.domain_id = None
		self.subdomain = None
		self.subdomain_id = None
		self.activity_id = None
		self.activity = None
		
	def load_database_objects(self):
		"""Load database objects in a thread-safe manner"""
		from startScan.models import ScanHistory, SubScan
		from scanEngine.models import EngineType
		
		self.scan = ScanHistory.objects.filter(pk=self.scan_id).first()
		self.subscan = SubScan.objects.filter(pk=self.subscan_id).first()
		self.engine = EngineType.objects.filter(pk=self.engine_id).first()
		self.domain = self.scan.domain if self.scan else None
		self.domain_id = self.domain.id if self.domain else None
		self.subdomain = self.subscan.subdomain if self.subscan else None
		self.subdomain_id = self.subdomain.id if self.subdomain else None
		
	@property
	def status_str(self):
		"""Get string representation of task status"""
		return CELERY_TASK_STATUS_MAP.get(self.status)


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
	"""
	Request = RengineRequest
	
	def __init__(self):
		super().__init__()
		# Thread-local storage for context isolation
		self._local = threading.local()

	@property
	def context(self):
		"""Get the current task context for this thread"""
		if not hasattr(self._local, 'context'):
			return None
		return self._local.context
		
	@property 
	def status_str(self):
		"""Get status string from context if available, fallback to instance"""
		if self.context:
			return self.context.status_str
		return CELERY_TASK_STATUS_MAP.get(getattr(self, 'status', None))
		
	# Proxy properties to context for backward compatibility
	@property
	def result(self):
		return self.context.result if self.context else getattr(self, '_result', None)
	
	@result.setter 
	def result(self, value):
		if self.context:
			self.context.result = value
		else:
			self._result = value
			
	@property
	def scan_id(self):
		return self.context.scan_id if self.context else getattr(self, '_scan_id', None)
		
	@property
	def domain(self):
		return self.context.domain if self.context else getattr(self, '_domain', None)
		
	@property
	def domain_id(self):
		return self.context.domain_id if self.context else getattr(self, '_domain_id', None)
		
	@property
	def subdomain(self):
		return self.context.subdomain if self.context else getattr(self, '_subdomain', None)
		
	@property
	def activity_id(self):
		return self.context.activity_id if self.context else getattr(self, '_activity_id', None)
		
	@activity_id.setter
	def activity_id(self, value):
		if self.context:
			self.context.activity_id = value
		else:
			self._activity_id = value
		
	@property
	def results_dir(self):
		return self.context.results_dir if self.context else getattr(self, '_results_dir', None)
		
	@property
	def output_path(self):
		return self.context.output_path if self.context else getattr(self, '_output_path', None)
		
	@output_path.setter
	def output_path(self, value):
		if self.context:
			self.context.output_path = value
		else:
			self._output_path = value
		
	@property
	def yaml_configuration(self):
		return self.context.yaml_configuration if self.context else getattr(self, '_yaml_configuration', {})
		
	@property
	def url_filter(self):
		return self.context.url_filter if self.context else getattr(self, '_url_filter', '')
		
	@property
	def out_of_scope_subdomains(self):
		return self.context.out_of_scope_subdomains if self.context else getattr(self, '_out_of_scope_subdomains', [])
		
	@property
	def history_file(self):
		return self.context.history_file if self.context else getattr(self, '_history_file', None)
		
	@property
	def scan(self):
		return self.context.scan if self.context else getattr(self, '_scan', None)
		
	@property
	def subscan(self):
		return self.context.subscan if self.context else getattr(self, '_subscan', None)
		
	@property
	def engine(self):
		return self.context.engine if self.context else getattr(self, '_engine', None)
		
	@property
	def subscan_id(self):
		return self.context.subscan_id if self.context else getattr(self, '_subscan_id', None)
		
	@property
	def engine_id(self):
		return self.context.engine_id if self.context else getattr(self, '_engine_id', None)
		
	@property
	def track(self):
		return self.context.track if self.context else getattr(self, '_track', True)
		
	@property
	def task_name(self):
		return self.context.task_name if self.context else getattr(self, '_task_name', None)
		
	@property
	def description(self):
		return self.context.description if self.context else getattr(self, '_description', None)
		
	@property
	def filename(self):
		return self.context.filename if self.context else getattr(self, '_filename', None)
		
	@filename.setter
	def filename(self, value):
		if self.context:
			self.context.filename = value
		else:
			self._filename = value
		
	@property
	def status(self):
		return self.context.status if self.context else getattr(self, '_status', None)
		
	@status.setter
	def status(self, value):
		if self.context:
			self.context.status = value
		else:
			self._status = value
		
	@property
	def error(self):
		return self.context.error if self.context else getattr(self, '_error', None)
		
	@error.setter
	def error(self, value):
		if self.context:
			self.context.error = value
		else:
			self._error = value
		
	@property
	def traceback(self):
		return self.context.traceback if self.context else getattr(self, '_traceback', None)
		
	@traceback.setter
	def traceback(self, value):
		if self.context:
			self.context.traceback = value
		else:
			self._traceback = value
		
	@property
	def subdomain_id(self):
		return self.context.subdomain_id if self.context else getattr(self, '_subdomain_id', None)

	def __call__(self, *args, **kwargs):
		# Create isolated context for this task execution
		task_name = self.name.split('.')[-1]
		description = kwargs.get('description') or ' '.join(task_name.split('_')).capitalize()
		ctx = kwargs.get('ctx', {})
		
		# Create new context instance for this thread/execution
		context = TaskContext(
			ctx=ctx,
			request=self.request,
			task_name=task_name,
			description=description
		)
		
		# Store context in thread-local storage to prevent pollution
		self._local.context = context
		
		# Load database objects
		context.load_database_objects()
		
		logger = get_task_logger(context.task_name)

		# Set filename if not already set
		if not context.filename:
			context.filename = get_output_file_name(
				context.scan_id,
				context.subscan_id,
				f'{context.task_name}.txt')
			if context.task_name == 'screenshot':
				context.filename = 'Requests.csv'
		context.output_path = f'{context.results_dir}/{context.filename}'

		if RENGINE_RECORD_ENABLED:
			if context.engine:
					# task not in engine.tasks, skip it.
					# create a rule for tasks that has to run parallel like dalfox
					# xss scan but not necessarily part of main task rather part like
					# dalfox scan being part of vulnerability task
					# Exempted tasks that can always run
					dependent_tasks = {
							'dalfox_xss_scan': 'vulnerability_scan',
							'crlfuzz': 'vulnerability_scan',
							'nuclei_scan': 'vulnerability_scan',
							'nuclei_individual_severity_module': 'vulnerability_scan',
							's3scanner': 'vulnerability_scan',
					}

					exempted_tasks = [
							'http_crawl',
							'scan_http_ports',
							'run_nmap',
							'nmap',
							'pre_crawl',
							'intermediate_crawl',
							'post_crawl'
					]

					# Skip if task is not part of engine and not exempted
					if (
							context.track and
							context.task_name not in context.engine.tasks and
							dependent_tasks.get(context.task_name) not in context.engine.tasks and
							context.task_name.lower() not in exempted_tasks
					):
							logger.debug(f'Task {context.task_name} is not part of engine "{context.engine.engine_name}" tasks. Skipping.')
							return False

			# Create ScanActivity for this task and send start scan notifs
			if context.track:
				# Build task identifier with description for better clarity
				task_identifier = f'{context.task_name}'
				if context.description and context.description != context.task_name.replace('_', ' ').capitalize():
					task_identifier += f' ({context.description})'
				
				if context.domain:
					logger.warning(f'Task {task_identifier} for {context.subdomain.name if context.subdomain else context.domain.name} is RUNNING')
				else:
					logger.warning(f'Task {task_identifier} is RUNNING')
				self.create_scan_activity()

		if RENGINE_CACHE_ENABLED:
			# Check for result in cache and return it if it's a hit
			record_key = get_task_cache_key(self.name, *args, **kwargs)
			cached_result = cache.get(record_key)
			if cached_result and cached_result != b'null':
				context.status = SUCCESS_TASK
				if RENGINE_RECORD_ENABLED and context.track:
					# Build task identifier with description for better clarity
					task_identifier = f'{context.task_name}'
					if context.description and context.description != context.task_name.replace('_', ' ').capitalize():
						task_identifier += f' ({context.description})'
					
					if context.domain:
						logger.warning(f'Task {task_identifier} for {context.subdomain.name if context.subdomain else context.domain.name} status is SUCCESS (CACHED)')
					else:
						logger.warning(f'Task {task_identifier} status is SUCCESS (CACHED)')
					self.update_scan_activity()
				return json.loads(cached_result)

		# Execute task, catch exceptions and update ScanActivity object after
		# task has finished running.
		try:
			context.result = self.run(*args, **kwargs)
			context.status = SUCCESS_TASK

		except Exception as exc:
			context.status = FAILED_TASK
			context.error = repr(exc)
			context.traceback = fmt_traceback(exc)
			context.result = context.traceback
			context.output_path = get_traceback_path(
				context.task_name,
				context.results_dir,
				context.scan_id,
				context.subscan_id)
			os.makedirs(os.path.dirname(context.output_path), exist_ok=True)

			if RENGINE_RAISE_ON_ERROR:
				raise exc

			logger.exception(exc)

		finally:
			self.write_results()

			if RENGINE_RECORD_ENABLED and context.track:
				# Build task identifier with description for better clarity
				task_identifier = f'{context.task_name}'
				if context.description and context.description != context.task_name.replace('_', ' ').capitalize():
					task_identifier += f' ({context.description})'
				
				if context.domain:
					msg = f'Task {task_identifier} for {context.subdomain.name if context.subdomain else context.domain.name} status is {context.status_str}'
				else:
					msg = f'Task {task_identifier} status is {context.status_str}'
				msg += f' | Error: {context.error}' if context.error else ''
				logger.warning(msg)
				
				self.update_scan_activity()

		# Set task result in cache if task was successful
		if RENGINE_CACHE_ENABLED and context.status == SUCCESS_TASK and context.result:
			cache.set(record_key, json.dumps(context.result))
			cache.expire(record_key, 600) # 10mn cache

		return context.result

	def write_results(self):
		context = self.context
		if not context or not context.result:
			return False
		is_json_results = isinstance(context.result, dict) or isinstance(context.result, list)
		if not context.output_path:
			return False
		if not os.path.exists(context.output_path):
			with open(context.output_path, 'w') as f:
				if is_json_results:
					json.dump(context.result, f, indent=4)
				else:
					f.write(context.result)
			logger.warning(f'Wrote {context.task_name} results to {context.output_path}')

	def create_scan_activity(self):
		context = self.context
		if not context or not context.track:
			return
			
		# Build task identifier with description for better clarity
		task_identifier = f'{context.task_name}'
		if context.description and context.description != context.task_name.replace('_', ' ').capitalize():
			task_identifier += f' ({context.description})'
		
		celery_id = context.request.id
		
		context.activity = ScanActivity(
			name=context.task_name,
			title=context.description,
			time=timezone.now(),
			status=RUNNING_TASK,
			celery_id=celery_id)
		context.activity.save()
		context.activity_id = context.activity.id
		
		if context.scan:
			context.activity.scan_of = context.scan
			context.activity.save()
			context.scan.celery_ids.append(celery_id)
			context.scan.save()
		if context.subscan:
			context.subscan.celery_ids.append(celery_id)
			context.subscan.save()

		# Send notification
		self.notify()

	def update_scan_activity(self):
		context = self.context
		if not context or not context.track:
			return
			
		# Build task identifier with description for better clarity
		task_identifier = f'{context.task_name}'
		if context.description and context.description != context.task_name.replace('_', ' ').capitalize():
			task_identifier += f' ({context.description})'

		# Trim error before saving to DB
		error_message = context.error
		if context.error and len(context.error) > 300:
			error_message = context.error[:288] + '...[trimmed]'

		# Use celery_id to find the correct activity (more reliable than context.activity reference)
		celery_id = getattr(context.request, 'id', 'NO_ID')
		try:
			fresh_activity = ScanActivity.objects.get(celery_id=celery_id)
			
			# Update the fresh instance
			fresh_activity.status = context.status
			fresh_activity.error_message = error_message
			fresh_activity.traceback = context.traceback
			fresh_activity.time = timezone.now()
			fresh_activity.save()
			
			# Update our local reference
			context.activity = fresh_activity
			context.activity_id = fresh_activity.id
			
		except ScanActivity.DoesNotExist:
			logger.error(f'Task {context.task_name} - No activity found with celery_id {celery_id}')
		except Exception as e:
			logger.error(f'Task {context.task_name} - Failed to update activity for celery_id {celery_id}: {e}')
			
		self.notify()

	def notify(self, name=None, severity=None, fields={}, add_meta_info=True):
		context = self.context
		if not context:
			return
			
		# Import here to avoid Celery circular import and be able to use `delay`
		from reNgine.tasks import send_task_notif
		return send_task_notif.delay(
			name or context.task_name,
			status=context.status_str,
			result=context.result,
			traceback=context.traceback,
			output_path=context.output_path,
			scan_history_id=context.scan_id,
			engine_id=context.engine_id,
			subscan_id=context.subscan_id,
			severity=severity,
			add_meta_info=add_meta_info,
			update_fields=fields)

	def s(self, *args, **kwargs):
		# TODO: set task status to INIT when creating a signature.
		return super().s(*args, **kwargs)
