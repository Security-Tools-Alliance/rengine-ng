import json
import os
import pickle
import random
import shutil
import traceback
import shlex
import subprocess
from time import sleep

import humanize
import redis
import requests
import tldextract
import xmltodict
import validators
import ipaddress

from bs4 import BeautifulSoup
from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from discord_webhook import DiscordEmbed, DiscordWebhook
from django.db.models import Q
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

from reNgine.common_serializers import *
from reNgine.definitions import *
from reNgine.settings import *
from scanEngine.models import *
from dashboard.models import *
from startScan.models import *
from targetApp.models import *


logger = get_task_logger(__name__)
DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(CELERY_BROKER_URL)

#------------------#
# EngineType utils #
#------------------#
def dump_custom_scan_engines(results_dir):
    """Dump custom scan engines to YAML files.

    Args:
        results_dir (str): Results directory (will be created if non-existent).
    """
    custom_engines = EngineType.objects.filter(default_engine=False)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir, exist_ok=True)
    for engine in custom_engines:
        with open(os.path.join(results_dir, f"{engine.engine_name}.yaml"), 'w') as f:
            f.write(engine.yaml_configuration)

def load_custom_scan_engines(results_dir):
    """Load custom scan engines from YAML files. The filename without .yaml will
    be used as the engine name.

    Args:
        results_dir (str): Results directory containing engines configs.
    """
    config_paths = [
        f for f in os.listdir(results_dir)
        if os.path.isfile(os.path.join(results_dir, f)) and f.endswith('.yaml')
    ]
    for path in config_paths:
        engine_name = os.path.splitext(os.path.basename(path))[0]
        full_path = os.path.join(results_dir, path)
        with open(full_path, 'r') as f:
            yaml_configuration = f.read()

        engine, _ = EngineType.objects.get_or_create(engine_name=engine_name)
        engine.yaml_configuration = yaml_configuration
        engine.save()


#--------------------------------#
# InterestingLookupModel queries #
#--------------------------------#
def get_lookup_keywords():
	"""Get lookup keywords from InterestingLookupModel.

	Returns:
		list: Lookup keywords.
	"""
	lookup_model = InterestingLookupModel.objects.first()
	lookup_obj = InterestingLookupModel.objects.filter().order_by('-id').first()
	custom_lookup_keywords = []
	default_lookup_keywords = []
	if lookup_model:
		default_lookup_keywords = [
			key.strip()
			for key in lookup_model.keywords.split(',')]
	if lookup_obj:
		custom_lookup_keywords = [
			key.strip()
			for key in lookup_obj.keywords.split(',')
		]
	lookup_keywords = default_lookup_keywords + custom_lookup_keywords
	lookup_keywords = list(filter(None, lookup_keywords)) # remove empty strings from list
	return lookup_keywords


#-------------------#
# SubDomain queries #
#-------------------#

def get_subdomains(write_filepath=None, exclude_subdomains=False, ctx={}):
	"""Get Subdomain objects from DB.

	Args:
		write_filepath (str): Write info back to a file.
		exclude_subdomains (bool): Exclude subdomains, only return subdomain matching domain.
		ctx (dict): ctx

	Returns:
		list: List of subdomains matching query.
	"""
	domain_id = ctx.get('domain_id')
	scan_id = ctx.get('scan_history_id')
	subdomain_id = ctx.get('subdomain_id')
	exclude_subdomains = ctx.get('exclude_subdomains', False)
	url_filter = ctx.get('url_filter', '')
	domain = Domain.objects.filter(pk=domain_id).first()
	scan = ScanHistory.objects.filter(pk=scan_id).first()

	query = Subdomain.objects
	if domain:
		query = query.filter(target_domain=domain)
	if scan:
		query = query.filter(scan_history=scan)
	if subdomain_id:
		query = query.filter(pk=subdomain_id)
	elif domain and exclude_subdomains:
		query = query.filter(name=domain.name)
	subdomain_query = query.distinct('name').order_by('name')
	subdomains = [
		subdomain.name
		for subdomain in subdomain_query.all()
		if subdomain.name
	]
	if not subdomains:
		logger.error('No subdomains were found in query !')

	if url_filter:
		subdomains = [f'{subdomain}/{url_filter}' for subdomain in subdomains]

	if write_filepath:
		with open(write_filepath, 'w') as f:
			f.write('\n'.join(subdomains))

	return subdomains

def get_new_added_subdomain(scan_id, domain_id):
	"""Find domains added during the last scan.

	Args:
		scan_id (int): startScan.models.ScanHistory ID.
		domain_id (int): startScan.models.Domain ID.

	Returns:
		django.models.querysets.QuerySet: query of newly added subdomains.
	"""
	scan = (
		ScanHistory.objects
		.filter(domain=domain_id)
		.filter(tasks__overlap=['subdomain_discovery'])
		.filter(id__lte=scan_id)
	)
	if not scan.count() > 1:
		return
	last_scan = scan.order_by('-start_scan_date')[1]
	scanned_host_q1 = (
		Subdomain.objects
		.filter(scan_history__id=scan_id)
		.values('name')
	)
	scanned_host_q2 = (
		Subdomain.objects
		.filter(scan_history__id=last_scan.id)
		.values('name')
	)
	added_subdomain = scanned_host_q1.difference(scanned_host_q2)
	return (
		Subdomain.objects
		.filter(scan_history=scan_id)
		.filter(name__in=added_subdomain)
	)


def get_removed_subdomain(scan_id, domain_id):
	"""Find domains removed during the last scan.

	Args:
		scan_id (int): startScan.models.ScanHistory ID.
		domain_id (int): startScan.models.Domain ID.

	Returns:
		django.models.querysets.QuerySet: query of newly added subdomains.
	"""
	scan_history = (
		ScanHistory.objects
		.filter(domain=domain_id)
		.filter(tasks__overlap=['subdomain_discovery'])
		.filter(id__lte=scan_id)
	)
	if not scan_history.count() > 1:
		return
	last_scan = scan_history.order_by('-start_scan_date')[1]
	scanned_host_q1 = (
		Subdomain.objects
		.filter(scan_history__id=scan_id)
		.values('name')
	)
	scanned_host_q2 = (
		Subdomain.objects
		.filter(scan_history__id=last_scan.id)
		.values('name')
	)
	removed_subdomains = scanned_host_q2.difference(scanned_host_q1)
	return (
		Subdomain.objects
		.filter(scan_history=last_scan)
		.filter(name__in=removed_subdomains)
	)


def get_interesting_subdomains(scan_history=None, domain_id=None):
	"""Get Subdomain objects matching InterestingLookupModel conditions.

	Args:
		scan_history (startScan.models.ScanHistory, optional): Scan history.
		domain_id (int, optional): Domain id.

	Returns:
		django.db.Q: QuerySet object.
	"""
	lookup_keywords = get_lookup_keywords()
	lookup_obj = (
		InterestingLookupModel.objects
		.filter(custom_type=True)
		.order_by('-id').first())
	if not lookup_obj:
		return Subdomain.objects.none()

	url_lookup = lookup_obj.url_lookup
	title_lookup = lookup_obj.title_lookup
	condition_200_http_lookup = lookup_obj.condition_200_http_lookup

	# Filter on domain_id, scan_history_id
	query = Subdomain.objects
	if domain_id:
		query = query.filter(target_domain__id=domain_id)
	elif scan_history:
		query = query.filter(scan_history__id=scan_history)

	# Filter on HTTP status code 200
	if condition_200_http_lookup:
		query = query.filter(http_status__exact=200)

	# Build subdomain lookup / page title lookup queries
	url_lookup_query = Q()
	title_lookup_query = Q()
	for key in lookup_keywords:
		if url_lookup:
			url_lookup_query |= Q(name__icontains=key)
		if title_lookup:
			title_lookup_query |= Q(page_title__iregex=f"\\y{key}\\y")

	# Filter on url / title queries
	url_lookup_query = query.filter(url_lookup_query)
	title_lookup_query = query.filter(title_lookup_query)

	# Return OR query
	return url_lookup_query | title_lookup_query


#------------------#
# EndPoint queries #
#------------------#

def get_http_urls(
		is_alive=False,
		is_uncrawled=False,
		strict=False,
		ignore_files=False,
		write_filepath=None,
		exclude_subdomains=False,
		get_only_default_urls=False,
		ctx={}):
	"""Get HTTP urls from EndPoint objects in DB. Support filtering out on a
	specific path.

	Args:
		is_alive (bool): If True, select only alive urls.
		is_uncrawled (bool): If True, select only urls that have not been crawled.
		write_filepath (str): Write info back to a file.
		get_only_default_urls (bool):

	Returns:
		list: List of URLs matching query.
	"""
	domain_id = ctx.get('domain_id')
	scan_id = ctx.get('scan_history_id')
	subdomain_id = ctx.get('subdomain_id')
	url_filter = ctx.get('url_filter', '')
	domain = Domain.objects.filter(pk=domain_id).first()
	scan = ScanHistory.objects.filter(pk=scan_id).first()

	query = EndPoint.objects
	if domain:
		logger.debug(f'Searching URLs by domain {domain}')
		query = query.filter(target_domain=domain)
	if scan:
		logger.debug(f'Searching URLs by scan {scan}')
		query = query.filter(scan_history=scan)
	if subdomain_id:
		subdomain = Subdomain.objects.filter(pk=subdomain_id).first()
		logger.debug(f'Searching URLs by subdomain {subdomain}')
		query = query.filter(subdomain__id=subdomain_id)
	elif exclude_subdomains and domain:
		logger.debug(f'Excluding subdomains')
		query = query.filter(http_url=domain.http_url)
	if get_only_default_urls:
		logger.debug(f'Searching only for default URL')
		query = query.filter(is_default=True)

	# If is_uncrawled is True, select only endpoints that have not been crawled
	# yet (no status)
	if is_uncrawled:
		logger.debug(f'Searching for uncrawled endpoints only')
		query = query.filter(http_status__isnull=True)

	# If a path is passed, select only endpoints that contains it
	if url_filter and domain:
		url = f'{domain.name}{url_filter}'
		if strict:
			query = query.filter(http_url=url)
		else:
			query = query.filter(http_url__contains=url)

	# Select distinct endpoints and order
	endpoints = query.distinct('http_url').order_by('http_url').all()

	# If is_alive is True, select only endpoints that are alive
	if is_alive:
		endpoints = [e for e in endpoints if e.is_alive]

	# Grab only http_url from endpoint objects
	endpoints = [e.http_url for e in endpoints]
	if ignore_files: # ignore all files
		extensions_path = f'{RENGINE_HOME}/fixtures/extensions.txt'
		with open(extensions_path, 'r') as f:
			extensions = tuple(f.strip() for f in f.readlines())
		endpoints = [e for e in endpoints if not urlparse(e).path.endswith(extensions)]

	if not endpoints:
		logger.error(f'No endpoints were found in query !')

	if write_filepath:
		with open(write_filepath, 'w') as f:
			f.write('\n'.join([url for url in endpoints if url is not None]))

	return endpoints

def get_interesting_endpoints(scan_history=None, target=None):
	"""Get EndPoint objects matching InterestingLookupModel conditions.

	Args:
		scan_history (startScan.models.ScanHistory): Scan history.
		target (str): Domain id.

	Returns:
		django.db.Q: QuerySet object.
	"""

	lookup_keywords = get_lookup_keywords()
	lookup_obj = InterestingLookupModel.objects.filter().order_by('-id').first()
	if not lookup_obj:
		return EndPoint.objects.none()
	url_lookup = lookup_obj.url_lookup
	title_lookup = lookup_obj.title_lookup
	condition_200_http_lookup = lookup_obj.condition_200_http_lookup

	# Filter on domain_id, scan_history_id
	query = EndPoint.objects
	if target:
		query = query.filter(target_domain__id=target)
	elif scan_history:
		query = query.filter(scan_history__id=scan_history)

	# Filter on HTTP status code 200
	if condition_200_http_lookup:
		query = query.filter(http_status__exact=200)

	# Build subdomain lookup / page title lookup queries
	url_lookup_query = Q()
	title_lookup_query = Q()
	for key in lookup_keywords:
		if url_lookup:
			url_lookup_query |= Q(http_url__icontains=key)
		if title_lookup:
			title_lookup_query |= Q(page_title__iregex=f"\\y{key}\\y")

	# Filter on url / title queries
	url_lookup_query = query.filter(url_lookup_query)
	title_lookup_query = query.filter(title_lookup_query)

	# Return OR query
	return url_lookup_query | title_lookup_query


#-----------#
# URL utils #
#-----------#

def get_subdomain_from_url(url):
	"""Get subdomain from HTTP URL.

	Args:
		url (str): HTTP URL.

	Returns:
		str: Subdomain name.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in url:
		url = "http://" + url

	url_obj = urlparse(url.strip())
	return url_obj.netloc.split(':')[0]

def is_valid_domain_or_subdomain(domain):
    try:
        URLValidator(schemes=['http', 'https'])('http://' + domain)
        return True
    except ValidationError:
        return False

def get_domain_from_subdomain(subdomain):
	"""Get domain from subdomain.

	Args:
		subdomain (str): Subdomain name.

	Returns:
		str: Domain name.
	"""

	if not is_valid_domain_or_subdomain(subdomain):
		return None

	# Use tldextract to parse the subdomain
	extracted = tldextract.extract(subdomain)

	# if tldextract recognized the tld then its the final result
	if extracted.suffix:
		domain = f"{extracted.domain}.{extracted.suffix}"
	else:
		# Fallback method for unknown TLDs, like .clouds or .local etc
		parts = subdomain.split('.')
		if len(parts) >= 2:
			domain = '.'.join(parts[-2:])
		else:
			return None

	# Validate the domain before returning
	return domain if is_valid_domain_or_subdomain(subdomain) else None

def sanitize_url(http_url):
	"""Removes HTTP ports 80 and 443 from HTTP URL because it's ugly.

	Args:
		http_url (str): Input HTTP URL.

	Returns:
		str: Stripped HTTP URL.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in http_url:
		http_url = "http://" + http_url
	url = urlparse(http_url)

	if url.netloc.endswith(':80'):
		url = url._replace(netloc=url.netloc.replace(':80', ''))
	elif url.netloc.endswith(':443'):
		url = url._replace(scheme=url.scheme.replace('http', 'https'))
		url = url._replace(netloc=url.netloc.replace(':443', ''))
	return url.geturl().rstrip('/')

def extract_path_from_url(url):
	parsed_url = urlparse(url)

	# Reconstruct the URL without scheme and netloc
	reconstructed_url = parsed_url.path

	if reconstructed_url.startswith('/'):
		reconstructed_url = reconstructed_url[1:]  # Remove the first slash

	if parsed_url.params:
		reconstructed_url += ';' + parsed_url.params
	if parsed_url.query:
		reconstructed_url += '?' + parsed_url.query
	if parsed_url.fragment:
		reconstructed_url += '#' + parsed_url.fragment

	return reconstructed_url

def is_valid_url(url):
    """Check if a URL is valid, including both full URLs and domain:port format.
    
    Args:
        url (str): URL to validate (https://domain.com or domain.com:port)
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    logger.debug(f'Validating URL: {url}')
    
    # Handle URLs with scheme (http://, https://)
    if url.startswith(('http://', 'https://')):
        return validators.url(url)
    
    # Handle domain:port format
    try:
        if ':' in url:
            domain, port = url.rsplit(':', 1)
            # Validate port
            port = int(port)
            if not 1 <= port <= 65535:
                logger.debug(f'Invalid port number: {port}')
                return False
        else:
            domain = url
            
        # Validate domain
        if validators.domain(domain) or validators.ipv4(domain) or validators.ipv6(domain):
            logger.debug(f'Valid domain/IP found: {domain}')
            return True
            
        logger.debug(f'Invalid domain/IP: {domain}')
        return False
        
    except (ValueError, ValidationError) as e:
        logger.debug(f'Validation error: {str(e)}')
        return False

#-------#
# Utils #
#-------#


def get_random_proxy():
	"""Get a random proxy from the list of proxies input by user in the UI.

	Returns:
		str: Proxy name or '' if no proxy defined in db or use_proxy is False.
	"""
	if not Proxy.objects.all().exists():
		return ''
	proxy = Proxy.objects.first()
	if not proxy.use_proxy:
		return ''
	proxy_name = random.choice(proxy.proxies.splitlines())
	logger.warning('Using proxy: ' + proxy_name)
	# os.environ['HTTP_PROXY'] = proxy_name
	# os.environ['HTTPS_PROXY'] = proxy_name
	return proxy_name

def remove_ansi_escape_sequences(text):
	# Regular expression to match ANSI escape sequences
	ansi_escape_pattern = r'\x1b\[.*?m'

	# Use re.sub() to replace the ANSI escape sequences with an empty string
	plain_text = re.sub(ansi_escape_pattern, '', text)
	return plain_text

def get_cms_details(url):
	"""Get CMS details using cmseek.py.

	Args:
		url (str): HTTP URL.

	Returns:
		dict: Response.
	"""
	# this function will fetch cms details using cms_detector
	response = {}
	cms_detector_command = f'python3 /home/rengine/tools/.github/CMSeeK/cmseek.py --random-agent --batch --follow-redirect -u {url}'
	os.system(cms_detector_command)

	response['status'] = False
	response['message'] = 'Could not detect CMS!'

	parsed_url = urlparse(url)

	domain_name = parsed_url.hostname
	port = parsed_url.port

	find_dir = domain_name

	if port:
		find_dir += f'_{port}'

	# subdomain may also have port number, and is stored in dir as _port

	cms_dir_path =  f'/home/rengine/tools/.github/CMSeeK/Result/{find_dir}'
	cms_json_path =  cms_dir_path + '/cms.json'

	if os.path.isfile(cms_json_path):
		with open(cms_json_path, 'r') as file:
			cms_file_content = json.loads(file.read())
		if not cms_file_content.get('cms_id'):
			return response
		response = {}
		response = cms_file_content
		response['status'] = True
		# remove cms dir path
		try:
			shutil.rmtree(cms_dir_path)
		except Exception as e:
			print(e)

	return response


#--------------------#
# NOTIFICATION UTILS #
#--------------------#

def send_telegram_message(message):
	"""Send Telegram message.

	Args:
		message (str): Message.
	"""
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_telegram and
		notif.telegram_bot_token and
		notif.telegram_bot_chat_id)
	if not do_send:
		return
	telegram_bot_token = notif.telegram_bot_token
	telegram_bot_chat_id = notif.telegram_bot_chat_id
	send_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?chat_id={telegram_bot_chat_id}&parse_mode=Markdown&text={message}'
	requests.get(send_url)


def send_slack_message(message):
	"""Send Slack message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {'text': message}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_slack and
		notif.slack_hook_url)
	if not do_send:
		return
	hook_url = notif.slack_hook_url
	requests.post(url=hook_url, data=json.dumps(message), headers=headers)

def send_lark_message(message):
	"""Send lark message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {"msg_type":"interactive","card":{"elements":[{"tag":"div","text":{"content":message,"tag":"lark_md"}}]}}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_lark and
		notif.lark_hook_url)
	if not do_send:
		return
	hook_url = notif.lark_hook_url
	requests.post(url=hook_url, data=json.dumps(message), headers=headers)

def send_discord_message(
		message,
		title='',
		severity=None,
		url=None,
		files=None,
		fields={},
		fields_append=[]):
	"""Send Discord message.

	If title and fields are specified, ignore the 'message' and create a Discord
	embed that can be updated later if specifying the same title (title is the
	cache key).

	Args:
		message (str): Message to send. If an embed is used, this is ignored.
		severity (str, optional): Severity. Colors are picked based on severity.
		files (list, optional): List of files to attach to message.
		title (str, optional): Discord embed title.
		url (str, optional): Discord embed URL.
		fields (dict, optional): Discord embed fields.
		fields_append (list, optional): Discord embed field names to update
			instead of overwrite.
	"""

	# Check if do send
	notif = Notification.objects.first()
	if not (notif and notif.send_to_discord and notif.discord_hook_url):
		return False

	# If fields and title, use an embed
	use_discord_embed = fields and title
	if use_discord_embed:
		message = '' # no need for message in embeds

	# Check for cached response in cache, using title as key
	cached_response = DISCORD_WEBHOOKS_CACHE.get(title) if title else None
	if cached_response:
		cached_response = pickle.loads(cached_response)

	# Get existing webhook if found in cache
	cached_webhook = DISCORD_WEBHOOKS_CACHE.get(title + '_webhook') if title else None
	if cached_webhook:
		webhook = pickle.loads(cached_webhook)
		webhook.remove_embeds()
	else:
		webhook = DiscordWebhook(
			url=notif.discord_hook_url,
			rate_limit_retry=False,
			content=message)

	# Get existing embed if found in cache
	embed = None
	cached_embed = DISCORD_WEBHOOKS_CACHE.get(title + '_embed') if title else None
	if cached_embed:
		embed = pickle.loads(cached_embed)
	elif use_discord_embed:
		embed = DiscordEmbed(title=title)

	# Set embed fields
	if embed:
		if url:
			embed.set_url(url)
		if severity:
			embed.set_color(DISCORD_SEVERITY_COLORS[severity])
		embed.set_description(message)
		embed.set_timestamp()
		existing_fields_dict = {field['name']: field['value'] for field in embed.fields}
		logger.debug(''.join([f'\n\t{k}: {v}' for k, v in fields.items()]))
		for name, value in fields.items():
			if not value: # cannot send empty field values to Discord [error 400]
				continue
			value = str(value)
			new_field = {'name': name, 'value': value, 'inline': False}

			# If field already existed in previous embed, update it.
			if name in existing_fields_dict.keys():
				field = [f for f in embed.fields if f['name'] == name][0]

				# Append to existing field value
				if name in fields_append:
					existing_val = field['value']
					existing_val = str(existing_val)
					if value not in existing_val:
						value = f'{existing_val}\n{value}'

					if len(value) > 1024: # character limit for embed field
						value = value[0:1016] + '\n[...]'

				# Update existing embed
				ix = embed.fields.index(field)
				embed.fields[ix]['value'] = value

			else:
				embed.add_embed_field(**new_field)

		webhook.add_embed(embed)

		# Add webhook and embed objects to cache, so we can pick them up later
		DISCORD_WEBHOOKS_CACHE.set(title + '_webhook', pickle.dumps(webhook))
		DISCORD_WEBHOOKS_CACHE.set(title + '_embed', pickle.dumps(embed))

	# Add files to webhook
	if files:
		for (path, name) in files:
			with open(path, 'r') as f:
				content = f.read()
			webhook.add_file(content, name)

	# Edit webhook if it already existed, otherwise send new webhook
	if cached_response:
		response = webhook.edit(cached_response)
	else:
		response = webhook.execute()
		if use_discord_embed and response.status_code == 200:
			DISCORD_WEBHOOKS_CACHE.set(title, pickle.dumps(response))

	# Get status code
	if response.status_code == 429:
		errors = json.loads(
			response.content.decode('utf-8'))
		wh_sleep = (int(errors['retry_after']) / 1000) + 0.15
		sleep(wh_sleep)
		send_discord_message(
				message,
				title,
				severity,
				url,
				files,
				fields,
				fields_append)
	elif response.status_code != 200:
		logger.error(
			f'Error while sending webhook data to Discord.'
			f'\n\tHTTP code: {response.status_code}.'
			f'\n\tDetails: {response.content}')


def enrich_notification(message, scan_history_id, subscan_id):
	"""Add scan id / subscan id to notification message.

	Args:
		message (str): Original notification message.
		scan_history_id (int): Scan history id.
		subscan_id (int): Subscan id.

	Returns:
		str: Message.
	"""
	if scan_history_id is not None:
		if subscan_id:
			message = f'`#{scan_history_id}_{subscan_id}`: {message}'
		else:
			message = f'`#{scan_history_id}`: {message}'
	return message


def get_scan_title(scan_id, subscan_id=None, task_name=None):
	return f'Subscan #{subscan_id} summary' if subscan_id else f'Scan #{scan_id} summary'


def get_scan_url(scan_id=None, subscan_id=None):
	if scan_id:
		return f'https://{DOMAIN_NAME}/scan/detail/{scan_id}'
	return None


def get_scan_fields(engine, scan, subscan=None, status='RUNNING', tasks=[]):
	scan_obj = subscan if subscan else scan
	if subscan:
		tasks_h = f'`{subscan.type}`'
		host = subscan.subdomain.name
		scan_obj = subscan
	else:
		tasks_h = '• ' + '\n• '.join(f'`{task.name}`' for task in tasks) if tasks else ''
		host = scan.domain.name
		scan_obj = scan

	# Find scan elapsed time
	duration = None
	if scan_obj and status in ['ABORTED', 'FAILED', 'SUCCESS']:
		td = scan_obj.stop_scan_date - scan_obj.start_scan_date
		duration = humanize.naturaldelta(td)
	elif scan_obj:
		td = timezone.now() - scan_obj.start_scan_date
		duration = humanize.naturaldelta(td)

	# Build fields
	url = get_scan_url(scan.id)
	fields = {
		'Status': f'**{status}**',
		'Engine': engine.engine_name,
		'Scan ID': f'[#{scan.id}]({url})'
	}

	if subscan:
		url = get_scan_url(scan.id, subscan.id)
		fields['Subscan ID'] = f'[#{subscan.id}]({url})'

	if duration:
		fields['Duration'] = duration

	fields['Host'] = host
	if tasks:
		fields['Tasks'] = tasks_h

	return fields


def get_task_title(task_name, scan_id=None, subscan_id=None):
	if scan_id:
		prefix = f'#{scan_id}'
		if subscan_id:
			prefix += f'-#{subscan_id}'
		return f'`{prefix}` - `{task_name}`'
	return f'`{task_name}` [unbound]'


def get_task_header_message(name, scan_history_id, subscan_id):
	msg = f'`{name}` [#{scan_history_id}'
	if subscan_id:
		msg += f'_#{subscan_id}]'
	msg += 'status'
	return msg


def get_task_cache_key(func_name, *args, **kwargs):
	args_str = '_'.join([str(arg) for arg in args])
	kwargs_str = '_'.join([f'{k}={v}' for k, v in kwargs.items() if k not in RENGINE_TASK_IGNORE_CACHE_KWARGS])
	return f'{func_name}__{args_str}__{kwargs_str}'


def get_output_file_name(scan_history_id, subscan_id, filename):
	title = f'{scan_history_id}'
	if subscan_id:
		title += f'-{subscan_id}'
	title += f'_{filename}'
	return title


def get_traceback_path(task_name, results_dir, scan_history_id=None, subscan_id=None):
	path = results_dir
	if scan_history_id:
		path += f'/#{scan_history_id}'
		if subscan_id:
			path += f'-#{subscan_id}'
	path += f'-{task_name}.txt'
	return path


def fmt_traceback(exc):
	return '\n'.join(traceback.format_exception(None, exc, exc.__traceback__))


#--------------#
# CLI BUILDERS #
#--------------#

def _build_cmd(cmd, options, flags, sep=" "):
	for k,v in options.items():
		if not v:
			continue
		cmd += f" {k}{sep}{v}"

	for flag in flags:
		if not flag:
			continue
		cmd += f" --{flag}"

	return cmd

def get_nmap_cmd(
		input_file,
		args=None,
		host=None,
		ports=None,
		output_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		flags=[]):

	# Initialize base options
	options = {
		"--max-rate": max_rate,
		"-oX": output_file,
		"--script": script,
		"--script-args": script_args,
	}

	# Build command with options
	cmd = 'nmap'
	cmd = _build_cmd(cmd, options, flags)
 
	# Add ports and service detection
	if ports and '-p' not in cmd:
		cmd = f'{cmd} -p {ports}'
	if '-sV' not in cmd:
		cmd = f'{cmd} -sV'
	if '-Pn' not in cmd:
		cmd = f'{cmd} -Pn'

	# Add input source
	if not input_file:
		cmd += f" {host}" if host else ""
	else:
		cmd += f" -iL {input_file}"

	return cmd

def reverse_whois(lookup_keyword):
	domains = []
	'''
		This function will use viewdns to fetch reverse whois info
		Input: lookup keyword like email or registrar name
		Returns a list of domains as string.
	'''
	url = f"https://viewdns.info:443/reversewhois/?q={lookup_keyword}"
	headers = {
		"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
		"Sec-Ch-Ua-Mobile": "?0",
		"Sec-Ch-Ua-Platform": "\"Linux\"",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
		"Referer": "https://viewdns.info/",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
	}
	response = requests.get(url, headers=headers)
	soup = BeautifulSoup(response.content, 'lxml')
	table = soup.find("table", {"border" : "1"})
	for row in table or []:
		dom = row.findAll('td')[0].getText()
		created_on = row.findAll('td')[1].getText()
		if dom == 'Domain Name':
			continue
		domains.append({'name': dom, 'created_on': created_on})
	return domains


def get_domain_historical_ip_address(domain):
	ips = []
	'''
		This function will use viewdns to fetch historical IP address
		for a domain
	'''
	url = f"https://viewdns.info/iphistory/?domain={domain}"
	headers = {
		"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
		"Sec-Ch-Ua-Mobile": "?0",
		"Sec-Ch-Ua-Platform": "\"Linux\"",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
		"Referer": "https://viewdns.info/",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
	}
	response = requests.get(url, headers=headers)
	soup = BeautifulSoup(response.content, 'lxml')
	table = soup.find("table", {"border" : "1"})
	for row in table or []:
		ip = row.findAll('td')[0].getText()
		location = row.findAll('td')[1].getText()
		owner = row.findAll('td')[2].getText()
		last_seen = row.findAll('td')[2].getText()
		if ip == 'IP Address':
			continue
		ips.append(
			{
				'ip': ip,
				'location': location,
				'owner': owner,
				'last_seen': last_seen,
			}
		)
	return ips


def get_open_ai_key():
	openai_key = OpenAiAPIKey.objects.all()
	return openai_key[0] if openai_key else None


def get_netlas_key():
	netlas_key = NetlasAPIKey.objects.all()
	return netlas_key[0] if netlas_key else None


def extract_between(text, pattern):
	match = pattern.search(text)
	if match:
		return match.group(1).strip()
	return ""

import re

def parse_custom_header(custom_header):
    """
    Parse the custom_header input to ensure it is a dictionary with valid header values.

    Args:
        custom_header (dict or str): Dictionary or string containing the custom headers.

    Returns:
        dict: Parsed dictionary of custom headers.
    """
    def is_valid_header_value(value):
        return bool(re.match(r'^[\w\-\s.,;:@()/+*=\'\[\]{}]+$', value))

    if isinstance(custom_header, str):
        header_dict = {}
        headers = custom_header.split(',')
        for header in headers:
            parts = header.split(':', 1)
            if len(parts) == 2:
                key, value = parts
                key = key.strip()
                value = value.strip()
                if is_valid_header_value(value):
                    header_dict[key] = value
                else:
                    raise ValueError(f"Invalid header value: '{value}'")
            else:
                raise ValueError(f"Invalid header format: '{header}'")
        return header_dict
    elif isinstance(custom_header, dict):
        for key, value in custom_header.items():
            if not is_valid_header_value(value):
                raise ValueError(f"Invalid header value: '{value}'")
        return custom_header
    else:
        raise ValueError("custom_header must be a dictionary or a string")

def generate_header_param(custom_header, tool_name=None):
    """
    Generate command-line parameters for a specific tool based on the custom header.

    Args:
        custom_header (dict or str): Dictionary or string containing the custom headers.
        tool_name (str, optional): Name of the tool. Defaults to None.

    Returns:
        str: Command-line parameter for the specified tool.
    """
    logger.debug(f"Generating header parameters for tool: {tool_name}")
    logger.debug(f"Input custom_header: {custom_header}")

    # Ensure the custom_header is a dictionary
    custom_header = parse_custom_header(custom_header)

    # Common formats
    common_headers = [f"{key}: {value}" for key, value in custom_header.items()]
    semi_colon_headers = ';;'.join(common_headers)
    colon_headers = [f"{key}:{value}" for key, value in custom_header.items()]

    # Define format mapping for each tool
    format_mapping = {
        'common': ' '.join([f' -H "{header}"' for header in common_headers]),
        'dalfox': ' '.join([f' -H "{header}"' for header in colon_headers]),
        'hakrawler': f' -h "{semi_colon_headers}"',
        'gospider': generate_gospider_params(custom_header),
    }

    # Get the appropriate format based on the tool name
    result = format_mapping.get(tool_name, format_mapping.get('common'))
    logger.debug(f"Selected format for {tool_name}: {result}")

    # Return the corresponding parameter for the specified tool or default to common_headers format
    return result

def generate_gospider_params(custom_header):
    """
    Generate command-line parameters for gospider based on the custom header.

    Args:
        custom_header (dict): Dictionary containing the custom headers.

    Returns:
        str: Command-line parameters for gospider.
    """
    params = []
    for key, value in custom_header.items():
        if key.lower() == 'user-agent':
            params.append(f' -u "{value}"')
        elif key.lower() == 'cookie':
            params.append(f' --cookie "{value}"')
        else:
            params.append(f' -H "{key}:{value}"')
    return ' '.join(params)

def is_iterable(variable):
    try:
        iter(variable)
        return True
    except TypeError:
        return False

def extract_columns(row, columns):
    """
    Extract specific columns from a row based on column indices.
    
    Args:
        row (list): The CSV row as a list of values.
        columns (list): List of column indices to extract.
    
    Returns:
        list: Extracted values from the specified columns.
    """
    return [row[i] for i in columns]

def create_scan_object(host_id, engine_id, initiated_by_id=None):
    '''
    create task with pending status so that celery task will execute when
    threads are free
    Args:
        host_id: int: id of Domain model
        engine_id: int: id of EngineType model
        initiated_by_id: int : id of User model (Optional)
    '''
    # get current time
    current_scan_time = timezone.now()
    # fetch engine and domain object
    engine = EngineType.objects.get(pk=engine_id)
    domain = Domain.objects.get(pk=host_id)
    scan = ScanHistory()
    scan.scan_status = INITIATED_TASK
    scan.domain = domain
    scan.scan_type = engine
    scan.start_scan_date = current_scan_time
    if initiated_by_id:
        user = User.objects.get(pk=initiated_by_id)
        scan.initiated_by = user
    scan.save()
    # save last scan date for domain model
    domain.start_scan_date = current_scan_time
    domain.save()
    return scan.id

def prepare_command(cmd, shell):
    """
    Prepare the command for execution.

    Args:
        cmd (str): The command to prepare.
        shell (bool): Whether to use shell execution.

    Returns:
        str or list: The prepared command, either as a string (for shell execution) or a list (for non-shell execution).
    """
    return cmd if shell else shlex.split(cmd)

def create_command_object(cmd, scan_id, activity_id):
    """
    Create a Command object in the database.

    Args:
        cmd (str): The command to be executed.
        scan_id (int): ID of the associated scan.
        activity_id (int): ID of the associated activity.

    Returns:
        Command: The created Command object.
    """
    return Command.objects.create(
        command=cmd,
        time=timezone.now(),
        scan_history_id=scan_id,
        activity_id=activity_id
    )

def process_line(line, trunc_char=None):
    """
    Process a line of output from the command.

    Args:
        line (str): The line to process.
        trunc_char (str, optional): Character to truncate the line. Defaults to None.

    Returns:
        str or dict: The processed line, either as a string or a JSON object if the line is valid JSON.
    """
    line = line.strip()
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    line = ansi_escape.sub('', line)
    line = line.replace('\\x0d\\x0a', '\n')
    if trunc_char and line.endswith(trunc_char):
        line = line[:-1]
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return line

def write_history(history_file, cmd, return_code, output):
    """
    Write command execution history to a file.

    Args:
        history_file (str): Path to the history file.
        cmd (str): The executed command.
        return_code (int): The return code of the command.
        output (str): The output of the command.
    """
    mode = 'a' if os.path.exists(history_file) else 'w'
    with open(history_file, mode) as f:
        f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')

def execute_command(command, shell, cwd):
    """
    Execute a command using subprocess.

    Args:
        command (str or list): The command to execute.
        shell (bool): Whether to use shell execution.
        cwd (str): The working directory for the command.

    Returns:
        subprocess.Popen: The Popen object for the executed command.
    """
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=shell,
        cwd=cwd,
        bufsize=-1,
        universal_newlines=True,
        encoding='utf-8'
    )

def get_data_from_post_request(request, field):
    """
    Get data from a POST request.

    Args:
        request (HttpRequest): The request object.
        field (str): The field to get data from.
    Returns:
        list: The data from the specified field.
    """
    if hasattr(request.data, 'getlist'):
        return request.data.getlist(field)
    else:
        return request.data.get(field, [])

def safe_int_cast(value, default=None):
    """
    Convert a value to an integer if possible, otherwise return a default value.

    Args:
        value: The value or the array of values to convert to an integer.
        default: The default value to return if conversion fails.

    Returns:
        int or default: The integer value if conversion is successful, otherwise the default value.
    """
    if isinstance(value, list):
        return [safe_int_cast(item) for item in value]
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def get_ip_info(ip_address):
	"""
	get_ip_info retrieves information about a given IP address, determining whether it is an IPv4 or IPv6 address. It returns an appropriate IP address object if the input is valid, or None if the input is not a valid IP address.

	Args:
		ip_address (str): The IP address to validate and retrieve information for.

	Returns:
		IPv4Address or IPv6Address or None: An IP address object if the input is valid, otherwise None.
	"""
	is_ipv4 = bool(validators.ipv4(ip_address))
	is_ipv6 = bool(validators.ipv6(ip_address))
	ip_data = None
	if is_ipv4:
		ip_data = ipaddress.IPv4Address(ip_address)
	elif is_ipv6:
		ip_data = ipaddress.IPv6Address(ip_address)
	else:
		return None
	return ip_data

def get_ips_from_cidr_range(target):
    """
    get_ips_from_cidr_range generates a list of IP addresses from a given CIDR range. It returns the list of valid IPv4 addresses or logs an error if the provided CIDR range is invalid.

    Args:
        target (str): The CIDR range from which to generate IP addresses.

    Returns:
        list of str: A list of IP addresses as strings if the CIDR range is valid; otherwise, an empty list is returned.
        
    Raises:
        ValueError: If the target is not a valid CIDR range, an error is logged.
    """
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(target)]
    except ValueError:
        logger.error(f'{target} is not a valid CIDR range. Skipping.')
        return []

def get_http_crawl_value(engine, config):
    """Get HTTP crawl value from config.
    
    Args:
        engine: EngineType object
        config: Configuration dictionary or None
        
    Returns:
        bool: True if HTTP crawl is enabled
    """
    # subscan engine value
    enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) if config else None
    if enable_http_crawl is None:
        # scan engine value
        yaml_config = yaml.safe_load(engine.yaml_configuration)
        enable_http_crawl = yaml_config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
    logger.debug(f'Enable HTTP crawl: {enable_http_crawl}')
    return enable_http_crawl

def get_or_create_port(ip_address, port_number, service_info=None):
    """Centralized port handling with service info management."""
    port, created = Port.objects.get_or_create(
        ip_address=ip_address,
        number=port_number,
        defaults={
            'is_uncommon': port_number in UNCOMMON_WEB_PORTS,
            'service_name': 'unknown',
            'description': ''
        }
    )
    
    if not created and service_info:
        update_port_service_info(port, service_info)
    
    return port

def update_port_service_info(port, service_info):
    """Update port service information consistently."""
    try:
        description_parts = []
        for key in ['service_product', 'service_version', 'service_extrainfo']:
            value = service_info.get(key)
            if value and value not in description_parts:
                description_parts.append(value)
        
        port.service_name = service_info.get('service_name', 'unknown').strip() or 'unknown'
        port.description = ' - '.join(filter(None, description_parts))[:1000]
        
        if port.ip_address:
            logger.debug(f'Updating service info for {port.ip_address.address}:{port.number}')
            
        port.save(update_fields=['service_name', 'description'])
        
    except Exception as e:
        logger.error(f"Error updating port {port.number}: {str(e)}")
        raise