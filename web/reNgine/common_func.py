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
import validators
import ipaddress

from bs4 import BeautifulSoup
from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from discord_webhook import DiscordEmbed, DiscordWebhook
from django.db.models import Q
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.utils import timezone

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
	subdomain = Subdomain.objects.filter(pk=subdomain_id).first()
	scan = ScanHistory.objects.filter(pk=scan_id).first()
	if subdomain:
		logger.info(f'Searching for endpoints to crawl on subdomain {subdomain}')
	else:
		logger.info(f'Searching for endpoints to crawl on domain {domain}')
	log_header = 'Found a total of '
	log_found = ''

	query = EndPoint.objects
	if domain:
		logger.debug(f'Searching URLs by domain {domain}')
		query = query.filter(target_domain=domain)
		log_found = f'{log_header}{query.count()} endpoints for domain {domain}'
		logger.debug(log_found)
	if scan:
		logger.debug(f'Searching URLs by scan {scan}')
		query = query.filter(scan_history=scan)
		log_found = f'{log_header}{query.count()} endpoints for scan {scan}'
		logger.debug(log_found)
	if subdomain_id:
		subdomain = Subdomain.objects.filter(pk=subdomain_id).first()
		logger.debug(f'Searching URLs by subdomain {subdomain}')
		query = query.filter(subdomain__id=subdomain_id)
		log_found = f'{log_header}{query.count()} endpoints for subdomain {subdomain}'
		logger.debug(log_found)
	elif exclude_subdomains and domain:
		logger.debug('Excluding subdomains')
		query = query.filter(http_url=domain.http_url)
		log_found = f'{log_header}{query.count()} endpoints for domain {domain}'
		logger.debug(log_found)
	if get_only_default_urls:
		logger.debug('Searching only for default URL')
		query = query.filter(is_default=True)
		log_found = f'{log_header}{query.count()} default endpoints'
		logger.debug(log_found)

	# If is_uncrawled is True, select only endpoints that have not been crawled
	# yet (no status)
	if is_uncrawled:
		logger.debug('Searching for uncrawled endpoints only')
		query = query.filter(http_status=0)
		log_found = f'{log_header}{query.count()} uncrawled endpoints'
		logger.debug(log_found)

	# If a path is passed, select only endpoints that contains it
	if url_filter and domain:
		logger.debug(f'Searching for endpoints with path {url_filter}')
		url = f'{domain.name}{url_filter}'
		if strict:
			query = query.filter(http_url=url)
		else:
			query = query.filter(http_url__contains=url)
		log_found = f'{log_header}{query.count()} endpoints with path {url_filter}'
		logger.debug(log_found)

	if log_found:
		logger.info(log_found)

	# Select distinct endpoints and order
	endpoints = query.distinct('http_url').order_by('http_url').all()

	# If is_alive is True, select only endpoints that are alive
	if is_alive:
		logger.debug('Searching for alive endpoints only')
		endpoints = [e for e in endpoints if e.is_alive]
		logger.debug(f'Found a total of {len(endpoints)} alive endpoints')

	# Grab only http_url from endpoint objects
	endpoints = [e.http_url for e in endpoints]
	if ignore_files: # ignore all files
		extensions_path = f'{RENGINE_HOME}/fixtures/extensions.txt'
		with open(extensions_path, 'r') as f:
			extensions = tuple(f.strip() for f in f.readlines())
		endpoints = [e for e in endpoints if not urlparse(e).path.endswith(extensions)]

	if not endpoints:
		logger.error('No endpoints were found in query !')

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




def ensure_endpoints_crawled_and_execute(task_function, ctx, description=None, max_wait_time=300):
    """
    Ensure endpoints are crawled before executing a task that needs alive endpoints.
    
    Args:
        task_function: The task function to execute
        ctx: Task context
        description: Task description
        max_wait_time: Maximum time to wait for endpoints (seconds)
        
    Returns:
        Task result or None if no alive endpoints available
    """
    from startScan.models import EndPoint
    from django.utils import timezone
    from copy import deepcopy
    import time
    
    logger.info(f'Ensuring endpoints are crawled for {task_function.__name__}')
    
    # Check if we already have alive endpoints
    alive_endpoints = get_http_urls(is_alive=True, ctx=ctx)
    
    if alive_endpoints:
        logger.info(f'Found {len(alive_endpoints)} alive endpoints, executing {task_function.__name__}')
        return task_function(ctx=ctx, description=description)
    
    # No alive endpoints found, check if we have uncrawled endpoints
    uncrawled_endpoints = get_http_urls(is_uncrawled=True, ctx=ctx)
    
    if not uncrawled_endpoints:
        logger.warning(f'No endpoints found for {task_function.__name__}, skipping task')
        return None
    
    logger.info(f'Found {len(uncrawled_endpoints)} uncrawled endpoints, launching HTTP crawl first')
    
    # Launch http_crawl synchronously for the specific endpoints we need
    from reNgine.tasks import http_crawl
    custom_ctx = deepcopy(ctx)
    custom_ctx['track'] = False  # Don't track this internal crawl
    
    # Execute http_crawl and wait for completion (but with timeout)
    http_crawl_task = http_crawl.delay(
        urls=uncrawled_endpoints[:50],  # Limit to avoid overwhelming
        ctx=custom_ctx,
        update_subdomain_metadatas=True
    )
    
    # Wait for crawl completion with timeout
    wait_time = 0
    check_interval = 10  # Check every 10 seconds
    
    while wait_time < max_wait_time:
        time.sleep(check_interval)
        wait_time += check_interval
        
        # Check if we now have alive endpoints
        alive_endpoints = get_http_urls(is_alive=True, ctx=ctx)
        if alive_endpoints:
            logger.info(f'HTTP crawl completed, found {len(alive_endpoints)} alive endpoints')
            return task_function(ctx=ctx, description=description)
        
        # Check if crawl task is done
        if http_crawl_task.ready():
            break
    
    # Final check after timeout
    alive_endpoints = get_http_urls(is_alive=True, ctx=ctx)
    if alive_endpoints:
        logger.info(f'Found {len(alive_endpoints)} alive endpoints after wait period')
        return task_function(ctx=ctx, description=description)
    else:
        logger.warning(f'No alive endpoints found after {wait_time}s wait, skipping {task_function.__name__}')
        return None


def smart_http_crawl_if_needed(urls, ctx, wait_for_completion=False, max_wait_time=120):
    """
    Intelligently launch http_crawl only if endpoints need to be crawled.
    
    Args:
        urls: URLs to crawl
        ctx: Task context
        wait_for_completion: Whether to wait for crawl completion
        max_wait_time: Maximum time to wait (seconds)
        
    Returns:
        True if crawl was launched/completed, False otherwise
    """
    from startScan.models import EndPoint
    from reNgine.tasks import http_crawl
    from copy import deepcopy
    import time
    
    if not urls:
        return False
    
    # Check which URLs actually need crawling
    scan_id = ctx.get('scan_history_id')
    
    urls_to_crawl = []
    for url in urls:
        # Check if endpoint exists and has been crawled
        existing_endpoint = EndPoint.objects.filter(
            scan_history_id=scan_id,
            http_url=url
        ).first()
        
        if not existing_endpoint or existing_endpoint.http_status == 0:
            urls_to_crawl.append(url)
    
    if not urls_to_crawl:
        logger.info('All endpoints already crawled, skipping HTTP crawl')
        return True
    
    logger.info(f'Launching HTTP crawl for {len(urls_to_crawl)} uncrawled URLs')
    
    custom_ctx = deepcopy(ctx)
    custom_ctx['track'] = False
    
    task = http_crawl.delay(urls=urls_to_crawl, ctx=custom_ctx, update_subdomain_metadatas=True)
    
    if not wait_for_completion:
        return True
    
    # Wait for completion
    wait_time = 0
    check_interval = 5
    
    while wait_time < max_wait_time and not task.ready():
        time.sleep(check_interval)
        wait_time += check_interval
    
    return task.ready()

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

#-------------------------------#
# Database Save Functions      #
#-------------------------------#

def save_endpoint(
        http_url,
        ctx={},
        is_default=False,
        http_status=0,
        **endpoint_data):
    """Get or create EndPoint object.

    Args:
        http_url (str): Input HTTP URL.
        ctx (dict): Context containing scan and domain information.
        is_default (bool): If the url is a default url for SubDomains.
        http_status (int): HTTP status code.
        endpoint_data: Additional endpoint data (including subdomain).
        
    Returns:
        tuple: (EndPoint, created) or (None, False) if invalid
    """
    from startScan.models import ScanHistory, EndPoint, Subdomain
    from targetApp.models import Domain
    from reNgine.common_func import sanitize_url, is_valid_url
    
    # Remove nulls and validate basic inputs
    endpoint_data = replace_nulls(endpoint_data)
    scheme = urlparse(http_url).scheme

    if not scheme:
        logger.error(f'{http_url} is missing scheme (http or https). Creating default endpoint with http scheme.')
        http_url = f'http://{http_url.strip()}'

    if not is_valid_url(http_url):
        logger.error(f'{http_url} is not a valid URL. Skipping.')
        return None, False

    # Get required objects
    scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
    domain = Domain.objects.filter(pk=ctx.get('domain_id')).first()
    subdomain = endpoint_data.get('subdomain')

    if not all([scan, domain]):
        logger.error('Missing scan or domain information')
        return None, False

    # Check if we're scanning an IP
    is_ip_scan = validators.ipv4(domain.name) or validators.ipv6(domain.name)

    # For regular domain scans, validate URL belongs to domain
    if not is_ip_scan and domain.name not in http_url:
        logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
        return None, False

    http_url = sanitize_url(http_url)

    # If this is a default endpoint, check if one already exists for this subdomain + port combination
    if is_default and subdomain:
        # Extract port from current URL
        parsed_current = urlparse(http_url)
        if parsed_current.port:
            current_port = parsed_current.port
        elif parsed_current.scheme == 'https':
            current_port = 443
        else:
            current_port = 80
        
        # Get all default endpoints for this subdomain
        existing_defaults = EndPoint.objects.filter(
            scan_history=scan,
            target_domain=domain,
            subdomain=subdomain,
            is_default=True
        )
        
        # Check if any existing default endpoint has the same port
        for existing_default in existing_defaults:
            # Extract port from existing URL
            parsed_existing = urlparse(existing_default.http_url)
            if parsed_existing.port:
                existing_port = parsed_existing.port
            elif parsed_existing.scheme == 'https':
                existing_port = 443
            else:
                existing_port = 80
                
            if existing_port == current_port:
                logger.info(f'Default endpoint already exists for subdomain {subdomain} on port {current_port}')
                return existing_default, False

    # Check for existing endpoint with same URL
    existing_endpoint = EndPoint.objects.filter(
        scan_history=scan,
        target_domain=domain,
        http_url=http_url
    ).first()

    if existing_endpoint:
        return existing_endpoint, False

    # Create new endpoint
    create_data = {
        'scan_history': scan,
        'target_domain': domain,
        'http_url': http_url,
        'is_default': is_default,
        'discovered_date': timezone.now(),
        'http_status': http_status
    }

    create_data |= endpoint_data

    endpoint = EndPoint.objects.create(**create_data)
    created = True

    # Add subscan relation if needed
    if created and ctx.get('subscan_id'):
        endpoint.endpoint_subscan_ids.add(ctx.get('subscan_id'))
        endpoint.save()

    return endpoint, created


def save_subdomain(subdomain_name, ctx={}):
    """Get or create Subdomain object.

    Args:
        subdomain_name (str): Subdomain name.
        ctx (dict): Context containing scan information and settings.

    Returns:
        tuple: (startScan.models.Subdomain, created) where `created` is a
            boolean indicating if the object has been created in DB.
    """
    from startScan.models import ScanHistory, Subdomain
    from targetApp.models import Domain
    
    scan_id = ctx.get('scan_history_id')
    subscan_id = ctx.get('subscan_id')
    out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
    subdomain_name = subdomain_name.lower()

    # Validate domain/IP format
    valid_domain = (
        validators.domain(subdomain_name) or
        validators.ipv4(subdomain_name) or
        validators.ipv6(subdomain_name)
    )
    if not valid_domain:
        logger.error(f'{subdomain_name} is not a valid domain/IP. Skipping.')
        return None, False

    # Check if subdomain is in scope
    if subdomain_name in out_of_scope_subdomains:
        logger.error(f'{subdomain_name} is out-of-scope. Skipping.')
        return None, False

    # Get domain object and check if we're scanning an IP
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    domain = scan.domain if scan else None
    
    if not domain:
        logger.error('No domain found in scan history. Skipping.')
        return None, False
        
    is_ip_scan = validators.ipv4(domain.name) or validators.ipv6(domain.name)

    # For regular domain scans, validate subdomain belongs to domain
    if not is_ip_scan and ctx.get('domain_id'):
        if domain.name not in subdomain_name:
            logger.error(f"{subdomain_name} is not a subdomain of domain {domain.name}. Skipping.")
            return None, False

    # Create or get subdomain object
    subdomain, created = Subdomain.objects.get_or_create(
        scan_history=scan,
        target_domain=domain,
        name=subdomain_name)

    if created:
        logger.info(f'Found new subdomain/rDNS: {subdomain_name}')
        subdomain.discovered_date = timezone.now()
        if subscan_id:
            subdomain.subdomain_subscan_ids.add(subscan_id)
        subdomain.save()

    return subdomain, created


def save_subdomain_metadata(subdomain, endpoint, extra_datas={}):
    """Save metadata from endpoint to subdomain.
    
    Args:
        subdomain: Subdomain object
        endpoint: EndPoint object  
        extra_datas: Additional metadata to save
    """
    
    if endpoint and endpoint.is_alive:
        logger.info(f'Saving HTTP metadatas from {endpoint.http_url}')
        subdomain.http_url = endpoint.http_url
        subdomain.http_status = endpoint.http_status
        subdomain.response_time = endpoint.response_time
        subdomain.page_title = endpoint.page_title
        subdomain.content_type = endpoint.content_type
        subdomain.content_length = endpoint.content_length
        subdomain.webserver = endpoint.webserver
        cname = extra_datas.get('cname')
        if cname and is_iterable(cname):
            subdomain.cname = ','.join(cname)
        cdn = extra_datas.get('cdn')
        if cdn and is_iterable(cdn):
            subdomain.is_cdn = ','.join(cdn)
            subdomain.cdn_name = extra_datas.get('cdn_name')
        for tech in endpoint.techs.all():
            subdomain.technologies.add(tech)
        subdomain.save()
    else:
        http_url = extra_datas.get('http_url')
        if http_url:
            subdomain.http_url = http_url
            subdomain.save()
        else:
            logger.error(f'No HTTP URL found for {subdomain.name}. Skipping.')


def remove_file_or_pattern(path, pattern=None, shell=True, history_file=None, scan_id=None, activity_id=None):
    """
    Safely removes a file/directory or pattern matching files
    Args:
        path: Path to file/directory to remove
        pattern: Optional pattern for multiple files (e.g. "*.csv")
        shell: Whether to use shell=True in run_command
        history_file: History file for logging
        scan_id: Scan ID for logging
        activity_id: Activity ID for logging
    Returns:
        bool: True if successful, False if error occurred
    """
    import glob
    from reNgine.tasks.command import run_command
    
    try:
        if pattern:
            # Check for files matching the pattern
            match_count = len(glob.glob(os.path.join(path, pattern)))
            if match_count == 0:
                logger.warning(f"No files matching pattern '{pattern}' in {path}")
                return True
            full_path = os.path.join(path, pattern)
        else:
            if not os.path.exists(path):
                logger.warning(f"Path {path} does not exist")
                return True
            full_path = path

        # Execute secure command
        run_command(
            f'rm -rf {full_path}',
            shell=shell,
            history_file=history_file,
            scan_id=scan_id,
            activity_id=activity_id
        )
        return True
    except Exception as e:
        logger.error(f"Failed to delete {full_path}: {str(e)}")
        return False


def extract_httpx_url(line, follow_redirect):
    """Extract final URL from httpx results.

    Args:
        line (dict): URL data output by httpx.

    Returns:
        tuple: (final_url, redirect_bool) tuple.
    """
    status_code = line.get('status_code', 0)
    final_url = line.get('final_url')
    location = line.get('location')
    chain_status_codes = line.get('chain_status_codes', [])
    http_url = line.get('url')

    # Final URL is already looking nice, if it exists and follow redirect is enabled, return it
    if final_url and follow_redirect:
        return final_url, False

    # Handle redirects manually if follow redirect is enabled
    if follow_redirect:
        REDIRECT_STATUS_CODES = [301, 302]
        is_redirect = (
            status_code in REDIRECT_STATUS_CODES
            or
            any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)
        )
        if is_redirect and location:
            if location.startswith(('http', 'https')):
                http_url = location
            else:
                http_url = f'{http_url}/{location.lstrip("/")}'
    else:
        is_redirect = False

    # Sanitize URL
    http_url = sanitize_url(http_url)

    return http_url, is_redirect


def get_and_save_dork_results(lookup_target, results_dir, type, lookup_keywords=None, lookup_extensions=None, delay=3, page_count=2, scan_history=None):
    """
        Uses gofuzz to dork and store information

        Args:
            lookup_target (str): target to look into such as stackoverflow or even the target itself
            results_dir (str): Results directory
            type (str): Dork Type Title
            lookup_keywords (str): comma separated keywords or paths to look for
            lookup_extensions (str): comma separated extensions to look for
            delay (int): delay between each requests
            page_count (int): pages in google to extract information
            scan_history (startScan.ScanHistory): Scan History Object
    """
    from reNgine.tasks.command import run_command
    from pathlib import Path
    
    results = []
    gofuzz_command = f'{GOFUZZ_EXEC_PATH} -t {lookup_target} -d {delay} -p {page_count}'

    if lookup_extensions:
        gofuzz_command += f' -e {lookup_extensions}'
    elif lookup_keywords:
        gofuzz_command += f' -w {lookup_keywords}'

    output_file = str(Path(results_dir) / 'gofuzz.txt')
    gofuzz_command += f' -o {output_file}'
    history_file = str(Path(results_dir) / 'commands.txt')

    try:
        run_command(
            gofuzz_command,
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id,
        )

        if not os.path.isfile(output_file):
            return

        with open(output_file) as f:
            for line in f.readlines():
                url = line.strip()
                if url:
                    results.append(url)
                    dork, created = Dork.objects.get_or_create(
                        type=type,
                        url=url
                    )
                    if scan_history:
                        scan_history.dorks.add(dork)

        # remove output file
        os.remove(output_file)

    except Exception as e:
        logger.exception(e)

    return results


def get_and_save_emails(scan_history, activity_id, results_dir):
    """Get and save emails from Google, Bing and Baidu.

    Args:
        scan_history (startScan.ScanHistory): Scan history object.
        activity_id: ScanActivity Object
        results_dir (str): Results directory.

    Returns:
        list: List of emails found.
    """
    from reNgine.tasks.command import run_command
    from pathlib import Path
    
    emails = []

    # Proxy settings
    # get_random_proxy()

    # Gather emails from Google, Bing and Baidu
    output_file = str(Path(results_dir) / 'emails_tmp.txt')
    history_file = str(Path(results_dir) / 'commands.txt')
    command = f'infoga --domain {scan_history.domain.name} --source all --report {output_file}'
    try:
        run_command(
            command,
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id,
            activity_id=activity_id)

        if not os.path.isfile(output_file):
            logger.info('No Email results')
            return []

        with open(output_file) as f:
            for line in f.readlines():
                if 'Email' in line:
                    split_email = line.split(' ')[2]
                    emails.append(split_email)

        output_path = str(Path(results_dir) / 'emails.txt')
        with open(output_path, 'w') as output_file:
            for email_address in emails:
                save_email(email_address, scan_history)
                output_file.write(f'{email_address}\n')

    except Exception as e:
        logger.exception(e)
    return emails


def save_metadata_info(meta_dict):
    """Extract metadata from Google Search.

    Args:
        meta_dict (dict): Info dict.

    Returns:
        list: List of startScan.MetaFinderDocument objects.
    """
    from dotted_dict import DottedDict
    from metafinder.extractor import extract_metadata_from_google_search
    
    logger.warning(f'Getting metadata for {meta_dict.osint_target}')

    scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

    # Proxy settings
    get_random_proxy()

    # Get metadata
    result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
    if not result:
        logger.error(f'No metadata result from Google Search for {meta_dict.osint_target}.')
        return []

    # Add metadata info to DB
    results = []
    for metadata_name, data in result.get_metadata().items():
        subdomain = Subdomain.objects.get(
            scan_history=meta_dict.scan_id,
            name=meta_dict.osint_target)
        metadata = DottedDict({k: v for k, v in data.items()})
        meta_finder_document = MetaFinderDocument(
            subdomain=subdomain,
            target_domain=meta_dict.domain,
            scan_history=scan_history,
            url=metadata.url,
            doc_name=metadata_name,
            http_status=metadata.status_code,
            producer=metadata.metadata.get('Producer'),
            creator=metadata.metadata.get('Creator'),
            creation_date=metadata.metadata.get('CreationDate'),
            modified_date=metadata.metadata.get('ModDate'),
            author=metadata.metadata.get('Author'),
            title=metadata.metadata.get('Title'),
            os=metadata.metadata.get('OSInfo'))
        meta_finder_document.save()
        results.append(data)
    return results


def save_email(email_address, scan_history=None):
    if not validators.email(email_address):
        logger.info(f'Email {email_address} is invalid. Skipping.')
        return None, False
    email, created = Email.objects.get_or_create(address=email_address)
    if created:
        logger.info(f'Found new email address {email_address}')

    # Add email to ScanHistory
    if scan_history:
        scan_history.emails.add(email)
        scan_history.save()

    return email, created


def save_employee(name, designation, scan_history=None):
    employee, created = Employee.objects.get_or_create(
        name=name,
        designation=designation)
    if created:
        logger.warning(f'Found new employee {name}')

    # Add employee to ScanHistory
    if scan_history:
        scan_history.employees.add(employee)
        scan_history.save()

    return employee, created


def save_ip_address(ip_address, subdomain=None, subscan=None, **kwargs):
    from reNgine.tasks.geo import geo_localize
    
    if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
        logger.info(f'IP {ip_address} is not a valid IP. Skipping.')
        return None, False
    ip, created = IpAddress.objects.get_or_create(address=ip_address)
    if created:
        logger.warning(f'Found new IP {ip_address}')

    # Set extra attributes
    for key, value in kwargs.items():
        setattr(ip, key, value)
    ip.save()

    # Add IP to subdomain
    if subdomain:
        subdomain.ip_addresses.add(ip)
        subdomain.save()

    # Add subscan to IP
    if subscan:
        ip.ip_subscan_ids.add(subscan)

    # Geo-localize IP asynchronously
    if created:
        geo_localize.delay(ip_address, ip.id)

    return ip, created


def save_vulnerability(**vuln_data):
    from django.utils import timezone
    
    references = vuln_data.pop('references', [])
    cve_ids = vuln_data.pop('cve_ids', [])
    cwe_ids = vuln_data.pop('cwe_ids', [])
    tags = vuln_data.pop('tags', [])
    subscan = vuln_data.pop('subscan', None)

    # remove nulls
    vuln_data = replace_nulls(vuln_data)

    # Create vulnerability
    vuln, created = Vulnerability.objects.get_or_create(**vuln_data)
    if created:
        vuln.discovered_date = timezone.now()
        vuln.open_status = True
        vuln.save()

    # Save vuln tags
    for tag_name in tags or []:
        tag, created = VulnerabilityTags.objects.get_or_create(name=tag_name)
        if tag:
            vuln.tags.add(tag)
            vuln.save()

    # Save CVEs
    for cve_id in cve_ids or []:
        cve, created = CveId.objects.get_or_create(name=cve_id)
        if cve:
            vuln.cve_ids.add(cve)
            vuln.save()

    # Save CWEs
    for cve_id in cwe_ids or []:
        cwe, created = CweId.objects.get_or_create(name=cve_id)
        if cwe:
            vuln.cwe_ids.add(cwe)
            vuln.save()

    # Save vuln reference
    if references:
        vuln.references = references
        vuln.save()

    # Save subscan id in vuln object
    if subscan:
        vuln.vuln_subscan_ids.add(subscan)
        vuln.save()

    return vuln, created


def create_or_update_port_with_service(port_number, service_info, ip_address=None):
    """Create or update port with service information from nmap for specific IP."""
    port = get_or_create_port(ip_address, port_number)
    if ip_address and service_info:
        update_port_service_info(port, service_info)
    return port


def parse_nmap_results(xml_file, output_file=None, parse_type='vulnerabilities'):
    """Parse results from nmap output file.

    Args:
        xml_file (str): nmap XML report file path.
        output_file (str, optional): JSON output file path.
        parse_type (str): Type of parsing to perform:
            - 'vulnerabilities': Parse vulnerabilities from nmap scripts
            - 'services': Parse service banners from -sV
            - 'ports': Parse only open ports

    Returns:
        list: List of parsed results depending on parse_type:
            - vulnerabilities: List of vulnerability dictionaries
            - services: List of service dictionaries
            - ports: List of port dictionaries
    """
    import json
    import xmltodict
    
    with open(xml_file, encoding='utf8') as f:
        content = f.read()
        try:
            nmap_results = xmltodict.parse(content)
        except Exception as e:
            logger.warning(e)
            logger.error(f'Cannot parse {xml_file} to valid JSON. Skipping.')
            return []

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(nmap_results, f, indent=4)

    hosts = nmap_results.get('nmaprun', {}).get('host', {})
    if isinstance(hosts, dict):
        hosts = [hosts]

    results = []
    
    for host in hosts:
        # Get hostname/IP
        hostnames_dict = host.get('hostnames', {})
        
        # Get all IP addresses of the host
        addresses = []
        host_addresses = host.get('address', [])
        if isinstance(host_addresses, dict):
            host_addresses = [host_addresses]
        for addr in host_addresses:
            if addr.get('@addrtype') in ['ipv4', 'ipv6']:
                addresses.append({
                    'addr': addr.get('@addr'),
                    'type': addr.get('@addrtype')
                })

        if hostnames_dict:
            if not (hostname_data := hostnames_dict.get('hostname', [])):
                hostnames = [addresses[0]['addr'] if addresses else 'unknown']
            else:
                # Convert to list if it's a unique dictionary
                if isinstance(hostname_data, dict):
                    hostname_data = [hostname_data]
                hostnames = [entry.get('@name') for entry in hostname_data if entry.get('@name')] or [addresses[0]['addr'] if addresses else 'unknown']
        else:
            hostnames = [addresses[0]['addr'] if addresses else 'unknown']

        # Process each hostname
        for hostname in hostnames:
            ports = host.get('ports', {}).get('port', [])
            if isinstance(ports, dict):
                ports = [ports]

            for port in ports:
                port_number = port['@portid']
                if not port_number or not port_number.isdigit():
                    continue
                    
                port_protocol = port['@protocol']
                port_state = port.get('state', {}).get('@state')
                
                # Skip closed ports
                if port_state != 'open':
                    continue

                url = sanitize_url(f'{hostname}:{port_number}')

                if parse_type == 'ports':
                    # Return only open ports info with addresses
                    results.append({
                        'host': hostname,
                        'port': port_number,
                        'protocol': port_protocol,
                        'state': port_state,
                        'addresses': addresses
                    })
                    continue

                if parse_type == 'services':
                    # Parse service information from -sV
                    service = port.get('service', {})
                    results.append({
                        'host': hostname,
                        'port': port_number,
                        'protocol': port_protocol,
                        'service_name': service.get('@name'),
                        'service_product': service.get('@product'),
                        'service_version': service.get('@version'),
                        'service_extrainfo': service.get('@extrainfo'),
                        'service_ostype': service.get('@ostype'),
                        'service_method': service.get('@method'),
                        'service_conf': service.get('@conf')
                    })
                    continue

                if parse_type == 'vulnerabilities':
                    # Original vulnerability parsing logic
                    url_vulns = []
                    scripts = port.get('script', [])
                    if isinstance(scripts, dict):
                        scripts = [scripts]

                    for script in scripts:
                        script_id = script['@id']
                        script_output = script['@output']
                        
                        if script_id == 'vulscan':
                            vulns = parse_nmap_vulscan_output(script_output)
                            url_vulns.extend(vulns)
                        elif script_id == 'vulners':
                            vulns = parse_nmap_vulners_output(script_output)
                            url_vulns.extend(vulns)
                        else:
                            logger.warning(f'Script output parsing for script "{script_id}" is not supported yet.')

                    for vuln in url_vulns:
                        vuln['source'] = NMAP
                        vuln['http_url'] = url
                        if 'http_path' in vuln:
                            vuln['http_url'] += vuln['http_path']
                        results.append(vuln)

    return results


def parse_nmap_http_csrf_output(script_output):
    pass


def parse_nmap_vulscan_output(script_output):
    """Parse nmap vulscan script output.

    Args:
        script_output (str): Vulscan script output.

    Returns:
        list: List of Vulnerability dicts.
    """
    import re
    import pprint
    
    data = {}
    vulns = []
    provider_name = ''

    # Sort all vulns found by provider so that we can match each provider with
    # a function that pulls from its API to get more info about the
    # vulnerability.
    for line in script_output.splitlines():
        if not line:
            continue
        if not line.startswith('['): # provider line
            if "No findings" in line:
                logger.info(f"No findings: {line}")
                continue
            elif ' - ' in line:
                provider_name, provider_url = tuple(line.split(' - '))
                data[provider_name] = {'url': provider_url.rstrip(':'), 'entries': []}
                continue
            else:
                # Log a warning
                logger.warning(f"Unexpected line format: {line}")
                continue
        reg = r'\[(.*)\] (.*)'
        matches = re.match(reg, line)
        id, title = matches.groups()
        entry = {'id': id, 'title': title}
        data[provider_name]['entries'].append(entry)

    logger.warning('Vulscan parsed output:')
    logger.warning(pprint.pformat(data))

    for provider_name in data:
        if provider_name == 'Exploit-DB':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'IBM X-Force':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'MITRE CVE':
            logger.error(f'Provider {provider_name} is not supported YET.')
            for entry in data[provider_name]['entries']:
                cve_id = entry['id']
                vuln = cve_to_vuln(cve_id)
                vulns.append(vuln)
        elif provider_name == 'OSVDB':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'OpenVAS (Nessus)':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'SecurityFocus':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        elif provider_name == 'VulDB':
            logger.error(f'Provider {provider_name} is not supported YET.')
            pass
        else:
            logger.error(f'Provider {provider_name} is not supported.')
    return vulns


def parse_nmap_vulners_output(script_output, url=''):
    """Parse nmap vulners script output.

    TODO: Rework this as it's currently matching all CVEs no matter the
    confidence.

    Args:
        script_output (str): Script output.

    Returns:
        list: List of found vulnerabilities.
    """
    import re
    
    vulns = []
    # Check for CVE in script output
    CVE_REGEX = re.compile(r'.*(CVE-\d\d\d\d-\d+).*')
    matches = CVE_REGEX.findall(script_output)
    matches = list(dict.fromkeys(matches))
    for cve_id in matches: # get CVE info
        vuln = cve_to_vuln(cve_id, vuln_type='nmap-vulners-nse')
        if vuln:
            vulns.append(vuln)
    return vulns


def cve_to_vuln(cve_id, vuln_type=''):
    """Search for a CVE using CVESearch and return Vulnerability data.

    Args:
        cve_id (str): CVE ID in the form CVE-*

    Returns:
        dict: Vulnerability dict.
    """
    from pycvesearch import CVESearch
    import pprint
    
    cve_info = CVESearch('https://cve.circl.lu').id(cve_id)
    if not cve_info:
        logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
        return None
    vuln_cve_id = cve_info['id']
    vuln_name = vuln_cve_id
    vuln_description = cve_info.get('summary', 'none').replace(vuln_cve_id, '').strip()
    try:
        vuln_cvss = float(cve_info.get('cvss', -1))
    except (ValueError, TypeError):
        vuln_cvss = -1
    vuln_cwe_id = cve_info.get('cwe', '')
    exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
    osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])
    references = cve_info.get('references', [])
    capec_objects = cve_info.get('capec', [])

    # Parse ovals for a better vuln name / type
    ovals = cve_info.get('oval', [])
    if ovals:
        vuln_name = ovals[0]['title']
        vuln_type = ovals[0]['family']

    # Set vulnerability severity based on CVSS score
    vuln_severity = 'info'
    if vuln_cvss < 4:
        vuln_severity = 'low'
    elif vuln_cvss < 7:
        vuln_severity = 'medium'
    elif vuln_cvss < 9:
        vuln_severity = 'high'
    else:
        vuln_severity = 'critical'

    # Build console warning message
    msg = f'{vuln_name} | {vuln_severity.upper()} | {vuln_cve_id} | {vuln_cwe_id} | {vuln_cvss}'
    for id in osvdb_ids:
        msg += f'\n\tOSVDB: {id}'
    for exploit_id in exploit_ids:
        msg += f'\n\tEXPLOITDB: {exploit_id}'
    logger.warning(msg)
    vuln = {
        'name': vuln_name,
        'type': vuln_type,
        'severity': NUCLEI_SEVERITY_MAP[vuln_severity],
        'description': vuln_description,
        'cvss_score': vuln_cvss,
        'references': references,
        'cve_ids': [vuln_cve_id],
        'cwe_ids': [vuln_cwe_id]
    }
    return vuln


def process_httpx_response(line):
    """TODO: implement this"""
    pass


def create_scan_activity(scan_history_id, message, status):
    from django.utils import timezone
    
    scan_activity = ScanActivity()
    scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
    scan_activity.title = message
    scan_activity.time = timezone.now()
    scan_activity.status = status
    scan_activity.save()
    return scan_activity.id


def save_imported_subdomains(subdomains, ctx={}):
    """Take a list of subdomains imported and write them to from_imported.txt.

    Args:
        subdomains (list): List of subdomain names.
        ctx (dict): Context dict with domain_id, results_dir, etc.
    """
    domain_id = ctx['domain_id']
    domain = Domain.objects.get(pk=domain_id)
    results_dir = ctx.get('results_dir', RENGINE_RESULTS)

    # Validate each subdomain and de-duplicate entries
    subdomains = list(
        {
            subdomain
            for subdomain in subdomains
            if domain.name == get_domain_from_subdomain(subdomain)
        }
    )
    if not subdomains:
        return

    logger.warning(f'Found {len(subdomains)} imported subdomains.')
    with open(f'{results_dir}/from_imported.txt', 'w+') as output_file:
        url_filter = ctx.get('url_filter')
        for subdomain in subdomains:
            # Save valid imported subdomains
            subdomain_name = subdomain.strip()
            subdomain_obj, _ = save_subdomain(subdomain_name, ctx=ctx)
            if not isinstance(subdomain_obj, Subdomain):
                logger.error(f"Invalid subdomain encountered: {subdomain}")
                continue
            subdomain_obj.is_imported_subdomain = True
            subdomain_obj.save()
            output_file.write(f'{subdomain}\n')

            # Create base endpoint (for scan)
            http_url = f'{subdomain_obj.name}{url_filter}' if url_filter else subdomain_obj.name
            endpoint, _ = save_endpoint(
                http_url=http_url,
                ctx=ctx,
                is_default=True,
                subdomain=subdomain_obj
            )
            save_subdomain_metadata(subdomain_obj, endpoint)


def process_nmap_service_results(xml_file):
    """Update port information with nmap service detection results"""
    import xml.etree.ElementTree as ET
    
    services = parse_nmap_results(xml_file, parse_type='services')
    
    for service in services:
        try:
            # Get IP from host address node
            ip = service.get('ip', '')
            host = service.get('host', '')
            
            # If IP is empty, try to get it from the host
            if not ip and host:
                # Parse XML to get IP for this host
                tree = ET.parse(xml_file)
                root = tree.getroot()
                for host_elem in root.findall('.//host'):
                    hostnames = host_elem.find('hostnames')
                    if hostnames is not None:
                        for hostname in hostnames.findall('hostname'):
                            if hostname.get('name') == host:
                                ip = host_elem.find('address').get('addr')
                                break
            
            # Skip if still empty or if it's a hostname
            if not ip or any(c.isalpha() for c in ip):
                logger.warning(f"Skipping invalid IP address: {ip} for host {host}")
                continue
                
            ip_address, _ = IpAddress.objects.get_or_create(
                address=ip
            )
            create_or_update_port_with_service(
                port_number=int(service['port']),
                service_info=service,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error(f"Failed to process port {service['port']}: {str(e)}")


def debug():
    try:
        # Activate remote debug for scan worker
        if CELERY_REMOTE_DEBUG:
            logger.info(f"\n⚡ Debugger started on port "+ str(CELERY_REMOTE_DEBUG_PORT) +", task is waiting IDE (VSCode ...) to be attached to continue ⚡\n")
            os.environ['GEVENT_SUPPORT'] = 'True'
            import debugpy
            debugpy.listen(('0.0.0.0',CELERY_REMOTE_DEBUG_PORT))
            debugpy.wait_for_client()
    except Exception as e:
        logger.error(e)


def parse_curl_output(response):
    # TODO: Enrich from other cURL fields.
    import re
    
    CURL_REGEX_HTTP_STATUS = f'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
    http_status = 0
    if response:
        failed = False
        regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
        try:
            http_status = int(regex.findall(response)[0])
        except (KeyError, TypeError, IndexError):
            pass
    return {
        'http_status': http_status,
    }

# TODO Implement associated domains
def get_associated_domains(keywords):
      return []