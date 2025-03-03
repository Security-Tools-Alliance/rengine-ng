import os
import json
import yaml

from pathlib import Path
from copy import deepcopy
from dotted_dict import DottedDict

from reNgine.definitions import (
    OSINT,
    OSINT_DORK,
    OSINT_CUSTOM_DORK,
)
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.command_builder import build_gofuzz_cmd, build_harvester_cmd, build_h8mail_cmd, build_infoga_cmd
from reNgine.utils.http import get_subdomain_from_url
from reNgine.utils.logger import default_logger as logger
from reNgine.utils.task_config import TaskConfig
from reNgine.tasks.command import run_command_line
from reNgine.tasks.http import http_crawl

from scanEngine.models import Proxy
from startScan.models import Dork, MetaFinderDocument, ScanHistory, Subdomain

@app.task(name='osint', bind=True, base=RengineTask)
def osint(self, host=None, ctx=None, description=None):
    """Run Open-Source Intelligence tools on selected domain.

    Args:
        host (str): Hostname to scan.
        ctx (dict): context of scan
    Returns:
        dict: Results from osint discovery and dorking.
    """
    from reNgine.utils.scan_helpers import execute_grouped_tasks

    if ctx is None:
        ctx = {}

    # Initialize task config
    config = TaskConfig(ctx, OSINT)
    task_config = config.get_task_config()

    grouped_tasks = []

    if 'discover' in task_config:
        logger.info('🕵️ Starting OSINT Discovery')
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        _task = osint_discovery.si(
            ctx=custom_ctx,
            host=self.scan.domain.name,
            scan_history_id=self.scan.id,
            activity_id=self.activity_id,
            results_dir=self.results_dir,
        )
        grouped_tasks.append(_task)

    if OSINT_DORK in task_config or OSINT_CUSTOM_DORK in task_config:
        logger.info('🕵️ Starting OSINT Dorking')
        _task = dorking.si(
            ctx=ctx,
            host=self.scan.domain.name,
            scan_history_id=self.scan.id,
            results_dir=self.results_dir
        )
        grouped_tasks.append(_task)

    execute_grouped_tasks(
        self,
        grouped_tasks,
        task_name="osint",
        callback_kwargs={'description': 'Processing OSINT results'}
    )
    
    logger.info('🕵️ OSINT Tasks submitted...')
    return {'status': 'submitted'}

@app.task(name='osint_discovery', bind=True, base=RengineTask)
def osint_discovery(self, ctx=None, host=None, scan_history_id=None, activity_id=None, results_dir=None):
    """Run OSINT discovery.

    Args:
        ctx (dict): context of scan
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results
    """
    from reNgine.utils.scan_helpers import execute_grouped_tasks
    if ctx is None:
        ctx = {}

    config = TaskConfig(ctx, OSINT)
    task_config = config.get_task_config()

    osint_lookup = task_config['discover']
    documents_limit = task_config['documents_limit']

    # Get and save meta info
    if 'metainfo' in osint_lookup:
        logger.info('🕵️ Saving Metainfo')
        osint_intensity = task_config['intensity']
        if osint_intensity == 'normal':
            meta_dict = DottedDict({
                'osint_target': host,
                'domain': host,
                'scan_id': scan_history_id,
                'documents_limit': documents_limit
            })
            meta_info = [save_metadata_info(meta_dict)]

            # TODO: disabled for now
            # elif osint_intensity == 'deep':
            #     subdomains = Subdomain.objects
            #     if self.scan:
            #         subdomains = subdomains.filter(scan_history=self.scan)
            #     for subdomain in subdomains:
            #         meta_dict = DottedDict({
            #             'osint_target': subdomain.name,
            #             'domain': self.domain,
            #             'scan_id': self.scan_id,
            #             'documents_limit': documents_limit
            #         })
            #         meta_info.append(save_metadata_info(meta_dict))

    grouped_tasks = []

    if 'emails' in osint_lookup:
        logger.info('🕵️ Lookup for emails')
        _task = h8mail.si(
            ctx=ctx,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
        )
        grouped_tasks.append(_task)

    if 'employees' in osint_lookup:
        logger.info('🕵️ Lookup for employees')
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        _task = theHarvester.si(
            ctx=custom_ctx,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
        )
        grouped_tasks.append(_task)

    execute_grouped_tasks(
        self,
        grouped_tasks,
        task_name="osint_discovery",
        callback_kwargs={'description': 'Processing OSINT discovery results'}
    )

@app.task(name='dorking', bind=True, base=RengineTask)
def dorking(self, ctx=None, host=None, scan_history_id=None, results_dir=None):
    """Run Google dorks.

    Args:
        ctx (dict): context of scan
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results
    """
    if ctx is None:
        ctx = {}

    config = TaskConfig(ctx, OSINT)
    task_config = config.get_task_config()

    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    dorks = task_config['dorks']
    custom_dorks = task_config['custom_dorks']

    # custom dorking has higher priority
    try:
        for custom_dork in custom_dorks:
            lookup_target = custom_dork.get('lookup_site')
            # replace with original host if _target_
            lookup_target = host if lookup_target == '_target_' else lookup_target
            if 'lookup_extensions' in custom_dork:
                get_and_save_dork_results(
                    ctx=ctx,
                    lookup_target=lookup_target,
                    results_dir=results_dir,
                    type='custom_dork',
                    lookup_extensions=custom_dork.get('lookup_extensions'),
                    scan_history=scan_history
                )
            elif 'lookup_keywords' in custom_dork:
                get_and_save_dork_results(
                    ctx=ctx,
                    lookup_target=lookup_target,
                    results_dir=results_dir,
                    type='custom_dork',
                    lookup_keywords=custom_dork.get('lookup_keywords'),
                    scan_history=scan_history
                )
    except Exception as e:
        logger.exception(e)

    # Run default dorks
    try:
        if dorks:
            process_dorks(host, results_dir, dorks, scan_history)
    except Exception as e:
        logger.exception(e)

@app.task(name='theHarvester', queue='io_queue', bind=True)
def theHarvester(self, ctx, host, scan_history_id, activity_id, results_dir):
    """Run theHarvester to get save emails, hosts, employees found in domain.

    Args:
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        activity_id: ScanActivity ID
        results_dir (str): Path to store scan results
        ctx (dict): context of scan

    Returns:
        dict: Dict of emails, employees, hosts and ips found during crawling.
    """
    if ctx is None:
        ctx = {}

    config = TaskConfig(ctx, OSINT)
    task_config = config.get_task_config()

    enable_http_crawl = task_config['enable_http_crawl']
    output_path_json = config.get_working_dir(filename='theHarvester.json')
    theHarvester_dir = str(Path.home() / ".config"  / 'theHarvester')

    # Update proxies.yaml
    proxy_query = Proxy.objects.all()
    if proxy_query.exists():
        proxy = proxy_query.first()
        if proxy.use_proxy:
            proxy_list = proxy.proxies.splitlines()
            yaml_data = {'http' : proxy_list}
            with open(Path(theHarvester_dir) / 'proxies.yaml', 'w') as file:
                yaml.dump(yaml_data, file)

    # Run cmd
    cmd = build_harvester_cmd(host, output_path_json)

    run_command_line.delay(
        cmd,
        shell=False,
        cwd=theHarvester_dir,
        history_file=self.history_file,
        scan_id=scan_history_id,
        activity_id=activity_id)

    # Get file location
    if not os.path.isfile(output_path_json):
        logger.error(f'Could not open {output_path_json}')
        return {}

    # Load theHarvester results
    with open(output_path_json, 'r') as f:
        data = json.load(f)

    # Re-indent theHarvester JSON
    with open(output_path_json, 'w') as f:
        json.dump(data, f, indent=4)

    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    process_osint_data(self, data, ctx, scan_history, enable_http_crawl=enable_http_crawl)

    # TODO: Lots of ips unrelated with our domain are found, disabling
    # this for now.
    # ips = data.get('ips', [])
    # for ip_address in ips:
    # 	ip, created = save_ip_address(
    # 		ip_address,
    # 		subscan=subscan)
    # 	if ip:
    # 		send_task_notif.delay(
    # 			'osint',
    # 			scan_history_id=scan_history_id,
    # 			subscan_id=subscan_id,
    # 			severity='success',
    # 			update_fields={'IPs': f'{ip.address}'})
    return data

@app.task(name='h8mail', queue='io_queue', bind=True, base=RengineTask)
def h8mail(self, ctx, host, scan_history_id, activity_id, results_dir):
    """Run h8mail.

    Args:
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        activity_id: ScanActivity ID
        results_dir (str): Path to store scan results
        ctx (dict): context of scan

    Returns:
        list[dict]: List of credentials info.
    """
    from reNgine.utils.db import save_email

    if ctx is None:
        ctx = {}
    logger.info('Getting leaked credentials')

    config = TaskConfig(ctx, OSINT)

    input_path = config.get_working_dir(filename='emails.txt')
    output_file = config.get_working_dir(filename='h8mail.json')

    cmd = build_h8mail_cmd(input_path, output_file)

    run_command_line.delay(
        cmd,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)

    with open(output_file) as f:
        data = json.load(f)
        creds = data.get('targets', [])

    # TODO: go through h8mail output and save emails to DB
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    for cred in creds:
        logger.info(cred)
        email_address = cred['target']
        pwn_num = cred['pwn_num']
        pwn_data = cred.get('data', [])
        email, created = save_email(email_address, scan_history=scan_history)
        # if email:
        # 	self.notify(fields={'Emails': f'• `{email.address}`'})
    return creds

def get_and_save_dork_results(ctx, lookup_target, results_dir, type, lookup_keywords=None, lookup_extensions=None, delay=3, page_count=2, scan_history=None):
    """
        Uses gofuzz to dork and store information

        Args:
            ctx (dict): context of scan
            lookup_target (str): target to look into such as stackoverflow or even the target itself
            results_dir (str): Results directory
            type (str): Dork Type Title
            lookup_keywords (str): comma separated keywords or paths to look for
            lookup_extensions (str): comma separated extensions to look for
            delay (int): delay between each requests
            page_count (int): pages in google to extract information
            scan_history (startScan.models.ScanHistory): Scan History Object
    """
    results = []

    config = TaskConfig(ctx, OSINT)

    # Get the command as a list or string as needed
    history_file = config.get_working_dir(filename='commands.txt')
    output_file = config.get_working_dir(filename='gofuzz.txt')
    try:
        run_command_line(
            build_gofuzz_cmd(lookup_target, delay, page_count, lookup_extensions, lookup_keywords, results_dir),
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id,
        )

        if not os.path.isfile(output_file):
            return

        with open(output_file) as f:
            for line in f:
                if url := line.strip():
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

def get_and_save_emails(ctx, scan_history, activity_id, output_path):
    """Get and save emails from Google, Bing and Baidu.

    Args:
        ctx (dict): context of scan
        scan_history (startScan.ScanHistory): Scan history object.
        activity_id: ScanActivity Object
        results_dir (str): Results directory.

    Returns:
        list: List of emails found.
    """
    from reNgine.utils.db import save_email

    emails = []

    config = TaskConfig(ctx, OSINT)

    # Gather emails from Google, Bing and Baidu
    output_file = config.get_working_dir(filename='emails_tmp.txt')
    history_file = config.get_working_dir(filename='commands.txt')
    
    try:
        run_command_line(
            build_infoga_cmd(scan_history.domain.name, output_file),
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id,
            activity_id=activity_id)

        if not os.path.isfile(output_file):
            logger.info('No Email results')
            return []

        with open(output_file) as f:
            for line in f:
                if 'Email' in line:
                    split_email = line.split(' ')[2]
                    emails.append(split_email)
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
    logger.info(f'Getting metadata for {meta_dict.osint_target}')

    scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

    # Get metadata
    #result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
    result=[]
    if not result:
        logger.warning(f'No metadata result from Google Search for {meta_dict.osint_target}.')
        return []

    # Add metadata info to DB
    results = []
    for metadata_name, data in result.get_metadata().items():
        subdomain = Subdomain.objects.get(
            scan_history=meta_dict.scan_id,
            name=meta_dict.osint_target)
        metadata = DottedDict(dict(data.items()))
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

def process_dorks(ctx, host, results_dir, dorks, scan_history):
    """Process a list of dorks against a host
    
    Args:
        ctx (dict): context of scan
        host (str): Target hostname
        results_dir (str): Directory to save results
        dorks (list): List of dork types to process
        scan_history: Scan history object
        
    Returns:
        dict: Dictionary mapping dork types to their results
    """
    # Define all dork configurations in a dictionary
    dork_configs = {
        # Single site dorks
        'stackoverflow': {
            'lookup_target': 'stackoverflow.com',
            'lookup_keywords': host,
        },

        # Path-based dorks
        'login_pages': {
            'lookup_target': host,
            'lookup_keywords': '/login/,login.html',
            'page_count': 5,
        },
        'admin_panels': {
            'lookup_target': host,
            'lookup_keywords': '/admin/,admin.html',
            'page_count': 5,
        },
        'dashboard_pages': {
            'lookup_target': host,
            'lookup_keywords': '/dashboard/,dashboard.html',
            'page_count': 5,
        },

        # Error and platform specific dorks
        'jenkins': {
            'lookup_target': host,
            'lookup_keywords': 'Jenkins',
            'page_count': 1,
        },
        'wordpress_files': {
            'lookup_target': host,
            'lookup_keywords': '/wp-content/,/wp-includes/',
            'page_count': 5,
        },
        'php_error': {
            'lookup_target': host,
            'lookup_keywords': 'PHP Parse error,PHP Warning,PHP Error',
            'page_count': 5,
        },

        # File extension based dorks
        'config_files': {
            'lookup_target': host,
            'lookup_extensions': 'env,xml,conf,toml,yml,yaml,cnf,inf,rdp,ora,txt,cfg,ini',
            'page_count': 4,
        },
        'exposed_documents': {
            'lookup_target': host,
            'lookup_extensions': 'doc,docx,odt,pdf,rtf,sxw,psw,ppt,pptx,pps,csv',
            'page_count': 7,
        },
        'db_files': {
            'lookup_target': host,
            'lookup_extensions': 'sql,db,dbf,mdb',
            'page_count': 1,
        },
        'git_exposed': {
            'lookup_target': host,
            'lookup_extensions': 'git',
            'page_count': 1,
        },

        # Multi-site dorks
        'social_media': {
            'multi_targets': ['tiktok.com', 'facebook.com', 'twitter.com', 'youtube.com', 'reddit.com'],
            'lookup_keywords': host,
        },
        'project_management': {
            'multi_targets': ['trello.com', 'atlassian.net'],
            'lookup_keywords': host,
        },
        'code_sharing': {
            'multi_targets': ['github.com', 'gitlab.com', 'bitbucket.org'],
            'lookup_keywords': host,
        },
    }

    all_results = {}

    for dork in dorks:
        if dork not in dork_configs:
            continue

        config = dork_configs[dork]

        # Handle multi-target dorks (like social media sites)
        if 'multi_targets' in config:
            all_results[dork] = []
            for site in config['multi_targets']:
                if results := get_and_save_dork_results(
                    ctx=ctx,
                    lookup_target=site,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=config['lookup_keywords'],
                    scan_history=scan_history,
                ):
                    all_results[dork].extend(results)
        else:
            # Handle regular single-target dorks
            kwargs = {
                'ctx': ctx,
                'lookup_target': config['lookup_target'],
                'results_dir': results_dir,
                'type': dork,
                'scan_history': scan_history
            }

            # Add optional parameters if they exist
            if 'lookup_keywords' in config:
                kwargs['lookup_keywords'] = config['lookup_keywords']
            if 'lookup_extensions' in config:
                kwargs['lookup_extensions'] = config['lookup_extensions']
            if 'page_count' in config:
                kwargs['page_count'] = config['page_count']

            all_results[dork] = get_and_save_dork_results(**kwargs)

    return all_results

def process_osint_data(self, data, ctx, scan_history, enable_http_crawl=False):
    """Process different types of OSINT data and save to database
    
    Args:
        self: Task instance
        data (dict): Data containing emails, people, hosts, etc.
        ctx (dict): context of scan
        scan_history: Scan history object
        enable_http_crawl (bool): Whether to enable HTTP crawling for discovered endpoints
        
    Returns:
        dict: Summary of processed data
    """
    from reNgine.utils.db import save_email, save_employee

    processors = {
        'emails': {
            'data_key': 'emails',
            'processor': lambda item: save_email(item, scan_history=scan_history),
            'notify_field': 'Emails',
            'notify_format': lambda obj: f'• `{obj.address}`',
        },
        'linkedin_people': {
            'data_key': 'linkedin_people',
            'processor': lambda item: save_employee(item, designation='linkedin', scan_history=scan_history),
            'notify_field': 'LinkedIn people',
            'notify_format': lambda obj: f'• {obj.name}',
        },
        'twitter_people': {
            'data_key': 'twitter_people',
            'processor': lambda item: save_employee(item, designation='twitter', scan_history=scan_history),
            'notify_field': 'Twitter people',
            'notify_format': lambda obj: f'• {obj.name}',
        },
        'hosts': {
            'data_key': 'hosts',
            'processor': lambda host: process_host(host, ctx, self),
            'notify_field': 'Hosts',
            'notify_format': lambda endpoint: f'• {endpoint.http_url}',
            'collect_for_crawl': True,
        }
    }
    
    # List to collect URLs for HTTP crawling
    urls_to_crawl = []
    
    # Process each type of data
    for config in processors.values():
        items = data.get(config['data_key'], [])
        
        for item in items:
            obj, created = config['processor'](item)
            
            # Skip invalid results
            if not obj:
                continue
                
            # Send notification
            if hasattr(self, 'notify'):
                self.notify(fields={config['notify_field']: config['notify_format'](obj)})
                
            # Collect URL for crawling if needed
            if config.get('collect_for_crawl') and obj:
                urls_to_crawl.append(obj.http_url)
    
    # Launch HTTP crawl if enabled and we have URLs
    if enable_http_crawl and urls_to_crawl:
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        http_crawl.delay(urls_to_crawl, ctx=custom_ctx)
        
    return {
        'urls_discovered': urls_to_crawl,
        'processed': True
    }

def process_host(host, ctx, task_instance):
    """Process and save a host
    
    Args:
        host (str): Host in format 'url:port'
        ctx (dict): context of scan
        task_instance: Task instance for logging
        
    Returns:
        tuple: (Endpoint object, created boolean)
    """
    from reNgine.utils.db import save_subdomain, save_endpoint

    
    split = tuple(host.split(':'))
    http_url = split[0]
    subdomain_name = get_subdomain_from_url(http_url)
    
    subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
    
    if not isinstance(subdomain, Subdomain):
        logger.error(f"Invalid subdomain encountered: {subdomain}")
        return None, False
        
    endpoint, created = save_endpoint(
        http_url,
        crawl=False,
        ctx=ctx,
        subdomain=subdomain
    )
    
    return endpoint, created
