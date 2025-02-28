import os
import json
import yaml

from pathlib import Path
from copy import deepcopy
from dotted_dict import DottedDict

from reNgine.definitions import (
    INTENSITY,
    ENABLE_HTTP_CRAWL,
    OSINT,
    OSINT_DEFAULT_CONFIG,
    OSINT_DORK,
    OSINT_CUSTOM_DORK,
    OSINT_DISCOVER,
    OSINT_DOCUMENTS_LIMIT,
)
from reNgine.settings import (
    DEFAULT_ENABLE_HTTP_CRAWL,
)
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.command_builder import CommandBuilder
from reNgine.utils.http import get_subdomain_from_url
from reNgine.utils.logger import Logger
from reNgine.utils.task_config import TaskConfig
from startScan.models import (
    ScanHistory,
    Subdomain,
)
from reNgine.tasks.command import run_command_line
from reNgine.tasks.http import http_crawl
from scanEngine.models import Proxy

logger = Logger(True)

@app.task(name='osint', bind=True, base=RengineTask)
def osint(self, host=None, ctx=None, description=None):
    """Run Open-Source Intelligence tools on selected domain.

    Args:
        host (str): Hostname to scan.

    Returns:
        dict: Results from osint discovery and dorking.
    """
    from reNgine.utils.scan_helpers import execute_grouped_tasks

    if ctx is None:
        ctx = {}
    config = TaskConfig(self.yaml_configuration, self.results_dir, self.scan_id, self.filename)
    osint_config = config.get_config(OSINT) or OSINT_DEFAULT_CONFIG

    grouped_tasks = []

    if 'discover' in osint_config:
        logger.info('🕵️ Starting OSINT Discovery')
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        _task = osint_discovery.si(
            config=osint_config,
            host=self.scan.domain.name,
            scan_history_id=self.scan.id,
            activity_id=self.activity_id,
            results_dir=self.results_dir,
            ctx=custom_ctx
        )
        grouped_tasks.append(_task)

    if OSINT_DORK in osint_config or OSINT_CUSTOM_DORK in osint_config:
        logger.info('🕵️ Starting OSINT Dorking')
        _task = dorking.si(
            config=osint_config,
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
def osint_discovery(self, config, host, scan_history_id, activity_id, results_dir, ctx=None):
    """Run OSINT discovery.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results

    Returns:
        dict: osint metadat and theHarvester and h8mail results.
    """
    from reNgine.utils.db import save_metadata_info
    from reNgine.utils.scan_helpers import execute_grouped_tasks
    if ctx is None:
        ctx = {}
    osint_lookup = config.get(OSINT_DISCOVER, [])
    osint_intensity = config.get(INTENSITY, 'normal')
    documents_limit = config.get(OSINT_DOCUMENTS_LIMIT, 50)
    # Get and save meta info
    if 'metainfo' in osint_lookup:
        logger.info('🕵️ Saving Metainfo')
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
            config=config,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
            ctx=ctx
        )
        grouped_tasks.append(_task)

    if 'employees' in osint_lookup:
        logger.info('🕵️ Lookup for employees')
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        _task = theHarvester.si(
            config=config,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
            ctx=custom_ctx
        )
        grouped_tasks.append(_task)

    execute_grouped_tasks(
        self,
        grouped_tasks,
        task_name="osint_discovery",
        callback_kwargs={'description': 'Processing OSINT discovery results'}
    )

    return {}

@app.task(name='dorking', bind=True, base=RengineTask)
def dorking(self, config, host, scan_history_id, results_dir):
    """Run Google dorks.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results

    Returns:
        list: Dorking results for each dork ran.
    """
    from reNgine.utils.db import get_and_save_dork_results

    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    dorks = config.get(OSINT_DORK, [])
    custom_dorks = config.get(OSINT_CUSTOM_DORK, [])
    results = []

    # custom dorking has higher priority
    try:
        for custom_dork in custom_dorks:
            lookup_target = custom_dork.get('lookup_site')
            # replace with original host if _target_
            lookup_target = host if lookup_target == '_target_' else lookup_target
            if 'lookup_extensions' in custom_dork:
                results = get_and_save_dork_results(
                    lookup_target=lookup_target,
                    results_dir=results_dir,
                    type='custom_dork',
                    lookup_extensions=custom_dork.get('lookup_extensions'),
                    scan_history=scan_history
                )
            elif 'lookup_keywords' in custom_dork:
                results = get_and_save_dork_results(
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
        for dork in dorks:
            logger.info(f'🕵️ Getting dork information for {dork}')
            if dork == 'stackoverflow':
                results = get_and_save_dork_results(
                    lookup_target='stackoverflow.com',
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=host,
                    scan_history=scan_history
                )
            # Add other default dorks here...

    except Exception as e:
        logger.exception(e)

    return results

@app.task(name='theHarvester', queue='io_queue', bind=True)
def theHarvester(self, config, host, scan_history_id, activity_id, results_dir, ctx=None):
    """Run theHarvester to get save emails, hosts, employees found in domain.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        activity_id: ScanActivity ID
        results_dir (str): Path to store scan results
        ctx (dict): context of scan

    Returns:
        dict: Dict of emails, employees, hosts and ips found during crawling.
    """
    from reNgine.utils.db import (
        save_email,
        save_employee,
        save_endpoint,
        save_subdomain,
    )

    if ctx is None:
        ctx = {}
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
    output_path_json = str(Path(results_dir) / 'theHarvester.json')
    theHarvester_dir = str(Path.home() / ".config"  / 'theHarvester')
    history_file = str(Path(results_dir) / 'commands.txt')

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
    harvester_builder = CommandBuilder('theHarvester')
    harvester_builder.add_option('-d', host)
    harvester_builder.add_option('-f', output_path_json)
    harvester_builder.add_option('-b', 'anubis,baidu,bevigil,binaryedge,bing,bingapi,bufferoverun,brave,censys,certspotter,criminalip,crtsh,dnsdumpster,duckduckgo,fullhunt,hackertarget,hunter,hunterhow,intelx,netlas,onyphe,otx,pentesttools,projectdiscovery,rapiddns,rocketreach,securityTrails,sitedossier,subdomaincenter,subdomainfinderc99,threatminer,tomba,urlscan,virustotal,yahoo,zoomeye')
    cmd = harvester_builder.build_list()

    run_command_line.delay(
        cmd,
        shell=False,
        cwd=theHarvester_dir,
        history_file=history_file,
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

    emails = data.get('emails', [])
    for email_address in emails:
        email, _ = save_email(email_address, scan_history=scan_history)
        if email:
            self.notify(fields={'Emails': f'• `{email.address}`'})

    linkedin_people = data.get('linkedin_people', [])
    for people in linkedin_people:
        employee, _ = save_employee(
            people,
            designation='linkedin',
            scan_history=scan_history)
        if employee:
            self.notify(fields={'LinkedIn people': f'• {employee.name}'})

    twitter_people = data.get('twitter_people', [])
    for people in twitter_people:
        employee, _ = save_employee(
            people,
            designation='twitter',
            scan_history=scan_history)
        if employee:
            self.notify(fields={'Twitter people': f'• {employee.name}'})

    hosts = data.get('hosts', [])
    urls = []
    for host in hosts:
        split = tuple(host.split(':'))
        http_url = split[0]
        subdomain_name = get_subdomain_from_url(http_url)
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        if not isinstance(subdomain, Subdomain):
            logger.error(f"Invalid subdomain encountered: {subdomain}")
            continue
        endpoint, _ = save_endpoint(
            http_url,
            crawl=False,
            ctx=ctx,
            subdomain=subdomain)
        if endpoint:
            urls.append(endpoint.http_url)
            self.notify(fields={'Hosts': f'• {endpoint.http_url}'})

    if enable_http_crawl:
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        http_crawl.delay(urls, ctx=custom_ctx)

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

@app.task(name='h8mail', queue='io_queue', bind=False)
def h8mail(config, host, scan_history_id, activity_id, results_dir, ctx=None):
    """Run h8mail.

    Args:
        config (dict): yaml_configuration
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
    logger.warning('Getting leaked credentials')
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    input_path = str(Path(results_dir) / 'emails.txt')
    output_file = str(Path(results_dir) / 'h8mail.json')

    h8mail_builder = CommandBuilder('h8mail')
    h8mail_builder.add_option('-t', input_path)
    h8mail_builder.add_option('--json', output_file)
    cmd = h8mail_builder.build_list()

    history_file = str(Path(results_dir) / 'commands.txt')

    run_command_line.delay(
        cmd,
        history_file=history_file,
        scan_id=scan_history_id,
        activity_id=activity_id)

    with open(output_file) as f:
        data = json.load(f)
        creds = data.get('targets', [])

    # TODO: go through h8mail output and save emails to DB
    for cred in creds:
        logger.warning(cred)
        email_address = cred['target']
        pwn_num = cred['pwn_num']
        pwn_data = cred.get('data', [])
        email, created = save_email(email_address, scan_history=scan_history)
        # if email:
        # 	self.notify(fields={'Emails': f'• `{email.address}`'})
    return creds
