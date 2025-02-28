import os
import json
import random
import validators

from copy import deepcopy
from urllib.parse import urlparse
from metafinder.extractor import extract_metadata_from_google_search
from pathlib import Path
from dotted_dict import DottedDict

from django.contrib.auth.models import User
from django.db.models import Q
from django.utils import timezone

from reNgine.definitions import (
    ENABLE_HTTP_CRAWL,
    GOFUZZ_EXEC_PATH,
    INITIATED_TASK,
)
from reNgine.settings import (
    DEFAULT_ENABLE_HTTP_CRAWL,
    RENGINE_HOME,
    RENGINE_RESULTS,
)
from scanEngine.models import (
    EngineType,
    InterestingLookupModel,
    Proxy
)

from startScan.models import (
    Dork,
    ScanActivity,
    Vulnerability,
    EndPoint,
    Subdomain,
    Email,
    Employee,
    Technology,
    MetaFinderDocument,
    ScanHistory,
    VulnerabilityTags,
    CveId,
    CweId,
    VulnerabilityReference,
    GPTVulnerabilityReport
)

from targetApp.models import (
    Domain,
)

from reNgine.utils.utils import (
    get_gpt_vuln_input_description,
    replace_nulls,
    is_iterable,
)
from reNgine.utils.http import (
    get_domain_from_subdomain,
    is_valid_url,
    sanitize_url,
)
from reNgine.utils.logger import Logger

from reNgine.tasks.command import run_command_line
from reNgine.gpt import GPTVulnerabilityReportGenerator
from reNgine.utils.command_builder import CommandBuilder

logger = Logger(True)

def save_vulns(self, notif, vulns_file, vulns):
    with open(vulns_file, 'w') as f:
        json.dump(vulns, f, indent=4)

    # Save vulnerabilities found by nmap
    vulns_str = ''
    for vuln_data in vulns:
        # URL is not necessarily an HTTP URL when running nmap (can be any
        # other vulnerable protocols). Look for existing endpoint and use its
        # URL as vulnerability.http_url if it exists.
        url = vuln_data['http_url']
        endpoint = EndPoint.objects.filter(http_url__contains=url).first()
        if endpoint:
            vuln_data['http_url'] = endpoint.http_url
        vuln, created = save_vulnerability(
            target_domain=self.domain,
            subdomain=self.subdomain,
            scan_history=self.scan,
            subscan=self.subscan,
            endpoint=endpoint,
            **vuln_data)
        vulns_str += f'• {str(vuln)}\n'
        if created:
            logger.warning(str(vuln))

    # Send only 1 notif for all vulns to reduce number of notifs
    if notif and notif.send_vuln_notif and vulns_str:
        logger.warning(vulns_str)
        self.notify(fields={'CVEs': vulns_str})

def save_vulnerability(**vuln_data):
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
    for url in references or []:
        ref, created = VulnerabilityReference.objects.get_or_create(url=url)
        if created:
            vuln.references.add(ref)
            vuln.save()

    # Save subscan id in vuln object
    if subscan:
        vuln.vuln_subscan_ids.add(subscan)
        vuln.save()

    return vuln, created

def save_endpoint(http_url, ctx=None, crawl=False, is_default=False, http_status=None, **endpoint_data):
    """Get or create EndPoint object. If crawl is True, also crawl the endpoint HTTP URL with httpx."""
    from reNgine.tasks.http import http_crawl
    if ctx is None:
        ctx = {}
    # Remove nulls and validate basic inputs
    endpoint_data = replace_nulls(endpoint_data)
    scheme = urlparse(http_url).scheme

    if not scheme:
        logger.error(f'{http_url} is missing scheme (http or https). Skipping.')
        return None, False

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

    # If this is a default endpoint, check if one already exists for this subdomain
    if is_default and subdomain:
        if existing_default := EndPoint.objects.filter(
            scan_history=scan,
            target_domain=domain,
            subdomain=subdomain,
            is_default=True,
        ).first():
            logger.info(f'Default endpoint already exists for subdomain {subdomain}')
            return existing_default, False

    if existing_endpoint := EndPoint.objects.filter(
        scan_history=scan, target_domain=domain, http_url=http_url
    ).first():
        return existing_endpoint, False

    # Create new endpoint
    if crawl:
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        results = http_crawl(urls=[http_url], ctx=custom_ctx)
        if not results or results[0]['failed']:
            logger.error(f'Endpoint for {http_url} does not seem to be up. Skipping.')
            return None, False

        endpoint_data = results[0]
        endpoint = EndPoint.objects.get(pk=endpoint_data['endpoint_id'])
        endpoint.is_default = is_default
        endpoint.save()
        created = endpoint_data['endpoint_created']
    else:
        create_data = {
            'scan_history': scan,
            'target_domain': domain,
            'subdomain': subdomain,
            'http_url': http_url,
            'is_default': is_default,
            'discovered_date': timezone.now(),
        }

        if http_status is not None:
            create_data['http_status'] = http_status

        create_data |= endpoint_data

        endpoint = EndPoint.objects.create(**create_data)
        created = True

    # Add subscan relation if needed
    if created and ctx.get('subscan_id'):
        endpoint.endpoint_subscan_ids.add(ctx.get('subscan_id'))
        endpoint.save()

    return endpoint, created

def save_subdomain(subdomain_name, ctx=None):
    """Get or create Subdomain object."""
    if ctx is None:
        ctx = {}
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
    if not is_ip_scan and ctx.get('domain_id') and domain.name not in subdomain_name:
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

def save_subdomain_metadata(subdomain, endpoint, extra_datas=None):
    if extra_datas is None:
        extra_datas = {}
    if endpoint and endpoint.is_alive:
        _extracted_from_save_subdomain_metadata_3(endpoint, subdomain, extra_datas)
    elif http_url := extra_datas.get('http_url'):
        subdomain.http_url = http_url
        subdomain.save()
    else:
        logger.error(f'No HTTP URL found for {subdomain.name}. Skipping.')


# TODO Rename this here and in `save_subdomain_metadata`
def _extracted_from_save_subdomain_metadata_3(endpoint, subdomain, extra_datas):
    logger.info(f'💾 Saving HTTP metadatas from {endpoint.http_url}')
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

def save_email(email_address, scan_history=None):
    if not validators.email(email_address):
        logger.info(f'💾 Email {email_address} is invalid. Skipping.')
        return None, False
    email, created = Email.objects.get_or_create(address=email_address)
    if created:
        logger.info(f'💾 Found new email address {email_address}')

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
        logger.warning(f'💾 Found new employee {name}')

    # Add employee to ScanHistory
    if scan_history:
        scan_history.employees.add(employee)
        scan_history.save()

    return employee, created

def save_imported_subdomains(subdomains, ctx=None):
    """Take a list of subdomains imported and write them to from_imported.txt.

    Args:
        subdomains (list): List of subdomain names.
        scan_history (startScan.models.ScanHistory): ScanHistory instance.
        domain (startScan.models.Domain): Domain instance.
        results_dir (str): Results directory.
    """
    if ctx is None:
        ctx = {}
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
        enable_http_crawl = ctx.get('yaml_configuration').get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
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
                http_url,
                ctx=ctx,
                crawl=enable_http_crawl,
                is_default=True,
                subdomain=subdomain_obj
            )
            save_subdomain_metadata(subdomain_obj, endpoint)

def save_metadata_info(meta_dict):
    """Extract metadata from Google Search.

    Args:
        meta_dict (dict): Info dict.

    Returns:
        list: List of startScan.MetaFinderDocument objects.
    """
    logger.warning(f'Getting metadata for {meta_dict.osint_target}')

    scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

    # Proxy settings
    get_random_proxy()

    # Get metadata
    #result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
    result=[]
    if not result:
        logger.error(f'No metadata result from Google Search for {meta_dict.osint_target}.')
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
            scan_history (startScan.models.ScanHistory): Scan History Object
    """
    results = []

    # Create the builder with the execution path as the base command
    cmd_builder = CommandBuilder(GOFUZZ_EXEC_PATH)
    cmd_builder.add_option('-t', lookup_target)
    cmd_builder.add_option('-d', delay)
    cmd_builder.add_option('-p', page_count)

    # Add conditional options
    if lookup_extensions:
        cmd_builder.add_option('-e', lookup_extensions)
    elif lookup_keywords:
        cmd_builder.add_option('-w', lookup_keywords)

    # Define the output file
    output_file = str(Path(results_dir) / 'gofuzz.txt')
    cmd_builder.add_option('-o', output_file)

    # Get the command as a list or string as needed
    gofuzz_command = cmd_builder.build_string()  # or cmd_builder.build_list() depending on usage
    history_file = str(Path(results_dir) / 'commands.txt')

    try:
        run_command_line(
            gofuzz_command,
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

def get_and_save_emails(scan_history, activity_id, results_dir):
    """Get and save emails from Google, Bing and Baidu.

    Args:
        scan_history (startScan.ScanHistory): Scan history object.
        activity_id: ScanActivity Object
        results_dir (str): Results directory.

    Returns:
        list: List of emails found.
    """
    emails = []

    # Proxy settings
    # get_random_proxy()

    # Gather emails from Google, Bing and Baidu
    output_file = str(Path(results_dir) / 'emails_tmp.txt')
    history_file = str(Path(results_dir) / 'commands.txt')
    cmd_builder = CommandBuilder('infoga')
    cmd_builder.add_option('--domain', scan_history.domain.name)
    cmd_builder.add_option('--source', 'all')
    cmd_builder.add_option('--report', output_file)
    command = cmd_builder.build_string()

    try:
        run_command_line(
            command,
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

        output_path = str(Path(results_dir) / 'emails.txt')
        with open(output_path, 'w') as output_file:
            for email_address in emails:
                save_email(email_address, scan_history)
                output_file.write(f'{email_address}\n')

    except Exception as e:
        logger.exception(e)
    return emails 

def get_vulnerability_gpt_report(vuln):
    title = vuln[0]
    path = vuln[1]
    logger.info(f'Getting GPT Report for {title}, PATH: {path}')
    if (
        stored := GPTVulnerabilityReport.objects.filter(url_path=path)
        .filter(title=title)
        .first()
    ):
        response = {
            'description': stored.description,
            'impact': stored.impact,
            'remediation': stored.remediation,
            'references': [url.url for url in stored.references.all()]
        }
    else:
        report = GPTVulnerabilityReportGenerator()
        vulnerability_description = get_gpt_vuln_input_description(
            title,
            path
        )
        response = report.get_vulnerability_description(vulnerability_description)
        add_gpt_description_db(
            title,
            path,
            response.get('description'),
            response.get('impact'),
            response.get('remediation'),
            response.get('references', [])
        )


    for vuln in Vulnerability.objects.filter(name=title, http_url__icontains=path):
        vuln.description = response.get('description', vuln.description)
        vuln.impact = response.get('impact')
        vuln.remediation = response.get('remediation')
        vuln.is_gpt_used = True
        vuln.save()

        for url in response.get('references', []):
            ref, created = VulnerabilityReference.objects.get_or_create(url=url)
            vuln.references.add(ref)
            vuln.save()

def add_gpt_description_db(title, path, description, impact, remediation, references):
    gpt_report = GPTVulnerabilityReport()
    gpt_report.url_path = path
    gpt_report.title = title
    gpt_report.description = description
    gpt_report.impact = impact
    gpt_report.remediation = remediation
    gpt_report.save()

    for url in references:
        ref, created = VulnerabilityReference.objects.get_or_create(url=url)
        gpt_report.references.add(ref)
        gpt_report.save()


def record_exists(model, data, exclude_keys=[]):
    """
    Check if a record already exists in the database based on the given data.

    Args:
        model (django.db.models.Model): The Django model to check against.
        data (dict): Data dictionary containing fields and values.
        exclude_keys (list): List of keys to exclude from the lookup.

    Returns:
        bool: True if the record exists, False otherwise.
    """
    def clean_request(request_str):
        if not request_str:
            return request_str
        request_lines = request_str.split('\r\n')
        cleaned_lines = [line for line in request_lines if not line.startswith('User-Agent:')]
        return '\r\n'.join(cleaned_lines)

    # Extract the keys that will be used for the lookup
    lookup_fields = data.copy()
    
    # Clean the request field if it contains a User-Agent line
    if 'request' in lookup_fields:
        lookup_fields['request'] = clean_request(lookup_fields['request'])

    # Remove the fields to exclude
    lookup_fields = {key: lookup_fields[key] for key in lookup_fields if key not in exclude_keys}

    # Get all existing records that might match
    base_query = {key: value for key, value in lookup_fields.items() if key != 'request'}
    existing_records = model.objects.filter(**base_query)
    
    if not existing_records.exists():
        logger.debug(f"No existing records found with lookup fields: {lookup_fields}")
        return False
    
    # For each existing record, log the differences
    for record in existing_records:
        differences = {}
        for key, value in lookup_fields.items():
            existing_value = getattr(record, key)
            if key == 'request':
                existing_value = clean_request(existing_value)
            if existing_value != value:
                differences[key] = {
                    'existing': existing_value,
                    'new': value
                }
        
        if differences:
            logger.debug(f"Record {record.id} has differences: {differences}")
        else:
            logger.debug(f"Record {record.id} matches exactly with lookup fields: {lookup_fields}")
            return True
            
    return False 

def save_technologies(techs, endpoint):
    """Save technologies associated with an endpoint.

    Args:
        techs (list): List of technology names to save.
        endpoint (EndPoint): The endpoint to associate technologies with.

    Returns:
        None
    """
    for technology in techs:
        tech, _ = Technology.objects.get_or_create(name=technology)
        endpoint.techs.add(tech)
        endpoint.save() 

def create_scan_activity(scan_history_id, message, status):
    scan_activity = ScanActivity()
    scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
    scan_activity.title = message
    scan_activity.time = timezone.now()
    scan_activity.status = status
    scan_activity.save()
    return scan_activity.id

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

def create_first_endpoint_from_nmap_data(hosts_data, domain, subdomain, ctx):
    """Create endpoints from Nmap service detection results.
    Returns the first created endpoint or None if failed."""
    
    if not hosts_data:
        logger.warning("No Nmap data provided. Skipping endpoint creation.")
        return None

    endpoint = None
    is_ip_scan = validators.ipv4(domain.name) or validators.ipv6(domain.name)
    url_filter = ctx.get('url_filter', '').rstrip('/')

    # For IP scans, ensure we have an entry for the IP itself
    if is_ip_scan and domain.name not in hosts_data:
        rdns_hostname = next(iter(hosts_data.keys()), None)
        if rdns_hostname and hosts_data[rdns_hostname]:
            hosts_data[domain.name] = hosts_data[rdns_hostname].copy()
            logger.info(f"Created IP endpoint data from rDNS {rdns_hostname}")

    for hostname, data in hosts_data.items():
        current_subdomain = subdomain
        schemes_to_try = []

        # If scheme is detected, try it first
        if data['scheme']:
            schemes_to_try.append(data['scheme'])

        # Add any missing schemes to try
        for scheme in ['https', 'http']:
            if scheme not in schemes_to_try:
                schemes_to_try.append(scheme)

        # Try each port with each scheme
        successful_endpoint = None
        for port in data['ports']:
            for scheme in schemes_to_try:
                host_url = f"{scheme}://{hostname}:{port}{url_filter}"
                logger.debug(f'Processing HTTP URL: {host_url}')

                # For IP scans, create endpoints for both IP and rDNS
                if is_ip_scan:
                    if hostname != domain.name:
                        # Create subdomain for rDNS
                        logger.info(f'Creating subdomain for rDNS hostname: {hostname}')
                        rdns_subdomain, _ = save_subdomain(hostname, ctx=ctx)
                        if rdns_subdomain:
                            # Try to create endpoint for rDNS
                            rdns_endpoint, _ = save_endpoint(
                                host_url,
                                ctx=ctx,
                                crawl=True,
                                is_default=True,
                                subdomain=rdns_subdomain
                            )
                            if rdns_endpoint:
                                successful_endpoint = rdns_endpoint
                                save_subdomain_metadata(
                                    rdns_subdomain,
                                    successful_endpoint,
                                    extra_datas={
                                        'open_ports': data['ports'],
                                    },
                                )
                                break  # Found working scheme, try next port

                    # Always try to create endpoint for IP itself
                    if hostname == domain.name or not endpoint:
                        current_endpoint, _ = save_endpoint(
                            f"{scheme}://{domain.name}:{port}{url_filter}",
                            ctx=ctx,
                            crawl=True,
                            is_default=True,
                            subdomain=current_subdomain
                        )
                        if current_endpoint:
                            successful_endpoint = current_endpoint
                            save_subdomain_metadata(
                                current_subdomain,
                                current_endpoint,
                                extra_datas={
                                    'http_url': f"{scheme}://{domain.name}:{port}{url_filter}",
                                    'open_ports': data['ports']
                                }
                            )
                            break  # Found working scheme, try next port

                else:
                    if hostname != domain.name:
                        logger.info(f'Creating subdomain for hostname: {hostname}')
                        current_subdomain, _ = save_subdomain(hostname, ctx=ctx)
                        if not current_subdomain:
                            logger.warning(f'Could not create subdomain for hostname: {hostname}. Skipping this host.')
                            continue

                    # Try to create endpoint with crawling
                    current_endpoint, _ = save_endpoint(
                        host_url,
                        ctx=ctx,
                        crawl=True,
                        is_default=True,
                        subdomain=current_subdomain
                    )

                    if current_endpoint:
                        successful_endpoint = current_endpoint
                        save_subdomain_metadata(
                            current_subdomain,
                            successful_endpoint,
                            extra_datas={
                                'open_ports': data['ports'],
                            },
                        )
                        break  # Found working scheme, try next port

            if successful_endpoint:
                break  # Found working port, stop trying others

        # Keep track of hostname data even if no endpoint was created
        if not successful_endpoint and current_subdomain:  # Added check for current_subdomain
            save_subdomain_metadata(
                current_subdomain,
                None,
                extra_datas={
                    'http_url': f"unknown://{hostname}{url_filter}",
                    'open_ports': data['ports']
                }
            )
        # Update main endpoint if needed
        elif not endpoint or hostname == domain.name:
            endpoint = successful_endpoint

    return endpoint

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
    logger.warning(f'🌐 Using proxy: {proxy_name}')
    # os.environ['HTTP_PROXY'] = proxy_name
    # os.environ['HTTPS_PROXY'] = proxy_name
    return proxy_name

#-------------------#
# SubDomain queries #
#-------------------#

def get_subdomains(write_filepath=None, exclude_subdomains=False, ctx=None):
    """Get Subdomain objects from DB.

    Args:
        write_filepath (str): Write info back to a file.
        exclude_subdomains (bool): Exclude subdomains, only return subdomain matching domain.
        ctx (dict): ctx

    Returns:
        list: List of subdomains matching query.
    """
    if ctx is None:
        ctx = {}
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
        logger.error('💾 No subdomains were found in query !')

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
    if scan.count() <= 1:
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
    if scan_history.count() <= 1:
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
    from reNgine.utils.db import get_lookup_keywords
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

def get_http_urls(is_alive=False, is_uncrawled=False, strict=False, ignore_files=False, write_filepath=None, exclude_subdomains=False, get_only_default_urls=False, ctx=None):
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
    if ctx is None:
        ctx = {}
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
        logger.debug('Excluding subdomains')
        query = query.filter(http_url=domain.http_url)
    if get_only_default_urls:
        logger.debug('Searching only for default URL')
        query = query.filter(is_default=True)

    # If is_uncrawled is True, select only endpoints that have not been crawled
    # yet (no status)
    if is_uncrawled:
        logger.debug('Searching for uncrawled endpoints only')
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
        logger.error('💾 No endpoints were found in query !')

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
