import os
import re
from pathlib import Path
from urllib.parse import urlparse

from celery import chain, chord
from celery.result import allow_join_result
from celery.utils.log import get_task_logger
from django.db.models import Count

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    FETCH_URL,
    REMOVE_DUPLICATE_ENDPOINTS,
    DUPLICATE_REMOVAL_FIELDS,
    ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS,
    GF_PATTERNS,
    IGNORE_FILE_EXTENSION,
    DEFAULT_IGNORE_FILE_EXTENSIONS,
    USES_TOOLS,
    ENDPOINT_SCAN_DEFAULT_TOOLS,
    THREADS,
    CUSTOM_HEADER,
    FOLLOW_REDIRECT,
    EXCLUDED_SUBDOMAINS,
    DEFAULT_GF_PATTERNS,
)
from reNgine.settings import (
    DEFAULT_THREADS,
    DELETE_DUPLICATES_THRESHOLD
)
from reNgine.tasks.command import run_command
from reNgine.utilities.endpoint import get_http_urls
from reNgine.utilities.url import get_subdomain_from_url, sanitize_url
from reNgine.utilities.proxy import get_random_proxy
from reNgine.utilities.command import generate_header_param
from reNgine.utilities.data import is_iterable
from reNgine.utilities.database import save_subdomain, save_endpoint
from startScan.models import EndPoint, Subdomain

logger = get_task_logger(__name__)


@app.task(name='fetch_url', queue='io_queue', base=RengineTask, bind=True)
def fetch_url(self, urls=[], ctx={}, description=None):
    """Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

    Args:
        urls (list): List of URLs to start from.
        description (str, optional): Task description shown in UI.
    """
    input_path = str(Path(self.results_dir) / 'input_endpoints_fetch_url.txt')
    proxy = get_random_proxy()

    # Config
    config = self.yaml_configuration.get(FETCH_URL) or {}
    should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
    duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)

    gf_patterns = config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)
    ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
    tools = config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS)
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    domain_request_headers = self.domain.request_headers if self.domain else None
    custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    follow_redirect = config.get(FOLLOW_REDIRECT, False)  # Get follow redirect setting
    if domain_request_headers or custom_header:
        custom_header = domain_request_headers or custom_header
    exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

    # Initialize the URLs
    if urls and is_iterable(urls) and any(url for url in urls if url):
        logger.debug('URLs provided by user')
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        logger.debug('URLs gathered from database')
        urls = get_http_urls(
            is_alive=True,
            write_filepath=input_path,
            exclude_subdomains=exclude_subdomains,
            get_only_default_urls=True,
            ctx=ctx
        )

    # check if urls is empty
    if not urls:
        logger.warning("No URLs found. Exiting fetch_url.")
        return

    # Log initial URLs
    logger.debug(f'Initial URLs: {urls}')

    # Initialize command map for tools
    cmd_map = {
        'gau': 'gau --config ' + str(Path.home() / '.config' / 'gau' / 'config.toml'),
        'hakrawler': 'hakrawler -subs -u',
        'waybackurls': 'waybackurls',
        'gospider': 'gospider --js -d 2 --sitemap --robots -w -r -a',
        'katana': 'katana -silent -jc -kf all -d 3 -fs rdn -td',
    }
    if proxy:
        cmd_map['gau'] += f' --proxy "{proxy}"'
        cmd_map['gospider'] += f' -p {proxy}'
        cmd_map['hakrawler'] += f' -proxy {proxy}'
        cmd_map['katana'] += f' -proxy {proxy}'
    if threads > 0:
        cmd_map['gau'] += f' --threads {threads}'
        cmd_map['gospider'] += f' -t {threads}'
        cmd_map['hakrawler'] += f' -t {threads}'
        cmd_map['katana'] += f' -c {threads}'
    if custom_header:
        cmd_map['gospider'] += generate_header_param(custom_header, 'gospider')
        cmd_map['hakrawler'] += generate_header_param(custom_header, 'hakrawler')
        cmd_map['katana'] += generate_header_param(custom_header, 'common')

    # Add follow_redirect option to tools that support it
    if follow_redirect is False:
        cmd_map['gospider'] += ' --no-redirect'
        cmd_map['hakrawler'] += ' -dr'
        cmd_map['katana'] += ' -dr'

    tasks = []

    # Iterate over each URL and generate commands for each tool
    for url in urls:
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc.split(':')[0]  # Remove port if present
        host_regex = f"'https?://{re.escape(base_domain)}(:[0-9]+)?(/.*)?$'"

        # Log the generated regex for the current URL
        logger.debug(f'Generated regex for domain {base_domain}: {host_regex}')

        cat_input = f'echo "{url}"'

        # Generate commands for each tool for the current URL
        for tool in tools:  # Only use tools specified in the config
            if tool in cmd_map:
                cmd = cmd_map[tool]
                tool_cmd = f'{cat_input} | {cmd} | grep -Eo {host_regex} > {self.results_dir}/urls_{tool}_{base_domain}.txt'
                tasks.append(run_command.si(
                    tool_cmd,
                    shell=True,
                    scan_id=self.scan_id,
                    activity_id=self.activity_id)
                )
                logger.debug(f'Generated command for tool {tool}: {tool_cmd}')

    # Group the tasks
    from celery import group
    task_group = group(tasks)

    # Cleanup task
    sort_output = [
        f'cat ' + str(Path(self.results_dir) / 'urls_*') + f' > {self.output_path}',
        f'cat {input_path} >> {self.output_path}',
        f'sort -u {self.output_path} -o {self.output_path}',
    ]
    if ignore_file_extension and is_iterable(ignore_file_extension):
        ignore_exts = '|'.join(ignore_file_extension)
        grep_ext_filtered_output = [
            f'cat {self.output_path} | grep -Eiv "\\.({ignore_exts}).*" > ' + str(Path(self.results_dir) / 'urls_filtered.txt'),
            f'mv ' + str(Path(self.results_dir) / 'urls_filtered.txt') + f' {self.output_path}'
        ]
        sort_output.extend(grep_ext_filtered_output)
    cleanup = chain(
        run_command.si(
            cmd,
            shell=True,
            scan_id=self.scan_id,
            activity_id=self.activity_id)
        for cmd in sort_output
    )

    # Run all commands
    task = chord(task_group)(cleanup)
    with allow_join_result():
        task.get()

    # Store all the endpoints and run httpx
    all_urls = []
    tool_mapping = {}  # New dictionary to map URLs to tools
    for tool in tools:
        for url in urls:
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc.split(':')[0]  # Remove port if present
            tool_output_file = f'{self.results_dir}/urls_{tool}_{base_domain}.txt'
            if os.path.exists(tool_output_file):
                with open(tool_output_file, 'r') as f:
                    discovered_urls = f.readlines()
                    for url in discovered_urls:
                        url = url.strip()
                        urlpath = None
                        base_url = None
                        if '] ' in url:  # found JS scraped endpoint e.g from gospider
                            split = tuple(url.split('] '))
                            if not len(split) == 2:
                                logger.warning(f'URL format not recognized for "{url}". Skipping.')
                                continue
                            base_url, urlpath = split
                            urlpath = urlpath.lstrip('- ')
                        elif ' - ' in url:  # found JS scraped endpoint e.g from gospider
                            base_url, urlpath = tuple(url.split(' - '))

                        if base_url and urlpath:
                            # Handle both cases: path-only and full URLs
                            if urlpath.startswith(('http://', 'https://')):
                                # Full URL case - check if in scope
                                parsed_url = urlparse(urlpath)
                                if self.domain.name in parsed_url.netloc:
                                    url = urlpath  # Use the full URL directly
                                    logger.debug(f'Found in-scope URL: {url}')
                                else:
                                    logger.debug(f'URL {urlpath} not in scope for domain {self.domain.name}. Skipping.')
                                    continue
                            else:
                                # Path-only case
                                subdomain = urlparse(base_url)
                                # Remove ./ at beginning of urlpath
                                urlpath = urlpath.lstrip('./')
                                # Ensure urlpath starts with /
                                if not urlpath.startswith('/'):
                                    urlpath = '/' + urlpath
                                url = f'{subdomain.scheme}://{subdomain.netloc}{urlpath}'

                        import validators
                        if not validators.url(url):
                            logger.warning(f'Invalid URL "{url}". Skipping.')
                            continue

                        if url not in tool_mapping:
                            tool_mapping[url] = set()
                        tool_mapping[url].add(tool)  # Use a set to ensure uniqueness

    all_urls = list(tool_mapping.keys())
    for url, found_tools in tool_mapping.items():
        unique_tools = ', '.join(found_tools)
        logger.info(f'URL {url} found by tools: {unique_tools}')

    # Filter out URLs if a path filter was passed
    if self.url_filter:
        all_urls = [url for url in all_urls if self.url_filter in url]

    # Write result to output path
    with open(self.output_path, 'w') as f:
        f.write('\n'.join(all_urls))
    logger.warning(f'Found {len(all_urls)} usable URLs')


    #-------------------#
    # GF PATTERNS MATCH #
    #-------------------#

    # Combine old gf patterns with new ones
    if gf_patterns and is_iterable(gf_patterns):
        self.scan.used_gf_patterns = ','.join(gf_patterns)
        self.scan.save()

    # Run gf patterns on saved endpoints
    # TODO: refactor to Celery task
    for gf_pattern in gf_patterns:
        # TODO: js var is causing issues, removing for now
        if gf_pattern == 'jsvar':
            logger.info('Ignoring jsvar as it is causing issues.')
            continue

        # Run gf on current pattern
        logger.warning(f'Running gf on pattern "{gf_pattern}"')
        gf_output_file = str(Path(self.results_dir) / f'gf_patterns_{gf_pattern}.txt')
        host_regex = f"'https?://{re.escape(self.domain.name)}(:[0-9]+)?(/.*)?$'"
        cmd = f'cat {self.output_path} | gf {gf_pattern} | grep -Eo {host_regex} >> {gf_output_file}'
        run_command(
            cmd,
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id)

        # Check output file
        if not os.path.exists(gf_output_file):
            logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
            continue

        # Read output file line by line and
        with open(gf_output_file, 'r') as f:
            lines = f.readlines()

        # Add endpoints / subdomains to DB
        for url in lines:
            http_url = sanitize_url(url)
            subdomain_name = get_subdomain_from_url(http_url)
            subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
            if not isinstance(subdomain, Subdomain):
                logger.error(f"Invalid subdomain encountered: {subdomain}")
                continue
            endpoint, created = save_endpoint(
                http_url=http_url,
                subdomain=subdomain,
                ctx=ctx)
            if not endpoint:
                continue
            earlier_pattern = None
            if not created:
                earlier_pattern = endpoint.matched_gf_patterns
            pattern = f'{earlier_pattern},{gf_pattern}' if earlier_pattern else gf_pattern
            endpoint.matched_gf_patterns = pattern
            # TODO Add tool that found the URL to the db (need to update db model)
            # endpoint.found_by_tools = ','.join(tool_mapping.get(url, []))  # Save tools in the endpoint
            endpoint.save()

    return all_urls


@app.task(name='remove_duplicate_endpoints', bind=False, queue='cpu_queue')
def remove_duplicate_endpoints(
        scan_history_id,
        domain_id,
        subdomain_id=None,
        filter_ids=[],
        # TODO Check if the status code could be set as parameters of the scan engine instead of hardcoded values
        filter_status=[200, 301, 302, 303, 307, 404, 410],  # Extended status codes
        duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS
    ):
    """Remove duplicate endpoints.

    Check for implicit redirections by comparing endpoints:
    - [x] `content_length` similarities indicating redirections
    - [x] `page_title` (check for same page title)
    - [ ] Sign-in / login page (check for endpoints with the same words)

    Args:
        scan_history_id: ScanHistory id.
        domain_id (int): Domain id.
        subdomain_id (int, optional): Subdomain id.
        filter_ids (list): List of endpoint ids to filter on.
        filter_status (list): List of HTTP status codes to filter on.
        duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates
    """
    logger.info(f'Removing duplicate endpoints based on {duplicate_removal_fields}')
    
    # Filter endpoints based on scan history and domain
    endpoints = (
        EndPoint.objects
        .filter(scan_history__id=scan_history_id)
        .filter(target_domain__id=domain_id)
    )
    if filter_status:
        endpoints = endpoints.filter(http_status__in=filter_status)

    if subdomain_id:
        endpoints = endpoints.filter(subdomain__id=subdomain_id)

    if filter_ids:
        endpoints = endpoints.filter(id__in=filter_ids)

    # Group by all duplicate removal fields combined
    fields_combined = duplicate_removal_fields[:]
    fields_combined.append('id')  # Add ID to ensure unique identification

    cl_query = (
        endpoints
        .values(*duplicate_removal_fields)
        .annotate(mc=Count('id'))
        .order_by('-mc')
    )

    for field_values in cl_query:
        if field_values['mc'] > DELETE_DUPLICATES_THRESHOLD:
            filter_criteria = {field: field_values[field] for field in duplicate_removal_fields}
            eps_to_delete = (
                endpoints
                .filter(**filter_criteria)
                .order_by('discovered_date')
                .all()[1:]
            )
            msg = f'Deleting {len(eps_to_delete)} endpoints [reason: same {filter_criteria}]'
            for ep in eps_to_delete:
                url = urlparse(ep.http_url)
                if url.path in ['', '/', '/login']:  # Ensure not to delete the original page that other pages redirect to
                    continue
                msg += f'\n\t {ep.http_url} [{ep.http_status}] {filter_criteria}'
                ep.delete()
            logger.warning(msg)


@app.task(name='run_gf_list', queue='run_command_queue')
def run_gf_list():
    try:
        # Prepare GF list command
        gf_command = 'gf -list'
        
        # Run GF list command
        return_code, output = run_command(
            cmd=gf_command,
            shell=True,
            remove_ansi_sequence=True
        )
        
        # Log the raw output
        logger.info(f"Raw output from GF list: {output}")
        
        # Check if the command was successful
        if return_code == 0:
            # Split the output into a list of patterns
            patterns = [pattern.strip() for pattern in output.split('\n') if pattern.strip()]
            return {
                'status': True,
                'output': patterns
            }
        else:
            logger.error(f"GF list command failed with return code: {return_code}")
            return {
                'status': False,
                'message': f"GF list command failed with return code: {return_code}"
            }
    
    except Exception as e:
        logger.error(f"Error running GF list: {e}")
        return {
            'status': False,
            'message': str(e)
        } 