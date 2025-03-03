import os
import re

from copy import deepcopy
from urllib.parse import urlparse
from django.db.models import Count

from reNgine.definitions import (
    FETCH_URL,
    ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS,
    ENDPOINT_SCAN_DEFAULT_TOOLS,
    ALL,
)
from reNgine.settings import DELETE_DUPLICATES_THRESHOLD
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.tasks.command import run_command_line
from reNgine.utils.http import (
    get_subdomain_from_url,
    sanitize_url,
    prepare_urls_with_fallback,
)
from startScan.models import EndPoint, Subdomain
from reNgine.utils.command_builder import CommandBuilder, build_piped_command, build_fetch_url_commands
from reNgine.utils.task_config import TaskConfig

logger = Logger(True)

@app.task(name='fetch_url', queue='io_queue', base=RengineTask, bind=True)
def fetch_url(self, urls=None, ctx=None, description=None):
    """Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

    Args:
        urls (list): List of URLs to start from.
        description (str, optional): Task description shown in UI.
    """
    from reNgine.utils.db import save_endpoint, save_subdomain
    from reNgine.tasks.http import http_crawl

    if urls is None:
        urls = []
    if ctx is None:
        ctx = {}

    logger.info('🔍 Initiating URL Fetch')

    # Initialize task config
    config = TaskConfig(ctx, FETCH_URL)
    task_config = config.get_task_config()

    # Initialize the URLs
    urls = prepare_urls_with_fallback(
        urls=urls, 
        input_path=task_config['input_path'], 
        ctx=ctx,
        is_alive=True,
        exclude_subdomains=task_config['exclude_subdomains'],
        get_only_default_urls=True
    )

    # Check if urls is empty
    if not urls:
        logger.warning("No URLs found. Exiting fetch_url.")
        return []

    # Get URL mapping for tools
    tools = task_config['tools']
    if ALL in tools:
        tools = ENDPOINT_SCAN_DEFAULT_TOOLS

    # Filter out unsupported tools
    tools = [tool for tool in tools if tool in ['gau', 'hakrawler', 'waybackurls', 'gospider', 'katana']]

    # Build commands for all tools
    host = self.subdomain.http_url if self.subdomain else self.domain.name
    cmd_map = build_fetch_url_commands(config)

    # Initialize variables for tracking URLs and their sources
    all_urls = set()
    tool_mapping = {}  # {url: [tools that found it]}

    # Run tools and collect URLs
    for tool in tools:
        if tool not in cmd_map:
            logger.warning(f'Tool {tool} not supported. Skipping.')
            continue

        logger.warning(f'Running {tool} for URL discovery')

        # Prepare output path for this tool
        self.output_path = config.get_working_dir(filename=f'urls_{tool}.txt')

        # Build and run the command using CommandBuilder
        tool_cmd = cmd_map[tool].add_option(host)

        sort_cmd = CommandBuilder("sort")
        sort_cmd.add_option("-u")

        # Create a piped command: tool | sort -u | tee output_file
        piped_cmd = build_piped_command([tool_cmd, sort_cmd], output_file=self.output_path)

        run_command_line.delay(
            cmd=piped_cmd.build_string(),
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id
        )

        # Check if output file exists
        if not os.path.exists(self.output_path):
            logger.error(f'Could not find {tool} output file {self.output_path}')
            continue

        # Process URLs from output file
        with open(self.output_path, 'r') as f:
            for url in f:
                url = url.strip()
                if not url:
                    continue

                # Sanitize and filter URL
                http_url = sanitize_url(url)

                # Skip URLs with ignored extensions
                if task_config['ignore_file_extension'] and any(http_url.endswith(ext) for ext in task_config['ignore_file_extension']):
                    continue

                # Track which tools found this URL
                if http_url not in tool_mapping:
                    tool_mapping[http_url] = []
                tool_mapping[http_url].append(tool)

                # Add to set of all URLs
                all_urls.add(http_url)

        logger.info(f'Discovered {len(all_urls)} unique URLs so far')

    # Add endpoints to database
    results = []
    
    for url in all_urls:
        subdomain_name = get_subdomain_from_url(url)
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        if not isinstance(subdomain, Subdomain):
            logger.error(f"Invalid subdomain encountered: {subdomain}")
            continue

        endpoint, created = save_endpoint(
            url,
            crawl=False,
            subdomain=subdomain,
            ctx=ctx
        )
        
        if endpoint:
            results.append({
                'endpoint_id': endpoint.id,
                'url': url,
                'created': created
            })

    # Remove duplicate endpoints if configured
    if task_config['should_remove_duplicate_endpoints']:
        removed_count = remove_duplicate_endpoints(
            scan_history_id=self.scan_id,
            domain_id=self.domain_id,
            subdomain_id=self.subdomain_id,
            filter_ids=[r.get('endpoint_id') for r in results if 'endpoint_id' in r]
        )
        if removed_count > 0:
            logger.info(f'Removed {removed_count} duplicate endpoints')

    # HTTP crawl if enabled
    if task_config['enable_http_crawl']:
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = True
        http_crawl.delay(list(all_urls), ctx=custom_ctx)

    # Run gf patterns if configured
    if task_config['gf_patterns']:
        _run_gf_patterns(self, task_config['gf_patterns'], ctx)

    return list(all_urls)

def _run_gf_patterns(self, gf_patterns, ctx):
    """Run gf patterns on discovered URLs.
    
    Args:
        gf_patterns (list): List of gf patterns to run
        ctx (dict): Context information
    """
    from reNgine.utils.db import save_endpoint, save_subdomain
    from reNgine.utils.http import get_subdomain_from_url, sanitize_url
    
    if not os.path.exists(self.output_path):
        logger.error(f'Could not find output file {self.output_path} for gf patterns')
        return
        
    # Only allow alphabets, numbers, and dash in target domain for regex
    host_regex = "\'https\?://[a-zA-Z0-9][a-zA-Z0-9\-\.]*\." + re.escape(self.target_domain) + "/[^\ ]*\'"
    
    # Run each gf pattern
    for gf_pattern in gf_patterns:
        if gf_pattern == 'jsvar':
            logger.info('Ignoring jsvar as it is causing issues.')
            continue
            
        # Run gf on current pattern
        logger.warning(f'Running gf on pattern "{gf_pattern}"')
        config = TaskConfig(ctx, FETCH_URL)
        gf_output_file = config.get_working_dir(filename=f'gf_patterns_{gf_pattern}.txt')
        
        # Build commands with CommandBuilder
        cat_cmd = CommandBuilder("cat")
        cat_cmd.add_option(self.output_path)
        
        gf_cmd = CommandBuilder("gf")
        gf_cmd.add_option(gf_pattern)
        
        grep_cmd = CommandBuilder("grep")
        grep_cmd.add_option("-Eo")
        grep_cmd.add_option(host_regex)
        
        # Create a piped command: cat file | gf pattern | grep -Eo regex >> output_file
        piped_cmd = build_piped_command(
            [cat_cmd, gf_cmd, grep_cmd], 
            output_file=gf_output_file,
            append=True
        )
        
        run_command_line.delay(
            cmd=piped_cmd.build_string(),
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id
        )
        
        # Check if output file exists
        if not os.path.exists(gf_output_file):
            logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
            continue
            
        # Process URLs from output file
        with open(gf_output_file, 'r') as f:
            for url in f:
                http_url = sanitize_url(url)
                subdomain_name = get_subdomain_from_url(http_url)
                subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
                
                if not isinstance(subdomain, Subdomain):
                    logger.error(f"Invalid subdomain encountered: {subdomain}")
                    continue
                    
                endpoint, created = save_endpoint(
                    http_url,
                    crawl=False,
                    subdomain=subdomain,
                    ctx=ctx
                )
                
                if not endpoint:
                    continue
                    
                # Update matched pattern
                earlier_pattern = None
                if not created:
                    earlier_pattern = endpoint.matched_gf_patterns
                pattern = f'{earlier_pattern},{gf_pattern}' if earlier_pattern else gf_pattern
                endpoint.matched_gf_patterns = pattern
                endpoint.save()

@app.task(name='run_gf_list', queue='run_command_queue', bind=False)
def run_gf_list():
    try:
        # Prepare GF list command using CommandBuilder
        gf_cmd = CommandBuilder("gf")
        gf_cmd.add_option("-list")
        
        # Run GF list command
        return_code, output = run_command_line.delay(
            cmd=gf_cmd.build_string(),
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

@app.task(name='remove_duplicate_endpoints', bind=False, queue='cpu_queue')
def remove_duplicate_endpoints(scan_history_id, domain_id, subdomain_id=None, filter_ids=None, filter_status=None, duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS):
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
    if filter_ids is None:
        filter_ids = []
    if filter_status is None:
        filter_status = [200, 301, 302, 303, 307, 404, 410]
    try:
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

                return len(eps_to_delete)
        return 0

    except Exception as e:
        logger.error(f'Error removing duplicate endpoints: {str(e)}')
        return 0
