from reNgine.definitions import (
    HTTP_CRAWL,
)
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.utils.command_executor import (
    stream_command
)
from reNgine.utils.http import (
    get_subdomain_from_url,
    build_httpx_command,
    process_httpx_line,
    prepare_urls_for_http_scan,
)
from reNgine.utils.utils import (
    remove_file_or_pattern,
)
from startScan.models import (
    Subdomain,
)
from reNgine.tasks.url import remove_duplicate_endpoints
from reNgine.utils.task_config import TaskConfig
from pathlib import Path

logger = Logger(True)
@app.task(name='http_crawl', queue='io_queue', base=RengineTask, bind=True)
def http_crawl(
                self, 
                urls=None, 
                method=None, 
                recrawl=False, 
                ctx=None, 
                track=True, 
                description=None,
                update_subdomain_metadatas=False, 
                should_remove_duplicate_endpoints=True, 
                duplicate_removal_fields=None):
    """Use httpx to query HTTP URLs for important info like page titles, http
    status, etc...

    Args:
        urls (list, optional): A set of URLs to check. Overrides default
            behavior which queries all endpoints related to this scan.
        method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
        recrawl (bool, optional): If False, filter out URLs that have already
            been crawled.
        should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
        duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates

    Returns:
        list: httpx results.
    """
    from reNgine.utils.db import (
        save_subdomain,
    )

    # Initialize context and duplicate_removal_fields
    if ctx is None:
        ctx = {}
    if duplicate_removal_fields is None:
        duplicate_removal_fields = []

    logger.info('🌐 Initiating HTTP Crawl')

    # Initialize task config
    config = TaskConfig(self.yaml_configuration, self.results_dir, self.scan_id, self.filename)
    
    # Get configuration from TaskConfig
    custom_header = config.prepare_custom_header(HTTP_CRAWL)
    threads = config.get_threads(HTTP_CRAWL)
    follow_redirect = config.get_follow_redirect(HTTP_CRAWL, False)
    self.output_path = None
    history_file = f'{self.results_dir}/commands.txt'

    # Prepare URLs for scanning using the specific function
    urls, input_path, subdomain_metadata_update = prepare_urls_for_http_scan(
        urls, 
        self.url_filter, 
        self.results_dir, 
        ctx,
        recrawl
    )

    # Update subdomain_metadatas flag if needed
    if subdomain_metadata_update:
        update_subdomain_metadatas = True

    # If no URLs found, skip it
    if not urls:
        logger.error('🌐 No URLs to crawl. Skipping.')
        return

    # Re-adjust thread number if few URLs
    if len(urls) < threads:
        threads = len(urls)

    # Get random proxy
    proxy = config.get_proxy()

    # Build the command
    cmd = build_httpx_command(
        threads, 
        proxy, 
        custom_header, 
        urls, 
        input_path, 
        method, 
        follow_redirect
    )

    # Process the results
    results = []
    endpoint_ids = []

    if not Path(input_path).exists():
        logger.error(f'📁 HTTP input file missing : {input_path}')
        return []

    for line in stream_command(
            cmd,
            history_file=history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id):

        # Skip invalid lines
        if not line or not isinstance(line, dict):
            continue

        # Check if the http request has an error
        if 'error' in line:
            logger.error(line)
            continue

        # No response from endpoint
        if line.get('failed', False):
            continue

        # Get subdomain from URL
        subdomain_name = get_subdomain_from_url(line.get('url', ''))
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

        if not isinstance(subdomain, Subdomain):
            logger.error(f"🌐 Invalid subdomain encountered: {subdomain}")
            continue

        # Process the line and get results
        endpoint, endpoint_str, result_data = process_httpx_line(
            line, 
            subdomain, 
            ctx, 
            follow_redirect, 
            update_subdomain_metadatas,
            self.subscan
        )

        if not endpoint:
            continue

        # Log and notify about the endpoint
        logger.warning(f'🌐 {endpoint_str}')
        if endpoint.is_alive and endpoint.http_status != 403:
            self.notify(
                fields={'Alive endpoint': f'• {endpoint_str}'},
                add_meta_info=False)

        # Add the results
        line['_cmd'] = cmd
        line.update(result_data)
        results.append(line)

        if techs_str := ', '.join(
            [f'`{tech}`' for tech in result_data['techs']]
        ):
            self.notify(
                fields={'Technologies': techs_str},
                add_meta_info=False)

        # Notify about IPs
        if result_data['a_records']:
            ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in result_data['a_records']])
            self.notify(
                fields={'IPs': ips_str},
                add_meta_info=False)

        # Notify about host IP
        if result_data['host']:
            self.notify(
                fields={'IPs': f'• `{result_data["host"]}`'},
                add_meta_info=False)

        # Add endpoint ID to the list
        endpoint_ids.append(endpoint.id)

    # Remove duplicate endpoints if needed
    if should_remove_duplicate_endpoints and endpoint_ids:
        remove_duplicate_endpoints(
            self.scan_id,
            self.domain_id,
            self.subdomain_id,
            filter_ids=endpoint_ids
        )

    # Clean up input file
    if not remove_file_or_pattern(
        input_path,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    ):
        logger.error(f"🌐 Failed to clean up input file {input_path}")

    return results
