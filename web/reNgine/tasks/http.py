from reNgine.definitions import (
    HTTP_CRAWL,
    THREADS,
    CUSTOM_HEADER,
    FOLLOW_REDIRECT,
)
from reNgine.settings import (
    DEFAULT_THREADS,
)
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.utils.formatters import (
    generate_header_param
)
from reNgine.utils.command_executor import (
    stream_command
)
from reNgine.utils.http import (
    extract_httpx_url,
    get_subdomain_from_url,
)
from reNgine.utils.ip import save_ip_address
from reNgine.utils.utils import (
    remove_file_or_pattern,
    is_iterable,
)
from startScan.models import (
    Subdomain,
)
from reNgine.tasks.url import remove_duplicate_endpoints

logger = Logger(True)
@app.task(name='http_crawl', queue='http_crawl_queue', base=RengineTask, bind=True)
def http_crawl(self, urls=None, method=None, recrawl=False, ctx=None, track=True, description=None, update_subdomain_metadatas=False, should_remove_duplicate_endpoints=True, duplicate_removal_fields=None):
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
        get_http_urls,
        get_random_proxy,
        save_endpoint,
        save_subdomain,
        save_subdomain_metadata,
        save_technologies
    )


    if ctx is None:
        ctx = {}
    if duplicate_removal_fields is None:
        duplicate_removal_fields = []
    logger.info('Initiating HTTP Crawl')

    # Initialize urls as empty list if None
    if urls is None:
        urls = []

    config = self.yaml_configuration.get(HTTP_CRAWL) or {}
    custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    if custom_header:
        custom_header = generate_header_param(custom_header, 'common')
    threads = config.get(THREADS, DEFAULT_THREADS)
    follow_redirect = config.get(FOLLOW_REDIRECT, False)
    self.output_path = None
    input_path = f'{self.results_dir}/httpx_input.txt'
    history_file = f'{self.results_dir}/commands.txt'
    if urls and is_iterable(urls):
        if self.url_filter:
            urls = [u for u in urls if self.url_filter in u]
        urls = [url for url in urls if url is not None]
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        # No url provided, so it's a subscan launched from subdomain list
        update_subdomain_metadatas = True
        all_urls = []

        # Append the base subdomain to get subdomain info if task is launched directly from subscan
        subdomain_id = ctx.get('subdomain_id')
        if subdomain_id:
            subdomain = Subdomain.objects.filter(id=ctx.get('subdomain_id')).first()
            all_urls.append(subdomain.name)

        # Get subdomain endpoints to crawl the entire list
        http_urls = get_http_urls(
            is_uncrawled=not recrawl,
            write_filepath=input_path,
            ctx=ctx
        )
        if not http_urls:
            logger.error('No URLs to crawl. Skipping.')
            return

        all_urls.extend(http_urls)

        urls = all_urls

        logger.debug(urls)

    # If no URLs found, skip it
    if not urls:
        return

    # Re-adjust thread number if few URLs to avoid spinning up a monster to
    # kill a fly.
    if len(urls) < threads:
        threads = len(urls)

    # Get random proxy
    proxy = get_random_proxy()

    cmd = (
        'httpx'
        + ' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent'
    )
    cmd += f' -t {threads}' if threads > 0 else ''
    cmd += f' --http-proxy {proxy}' if proxy else ''
    cmd += f' {custom_header}' if custom_header else ''
    cmd += ' -json'
    cmd += f' -u {urls[0]}' if len(urls) == 1 else f' -l {input_path}'
    cmd += f' -x {method}' if method else ''
    cmd += ' -silent'
    if follow_redirect:
        cmd += ' -fr'
    results = []
    endpoint_ids = []
    for line in stream_command(
            cmd,
            history_file=history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id):

        if not line or not isinstance(line, dict):
            continue

        # Check if the http request has an error
        if 'error' in line:
            logger.error(line)
            continue

        # No response from endpoint
        if line.get('failed', False):
            continue

        # Parse httpx output
        host = line.get('host', '')
        content_length = line.get('content_length', 0)
        http_status = line.get('status_code')
        http_url, is_redirect = extract_httpx_url(line, follow_redirect)
        page_title = line.get('title')
        webserver = line.get('webserver')
        cdn = line.get('cdn', False)
        rt = line.get('time')
        techs = line.get('tech', [])
        #cname = line.get('cname', '')
        content_type = line.get('content_type', '')
        response_time = -1
        if rt:
            response_time = float(''.join(ch for ch in rt if not ch.isalpha()))
            if rt[-2:] == 'ms':
                response_time /= 1000

        # Create/get Subdomain object in DB
        subdomain_name = get_subdomain_from_url(http_url)
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        if not isinstance(subdomain, Subdomain):
            logger.error(f"Invalid subdomain encountered: {subdomain}")
            continue

        # Save default HTTP URL to endpoint object in DB
        endpoint, created = save_endpoint(
            http_url,
            crawl=False,
            ctx=ctx,
            subdomain=subdomain,
            is_default=update_subdomain_metadatas
        )
        if not endpoint:
            continue
        endpoint.http_status = http_status
        endpoint.page_title = page_title
        endpoint.content_length = content_length
        endpoint.webserver = webserver
        endpoint.response_time = response_time
        endpoint.content_type = content_type
        endpoint.save()
        endpoint_str = f'{http_url} [{http_status}] `{content_length}B` `{webserver}` `{rt}`'
        logger.warning(endpoint_str)
        if endpoint and endpoint.is_alive and endpoint.http_status != 403:
            self.notify(
                fields={'Alive endpoint': f'• {endpoint_str}'},
                add_meta_info=False)

        # Add endpoint to results
        line['_cmd'] = cmd
        line['final_url'] = http_url
        line['endpoint_id'] = endpoint.id
        line['endpoint_created'] = created
        line['is_redirect'] = is_redirect
        results.append(line)

        # Add technology objects to DB
        save_technologies(techs, endpoint)
        techs_str = ', '.join([f'`{tech}`' for tech in techs])
        self.notify(
            fields={'Technologies': techs_str},
            add_meta_info=False)

        # Add IP objects for 'a' records to DB
        a_records = line.get('a', [])
        for ip_address in a_records:
            ip, created = save_ip_address(
                ip_address,
                subdomain,
                subscan=self.subscan,
                cdn=cdn)
        ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in a_records])
        self.notify(
            fields={'IPs': ips_str},
            add_meta_info=False)

        # Add IP object for host in DB
        if host:
            ip, created = save_ip_address(
                host,
                subdomain,
                subscan=self.subscan,
                cdn=cdn)
            self.notify(
                fields={'IPs': f'• `{ip.address}`'},
                add_meta_info=False)

        # Save subdomain metadatas
        if update_subdomain_metadatas:
            save_subdomain_metadata(subdomain, endpoint, line)

        endpoint_ids.append(endpoint.id)

    if should_remove_duplicate_endpoints:
        # Remove 'fake' alive endpoints that are just redirects to the same page
        remove_duplicate_endpoints(
            self.scan_id,
            self.domain_id,
            self.subdomain_id,
            filter_ids=endpoint_ids
        )

    # Remove input file
    if not remove_file_or_pattern(
        input_path,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    ):
        logger.error(f"Failed to clean up input file {input_path}")

    return results
