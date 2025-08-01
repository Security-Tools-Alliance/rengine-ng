import json
from datetime import datetime

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    HTTP_CRAWL,
    CUSTOM_HEADER,
    HTTP_PRE_CRAWL_ALL_PORTS,
    HTTP_PRE_CRAWL_BATCH_SIZE,
    HTTP_PRE_CRAWL_UNCOMMON_PORTS,
    THREADS,
    FOLLOW_REDIRECT,
    COMMON_WEB_PORTS,
)
from reNgine.settings import DEFAULT_THREADS
from reNgine.tasks.command import stream_command
from reNgine.utilities.endpoint import get_http_urls, smart_http_crawl_if_needed
from reNgine.utilities.url import get_subdomain_from_url, extract_httpx_url, add_port_urls_to_crawl
from reNgine.utilities.dns import resolve_subdomain_ips
from reNgine.utilities.engine import get_crawl_config_safe
from reNgine.utilities.command import generate_header_param
from reNgine.utilities.proxy import get_random_proxy
from reNgine.utilities.data import is_iterable
from reNgine.utilities.port import get_or_create_port
from reNgine.utilities.database import (
    save_subdomain,
    save_endpoint,
    save_ip_address,
    save_subdomain_metadata,
)
from reNgine.utilities.file import remove_file_or_pattern
from startScan.models import (
    Subdomain,
    Technology,
    EndPoint,
)

logger = get_task_logger(__name__)


@app.task(name='http_crawl', queue='io_queue', base=RengineTask, bind=True)
def http_crawl(
        self,
        urls=None,  # Changed from urls=[]
        method=None,
        recrawl=False,
        ctx={},
        track=True,
        description=None,
        update_subdomain_metadatas=False,
        is_default=False,
        should_remove_duplicate_endpoints=True,
        duplicate_removal_fields=[]):
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
    logger.info('Initiating HTTP Crawl')

    # Initialize urls as empty list if None
    if urls is None:
        urls = []

    # Config - use safe crawl config getter with fallback to defaults
    config = get_crawl_config_safe(self, HTTP_CRAWL)

    # Get custom header safely from config or global configuration
    custom_header = config.get(CUSTOM_HEADER)
    if not custom_header:
        try:
            yaml_config = self.yaml_configuration
            if isinstance(yaml_config, str):
                import yaml
                yaml_config = yaml.safe_load(yaml_config)
            if isinstance(yaml_config, dict):
                custom_header = yaml_config.get(CUSTOM_HEADER)
        except Exception as e:
            logger.exception("Failed to extract custom header from YAML configuration")
            custom_header = None
    if custom_header:
        custom_header = generate_header_param(custom_header, 'common')
    threads = config.get(THREADS, DEFAULT_THREADS)
    follow_redirect = config.get(FOLLOW_REDIRECT, False)
    self.output_path = None
    input_path = f'{self.results_dir}/httpx_input.txt'
    history_file = f'{self.results_dir}/commands.txt'
    if urls and is_iterable(urls) and any(url for url in urls if url):
        if self.url_filter:
            urls = [u for u in urls if self.url_filter in u]
        urls = [url for url in urls if url is not None]
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        # No url provided, so it's a subscan launched from subdomain list
        update_subdomain_metadatas = True
        is_default = True  # When scanning directly from subdomain, endpoints are default
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

    # Run command
    cmd = 'httpx'
    cmd += ' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent -nfs'
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
            logger.error("No line found")
            continue

        # Check if the http request has an error
        if 'error' in line:
            logger.error(line)
            continue

        line_str = json.dumps(line, indent=2)
        logger.debug(line_str)

        # No response from endpoint
        if line.get('failed', False):
            logger.error("Failed to crawl endpoint")
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
        cname = line.get('cname', '')
        content_type = line.get('content_type', '')
        response_time = -1
        port_number = line.get('port')
        host_ip = line.get('ip')
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
            http_url=http_url,
            http_status=http_status,
            ctx=ctx,
            subdomain=subdomain,
            is_default=is_default
        )
        if not endpoint:
            continue
        logger.info(f'Updating endpoint datas: {endpoint}')
        # Update endpoint object
        endpoint.discovered_date = datetime.now()
        endpoint.http_status = http_status
        endpoint.http_url = http_url
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

        # If endpoint is alive (http_status > 0), record the port in the database
        if http_status and http_status > 0 and port_number:
            port_number = int(port_number) if isinstance(port_number, str) else port_number
            logger.info(f'Endpoint {http_url} is alive (status {http_status}), recording port {port_number}')

            # Get all IPs associated with this subdomain and record the port
            subdomain_ips = subdomain.ip_addresses.all()
            for ip in subdomain_ips:
                get_or_create_port(
                    ip_address=ip,
                    port_number=port_number,
                    service_info={
                        'service_name': 'web',
                        'service_product': webserver or 'unknown'
                    }
                )
                logger.debug(f'Recorded port {port_number} for IP {ip.address}')

            # Also record the port for the host IP if provided by httpx
            if host and host != subdomain_name:
                # Get or create IP for the host
                host_ip, _ = save_ip_address(host, subdomain, subscan=self.subscan)
                if host_ip:
                    get_or_create_port(
                        ip_address=host_ip,
                        port_number=port_number,
                        service_info={
                            'service_name': 'web',
                            'service_product': webserver or 'unknown'
                        }
                    )
                    logger.debug(f'Recorded port {port_number} for host IP {host_ip.address}')

        # Add endpoint to results
        line['_cmd'] = cmd
        line['final_url'] = http_url
        line['endpoint_id'] = endpoint.id
        line['endpoint_created'] = created
        line['is_redirect'] = is_redirect
        results.append(line)

        # Add technology objects to DB
        for technology in techs:
            tech, _ = Technology.objects.get_or_create(name=technology)
            endpoint.techs.add(tech)
            endpoint.save()
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

    # Check if httpx returned any lines
    if not results:
        logger.warning(f"httpx returned no lines for command: {cmd}")
        logger.warning(f"URLs processed: {urls}")
        if len(urls) > 1:
            logger.error(f"Input file path: {input_path}")

    if should_remove_duplicate_endpoints:
        from reNgine.tasks.url import remove_duplicate_endpoints
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


@app.task(name='pre_crawl', queue='cpu_queue', base=RengineTask, bind=True)
def pre_crawl(self, ctx={}, description=None):
    """
    Pre-crawl existing subdomains to ensure endpoints are alive
    before heavy tasks like nuclei, screenshot, waf_detection, etc. starts
    Also handles initial web service detection if no endpoints exist.
    """
    logger.info('Starting pre-crawl phase')

    domain_id = ctx.get('domain_id')

    # Get configuration for pre-crawl limits - use safe config getter
    config = get_crawl_config_safe(self, HTTP_CRAWL)
    precrawl_batch_size = config.get('precrawl_batch_size', HTTP_PRE_CRAWL_BATCH_SIZE)
    precrawl_ports = config.get('precrawl_ports', COMMON_WEB_PORTS)
    precrawl_uncommon_ports = config.get('precrawl_uncommon_ports', HTTP_PRE_CRAWL_UNCOMMON_PORTS)
    precrawl_all_ports = config.get('precrawl_all_ports', HTTP_PRE_CRAWL_ALL_PORTS)

    # Get existing subdomains from current scan
    existing_subdomains = Subdomain.objects.filter(
        target_domain_id=domain_id,
        scan_history_id=ctx.get('scan_history_id')
    )

    total_subdomains = existing_subdomains.count()
    logger.info(f'Found {total_subdomains} existing subdomains')

    # Get URLs to crawl (both existing and newly created)
    urls_to_crawl = []
    additional_urls_to_test = []
    total_ips_resolved = 0
    all_discovered_ips = set()  # Collect all discovered IPs

    for subdomain in existing_subdomains:
        # First, resolve DNS for this subdomain to discover IPs
        ips_discovered = resolve_subdomain_ips(subdomain.name)
        total_ips_resolved += len(ips_discovered)
        all_discovered_ips.update(ips_discovered)  # Add to collection
        
        for ip_address in ips_discovered:
            # Save IP to database and associate with subdomain
            ip_obj, ip_created = save_ip_address(ip_address, subdomain)
            if ip_created:
                logger.info(f'DNS resolved new IP {ip_address} for subdomain {subdomain.name}')
            else:
                logger.debug(f'IP {ip_address} already known for subdomain {subdomain.name}')
        
        # Get endpoints for this subdomain that need crawling
        subdomain_endpoints = get_http_urls(is_uncrawled=True, ctx={'subdomain_id': subdomain.id})
        urls_to_crawl.extend(subdomain_endpoints)

        # Check if there's only one endpoint and it's the default one
        if len(subdomain_endpoints) == 1 and EndPoint.objects.filter(
                        subdomain=subdomain,
                        is_default=True
                    ).first():
            
            # Use function to add port URLs for testing
            add_port_urls_to_crawl(
                subdomain.name, 
                urls_to_crawl, 
                additional_urls_to_test, 
                precrawl_ports, 
                precrawl_all_ports, 
                precrawl_uncommon_ports, 
                entity_type="subdomain"
            )

    # Now process all discovered IPs (outside the subdomain loop)
    if all_discovered_ips:
        logger.info(f'Processing {len(all_discovered_ips)} discovered IPs for endpoint creation and port testing')
                             
        # Create endpoints and test ports for each discovered IP
        for ip_address in all_discovered_ips:
            # Create a subdomain entry for the IP itself (for endpoint association)
            ip_subdomain, ip_subdomain_created = save_subdomain(ip_address, ctx=ctx)
            if ip_subdomain_created:
                logger.info(f'Created subdomain entry for IP: {ip_address}')
            
            # Create basic HTTP endpoint
            url = f'http://{ip_address}'
            if url not in urls_to_crawl:
                # Create basic endpoint for this IP
                endpoint, endpoint_created = save_endpoint(
                    http_url=url,
                    ctx=ctx,
                    subdomain=ip_subdomain,
                    is_default=True
                )
                if endpoint:
                    urls_to_crawl.append(url)
                    additional_urls_to_test.append(url)
                    logger.debug(f'Created basic endpoint for IP: {url}')
            
            # Also test ports on this IP like we do for subdomains
            add_port_urls_to_crawl(
                ip_address, 
                urls_to_crawl, 
                additional_urls_to_test, 
                precrawl_ports, 
                precrawl_all_ports, 
                precrawl_uncommon_ports, 
                entity_type="IP"
            )

    if additional_urls_to_test:
        logger.info(f'Added {len(additional_urls_to_test)} additional URLs to test on configured ports')

    if urls_to_crawl:
        logger.info(f'Pre-crawling {len(urls_to_crawl)} URLs (batch size: {precrawl_batch_size})')

        # Count alive endpoints before pre-crawl
        alive_before = len(get_http_urls(is_alive=True, ctx=ctx))

        # Process in batches to avoid overwhelming the system
        for i in range(0, len(urls_to_crawl), precrawl_batch_size):
            batch = urls_to_crawl[i:i+precrawl_batch_size]
            logger.info(f'Processing batch {i//precrawl_batch_size + 1}: {len(batch)} URLs')

            # Calculate dynamic max_wait_time based on batch size (5 seconds per URL)
            dynamic_max_wait_time = len(batch) * 5

            # Use smart crawl with completion wait
            smart_http_crawl_if_needed(
                batch,
                ctx,
                wait_for_completion=True,
                max_wait_time=dynamic_max_wait_time,
                is_default=True,
                update_subdomain_metadatas=True
            )

        # Log results
        alive_count = len(get_http_urls(is_alive=True, ctx=ctx))
        new_alive = alive_count - alive_before
        logger.info(f'Pre-crawl completed. {new_alive} new alive endpoints discovered (total: {alive_count})')
        logger.info(f'Processed {total_subdomains} subdomains and {total_ips_resolved} discovered IPs')
    else:
        alive_count = 0
        logger.info('No URLs to pre-crawl')
        logger.info(f'Found {total_subdomains} subdomains and {total_ips_resolved} discovered IPs (no endpoints to test)')

    return {
        'urls_crawled': len(urls_to_crawl), 
        'alive_endpoints': alive_count,
        'total_subdomains': total_subdomains,
        'total_ips': total_ips_resolved,
        'additional_urls_tested': len(additional_urls_to_test),
    }


@app.task(name='intermediate_crawl', queue='cpu_queue', base=RengineTask, bind=True)
def intermediate_crawl(self, ctx={}, description=None):
    """
    Intermediate crawl phase - crawl newly discovered endpoints after fetch_url
    """
    logger.info('Starting intermediate crawl phase')
    
    # Get all uncrawled endpoints
    uncrawled_endpoints = get_http_urls(is_uncrawled=True, ctx=ctx)
    
    if not uncrawled_endpoints:
        logger.info('No uncrawled endpoints found for intermediate crawl')
        return {'urls_crawled': 0, 'alive_endpoints': 0}
    
    # Get batch size from configuration - use safe config getter
    config = get_crawl_config_safe(self, HTTP_CRAWL)
    batch_size = config.get('precrawl_batch_size', HTTP_PRE_CRAWL_BATCH_SIZE)
    
    logger.info(f'Intermediate crawling {len(uncrawled_endpoints)} URLs (batch size: {batch_size})')
    
    # Process in batches
    for i in range(0, len(uncrawled_endpoints), batch_size):
        batch = uncrawled_endpoints[i:i+batch_size]
        logger.info(f'Processing intermediate crawl batch {i//batch_size + 1}: {len(batch)} URLs')
        
        # Calculate dynamic max_wait_time based on batch size (5 seconds per URL)
        dynamic_max_wait_time = len(batch) * 5
        
        # Use smart crawl with completion wait
        smart_http_crawl_if_needed(
            batch,
            ctx,
            wait_for_completion=True,
            max_wait_time=dynamic_max_wait_time,
            is_default=False,
            update_subdomain_metadatas=False
        )
    
    # Log results
    alive_count = len(get_http_urls(is_alive=True, ctx=ctx))
    logger.info(f'Intermediate crawl completed. {alive_count} alive endpoints available.')
    
    return {
        'urls_crawled': len(uncrawled_endpoints),
        'alive_endpoints': alive_count
    }


@app.task(name='post_crawl', queue='cpu_queue', base=RengineTask, bind=True)
def post_crawl(self, ctx={}, description=None):
    """
    Post-crawl phase - final verification and cleanup of endpoints
    """
    logger.info('Starting post-crawl verification phase')
    
    # Check for any remaining uncrawled endpoints and crawl them
    logger.info(f'Getting uncrawled endpoints for post-crawl')
    uncrawled_endpoints = get_http_urls(is_uncrawled=True, ctx=ctx)
    
    if uncrawled_endpoints:
        logger.info(f'Found {len(uncrawled_endpoints)} uncrawled endpoints, performing final crawl')
        
        # Final crawl with smaller batch size for reliability
        batch_size = min(20, len(uncrawled_endpoints))
        
        for i in range(0, len(uncrawled_endpoints), batch_size):
            batch = uncrawled_endpoints[i:i+batch_size]
            logger.info(f'Final crawl batch {i//batch_size + 1}: {len(batch)} URLs')
            
            # Calculate dynamic max_wait_time based on batch size (5 seconds per URL)
            dynamic_max_wait_time = len(batch) * 5
            
            smart_http_crawl_if_needed(
                batch,
                ctx,
                wait_for_completion=True,
                max_wait_time=dynamic_max_wait_time,
                is_default=False,
                update_subdomain_metadatas=False
            )
    
    # Final statistics
    logger.info(f'Getting endpoints statistics')
    final_alive_count = len(get_http_urls(is_alive=True, ctx=ctx))
    final_total_count = len(get_http_urls(ctx=ctx))
    
    logger.info(f'Post-crawl completed. Final stats: {final_alive_count} alive endpoints out of {final_total_count} total')
    
    return {
        'total_endpoints': final_total_count,
        'alive_endpoints': final_alive_count,
        'uncrawled_processed': len(uncrawled_endpoints)
    }