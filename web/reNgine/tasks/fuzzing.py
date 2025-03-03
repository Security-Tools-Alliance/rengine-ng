from pathlib import Path
from copy import deepcopy
from urllib.parse import urlparse
from django.utils import timezone

from reNgine.definitions import DIR_FILE_FUZZ
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.command_executor import stream_command
from reNgine.utils.logger import Logger
from reNgine.utils.http import get_subdomain_from_url, prepare_urls_with_fallback
from startScan.models import DirectoryScan, Subdomain
from reNgine.utils.command_builder import build_ffuf_cmd
from reNgine.utils.task_config import TaskConfig
from reNgine.utils.parsers import parse_ffuf_result

"""
Celery tasks.
"""

logger = Logger(is_task_logger=True)  # Use task logger for Celery tasks


@app.task(name='dir_file_fuzz', queue='io_queue', base=RengineTask, bind=True)
def dir_file_fuzz(self, ctx=None, description=None):
    """Perform directory scan, and currently uses `ffuf` as a default tool.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of URLs discovered.
    """
    if ctx is None:
        ctx = {}
    from reNgine.tasks.http import http_crawl

    # Initialize the task configuration
    config = TaskConfig(ctx, DIR_FILE_FUZZ)
    task_config = config.get_task_config()

    # Build command
    base_cmd_builder = build_ffuf_cmd(config)

    # Grab URLs to fuzz
    urls = prepare_urls_with_fallback(
        is_alive=True,
        ignore_files=False,
        write_filepath=task_config['input_path'],
        get_only_default_urls=True,
        ctx=ctx
    )

    subdomain = None
    if ctx.get('subdomain_id') and ctx['subdomain_id'] > 0:
        subdomain = Subdomain.objects.get(id=ctx['subdomain_id'])

    # Loop through URLs and run command
    results = []
    crawl_urls = []
    for url in urls:
        '''
            Above while fetching urls, we are not ignoring files, because some
            default urls may redirect to https://example.com/login.php
            so, ignore_files is set to False
            but, during fuzzing, we will only need part of the path, in above example
            it is still a good idea to ffuf base url https://example.com
            so files from base url
        '''
        cmd_builder = deepcopy(base_cmd_builder)
        url_parse = urlparse(url)
        url = f'{url_parse.scheme}://{url_parse.netloc}'
        url += '/FUZZ' # TODO: fuzz not only URL but also POST / PUT / headers

        # Build final cmd
        cmd_builder.add_option('-u', url, condition=bool(url))

        # Initialize DirectoryScan object
        dirscan = DirectoryScan()
        dirscan.scanned_date = timezone.now()
        dirscan.command_line = cmd_builder.build_list()
        dirscan.save()

        # Get subdomain
        if not subdomain:
            subdomain_name = get_subdomain_from_url(url)
            subdomain = Subdomain.objects.get(name=subdomain_name, scan_history=self.scan)

        # Loop through results and populate EndPoint and DirectoryFile in DB
        for line in stream_command(cmd_builder.build_list(), shell=False, history_file=self.history_file, scan_id=self.scan_id, activity_id=self.activity_id):

            # Parse FFUF result
            parsed_result = parse_ffuf_result(line, ctx)

            # Skip if parsing failed
            if not parsed_result:
                continue

            # Append raw line to results
            results.append(line)

            # Process the result
            if not process_ffuf_result(
                parsed_result, 
                subdomain, 
                dirscan, 
                ctx, 
                crawl_urls, 
                subscan=self.subscan
            ):
                logger.error(f'❌ Failed to process FFUF result: {line}')

    # Crawl discovered URLs
    if task_config['enable_http_crawl']:
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        http_crawl.delay(crawl_urls, ctx=custom_ctx)

    if not Path(self.output_path).exists():
        logger.error(f'❌ FFUF results file missing : {self.output_path}')
        return []

    return results

def process_ffuf_result(parsed_result, subdomain, dirscan, ctx, crawl_urls, subscan=None):
    """Process a parsed FFUF result and save to database
    
    Args:
        parsed_result (dict): Parsed FFUF result
        subdomain (Subdomain): The subdomain object
        dirscan (DirectoryScan): The directory scan object
        ctx (dict): Context information
        crawl_urls (list): List to append URLs for crawling
        subscan: Optional subscan object
        
    Returns:
        bool: True if processing succeeded, False otherwise
    """
    from startScan.models import DirectoryFile
    from reNgine.utils.db import save_endpoint
    from reNgine.definitions import CELERY_DEBUG
    
    # Extract parsed data
    url = parsed_result['url']
    name = parsed_result['name']
    length = parsed_result['length']
    status = parsed_result['status']
    words = parsed_result['words']
    lines = parsed_result['lines']
    content_type = parsed_result['content_type']
    response_time = parsed_result['response_time']
    
    # If name empty log error and return failure
    if not name:
        logger.error(f'🔨 FUZZ not found for "{url}"')
        return False

    # Get or create endpoint from URL
    endpoint, created = save_endpoint(url, crawl=False, ctx=ctx, subdomain=subdomain)
    
    # Return failure if endpoint returned is None
    if endpoint is None:
        return False
    
    # Save endpoint data
    endpoint.http_status = status
    endpoint.content_length = length
    endpoint.response_time = response_time
    endpoint.content_type = content_type
    endpoint.save()

    # Save directory file output from FFUF output
    dfile, created = DirectoryFile.objects.get_or_create(
        name=name,
        length=length,
        words=words,
        lines=lines,
        content_type=content_type,
        url=url,
        http_status=status)

    # Log newly created file or directory if debug activated
    if created and CELERY_DEBUG:
        logger.warning(f'🔨 Found new directory or file {url}')

    # Add file to current dirscan
    dirscan.directory_files.add(dfile)

    # Add subscan relation to dirscan if exists
    if subscan:
        dirscan.dir_subscan_ids.add(subscan)

    # Save dirscan datas
    dirscan.save()

    # Add dirscan to subdomain
    subdomain.directories.add(dirscan)
    subdomain.save()

    crawl_urls.append(endpoint.http_url)
    return True
