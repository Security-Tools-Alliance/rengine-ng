import base64

from pathlib import Path
from copy import deepcopy
from urllib.parse import urlparse
from django.utils import timezone

from reNgine.definitions import (
    AUTO_CALIBRATION,
    DEFAULT_DIR_FILE_FUZZ_EXTENSIONS,
    DIR_FILE_FUZZ,
    EXTENSIONS,
    FFUF_DEFAULT_FOLLOW_REDIRECT,
    FFUF_DEFAULT_MATCH_HTTP_STATUS,
    FFUF_DEFAULT_RECURSIVE_LEVEL,
    FFUF_DEFAULT_WORDLIST_NAME,
    FFUF_DEFAULT_WORDLIST_PATH,
    MATCH_HTTP_STATUS,
    MAX_TIME,
    RECURSIVE_LEVEL,
    STOP_ON_ERROR,
    WORDLIST,
)
from reNgine.settings import (
    CELERY_DEBUG,
)
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.utils.command_executor import stream_command
from reNgine.utils.http import (
    extract_path_from_url,
    get_subdomain_from_url,
)
from startScan.models import (
    DirectoryFile,
    DirectoryScan,
    Subdomain,
)
from reNgine.utils.command_builder import CommandBuilder
from reNgine.utils.task_config import TaskConfig

"""
Celery tasks.
"""

logger = Logger(is_task_logger=True)  # Use task logger for Celery tasks


@app.task(name='dir_file_fuzz', queue='io_queue', base=RengineTask, bind=True)
def dir_file_fuzz(self, ctx={}, description=None):
    """Perform directory scan, and currently uses `ffuf` as a default tool.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of URLs discovered.
    """
    from reNgine.tasks.http import http_crawl
    from reNgine.utils.db import get_http_urls, get_random_proxy, save_endpoint

    # Initialize the task configuration
    config = TaskConfig(self.yaml_configuration, self.results_dir, self.scan_id, self.filename)
    
    # Get the configurations
    fuzz_config = config.get_config(DIR_FILE_FUZZ)
    custom_header = config.prepare_custom_header(DIR_FILE_FUZZ)
    auto_calibration = config.get_value(DIR_FILE_FUZZ, AUTO_CALIBRATION, True)
    enable_http_crawl = config.get_http_crawl_enabled(DIR_FILE_FUZZ)
    rate_limit = config.get_rate_limit(DIR_FILE_FUZZ)
    extensions = fuzz_config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)
    extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
    extensions_str = ','.join(map(str, extensions))
    follow_redirect = config.get_follow_redirect(DIR_FILE_FUZZ, FFUF_DEFAULT_FOLLOW_REDIRECT)
    max_time = config.get_value(DIR_FILE_FUZZ, MAX_TIME, 0)
    match_http_status = fuzz_config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)
    mc = ','.join([str(c) for c in match_http_status])
    recursive_level = config.get_value(DIR_FILE_FUZZ, RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL)
    stop_on_error = config.get_value(DIR_FILE_FUZZ, STOP_ON_ERROR, False)
    timeout = config.get_timeout(DIR_FILE_FUZZ)
    threads = config.get_threads(DIR_FILE_FUZZ)
    wordlist_name = fuzz_config.get(WORDLIST, FFUF_DEFAULT_WORDLIST_NAME)
    delay = config.calculate_delay(rate_limit, threads)
    input_path = config.get_input_path('dir_file_fuzz')

    # Get wordlist
    wordlist_name = FFUF_DEFAULT_WORDLIST_NAME if wordlist_name == 'default' else wordlist_name
    wordlist_path = str(Path(FFUF_DEFAULT_WORDLIST_PATH) / f'{wordlist_name}.txt')

    # Build command
    cmd_builder = CommandBuilder('ffuf')
    cmd_builder.add_option('-w', wordlist_path)
    cmd_builder.add_option('-e', extensions_str, condition=bool(extensions))
    cmd_builder.add_option('-maxtime', max_time, condition=max_time > 0)
    cmd_builder.add_option('-p', delay, condition=delay > 0)
    if recursive_level > 0:
        cmd_builder.add_option('-recursion')
        cmd_builder.add_option('-recursion-depth', recursive_level)
    cmd_builder.add_option('-t', threads, condition=threads and threads > 0)
    cmd_builder.add_option('-timeout', timeout, condition=timeout and timeout > 0)
    cmd_builder.add_option('-se', condition=stop_on_error)
    cmd_builder.add_option('-fr', condition=follow_redirect)
    cmd_builder.add_option('-ac', condition=auto_calibration)
    cmd_builder.add_option('-mc', mc, condition=bool(mc))
    cmd_builder.add_option(custom_header, condition=bool(custom_header))

    # Grab URLs to fuzz
    urls = get_http_urls(
        is_alive=True,
        ignore_files=False,
        write_filepath=input_path,
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
        url_parse = urlparse(url)
        url = f'{url_parse.scheme}://{url_parse.netloc}'
        url += '/FUZZ' # TODO: fuzz not only URL but also POST / PUT / headers
        proxy = get_random_proxy()

        # Build final cmd
        cmd_builder.add_option('-u', url, condition=bool(url))
        cmd_builder.add_option('-json')
        cmd_builder.add_option('-s')
        cmd_builder.add_option('-x', proxy, condition=bool(proxy))

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
        for line in stream_command(
                cmd_builder.build_list(),
                shell=False,
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id):

            # Empty line, continue to the next record
            if not isinstance(line, dict):
                continue

            # Append line to results
            results.append(line)

            # Retrieve FFUF output
            url = line['url']
            # Extract path and convert to base64 (need byte string encode & decode)
            name = base64.b64encode(extract_path_from_url(url).encode()).decode()
            length = line['length']
            status = line['status']
            words = line['words']
            lines = line['lines']
            content_type = line['content-type']
            duration = line['duration']

            # If name empty log error and continue
            if not name:
                logger.error(f'🔨 FUZZ not found for "{url}"')
                continue

            # Get or create endpoint from URL
            endpoint, created = save_endpoint(url, crawl=False, ctx=ctx, subdomain=subdomain)

            # Continue to next line if endpoint returned is None
            if endpoint is None:
                continue

            # Save endpoint data from FFUF output
            endpoint.http_status = status
            endpoint.content_length = length
            endpoint.response_time = duration / 1000000000
            endpoint.content_type = content_type
            endpoint.content_length = length
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
            if self.subscan:
                dirscan.dir_subscan_ids.add(self.subscan)

            # Save dirscan datas
            dirscan.save()

            # Add dirscan to subdomain
            subdomain.directories.add(dirscan)
            subdomain.save()

            crawl_urls.append(endpoint.http_url)

    # Crawl discovered URLs
    if enable_http_crawl:
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = False
        http_crawl.delay(crawl_urls, ctx=custom_ctx)

    if not Path(self.output_path).exists():
        logger.error(f'❌ FFUF results file missing : {self.output_path}')
        return []

    return results
