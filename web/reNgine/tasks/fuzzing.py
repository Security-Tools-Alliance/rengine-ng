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
    RATE_LIMIT,
    RECURSIVE_LEVEL,
    STOP_ON_ERROR,
    THREADS,
    TIMEOUT,
    CUSTOM_HEADER,
    FOLLOW_REDIRECT,
    WORDLIST,
)
from reNgine.settings import (
    CELERY_DEBUG,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RATE_LIMIT,
    DEFAULT_THREADS,
)
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.utils.formatters import generate_header_param
from reNgine.utils.command_executor import stream_command
from reNgine.utils.http import (
    extract_path_from_url,
    get_http_crawl_value,
    get_subdomain_from_url,
)
from startScan.models import (
    DirectoryFile,
    DirectoryScan,
    Subdomain,
)

"""
Celery tasks.
"""

logger = Logger(is_task_logger=True)  # Use task logger for Celery tasks


@app.task(name='dir_file_fuzz', queue='dir_fuzzing_queue', base=RengineTask, bind=True)
def dir_file_fuzz(self, ctx={}, description=None):
    """Perform directory scan, and currently uses `ffuf` as a default tool.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of URLs discovered.
    """
    from reNgine.tasks.http import http_crawl
    from reNgine.utils.db import get_http_urls, get_random_proxy, save_endpoint

    # Config
    cmd = 'ffuf'
    config = self.yaml_configuration.get(DIR_FILE_FUZZ) or {}
    custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    if custom_header:
        custom_header = generate_header_param(custom_header,'common')
    auto_calibration = config.get(AUTO_CALIBRATION, True)
    enable_http_crawl = get_http_crawl_value(self, config)
    rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
    extensions = config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)
    extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
    extensions_str = ','.join(map(str, extensions))
    follow_redirect = config.get(FOLLOW_REDIRECT, FFUF_DEFAULT_FOLLOW_REDIRECT)
    max_time = config.get(MAX_TIME, 0)
    match_http_status = config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)
    mc = ','.join([str(c) for c in match_http_status])
    recursive_level = config.get(RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL)
    stop_on_error = config.get(STOP_ON_ERROR, False)
    timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    wordlist_name = config.get(WORDLIST, FFUF_DEFAULT_WORDLIST_NAME)
    delay = rate_limit / (threads * 100) # calculate request pause delay from rate_limit and number of threads
    input_path = str(Path(self.results_dir) / 'input_dir_file_fuzz.txt')

    # Get wordlist
    wordlist_name = FFUF_DEFAULT_WORDLIST_NAME if wordlist_name == 'default' else wordlist_name
    wordlist_path = str(Path(FFUF_DEFAULT_WORDLIST_PATH) / f'{wordlist_name}.txt')

    # Build command
    cmd += f' -w {wordlist_path}'
    cmd += f' -e {extensions_str}' if extensions else ''
    cmd += f' -maxtime {max_time}' if max_time > 0 else ''
    cmd += f' -p {delay}' if delay > 0 else ''
    cmd += f' -recursion -recursion-depth {recursive_level} ' if recursive_level > 0 else ''
    cmd += f' -t {threads}' if threads and threads > 0 else ''
    cmd += f' -timeout {timeout}' if timeout and timeout > 0 else ''
    cmd += ' -se' if stop_on_error else ''
    cmd += ' -fr' if follow_redirect else ''
    cmd += ' -ac' if auto_calibration else ''
    cmd += f' -mc {mc}' if mc else ''
    cmd += f' {custom_header}' if custom_header else ''

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
        fcmd = cmd
        fcmd += f' -x {proxy}' if proxy else ''
        fcmd += f' -u {url} -json -s'

        # Initialize DirectoryScan object
        dirscan = DirectoryScan()
        dirscan.scanned_date = timezone.now()
        dirscan.command_line = fcmd
        dirscan.save()

        # Get subdomain
        if not subdomain:
            subdomain_name = get_subdomain_from_url(url)
            subdomain = Subdomain.objects.get(name=subdomain_name, scan_history=self.scan)

        # Loop through results and populate EndPoint and DirectoryFile in DB
        results = []
        crawl_urls = []
        for line in stream_command(
                fcmd,
                shell=True,
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
                logger.error(f'FUZZ not found for "{url}"')
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
                logger.warning(f'Found new directory or file {url}')

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
        http_crawl(crawl_urls, ctx=custom_ctx)

    return results
