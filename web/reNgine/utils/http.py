import contextlib
import re
import validators
import tldextract
import yaml

from urllib.parse import urlparse
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

from reNgine.utils.logger import Logger
from reNgine.definitions import ENABLE_HTTP_CRAWL
from reNgine.settings import DEFAULT_ENABLE_HTTP_CRAWL

logger = Logger(True)

def get_subdomain_from_url(url):
    """Get subdomain from HTTP URL.

    Args:
        url (str): HTTP URL.

    Returns:
        str: Subdomain name.
    """
        # Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
    if "://" not in url:
        url = f"http://{url}"

    url_obj = urlparse(url.strip())
    return url_obj.netloc.split(':')[0]

def is_valid_domain_or_subdomain(domain):
    try:
        URLValidator(schemes=['http', 'https'])(f'http://{domain}')
        return True
    except ValidationError:
        return False

def get_domain_from_subdomain(subdomain):
    """Get domain from subdomain.

    Args:
        subdomain (str): Subdomain name.

    Returns:
        str: Domain name.
    """

    if not is_valid_domain_or_subdomain(subdomain):
        return None

    # Use tldextract to parse the subdomain
    extracted = tldextract.extract(subdomain)

    # if tldextract recognized the tld then its the final result
    if extracted.suffix:
        domain = f"{extracted.domain}.{extracted.suffix}"
    else:
        # Fallback method for unknown TLDs, like .clouds or .local etc
        parts = subdomain.split('.')
        if len(parts) >= 2:
            domain = '.'.join(parts[-2:])
        else:
            return None

    # Validate the domain before returning
    return domain if is_valid_domain_or_subdomain(subdomain) else None

def sanitize_url(http_url):
    """Removes HTTP ports 80 and 443 from HTTP URL because it's ugly.

    Args:
        http_url (str): Input HTTP URL.

    Returns:
        str: Stripped HTTP URL.
    """
        # Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
    if "://" not in http_url:
        http_url = f"http://{http_url}"
    url = urlparse(http_url)

    if url.netloc.endswith(':80'):
        url = url._replace(netloc=url.netloc.replace(':80', ''))
    elif url.netloc.endswith(':443'):
        url = url._replace(scheme=url.scheme.replace('http', 'https'))
        url = url._replace(netloc=url.netloc.replace(':443', ''))
    return url.geturl().rstrip('/')

def extract_path_from_url(url):
    parsed_url = urlparse(url)

    # Reconstruct the URL without scheme and netloc
    reconstructed_url = parsed_url.path

    if reconstructed_url.startswith('/'):
        reconstructed_url = reconstructed_url[1:]  # Remove the first slash

    if parsed_url.params:
        reconstructed_url += f';{parsed_url.params}'
    if parsed_url.query:
        reconstructed_url += f'?{parsed_url.query}'
    if parsed_url.fragment:
        reconstructed_url += f'#{parsed_url.fragment}'

    return reconstructed_url

def is_valid_url(url):
    """Check if a URL is valid, including both full URLs and domain:port format.
    
    Args:
        url (str): URL to validate (https://domain.com or domain.com:port)
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    logger.debug(f'🌐 Validating URL: {url}')
    
    # Handle URLs with scheme (http://, https://)
    if url.startswith(('http://', 'https://')):
        return validators.url(url)
    
    # Handle domain:port format
    try:
        if ':' in url:
            domain, port = url.rsplit(':', 1)
            # Validate port
            port = int(port)
            if not 1 <= port <= 65535:
                logger.debug(f'🌐 Invalid port number: {port}')
                return False
        else:
            domain = url
            
        # Validate domain
        if validators.domain(domain) or validators.ipv4(domain) or validators.ipv6(domain):
            logger.debug(f'🌐 Valid domain/IP found: {domain}')
            return True
            
        logger.debug(f'🌐 Invalid domain/IP: {domain}')
        return False
        
    except (ValueError, ValidationError) as e:
        logger.debug(f'🌐 Validation error: {str(e)}')
        return False

def process_httpx_response(line):
    """TODO: implement this"""


def extract_httpx_url(line, follow_redirect):
    """Extract final URL from httpx results.

    Args:
        line (dict): URL data output by httpx.

    Returns:
        tuple: (final_url, redirect_bool) tuple.
    """
    status_code = line.get('status_code', 0)
    final_url = line.get('final_url')
    location = line.get('location')
    chain_status_codes = line.get('chain_status_codes', [])
    http_url = line.get('url')

    # Final URL is already looking nice, if it exists and follow redirect is enabled, return it
    if final_url and follow_redirect:
        return final_url, False

    # Handle redirects manually if follow redirect is enabled
    if follow_redirect:
        REDIRECT_STATUS_CODES = [301, 302]
        is_redirect = (
            status_code in REDIRECT_STATUS_CODES
            or
            any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)
        )
        if is_redirect and location:
            if location.startswith(('http', 'https')):
                http_url = location
            else:
                http_url = f'{http_url}/{location.lstrip("/")}'
    else:
        is_redirect = False

    # Sanitize URL
    http_url = sanitize_url(http_url)

    return http_url, is_redirect

def get_http_crawl_value(config, yaml_configuration):
    """Get HTTP crawl value from config.
    
    Args:
        engine: EngineType object
        config: Configuration dictionary or None
        
    Returns:
        bool: True if HTTP crawl is enabled
    """
    # subscan engine value
    enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) if config else None
    if enable_http_crawl is None:
        # scan engine value
        yaml_config = yaml.safe_load(yaml_configuration)
        enable_http_crawl = yaml_config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
    logger.debug(f'Enable HTTP crawl: {enable_http_crawl}')
    return enable_http_crawl

def parse_curl_output(response):
    http_status = 0
    if response:
        # TODO: Enrich from other cURL fields.
        CURL_REGEX_HTTP_STATUS = 'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
        regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
        with contextlib.suppress(KeyError, TypeError, IndexError):
            http_status = int(regex.findall(response)[0])
    return {
        'http_status': http_status,
    }

def get_data_from_post_request(request, field):
    """
    Get data from a POST request.

    Args:
        request (HttpRequest): The request object.
        field (str): The field to get data from.
    Returns:
        list: The data from the specified field.
    """
    if hasattr(request.data, 'getlist'):
        return request.data.getlist(field)
    else:
        return request.data.get(field, [])

def prepare_urls_with_fallback(urls=None, input_path=None, ctx=None, **http_urls_params):
    """Prepare URLs from input list or database.
    
    This function handles a common pattern of working with URLs:
    1. If URLs are provided as input, write them to a file
    2. Otherwise, retrieve URLs from the database with custom parameters
    
    Args:
        urls (list): List of URLs to use, can be None or empty
        input_path (str): Path to output file
        ctx (dict): Context dictionary
        **http_urls_params: Parameters to pass to get_http_urls if needed
            Common parameters include is_alive, ignore_files, exclude_subdomains, etc.
            
    Returns:
        list: The final list of URLs to process
    """
    from reNgine.utils.db import get_http_urls
    from reNgine.utils.utils import is_iterable
    from reNgine.utils.mock import prepare_urls_mock

    # Set default parameters if not provided
    if 'write_filepath' not in http_urls_params:
        http_urls_params['write_filepath'] = input_path

    # Always pass context to get_http_urls
    if ctx is not None:
        http_urls_params['ctx'] = ctx

    # Check if we have input URLs
    if urls and is_iterable(urls):
        logger.debug('🌐 URLs provided by user, writing to file')
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    elif ctx.get('dry_run'):
        urls = prepare_urls_mock(ctx, input_path)
    else:
        # Normal mode - fetch from database
        logger.debug('🌐 URLs gathered from database')
        urls = get_http_urls(**http_urls_params)

    ctx['urls'] = urls

    return urls

def filter_urls_by_extension(urls, extensions_to_ignore=None):
    """Filter out URLs with specific file extensions.
    
    Args:
        urls (list): List of URLs to filter
        extensions_to_ignore (list): List of file extensions to ignore
        
    Returns:
        list: Filtered list of URLs
    """
    if not extensions_to_ignore:
        return urls

    return [
        url
        for url in urls
        if not any(url.endswith(ext) for ext in extensions_to_ignore)
    ]

def prepare_urls_for_http_scan(urls, url_filter, results_dir, ctx=None, recrawl=False):
    """Prepare URLs specifically for HTTP scanning, handling subscan logic.
    
    This function extends the basic URL preparation to handle the special case
    of subscans launched from subdomain lists.
    
    Args:
        urls (list): List of URLs to use, can be None or empty
        url_filter (str): Filter to apply to URLs
        results_dir (str): Directory to store results
        ctx (dict): Context dictionary
        recrawl (bool): Whether to recrawl already crawled endpoints
        
    Returns:
        tuple: (urls, input_path, update_subdomain_metadatas)
            - urls: final list of URLs to scan
            - input_path: path to the file containing URLs
            - update_subdomain_metadatas: whether to update subdomain metadata
    """
    from reNgine.utils.db import get_http_urls
    from reNgine.utils.utils import is_iterable
    from startScan.models import Subdomain
    
    input_path = f'{results_dir}/input_endpoints.txt'
    update_subdomain_metadatas = False
    
    # Check if we have input URLs
    if urls and is_iterable(urls):
        logger.debug('URLs provided by user, writing to file')
        with open(input_path, 'w') as f:
            f.write('\n'.join(urls))
    else:
        # No url provided, so it's a subscan launched from subdomain list
        update_subdomain_metadatas = True
        all_urls = []

        # Append the base subdomain if task is launched directly from subscan
        subdomain_id = ctx.get('subdomain_id') if ctx else None
        if subdomain_id:
            if subdomain := Subdomain.objects.filter(id=subdomain_id).first():
                all_urls.append(subdomain.name)

        if http_urls := get_http_urls(
            is_uncrawled=not recrawl, write_filepath=input_path, ctx=ctx
        ):
            all_urls.extend(http_urls)
            urls = all_urls

    return urls, input_path, update_subdomain_metadatas
