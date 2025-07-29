import validators
import tldextract
from urllib.parse import urlparse
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


#-----------#
# URL utils #
#-----------#

def add_port_urls_to_crawl(name, urls_to_crawl, additional_urls_to_test, precrawl_ports, precrawl_all_ports, precrawl_uncommon_ports, entity_type="subdomain"):
    """
    Add port URLs to crawl list for a given name (subdomain or IP)
    
    Args:
        name: subdomain name or IP address
        urls_to_crawl: list to append URLs to
        additional_urls_to_test: list to append additional URLs to
        precrawl_ports: configured common ports
        precrawl_all_ports: whether to test all ports
        precrawl_uncommon_ports: whether to test uncommon ports
        entity_type: "subdomain" or "IP" for logging
    """
    from reNgine.definitions import COMMON_WEB_PORTS, UNCOMMON_WEB_PORTS
    
    # Determine which ports to test based on configuration
    ports_to_test = list(precrawl_ports)  # Start with configured common ports
    
    if precrawl_all_ports:
        # If all ports requested, combine common and uncommon
        ports_to_test = list(set(COMMON_WEB_PORTS + UNCOMMON_WEB_PORTS))
        logger.info(f'Found single default endpoint for {entity_type} {name}, testing ALL ports (COMMON + UNCOMMON)')
    elif precrawl_uncommon_ports:
        # If uncommon ports requested, add them to the configured ports
        ports_to_test = list(set(precrawl_ports + UNCOMMON_WEB_PORTS))
        logger.info(f'Found single default endpoint for {entity_type} {name}, testing COMMON and UNCOMMON ports')
    else:
        # Only test configured common ports (default behavior)
        logger.info(f'Found single default endpoint for {entity_type} {name}, testing configured ports: {precrawl_ports}')

    # Add port URLs to crawl list (not to database yet)
    # Test both http and https schemes since we don't know which one is available
    for port in ports_to_test:
        # Special handling for default ports 80 and 443
        if port == 80:
            # Port 80 is HTTP default, no need to specify port
            url = f'http://{name}'
            if url not in urls_to_crawl:
                urls_to_crawl.append(url)
                additional_urls_to_test.append(url)
                logger.debug(f'Added port URL to crawl: {url}')
        elif port == 443:
            # Port 443 is HTTPS default, no need to specify port
            url = f'https://{name}'
            if url not in urls_to_crawl:
                urls_to_crawl.append(url)
                additional_urls_to_test.append(url)
                logger.debug(f'Added port URL to crawl: {url}')
        else:
            # For all other ports, test both schemes
            for scheme in ['http', 'https']:
                url = f'{scheme}://{name}:{port}'

                # Don't add if it already exists in crawl list
                if url not in urls_to_crawl:
                    urls_to_crawl.append(url)
                    additional_urls_to_test.append(url)
                    logger.debug(f'Added port URL to crawl: {url}')


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
    logger.debug(f'Validating URL: {url}')
    
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
                logger.debug(f'Invalid port number: {port}')
                return False
        else:
            domain = url
            
        # Validate domain
        if validators.domain(domain) or validators.ipv4(domain) or validators.ipv6(domain):
            logger.debug(f'Valid domain/IP found: {domain}')
            return True
            
        logger.debug(f'Invalid domain/IP: {domain}')
        return False
        
    except (ValueError, ValidationError) as e:
        logger.debug(f'Validation error: {str(e)}')
        return False


def extract_httpx_url(line, follow_redirect):
    """Extract final URL from httpx results.

    Args:
        line (dict): URL data output by httpx.
        follow_redirect (bool): Whether redirects were followed by httpx.

    Returns:
        tuple: (final_url, redirect_bool) tuple.
    """
    status_code = line.get('status_code', 0)
    final_url = line.get('final_url')
    location = line.get('location')
    chain_status_codes = line.get('chain_status_codes', [])
    original_url = line.get('url')

    # Detect if there was a redirection based on status codes, location header, or URL change
    REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308]
    has_redirect = (
        status_code in REDIRECT_STATUS_CODES or  # Direct redirect status
        location is not None or  # Location header present
        (final_url is not None and final_url != original_url) or  # Final URL different from original
        any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)  # Redirect in chain
    )

    if follow_redirect:
        # When following redirects, return the final destination
        if final_url:
            # httpx followed redirects and gave us the final URL
            return final_url, has_redirect
        elif location:
            # Fallback: use location header if final_url not provided
            if location.startswith(('http', 'https')):
                return sanitize_url(location), has_redirect
            else:
                # Relative redirect
                return sanitize_url(f'{original_url.rstrip("/")}/{location.lstrip("/")}'), has_redirect
    
    # When not following redirects, always return the original URL
    # This ensures we record the actual endpoint that was tested
    return sanitize_url(original_url), has_redirect 