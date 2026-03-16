from urllib.parse import urlparse

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
import tldextract
import validators

from reNgine.utilities.logger import get_module_logger


PREFIX_URL = "[URL]"
logger = get_module_logger(__name__)


# -----------#
# URL utils #
# -----------#


def add_port_urls_to_crawl(
    name,
    urls_to_crawl,
    additional_urls_to_test,
    precrawl_ports,
    precrawl_all_ports,
    precrawl_uncommon_ports,
    entity_type="subdomain",
):
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
        ports_to_test = list(set(COMMON_WEB_PORTS + UNCOMMON_WEB_PORTS))
        logger.log_line(
            PREFIX_URL,
            "ADD_PORT_URLS",
            "Found single default endpoint for %s %s, testing ALL ports (COMMON + UNCOMMON)" % (entity_type, name),
            level="info",
        )
    elif precrawl_uncommon_ports:
        ports_to_test = list(set(precrawl_ports + UNCOMMON_WEB_PORTS))
        logger.log_line(
            PREFIX_URL,
            "ADD_PORT_URLS",
            "Found single default endpoint for %s %s, testing COMMON and UNCOMMON ports" % (entity_type, name),
            level="info",
        )
    else:
        logger.log_line(
            PREFIX_URL,
            "ADD_PORT_URLS",
            "Found single default endpoint for %s %s, testing configured ports: %s"
            % (entity_type, name, precrawl_ports),
            level="info",
        )

    # Add port URLs to crawl list (not to database yet)
    # Test both http and https schemes since we don't know which one is available
    for port in ports_to_test:
        # Special handling for default ports 80 and 443
        if port == 80:
            url = "http://%s" % (name,)
            if url not in urls_to_crawl:
                urls_to_crawl.append(url)
                additional_urls_to_test.append(url)
                logger.log_line(
                    PREFIX_URL,
                    "ADD_PORT_URLS",
                    "Added port URL to crawl: %s" % (url,),
                    level="debug",
                )
        elif port == 443:
            url = "https://%s" % (name,)
            if url not in urls_to_crawl:
                urls_to_crawl.append(url)
                additional_urls_to_test.append(url)
                logger.log_line(
                    PREFIX_URL,
                    "ADD_PORT_URLS",
                    "Added port URL to crawl: %s" % (url,),
                    level="debug",
                )
        else:
            for scheme in ["http", "https"]:
                url = "%s://%s:%s" % (scheme, name, port)
                if url not in urls_to_crawl:
                    urls_to_crawl.append(url)
                    additional_urls_to_test.append(url)
                    logger.log_line(
                        PREFIX_URL,
                        "ADD_PORT_URLS",
                        "Added port URL to crawl: %s" % (url,),
                        level="debug",
                    )


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
    return url_obj.netloc.split(":")[0]


def is_valid_domain_or_subdomain(domain):
    try:
        URLValidator(schemes=["http", "https"])(f"http://{domain}")
        return True
    except ValidationError:
        return False


def normalize_subdomain_host(name: str) -> str:
    """
    Normalize a subdomain host for validation and storage.

    Strips leading dots (e.g. DNS zone format ".example.com" from Chaos)
    and lowercases for consistent storage and comparison (hostnames are
    case-insensitive). Returns empty string if input is invalid.
    """
    if not name or not isinstance(name, str):
        return ""
    return name.strip().lstrip(".").strip().lower()


def is_acceptable_subdomain_name(name: str) -> bool:
    """
    Return True if the string can serve as a subdomain name (hostname or IP).

    Use this predicate for creating or associating Subdomains from Secator findings
    (Endpoint, Ip, Port, Record, Certificate, etc.). Accepts:
    - Standard FQDNs (is_valid_domain)
    - Local/private hostnames (.lan, .local, etc. via is_valid_domain_or_subdomain)
    - IP addresses (IPv4/IPv6)
    """
    if not name or not isinstance(name, str):
        return False
    from reNgine.core.validators import is_valid_domain, is_valid_ip

    name = name.strip()
    if not name:
        return False
    return bool(is_valid_domain(name) or is_valid_domain_or_subdomain(name) or is_valid_ip(name))


def get_domain_from_subdomain(subdomain):
    """Get domain from subdomain with improved handling of edge cases.

    This function handles complex TLDs like .co.uk, .com.au, and internationalized
    domains correctly using tldextract library.

    Args:
        subdomain (str): Subdomain name.

    Returns:
        str: Domain name, or None if extraction fails.
    """
    if not subdomain or not isinstance(subdomain, str):
        return None

    # Clean the input - remove whitespace and convert to lowercase
    subdomain = subdomain.strip().lower()

    if not is_valid_domain_or_subdomain(subdomain):
        return None

    # Use tldextract to parse the subdomain - handles complex TLDs and IDNs
    try:
        extracted = tldextract.extract(subdomain)

        # Check if we have both domain and suffix (TLD)
        if extracted.domain and extracted.suffix:
            domain = f"{extracted.domain}.{extracted.suffix}"

            # Additional validation to ensure the extracted domain is valid
            if is_valid_domain_or_subdomain(domain):
                return domain

        # Special handling for .local domains and other private TLDs
        # tldextract doesn't recognize .local as a valid TLD, so we need custom logic
        if extracted.domain and not extracted.suffix and extracted.subdomain:
            # This is likely a private TLD like .local
            # Extract the last two parts: subdomain.domain
            parts = subdomain.split(".")
            if len(parts) >= 2:
                # Take the last two parts as domain.tld
                potential_domain = ".".join(parts[-2:])
                if is_valid_domain_or_subdomain(potential_domain):
                    logger.log_line(
                        PREFIX_URL,
                        "GET_DOMAIN",
                        "Extracted private TLD domain: %s from %s" % (potential_domain, subdomain),
                        level="debug",
                    )
                    return potential_domain

        # Fallback method for edge cases where tldextract might not recognize the TLD
        # Use tldextract's fallback with PSL private domains enabled
        fallback_extracted = tldextract.extract(subdomain, include_psl_private_domains=True)
        if fallback_extracted.domain and fallback_extracted.suffix:
            potential_domain = f"{fallback_extracted.domain}.{fallback_extracted.suffix}"
            if is_valid_domain_or_subdomain(potential_domain):
                return potential_domain

        # If all else fails, return None
        return None

    except Exception as e:
        logger.log_line(
            PREFIX_URL,
            "GET_DOMAIN",
            "Error extracting domain from subdomain '%s': %s" % (subdomain, e),
            level="warning",
        )
        return None


def is_apex_domain(host: str) -> bool:
    """True if host is an apex/registered domain (no subdomain), using public suffix list.

    E.g. example.com -> True, www.example.com -> False, example.co.uk -> True.
    Uses tldextract so multi-part TLDs (co.uk, com.au) are handled correctly.
    """
    if not host or not isinstance(host, str):
        return False
    host = host.strip().lower()
    if not host:
        return False
    try:
        extracted = tldextract.extract(host)
        return (
            bool(extracted.domain)
            and bool(extracted.suffix)
            and (not extracted.subdomain or extracted.subdomain.strip() == "")
        )
    except Exception:
        return False


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

    if url.netloc.endswith(":80"):
        url = url._replace(netloc=url.netloc.replace(":80", ""))
    elif url.netloc.endswith(":443"):
        url = url._replace(scheme=url.scheme.replace("http", "https"))
        url = url._replace(netloc=url.netloc.replace(":443", ""))
    return url.geturl().rstrip("/")


def extract_path_from_url(url):
    parsed_url = urlparse(url)

    # Reconstruct the URL without scheme and netloc
    reconstructed_url = parsed_url.path

    if reconstructed_url.startswith("/"):
        reconstructed_url = reconstructed_url[1:]  # Remove the first slash

    if parsed_url.params:
        reconstructed_url += f";{parsed_url.params}"
    if parsed_url.query:
        reconstructed_url += f"?{parsed_url.query}"
    if parsed_url.fragment:
        reconstructed_url += f"#{parsed_url.fragment}"

    return reconstructed_url


def is_valid_url(url):
    """Check if a URL is valid, including both full URLs and domain:port format.

    Args:
        url (str): URL to validate (https://domain.com or domain.com:port)

    Returns:
        bool: True if valid URL, False otherwise
    """
    logger.log_line(
        PREFIX_URL,
        "VALIDATE",
        "Validating URL: %s" % (url,),
        level="debug",
    )

    # Handle URLs with scheme (http://, https://)
    if url.startswith(("http://", "https://")):
        return validators.url(url)

    # Handle domain:port format
    try:
        if ":" in url:
            domain, port = url.rsplit(":", 1)
            # Validate port
            port = int(port)
            if not 1 <= port <= 65535:
                logger.log_line(
                    PREFIX_URL,
                    "VALIDATE",
                    "Invalid port number: %s" % (port,),
                    level="debug",
                )
                return False
        else:
            domain = url

        if validators.domain(domain) or validators.ipv4(domain) or validators.ipv6(domain):
            logger.log_line(
                PREFIX_URL,
                "VALIDATE",
                "Valid domain/IP found: %s" % (domain,),
                level="debug",
            )
            return True

        logger.log_line(
            PREFIX_URL,
            "VALIDATE",
            "Invalid domain/IP: %s" % (domain,),
            level="debug",
        )
        return False

    except (ValueError, ValidationError) as e:
        logger.log_line(
            PREFIX_URL,
            "VALIDATE",
            "Validation error: %s" % (e,),
            level="debug",
        )
        return False


def is_target_allowed_for_domain(target, domain_name, ctx=None, target_type="subdomain"):
    """
    Check if a target (subdomain or URL) is allowed for a given domain based on scan context and target type.

    This function centralizes the validation logic for determining whether a target
    should be allowed for a specific domain, taking into account:
    - Regular domain scans (strict validation)
    - IP address scans (allow IP targets)
    - Custom text targets (allow any valid target)

    Args:
        target (str): The target to validate (subdomain name or URL)
        domain_name (str): The domain name being scanned
        ctx (dict, optional): Scan context containing domain_id and other info
        target_type (str): Type of target - "subdomain" or "url"

    Returns:
        bool: True if target is allowed, False otherwise
    """
    from reNgine.utilities.misc import determine_target_type

    # Extract hostname from URL if needed
    if target_type == "url":
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        if not hostname:
            # Invalid URL without hostname
            return False
    else:
        hostname = target

    # IP addresses are always allowed
    if validators.ipv4(hostname) or validators.ipv6(hostname):
        return True

    # Determine target type for custom text targets
    scan_target_type = determine_target_type(domain_name)
    is_custom_text_target = scan_target_type == "custom_text"

    # For custom text targets, allow any valid target (no strict domain validation)
    if is_custom_text_target:
        return True

    # If no domain_id in context, allow the target (backward compatibility)
    if not ctx or not ctx.get("domain_id"):
        return True

    # Strict validation: hostname must be a subdomain of the domain
    return _is_valid_subdomain(hostname, domain_name)


def _is_valid_subdomain(target, domain_name):
    """
    Check if target is a valid subdomain of the given domain.

    This function uses tldextract (via get_domain_from_subdomain) to properly extract
    the root domain from the target and compares it with the expected domain_name.
    This simple approach (KISS principle) handles all edge cases correctly, including
    multi-level subdomains and complex TLDs.

    Examples:
        - 'sub.example.com' for 'example.com' -> True
        - 'a.b.c.example.com' for 'example.com' -> True
        - 'example.com.evil.com' for 'example.com' -> False
        - 'notexample.com' for 'example.com' -> False

    Args:
        target (str): The target to validate (subdomain or hostname)
        domain_name (str): The domain name to validate against

    Returns:
        bool: True if target is a valid subdomain, False otherwise
    """
    # Handle exact match
    if target == domain_name:
        return True

    # Use get_domain_from_subdomain to extract the root domain from target
    # This leverages tldextract which handles all TLD complexities
    extracted_domain = get_domain_from_subdomain(target)

    # The target is valid if its extracted domain matches the expected domain
    return extracted_domain == domain_name


def extract_httpx_url(line, follow_redirect):
    """Extract final URL from httpx results.

    Args:
        line (dict): URL data output by httpx.
        follow_redirect (bool): Whether redirects were followed by httpx.

    Returns:
        tuple: (final_url, redirect_bool) tuple.
    """
    status_code = line.get("status_code", 0)
    final_url = line.get("final_url")
    location = line.get("location")
    chain_status_codes = line.get("chain_status_codes", [])
    original_url = line.get("url")

    # Detect if there was a redirection based on status codes, location header, or URL change
    redirect_status_codes = [301, 302, 303, 307, 308]
    has_redirect = (
        status_code in redirect_status_codes  # Direct redirect status
        or location is not None  # Location header present
        or (final_url is not None and final_url != original_url)  # Final URL different from original
        or any(x in redirect_status_codes for x in chain_status_codes)  # Redirect in chain
    )

    if follow_redirect:
        # When following redirects, return the final destination
        if final_url:
            # httpx followed redirects and gave us the final URL
            return final_url, has_redirect
        elif location:
            # Fallback: use location header if final_url not provided
            if location.startswith(("http", "https")):
                return sanitize_url(location), has_redirect
            else:
                # Relative redirect
                return sanitize_url(f"{original_url.rstrip('/')}/{location.lstrip('/')}"), has_redirect

    # When not following redirects, always return the original URL
    # This ensures we record the actual endpoint that was tested
    return sanitize_url(original_url), has_redirect
