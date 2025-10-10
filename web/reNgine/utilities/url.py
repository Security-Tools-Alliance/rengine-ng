"""
URL utilities for URL manipulation and validation.

This module provides functionality for URL manipulation, validation,
and processing using core utilities.
"""

from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger
import tldextract

from reNgine.utilities.core.data import remove_control_characters
from reNgine.utilities.core.network import build_url, extract_domain_from_url, parse_url
from reNgine.utilities.core.validation import (
    is_valid_domain,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_subdomain,
    is_valid_url,
)


logger = get_task_logger(__name__)


class URLProcessor:
    """URL processor using core utilities"""

    def __init__(self):
        pass

    def sanitize_url(self, url: str) -> str:
        """
        Sanitize URL by removing unwanted characters and normalizing.

        Args:
            url: URL to sanitize

        Returns:
            Sanitized URL
        """
        if not url or not isinstance(url, str):
            return ""

        # Remove whitespace
        url = url.strip()

        # Remove control characters
        url = remove_control_characters(url)

        # Ensure URL starts with protocol
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        return url

    def get_subdomain_from_url(self, url: str) -> str:
        """
        Extract subdomain from URL.

        Args:
            url: URL to extract subdomain from

        Returns:
            Subdomain name
        """
        try:
            parsed = parse_url(url)
            if parsed and parsed["netloc"]:
                return parsed["netloc"].split(":")[0]
        except Exception:
            return ""

    def add_port_to_url(self, url: str, port: int) -> str:
        """
        Add port to URL.

        Args:
            url: Base URL
            port: Port number to add

        Returns:
            URL with port
        """
        try:
            if parsed := parse_url(url):
                if parsed["port"]:
                    # Replace existing port
                    f"{parsed['hostname']}:{port}"
                else:
                    # Add new port
                    f"{parsed['netloc']}:{port}"

                return build_url(
                    parsed["scheme"], parsed["hostname"], port, parsed["path"], parsed["query"], parsed["fragment"]
                )
        except Exception:
            return url

    def remove_port_from_url(self, url: str) -> str:
        """
        Remove port from URL.

        Args:
            url: URL to remove port from

        Returns:
            URL without port
        """
        try:
            parsed = parse_url(url)
            if parsed and parsed["port"]:
                return build_url(
                    parsed["scheme"],
                    parsed["hostname"],
                    None,  # Remove port
                    parsed["path"],
                    parsed["query"],
                    parsed["fragment"],
                )
            return url
        except Exception:
            return url

    def normalize_url(self, url: str) -> str:
        """
        Normalize URL by removing trailing slashes and normalizing path.

        Args:
            url: URL to normalize

        Returns:
            Normalized URL
        """
        try:
            if parsed := parse_url(url):
                # Normalize path
                path = parsed["path"]
                if path and path != "/" and path.endswith("/"):
                    path = path.rstrip("/")

                return build_url(
                    parsed["scheme"], parsed["hostname"], parsed["port"], path, parsed["query"], parsed["fragment"]
                )
        except Exception:
            return url

    def is_same_domain(self, url1: str, url2: str) -> bool:
        """
        Check if two URLs belong to the same domain.

        Args:
            url1: First URL
            url2: Second URL

        Returns:
            True if same domain, False otherwise
        """
        try:
            domain1 = extract_domain_from_url(url1)
            domain2 = extract_domain_from_url(url2)
            return domain1 == domain2
        except Exception:
            return False

    def extract_paths_from_urls(self, urls: List[str]) -> List[str]:
        """
        Extract unique paths from a list of URLs.

        Args:
            urls: List of URLs

        Returns:
            List of unique paths
        """
        paths = set()

        for url in urls:
            try:
                parsed = parse_url(url)
                if parsed and parsed["path"] and parsed["path"] != "/":
                    paths.add(parsed["path"])
            except Exception:
                continue

        return list(paths)

    def filter_urls_by_domain(self, urls: List[str], domain: str) -> List[str]:
        """
        Filter URLs by domain.

        Args:
            urls: List of URLs to filter
            domain: Domain to filter by

        Returns:
            List of URLs belonging to the domain
        """
        filtered_urls = []

        filtered_urls.extend(url for url in urls if self.is_same_domain(url, f"http://{domain}"))
        return filtered_urls

    def validate_urls_batch(self, urls: List[str]) -> Dict[str, Any]:
        """
        Validate a batch of URLs.

        Args:
            urls: List of URLs to validate

        Returns:
            Validation results
        """
        valid_urls = []
        invalid_urls = []

        for url in urls:
            if is_valid_url(url):
                valid_urls.append(url)
            else:
                invalid_urls.append(url)

        return {
            "valid_urls": valid_urls,
            "invalid_urls": invalid_urls,
            "total_count": len(urls),
            "valid_count": len(valid_urls),
            "invalid_count": len(invalid_urls),
        }


def sanitize_url(url: str) -> str:
    """
    Sanitize URL by removing unwanted characters and normalizing.

    Args:
        url: URL to sanitize

    Returns:
        Sanitized URL
    """
    processor = URLProcessor()
    return processor.sanitize_url(url)


def get_subdomain_from_url(url: str) -> str:
    """
    Extract subdomain from URL.

    Args:
        url: URL to extract subdomain from

    Returns:
        Subdomain name
    """
    processor = URLProcessor()
    return processor.get_subdomain_from_url(url)


def add_port_to_url(url: str, port: int) -> str:
    """
    Add port to URL.

    Args:
        url: Base URL
        port: Port number to add

    Returns:
        URL with port
    """
    processor = URLProcessor()
    return processor.add_port_to_url(url, port)


def remove_port_from_url(url: str) -> str:
    """
    Remove port from URL.

    Args:
        url: URL to remove port from

    Returns:
        URL without port
    """
    processor = URLProcessor()
    return processor.remove_port_from_url(url)


def normalize_url(url: str) -> str:
    """
    Normalize URL by removing trailing slashes and normalizing path.

    Args:
        url: URL to normalize

    Returns:
        Normalized URL
    """
    processor = URLProcessor()
    return processor.normalize_url(url)


def is_same_domain(url1: str, url2: str) -> bool:
    """
    Check if two URLs belong to the same domain.

    Args:
        url1: First URL
        url2: Second URL

    Returns:
        True if same domain, False otherwise
    """
    processor = URLProcessor()
    return processor.is_same_domain(url1, url2)


def extract_paths_from_urls(urls: List[str]) -> List[str]:
    """
    Extract unique paths from a list of URLs.

    Args:
        urls: List of URLs

    Returns:
        List of unique paths
    """
    processor = URLProcessor()
    return processor.extract_paths_from_urls(urls)


def filter_urls_by_domain(urls: List[str], domain: str) -> List[str]:
    """
    Filter URLs by domain.

    Args:
        urls: List of URLs to filter
        domain: Domain to filter by

    Returns:
        List of URLs belonging to the domain
    """
    processor = URLProcessor()
    return processor.filter_urls_by_domain(urls, domain)


def validate_urls_batch(urls: List[str]) -> Dict[str, Any]:
    """
    Validate a batch of URLs.

    Args:
        urls: List of URLs to validate

    Returns:
        Validation results
    """
    processor = URLProcessor()
    return processor.validate_urls_batch(urls)


def get_url_statistics(urls: List[str]) -> Dict[str, Any]:
    """
    Get statistics from a list of URLs.

    Args:
        urls: List of URLs

    Returns:
        Statistics dictionary
    """
    if not urls:
        return {"total_urls": 0, "unique_domains": 0, "unique_paths": 0, "http_urls": 0, "https_urls": 0}

    unique_domains = set()
    unique_paths = set()
    http_count = 0
    https_count = 0

    for url in urls:
        try:
            parsed = parse_url(url)
            if not parsed:
                continue

            # Count protocols
            if parsed["scheme"] == "http":
                http_count += 1
            elif parsed["scheme"] == "https":
                https_count += 1

            # Collect unique domains
            if parsed["netloc"]:
                unique_domains.add(parsed["netloc"].split(":")[0])

            # Collect unique paths
            if parsed["path"] and parsed["path"] != "/":
                unique_paths.add(parsed["path"])

        except Exception:
            continue

    return {
        "total_urls": len(urls),
        "unique_domains": len(unique_domains),
        "unique_paths": len(unique_paths),
        "http_urls": http_count,
        "https_urls": https_count,
    }


def get_http_urls(
    is_alive: bool = False,
    is_uncrawled: bool = False,
    strict: bool = False,
    ignore_files: bool = False,
    write_filepath: Optional[str] = None,
    exclude_subdomains: bool = False,
    get_only_default_urls: bool = False,
    ctx: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Get HTTP URLs from EndPoint objects in database with filtering support.

    Args:
        is_alive (bool): If True, select only alive URLs
        is_uncrawled (bool): If True, select only URLs that have not been crawled
        strict (bool): Apply strict filtering
        ignore_files (bool): Ignore file URLs
        write_filepath (str, optional): Write URLs to file
        exclude_subdomains (bool): Exclude subdomain URLs
        get_only_default_urls (bool): Get only default URLs (/, /index.html, etc.)
        ctx (dict, optional): Context with domain_id, scan_history_id, subdomain_id, url_filter

    Returns:
        list: List of URLs matching query

    Example:
        >>> urls = get_http_urls(is_alive=True, ctx={"domain_id": 1})
        >>> # Returns: ["http://example.com", "https://example.com/api"]
    """
    try:
        from celery.utils.log import get_task_logger

        from startScan.models import EndPoint, ScanHistory
        from targetApp.models import Domain, Subdomain

        logger = get_task_logger(__name__)

        if ctx is None:
            ctx = {}

        domain_id = ctx.get("domain_id")
        scan_id = ctx.get("scan_history_id")
        subdomain_id = ctx.get("subdomain_id")
        url_filter = ctx.get("url_filter", "")

        domain = Domain.objects.filter(pk=domain_id).first() if domain_id else None
        subdomain = Subdomain.objects.filter(pk=subdomain_id).first() if subdomain_id else None
        scan = ScanHistory.objects.filter(pk=scan_id).first() if scan_id else None

        if subdomain:
            logger.info(f"Searching for endpoints on subdomain {subdomain}")
        else:
            logger.info(f"Searching for endpoints on domain {domain}")

        # Build query
        query = EndPoint.objects

        if domain:
            logger.debug(f"Searching URLs by domain {domain}")
            query = query.filter(target_domain=domain)

        if scan:
            logger.debug(f"Searching URLs by scan {scan}")
            query = query.filter(scan_history=scan)

        if subdomain:
            logger.debug(f"Searching URLs by subdomain {subdomain}")
            query = query.filter(target_subdomain=subdomain)

        # Apply filters
        if is_alive:
            query = query.filter(is_alive=True)

        if is_uncrawled:
            query = query.filter(is_uncrawled=True)

        if strict:
            query = query.filter(is_alive=True, http_status__in=[200, 301, 302, 403, 401])

        if ignore_files:
            # Exclude common file extensions
            file_extensions = [
                ".pdf",
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".css",
                ".js",
                ".ico",
                ".svg",
                ".woff",
                ".woff2",
            ]
            for ext in file_extensions:
                query = query.exclude(http_url__endswith=ext)

        if exclude_subdomains:
            query = query.filter(target_subdomain__isnull=True)

        if get_only_default_urls:
            default_paths = ["/", "/index.html", "/index.php", "/default.html", "/home.html"]
            query = query.filter(http_url__in=default_paths)

        if url_filter:
            query = query.filter(http_url__icontains=url_filter)

        # Get URLs
        endpoints = query.values_list("http_url", flat=True).distinct()
        urls = list(endpoints)

        logger.info(f"Found {len(urls)} URLs matching criteria")

        # Write to file if requested
        if write_filepath and urls:
            try:
                with open(write_filepath, "w", encoding="utf-8") as f:
                    for url in urls:
                        f.write(f"{url}\n")
                logger.info(f"URLs written to {write_filepath}")
            except Exception as e:
                logger.error(f"Failed to write URLs to file {write_filepath}: {e}")

        return urls

    except ImportError as e:
        logger.error(f"Database models not available: {e}")
        return []
    except Exception as e:
        logger.error(f"Error getting HTTP URLs: {e}")
        return []


def get_domain_from_subdomain(subdomain: str) -> Optional[str]:
    """
    Get domain from subdomain with improved handling of edge cases.

    This function handles complex TLDs like .co.uk, .com.au, and internationalized
    domains correctly using tldextract library.

    Args:
        subdomain (str): Subdomain name

    Returns:
        str: Domain name, or None if extraction fails

    Example:
        >>> get_domain_from_subdomain("www.example.com")
        "example.com"
        >>> get_domain_from_subdomain("api.subdomain.example.co.uk")
        "example.co.uk"
    """
    if not subdomain or not isinstance(subdomain, str):
        return None

    # Clean the input - remove whitespace and convert to lowercase
    subdomain = subdomain.strip().lower()

    if not is_valid_subdomain(subdomain):
        return None

    # Use tldextract to parse the subdomain - handles complex TLDs and IDNs
    try:
        extracted = tldextract.extract(subdomain)

        # Check if we have both domain and suffix (TLD)
        if extracted.domain and extracted.suffix:
            domain = f"{extracted.domain}.{extracted.suffix}"

            # Additional validation to ensure the extracted domain is valid
            if is_valid_domain(domain):
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
                if is_valid_domain(potential_domain):
                    logger.debug(f"Extracted private TLD domain: {potential_domain} from {subdomain}")
                    return potential_domain

        # Fallback method for edge cases where tldextract might not recognize the TLD
        # Use tldextract's fallback with PSL private domains enabled
        fallback_extracted = tldextract.extract(subdomain, include_psl_private_domains=True)
        if fallback_extracted.domain and fallback_extracted.suffix:
            potential_domain = f"{fallback_extracted.domain}.{fallback_extracted.suffix}"
            if is_valid_domain(potential_domain):
                return potential_domain

        # If all else fails, return None
        return None

    except Exception as e:
        logger.warning(f"Error extracting domain from subdomain '{subdomain}': {str(e)}")
        return None


def _is_valid_subdomain(target: str, domain_name: str) -> bool:
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


def is_target_allowed_for_domain(
    target: str, domain_name: str, ctx: Optional[Dict[str, Any]] = None, target_type: str = "subdomain"
) -> bool:
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

    Example:
        >>> is_target_allowed_for_domain("www.example.com", "example.com")
        True
        >>> is_target_allowed_for_domain("evil.com", "example.com")
        False
        >>> is_target_allowed_for_domain("192.168.1.1", "example.com")
        True
    """
    try:
        # Extract hostname from URL if needed
        if target_type == "url":
            parsed_url = parse_url(target)
            hostname = parsed_url["hostname"] if parsed_url else None
            if not hostname:
                # Invalid URL without hostname
                return False
        else:
            hostname = target

        # IP addresses are always allowed
        if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
            return True

        if is_valid_ipv4(domain_name) or is_valid_ipv6(domain_name) or not is_valid_domain(domain_name):
            return True

        # If no domain_id in context, allow the target (backward compatibility)
        if not ctx or not ctx.get("domain_id"):
            return True

        # Strict validation: hostname must be a subdomain of the domain
        return _is_valid_subdomain(hostname, domain_name)

    except Exception as e:
        logger.warning(f"Error validating target '{target}' for domain '{domain_name}': {str(e)}")
        return False
