"""
⚠️ LEGACY MODULE ⚠️

This module contains legacy endpoint utilities that use old task architecture.
Functions using http_crawl task are deprecated and will not work with Secator-based scans.

For new code, use Secator workflows/tasks directly via SecatorRunner.
"""

from urllib.parse import urlparse

from reNgine.utilities.logger import get_module_logger
from django.db.models import Q

from reNgine.settings import RENGINE_HOME
from startScan.models import EndPoint, ScanHistory, Subdomain
from targetApp.models import Domain

from .lookup import get_lookup_keywords


logger = get_module_logger(__name__)


# ------------------#
# EndPoint queries #
# ------------------#


def get_http_urls(
    is_alive=False,
    is_uncrawled=False,
    strict=False,
    ignore_files=False,
    write_filepath=None,
    exclude_subdomains=False,
    get_only_default_urls=False,
    ctx=None,
):
    """Get HTTP urls from EndPoint objects in DB. Support filtering out on a
    specific path.

    Args:
        is_alive (bool): If True, select only alive urls.
        is_uncrawled (bool): If True, select only urls that have not been crawled.
        write_filepath (str): Write info back to a file.
        get_only_default_urls (bool):

    Returns:
        list: List of URLs matching query.
    """
    if ctx is None:
        ctx = {}

    domain_id = ctx.get("domain_id")
    scan_id = ctx.get("scan_history_id")
    subdomain_id = ctx.get("subdomain_id")
    url_filter = ctx.get("url_filter", "")
    domain = Domain.objects.filter(pk=domain_id).first()
    subdomain = Subdomain.objects.filter(pk=subdomain_id).first()
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if subdomain:
        logger.info(f"Searching for endpoints on subdomain {subdomain}")
    else:
        logger.info(f"Searching for endpoints on domain {domain}")
    log_header = "Found a total of "
    log_found = ""

    query = EndPoint.objects
    if domain:
        logger.debug(f"Searching URLs by domain {domain}")
        query = query.filter(target_domain=domain)
        log_found = f"{log_header}{query.count()} endpoints for domain {domain}"
        logger.debug(log_found)
    if scan:
        logger.debug(f"Searching URLs by scan {scan}")
        query = query.filter(scan_history=scan)
        log_found = f"{log_header}{query.count()} endpoints for scan {scan}"
        logger.debug(log_found)
    if subdomain_id:
        subdomain = Subdomain.objects.filter(pk=subdomain_id).first()
        logger.debug(f"Searching URLs by subdomain {subdomain}")
        query = query.filter(subdomain__id=subdomain_id)
        log_found = f"{log_header}{query.count()} endpoints for subdomain {subdomain}"
        logger.debug(log_found)
    elif exclude_subdomains and domain:
        logger.debug("Excluding subdomains")
        query = query.filter(http_url=domain.http_url)
        log_found = f"{log_header}{query.count()} endpoints for domain {domain}"
        logger.debug(log_found)
    if get_only_default_urls:
        logger.debug("Searching only for default URL")
        query = query.filter(is_default=True)
        log_found = f"{log_header}{query.count()} default endpoints"
        logger.debug(log_found)

    # If is_uncrawled is True, select only endpoints that have not been crawled
    # yet (no status)
    if is_uncrawled:
        logger.debug("Searching for uncrawled endpoints only")
        query = query.filter(http_status=0)
        log_found = f"{log_header}{query.count()} uncrawled endpoints"
        logger.debug(log_found)

    # If a path is passed, select only endpoints that contains it
    if url_filter and domain:
        logger.debug(f"Searching for endpoints with path {url_filter}")
        url = f"{domain.name}{url_filter}"
        if strict:
            query = query.filter(http_url=url)
        else:
            query = query.filter(http_url__contains=url)
        log_found = f"{log_header}{query.count()} endpoints with path {url_filter}"
        logger.debug(log_found)

    if log_found:
        logger.info(log_found)

    # Select distinct endpoints and order
    endpoints = query.distinct("http_url").order_by("http_url").all()

    # If is_alive is True, select only endpoints that are alive
    if is_alive:
        logger.debug("Searching for alive endpoints only")
        endpoints = [e for e in endpoints if e.is_alive]
        logger.debug(f"Found a total of {len(endpoints)} alive endpoints")

    # Grab only http_url from endpoint objects
    endpoints = [e.http_url for e in endpoints]
    if ignore_files:  # ignore all files
        extensions_path = f"{RENGINE_HOME}/fixtures/extensions.txt"
        with open(extensions_path, "r") as f:
            extensions = tuple(f.strip() for f in f.readlines())
        endpoints = [e for e in endpoints if not urlparse(e).path.endswith(extensions)]

    if not endpoints:
        logger.error("No endpoints were found in query !")

    if write_filepath:
        with open(write_filepath, "w") as f:
            f.write("\n".join([url for url in endpoints if url is not None]))

    return endpoints


def get_interesting_endpoints(scan_history=None, target=None):
    """Get EndPoint objects matching InterestingLookupModel conditions.

    Args:
        scan_history (startScan.models.ScanHistory): Scan history.
        target (str): Domain id.

    Returns:
        django.db.Q: QuerySet object.
    """
    from scanEngine.models import InterestingLookupModel

    lookup_keywords = get_lookup_keywords()
    lookup_obj = InterestingLookupModel.objects.filter().order_by("-id").first()
    if not lookup_obj:
        return EndPoint.objects.none()
    url_lookup = lookup_obj.url_lookup
    title_lookup = lookup_obj.title_lookup
    condition_200_http_lookup = lookup_obj.condition_200_http_lookup

    # Filter on domain_id, scan_history_id
    query = EndPoint.objects
    if target:
        query = query.filter(target_domain__id=target)
    elif scan_history:
        query = query.filter(scan_history__id=scan_history)

    # Filter on HTTP status code 200
    if condition_200_http_lookup:
        query = query.filter(http_status__exact=200)

    # Build subdomain lookup / page title lookup queries
    url_lookup_query = Q()
    title_lookup_query = Q()
    for key in lookup_keywords:
        if url_lookup:
            url_lookup_query |= Q(http_url__icontains=key)
        if title_lookup:
            title_lookup_query |= Q(page_title__iregex=f"\\y{key}\\y")

    # Filter on url / title queries
    url_lookup_query = query.filter(url_lookup_query)
    title_lookup_query = query.filter(title_lookup_query)

    # Return OR query
    return url_lookup_query | title_lookup_query


def ensure_endpoints_crawled_and_execute(task_function, ctx, description=None, max_wait_time=300):
    """
    DEPRECATED: Ensure endpoints are crawled before executing a task that needs alive endpoints.

    This function is deprecated and will raise NotImplementedError.
    Use Secator workflows for endpoint crawling and task execution.

    Args:
        task_function: The task function to execute
        ctx: Task context
        description: Task description
        max_wait_time: Maximum time to wait for endpoints (seconds)

    Returns:
        Task result or None if no alive endpoints available

    Raises:
        NotImplementedError: Always raised as this function is deprecated
    """
    # NOTE: http_crawl task removed - legacy task, functionality now in Secator
    # This function is deprecated and will not work with Secator-based scans
    logger.warning("ensure_endpoints_crawled_and_execute is deprecated - use Secator workflows instead")
    raise NotImplementedError(
        "ensure_endpoints_crawled_and_execute is deprecated and no longer supported. "
        "Use Secator workflows for endpoint crawling and task execution."
    )


def smart_http_crawl_if_needed(
    urls, ctx, wait_for_completion=False, max_wait_time=120, is_default=False, update_subdomain_metadatas=False
):
    """
    DEPRECATED: Intelligently launch http_crawl only if endpoints need to be crawled.

    This function is deprecated and will raise NotImplementedError.
    Use Secator workflows for HTTP crawling functionality.

    Args:
        urls: URLs to crawl
        ctx: Task context
        wait_for_completion: Whether to wait for crawl completion
        max_wait_time: Maximum time to wait (seconds)
        is_default: Whether discovered endpoints should be marked as default
        update_subdomain_metadatas: Whether to update subdomain metadata

    Returns:
        True if crawl was launched/completed, False otherwise

    Raises:
        NotImplementedError: Always raised as this function is deprecated
    """
    # NOTE: http_crawl task removed - legacy task, functionality now in Secator
    logger.warning("smart_http_crawl_if_needed is deprecated - use Secator workflows instead")
    raise NotImplementedError(
        "smart_http_crawl_if_needed is deprecated and no longer supported. "
        "Use Secator workflows for HTTP crawling functionality."
    )
