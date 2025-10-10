"""
Endpoint utilities for reNgine.

This module provides utilities for working with endpoints and interesting lookups.
"""

import logging


logger = logging.getLogger(__name__)


def get_interesting_endpoints(scan_history=None, target=None):
    """Get EndPoint objects matching InterestingLookupModel conditions.

    Args:
        scan_history (startScan.models.ScanHistory): Scan history.
        target (str): Domain id.

    Returns:
        django.db.Q: QuerySet object.
    """
    from reNgine.utilities.lookup import get_lookup_keywords
    from scanEngine.models import InterestingLookupModel
    from startScan.models import EndPoint

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

    # Filter on URL keywords
    if url_lookup:
        from django.db.models import Q

        url_conditions = Q()
        for keyword in lookup_keywords:
            url_conditions |= Q(url__icontains=keyword)
        query = query.filter(url_conditions)

    # Filter on title keywords
    if title_lookup:
        from django.db.models import Q

        title_conditions = Q()
        for keyword in lookup_keywords:
            title_conditions |= Q(page_title__icontains=keyword)
        query = query.filter(title_conditions)

    return query


def ensure_endpoints_crawled_and_execute(task_function, ctx, description=None, max_wait_time=300):
    """
    Ensure endpoints are crawled before executing a task that needs alive endpoints.

    Args:
        task_function: The task function to execute
        ctx: Task context
        description: Task description
        max_wait_time: Maximum time to wait for endpoints (seconds)

    Returns:
        Task result or None if no alive endpoints available
    """
    from copy import deepcopy
    import time

    from reNgine.utilities.url import get_http_urls

    logger.info(f"Ensuring endpoints are crawled for {task_function.__name__}")

    if alive_endpoints := get_http_urls(is_alive=True, ctx=ctx):
        logger.info(f"Found {len(alive_endpoints)} alive endpoints, executing {task_function.__name__}")
        return task_function(ctx=ctx, description=description)

    # No alive endpoints found, check if we have uncrawled endpoints
    uncrawled_endpoints = get_http_urls(is_uncrawled=True, ctx=ctx)

    if not uncrawled_endpoints:
        logger.warning(f"No endpoints found for {task_function.__name__}, skipping task")
        return None

    logger.info(f"Found {len(uncrawled_endpoints)} uncrawled endpoints, launching HTTP crawl first")

    # Launch http_crawl synchronously for the specific endpoints we need
    from reNgine.tasks import http_crawl

    custom_ctx = deepcopy(ctx)
    custom_ctx["track"] = False  # Don't track this internal crawl

    # Execute http_crawl and wait for completion (but with timeout)
    http_crawl_task = http_crawl.delay(
        urls=uncrawled_endpoints[:50],  # Limit to avoid overwhelming
        ctx=custom_ctx,
        update_subdomain_metadatas=True,
    )

    # Wait for crawl completion with timeout
    wait_time = 0
    check_interval = 10  # Check every 10 seconds

    while wait_time < max_wait_time:
        time.sleep(check_interval)
        wait_time += check_interval

        if alive_endpoints := get_http_urls(is_alive=True, ctx=ctx):
            logger.info(f"HTTP crawl completed, found {len(alive_endpoints)} alive endpoints")
            return task_function(ctx=ctx, description=description)

        # Check if crawl task is done
        if http_crawl_task.ready():
            break

    if alive_endpoints := get_http_urls(is_alive=True, ctx=ctx):
        logger.info(f"Found {len(alive_endpoints)} alive endpoints after wait period")
        return task_function(ctx=ctx, description=description)
    else:
        logger.warning(f"No alive endpoints found after {wait_time}s wait, skipping {task_function.__name__}")
        return None
