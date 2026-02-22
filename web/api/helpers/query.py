"""
Query-building helpers for API views.

Extracts complex queryset logic from views (e.g. ScanStatus, SubdomainDatatableViewSet)
to keep view methods short and testable.
"""

from collections import defaultdict
from typing import Any, Optional, Union

from django.db.models import Max, Prefetch, Q
from django.db.models.query import QuerySet

from reNgine.definitions import (
    FAILED_TASK,
    RUNNING_TASK,
    SCAN_STATUS_PENDING,
    SCAN_STATUSES_CURRENT,
    SCAN_STATUSES_RECENTLY_COMPLETED,
    SUCCESS_TASK,
)
from reNgine.utilities.db import count_subquery
from reNgine.utilities.subdomain import get_interesting_subdomains


def get_scan_status_querysets(
    project_slug: str,
    max_running_tasks: int = 20,
    recently_completed_scans_limit: int = 5,
    recently_completed_tasks_limit: int = 10,
) -> dict:
    """
    Build all querysets needed for the project dashboard scan/task status.

    Recently completed scans = scan_status in SCAN_STATUSES_RECENTLY_COMPLETED (Queued, Completed, Failed).
    Current scans = scan_status in SCAN_STATUSES_CURRENT (Running, Running Background).
    Pending scans = scan_status SCAN_STATUS_PENDING. Limits control dashboard list size.
    Status groupings are defined in reNgine.definitions; use those or is_scan_status_* helpers elsewhere.

    Returns a dict with keys: pending_scans, current_scans, recently_completed_scans,
    pending_tasks, current_tasks, recently_completed_tasks (each a queryset or list).
    """
    from startScan.models import EndPoint, ScanActivity, ScanHistory, Subdomain, SubScan, Vulnerability

    # Scalar count subqueries avoid cartesian products that annotate(Count(..., distinct=True)) would cause.
    base_scan = (
        ScanHistory.objects.filter(target__project__slug=project_slug)
        .select_related("target", "target__project", "scan_type")
        .prefetch_related(
            "target__organizations",
            "secatorrunner_set",
            "scanactivity_set",
        )
        .annotate(
            subdomain_count=count_subquery(Subdomain, "scan_history_id"),
            endpoint_count=count_subquery(EndPoint, "scan_history_id"),
            vulnerability_count=count_subquery(Vulnerability, "scan_history_id"),
        )
    )
    recently_completed_scans = base_scan.order_by("-start_scan_date").filter(
        scan_status__in=SCAN_STATUSES_RECENTLY_COMPLETED
    )[:recently_completed_scans_limit]
    current_scans = base_scan.order_by("-start_scan_date").filter(scan_status__in=SCAN_STATUSES_CURRENT)
    pending_scans = base_scan.order_by("-start_scan_date").filter(scan_status=SCAN_STATUS_PENDING)

    activity_base = ScanActivity.objects.filter(scan_of__target__project__slug=project_slug).select_related(
        "scan_of", "scan_of__target"
    )
    recently_completed_tasks = activity_base.order_by("-time", "-pk").filter(
        Q(status=FAILED_TASK) | Q(status=SUCCESS_TASK)
    )[:recently_completed_tasks_limit]
    current_tasks = activity_base.order_by("-time", "-pk").filter(status=RUNNING_TASK)[:max_running_tasks]
    pending_tasks = (
        SubScan.objects.filter(scan_history__target__project__slug=project_slug)
        .filter(status=SCAN_STATUS_PENDING)
        .select_related("scan_history", "scan_history__target", "subdomain", "engine", "secator_runner")
    )

    return {
        "pending_scans": pending_scans,
        "current_scans": current_scans,
        "recently_completed_scans": recently_completed_scans,
        "pending_tasks": pending_tasks,
        "current_tasks": current_tasks,
        "recently_completed_tasks": recently_completed_tasks,
    }


def build_subdomain_datatable_queryset(
    project_slug: str,
    scan_id: Optional[int] = None,
    target_id: Optional[int] = None,
    url_query: Optional[str] = None,
    ip_address: Optional[str] = None,
    name: Optional[str] = None,
    is_important: bool = False,
    only_directory: bool = False,
):
    """
    Build the Subdomain datatable queryset and optional interesting subdomain names.

    Annotates: endpoint_count; info_count, low_count, medium_count, high_count, critical_count
    (vulnerability counts by severity 0-4); vuln_count, subscan_count, todos_count (undone only).

    Returns (queryset, datatable_interesting_names).
    datatable_interesting_names is a set of subdomain names when scan_id or target_id is set, else None.
    """

    from recon_note.models import TodoNote
    from startScan.models import EndPoint, Subdomain, SubScan, Vulnerability

    subdomains = Subdomain.objects.filter(domain__scan_history__target__project__slug=project_slug)
    if is_important:
        subdomains = subdomains.filter(is_important=True)
    if target_id:
        subdomains = subdomains.filter(domain__scan_history__target_id=target_id)
    elif url_query:
        subdomains = subdomains.filter(Q(domain__name=url_query))
    elif scan_id is not None:
        subdomains = subdomains.filter(scan_history__id=scan_id)

    if only_directory:
        subdomains = subdomains.exclude(directories__isnull=True)
    if ip_address:
        subdomains = subdomains.filter(ip_addresses__address__icontains=ip_address)
    if name:
        subdomains = subdomains.filter(name=name)

    if scan_id is not None:
        interesting = get_interesting_subdomains(scan_history=scan_id)
        datatable_interesting_names = set(interesting.values_list("name", flat=True))
    elif target_id is not None:
        interesting = get_interesting_subdomains(target_id=target_id)
        datatable_interesting_names = set(interesting.values_list("name", flat=True))
    else:
        datatable_interesting_names = None

    latest_subdomain_ids = subdomains.values("name").annotate(max_id=Max("id")).values_list("max_id", flat=True)
    base_filter: dict = {"id__in": latest_subdomain_ids}
    if scan_id is not None:
        base_filter["scan_history_id"] = scan_id

    # Scalar count subqueries avoid cartesian products vs Count(distinct=...) over joins.
    queryset = (
        Subdomain.objects.filter(**base_filter)
        .annotate(
            endpoint_count=count_subquery(EndPoint, "subdomain_id"),
            info_count=count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 0}),
            low_count=count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 1}),
            medium_count=count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 2}),
            high_count=count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 3}),
            critical_count=count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 4}),
            vuln_count=count_subquery(Vulnerability, "subdomain_id"),
            subscan_count=count_subquery(SubScan, "subdomain_id"),
            todos_count=count_subquery(TodoNote, "subdomain_id", filter_kwargs={"is_done": False}),
        )
        .prefetch_related(
            "ip_addresses",
            "ip_addresses__ports",
            "technologies",
            "waf",
            "directories",
            "scan_history",
            Prefetch(
                "endpoint_set",
                queryset=EndPoint.objects.filter(is_default=True),
                to_attr="default_endpoint_list",
            ),
        )
    )
    return queryset, datatable_interesting_names


def get_ip_subdomain_data(ip_queryset: Union[QuerySet, list]) -> dict[int, dict[str, Any]]:
    """
    Precompute subdomain count and names per IP for IpSerializer context.

    Avoids N+1 when serializing multiple IpAddress instances. Returns a dict
    ip_id -> {"count": int, "names": list[str]}.
    """
    from startScan.models import Subdomain

    if hasattr(ip_queryset, "values_list"):
        ip_ids = list(ip_queryset.values_list("id", flat=True))
    else:
        ip_ids = [ip.id for ip in ip_queryset]
    if not ip_ids:
        return {}

    through = Subdomain.ip_addresses.through
    data: dict[int, dict[str, Any]] = defaultdict(lambda: {"count": 0, "names": []})
    for ip_id, name in (
        through.objects.filter(ipaddress_id__in=ip_ids).values_list("ipaddress_id", "subdomain__name").distinct()
    ):
        data[ip_id]["count"] += 1
        data[ip_id]["names"].append(name)
    return dict(data)
