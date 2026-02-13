"""
Query-building helpers for API views.

Extracts complex queryset logic from views (e.g. ScanStatus, SubdomainDatatableViewSet)
to keep view methods short and testable.
"""

from typing import Optional

from django.db.models import Count, Max, Prefetch, Q

from reNgine.definitions import FAILED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.utilities.subdomain import get_interesting_subdomains


def get_scan_status_querysets(
    project_slug: str,
    max_running_tasks: int = 30,
) -> dict:
    """
    Build all querysets needed for the project dashboard scan/task status.

    Returns a dict with keys: pending_scans, current_scans, recently_completed_scans,
    pending_tasks, current_tasks, recently_completed_tasks (each a queryset or list).
    """
    from startScan.models import ScanActivity, ScanHistory, SubScan

    base_scan = (
        ScanHistory.objects.filter(domain__project__slug=project_slug)
        .select_related("domain", "domain__project", "scan_type")
        .annotate(
            subdomain_count=Count("subdomain", distinct=True),
            endpoint_count=Count("endpoint", distinct=True),
            vulnerability_count=Count("vulnerability", distinct=True),
        )
    )
    recently_completed_scans = base_scan.order_by("-start_scan_date").filter(
        Q(scan_status=0) | Q(scan_status=2) | Q(scan_status=3)
    )[:10]
    current_scans = base_scan.order_by("-start_scan_date").filter(Q(scan_status=1) | Q(scan_status=4))
    pending_scans = base_scan.filter(scan_status=-1)

    activity_base = ScanActivity.objects.filter(scan_of__domain__project__slug=project_slug).select_related(
        "scan_of", "scan_of__domain"
    )
    recently_completed_tasks = activity_base.order_by("-time", "-pk").filter(
        Q(status=FAILED_TASK) | Q(status=SUCCESS_TASK)
    )[:15]
    current_tasks = activity_base.order_by("-time", "-pk").filter(status=RUNNING_TASK)[:max_running_tasks]
    pending_tasks = (
        SubScan.objects.filter(scan_history__domain__project__slug=project_slug)
        .filter(status=-1)
        .select_related("scan_history", "scan_history__domain", "subdomain", "engine", "secator_runner")
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

    Returns (queryset, datatable_interesting_names).
    datatable_interesting_names is a set of subdomain names when scan_id is set, else None.
    """

    from startScan.models import EndPoint, Subdomain

    subdomains = Subdomain.objects.filter(target_domain__project__slug=project_slug)
    if is_important:
        subdomains = subdomains.filter(is_important=True)
    if target_id:
        subdomains = subdomains.filter(target_domain__id=target_id)
    elif url_query:
        subdomains = subdomains.filter(Q(target_domain__name=url_query))
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
    else:
        datatable_interesting_names = None

    latest_subdomain_ids = subdomains.values("name").annotate(max_id=Max("id")).values_list("max_id", flat=True)
    base_filter: dict = {"id__in": latest_subdomain_ids}
    if scan_id is not None:
        base_filter["scan_history_id"] = scan_id

    queryset = (
        Subdomain.objects.filter(**base_filter)
        .annotate(
            endpoint_count=Count("endpoint", distinct=True),
            info_count=Count("vulnerability", filter=Q(vulnerability__severity=0), distinct=True),
            low_count=Count("vulnerability", filter=Q(vulnerability__severity=1), distinct=True),
            medium_count=Count("vulnerability", filter=Q(vulnerability__severity=2), distinct=True),
            high_count=Count("vulnerability", filter=Q(vulnerability__severity=3), distinct=True),
            critical_count=Count("vulnerability", filter=Q(vulnerability__severity=4), distinct=True),
            vuln_count=Count("vulnerability", distinct=True),
            subscan_count=Count("subscan", distinct=True),
            todos_count=Count(
                "todonote",
                filter=Q(todonote__is_done=False),
                distinct=True,
            ),
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
