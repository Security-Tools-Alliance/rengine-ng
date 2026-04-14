"""
Query-building helpers for API views.

Extracts complex queryset logic from views (e.g. ScanStatus, SubdomainDatatableViewSet)
to keep view methods short and testable.
"""

from collections import defaultdict
from typing import Any, Optional, Union

from django.db.models import Max, Prefetch, Q
from django.db.models.query import QuerySet

from reNgine.core.data import safe_int_cast
from reNgine.definitions import (
    FAILED_TASK,
    RUNNING_TASK,
    SCAN_STATUS_PENDING,
    SCAN_STATUSES_CURRENT,
    SCAN_STATUSES_RECENTLY_COMPLETED,
    SUCCESS_TASK,
)
from reNgine.llm.attack_surface_storage import annotate_queryset_with_llm_attack_surface_count
from reNgine.services.default_endpoint_queryset import subdomain_all_endpoints_for_tech_queryset
from reNgine.utilities.db import count_subquery, count_subquery_related
from reNgine.utilities.subdomain import get_interesting_subdomains


def datatable_port_services_serializer_context(port_query_param: Any) -> dict[str, Any]:
    """
    Context fragment for ``IpSerializer`` / ``SubdomainSerializer`` ``services_for_request_port``.

    Prefer ``datatable_ip_list_serializer_context`` or ``datatable_subdomain_list_serializer_context``
    in list views so ``scan_id``, ``target_id``, and port flags stay wired consistently.
    """
    port_filter = safe_int_cast(port_query_param)
    port_filter_ok = isinstance(port_filter, int) and 1 <= port_filter <= 65535
    return {
        "filter_port_number": port_filter if port_filter_ok else None,
        "expose_ip_port_services": port_filter_ok,
    }


def datatable_ip_list_serializer_context(
    *,
    scan_id: Any = None,
    target_id: Any = None,
    port_query_param: Any = None,
    ip_subdomain_data: Optional[dict] = None,
) -> dict[str, Any]:
    """
    Serializer context for ``IpSerializer`` list/DataTables (``ListIPs``).

    Includes ``scan_id``, ``target_id``, port-service column flags, and optional
    ``ip_subdomain_data`` from ``get_ip_subdomain_data``.
    """
    ctx: dict[str, Any] = {
        "scan_id": safe_int_cast(scan_id),
        "target_id": safe_int_cast(target_id),
        **datatable_port_services_serializer_context(port_query_param),
    }
    if ip_subdomain_data is not None:
        ctx["ip_subdomain_data"] = ip_subdomain_data
    return ctx


def datatable_subdomain_list_serializer_context(
    *,
    scan_id: Any = None,
    target_id: Any = None,
    port_query_param: Any = None,
    datatable_interesting_names: Optional[set[str]] = None,
) -> dict[str, Any]:
    """
    Serializer context for ``SubdomainSerializer`` list/DataTables (``ListSubdomains``).

    Sets ``scan_id`` and ``target_id`` for nested ``IpSerializer`` rows and default-endpoint
    scoping in ``DefaultEndpointTechnologyMixin``. Omits ``datatable_interesting_names`` when
    ``None`` so ``get_is_interesting`` keeps its per-row query fallback.
    """
    ctx: dict[str, Any] = {
        "scan_id": safe_int_cast(scan_id),
        "target_id": safe_int_cast(target_id),
        **datatable_port_services_serializer_context(port_query_param),
    }
    if datatable_interesting_names is not None:
        ctx["datatable_interesting_names"] = datatable_interesting_names
    return ctx


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


def build_endpoint_datatable_queryset(request: Any) -> QuerySet:
    """
    EndPoint rows for the endpoint DataTable: latest id per http_url within request scope.
    Same filters as EndPointViewSet list / advanced-search distinct values.
    """
    from reNgine.services.default_endpoint_queryset import apply_endpoint_techs_prefetch
    from startScan.models import EndPoint

    req = datatable_request_params(request)
    scan_id = safe_int_cast(req.get("scan_history")) or safe_int_cast(req.get("scan_id"))
    target_id = safe_int_cast(req.get("target_id"))
    url_query = req.get("query_param")
    subdomain_id = safe_int_cast(req.get("subdomain_id"))
    project = (req.get("project") or "").strip()
    if not project:
        return EndPoint.objects.none()

    endpoints = EndPoint.objects.filter(scan_history__target__project__slug=project)
    if scan_id:
        endpoints = endpoints.filter(scan_history__id=scan_id)
    if url_query:
        endpoints = endpoints.filter(Q(domain__name=url_query))
    if "gf_tag" in req and req.get("gf_tag"):
        endpoints = endpoints.filter(matched_gf_patterns__icontains=req.get("gf_tag"))
    if target_id:
        endpoints = endpoints.filter(domain__scan_history__target_id=target_id)
    if subdomain_id:
        endpoints = endpoints.filter(subdomain__id=subdomain_id)

    latest_ids = endpoints.values("http_url").annotate(max_id=Max("id")).values_list("max_id", flat=True)
    return apply_endpoint_techs_prefetch(EndPoint.objects.filter(id__in=latest_ids).order_by("-scan_history_id", "-id"))


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
    from reNgine.services.default_endpoint_queryset import apply_endpoint_port_and_techs_related
    from startScan.models import Certificate, EndPoint, Subdomain, SubScan, Vulnerability

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

    # When target_id is set, aggregate vulnerability counts by subdomain name (across all scans for that target).
    # Otherwise count by subdomain_id only (single scan or global view).
    target_vuln_filter = {"subdomain__domain__scan_history__target_id": target_id} if target_id is not None else None
    if target_vuln_filter is not None:
        vuln_info = count_subquery_related(
            Vulnerability, "subdomain__name", outer_ref_name="name", filter_kwargs={**target_vuln_filter, "severity": 0}
        )
        vuln_low = count_subquery_related(
            Vulnerability, "subdomain__name", outer_ref_name="name", filter_kwargs={**target_vuln_filter, "severity": 1}
        )
        vuln_medium = count_subquery_related(
            Vulnerability, "subdomain__name", outer_ref_name="name", filter_kwargs={**target_vuln_filter, "severity": 2}
        )
        vuln_high = count_subquery_related(
            Vulnerability, "subdomain__name", outer_ref_name="name", filter_kwargs={**target_vuln_filter, "severity": 3}
        )
        vuln_critical = count_subquery_related(
            Vulnerability, "subdomain__name", outer_ref_name="name", filter_kwargs={**target_vuln_filter, "severity": 4}
        )
        vuln_total = count_subquery_related(
            Vulnerability, "subdomain__name", outer_ref_name="name", filter_kwargs=target_vuln_filter
        )
    else:
        vuln_info = count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 0})
        vuln_low = count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 1})
        vuln_medium = count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 2})
        vuln_high = count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 3})
        vuln_critical = count_subquery(Vulnerability, "subdomain_id", filter_kwargs={"severity": 4})
        vuln_total = count_subquery(Vulnerability, "subdomain_id")

    from reNgine.llm.attack_surface_storage import annotate_subdomain_queryset_with_llm_attack_surface_flag

    # Scalar count subqueries avoid cartesian products vs Count(distinct=...) over joins.
    queryset = annotate_subdomain_queryset_with_llm_attack_surface_flag(
        Subdomain.objects.filter(**base_filter).annotate(
            endpoint_count=count_subquery(EndPoint, "subdomain_id"),
            info_count=vuln_info,
            low_count=vuln_low,
            medium_count=vuln_medium,
            high_count=vuln_high,
            critical_count=vuln_critical,
            vuln_count=vuln_total,
            subscan_count=count_subquery(SubScan, "subdomain_id"),
            certificate_count=count_subquery(Certificate, "subdomain_id"),
            todos_count=count_subquery(TodoNote, "subdomain_id", filter_kwargs={"is_done": False}),
        )
    ).prefetch_related(
        "ip_addresses",
        "ip_addresses__ports",
        "technologies",
        "waf",
        "directories",
        "scan_history",
        Prefetch(
            "endpoint_set",
            queryset=apply_endpoint_port_and_techs_related(subdomain_all_endpoints_for_tech_queryset()),
            to_attr="all_endpoints_for_tech_list",
        ),
    )
    return queryset, datatable_interesting_names


def datatable_request_params(request: Any) -> Any:
    """Query dict for DataTable / advanced-search value requests (DRF or WSGI)."""
    return request.query_params if hasattr(request, "query_params") else request.GET


def parse_subdomain_datatable_request(request: Any) -> dict[str, Any]:
    """
    Parsed filter params for subdomain DataTable and distinct-value APIs.
    Single source for SubdomainViewSet.get_queryset and advanced_search_values.
    """
    req = datatable_request_params(request)
    return {
        "project_slug": (req.get("project") or "").strip(),
        "scan_id": safe_int_cast(req.get("scan_id")),
        "target_id": safe_int_cast(req.get("target_id")),
        "url_query": req.get("query_param"),
        "ip_address": req.get("ip_address"),
        "name": req.get("name"),
        "is_important": "is_important" in req,
        "only_directory": "only_directory" in req,
    }


def subdomain_datatable_from_request(request: Any) -> tuple[QuerySet, Any]:
    """Subdomain queryset and interesting-names set; same scope as the DataTable list."""
    kwargs = parse_subdomain_datatable_request(request)
    return build_subdomain_datatable_queryset(**kwargs)


def build_vulnerability_datatable_base_queryset(request: Any) -> QuerySet:
    """
    Vulnerability rows scoped like VulnerabilityViewSet (filters only, no prefetch).
    Used by distinct-value API and list view base filter.
    """
    from startScan.models import Subdomain, Vulnerability

    req = datatable_request_params(request)
    scan_id = safe_int_cast(req.get("scan_history"))
    target_id = safe_int_cast(req.get("target_id"))
    domain = req.get("domain")
    severity = req.get("severity")
    subdomain_id = safe_int_cast(req.get("subdomain_id"))
    subdomain_name = req.get("subdomain")
    vulnerability_name = req.get("vulnerability_name")
    slug = (req.get("project") or "").strip()

    if slug:
        vulnerabilities = Vulnerability.objects.filter(scan_history__target__project__slug=slug)
    else:
        vulnerabilities = Vulnerability.objects.all()

    if scan_id:
        qs = vulnerabilities.filter(scan_history__id=scan_id).distinct()
    elif target_id:
        qs = vulnerabilities.filter(domain__scan_history__target_id=target_id).distinct()
    elif subdomain_name:
        subdomains = Subdomain.objects.filter(name=subdomain_name)
        qs = vulnerabilities.filter(subdomain__in=subdomains).distinct()
    else:
        qs = vulnerabilities.distinct()

    if domain:
        qs = qs.filter(Q(domain__name=domain)).distinct()
    if vulnerability_name:
        qs = qs.filter(Q(name=vulnerability_name)).distinct()
    if severity:
        qs = qs.filter(severity=severity)
    if subdomain_id:
        qs = qs.filter(subdomain__id=subdomain_id)
    return qs


def build_ip_datatable_base_queryset(request: Any) -> QuerySet:
    """
    IP rows scoped like ListIPs (filters only, no prefetch).
    Used by advanced-search distinct values and ListIPs to avoid diverging filters.

    When both ``scan_id`` and ``target_id`` are present, ``scan_id`` wins so scan-detail
    UIs (e.g. Discovered Ports modal) stay scoped to the current scan. This is intentional:
    do not merge both filters; clients sending both must expect scan-only scope (not an error).

    With neither ``scan_id`` nor ``target_id``, rows are restricted to IPs linked to at least
    one subdomain (``ip_addresses__isnull=False`` on the Subdomain M2M reverse), avoiding a
    subquery over all subdomain primary keys.

    Query param ``port``: if present and parses to an integer in 1..65535, filter by
    ``ports__number``; non-numeric or out-of-range values are ignored (no error response).
    """
    from startScan.models import IpAddress, ScanHistory

    req = datatable_request_params(request)
    scan_id = safe_int_cast(req.get("scan_id"))
    target_id = safe_int_cast(req.get("target_id"))
    port_num = safe_int_cast(req.get("port"))
    port_ok = isinstance(port_num, int) and 1 <= port_num <= 65535

    # scan_id branch first: when both IDs are present, target_id is ignored (see docstring).
    if scan_id:
        ips = IpAddress.objects.filter(
            Q(ip_addresses__scan_history_id=scan_id) | Q(ip_endpoints__scan_history_id=scan_id)
        ).distinct()
    elif target_id:
        scan_ids = ScanHistory.objects.filter(target_id=target_id).values_list("id", flat=True)
        ips = IpAddress.objects.filter(
            Q(ip_addresses__scan_history_id__in=scan_ids) | Q(ip_endpoints__scan_history_id__in=scan_ids)
        ).distinct()
    else:
        # IPs linked to at least one subdomain (M2M); avoids a subquery over all subdomain PKs.
        ips = IpAddress.objects.filter(ip_addresses__isnull=False).distinct()

    if port_ok:
        ips = ips.filter(ports__number=port_num)
    return annotate_queryset_with_llm_attack_surface_count(ips, IpAddress)


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
