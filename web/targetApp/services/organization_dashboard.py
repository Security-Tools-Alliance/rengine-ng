"""
Organization dashboard service.

Builds all aggregate data and feeds for the organization dashboard view,
filtered by targets belonging to the organization (direct + via scopes).
"""

from datetime import timedelta
from typing import Any

from django.db.models import Count, Max, Q
from django.utils import timezone

from reNgine.utilities.time import date_to_aware_datetime
from startScan.models import (
    CveId,
    CweId,
    Domain,
    EndPoint,
    Exploit,
    ScanActivity,
    ScanHistory,
    Subdomain,
    SubScan,
    Vulnerability,
    VulnerabilityTags,
)
from targetApp.models import Organization


def _target_ids_queryset(organization: Organization):
    """Return target IDs for this organization (direct + via scopes)."""
    return organization.get_targets().values_list("id", flat=True)


def _target_filter(target_ids: list[int]) -> Q:
    """Q filter for scan_history__target_id__in=target_ids; empty list => no match."""
    return Q(pk=-1) if not target_ids else Q(scan_history__target_id__in=target_ids)


def get_organization_dashboard_data(organization: Organization) -> dict[str, Any]:
    """
    Build dashboard context for an organization.

    All counts, feeds, and timelines are restricted to targets belonging to
    this organization (organization.get_targets()).
    """
    target_ids = list(_target_ids_queryset(organization))
    scan_target_q = _target_filter(target_ids)

    # Scopes list with summary (name, type, target count)
    scopes_data = []
    for scope in organization.scopes.all().prefetch_related("targets").order_by("name"):
        scopes_data.append(
            {
                "id": scope.id,
                "name": scope.name,
                "scope_type": scope.scope_type,
                "scope_type_display": scope.get_scope_type_display(),
                "target_count": scope.targets.count(),
            }
        )

    scope_count = len(scopes_data)
    target_count = len(target_ids)

    if not target_ids:
        return _empty_dashboard_context(
            organization=organization,
            scope_count=scope_count,
            scopes_data=scopes_data,
        )

    # Domain counts (domains = scan findings, one per scan/target)
    domain_counts = Domain.get_all_counts(Domain.objects.filter(scan_target_q))

    # Subdomain counts: unique by name (latest id per name) then get_all_counts
    latest_subdomain_ids = (
        Subdomain.objects.filter(scan_target_q)
        .values("name")
        .annotate(max_id=Max("id"))
        .values_list("max_id", flat=True)
    )
    subdomain_queryset = Subdomain.objects.filter(id__in=latest_subdomain_ids)
    subdomain_counts = Subdomain.get_all_counts(subdomain_queryset)

    # Endpoint counts: unique by http_url
    latest_endpoint_ids = (
        EndPoint.objects.filter(scan_target_q)
        .values("http_url")
        .annotate(max_id=Max("id"))
        .values_list("max_id", flat=True)
    )
    endpoint_queryset = EndPoint.objects.filter(id__in=latest_endpoint_ids)
    endpoint_counts = EndPoint.get_counts(endpoint_queryset)

    # ScanHistory counts
    scan_history_counts = ScanHistory.get_all_counts(ScanHistory.objects.filter(target_id__in=target_ids))

    # SubScan counts
    subscan_counts = SubScan.get_all_counts(SubScan.objects.filter(scan_target_q))

    # Activity feed (scan_of = ScanHistory)
    activity_feed = (
        ScanActivity.objects.filter(scan_of__target_id__in=target_ids)
        .select_related("scan_of", "scan_of__target")
        .order_by("-time")[:50]
    )

    # Vulnerability data: feed + most_common (critical first, then by date; sort in Python to guarantee order)
    vuln_queryset = Vulnerability.objects.filter(scan_target_q)
    # KPI counts from vulns directly (same scope as feed), not from subdomain dedup to match feed
    vuln_counts_direct = vuln_queryset.aggregate(
        vuln_info=Count("id", filter=Q(severity=0)),
        vuln_low=Count("id", filter=Q(severity=1)),
        vuln_medium=Count("id", filter=Q(severity=2)),
        vuln_high=Count("id", filter=Q(severity=3)),
        vuln_critical=Count("id", filter=Q(severity=4)),
        vuln_unknown=Count("id", filter=Q(severity=-1)),
    )
    total_vul_direct = sum(vuln_counts_direct.get(k, 0) or 0 for k in vuln_counts_direct)
    total_vul_ignore_info_direct = (
        (vuln_counts_direct.get("vuln_low") or 0)
        + (vuln_counts_direct.get("vuln_medium") or 0)
        + (vuln_counts_direct.get("vuln_high") or 0)
        + (vuln_counts_direct.get("vuln_critical") or 0)
    )
    vuln_feed_qs = vuln_queryset.select_related("subdomain", "endpoint", "domain", "scan_history").prefetch_related(
        "cve_ids", "cwe_ids", "tags"
    )[:200]
    vuln_list = list(vuln_feed_qs)
    # Critical (4) first, then High (3), Medium (2), Low (1), Info (0), Unknown (-1); same severity = newest first
    vuln_feed = sorted(
        vuln_list,
        key=lambda v: (
            v.severity,
            v.discovered_date.timestamp() if v.discovered_date else 0,
        ),
        reverse=True,
    )[:50]
    vuln_full_queryset = vuln_queryset  # for most_common over all org vulns
    most_common_cve = list(CveId.get_most_common(vuln_full_queryset))
    most_common_cwe = list(CweId.get_most_common(vuln_full_queryset))
    most_common_tags = list(VulnerabilityTags.get_most_common(vuln_full_queryset))

    # Timeline (last 7 days)
    last_week = timezone.now() - timedelta(days=7)
    date_range = [last_week + timedelta(days=i) for i in range(7)]

    def timeline_for_queryset(qs, date_field: str):
        if not target_ids:
            return [0] * 7
        raw = _counts_by_date(qs, date_field, date_range[0])
        return [_raw_for_date(raw, d) for d in date_range][::-1]

    targets_timeline = timeline_for_queryset(Domain.objects.filter(scan_target_q), "insert_date")
    subdomains_timeline = timeline_for_queryset(Subdomain.objects.filter(scan_target_q), "discovered_date")
    vulns_timeline = timeline_for_queryset(Vulnerability.objects.filter(scan_target_q), "discovered_date")
    endpoints_timeline = timeline_for_queryset(EndPoint.objects.filter(scan_target_q), "discovered_date")

    scan_timeline_pending = _scan_timeline(ScanHistory, target_ids, date_range, status=0)
    scan_timeline_running = _scan_timeline(ScanHistory, target_ids, date_range, status=1)
    scan_timeline_completed = _scan_timeline(ScanHistory, target_ids, date_range, status=2)
    scan_timeline_failed = _scan_timeline(ScanHistory, target_ids, date_range, status=3)

    subscan_timeline_pending = _subscan_timeline(target_ids, date_range, status=-1)
    subscan_timeline_running = _subscan_timeline(target_ids, date_range, status=1)
    subscan_timeline_completed = _subscan_timeline(target_ids, date_range, status=2)
    subscan_timeline_failed = _subscan_timeline(target_ids, date_range, status=0)
    subscan_timeline_aborted = _subscan_timeline(target_ids, date_range, status=3)
    subscan_timeline_finalizing = _subscan_timeline(target_ids, date_range, status=4)

    domain_total = domain_counts.get("total") or 0
    exploit_total = Exploit.objects.filter(scan_history__target_id__in=target_ids).count()

    return {
        "organization": organization,
        "scope_count": scope_count,
        "scopes_data": scopes_data,
        "target_count": target_count,
        "domain_count": domain_total,
        "scan_count": scan_history_counts,
        "subscan_count": subscan_counts,
        "subdomain_count": subdomain_counts.get("total") or 0,
        "subdomain_with_ip_count": subdomain_counts.get("with_ip") or 0,
        "alive_count": subdomain_counts.get("alive") or 0,
        "endpoint_count": endpoint_counts.get("total") or 0,
        "endpoint_alive_count": endpoint_counts.get("alive") or 0,
        "info_count": vuln_counts_direct.get("vuln_info") or 0,
        "low_count": vuln_counts_direct.get("vuln_low") or 0,
        "medium_count": vuln_counts_direct.get("vuln_medium") or 0,
        "high_count": vuln_counts_direct.get("vuln_high") or 0,
        "critical_count": vuln_counts_direct.get("vuln_critical") or 0,
        "unknown_count": vuln_counts_direct.get("vuln_unknown") or 0,
        "total_vul_count": total_vul_direct,
        "total_vul_ignore_info_count": total_vul_ignore_info_direct,
        "organization_exploit_count": exploit_total,
        "vulnerability_feed": vuln_feed,
        "activity_feed": activity_feed,
        "most_common_cve": most_common_cve,
        "most_common_cwe": most_common_cwe,
        "most_common_tags": most_common_tags,
        "targets_in_last_week": targets_timeline,
        "subdomains_in_last_week": subdomains_timeline,
        "vulns_in_last_week": vulns_timeline,
        "endpoints_in_last_week": endpoints_timeline,
        "scans_in_last_week": {
            "pending": scan_timeline_pending,
            "running": scan_timeline_running,
            "completed": scan_timeline_completed,
            "failed": scan_timeline_failed,
        },
        "subscans_in_last_week": {
            "pending": subscan_timeline_pending,
            "running": subscan_timeline_running,
            "completed": subscan_timeline_completed,
            "failed": subscan_timeline_failed,
            "aborted": subscan_timeline_aborted,
            "finalizing": subscan_timeline_finalizing,
        },
    }


def _empty_dashboard_context(
    organization: Organization,
    scope_count: int,
    scopes_data: list[dict],
) -> dict[str, Any]:
    """Return dashboard context when organization has no targets."""
    empty_timeline = [0] * 7
    return {
        "organization": organization,
        "scope_count": scope_count,
        "scopes_data": scopes_data,
        "target_count": 0,
        "domain_count": 0,
        "scan_count": {"total": 0, "pending": 0, "running": 0, "completed": 0, "failed": 0},
        "subscan_count": {"total": 0, "pending": 0, "running": 0, "completed": 0, "failed": 0},
        "subdomain_count": 0,
        "subdomain_with_ip_count": 0,
        "alive_count": 0,
        "endpoint_count": 0,
        "endpoint_alive_count": 0,
        "info_count": 0,
        "low_count": 0,
        "medium_count": 0,
        "high_count": 0,
        "critical_count": 0,
        "unknown_count": 0,
        "total_vul_count": 0,
        "total_vul_ignore_info_count": 0,
        "organization_exploit_count": 0,
        "vulnerability_feed": [],
        "activity_feed": [],
        "most_common_cve": [],
        "most_common_cwe": [],
        "most_common_tags": [],
        "targets_in_last_week": empty_timeline,
        "subdomains_in_last_week": empty_timeline,
        "vulns_in_last_week": empty_timeline,
        "endpoints_in_last_week": empty_timeline,
        "scans_in_last_week": {
            "pending": empty_timeline,
            "running": empty_timeline,
            "completed": empty_timeline,
            "failed": empty_timeline,
        },
        "subscans_in_last_week": {
            "pending": empty_timeline,
            "running": empty_timeline,
            "completed": empty_timeline,
            "failed": empty_timeline,
            "aborted": empty_timeline,
            "finalizing": empty_timeline,
        },
    }


def _counts_by_date(queryset, date_field: str, since_date):
    """Daily counts for a queryset by date field (replicate model get_counts_by_date)."""
    from django.db.models.functions import TruncDay

    counts = (
        queryset.filter(**{f"{date_field}__gte": since_date})
        .annotate(date=TruncDay(date_field))
        .values("date")
        .annotate(count=Count("id"))
        .order_by("date")
    )
    return {item["date"]: item["count"] for item in counts}


def _raw_for_date(raw_data: dict, date) -> int:
    aware = date_to_aware_datetime(date)
    return raw_data.get(aware, 0)


def _scan_timeline(model, target_ids: list[int], date_range, status: int) -> list[int]:
    if not target_ids:
        return [0] * 7
    qs = model.objects.filter(target_id__in=target_ids, scan_status=status)
    raw = _counts_by_date(qs, "start_scan_date", date_range[0])
    return [_raw_for_date(raw, d) for d in date_range][::-1]


def _subscan_timeline(target_ids: list[int], date_range, status: int) -> list[int]:
    if not target_ids:
        return [0] * 7
    qs = SubScan.objects.filter(scan_history__target_id__in=target_ids, status=status)
    raw = _counts_by_date(qs, "start_scan_date", date_range[0])
    return [_raw_for_date(raw, d) for d in date_range][::-1]
