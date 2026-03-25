"""
Build large, structured recon payloads for aggregate LLM attack-surface analysis.

Used for Target, Scope, Organization, and ScanHistory levels. Applies row caps and includes
explicit truncation notices so the model can avoid hallucinating missing data.
"""

from __future__ import annotations

from collections.abc import Sequence
import json

from django.db.models import Case, Count, IntegerField, Prefetch, Q, QuerySet, When

from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Organization, Scope, Target


MAX_SUBDOMAINS_IN_CONTEXT = 500
MAX_IPS_IN_CONTEXT = 250
MAX_VULN_ROWS_IN_CONTEXT = 150
MAX_CONTEXT_CHARS = 115_000
SCAN_CONFIG_SUMMARY_MAX_CHARS = 700


def _scan_config_summary(config: object | None) -> str:
    if config is None:
        return "(none)"
    try:
        text = json.dumps(config, sort_keys=True, default=str)
    except TypeError:
        text = str(config)
    if len(text) > SCAN_CONFIG_SUMMARY_MAX_CHARS:
        return "%s\n... (scan_config truncated)" % (text[:SCAN_CONFIG_SUMMARY_MAX_CHARS],)
    return text


def _collect_target_ids_for_scope(scope: Scope) -> list[int]:
    return list(scope.targets.values_list("pk", flat=True))


def _collect_target_ids_for_organization(organization: Organization) -> list[int]:
    return list(organization.get_targets().values_list("pk", flat=True))


def _vulnerability_summary_for_targets(target_ids: Sequence[int]) -> str:
    if not target_ids:
        return "No targets; vulnerability summary omitted."
    base = Vulnerability.objects.filter(scan_history__target_id__in=target_ids)
    total = base.count()
    by_sev = base.values("severity").annotate(n=Count("id")).order_by("severity")
    sev_parts = ["%s:%s" % (row["severity"], row["n"]) for row in by_sev]
    lines = ["Total vulnerabilities (linked scans on these targets): %s" % (total,)]
    lines.append("By severity code: %s" % (", ".join(sev_parts) if sev_parts else "none",))
    sample = base.order_by("-severity", "id").values_list("name", flat=True)[:MAX_VULN_ROWS_IN_CONTEXT]
    names = list(sample)
    for name in names:
        lines.append("- %s" % (name[:300],))
    if total > len(names):
        lines.append(
            "... (%s more vulnerabilities not listed; list truncated at %s rows)"
            % (total - len(names), MAX_VULN_ROWS_IN_CONTEXT)
        )
    return "\n".join(lines)


def _ip_block_for_targets(target_ids: Sequence[int]) -> str:
    if not target_ids:
        return "(no targets)\n"
    base_qs = (
        IpAddress.objects.filter(
            Q(ip_addresses__scan_history__target_id__in=target_ids)
            | Q(ip_endpoints__scan_history__target_id__in=target_ids)
        )
        .distinct()
        .prefetch_related("ports")
        .order_by("id")
    )
    rows = list(base_qs[: MAX_IPS_IN_CONTEXT + 1])
    truncated = len(rows) > MAX_IPS_IN_CONTEXT
    rows = rows[:MAX_IPS_IN_CONTEXT]
    lines = []
    for ip_row in rows:
        ports = ", ".join("%s/%s" % (p.number, p.service_name or "") for p in ip_row.ports.all()[:40])
        lines.append(
            "IP: %s | alive=%s | cdn=%s | proto=%s | ptr=%s | ports=%s"
            % (
                ip_row.address,
                ip_row.alive,
                ip_row.is_cdn,
                ip_row.protocol or "",
                ip_row.reverse_pointer or "",
                ports[:500],
            )
        )
    body = "\n".join(lines) + "\n"
    if truncated:
        body += "\n... (more IP rows exist; list truncated at %s)\n" % (MAX_IPS_IN_CONTEXT,)
    return body


def _subdomain_block_for_targets(target_ids: Sequence[int]) -> str:
    if not target_ids:
        return "(no targets)\n"
    base_qs: QuerySet[Subdomain] = (
        Subdomain.objects.filter(scan_history__target_id__in=target_ids)
        .distinct()
        .prefetch_related("technologies")
        .order_by("id")
    )
    rows = list(base_qs[: MAX_SUBDOMAINS_IN_CONTEXT + 1])
    truncated = len(rows) > MAX_SUBDOMAINS_IN_CONTEXT
    rows = rows[:MAX_SUBDOMAINS_IN_CONTEXT]
    lines = []
    for s in rows:
        tech_names = list(s.technologies.values_list("name", flat=True)[:20])
        tech = ",".join(tech_names)
        lines.append(
            "%s | http_status=%s | title=%s | webserver=%s | tech=%s | cdn=%s"
            % (
                s.name,
                s.http_status,
                (s.page_title or "")[:120],
                (s.webserver or "")[:80],
                tech[:400],
                s.is_cdn,
            )
        )
    body = "\n".join(lines) + "\n"
    if truncated:
        body += "\n... (more subdomains exist; list truncated at %s)\n" % (MAX_SUBDOMAINS_IN_CONTEXT,)
    return body


def _scan_stats_for_targets(target_ids: Sequence[int]) -> str:
    if not target_ids:
        return "Scan count: 0"
    n = ScanHistory.objects.filter(target_id__in=target_ids).count()
    return "ScanHistory rows for these targets: %s" % (n,)


def _build_aggregate_body(target_ids: Sequence[int], analysis_header: str) -> str:
    scan_line = _scan_stats_for_targets(target_ids)
    sub_block = _subdomain_block_for_targets(target_ids)
    ip_block = _ip_block_for_targets(target_ids)
    vuln_block = _vulnerability_summary_for_targets(target_ids)
    parts = [
        analysis_header.strip(),
        "",
        "=== SCAN_SUMMARY ===",
        scan_line,
        "",
        "=== SUBDOMAINS ===",
        sub_block,
        "",
        "=== IP_ADDRESSES ===",
        ip_block,
        "",
        "=== VULNERABILITIES ===",
        vuln_block,
    ]
    text = "\n".join(parts)
    if len(text) > MAX_CONTEXT_CHARS:
        return text[:MAX_CONTEXT_CHARS] + "\n\n... (overall context truncated at %s characters)\n" % (
            MAX_CONTEXT_CHARS,
        )
    return text


def build_context_for_target(target: Target) -> str:
    header = "Analysis level: single Target\nTarget id=%s value=%s type=%s\nTarget scan_config (summary): %s\n" % (
        target.id,
        target.value,
        target.target_type,
        _scan_config_summary(target.scan_config),
    )
    return _build_aggregate_body([target.id], header)


def build_context_for_scope(scope: Scope) -> str:
    tids = _collect_target_ids_for_scope(scope)
    header = (
        "Analysis level: Scope\n"
        "Scope id=%s name=%s type=%s\n"
        "Organization id=%s name=%s\n"
        "Dates: start=%s end=%s\n"
        "Description: %s\n"
        "Scope scan_config (summary): %s\n"
        "Target count in scope: %s\n"
        "Target ids: %s\n"
        % (
            scope.id,
            scope.name,
            scope.scope_type,
            scope.organization_id,
            scope.organization.name,
            scope.start_date,
            scope.end_date,
            (scope.description or "")[:800],
            _scan_config_summary(scope.scan_config),
            len(tids),
            ",".join(str(x) for x in tids[:200]) + ("..." if len(tids) > 200 else ""),
        )
    )
    return _build_aggregate_body(tids, header)


def build_context_for_organization(organization: Organization) -> str:
    tids = _collect_target_ids_for_organization(organization)
    header = (
        "Analysis level: Organization\n"
        "Organization id=%s name=%s\n"
        "Description: %s\n"
        "Organization scan_config (summary): %s\n"
        "Aggregated target count: %s\n"
        "Target ids: %s\n"
        % (
            organization.id,
            organization.name,
            (organization.description or "")[:800],
            _scan_config_summary(organization.scan_config),
            len(tids),
            ",".join(str(x) for x in tids[:200]) + ("..." if len(tids) > 200 else ""),
        )
    )
    return _build_aggregate_body(tids, header)


def _vulnerability_summary_for_scan_history(scan_id: int) -> str:
    base = Vulnerability.objects.filter(scan_history_id=scan_id)
    total = base.count()
    severity_weight = Case(
        When(severity=4, then=0),  # CRITICAL
        When(severity=3, then=1),  # HIGH
        When(severity=2, then=2),  # MEDIUM
        When(severity=1, then=3),  # LOW
        When(severity=0, then=4),  # INFO
        When(severity=-1, then=5),  # UNKNOWN
        default=6,
        output_field=IntegerField(),
    )
    by_sev = base.values("severity").annotate(n=Count("id")).order_by(severity_weight)
    sev_parts = ["%s:%s" % (row["severity"], row["n"]) for row in by_sev]
    lines = ["Total vulnerabilities (for this scan): %s" % (total,)]
    lines.append("By severity code: %s" % (", ".join(sev_parts) if sev_parts else "none",))
    sample = base.order_by(severity_weight, "id").values_list("name", flat=True)[:MAX_VULN_ROWS_IN_CONTEXT]
    names = list(sample)
    for name in names:
        lines.append("- %s" % (name[:300],))
    if total > len(names):
        lines.append(
            "... (%s more vulnerabilities not listed; list truncated at %s rows)"
            % (total - len(names), MAX_VULN_ROWS_IN_CONTEXT)
        )
    return "\n".join(lines)


def _ip_block_for_scan_history(scan_id: int) -> str:
    base_qs = (
        IpAddress.objects.filter(Q(ip_addresses__scan_history__id=scan_id) | Q(ip_endpoints__scan_history__id=scan_id))
        .distinct()
        .prefetch_related(Prefetch("ports", queryset=Port.objects.order_by("number", "id")))
        .order_by("id")
    )
    rows = list(base_qs[: MAX_IPS_IN_CONTEXT + 1])
    truncated = len(rows) > MAX_IPS_IN_CONTEXT
    rows = rows[:MAX_IPS_IN_CONTEXT]
    lines = []
    for ip_row in rows:
        ports = ", ".join("%s/%s" % (p.number, p.service_name or "") for p in ip_row.ports.all()[:40])
        lines.append(
            "IP: %s | alive=%s | cdn=%s | proto=%s | ptr=%s | ports=%s"
            % (
                ip_row.address,
                ip_row.alive,
                ip_row.is_cdn,
                ip_row.protocol or "",
                ip_row.reverse_pointer or "",
                ports[:500],
            )
        )
    body = "\n".join(lines) + "\n"
    if truncated:
        body += "\n... (more IP rows found in this scan run; list truncated at %s)\n" % (MAX_IPS_IN_CONTEXT,)
    return body


def _subdomain_block_for_scan_history(scan_id: int) -> str:
    base_qs: QuerySet[Subdomain] = (
        Subdomain.objects.filter(scan_history_id=scan_id).distinct().prefetch_related("technologies").order_by("id")
    )
    rows = list(base_qs[: MAX_SUBDOMAINS_IN_CONTEXT + 1])
    truncated = len(rows) > MAX_SUBDOMAINS_IN_CONTEXT
    rows = rows[:MAX_SUBDOMAINS_IN_CONTEXT]
    lines = []
    for s in rows:
        tech_names = list(s.technologies.values_list("name", flat=True)[:20])
        tech = ",".join(tech_names)
        lines.append(
            "%s | http_status=%s | title=%s | webserver=%s | tech=%s | cdn=%s"
            % (
                s.name,
                s.http_status,
                (s.page_title or "")[:120],
                (s.webserver or "")[:80],
                tech[:400],
                s.is_cdn,
            )
        )
    body = "\n".join(lines) + "\n"
    if truncated:
        body += "\n... (more subdomains found in this scan run; list truncated at %s)\n" % (MAX_SUBDOMAINS_IN_CONTEXT,)
    return body


def build_context_for_scan_history(scan: ScanHistory) -> str:
    target = getattr(scan, "target", None)
    target_value = target.value if target else ""
    target_type = target.target_type if target else ""

    header = (
        "Analysis level: single ScanHistory run\n"
        "ScanHistory id=%s\n"
        "Associated target id=%s value=%s type=%s\n"
        "Scan run status=%s\n"
        "Scan run dates: start=%s stop=%s\n"
        "ScanHistory scan_config (summary): %s\n"
    ) % (
        scan.id,
        scan.target_id,
        target_value,
        target_type,
        scan.scan_status,
        scan.start_scan_date,
        getattr(scan, "stop_scan_date", None),
        _scan_config_summary(scan.scan_config),
    )

    scan_line = "Single scan run (one execution) mapped to the scan_config above."
    sub_block = _subdomain_block_for_scan_history(scan.id)
    ip_block = _ip_block_for_scan_history(scan.id)
    vuln_block = _vulnerability_summary_for_scan_history(scan.id)

    parts = [
        header.strip(),
        "",
        "=== SCAN_RUN_SUMMARY ===",
        scan_line,
        "",
        "=== SUBDOMAINS_IN_SCAN_RUN ===",
        sub_block,
        "",
        "=== IP_ADDRESSES_IN_SCAN_RUN ===",
        ip_block,
        "",
        "=== VULNERABILITIES_IN_SCAN_RUN ===",
        vuln_block,
    ]
    text = "\n".join(parts)
    if len(text) > MAX_CONTEXT_CHARS:
        return text[:MAX_CONTEXT_CHARS] + "\n\n... (overall context truncated at %s characters)\n" % (
            MAX_CONTEXT_CHARS,
        )
    return text
