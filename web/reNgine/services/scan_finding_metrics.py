"""
Centralized per-scan finding counts for dashboards, APIs, and WebSocket payloads.

Keeps subdomain, endpoint, vulnerability, and IP metrics consistent across surfaces.
IP-in-scan sets (e.g. ip_address_ids_in_scan) follow the same rules as ``reNgine.utilities.scan_lookups``:
Subdomain M2M to IpAddress for the scan, or EndPoint.ip_address on that scan.
(Subdomain rows are not created for IP literals; see SubdomainRepository.get_or_create_from_host.)

Use these entry points to avoid drift:
- Full per-scan dict (WebSocket scan status, scan detail context): get_scan_finding_counts
  (IP keys: SCAN_FINDING_IP_COUNT_KEY, SCAN_FINDING_IP_ALIVE_KEY).
- Distinct IP count only when a full dict is too heavy (e.g. DRF): get_ip_address_total_for_scan
- IP total + alive for one scan: get_ip_address_metrics_for_scan
- List views with prefetch: attach_ip_metrics_to_scans sets SCAN_HISTORY_IP_COUNT_ATTR /
  SCAN_HISTORY_IP_ALIVE_ATTR on each ScanHistory (+ bulk_ip_metrics_for_scans).
- APIs that filter client-supplied IP PKs by scan: partition_ip_address_ids_for_scan_history.
- APIs that filter client-supplied IP PKs by target (all scans of that target): partition_ip_address_ids_for_target.
- Single-PK membership check: ip_address_id_linked_to_scan (shared Q: ip_address_linked_to_scan_q).
- Target / multi-target / project aggregates: get_ip_metrics_for_target,
  get_ip_metrics_for_target_ids, get_ip_metrics_for_project
- Target list views: attach_ip_metrics_to_targets sets TARGET_IP_COUNT_ATTR /
  TARGET_IP_ALIVE_ATTR on each Target (+ bulk_ip_metrics_for_targets).
- Serialized IP widgets (summary, scan detail, reports): ip_addresses_queryset_for_scan,
  ip_addresses_queryset_for_target (same membership as counts above).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Set

from django.db.models import Q, QuerySet

from startScan.models import (
    Domain,
    EndPoint,
    Exploit,
    IpAddress,
    ScanHistory,
    Secret,
    Subdomain,
    Vulnerability,
)


# Keys in get_scan_finding_counts payloads and WebSocket scan_status_update (keep in sync).
SCAN_FINDING_IP_COUNT_KEY = "ip_address_count"
SCAN_FINDING_IP_ALIVE_KEY = "ip_alive_count"

# Dynamic attributes set on ScanHistory by attach_ip_metrics_to_scans (same names as payload keys).
SCAN_HISTORY_IP_COUNT_ATTR = "ip_address_count"
SCAN_HISTORY_IP_ALIVE_ATTR = "ip_alive_count"

# Dynamic attributes set on Target by attach_ip_metrics_to_targets (same string values as above).
TARGET_IP_COUNT_ATTR = "ip_address_count"
TARGET_IP_ALIVE_ATTR = "ip_alive_count"


def ip_address_linked_to_scan_q(scan_history_id: int) -> Q:
    """Filter on IpAddress queryset: linked to the scan via Subdomain M2M or EndPoint.ip_address."""
    return Q(ip_addresses__scan_history_id=scan_history_id) | Q(ip_endpoints__scan_history_id=scan_history_id)


def ip_address_id_linked_to_scan(ip_address_id: int, scan_history_id: int) -> bool:
    """
    True if the IpAddress PK is tied to the scan (same rules as ``ip_address_ids_in_scan`` / ``reNgine.utilities.scan_lookups``).

    Prefer this or ``partition_ip_address_ids_for_scan_history`` over ad-hoc IpAddress filters.
    """
    if not ip_address_id or scan_history_id < 1:
        return False
    return IpAddress.objects.filter(pk=ip_address_id).filter(ip_address_linked_to_scan_q(scan_history_id)).exists()


def ip_address_ids_in_scan(scan_history_id: int) -> Set[int]:
    """Distinct IpAddress PKs tied to the scan (Subdomain M2M or EndPoint.ip_address)."""
    via_m2m = (
        IpAddress.objects.filter(ip_addresses__scan_history_id=scan_history_id).values_list("id", flat=True).distinct()
    )
    via_ep = (
        IpAddress.objects.filter(ip_endpoints__scan_history_id=scan_history_id).values_list("id", flat=True).distinct()
    )
    return set(via_m2m).union(set(via_ep))


def partition_ip_address_ids_for_scan_history(
    ip_ids: Sequence[int],
    scan_history_id: int,
) -> tuple[list[int], list[int]]:
    """
    Split requested IP PKs into those linked to the scan vs not (same order as ``ip_ids``).

    “Linked” matches ``ip_address_ids_in_scan`` / ``reNgine.utilities.scan_lookups``: Subdomain.ip_addresses M2M for the
    scan or ``EndPoint.ip_address`` on that scan.
    """
    allowed = ip_address_ids_in_scan(scan_history_id)
    valid = [i for i in ip_ids if i in allowed]
    invalid = [i for i in ip_ids if i not in allowed]
    return valid, invalid


def ip_address_ids_for_target(target_id: int) -> Set[int]:
    """
    Distinct IpAddress PKs tied to any scan of this target (Subdomain M2M or EndPoint.ip_address).

    Same union semantics as ``ListIPs`` / ``build_ip_datatable_base_queryset`` for ``target_id``.
    """
    if not target_id or target_id < 1:
        return set()
    scan_ids = list(ScanHistory.objects.filter(target_id=target_id).values_list("id", flat=True))
    if not scan_ids:
        return set()
    via_m2m = set(
        IpAddress.objects.filter(ip_addresses__scan_history_id__in=scan_ids).values_list("id", flat=True).distinct()
    )
    via_ep = set(
        IpAddress.objects.filter(ip_endpoints__scan_history_id__in=scan_ids).values_list("id", flat=True).distinct()
    )
    return via_m2m.union(via_ep)


def partition_ip_address_ids_for_target(
    ip_ids: Sequence[int],
    target_id: int,
) -> tuple[list[int], list[int]]:
    """Split requested IP PKs into those linked to the target vs not."""
    allowed = ip_address_ids_for_target(target_id)
    valid = [i for i in ip_ids if i in allowed]
    invalid = [i for i in ip_ids if i not in allowed]
    return valid, invalid


def bulk_ip_metrics_for_targets(target_ids: Iterable[int]) -> Dict[int, tuple[int, int]]:
    """
    Map target_id -> (distinct_ip_count, alive_ip_count) across all scans of that target.

    Same semantics as ``IpAddress.get_counts_for_scan_histories`` over the union of that
    target's scan IDs (Subdomain M2M or EndPoint.ip_address), computed in bulk.
    """
    tid_list: List[int] = list(dict.fromkeys(int(x) for x in target_ids if x))
    if not tid_list:
        return {}
    target_to_ips: Dict[int, Set[int]] = {t: set() for t in tid_list}

    subdomain_pairs = (
        Subdomain.objects.filter(
            scan_history__target_id__in=tid_list,
            ip_addresses__isnull=False,
        )
        .values_list("scan_history__target_id", "ip_addresses__id")
        .distinct()
        .iterator(chunk_size=2000)
    )
    for target_id, ip_id in subdomain_pairs:
        if target_id in target_to_ips and ip_id:
            target_to_ips[target_id].add(ip_id)

    endpoint_pairs = (
        EndPoint.objects.filter(
            scan_history__target_id__in=tid_list,
            ip_address_id__isnull=False,
        )
        .values_list("scan_history__target_id", "ip_address_id")
        .distinct()
        .iterator(chunk_size=2000)
    )
    for target_id, ip_id in endpoint_pairs:
        if target_id in target_to_ips and ip_id:
            target_to_ips[target_id].add(ip_id)

    all_ip_ids: Set[int] = set()
    for s in target_to_ips.values():
        all_ip_ids.update(s)

    alive_map: Dict[int, bool] = {}
    if all_ip_ids:
        for pk, alive in (
            IpAddress.objects.filter(id__in=all_ip_ids).values_list("id", "alive").iterator(chunk_size=2000)
        ):
            alive_map[pk] = bool(alive)

    out: Dict[int, tuple[int, int]] = {}
    for tid in tid_list:
        ip_ids = target_to_ips[tid]
        if not ip_ids:
            out[tid] = (0, 0)
            continue
        alive_n = sum(1 for i in ip_ids if alive_map.get(i))
        out[tid] = (len(ip_ids), alive_n)
    return out


def attach_ip_metrics_to_targets(targets: List[Any]) -> None:
    """Set distinct IP totals on each Target instance (bulk lookup)."""
    if not targets:
        return
    metrics = bulk_ip_metrics_for_targets(t.id for t in targets)
    for t in targets:
        c, a = metrics.get(t.id, (0, 0))
        setattr(t, TARGET_IP_COUNT_ATTR, c)
        setattr(t, TARGET_IP_ALIVE_ATTR, a)


def get_ip_metrics_for_target(target_id: int) -> tuple[int, int]:
    """Distinct IP count and alive count across all scans of the target."""
    metrics = bulk_ip_metrics_for_targets([target_id])
    return metrics.get(int(target_id), (0, 0))


def get_ip_metrics_for_target_ids(target_ids: Iterable[int]) -> tuple[int, int]:
    """Distinct IP and alive counts across all scans of the given targets."""
    tid = [int(x) for x in dict.fromkeys(target_ids) if x]
    if not tid:
        return 0, 0
    scan_ids = list(ScanHistory.objects.filter(target_id__in=tid).values_list("id", flat=True))
    counts = IpAddress.get_counts_for_scan_histories(scan_ids)
    return counts["total"], counts["alive"]


def get_ip_metrics_for_project(project) -> tuple[int, int]:
    """Distinct IP count and alive count across all scans in the project."""
    counts = IpAddress.get_project_counts(project)
    return counts["total"], counts["alive"]


def get_ip_address_metrics_for_scan(scan_history_id: int) -> tuple[int, int]:
    """Return (distinct_ip_count, alive_ip_count) for the scan."""
    ids = ip_address_ids_in_scan(scan_history_id)
    if not ids:
        return 0, 0
    alive = IpAddress.objects.filter(id__in=ids, alive=True).count()
    return len(ids), alive


def get_ip_address_total_for_scan(scan_history_id: int) -> int:
    """Distinct IP count for one scan; matches ip_address_count in get_scan_finding_counts."""
    total, _alive = get_ip_address_metrics_for_scan(scan_history_id)
    return total


def get_scan_finding_counts(scan_history_id: int) -> Dict[str, Any]:
    """
    Return counts for a single ScanHistory (dashboard tiles, WebSocket, API parity).

    Keys align with send_scan_status_update / project dashboard expectations.
    """
    domain_count = Domain.objects.filter(scan_history_id=scan_history_id).count()
    subdomain_count = Subdomain.objects.filter(scan_history_id=scan_history_id).count()
    alive_count = Subdomain.objects.filter(scan_history_id=scan_history_id, http_status__gt=0).count()
    endpoint_count = EndPoint.objects.filter(scan_history_id=scan_history_id).count()
    endpoint_alive_count = EndPoint.objects.filter(scan_history_id=scan_history_id, http_status__gt=0).count()
    vulnerability_count = Vulnerability.objects.filter(scan_history_id=scan_history_id).count()
    secret_count = Secret.objects.filter(scan_history_id=scan_history_id).count()
    exploit_count = Exploit.objects.filter(scan_history_id=scan_history_id).count()
    ip_address_count, ip_alive_count = get_ip_address_metrics_for_scan(scan_history_id)
    return {
        "domain_count": domain_count,
        "subdomain_count": subdomain_count,
        "alive_count": alive_count,
        "endpoint_count": endpoint_count,
        "endpoint_alive_count": endpoint_alive_count,
        "vulnerability_count": vulnerability_count,
        "secret_count": secret_count,
        "exploit_count": exploit_count,
        "ip_address_count": ip_address_count,
        "ip_alive_count": ip_alive_count,
    }


def bulk_ip_metrics_for_scans(scan_ids: Iterable[int]) -> Dict[int, tuple[int, int]]:
    """
    Map scan_history_id -> (ip_address_count, ip_alive_count).

    Uses a bounded number of queries (not one per scan for the IP dimension).
    Subdomain and EndPoint source queries use ``.distinct()`` and ``iterator()`` so duplicate
    join rows (same IP on many subdomains) do not inflate memory or row fetches before the
    per-scan ``set`` deduplication.
    """
    ids_list: List[int] = list(dict.fromkeys(int(x) for x in scan_ids if x))
    if not ids_list:
        return {}

    scan_to_ips: Dict[int, Set[int]] = {sid: set() for sid in ids_list}

    subdomain_pairs = (
        Subdomain.objects.filter(
            scan_history_id__in=ids_list,
            ip_addresses__isnull=False,
        )
        .values_list("scan_history_id", "ip_addresses__id")
        .distinct()
        .iterator(chunk_size=2000)
    )
    for scan_history_id, ip_id in subdomain_pairs:
        if scan_history_id in scan_to_ips and ip_id:
            scan_to_ips[scan_history_id].add(ip_id)

    endpoint_pairs = (
        EndPoint.objects.filter(
            scan_history_id__in=ids_list,
            ip_address_id__isnull=False,
        )
        .values_list("scan_history_id", "ip_address_id")
        .distinct()
        .iterator(chunk_size=2000)
    )
    for scan_history_id, ip_id in endpoint_pairs:
        if scan_history_id in scan_to_ips and ip_id:
            scan_to_ips[scan_history_id].add(ip_id)

    all_ip_ids: Set[int] = set()
    for s in scan_to_ips.values():
        all_ip_ids.update(s)

    alive_map: Dict[int, bool] = {}
    if all_ip_ids:
        for pk, alive in (
            IpAddress.objects.filter(id__in=all_ip_ids).values_list("id", "alive").iterator(chunk_size=2000)
        ):
            alive_map[pk] = bool(alive)

    out: Dict[int, tuple[int, int]] = {}
    for sid in ids_list:
        ip_ids = scan_to_ips[sid]
        if not ip_ids:
            out[sid] = (0, 0)
            continue
        alive_n = sum(1 for i in ip_ids if alive_map.get(i))
        out[sid] = (len(ip_ids), alive_n)
    return out


def ip_addresses_queryset_for_scan(scan_history_id: int) -> QuerySet[IpAddress]:
    """
    IpAddress rows linked to the scan (M2M or EndPoint.ip_address), with ports prefetched.

    Matches ``ip_address_ids_in_scan`` / ``get_ip_address_metrics_for_scan`` semantics.
    """
    if not scan_history_id or scan_history_id < 1:
        return IpAddress.objects.none()
    ids = ip_address_ids_in_scan(scan_history_id)
    if not ids:
        return IpAddress.objects.none()
    return IpAddress.objects.filter(pk__in=ids).prefetch_related("ports").order_by("address", "id")


def ip_addresses_queryset_for_target(target_id: int) -> QuerySet[IpAddress]:
    """
    IpAddress rows linked to any scan of the target (M2M or EndPoint.ip_address), ports prefetched.

    Matches ``ip_address_ids_for_target`` / ``get_ip_metrics_for_target`` semantics.
    """
    if not target_id or target_id < 1:
        return IpAddress.objects.none()
    ids = ip_address_ids_for_target(target_id)
    if not ids:
        return IpAddress.objects.none()
    return IpAddress.objects.filter(pk__in=ids).prefetch_related("ports").order_by("address", "id")


def attach_ip_metrics_to_scans(scans: List[ScanHistory]) -> None:
    """
    Set distinct IP totals on each ScanHistory (bulk lookup).

    Sets attributes named SCAN_HISTORY_IP_COUNT_ATTR and SCAN_HISTORY_IP_ALIVE_ATTR
    (same string values as SCAN_FINDING_IP_COUNT_KEY / SCAN_FINDING_IP_ALIVE_KEY).
    """
    if not scans:
        return
    metrics = bulk_ip_metrics_for_scans(s.id for s in scans)
    for s in scans:
        c, a = metrics.get(s.id, (0, 0))
        setattr(s, SCAN_HISTORY_IP_COUNT_ATTR, c)
        setattr(s, SCAN_HISTORY_IP_ALIVE_ATTR, a)
