"""
Centralized scan-scoped lookups for association logic.

Provides consistent IpAddress, EndPoint, Subdomain, and Port resolution within
a scan_history so that Vulnerability and Exploit association helpers share the
same filter patterns and avoid subtle inconsistencies.

Expected model relations (startScan.models). Changes to these will break lookups;
see tests in reNgine/tests/utilities/test_scan_lookups.py.
- Subdomain: FK scan_history_id → ScanHistory; M2M ip_addresses → IpAddress.
- EndPoint: FK scan_history_id → ScanHistory; optional FK ip_address → IpAddress (IP-only host).
- IpAddress "in scan": linked from a Subdomain of the scan (M2M) or from an EndPoint of the scan
  with ip_address set.
- Port: FK ip_address → IpAddress; in-scan if that IpAddress is in the scan by the rules above.
"""

from typing import Iterable, Optional

from django.db.models import Q

from reNgine.core.ip_literal import normalize_ip_address_text
from reNgine.services.scan_finding_metrics import ip_address_id_linked_to_scan
from startScan.models import EndPoint, IpAddress, Port, Subdomain


def get_ip_linked_to_scan_ids(address: str, scan_ids: Iterable[int]) -> Optional[IpAddress]:
    """Return IpAddress with given address linked to any of the scans (M2M or IP-backed endpoints)."""
    normalized = normalize_ip_address_text((address or "").strip())
    if not normalized:
        return None
    sid = [int(x) for x in dict.fromkeys(scan_ids) if x]
    if not sid:
        return None
    q = Q(ip_addresses__scan_history_id__in=sid) | Q(ip_endpoints__scan_history_id__in=sid)
    return IpAddress.objects.filter(address=normalized).filter(q).order_by("id").first()


def get_ip_in_scan(address: str, scan_history_id: int) -> Optional[IpAddress]:
    """Return IpAddress with given address linked to the scan (M2M or IP-backed endpoints), or None."""
    return get_ip_linked_to_scan_ids(address, [scan_history_id])


def _ports_linked_to_scan_ids_q(scan_ids: list[int]) -> Q:
    return Q(ip_address__ip_addresses__scan_history_id__in=scan_ids) | Q(
        ip_address__ip_endpoints__scan_history_id__in=scan_ids
    )


def filter_ports_queryset_by_scan_ids(queryset, scan_ids: Iterable[int]):
    """Restrict a Port queryset to rows whose IpAddress is linked to any of the scans (M2M or endpoint)."""
    sid = [int(x) for x in dict.fromkeys(scan_ids) if x]
    if not sid:
        return queryset.none()
    return queryset.filter(_ports_linked_to_scan_ids_q(sid)).distinct()


def get_endpoint_in_scan(http_url: str, scan_history_id: int) -> Optional[EndPoint]:
    """Return EndPoint with given http_url in the scan, or None."""
    return EndPoint.objects.filter(
        http_url=http_url,
        scan_history_id=scan_history_id,
    ).first()


def get_subdomain_in_scan_by_name(name: str, scan_history_id: int) -> Optional[Subdomain]:
    """Return Subdomain with given name (normalized) in the scan, or None."""
    if normalized := (name or "").strip().lower():
        return Subdomain.objects.filter(
            name=normalized,
            scan_history_id=scan_history_id,
        ).first()
    else:
        return None


def subdomain_exists_in_scan(subdomain_id: Optional[int], scan_history_id: int) -> bool:
    """Return True if subdomain_id belongs to the scan."""
    if subdomain_id is None:
        return False
    return Subdomain.objects.filter(
        id=subdomain_id,
        scan_history_id=scan_history_id,
    ).exists()


def endpoint_exists_in_scan(endpoint_id: Optional[int], scan_history_id: int) -> bool:
    """Return True if endpoint_id belongs to the scan."""
    if endpoint_id is None:
        return False
    return EndPoint.objects.filter(
        id=endpoint_id,
        scan_history_id=scan_history_id,
    ).exists()


def ip_exists_in_scan(ip_address_id: Optional[int], scan_history_id: int) -> bool:
    """Return True if ip_address_id is an IpAddress linked to the scan (delegates to scan_finding_metrics)."""
    if ip_address_id is None:
        return False
    return ip_address_id_linked_to_scan(int(ip_address_id), int(scan_history_id))


def get_port_for_ip(ip_address: IpAddress, port_number: int) -> Optional[Port]:
    """Return Port for the given IpAddress and port number, or None."""
    return Port.objects.filter(
        ip_address=ip_address,
        number=port_number,
    ).first()


def port_exists_in_scan(port_id: Optional[int], scan_history_id: int) -> bool:
    """Return True if port_id belongs to an IpAddress linked to the scan."""
    if port_id is None:
        return False
    return Port.objects.filter(id=port_id).filter(_ports_linked_to_scan_ids_q([scan_history_id])).exists()
