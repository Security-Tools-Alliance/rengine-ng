"""
Centralized scan-scoped lookups for association logic.

Provides consistent IpAddress, EndPoint, Subdomain, and Port resolution within
a scan_history so that Vulnerability and Exploit association helpers share the
same filter patterns and avoid subtle inconsistencies.

Expected model relations (startScan.models). Changes to these will break lookups;
see tests in reNgine/tests/services/repositories/test_scan_lookups.py.
- Subdomain: FK scan_history_id → ScanHistory; M2M ip_addresses (related_name
  "ip_addresses" on IpAddress side) → IpAddress. So IpAddress is "in scan" via
  IpAddress.objects.filter(ip_addresses__scan_history_id=scan_history_id).
- EndPoint: FK scan_history_id → ScanHistory.
- Port: FK ip_address → IpAddress. So Port is "in scan" via
  Port → ip_address → ip_addresses (reverse M2M) → Subdomain.scan_history_id.
"""

from typing import Optional

from startScan.models import EndPoint, IpAddress, Port, Subdomain


def get_ip_in_scan(address: str, scan_history_id: int) -> Optional[IpAddress]:
    """Return IpAddress with given address linked to the scan, or None."""
    return IpAddress.objects.filter(
        address=address.strip(),
        ip_addresses__scan_history_id=scan_history_id,
    ).first()


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
    """Return True if ip_address_id is an IpAddress linked to the scan."""
    if ip_address_id is None:
        return False
    return IpAddress.objects.filter(
        id=ip_address_id,
        ip_addresses__scan_history_id=scan_history_id,
    ).exists()


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
    return Port.objects.filter(
        id=port_id,
        ip_address__ip_addresses__scan_history_id=scan_history_id,
    ).exists()
