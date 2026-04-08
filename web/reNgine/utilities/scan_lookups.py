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
from urllib.parse import urlparse

from django.db.models import Q

from reNgine.core.ip_literal import normalize_ip_address_text
from reNgine.core.validators import is_valid_url
from reNgine.services.scan_finding_metrics import ip_address_id_linked_to_scan
from reNgine.utilities.domain import get_or_create_domain_for_target
from reNgine.utilities.logger import get_module_logger
from startScan.models import Domain, EndPoint, IpAddress, Port, ScanHistory, Subdomain


PREFIX_SCAN_LOOKUPS = "[SCAN_LOOKUPS]"
logger = get_module_logger(__name__)


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


def get_or_create_endpoint_in_scan_for_ingestion(
    http_url: str,
    scan_history_id: int,
    target_id: Optional[int] = None,
) -> Optional[EndPoint]:
    """
    Resolve endpoint in-scan for ingestion flows, creating it when missing.

    This helper is for write paths only (repositories processing Secator findings). It
    keeps lookup/creation policy centralized and reuses ``EndpointRepository.get_or_create``
    so host assignment (subdomain vs ip) follows existing endpoint repository contracts.
    """
    normalized_url = (http_url or "").strip()
    if not normalized_url or not is_valid_url(normalized_url):
        return None
    if endpoint := get_endpoint_in_scan(normalized_url, scan_history_id):
        return endpoint
    scan_target_id = ScanHistory.objects.filter(id=scan_history_id).values_list("target_id", flat=True).first()
    resolved_target_id = scan_target_id or target_id
    if target_id and scan_target_id and target_id != scan_target_id:
        logger.log_line(
            PREFIX_SCAN_LOOKUPS,
            "ENDPOINT_CREATE",
            f"Using scan target_id={scan_target_id} over caller target_id={target_id} for scan_id={scan_history_id}",
            level="debug",
        )
    if not resolved_target_id:
        logger.log_line(
            PREFIX_SCAN_LOOKUPS,
            "ENDPOINT_CREATE",
            f"Cannot create endpoint without target: scan_id={scan_history_id} url={normalized_url[:120]}",
            level="warning",
        )
        return None
    domain = None
    hostname = (urlparse(normalized_url).hostname or "").strip().lower()
    if hostname:
        if subdomain := Subdomain.objects.filter(name=hostname, scan_history_id=scan_history_id).order_by("id").first():
            domain = subdomain.domain
        if not domain:
            host_parts = hostname.split(".")
            candidate_domain_names = [".".join(host_parts[i:]) for i in range(len(host_parts) - 1)]
            matched_domains = Domain.objects.filter(
                scan_history_id=scan_history_id,
                name__in=candidate_domain_names,
            )
            domain = max(matched_domains, key=lambda item: len(item.name), default=None)
        if not domain:
            logger.log_line(
                PREFIX_SCAN_LOOKUPS,
                "ENDPOINT_CREATE",
                (
                    "No scan-scoped domain inferred from hostname: "
                    f"scan_id={scan_history_id} hostname={hostname[:120]} url={normalized_url[:120]}"
                ),
                level="warning",
            )
    else:
        domain = Domain.objects.filter(scan_history_id=scan_history_id).order_by("id").first()
    if not domain:
        domain = get_or_create_domain_for_target(resolved_target_id, scan_history_id)
    if not domain:
        logger.log_line(
            PREFIX_SCAN_LOOKUPS,
            "ENDPOINT_CREATE",
            (
                "Cannot create endpoint without domain: "
                f"scan_id={scan_history_id} "
                f"resolved_target_id={resolved_target_id} "
                f"url={normalized_url[:120]}"
            ),
            level="warning",
        )
        return None
    # Local import avoids repository import cycles at module load time.
    from reNgine.services.repositories.endpoint_repository import EndpointRepository

    endpoint, _ = EndpointRepository().get_or_create(normalized_url, scan_history_id, domain.id)
    return endpoint


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
    return ip_address_id_linked_to_scan(ip_address_id, scan_history_id)


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
