"""
WHOIS, ASN, and related infrastructure tags from Secator (_type=tag).

This module is not for Secator DNS ``record`` findings (those use DnsRepository).
It groups tag handlers that enrich domain or IP context (raw WHOIS, ASN metadata).
"""

from typing import Any, Dict, Optional, Tuple

from reNgine.core.validators import is_valid_ip
from reNgine.utilities.logger import get_module_logger
from startScan.models import IpAddress


logger = get_module_logger(__name__)

TagHandlerResult = Tuple[Optional[Any], Optional[int]]


def save_asn_from_secator_tag(
    data: Dict[str, Any],
    scan_history_id: int,
    target_id: int,
) -> Optional[Any]:
    """
    Store ASN info from Secator getasn tag on IpAddress (if match is IP) or DomainInfo (if match is host/domain).

    Returns the saved object (IpAddress or DomainInfo) with .id for API response, or None on failure.
    """
    match = (data.get("match") or "").strip()
    value = (data.get("value") or "").strip()
    if not match:
        logger.log_line(
            "[TAG_ASN]",
            "SAVE",
            "ASN tag: empty match",
            level="warning",
        )
        return None
    if not value:
        logger.log_line(
            "[TAG_ASN]",
            "SAVE",
            "ASN tag: empty value",
            level="warning",
        )
        return None

    if is_valid_ip(match):
        ip_obj = IpAddress.objects.filter(
            ip_addresses__scan_history_id=scan_history_id,
            address=match,
        ).first()
        if not ip_obj:
            logger.log_line(
                "[TAG_ASN]",
                "SAVE",
                "ASN tag: no IpAddress found for scan %s and address %s" % (scan_history_id, match),
                level="warning",
            )
            return None
        if ip_obj.extra_data is None:
            ip_obj.extra_data = {}
        ip_obj.extra_data["asn"] = value
        ip_obj.save()
        return ip_obj

    from reNgine.services.repositories.domain_repository import DomainRepository

    domain_info = DomainRepository().save_asn_from_secator_tag(scan_history_id, target_id, match, value)
    return domain_info


def handle_whois_tag(data: Dict[str, Any], scan_history_id: int, target_id: int) -> TagHandlerResult:
    from reNgine.services.repositories.domain_repository import DomainRepository

    domain_name = (data.get("match") or "").strip()
    value = data.get("value") or ""
    obj = DomainRepository().save_raw_whois_from_secator_tag(scan_history_id, target_id, domain_name, value)
    if obj is not None:
        return (obj, None)
    return (None, 422)


def handle_asn_tag(data: Dict[str, Any], scan_history_id: int, target_id: int) -> TagHandlerResult:
    obj = save_asn_from_secator_tag(data, scan_history_id, target_id)
    if obj is not None:
        return (obj, None)
    return (None, 422)
