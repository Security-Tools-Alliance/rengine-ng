"""
Seed ScanHistory, Domain, Subdomain, and IpAddress from IP/DNS discovery UI selections.

Reuses one completed ScanHistory per Target (scan_config.seed_source == ip_discovery) so
repeated imports do not clutter the scan list.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, TypedDict

from django.utils import timezone
import validators

from reNgine.definitions import SCAN_STATUS_COMPLETED
from reNgine.services.repositories.ip_repository import IpRepository
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.domain import normalize_domain_name
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import get_domain_from_subdomain, is_acceptable_subdomain_name, normalize_subdomain_host
from startScan.models import Domain, ScanHistory, Subdomain
from targetApp.models import Target


PREFIX = "[IP_DISCOVERY_SEED]"
logger = get_module_logger(__name__)

IP_DISCOVERY_SEED_SOURCE = "ip_discovery"


class IpDiscoverySeedStats(TypedDict):
    domains_created: int
    domains_existing: int
    subdomains_created: int
    subdomains_existing: int
    ips_created: int
    ips_existing: int


def normalize_apex_for_target(name: str) -> Optional[str]:
    """
    Return registered apex for a target host value, or None if not a valid domain label.
    """
    raw = (name or "").strip()
    if not raw:
        return None
    norm = normalize_domain_name(raw)
    if not norm or not validators.domain(norm):
        return None
    registered = get_domain_from_subdomain(norm)
    return registered or norm


def apex_for_hostname(hostname: str) -> Optional[str]:
    """Registered domain apex for an FQDN, or None if invalid."""
    norm = normalize_domain_name(hostname)
    if not norm:
        return None
    return get_domain_from_subdomain(norm) or norm


def fqdn_under_declared_apex(fqdn: str, apex: str) -> bool:
    """
    True if fqdn is the apex itself or a hostname under that apex (suffix match).

    Used when the user sets an explicit target apex: selections are trusted, but we
    still reject names that are clearly outside that namespace (e.g. nas.local vs ray.local).
    """
    fqdn_n = normalize_domain_name(fqdn or "")
    apex_n = normalize_domain_name(apex or "")
    if not fqdn_n or not apex_n:
        return False
    if fqdn_n == apex_n:
        return True
    return fqdn_n.endswith("." + apex_n)


def _permissive_rengine_context() -> Dict[str, Any]:
    return {"finding_scope_filters": {"host_filter": lambda _h: True}}


def get_or_create_ip_discovery_seed_scan(
    target: Target,
    *,
    initiated_by: Optional[Any] = None,
) -> ScanHistory:
    existing = (
        ScanHistory.objects.filter(
            target_id=target.id,
            scan_config__seed_source=IP_DISCOVERY_SEED_SOURCE,
        )
        .order_by("-id")
        .first()
    )
    if existing:
        return existing
    now = timezone.now()
    scan = ScanHistory.objects.create(
        target=target,
        start_scan_date=now,
        stop_scan_date=now,
        scan_status=SCAN_STATUS_COMPLETED,
        tasks=["ip_discovery_seed"],
        scan_config={"seed_source": IP_DISCOVERY_SEED_SOURCE},
        initiated_by=initiated_by if getattr(initiated_by, "is_authenticated", False) else None,
    )
    logger.log_line(
        PREFIX,
        "SCAN",
        "Created ip_discovery seed ScanHistory id=%s for target_id=%s" % (scan.id, target.id),
        level="info",
    )
    return scan


def _normalize_discovered_names(names: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for raw in names:
        norm = normalize_domain_name(raw or "")
        if not norm or not validators.domain(norm):
            continue
        apex = get_domain_from_subdomain(norm) or norm
        if apex not in seen:
            seen.add(apex)
            out.append(apex)
    return out


def seed_findings_from_ip_discovery(
    target: Target,
    *,
    discovered_domain_names: List[str],
    resolved_host_payloads: List[Dict[str, Any]],
    used_dns_servers: str = "",
    initiated_by: Optional[Any] = None,
    restrict_to_target_apex: Optional[str] = None,
) -> IpDiscoverySeedStats:
    """
    Attach discovery selections to a reusable seed scan for this target.

    Args:
        target: Host-type target whose value is the apex (or compatible).
        discovered_domain_names: Apex names from checked domain boxes (normalized).
        resolved_host_payloads: Dicts with keys domain, ip, is_alive (UI JSON shape).
        used_dns_servers: Optional comma-separated list stored on new Domain rows.
        initiated_by: User for ScanHistory when creating the seed scan.
        restrict_to_target_apex: If set, only host rows and domain names under this apex.
    """
    stats: IpDiscoverySeedStats = {
        "domains_created": 0,
        "domains_existing": 0,
        "subdomains_created": 0,
        "subdomains_existing": 0,
        "ips_created": 0,
        "ips_existing": 0,
    }
    scan = get_or_create_ip_discovery_seed_scan(target, initiated_by=initiated_by)
    dns_value = (used_dns_servers or "").strip() or None

    domain_names = _normalize_discovered_names(discovered_domain_names)
    ra_restrict = normalize_domain_name(restrict_to_target_apex or "")

    now = timezone.now()
    for apex in domain_names:
        defaults: Dict[str, Any] = {"insert_date": now}
        if dns_value:
            defaults["custom_dns_servers"] = dns_value
        _dom, created = Domain.objects.get_or_create(
            scan_history=scan,
            name=apex,
            defaults=defaults,
        )
        if created:
            stats["domains_created"] += 1
        else:
            stats["domains_existing"] += 1

    sub_repo = SubdomainRepository()
    ip_repo = IpRepository()
    ctx = _permissive_rengine_context()
    seen_hosts: set[str] = set()

    for item in resolved_host_payloads:
        hostname = item.get("domain")
        ip = item.get("ip")
        if not hostname or not isinstance(hostname, str):
            continue
        if not ip or not isinstance(ip, str):
            continue
        hn_strip = hostname.strip()
        ip_strip = ip.strip()
        if hn_strip == ip_strip:
            try:
                ipaddress.ip_address(ip_strip)
            except ValueError:
                continue
            ip_obj, ip_created = ip_repo.get_or_create_for_scan(
                scan.id,
                target.id,
                ip_strip,
                alive=bool(item.get("is_alive")),
                rengine_context=ctx,
            )
            if ip_obj:
                if ip_created:
                    stats["ips_created"] += 1
                else:
                    stats["ips_existing"] += 1
            continue
        hn_norm = normalize_domain_name(hostname) or hn_strip.lower()
        if not (validators.domain(hn_strip) or is_acceptable_subdomain_name(hn_norm)):
            continue
        if ra_restrict and not fqdn_under_declared_apex(hn_norm, ra_restrict):
            continue
        norm_host = normalize_subdomain_host(hostname)
        if not norm_host or norm_host in seen_hosts:
            continue
        seen_hosts.add(norm_host)

        had_sub = Subdomain.objects.filter(name=norm_host, scan_history_id=scan.id).exists()
        sub = sub_repo.get_or_create_from_host(
            scan.id,
            target.id,
            hostname,
            rengine_context=ctx,
        )
        if not sub:
            continue
        if not had_sub:
            stats["subdomains_created"] += 1
        else:
            stats["subdomains_existing"] += 1
        if not sub.is_imported_subdomain:
            sub.is_imported_subdomain = True
            sub.save(update_fields=["is_imported_subdomain"])

        is_alive = bool(item.get("is_alive"))
        ip_obj, ip_created = ip_repo.get_or_create_for_scan(
            scan.id,
            target.id,
            ip,
            alive=is_alive,
            rengine_context=ctx,
        )
        if ip_obj:
            sub.ip_addresses.add(ip_obj)
            if ip_created:
                stats["ips_created"] += 1
            else:
                stats["ips_existing"] += 1

    return stats


def compute_total_processed(
    target_created: bool,
    stats: IpDiscoverySeedStats,
    had_selections: bool,
) -> int:
    """Derive a positive count for UX when the operation should count as success."""
    created = (
        (1 if target_created else 0) + stats["domains_created"] + stats["subdomains_created"] + stats["ips_created"]
    )
    if created > 0:
        return created
    if had_selections:
        return 1
    return 1 if target_created else 0
