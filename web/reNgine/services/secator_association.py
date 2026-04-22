"""
Secator association resolution – single place for precedence and parsing.

Encapsulates how we derive association targets (endpoint URL, subdomain host,
IP, port) from a parsed Secator value (matched_at / http_url) and optional
item_ip. Vulnerability and Exploit repositories use this so precedence rules
and branching live in one documented module.

Precedence (applied in order; earlier wins for that FK when fill_missing_only):
1. rengine_context (subdomain_id, endpoint_id, ip_address_id, port_id) is
   applied first in the repository (_apply_rengine_context_*) when present and
   valid for the scan.
2. Parsed value (from parse_secator_target_value):
   - kind "url": endpoint by url_normalized; subdomain by host.
   - kind "host_port" or "ip": subdomain by host or ip; ip_address (and port
     for Vulnerability) from parsed ip/port.
3. item_ip: used only when the parsed value did not yield an IP (e.g. URL
   with hostname); fills ip_address as fallback.

Only values that parse as full http(s) URL, host:port, or bare IP are
processed. Bare hostnames and relative paths are not handled.
"""

from dataclasses import dataclass, field
from typing import Any, List, Optional

from reNgine.core.secator_target import SecatorTargetValue


def should_skip_association(
    record: Any,
    field_name: str,
    fill_missing_only: bool,
    already_changed: List[str],
) -> bool:
    """
    Return True if _try_associate_* should skip (no-op) for this field.

    Used by Vulnerability and Exploit repositories to avoid duplicating
    fill_missing_only and already_changed logic.
    """
    if fill_missing_only and getattr(record, field_name, None) is not None:
        return True
    if field_name in already_changed:
        return True
    return False


@dataclass(frozen=True)
class ResolvedAssociationTarget:
    """What to associate from a parsed Secator value and optional item_ip."""

    endpoint_url: Optional[str] = None
    hosts_for_subdomain: List[str] = field(default_factory=list)
    ip_str: Optional[str] = None
    port: Optional[int] = None
    use_item_ip_fallback: bool = False


def resolve_association_target(
    parsed: SecatorTargetValue,
    item_ip: str = "",
) -> ResolvedAssociationTarget:
    """
    Resolve association targets from a parsed value and optional item_ip.

    Encodes precedence: URL → endpoint + host; host:port/IP → host + ip + port;
    item_ip used only when parsed has no ip (use_item_ip_fallback=True).

    Args:
        parsed: Result of parse_secator_target_value(matched_at or http_url).
        item_ip: Optional IP string from the Secator item (e.g. item.get("ip")).

    Returns:
        ResolvedAssociationTarget with endpoint_url, hosts_for_subdomain,
        ip_str, port, and use_item_ip_fallback. Repositories use these to drive
        their _try_associate_* lookups.
    """
    item_ip_stripped = (item_ip or "").strip()
    if parsed.kind == "url" and parsed.url_normalized:
        hosts = [parsed.host] if parsed.host else []
        return ResolvedAssociationTarget(
            endpoint_url=parsed.url_normalized,
            hosts_for_subdomain=hosts,
            ip_str=None,
            port=None,
            use_item_ip_fallback=bool(item_ip_stripped and not parsed.ip),
        )
    if parsed.kind in ("host_port", "ip"):
        host_or_ip = parsed.host or parsed.ip
        hosts = [host_or_ip] if host_or_ip else []
        ip_str = parsed.ip or (item_ip_stripped or None)
        return ResolvedAssociationTarget(
            endpoint_url=None,
            hosts_for_subdomain=hosts,
            ip_str=ip_str or None,
            port=parsed.port,
            use_item_ip_fallback=False,
        )
    return ResolvedAssociationTarget(use_item_ip_fallback=bool(item_ip_stripped))
