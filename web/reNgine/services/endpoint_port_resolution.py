"""
Single description of how an ``EndPoint`` row is associated with a ``Port`` from the URL port.

- URL port: ``extract_port_number_from_http_url`` (shared).
- Host/port → Port pk: ``resolve_port_pk_for_endpoint_maps`` (backfill, in-memory maps) mirrors
  ``EndpointRepository._resolve_port_for_host`` (live ORM). Keep these aligned when rules change.

Historical backfill: ``startScan.migrations.0130_endpoint_port_fk_and_backfill``.
"""

from __future__ import annotations

from typing import AbstractSet, Mapping, MutableMapping, Optional, TypeAlias
from urllib.parse import urlparse


# (ip_address_id, TCP/UDP port number) -> canonical Port.pk (first row wins in backfill).
PortLookupKey: TypeAlias = tuple[int, int]
PortIdByIpAndNumber: TypeAlias = dict[PortLookupKey, int]

RESOLUTION_RULES_SUMMARY = (
    "If the endpoint has an IP: use the Port row for (ip_address_id, URL port number). "
    "If the endpoint has only a subdomain: set port_id only when exactly one distinct Port "
    "matches that URL port among IPs linked to the subdomain via M2M."
)


def extract_port_number_from_http_url(http_url: str | None) -> Optional[int]:
    """
    TCP/UDP port implied by ``http_url``: explicit ``parsed.port``, else 443/80 for https/http.

    Returns ``None`` when the URL is empty, ``urlparse`` fails, or the scheme is not http(s).
    """
    if not http_url:
        return None
    try:
        parsed = urlparse(http_url)
    except Exception:
        return None
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def resolve_port_id_from_ip_port_map(
    port_id_by_ip_and_number: PortIdByIpAndNumber,
    ip_address_id: int,
    port_number: int,
) -> Optional[int]:
    return port_id_by_ip_and_number.get((ip_address_id, port_number))


def resolve_port_id_for_subdomain_from_ip_port_map(
    port_id_by_ip_and_number: PortIdByIpAndNumber,
    linked_ip_ids: AbstractSet[int],
    port_number: int,
) -> Optional[int]:
    candidate_port_ids = {port_id_by_ip_and_number.get((ip_id, port_number)) for ip_id in linked_ip_ids}
    candidate_port_ids.discard(None)
    if len(candidate_port_ids) == 1:
        return next(iter(candidate_port_ids))
    return None


def resolve_port_pk_for_endpoint_maps(
    *,
    port_number: int,
    ip_address_id: int | None,
    subdomain_id: int | None,
    subdomain_to_ip_ids: Mapping[int, AbstractSet[int]],
    port_id_by_ip_and_number: PortIdByIpAndNumber,
    subdomain_port_cache: MutableMapping[tuple[int, int], int | None] | None = None,
) -> int | None:
    """
    Resolve ``Port`` pk for one endpoint row using batch maps (migration 0130).

    Same decision order as ``EndpointRepository._resolve_port_for_host``: IP branch first,
    then subdomain + linked IPs + ``resolve_port_id_for_subdomain_from_ip_port_map``.
    """
    if ip_address_id:
        return resolve_port_id_from_ip_port_map(port_id_by_ip_and_number, ip_address_id, port_number)
    if not subdomain_id:
        return None
    cache_key = (subdomain_id, port_number)
    if subdomain_port_cache is not None and cache_key in subdomain_port_cache:
        return subdomain_port_cache[cache_key]
    ip_ids = subdomain_to_ip_ids.get(subdomain_id, set())
    resolved = resolve_port_id_for_subdomain_from_ip_port_map(port_id_by_ip_and_number, ip_ids, port_number)
    if subdomain_port_cache is not None:
        subdomain_port_cache[cache_key] = resolved
    return resolved
