"""
Helpers for assigning subdomain vs IP host fields on models with XOR / exactly-one constraints.

Use before save() to avoid violating ``endpoint_exactly_one_host`` or ``subscan_subdomain_ip_xor``.
"""

from __future__ import annotations

from startScan.models import EndPoint, IpAddress, Subdomain, SubScan


def apply_endpoint_host(
    endpoint: EndPoint,
    *,
    subdomain: Subdomain | None = None,
    ip_address: IpAddress | None = None,
) -> None:
    """
    Set exactly one of ``subdomain`` or ``ip_address`` on ``endpoint``; clear the other FK.

    Raises:
        ValueError: If both are set, or both are None.
    """
    has_sub = subdomain is not None
    has_ip = ip_address is not None
    if has_sub == has_ip:
        raise ValueError("EndPoint requires exactly one of subdomain or ip_address.")
    if has_sub:
        endpoint.subdomain = subdomain
        endpoint.ip_address = None
    else:
        endpoint.ip_address = ip_address
        endpoint.subdomain = None


def apply_subscan_host(
    subscan: SubScan,
    *,
    subdomain: Subdomain | None = None,
    ip_address: IpAddress | None = None,
) -> None:
    """
    Assign at most one host target; clears the opposite FK when one is set.

    Raises:
        ValueError: If both ``subdomain`` and ``ip_address`` are non-None.
    """
    if subdomain is not None and ip_address is not None:
        raise ValueError("SubScan cannot have both subdomain and ip_address set.")
    if subdomain is not None:
        subscan.subdomain = subdomain
        subscan.ip_address = None
    elif ip_address is not None:
        subscan.ip_address = ip_address
        subscan.subdomain = None
