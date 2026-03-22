"""
Validation helpers for APIs that accept either subdomain or IP identifiers.

Several endpoints accept mutually exclusive subdomain_id / ip_address_id (or list forms)
to avoid ambiguous host targeting. Centralizing the checks keeps error messages and
semantics consistent across LLM, Secator subtasks, and recon notes.

Related helpers (request shape vs scan membership; reuse instead of duplicating checks):
- ``api.helpers.secator_scan_target_request``: comma-separated id lists (GET) and JSON
  ``ip_address_ids`` coercion (POST); ``positive_ip_ids`` for PK lists after coercion.
- ``startScan.services.host_assignment``: exclusive subdomain vs ``IpAddress`` on ``EndPoint`` / ``SubScan``.
- ``reNgine.services.scan_finding_metrics.partition_ip_address_ids_for_scan_history``:
  split requested IP PKs into in-scan vs out-of-scan for a ``ScanHistory``.
"""

from __future__ import annotations

from typing import Optional, Sequence


def xor_subdomain_ip_single_ids_error(
    subdomain_id: Optional[int],
    ip_address_id: Optional[int],
    *,
    message: str = "Provide exactly one of subdomain_id or ip_address_id",
) -> Optional[str]:
    """
    Return an error message if both or neither id is set after int coercion; else None.

    Used when the API requires exactly one of subdomain_id or ip_address_id.
    """
    has_sub = bool(subdomain_id)
    has_ip = bool(ip_address_id)
    if has_sub == has_ip:
        return message
    return None


def both_subdomain_and_ip_provided_error(
    subdomain_id: Optional[int],
    ip_address_id: Optional[int],
    *,
    message: str = "Provide only one of subdomain_id or ip_address_id.",
) -> Optional[str]:
    """Return an error message if both ids are set; recon notes allow neither."""
    if bool(subdomain_id) and bool(ip_address_id):
        return message
    return None


def xor_subdomain_ids_or_ip_address_ids_error(
    subdomain_ids: Sequence[int],
    ip_address_ids: Sequence[int],
    *,
    message: str = "Provide exactly one of subdomain_ids or ip_address_ids",
) -> Optional[str]:
    """Return an error if both or neither non-empty list is provided."""
    has_sub = bool(subdomain_ids)
    has_ip = bool(ip_address_ids)
    if has_sub == has_ip:
        return message
    return None


def subdomain_ids_conflict_when_ip_address_ids_requested_error(
    subdomain_ids: Sequence[int],
    *,
    message: str = "subdomain_ids and ip_address_ids cannot be combined",
) -> Optional[str]:
    """
    Return an error when the client also passed subdomain_ids while selecting ip_address_ids.

    Used for query parsing where ip_address_ids is present and must not mix with subdomain_ids.
    """
    if subdomain_ids:
        return message
    return None
