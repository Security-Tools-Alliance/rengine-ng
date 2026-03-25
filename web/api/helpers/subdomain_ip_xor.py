"""
Validation helpers for APIs that accept either subdomain or IP identifiers.

Several endpoints accept mutually exclusive subdomain_id / ip_address_id (or list forms)
to avoid ambiguous host targeting. Centralizing the checks keeps error messages and
semantics consistent across LLM, Secator subtasks, and recon notes.

``LLMAttackSuggestion`` additionally accepts exactly one of ``target_id``, ``scope_id``,
``organization_id``, or ``scan_history_id`` together with the host-level ids; see
``xor_attack_surface_entity_ids_error`` and
``attack_surface_entity_query_params_invalid_error``.

Related helpers (request shape vs scan membership; reuse instead of duplicating checks):
- ``api.helpers.secator_scan_target_request``: comma-separated id lists (GET) and JSON
  ``ip_address_ids`` coercion (POST); ``positive_ip_ids`` for PK lists after coercion.
- ``startScan.services.host_assignment``: exclusive subdomain vs ``IpAddress`` on ``EndPoint`` / ``SubScan``.
- ``reNgine.services.scan_finding_metrics.partition_ip_address_ids_for_scan_history``:
  split requested IP PKs into in-scan vs out-of-scan for a ``ScanHistory``.
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence, Tuple


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


ATTACK_SURFACE_ENTITY_XOR_MESSAGE = (
    "Provide exactly one of subdomain_id, ip_address_id, target_id, scope_id, organization_id, or scan_history_id"
)

# Protocol kinds for LLM attack-surface API dispatch. Keep aligned with
# ``static/custom/target_entity_kind.js`` (RENGINE_ATTACK_SURFACE_ENTITY_*) and
# ``resolve_attack_surface_entity_kind_and_pk`` below.
ATTACK_SURFACE_KIND_SUBDOMAIN = "subdomain"
ATTACK_SURFACE_KIND_IP = "ip"
ATTACK_SURFACE_KIND_TARGET = "target"
ATTACK_SURFACE_KIND_SCOPE = "scope"
ATTACK_SURFACE_KIND_ORGANIZATION = "organization"
ATTACK_SURFACE_KIND_SCAN_HISTORY = "scan_history"

ATTACK_SURFACE_ENTITY_KINDS: frozenset[str] = frozenset(
    {
        ATTACK_SURFACE_KIND_SUBDOMAIN,
        ATTACK_SURFACE_KIND_IP,
        ATTACK_SURFACE_KIND_TARGET,
        ATTACK_SURFACE_KIND_SCOPE,
        ATTACK_SURFACE_KIND_ORGANIZATION,
        ATTACK_SURFACE_KIND_SCAN_HISTORY,
    }
)

ATTACK_SURFACE_QUERY_ID_KIND_BY_KEY: Tuple[Tuple[str, str], ...] = (
    ("subdomain_id", ATTACK_SURFACE_KIND_SUBDOMAIN),
    ("ip_address_id", ATTACK_SURFACE_KIND_IP),
    ("target_id", ATTACK_SURFACE_KIND_TARGET),
    ("scope_id", ATTACK_SURFACE_KIND_SCOPE),
    ("organization_id", ATTACK_SURFACE_KIND_ORGANIZATION),
    ("scan_history_id", ATTACK_SURFACE_KIND_SCAN_HISTORY),
)

ATTACK_SURFACE_ENTITY_QUERY_ID_KEYS = tuple(key for key, _ in ATTACK_SURFACE_QUERY_ID_KIND_BY_KEY)


def iter_attack_surface_entity_kinds_and_ids(
    subdomain_id: Optional[int],
    ip_address_id: Optional[int],
    target_id: Optional[int],
    scope_id: Optional[int],
    organization_id: Optional[int],
    scan_history_id: Optional[int],
) -> Iterable[Tuple[str, Optional[int]]]:
    """
    Yield (kind, id) pairs for supported attack-surface aggregate entity ids.

    Centralizes enumeration so XOR validation and dispatch resolution stay consistent
    as new kinds are added (e.g. ``scan_history_id``).
    """
    id_by_key = {
        "subdomain_id": subdomain_id,
        "ip_address_id": ip_address_id,
        "target_id": target_id,
        "scope_id": scope_id,
        "organization_id": organization_id,
        "scan_history_id": scan_history_id,
    }
    for key, kind in ATTACK_SURFACE_QUERY_ID_KIND_BY_KEY:
        yield kind, id_by_key[key]


def xor_attack_surface_entity_ids_error(
    subdomain_id: Optional[int],
    ip_address_id: Optional[int],
    target_id: Optional[int],
    scope_id: Optional[int],
    organization_id: Optional[int],
    scan_history_id: Optional[int],
    *,
    message: str = ATTACK_SURFACE_ENTITY_XOR_MESSAGE,
) -> Optional[str]:
    """
    Return an error if the number of provided entity ids is not exactly one.

    Used by ``LLMAttackSuggestion`` GET/DELETE so the client cannot combine host-level
    and aggregate analysis selectors.

    An id counts as provided only when it is a positive integer (> 0), consistent with
    PK validation elsewhere (``0`` and negative values are ignored).
    """
    count = sum(
        1
        for _, pk in iter_attack_surface_entity_kinds_and_ids(
            subdomain_id=subdomain_id,
            ip_address_id=ip_address_id,
            target_id=target_id,
            scope_id=scope_id,
            organization_id=organization_id,
            scan_history_id=scan_history_id,
        )
        if isinstance(pk, int) and pk > 0
    )
    if count != 1:
        return message
    return None


ATTACK_SURFACE_OPTIONAL_POSITIVE_INT_KEYS = ("attack_surface_analysis_id",)


def attack_surface_entity_query_params_invalid_error(query_params) -> Optional[str]:
    """
    Return an error if any attack-surface entity id appears in the query string but is not
    a positive integer.

    Prevents ``target_id=0`` (ignored by XOR counting) from silently combining with another
    entity id so the handler falls through to the wrong branch.
    """
    for key in ATTACK_SURFACE_ENTITY_QUERY_ID_KEYS:
        if key not in query_params:
            continue
        raw = query_params.get(key)
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            continue
        try:
            val = int(raw)
        except (ValueError, TypeError):
            return "%s must be a positive integer" % key
        if val <= 0:
            return "%s must be a positive integer" % key
    for key in ATTACK_SURFACE_OPTIONAL_POSITIVE_INT_KEYS:
        if key not in query_params:
            continue
        raw = query_params.get(key)
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            continue
        try:
            val = int(raw)
        except (ValueError, TypeError):
            return "%s must be a positive integer" % key
        if val <= 0:
            return "%s must be a positive integer" % key
    return None


def resolve_attack_surface_entity_kind_and_pk(
    subdomain_id: Optional[int],
    ip_address_id: Optional[int],
    target_id: Optional[int],
    scope_id: Optional[int],
    organization_id: Optional[int],
    scan_history_id: Optional[int],
) -> Optional[Tuple[str, int]]:
    """
    Return ``(kind, pk)`` for the single positive entity id (or ``None`` if none/multiple).

    Supported positive ids are mutually exclusive:
    ``subdomain_id``, ``ip_address_id``, ``target_id``, ``scope_id``,
    ``organization_id``, and ``scan_history_id``.

    ``kind`` is one of the ``ATTACK_SURFACE_KIND_*`` constants (same strings as the JS UI).
    After ``xor_attack_surface_entity_ids_error`` returns no error, this should return exactly
    one ``(kind, pk)`` pair; ``None`` indicates an inconsistent state and callers must respond
    with 400 using ``ATTACK_SURFACE_ENTITY_XOR_MESSAGE``.
    """
    positive_pairs: list[Tuple[str, int]] = [
        (kind, pk)
        for kind, pk in iter_attack_surface_entity_kinds_and_ids(
            subdomain_id=subdomain_id,
            ip_address_id=ip_address_id,
            target_id=target_id,
            scope_id=scope_id,
            organization_id=organization_id,
            scan_history_id=scan_history_id,
        )
        if isinstance(pk, int) and pk > 0
    ]
    if len(positive_pairs) != 1:
        return None
    return positive_pairs[0]
