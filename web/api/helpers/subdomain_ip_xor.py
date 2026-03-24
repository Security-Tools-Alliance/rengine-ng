"""
Validation helpers for APIs that accept either subdomain or IP identifiers.

Several endpoints accept mutually exclusive subdomain_id / ip_address_id (or list forms)
to avoid ambiguous host targeting. Centralizing the checks keeps error messages and
semantics consistent across LLM, Secator subtasks, and recon notes.

``LLMAttackSuggestion`` additionally accepts exactly one of ``target_id``, ``scope_id``,
or ``organization_id`` together with the host-level ids; see
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

from typing import Optional, Sequence, Tuple


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
    "Provide exactly one of subdomain_id, ip_address_id, target_id, scope_id, or organization_id"
)

# Protocol kinds for LLM attack-surface API dispatch. Keep aligned with
# ``static/custom/target_entity_kind.js`` (RENGINE_ATTACK_SURFACE_ENTITY_*) and
# ``resolve_attack_surface_entity_kind_and_pk`` below.
ATTACK_SURFACE_KIND_SUBDOMAIN = "subdomain"
ATTACK_SURFACE_KIND_IP = "ip"
ATTACK_SURFACE_KIND_TARGET = "target"
ATTACK_SURFACE_KIND_SCOPE = "scope"
ATTACK_SURFACE_KIND_ORGANIZATION = "organization"

ATTACK_SURFACE_ENTITY_KINDS: frozenset[str] = frozenset(
    {
        ATTACK_SURFACE_KIND_SUBDOMAIN,
        ATTACK_SURFACE_KIND_IP,
        ATTACK_SURFACE_KIND_TARGET,
        ATTACK_SURFACE_KIND_SCOPE,
        ATTACK_SURFACE_KIND_ORGANIZATION,
    }
)


def xor_attack_surface_entity_ids_error(
    subdomain_id: Optional[int],
    ip_address_id: Optional[int],
    target_id: Optional[int],
    scope_id: Optional[int],
    organization_id: Optional[int],
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
        1 for x in (subdomain_id, ip_address_id, target_id, scope_id, organization_id) if isinstance(x, int) and x > 0
    )
    if count != 1:
        return message
    return None


ATTACK_SURFACE_ENTITY_QUERY_ID_KEYS = (
    "subdomain_id",
    "ip_address_id",
    "target_id",
    "scope_id",
    "organization_id",
)


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
    return None


def resolve_attack_surface_entity_kind_and_pk(
    subdomain_id: Optional[int],
    ip_address_id: Optional[int],
    target_id: Optional[int],
    scope_id: Optional[int],
    organization_id: Optional[int],
) -> Optional[Tuple[str, int]]:
    """
    Return ``(kind, pk)`` for the single positive entity id, or ``None`` if none or multiple.

    ``kind`` is one of the ``ATTACK_SURFACE_KIND_*`` constants (same strings as the JS UI).
    After ``xor_attack_surface_entity_ids_error`` returns no error, this should return
    exactly one pair; ``None`` indicates an inconsistent state and callers should respond
    with 400 using ``ATTACK_SURFACE_ENTITY_XOR_MESSAGE``.
    """
    pairs: list[Tuple[str, int]] = []
    if isinstance(subdomain_id, int) and subdomain_id > 0:
        pairs.append((ATTACK_SURFACE_KIND_SUBDOMAIN, subdomain_id))
    if isinstance(ip_address_id, int) and ip_address_id > 0:
        pairs.append((ATTACK_SURFACE_KIND_IP, ip_address_id))
    if isinstance(target_id, int) and target_id > 0:
        pairs.append((ATTACK_SURFACE_KIND_TARGET, target_id))
    if isinstance(scope_id, int) and scope_id > 0:
        pairs.append((ATTACK_SURFACE_KIND_SCOPE, scope_id))
    if isinstance(organization_id, int) and organization_id > 0:
        pairs.append((ATTACK_SURFACE_KIND_ORGANIZATION, organization_id))
    if len(pairs) != 1:
        return None
    return pairs[0]
