"""
Shared request parsing for Secator / scan endpoints that accept IP or subdomain target lists.

Keeps comma-separated query parsing and JSON body list/string coercion aligned across views.
For XOR / mutual-exclusion rules and stable error strings see ``api.helpers.subdomain_ip_xor``.
For whether an IP PK belongs to a scan see ``reNgine.services.scan_finding_metrics``.
"""

from __future__ import annotations

from typing import Any


def parse_comma_separated_int_ids(param: str, *, field_label: str) -> list[int]:
    """
    Parse a non-empty comma-separated list of integers (query params).

    Raises:
        ValueError: Empty input, invalid integer token, or wrong shape.
    """
    if not param or not str(param).strip():
        raise ValueError("%s must contain at least one valid id" % field_label)
    try:
        ids = [int(x.strip()) for x in str(param).split(",") if x.strip()]
    except (TypeError, ValueError) as e:
        raise ValueError("%s must be a comma-separated list of integers" % field_label) from e
    if not ids:
        raise ValueError("%s must contain at least one valid id" % field_label)
    return ids


def coerce_json_ip_address_ids(raw: Any) -> list[int]:
    """
    Coerce ``ip_address_ids`` from a request body: None, int, list/tuple of ints,
    or comma-separated string (same shapes as Secator / scan bulk actions).

    Raises:
        ValueError: Unsupported types or non-int-coercible elements.
    """
    if raw is None:
        return []
    if isinstance(raw, int):
        return [raw]
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            return [int(x.strip()) for x in text.split(",") if x.strip()]
        except (TypeError, ValueError) as e:
            raise ValueError("Invalid ip_address_ids") from e
    if isinstance(raw, (list, tuple)):
        try:
            return [int(x) for x in raw]
        except (TypeError, ValueError) as e:
            raise ValueError("Invalid ip_address_ids") from e
    raise ValueError("Invalid ip_address_ids")


def positive_ip_ids(ip_ids: list[int]) -> list[int]:
    """Return a copy with only strictly positive integer PKs (stable order)."""
    return [pk for pk in ip_ids if pk > 0]
