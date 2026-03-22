"""
Canonical parsing and normalization for IPv4/IPv6 literal strings.

Single place for strip + ipaddress validation used by validators, repositories, and migrations.
"""

from __future__ import annotations

import ipaddress
from typing import Optional


def normalize_ip_address_text(value: Optional[str]) -> Optional[str]:
    """
    Return the canonical string form of value if it is a valid IPv4/IPv6 address literal.

    Leading/trailing whitespace is ignored. Returns None for empty, non-string, or invalid input.
    """
    if not value or not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        return str(ipaddress.ip_address(stripped))
    except (ValueError, ipaddress.AddressValueError):
        return None


def is_ip_literal_text(value: Optional[str]) -> bool:
    """True if value parses as an IPv4 or IPv6 address after stripping."""
    return normalize_ip_address_text(value) is not None
