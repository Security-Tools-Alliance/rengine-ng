"""
Scope normalizer service.

Parses raw scope input (hosts and/or IPs, comma or newline separated),
deduplicates, and produces domain targets, IP targets, and allowed_finding_hosts.
Pure logic, no HTTP/DB dependencies; reusable from API or management commands.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from reNgine.core.validators import is_valid_ip
from reNgine.utilities.domain import normalize_host_string
from reNgine.utilities.url import get_domain_from_subdomain


def strip_trailing_port(host_value: str) -> str:
    """
    Remove a trailing numeric port from a host string (host:port or [ipv6]:port).

    IPv6 literals use [host]:port (e.g. [::1]:443); otherwise the last colon
    is used to split host and port. Returns the host part when a port is stripped,
    otherwise the value unchanged. Reusable for any host normalization path that
    accepts host:port input.
    """
    if not host_value or not isinstance(host_value, str):
        return host_value or ""
    value = host_value.strip()
    if not value:
        return host_value
    if value.startswith("["):
        bracket_end = value.find("]:")
        if bracket_end != -1 and value[bracket_end + 2 :].strip().isdigit():
            return value[1:bracket_end].strip().lower()
        return value
    host, sep, port = value.rpartition(":")
    if sep and port.strip().isdigit() and host.strip() and ":" not in host:
        return host.strip().lower()
    return value


@dataclass(frozen=True)
class ScopeNormalizerResult:
    """Result of parsing raw scope input."""

    domain_targets: tuple[str, ...]
    ip_targets: tuple[str, ...]
    allowed_finding_hosts: tuple[str, ...]


def parse_scope_raw_input(raw_text: str) -> ScopeNormalizerResult:
    """
    Parse raw scope text into domain targets, IP targets, and allowed hosts.

    Splits by newlines and commas, strips and lowercases, deduplicates.
    - Valid IPs go to ip_targets and allowed_finding_hosts.
    - Non-IP tokens with a valid registered domain go to allowed_finding_hosts
      and their root domain is added to domain_targets.

    Returns:
        ScopeNormalizerResult with domain_targets, ip_targets, allowed_finding_hosts
        (all deduplicated, stable order).
    """
    if not raw_text or not isinstance(raw_text, str):
        return ScopeNormalizerResult((), (), ())

    raw = raw_text.strip()
    if not raw:
        return ScopeNormalizerResult((), (), ())

    tokens = re.split(r"[\n,]+", raw)
    seen_hosts: set[str] = set()
    seen_roots: set[str] = set()
    domain_targets: list[str] = []
    ip_targets: list[str] = []
    allowed_finding_hosts: list[str] = []

    for token in tokens:
        value = normalize_host_string(token)
        if not value:
            continue
        value = strip_trailing_port(value)
        if not value:
            continue

        if value in seen_hosts:
            continue
        seen_hosts.add(value)

        if is_valid_ip(value):
            ip_targets.append(value)
            allowed_finding_hosts.append(value)
            continue

        if root := get_domain_from_subdomain(value):
            allowed_finding_hosts.append(value)
            if root not in seen_roots:
                seen_roots.add(root)
                domain_targets.append(root)

    return ScopeNormalizerResult(
        domain_targets=tuple(domain_targets),
        ip_targets=tuple(ip_targets),
        allowed_finding_hosts=tuple(allowed_finding_hosts),
    )
