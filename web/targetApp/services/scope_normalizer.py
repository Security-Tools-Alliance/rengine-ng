"""
Scope normalizer service.

Parses raw scope input (hosts, IPs, CIDR ranges, HTTP(S) URLs; comma or newline separated),
deduplicates, and produces domain, IP, CIDR, and URL targets plus allowed_finding_hosts.
Pure logic, no HTTP/DB dependencies; reusable from API or management commands.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse

import validators

from reNgine.core.validators import is_valid_cidr, is_valid_ip
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
    cidr_targets: tuple[str, ...]
    url_targets: tuple[str, ...]
    allowed_finding_hosts: tuple[str, ...]


def parse_scope_raw_input(raw_text: str) -> ScopeNormalizerResult:
    """
    Parse raw scope text into domain, IP, CIDR, and URL targets, and allowed hosts.

    Splits by newlines and commas, strips and lowercases, deduplicates.
    - HTTP(S) URLs (validated like add_target) go to url_targets; hostname is added
      to allowed_finding_hosts when present.
    - Valid CIDR notations go to cidr_targets and allowed_finding_hosts.
    - Valid IPs go to ip_targets and allowed_finding_hosts.
    - Other tokens with a valid registered domain go to allowed_finding_hosts
      and their root domain is added to domain_targets.

    Returns:
        ScopeNormalizerResult (all deduplicated, stable order).
    """
    if not raw_text or not isinstance(raw_text, str):
        return ScopeNormalizerResult((), (), (), (), ())

    raw = raw_text.strip()
    if not raw:
        return ScopeNormalizerResult((), (), (), (), ())

    tokens = re.split(r"[\n,]+", raw)
    seen_hosts: set[str] = set()
    seen_roots: set[str] = set()
    domain_targets: list[str] = []
    ip_targets: list[str] = []
    cidr_targets: list[str] = []
    url_targets: list[str] = []
    allowed_finding_hosts: list[str] = []

    for token in tokens:
        trimmed = token.strip()
        if not trimmed:
            continue
        lowered_url_candidate = trimmed.lower()
        if lowered_url_candidate.startswith(("http://", "https://")):
            if not validators.url(lowered_url_candidate):
                continue
            if lowered_url_candidate in seen_hosts:
                continue
            seen_hosts.add(lowered_url_candidate)
            url_targets.append(lowered_url_candidate)
            hostname = urlparse(lowered_url_candidate).hostname
            if hostname:
                allowed_finding_hosts.append(hostname.lower())
            continue

        value = normalize_host_string(token)
        if not value:
            continue
        value = strip_trailing_port(value)
        if not value:
            continue

        if value in seen_hosts:
            continue
        seen_hosts.add(value)

        if is_valid_cidr(value):
            cidr_targets.append(value)
            allowed_finding_hosts.append(value)
            continue

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
        cidr_targets=tuple(cidr_targets),
        url_targets=tuple(url_targets),
        allowed_finding_hosts=tuple(allowed_finding_hosts),
    )
