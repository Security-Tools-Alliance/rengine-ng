"""
Secator target value parsing - Leaf layer.
Parses matched_at / http_url from Secator findings into normalized forms.
Only accepts: full http(s) URL, host:port, or bare IP. Invalid values are rejected.
"""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from reNgine.core.validators import is_valid_ip, is_valid_port


@dataclass(frozen=True)
class SecatorTargetValue:
    """Parsed result for a Secator matched_at / http_url value."""

    is_valid: bool
    kind: str  # "url" | "host_port" | "ip"
    url_normalized: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    ip: Optional[str] = None


def parse_secator_target_value(value: Optional[str]) -> SecatorTargetValue:
    """
    Parse a Secator matched_at or http_url value.

    Only treats the value if it is one of:
    - Full URL: http://... or https://...
    - host:port: hostname or IP with port (e.g. example.com:443, 192.168.1.1:8080)
    - Bare IP: IPv4 or IPv6

    Otherwise returns is_valid=False and the value is not used for association.

    Args:
        value: Raw string (matched_at, http_url, etc.)

    Returns:
        SecatorTargetValue with is_valid, kind, and parsed fields.
    """
    if not value or not isinstance(value, str):
        return SecatorTargetValue(is_valid=False, kind="")

    raw = value.strip()
    if not raw:
        return SecatorTargetValue(is_valid=False, kind="")

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            host = (parsed.hostname or "").strip().lower()
            port = parsed.port
            # Path and query are preserved as-is (case-sensitive); only netloc is lowercased.
            # Empty path is canonicalized to "/". Trailing slashes are not stripped, so lookups
            # match EndPoint.http_url values stored with their original path form.
            path = (parsed.path or "").strip() or "/"
            query_suffix = ("?" + parsed.query) if parsed.query else ""
            url_normalized = "%s://%s%s%s" % (
                parsed.scheme,
                parsed.netloc.lower(),
                path,
                query_suffix,
            )
            return SecatorTargetValue(
                is_valid=True,
                kind="url",
                url_normalized=url_normalized,
                host=host or None,
                port=port,
                ip=host if (host and is_valid_ip(host)) else None,
            )
        return SecatorTargetValue(is_valid=False, kind="")

    if is_valid_ip(raw):
        return SecatorTargetValue(
            is_valid=True,
            kind="ip",
            host=raw,
            ip=raw,
            port=None,
        )

    if ":" in raw:
        host_part: Optional[str]
        port_part: Optional[str]
        if raw.startswith("[") and "]:" in raw:
            bracket = raw.find("]:")
            if bracket != -1:
                host_part = raw[1:bracket].strip()
                port_part = raw[bracket + 2 :].strip()
            else:
                return SecatorTargetValue(is_valid=False, kind="")
        else:
            last_colon = raw.rfind(":")
            if last_colon <= 0:
                return SecatorTargetValue(is_valid=False, kind="")
            host_part = raw[:last_colon].strip()
            port_part = raw[last_colon + 1 :].strip()

        if not host_part or not port_part:
            return SecatorTargetValue(is_valid=False, kind="")
        try:
            port_num = int(port_part)
        except ValueError:
            return SecatorTargetValue(is_valid=False, kind="")
        if not is_valid_port(port_num):
            return SecatorTargetValue(is_valid=False, kind="")
        is_host_ip = is_valid_ip(host_part)
        return SecatorTargetValue(
            is_valid=True,
            kind="host_port",
            host=host_part,
            port=port_num,
            ip=host_part if is_host_ip else None,
        )

    return SecatorTargetValue(is_valid=False, kind="")
