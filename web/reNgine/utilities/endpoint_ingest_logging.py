"""Shared key=value suffixes for endpoint ingestion logs (scan id, URL snippets, resolution reasons)."""

from __future__ import annotations


def format_endpoint_host_unresolved_suffix(
    scan_history_id: int,
    http_url: str,
    *,
    hostname_override: str | None = None,
    reason: str | None = None,
    max_url_len: int = 200,
) -> str:
    """Build a single space-separated ``key=value`` fragment for host-resolution skip lines."""
    url_snip = (http_url or "")[:max_url_len]
    r = reason or "unspecified"
    if hostname_override is not None:
        return "scan_id=%s url=%s hostname_override=%s reason=%s" % (
            scan_history_id,
            url_snip,
            hostname_override or "",
            r,
        )
    return "scan_id=%s url=%s reason=%s" % (scan_history_id, url_snip, r)
