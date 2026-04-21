"""
Centralized generation of synthetic IDs for Secator findings that are not persisted.

Used when a finding is skipped (e.g. out of scope) or ignored; the API returns 200
with one of these IDs so Secator does not treat the request as failed.

Format (stable for downstream parsing):
- Generic finding (subdomain, certificate, record, etc.):
  ``skipped_scope_<finding_type>_<timestamp_ms>``
  Example: ``skipped_scope_certificate_1731546789123``
- Tag finding (whois, asn, url_pattern, etc.):
  ``skipped_scope_tag_<category>_<name>_<timestamp_ms>``
  Example: ``skipped_scope_tag_info_whois_1731546789123``

All IDs share the prefix ``skipped_scope_``. Timestamp is milliseconds since epoch.
"""

import time
from typing import Optional


def synthetic_id_skipped_scope(
    finding_type: str,
    tag_category: Optional[str] = None,
    tag_name: Optional[str] = None,
) -> str:
    """
    Generate a synthetic ID for a finding skipped due to scope (e.g. out of scope).

    Use for both generic findings (certificate, record, subdomain, ...) and tag
    findings (whois, asn, ...) so format and generation stay in one place.

    Args:
        finding_type: Secator finding type (e.g. "subdomain", "certificate", "tag").
        tag_category: For tag findings, the tag category (e.g. "info").
        tag_name: For tag findings, the tag name (e.g. "whois").

    Returns:
        Synthetic ID string with prefix skipped_scope_.
    """
    ts = int(time.time() * 1000)
    if finding_type == "tag" and tag_category is not None and tag_name is not None:
        return "skipped_scope_tag_%s_%s_%d" % (tag_category, tag_name, ts)
    return "skipped_scope_%s_%d" % (finding_type, ts)
