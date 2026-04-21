"""Persist Subdomain–Technology M2M rows (through model) with optional Secator source."""

from __future__ import annotations

from typing import Optional

from startScan.models import Subdomain, SubdomainTechnology, Technology


def upsert_subdomain_technology_link(
    subdomain: Subdomain,
    technology: Technology,
    source: Optional[str] = None,
) -> None:
    """
    Ensure a single through row per (subdomain, technology).

    On create, the row's ``source`` field is set when the ``source`` argument is non-empty.
    On update, a new non-empty ``source`` replaces the previous value; empty or omitted
    ``source`` does not clear an existing stored source.
    """
    trimmed = (source or "").strip()
    val: Optional[str] = trimmed[:200] if trimmed else None
    link, created = SubdomainTechnology.objects.get_or_create(
        subdomain=subdomain,
        technology=technology,
        defaults={"source": val},
    )
    if not created and val is not None and link.source != val:
        link.source = val
        link.save(update_fields=["source"])
