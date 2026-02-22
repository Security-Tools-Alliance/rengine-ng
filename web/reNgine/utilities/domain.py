"""
Resolve Domain from Target for scan context.
Domain is a finding; link to target via scan_history (Domain.scan_history.target_id).

All resolution uses a single normalization and optional centralized failure logging.

Use these helpers for any Domain lookup or creation; do not inline
Domain.objects.get_or_create or filter by scan_history_id+name elsewhere.
"""

from typing import Any, Optional

from django.db.models import QuerySet
from django.utils import timezone

from startScan.models import Domain


def normalize_domain_name(domain_name: str) -> Optional[str]:
    """
    Normalize a domain name for lookup or storage: strip, lower, strip trailing dot.

    Returns None if the result would be empty or the input is not a string.
    IDN / Unicode domains are preserved as-is (no IDNA encoding).
    """
    if not isinstance(domain_name, str):
        return None
    return domain_name.strip().lower().rstrip(".") or None


def get_domain_for_scan_by_name(scan_history_id: int, domain_name: str) -> Optional[Domain]:
    """
    Return the Domain for this scan with the given name, or None.

    Does not create; used when we must only attach data to an existing scan domain.
    """
    if normalized := normalize_domain_name(domain_name):
        return Domain.objects.filter(scan_history_id=scan_history_id, name=normalized).first()
    else:
        return None


def get_or_create_domain_for_target(scan_history_id: int, domain_name: str) -> Optional[Domain]:
    """
    Get or create a Domain for the given scan and domain name.

    Scoped by (scan_history_id, name). Used by Secator finding repositories
    when they need a Domain FK from scan context + item data.
    """
    normalized = normalize_domain_name(domain_name)
    if not normalized:
        return None
    now = timezone.now()
    domain, _ = Domain.objects.get_or_create(
        scan_history_id=scan_history_id,
        name=normalized,
        defaults={"insert_date": now},
    )
    return domain


def resolve_domain_for_scan(
    scan_history_id: int,
    *candidate_names: str,
    create: bool = True,
    log_failure: Optional[dict[str, Any]] = None,
) -> Optional[Domain]:
    """
    Resolve a Domain for the given scan by trying candidate names in order.

    Each candidate is normalized, then reduced to its registered domain
    (e.g. www.example.com -> example.com, api.example.co.uk -> example.co.uk)
    using tldextract via get_domain_from_subdomain.
    If extraction fails (IP address, invalid name), the normalized value is kept as-is.

    Args:
        scan_history_id: ScanHistory id.
        *candidate_names: One or more names to try (e.g. hostname then target.value).
        create: If True, get_or_create for first valid name; if False, only lookup existing.
        log_failure: Optional dict with "logger", "prefix", "extra" (extra string for message).
                     If set and result is None, logs "Could not resolve domain for scan ...".

    Returns:
        Domain or None.
    """
    from reNgine.utilities.url import get_domain_from_subdomain

    for name in candidate_names:
        normalized = normalize_domain_name(name or "")
        if not normalized:
            continue
        registered = get_domain_from_subdomain(normalized)
        domain_name_to_use = registered or normalized
        if create:
            domain = get_or_create_domain_for_target(scan_history_id, domain_name_to_use)
        else:
            domain = get_domain_for_scan_by_name(scan_history_id, domain_name_to_use)
        if domain is not None:
            return domain
    if log_failure:
        _log_resolution_failure(scan_history_id, log_failure)
    return None


def get_scan_display_name(target_value: str = "") -> str:
    """
    Return the display name for a scan from its target value.

    The scan target (Target.value) is the canonical source of "what was scanned".
    Domain is a finding, not the identity of the scan.
    """
    return (target_value or "").strip() or ""


def get_domain_by_id(domain_id: Optional[int]) -> Optional[Domain]:
    """
    Return the Domain with the given primary key, or None if not found or domain_id is None.

    Use this instead of Domain.objects.get(id=...) to centralize lookup-by-id and
    handle missing domains uniformly (return None instead of raising DoesNotExist).
    """
    if domain_id is None:
        return None
    return Domain.objects.filter(pk=domain_id).first()


def get_domains_queryset_for_scan(scan_history_id: int) -> QuerySet[Domain]:
    """
    Return the base queryset of Domain objects for the given scan.

    Callers may chain .prefetch_related(), .order_by(), etc. as needed.
    """
    return Domain.objects.filter(scan_history_id=scan_history_id)


def _log_resolution_failure(scan_history_id: int, log_failure: dict[str, Any]) -> None:
    logger = log_failure.get("logger")
    prefix = log_failure.get("prefix", "")
    extra = log_failure.get("extra", "")
    if not (logger and prefix):
        return
    msg = "Could not resolve domain for scan (scan_history_id=%s" % (scan_history_id,)
    if extra:
        msg += ", %s)" % (extra,)
    else:
        msg += ")"
    logger.log_line(prefix, "RESOLVE", msg, level="warning")
