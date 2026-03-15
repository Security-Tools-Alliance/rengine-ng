"""
Centralized routing of Secator Tag findings to the appropriate repository.

When the Secator API receives a finding with _type=tag, it calls dispatch_secator_tag
instead of branching on (name, category) in the view. Handlers are registered by
(category, name); ignored tags are not persisted but return 200 with a synthetic id.
See ref-secator-tag-routing in the wiki.
"""

import time
from typing import Any, Callable, Dict, Optional, Tuple

from reNgine.core.exceptions import FindingOutOfScopeError
from reNgine.secator.synthetic_id import synthetic_id_skipped_scope


TagHandler = Callable[[Dict[str, Any], int, int], Tuple[Optional[Any], Optional[int]]]

# (category, name) pairs that should not be persisted; API returns 200 with synthetic id
TAG_IGNORED: frozenset[Tuple[str, str]] = frozenset(
    {
        ("info", "net_interface"),
        ("info", "net_cidr"),
        ("info", "user_input"),
    }
)


def _handler_whois(data: Dict[str, Any], scan_history_id: int, target_id: int) -> Tuple[Optional[Any], Optional[int]]:
    from reNgine.services.repositories.domain_repository import DomainRepository

    domain_name = (data.get("match") or "").strip()
    value = data.get("value") or ""
    obj = DomainRepository().save_raw_whois_from_secator_tag(scan_history_id, target_id, domain_name, value)
    if obj is not None:
        return (obj, None)
    return (None, 422)


def _handler_url_pattern(
    data: Dict[str, Any], scan_history_id: int, target_id: int
) -> Tuple[Optional[Any], Optional[int]]:
    from reNgine.services.repositories.endpoint_repository import EndpointRepository

    http_url = (data.get("match") or data.get("value") or "").strip()
    pattern_name = (data.get("name") or "").strip()
    obj = EndpointRepository().add_gf_pattern_from_secator_tag(scan_history_id, target_id, http_url, pattern_name)
    if obj is not None:
        return (obj, None)
    return (None, 422)


def _handler_asn(data: Dict[str, Any], scan_history_id: int, target_id: int) -> Tuple[Optional[Any], Optional[int]]:
    from reNgine.secator.tag_routing_handlers import save_asn_from_secator_tag

    obj = save_asn_from_secator_tag(data, scan_history_id, target_id)
    if obj is not None:
        return (obj, None)
    return (None, 422)


def _handler_secret(data: Dict[str, Any], scan_history_id: int, target_id: int) -> Tuple[Optional[Any], Optional[int]]:
    from reNgine.services.repositories.secret_repository import SecretRepository

    obj = SecretRepository().save_from_secator_tag(data, scan_history_id, target_id)
    if obj is not None:
        return (obj, None)
    return (None, 422)


# (category, name) -> handler; (category, None) = any name in that category
_TAG_HANDLERS: Dict[Tuple[str, Optional[str]], TagHandler] = {
    ("info", "whois"): _handler_whois,
    ("url_pattern", None): _handler_url_pattern,
    ("info", "asn"): _handler_asn,
    ("secret", None): _handler_secret,
}


def get_tag_handler(category: str, name: str) -> Optional[TagHandler]:
    """Return the handler for (category, name), or None for fallback to TechnologyRepository."""
    key_specific = (category, name)
    if key_specific in _TAG_HANDLERS:
        return _TAG_HANDLERS[key_specific]
    key_any = (category, None)
    if key_any in _TAG_HANDLERS:
        return _TAG_HANDLERS[key_any]
    return None


def is_tag_ignored(category: str, name: str) -> bool:
    """Return True if this tag should be ignored (not persisted, API returns 200 with synthetic id)."""
    return (category, name) in TAG_IGNORED


def dispatch_secator_tag(
    finding_data: Dict[str, Any],
    scan_history_id: int,
    target_id: int,
    validate_scan_context: Callable[..., Tuple[bool, Any, Any, Any]],
    is_update: bool = False,
) -> Tuple[str, ...]:
    """
    Route a Secator tag finding to the appropriate handler or indicate fallback/ignored.

    Args:
        finding_data: The finding payload (must contain category and name for tag).
        scan_history_id: Scan history id from context.
        target_id: Target id from context.
        validate_scan_context: Function that returns (is_valid, error_response, scan_history, target).
        is_update: True for UPDATE (use 400 on error), False for CREATE (use 422).

    Returns:
        ("ignored", synthetic_id) - view returns 200 with id=synthetic_id.
        ("skipped", synthetic_id) - view returns 200 with id=synthetic_id (finding out of scope).
        ("success", saved_object) - view returns 200 with id=saved_object.id.
        ("error", status_code, error_message) - view returns Response with that status.
        ("fallback",) - view continues with get_repository_for_finding_type("tag").
    """
    category = (finding_data.get("category") or "").strip()
    name = (finding_data.get("name") or "").strip()

    if is_tag_ignored(category, name):
        synthetic_id = "tag_ignored_%s_%s_%d" % (category, name, int(time.time() * 1000))
        return ("ignored", synthetic_id)

    handler = get_tag_handler(category, name)
    if handler is None:
        return ("fallback",)

    is_valid, error_response, _scan_history, target = validate_scan_context(scan_history_id, target_id)
    if not is_valid:
        err_msg = "Validation failed"
        if getattr(error_response, "data", None) and isinstance(error_response.data, dict):
            err_msg = error_response.data.get("error", err_msg)
        if not isinstance(err_msg, str):
            err_msg = str(err_msg)
        return ("error", error_response.status_code, err_msg)

    effective_target_id = target.id if target else target_id
    try:
        saved_object, error_status = handler(finding_data, scan_history_id, effective_target_id)
    except FindingOutOfScopeError:
        synthetic_id = synthetic_id_skipped_scope("tag", tag_category=category, tag_name=name)
        return ("skipped", synthetic_id)
    if error_status is not None:
        msg = "Failed to save tag. Validation error or missing required fields."
        return ("error", 400 if is_update else 422, msg)
    if saved_object is not None:
        return ("success", saved_object)
    msg = "Failed to save tag. Domain/endpoint not found or validation error."
    return ("error", 400 if is_update else 422, msg)
