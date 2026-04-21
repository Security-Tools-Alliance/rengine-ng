"""
Central dispatch for Secator findings with _type=tag.

Handlers register via ``register_tag_handler``; built-ins are loaded at import.
Ignored tags return a synthetic id without persistence; built-in ignores are scoped by
``_source`` (Secator task names such as ``netdetect`` / ``prompt``) so unrelated producers
are not suppressed. Use ``register_ignored_tag(..., allowed_sources=None)`` to ignore
regardless of source.

Nuclei: DNS templates map to DnsRepository (Record shape); other info tags to Technology or ignored.

See wiki: ref-secator-tag-routing.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Collection, Dict, FrozenSet, List, Optional, Tuple

from reNgine.core.exceptions import FindingOutOfScopeError
from reNgine.secator.synthetic_id import synthetic_id_skipped_scope

from . import nuclei as nuclei_mod
from .dns import handle_asn_tag, handle_whois_tag
from .handlers import handle_secret_tag, handle_url_pattern_tag


TagHandler = Callable[[Dict[str, Any], int, int], Tuple[Optional[Any], Optional[int]]]

_tag_handlers: Dict[Tuple[str, Optional[str]], TagHandler] = {}
_tag_ignore_rules: List[Tuple[str, str, Optional[FrozenSet[str]]]] = []


def register_tag_handler(
    category: str,
    name: Optional[str],
    handler: TagHandler,
) -> None:
    """Register a handler for (category, name). Use name=None for a category-wide handler."""
    key = (category.strip(), name.strip() if isinstance(name, str) else name)
    _tag_handlers[key] = handler


def register_ignored_tag(
    category: str,
    name: str,
    *,
    allowed_sources: Optional[Collection[str]] = None,
) -> None:
    """
    Register a tag (category, name) as ignored (no persistence, synthetic id).

    If allowed_sources is None, the pair is ignored regardless of ``_source``.
    Otherwise ignoring applies only when normalized ``_source`` is in allowed_sources
    (lowercase comparison; Secator task names such as ``netdetect`` / ``prompt``).
    """
    cat = category.strip()
    tag_name = name.strip()
    src_set: Optional[FrozenSet[str]]
    if allowed_sources is None:
        src_set = None
    else:
        src_set = frozenset(s.strip().lower() for s in allowed_sources if isinstance(s, str) and s.strip())
    _tag_ignore_rules.append((cat, tag_name, src_set))
    _rebuild_tag_ignored_export()


def _tag_ignore_pairs_snapshot() -> FrozenSet[Tuple[str, str]]:
    return frozenset((c, n) for c, n, _ in _tag_ignore_rules)


def _rebuild_tag_ignored_export() -> None:
    global TAG_IGNORED
    TAG_IGNORED = _tag_ignore_pairs_snapshot()


TAG_IGNORED: FrozenSet[Tuple[str, str]] = frozenset()


def is_registered_ignored_tag_pair(category: str, name: str) -> bool:
    """True if (category, name) has any ignore rule (regardless of source filter)."""
    c, n = category.strip(), name.strip()
    return any(rc == c and rn == n for rc, rn, _ in _tag_ignore_rules)


def _normalized_finding_source(finding_data: Dict[str, Any]) -> str:
    src = finding_data.get("_source")
    if isinstance(src, str) and src.strip():
        return src.strip().lower()
    return ""


def is_tag_ignored(finding_data: Dict[str, Any]) -> bool:
    """True when this payload matches an ignore rule and optional ``_source`` filter."""
    category = (finding_data.get("category") or "").strip()
    name = (finding_data.get("name") or "").strip()
    norm_src = _normalized_finding_source(finding_data)
    for rule_cat, rule_name, allowed in _tag_ignore_rules:
        if rule_cat != category or rule_name != name:
            continue
        if allowed is None:
            return True
        return norm_src in allowed
    return False


def get_tag_handler(category: str, name: str) -> Optional[TagHandler]:
    """Return the handler for (category, name), or None for fallback to TechnologyRepository."""
    key_specific = (category, name)
    if key_specific in _tag_handlers:
        return _tag_handlers[key_specific]
    key_any = (category, None)
    if key_any in _tag_handlers:
        return _tag_handlers[key_any]
    return None


def _tag_label(category: str, name: str) -> str:
    return "category=%s name=%s" % (category or "?", name or "?")


def _format_tag_error(category: str, name: str, detail: str) -> str:
    return "Failed to save tag (%s): %s" % (_tag_label(category, name), detail)


def _apply_builtin_registrations() -> None:
    register_tag_handler("info", "whois", handle_whois_tag)
    register_tag_handler("url_pattern", None, handle_url_pattern_tag)
    register_tag_handler("info", "asn", handle_asn_tag)
    register_tag_handler("secret", None, handle_secret_tag)
    # Secator tasks: netdetect (net_*), prompt (user_input); see secator/tasks/netdetect.py, prompt.py
    register_ignored_tag("info", "net_interface", allowed_sources=("netdetect",))
    register_ignored_tag("info", "net_cidr", allowed_sources=("netdetect",))
    register_ignored_tag("info", "user_input", allowed_sources=("prompt",))
    _rebuild_tag_ignored_export()


_apply_builtin_registrations()


def dispatch_secator_tag(
    finding_data: Dict[str, Any],
    scan_history_id: int,
    target_id: int,
    validate_scan_context: Callable[..., Tuple[bool, Any, Any, Any]],
    is_update: bool = False,
) -> Tuple[str, ...]:
    """
    Route a Secator tag finding to the appropriate handler or indicate fallback/ignored.

    Returns:
        ("ignored", synthetic_id)
        ("skipped", synthetic_id)
        ("success", saved_object)
        ("error", status_code, error_message)
        ("fallback",) — caller uses TechnologyRepository
    """
    category = (finding_data.get("category") or "").strip()
    name = (finding_data.get("name") or "").strip()

    if is_tag_ignored(finding_data):
        synthetic_id = "tag_ignored_%s_%s_%d" % (category, name, int(time.time() * 1000))
        return ("ignored", synthetic_id)

    handler = get_tag_handler(category, name)
    if handler is not None:
        is_valid, error_response, _scan_history, target = validate_scan_context(scan_history_id, target_id)
        if not is_valid:
            err_msg = "Validation failed"
            if getattr(error_response, "data", None) and isinstance(error_response.data, dict):
                err_msg = error_response.data.get("error", err_msg)
            if not isinstance(err_msg, str):
                err_msg = str(err_msg)
            return (
                "error",
                error_response.status_code,
                _format_tag_error(category, name, "invalid scan or target context: %s" % err_msg),
            )

        effective_target_id = target.id if target else target_id
        try:
            saved_object, error_status = handler(finding_data, scan_history_id, effective_target_id)
        except FindingOutOfScopeError:
            synthetic_id = synthetic_id_skipped_scope("tag", tag_category=category, tag_name=name)
            return ("skipped", synthetic_id)
        if error_status is not None:
            msg = _format_tag_error(
                category,
                name,
                "handler reported validation error or missing required fields.",
            )
            return ("error", error_status, msg)
        if saved_object is not None:
            return ("success", saved_object)
        msg = _format_tag_error(
            category,
            name,
            "domain, endpoint, or related entity not found, or validation failed.",
        )
        fallback_status = 400 if is_update else 422
        return ("error", fallback_status, msg)

    if nuclei_mod.should_route_nuclei_tag_to_dns_record(finding_data):
        is_valid, error_response, _scan_history, target = validate_scan_context(scan_history_id, target_id)
        if not is_valid:
            err_msg = "Validation failed"
            if getattr(error_response, "data", None) and isinstance(error_response.data, dict):
                err_msg = error_response.data.get("error", err_msg)
            if not isinstance(err_msg, str):
                err_msg = str(err_msg)
            return (
                "error",
                error_response.status_code,
                _format_tag_error(category, name, "invalid scan or target context: %s" % err_msg),
            )

        effective_target_id = target.id if target else target_id
        try:
            item = nuclei_mod.build_nuclei_dns_record_item(finding_data)
            if not (item.get("name") or "").strip():
                msg = _format_tag_error(category, name, "Nuclei DNS tag missing record name (match).")
                return ("error", 400 if is_update else 422, msg)
            from reNgine.services.repositories.dns_repository import DnsRepository

            saved_object = DnsRepository().save_from_secator(
                item,
                scan_history_id,
                effective_target_id,
                rengine_context=dict(finding_data.get("_context") or {}),
            )
        except FindingOutOfScopeError:
            synthetic_id = synthetic_id_skipped_scope("tag", tag_category=category, tag_name=name)
            return ("skipped", synthetic_id)
        if saved_object is None:
            msg = _format_tag_error(
                category,
                name,
                "could not persist Nuclei DNS record (validation or scope).",
            )
            return ("error", 400 if is_update else 422, msg)
        return ("success", saved_object)

    if nuclei_mod.is_nuclei_tag(finding_data):
        if not nuclei_mod.is_nuclei_technology_tag(finding_data):
            synthetic_id = "tag_ignored_nuclei_non_tech_%d" % int(time.time() * 1000)
            return ("ignored", synthetic_id)

        is_valid, error_response, _scan_history, target = validate_scan_context(scan_history_id, target_id)
        if not is_valid:
            err_msg = "Validation failed"
            if getattr(error_response, "data", None) and isinstance(error_response.data, dict):
                err_msg = error_response.data.get("error", err_msg)
            if not isinstance(err_msg, str):
                err_msg = str(err_msg)
            return (
                "error",
                error_response.status_code,
                _format_tag_error(category, name, "invalid scan or target context: %s" % err_msg),
            )

        effective_target_id = target.id if target else target_id
        try:
            item = nuclei_mod.build_nuclei_technology_item(finding_data)
            from reNgine.services.repositories.technology_repository import TechnologyRepository

            saved_object = TechnologyRepository().save_from_secator(
                item,
                scan_history_id,
                effective_target_id,
                rengine_context=dict(finding_data.get("_context") or {}),
            )
        except FindingOutOfScopeError:
            synthetic_id = synthetic_id_skipped_scope("tag", tag_category=category, tag_name=name)
            return ("skipped", synthetic_id)
        if saved_object is None:
            msg = _format_tag_error(
                category,
                name,
                "could not persist Nuclei technology fingerprint.",
            )
            return ("error", 400 if is_update else 422, msg)
        return ("success", saved_object)

    return ("fallback",)
