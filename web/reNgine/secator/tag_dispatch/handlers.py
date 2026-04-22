"""
Secator tag handlers for URL patterns (gf) and secrets.
"""

from typing import Any, Dict, Optional, Tuple


TagHandlerResult = Tuple[Optional[Any], Optional[int]]


def _is_absent_in_or_chain(val: Any) -> bool:
    """Mirror Python ``or`` short-circuit absent values (None, False, numeric zero, empty string/container)."""
    if val is None or val is False:
        return True
    if isinstance(val, float) and val == 0.0:
        return True
    if isinstance(val, int) and not isinstance(val, bool) and val == 0:
        return True
    if isinstance(val, str):
        return False
    if isinstance(val, (list, tuple, set, dict)) and len(val) == 0:
        return True
    return False


def _strip_tag_string_field(data: Dict[str, Any], *keys: str) -> str:
    """Resolve first key value that would be chosen by chained ``or``, then return stripped text (non-str coerced)."""
    picked: Any = None
    for key in keys:
        val = data.get(key)
        if _is_absent_in_or_chain(val):
            continue
        picked = val
        break
    if picked is None:
        return ""
    if isinstance(picked, str):
        return picked.strip()
    return str(picked).strip()


def _strip_single_tag_field(data: Dict[str, Any], key: str) -> str:
    val = data.get(key)
    if _is_absent_in_or_chain(val):
        return ""
    if isinstance(val, str):
        return val.strip()
    return str(val).strip()


def handle_url_pattern_tag(data: Dict[str, Any], scan_history_id: int, target_id: int) -> TagHandlerResult:
    from reNgine.services.repositories.endpoint_repository import EndpointRepository

    http_url = _strip_tag_string_field(data, "match", "value")
    pattern_name = _strip_single_tag_field(data, "name")
    obj = EndpointRepository().add_gf_pattern_from_secator_tag(scan_history_id, target_id, http_url, pattern_name)
    if obj is not None:
        return (obj, None)
    return (None, 422)


def handle_secret_tag(data: Dict[str, Any], scan_history_id: int, target_id: int) -> TagHandlerResult:
    from reNgine.services.repositories.secret_repository import SecretRepository

    obj = SecretRepository().save_from_secator_tag(data, scan_history_id, target_id)
    if obj is not None:
        return (obj, None)
    return (None, 422)
