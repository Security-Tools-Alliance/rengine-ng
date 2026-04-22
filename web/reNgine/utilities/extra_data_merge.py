"""
Shallow merge of Secator-style payloads into model JSONField extra_data.

Used by IP, Port, and DNS repositories so empty / non-dict handling and change
detection stay consistent.

Also provides :func:`bounded_diagnostic_preview` for consistent log truncation
when recording malformed payloads.
"""

from typing import Any, Dict, Optional

from reNgine.utilities.logger import get_module_logger


PREFIX_EXTRA_DATA_MERGE = "[EXTRA_DATA_MERGE]"
_logger = get_module_logger(__name__)

_DEFAULT_PREVIEW_MAX_LEN = 200
_PREVIEW_TRUNCATION_SUFFIX = "...[truncated]"


def bounded_diagnostic_preview(
    value: Any,
    max_len: int = _DEFAULT_PREVIEW_MAX_LEN,
    *,
    use_repr: bool = False,
) -> str:
    """
    Build a length-bounded string for logs (malformed Secator / JSONField values).

    Uses ``str`` by default, or ``repr`` when ``use_repr`` is True. On conversion
    failure returns ``<unprintable>``. Truncation keeps the total length at most
    ``max_len`` when the suffix fits.
    """
    try:
        preview = repr(value) if use_repr else str(value)
    except Exception:
        preview = "<unprintable>"
    if len(preview) <= max_len:
        return preview
    suffix = _PREVIEW_TRUNCATION_SUFFIX
    keep = max_len - len(suffix)
    if keep < 1:
        return preview[:max_len]
    return preview[:keep] + suffix


def coerce_extra_data_field_to_plain_dict(value: Any) -> Dict[str, Any]:
    """
    Normalise a JSONField value to a plain dict for shallow merge.

    Non-dict or ``None`` becomes ``{}``. Otherwise performs a shallow copy by iterating
    keys (avoids ``dict()`` fast-path on broken ``dict`` subclasses). On failure,
    returns ``{}`` after logging.
    """
    if value is None or not isinstance(value, dict):
        return {}
    try:
        return {k: value[k] for k in value}
    except (TypeError, ValueError, KeyError):
        preview = bounded_diagnostic_preview(value, use_repr=True)
        _logger.log_line(
            PREFIX_EXTRA_DATA_MERGE,
            "COERCE",
            "Could not copy extra_data mapping to plain dict; using empty dict. raw_type=%s preview=%s"
            % (type(value).__name__, preview),
            level="warning",
        )
        return {}


def merge_extra_data_payload_into_model(
    obj: Any,
    payload: Optional[Dict[str, Any]],
    *,
    field_name: str = "extra_data",
    persist: bool = True,
) -> bool:
    """
    Shallow-merge payload into obj's JSONField (default field_name ``extra_data``).

    Args:
        obj: Model instance with a dict-like JSONField.
        payload: Incoming keys to merge; ignored when None or not a dict. An empty
            dict is allowed and results in no key updates (no-op merge).
        field_name: Attribute name on ``obj`` (default ``extra_data``).
        persist: When True, call ``save(update_fields=[field_name])`` if the field changed.

    Returns:
        True if ``obj``'s field was updated in memory; False if there was nothing to merge
        or no effective change. When ``persist`` is False and this returns True, the caller
        must persist ``obj``.
    """
    if payload is None or not isinstance(payload, dict):
        return False
    existing = getattr(obj, field_name)
    current = coerce_extra_data_field_to_plain_dict(existing)
    before = dict(current)
    for key, val in payload.items():
        current[key] = val
    if current == before:
        return False
    setattr(obj, field_name, current)
    if persist:
        obj.save(update_fields=[field_name])
    return True


def merge_secator_item_extra_data_into_model(
    obj: Any,
    item: Dict[str, Any],
    *,
    field_name: str = "extra_data",
    persist: bool = True,
) -> bool:
    """Merge ``item['extra_data']`` when it is a non-empty dict."""
    raw = item.get("extra_data")
    if not isinstance(raw, dict):
        return False
    return merge_extra_data_payload_into_model(obj, raw, field_name=field_name, persist=persist)
