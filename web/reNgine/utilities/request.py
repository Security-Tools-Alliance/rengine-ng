"""
Helpers for reading request data from either form POST or JSON body.

Use these when an endpoint accepts both application/x-www-form-urlencoded
and application/json with the same logical keys, so parsing and error
handling stay consistent.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional, Tuple


if TYPE_CHECKING:
    from django.http import HttpRequest


def get_string_from_post_or_json(
    request: HttpRequest,
    key: str = "raw",
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract a string value from POST form data or JSON body.

    Checks request.POST[key] first; if missing and request has a body,
    decodes as UTF-8 JSON and returns data[key] if it is a string.
    Invalid JSON returns an error message so callers can respond with 400.

    Returns:
        (value, error): value is the string or None; error is a message
        for 400 response (e.g. "Invalid JSON body") or None.
    """
    content_type = (request.content_type or "").lower()
    if "application/json" not in content_type:
        post_val = request.POST.get(key)
        return (post_val if isinstance(post_val, str) else None, None)
    if not request.body:
        return (None, None)
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return (None, "Invalid JSON body")
    if not isinstance(data, dict) or key not in data:
        return (None, None)
    val = data[key]
    return (val if isinstance(val, str) else None, None)
