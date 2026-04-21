"""
Pagination helpers for API views (DataTables and REST style).

Shared by api.views and api.mixins to avoid circular imports and centralize
validation of start/length and page/page_size.
"""

from reNgine.core.data import safe_int_cast
from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)
PREFIX_API = "[API]"

PAGINATION_MAX_LENGTH = 10000

DEFAULT_LIST_LIMIT = 200


def parse_pagination_params(start=None, length=None, page=None, page_size=None):
    """
    Validate and parse pagination parameters from query string.

    Supports two pagination modes:
    - DataTables style: start (offset) and length (page size)
    - REST style: page (page number, 1-indexed) and page_size

    Args:
        start: Starting offset for DataTables pagination
        length: Number of items per page for DataTables pagination
        page: Page number (1-indexed) for REST pagination
        page_size: Number of items per page for REST pagination

    Returns:
        dict: Parsed pagination parameters with 'type', 'start', and 'length' keys

    Raises:
        rest_framework.exceptions.ValidationError: If parameters are invalid
    """
    from rest_framework.exceptions import ValidationError

    try:
        if start is not None and length is not None:
            start_val = int(start)
            length_val = int(length)

            if start_val < 0:
                raise ValueError("Start offset must be non-negative")
            if length_val < -1 or length_val == 0:
                raise ValueError("Length must be positive or -1 for all")
            if length_val == -1:
                length_val = PAGINATION_MAX_LENGTH
            elif length_val > PAGINATION_MAX_LENGTH:
                raise ValueError(f"Length exceeds maximum allowed value ({PAGINATION_MAX_LENGTH})")

            return {"type": "datatables", "start": start_val, "length": length_val}

        if page is not None and page_size is not None:
            page_val = int(page)
            page_size_val = int(page_size)

            if page_val < 1:
                raise ValueError("Page number must be at least 1")
            if page_size_val <= 0:
                raise ValueError("Page size must be positive")
            if page_size_val > PAGINATION_MAX_LENGTH:
                raise ValueError(f"Page size exceeds maximum allowed value ({PAGINATION_MAX_LENGTH})")

            start_val = (page_val - 1) * page_size_val
            return {"type": "rest", "start": start_val, "length": page_size_val, "page": page_val}

        return None

    except ValueError as e:
        logger.log_line(
            PREFIX_API,
            "PAGINATION",
            "Pagination parameter validation error: %s" % (str(e),),
            level="warning",
        )
        raise ValidationError("Invalid pagination parameters.")


def parse_limit_from_request(request, default_limit: int = DEFAULT_LIST_LIMIT) -> int:
    """
    Read and validate limit from request (GET query_params or POST data).

    Used by list endpoints (ListSubScans, ListTodoNotes, ListTechnology) to keep
    limit/total_count behaviour uniform. Limit is capped at PAGINATION_MAX_LENGTH.

    Args:
        request: The HTTP request. For GET, reads query_params["limit"];
            for POST, reads data["limit"] if present.
        default_limit: Value used when limit is missing or invalid.

    Returns:
        int: Limit in range [1, PAGINATION_MAX_LENGTH].
    """
    raw = None
    if request.method == "POST" and getattr(request, "data", None) and request.data:
        raw = request.data.get("limit")
    if raw is None:
        raw = request.query_params.get("limit")
    value = safe_int_cast(raw) if raw is not None else None
    if value is None or value < 1:
        value = default_limit
    return min(max(1, value), PAGINATION_MAX_LENGTH)
