"""
Process-wide filter warnings for DataTables apply_filter_list_in / apply_filter_list_in_by_param.

Consumed by DEBUG-only health view (e.g. GET /api/health/datatables-filters/) so drift or
bad query params are visible without scanning logs.
"""

import threading

from reNgine.utilities.logger import get_module_logger


PREFIX_DATATABLES = "[DATATABLES]"
logger = get_module_logger(__name__)

_filter_warnings_lock = threading.Lock()
_filter_warnings_list: list[str] = []


def append_filter_warning(message: str) -> None:
    with _filter_warnings_lock:
        _filter_warnings_list.append(message)


def log_and_append_filter_warning(message: str) -> None:
    logger.log_line(PREFIX_DATATABLES, "FILTER", message, level="warning")
    append_filter_warning(message)


def get_datatable_filter_warnings(clear: bool = False) -> list[str]:
    """
    Return and optionally clear warnings from apply_filter_list_in / apply_filter_list_in_by_param.

    When inputs are malformed those functions log and return queryset unchanged; they also append
    to this process-wide list. Call from a DEBUG-only health view to surface drift or bad query
    params. clear=True resets the list after return.
    """
    with _filter_warnings_lock:
        out = list(_filter_warnings_list)
        if clear:
            _filter_warnings_list.clear()
    return out
