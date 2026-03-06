"""
DataTables filter query params, filter contexts (select id -> param name), and filter application.

Optional filter query params (filter_organization, filter_status, etc.) are defined here.
Label-to-code helpers (scan status, task status, severity, scope type) live here so the UI
stays in sync with backend resolution. Full endpoint-to-parameter documentation: project wiki
datatables-api-filters.md.
"""

from typing import Any, Callable, Optional

from django.db.models import QuerySet
from django.http import HttpRequest

from .health import log_and_append_filter_warning


# --- Filter parameter names (single source of truth) ---

FILTER_PARAM_ORGANIZATION = "filter_organization"
FILTER_PARAM_STATUS = "filter_status"
FILTER_PARAM_TARGET = "filter_target"
FILTER_PARAM_SCAN_ENGINE = "filter_scan_engine"
FILTER_PARAM_SCOPE = "filter_scope"
FILTER_PARAM_SCOPE_TYPE = "filter_scope_type"
FILTER_PARAM_NAME = "filter_name"

FILTER_PARAM_HTTP_STATUS = "filter_http_status"
FILTER_PARAM_PAGE_TITLE = "filter_page_title"
FILTER_PARAM_SUBDOMAIN = "filter_subdomain"
FILTER_PARAM_SEVERITY = "filter_severity"
FILTER_PARAM_SOURCE = "filter_source"
FILTER_PARAM_ENGINE_NAME = "filter_engine_name"
FILTER_PARAM_BUCKET_NAME = "filter_bucket_name"


# --- Filter contexts (select id -> param name), passed to templates for ajax.data ---
#
# Mapping: keys = HTML element IDs of <select> filters in template partials (e.g. filters_scan_history.html).
# Values = API query param names sent in DataTables ajax.data. Frontend filter_ids.js RENGINE_FILTER_IDS_*
# must list the same select IDs for each table. When adding a filter: add the select in the template
# with this id, add the key here, and add the id to the corresponding RENGINE_FILTER_IDS array in filter_ids.js.
#
# Each FILTER_CONTEXT_* below lists: Template (page) | Filter partial (path under base/_items/datatables_filters/).

# Template: startScan/history.html | Filter partial: filters_scan_history.html
FILTER_CONTEXT_SCAN_HISTORY: dict[str, str] = {
    "filterByOrganization": FILTER_PARAM_ORGANIZATION,
    "filterByScanStatus": FILTER_PARAM_STATUS,
    "filterByTarget": FILTER_PARAM_TARGET,
    "filterByScanType": FILTER_PARAM_SCAN_ENGINE,
}

# Template: startScan/subscan_history.html | Filter partial: filters_scan_history.html
FILTER_CONTEXT_SUBSCAN_HISTORY: dict[str, str] = {
    "filterByOrganization": FILTER_PARAM_ORGANIZATION,
    "filterByScanStatus": FILTER_PARAM_STATUS,
    "filterByTarget": FILTER_PARAM_TARGET,
    "filterByScanType": FILTER_PARAM_SCAN_ENGINE,
}

# Template: targetApp/target/list.html | Filter partial: filters_target_list.html
FILTER_CONTEXT_TARGET_LIST: dict[str, str] = {
    "filterByOrganization": FILTER_PARAM_ORGANIZATION,
    "filterByScope": FILTER_PARAM_SCOPE,
}

# Template: targetApp/scope/list.html | Filter partial: filters_scope_list.html
FILTER_CONTEXT_SCOPE_LIST: dict[str, str] = {
    "filterByOrganization": FILTER_PARAM_ORGANIZATION,
    "filterByScopeType": FILTER_PARAM_SCOPE_TYPE,
}

# Template: targetApp/organization/list.html | Filter partial: filters_organization_list.html
FILTER_CONTEXT_ORGANIZATION_LIST: dict[str, str] = {
    "filterByName": FILTER_PARAM_NAME,
}

# Template: scanEngine/wordlist/index.html | Filter partial: filters_wordlist.html
FILTER_CONTEXT_WORDLIST_LIST: dict[str, str] = {
    "filterByName": FILTER_PARAM_NAME,
}

# Template: scanEngine/index.html | Filter partial: filters_scan_engine.html
FILTER_CONTEXT_SCAN_ENGINE_LIST: dict[str, str] = {
    "filterByEngineName": FILTER_PARAM_ENGINE_NAME,
}

# Template: startScan/detail_scan.html (S3 tab) | Filter partial: filters_s3_buckets.html
FILTER_CONTEXT_S3_BUCKETS: dict[str, str] = {
    "filterByBucketName": FILTER_PARAM_BUCKET_NAME,
}


# --- Label-to-code helpers (single place for status/severity/scope_type) ---

SCAN_STATUS_LABEL_ALIASES = {
    "Scanning": "Running",
    "Aborted": "Failed",
    "Successful": "Completed",
}

TASK_STATUS_LABEL_ALIASES = {
    "In Progress": "RUNNING",
    "Successful": "SUCCESS",
    "Pending": "INITIATED",
    "Aborted": "ABORTED",
    "Failed": "FAILED",
}


def get_scan_status_codes_for_labels(
    labels: list[str],
    aliases: Optional[dict[str, str]] = None,
) -> list[int]:
    """Resolve scan status labels (e.g. from filter dropdown) to ScanHistory.scan_status codes."""
    from reNgine.definitions import SCAN_STATUSES

    label_to_code = {label: code for code, label in SCAN_STATUSES}
    alias_map = aliases if aliases is not None else SCAN_STATUS_LABEL_ALIASES
    return [
        label_to_code.get(alias_map.get(label, label))
        for label in labels
        if label_to_code.get(alias_map.get(label, label)) is not None
    ]


def get_scan_status_filter_labels() -> list[str]:
    """Return the list of labels to show in the scan history status filter dropdown."""
    from reNgine.definitions import SCAN_STATUSES

    label_to_code = {label: code for code, label in SCAN_STATUSES}
    code_to_label: dict[int, str] = {}
    for alias_label, canonical_label in SCAN_STATUS_LABEL_ALIASES.items():
        code = label_to_code.get(canonical_label)
        if code is not None:
            code_to_label.setdefault(code, alias_label)
    labels: list[str] = []
    seen: set[str] = set()
    for code, canonical_label in SCAN_STATUSES:
        label = code_to_label.get(code, canonical_label)
        if label not in seen:
            seen.add(label)
            labels.append(label)
    return labels


def get_task_status_filter_labels() -> list[str]:
    """Return the list of labels to show in the subscan/task status filter dropdown."""
    return ["Pending", "In Progress", "Aborted", "Successful", "Failed"]


def get_task_status_codes_for_labels(
    labels: list[str],
    aliases: Optional[dict[str, str]] = None,
) -> list[int]:
    """Resolve task status labels to SubScan/ScanActivity status codes."""
    from reNgine.definitions import TASK_STATUS_MAP

    display_to_code = {v: k for k, v in TASK_STATUS_MAP.items()}
    alias_map = aliases if aliases is not None else TASK_STATUS_LABEL_ALIASES
    return [
        display_to_code.get(alias_map.get(label, label))
        for label in labels
        if display_to_code.get(alias_map.get(label, label)) is not None
    ]


def get_nuclei_severity_codes_for_labels(labels: list[str]) -> list[int]:
    """Resolve severity labels to Vulnerability severity codes."""
    from reNgine.definitions import NUCLEI_SEVERITY_MAP

    codes = [NUCLEI_SEVERITY_MAP.get(s.lower(), -2) for s in labels]
    return [c for c in codes if c != -2]


def get_scope_type_values_for_labels(labels: list[str]) -> list[str]:
    """Resolve scope type labels to Scope.scope_type values."""
    from targetApp.constants import SCOPE_TYPE_CHOICES

    label_to_value = {label: value for value, label in SCOPE_TYPE_CHOICES}
    return [label_to_value.get(t, t) for t in labels if label_to_value.get(t, t)]


def get_request_filter_list(request: HttpRequest, param_key: str) -> list:
    """
    Return list of filter values for a DataTables multi-value filter param.

    Accepts both param_key and param_key + "[]" (frontend multi-select convention).
    When both are present, param_key takes precedence (getlist(param_key) is used first).
    """
    from_param = list(request.GET.getlist(param_key))
    if from_param:
        return from_param
    return list(request.GET.getlist(f"{param_key}[]"))


def apply_filter_list_in(
    queryset: QuerySet[Any],
    lookup: str,
    values: list,
    value_mapper: Optional[Callable[[Any], Any]] = None,
    distinct: bool = False,
    empty_when_no_valid_values: bool = True,
) -> QuerySet[Any]:
    """
    Apply a __in filter when values is non-empty; optional value_mapper and distinct.

    When value_mapper is used, inputs that map to None are dropped. If all inputs
    map to None and empty_when_no_valid_values=True, returns queryset.none().
    If empty_when_no_valid_values=False, leaves queryset unchanged and logs a
    warning (tolerant of label drift / outdated filter values).
    """
    if queryset is None:
        log_and_append_filter_warning("apply_filter_list_in: queryset is None; returning unchanged")
        return queryset
    if not lookup or not isinstance(lookup, str):
        log_and_append_filter_warning("apply_filter_list_in: lookup is missing or not a string")
        return queryset
    if values is not None and not isinstance(values, list):
        log_and_append_filter_warning(f"apply_filter_list_in: values must be a list; got {type(values).__name__}")
        return queryset
    if not values:
        return queryset
    if value_mapper is not None:
        mapped = [value_mapper(v) for v in values]
        values = [v for v in mapped if v is not None]
    if not values:
        if empty_when_no_valid_values:
            return queryset.none()
        log_and_append_filter_warning("apply_filter_list_in: all values mapped to None; leaving queryset unchanged")
        return queryset
    qs = queryset.filter(**{lookup: values})
    return qs.distinct() if distinct else qs


def apply_filter_list_in_by_param(
    queryset: QuerySet[Any],
    request: HttpRequest,
    param_key: str,
    lookup: str,
    value_mapper: Optional[Callable[[Any], Any]] = None,
    distinct: bool = False,
    strip_empty: bool = True,
) -> QuerySet[Any]:
    """
    Apply a __in filter from request query params. Reads values via get_request_filter_list,
    optionally strips empty strings, then delegates to apply_filter_list_in.
    """
    if queryset is None:
        log_and_append_filter_warning("apply_filter_list_in_by_param: queryset is None; returning unchanged")
        return queryset
    if request is None:
        log_and_append_filter_warning(f"apply_filter_list_in_by_param: request is None for lookup {lookup}")
        return queryset
    if not param_key or not isinstance(param_key, str):
        log_and_append_filter_warning("apply_filter_list_in_by_param: param_key is missing or not a string")
        return queryset
    if not lookup or not isinstance(lookup, str):
        log_and_append_filter_warning("apply_filter_list_in_by_param: lookup is missing or not a string")
        return queryset
    values = get_request_filter_list(request, param_key)
    if strip_empty:
        values = [v for v in values if v]
    return apply_filter_list_in(queryset, lookup, values, value_mapper=value_mapper, distinct=distinct)


def apply_filter_scan_status(queryset: QuerySet[Any], request: HttpRequest) -> QuerySet[Any]:
    """Apply scan status filter (ScanHistory.scan_status) from filter_status param."""
    labels = get_request_filter_list(request, FILTER_PARAM_STATUS)
    if codes := get_scan_status_codes_for_labels(labels):
        queryset = queryset.filter(scan_status__in=codes)
    return queryset


def apply_filter_task_status(queryset: QuerySet[Any], request: HttpRequest) -> QuerySet[Any]:
    """Apply task/subscan status filter (SubScan.status) from filter_status param."""
    labels = get_request_filter_list(request, FILTER_PARAM_STATUS)
    if codes := get_task_status_codes_for_labels(labels):
        queryset = queryset.filter(status__in=codes)
    return queryset


def apply_filter_scope_type(queryset: QuerySet[Any], request: HttpRequest) -> QuerySet[Any]:
    """Apply scope type filter (Scope.scope_type) from filter_scope_type param."""
    labels = get_request_filter_list(request, FILTER_PARAM_SCOPE_TYPE)
    if values := get_scope_type_values_for_labels(labels):
        queryset = queryset.filter(scope_type__in=values)
    return queryset
