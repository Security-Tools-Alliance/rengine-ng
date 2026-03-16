"""
DataTables column index -> order field maps and ordering helpers.

Keys are DataTables column indices as strings ("0", "1", ...). Values are Django model
fields or lookups for order_by(). Views use apply_datatables_order(qs, request, DATATABLE_COLUMN_MAP_XXX);
the index sent in order[0][column] must exist as a key in the map.

Contract: column maps, serializer, and frontend columns array must stay in sync when adding,
moving, or removing columns. Index N = position in the frontend columns array (0-based).
Frontend should use name-based columnDefs (targets: "columnName") so render/visibility do not
depend on indices; only ordering uses indices via this map. See README "Column indices vs names".
"""

from django.db.models import F, QuerySet
from django.http import HttpRequest


# --- Column index -> order field maps (must match frontend DataTables column order) ---

DATATABLE_COLUMN_MAP_SUBDOMAIN_CHANGES = {
    "0": "name",
    "1": "page_title",
    "2": "http_status",
    "3": "content_length",
    "4": "change",
    "5": "http_url",
    "6": "is_cdn",
    "7": "is_important",
}

DATATABLE_COLUMN_MAP_ENDPOINT_CHANGES = {
    "0": "http_url",
    "1": "page_title",
    "2": "http_status",
    "3": "content_length",
    "4": "change",
}

DATATABLE_COLUMN_MAP_INTERESTING_SUBDOMAIN = {
    "0": "name",
    "1": "page_title",
    "2": "http_status",
    "3": "content_length",
}

DATATABLE_COLUMN_MAP_INTERESTING_ENDPOINT = {
    "0": "http_url",
    "1": "page_title",
    "2": "http_status",
    "3": "matched_gf_patterns",
    "4": "content_type",
    "5": "content_length",
    "6": "response_time",
    "7": "screenshot_url",
    "8": "techs",
    "9": "webserver",
}

DATATABLE_COLUMN_MAP_SUBDOMAIN = {
    "0": "checked",
    "1": "name",
    "4": "http_status",
    "5": "page_title",
    "8": "content_length",
    "10": "response_time",
}

DATATABLE_COLUMN_MAP_ENDPOINT = {
    "1": "http_url",
    "2": "http_status",
    "3": "page_title",
    "4": "matched_gf_patterns",
    "5": "content_type",
    "6": "content_length",
    "7": "techs",
    "8": "webserver",
    "9": "response_time",
}

DATATABLE_COLUMN_MAP_VULNERABILITY = {
    "1": "source",
    "3": "name",
    "7": "severity",
    "11": "http_url",
    "15": "open_status",
}

DATATABLE_COLUMN_MAP_SECRET = {
    "0": "id",
    "1": "rule_name",
    "2": "matched_at",
    "3": "source",
    "4": "value",
    "5": "discovered_date",
}

DATATABLE_COLUMN_MAP_EXPLOIT = {
    "0": "id",
    "1": "name",
    "2": "exploit_id",
    "3": "provider",
    "4": "discovered_date",
    "5": "reference",
    "6": "matched_at",
    "7": "domain__name",
    "8": "discovered_date",
    "9": "discovered_date",
    "10": "id",
}

DATATABLE_COLUMN_MAP_IPS = {
    "0": "address",
    "1": "alive",
    "2": "is_cdn",
}

DATATABLE_COLUMN_MAP_DIRECTORY = {
    "0": "url",
    "1": "name",
    "2": "http_status",
    "3": "length",
    "4": "lines",
    "5": "words",
}

DATATABLE_COLUMN_MAP_SCOPES = {
    "0": "name",
    "1": "organization__name",
    "2": "scope_type",
    "3": "start_date",
    "4": "end_date",
    "5": "target_count",
    "6": "worker_count",
    "7": "insert_date",
}

DATATABLE_COLUMN_MAP_ORGANIZATIONS = {
    "0": "name",
    "1": "description",
    "2": "scope_count",
    "3": "total_targets",
    "4": "insert_date",
}

DATATABLE_COLUMN_MAP_SCAN_HISTORY = {
    "1": "id",
    "2": "target__value",
    "3": "start_scan_date",
    "4": "scan_type__engine_name",
    "5": "id",
    "6": "start_scan_date",
    "7": "initiated_by__username",
    "8": "scan_status",
    "9": "scan_status",
    "11": "target__scopes__name",
}

DATATABLE_COLUMN_MAP_SUBSCAN_HISTORY = {
    "2": "scan_history__target__value",
    "3": "engine__engine_name",
    "4": "id",
    "5": "start_scan_date",
    "6": "status",
    "7": "start_scan_date",
}

DATATABLE_COLUMN_MAP_SCHEDULED_SCANS = {
    "0": "name",
    "1": "frequency_type",
    "2": "last_run_at",
    "3": "total_run_count",
    "4": "one_off",
    "5": "enabled",
}

DATATABLE_COLUMN_MAP_TARGETS = {
    "2": "value",
    "6": "last_scan_start_date_annot",
    "10": "insert_date",
    "14": "scope_group_name",
}

DATATABLE_COLUMN_MAP_S3_BUCKETS = {
    "0": "name",
    "1": "region",
    "2": "provider",
    "4": "num_objects",
    "5": "size",
}

DATATABLE_COLUMN_MAP_WORDLIST = {
    "0": "name",
    "1": "short_name",
    "2": "count",
}

DATATABLE_COLUMN_MAP_SCAN_ENGINE = {
    "0": "id",
    "1": "engine_name",
    "2": "default_engine",
    "3": "scan_type",
}

# Fields that should be ordered with nulls last (e.g. never-scanned targets at the end).
DATATABLE_NULLS_LAST_FIELDS = frozenset({"last_scan_start_date_annot"})


def get_datatables_order_column(
    request: HttpRequest,
    column_map: dict[str, str],
    default_order: str = "id",
) -> str:
    """
    Resolve DataTables order[0][column] and order[0][dir] to an order_by string.

    Column map values must be bare field names (no leading "-"). Default_order is
    used when the column is missing or not in the map; it may be prefixed (e.g.
    "-severity") to indicate default descending. Request direction (asc/desc) is
    always applied when present; when absent, direction is taken from
    default_order only when the fallback was used.
    """
    order_col = request.GET.get("order[0][column]", None)
    order_direction = request.GET.get("order[0][dir]", None)
    if order_col is not None and str(order_col) in column_map:
        field = column_map[str(order_col)]
        assert not field.startswith("-"), (
            "column_map must use bare field names only; use default_order for default direction"
        )
        used_default = False
    else:
        field = default_order or "id"
        used_default = True
    bare_field = field.lstrip("-") or "id"
    if order_direction == "desc":
        return f"-{bare_field}"
    if order_direction == "asc":
        return bare_field
    if used_default and field.startswith("-"):
        return f"-{bare_field}"
    return bare_field


def apply_datatables_order(
    queryset: QuerySet,
    request: HttpRequest,
    column_map: dict[str, str],
    default_order: str = "id",
    nulls_last_fields: set[str] | frozenset[str] | None = None,
) -> QuerySet:
    """
    Apply DataTables order params to a queryset.

    When nulls_last_fields is set and the resolved order field is in it,
    uses F(field).asc(nulls_last=True) or .desc(nulls_last=True) so nulls
    appear last. Otherwise uses plain order_by(order_str).
    """
    order_str = get_datatables_order_column(request, column_map, default_order)
    fields = nulls_last_fields or set()
    field = order_str.lstrip("-")
    if field in fields:
        desc = order_str.startswith("-")
        return queryset.order_by(F(field).desc(nulls_last=True) if desc else F(field).asc(nulls_last=True))
    return queryset.order_by(order_str)


def get_datatables_column_search_value(
    request: HttpRequest,
    column_map: dict[str, str],
    field_name: str,
) -> str:
    """
    Return the search value for a given DataTables column (columns[i][search][value]).

    field_name must match the value in the column_map (e.g. "value" for targets).
    When multiple indices map to the same field, the first non-empty search value is returned.
    """
    if request is None or not isinstance(column_map, dict) or not field_name:
        return ""
    indices = [idx for idx, name in column_map.items() if name == field_name]
    if not indices:
        return ""
    for idx in indices:
        raw = request.GET.get(f"columns[{idx}][search][value]", "") or ""
        value = raw.strip()
        if value:
            return value
    return ""
