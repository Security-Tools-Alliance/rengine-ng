"""
Shared helpers for DataTables-style list views (column index to order field mapping)
and central wiring of action column URLs for renderers (subdomain, vulnerability, target).

Any view that consumes DataTables GET params order[0][column] and order[0][dir]
must use get_datatables_order_column (or apply_datatables_order) with one of the
central column maps below. Column maps are the single source of truth for
index -> model field; frontend table column order must match these indices.
"""

from typing import Any, Optional

from django.db.models import F, QuerySet
from django.http import HttpRequest
from django.urls import reverse


# --- Central column index -> order field maps (must match frontend DataTables column order) ---

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
    "3": "content_length",
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

# Targets list (Target): indices match targetApp/templates/target/list.html columns.
# Columns: 0=checkbox, 1=id, 2=name, 3=description, 4=summary, 5=id(added on), 6=start_scan_date, 7=action, 8+=hidden.
DATATABLE_COLUMN_MAP_TARGETS = {
    "2": "value",
    "6": "start_scan_date",
    "10": "insert_date",
}


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

    Args:
        request: The HTTP request (GET params: order[0][column], order[0][dir]).
        column_map: Map from column index string to bare model field name, e.g. {"0": "name"}.
        default_order: Field name when column is missing or not in map; may start with "-" for default desc.

    Returns:
        Order string for queryset.order_by(), e.g. "name", "-http_status".
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


# Fields that should be ordered with nulls last (e.g. never-scanned targets at the end).
DATATABLE_NULLS_LAST_FIELDS = frozenset({"start_scan_date"})


def apply_datatables_order(
    queryset: QuerySet[Any],
    request: HttpRequest,
    column_map: dict[str, str],
    default_order: str = "id",
    nulls_last_fields: Optional[set[str]] = None,
) -> QuerySet[Any]:
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


def _target_url_base(url: str) -> str:
    """Strip trailing /0 or /0/ so the frontend can append row.id.
    Returns base with a trailing slash so that (base + id) yields the correct path (e.g. base/2).
    Ensures a leading slash so that href values are absolute paths.
    """
    u = url.rstrip("/")
    base = (u[:-1].rstrip("/")) if u.endswith("/0") else u
    base = base if base.startswith("/") else f"/{base}"
    return base if base.endswith("/") else f"{base}/"


def get_datatable_action_urls(project_slug: str) -> dict:
    """
    Build the full dict of action URLs for datatables_action_renderers.js.

    Target URLs are returned as "base" strings (trailing id stripped) so the
    frontend can append row.id. All other URLs are used as-is.

    Args:
        project_slug: Current project slug for project-scoped URLs.

    Returns:
        Dict with keys 'subdomain', 'vulnerability', 'target', each mapping to
        the URL dict expected by the corresponding renderer.
    """
    return {
        "subdomain": {
            "attackSurface": reverse("api:llm_get_possible_attacks"),
            "toggleSubdomain": reverse("api:toggle_subdomain"),
            "cmsDetector": reverse("api:cms_detector"),
        },
        "vulnerability": {
            "llmReport": reverse("api:llm_vulnerability_report_generator"),
            "hackeroneReport": reverse("api:vulnerability_report"),
            "deleteVulnerability": reverse("api:delete_vulnerability"),
        },
        "target": {
            "targetSummaryBase": _target_url_base(reverse("target_summary", args=[project_slug, 0])),
            "startScanBase": _target_url_base(reverse("start_scan", args=[project_slug, 0])),
            "scheduleScanBase": _target_url_base(reverse("schedule_scan", args=[project_slug, 0])),
            "updateTargetBase": _target_url_base(reverse("update_target", args=[project_slug, 0])),
            "deleteTargetBase": _target_url_base(reverse("delete_target", args=[project_slug, 0])),
        },
    }
