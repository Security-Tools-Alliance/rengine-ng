"""
Per-table DataTables config: table IDs, row-group cookie/selector, filter context, and validation.

Consumer reference: get_datatable_table_config(table_id) is used in startScan.views and
targetApp.views to pass datatable_filter_select_to_param, datatable_row_group_cookie_key and
datatable_row_group_selector to templates. validate_datatable_filter_config() is called from
tests to catch drift between backend FILTER_CONTEXT_* and frontend filter partials (select id
must match FILTER_CONTEXT_* keys).
"""

from typing import Any

from .filters import (
    FILTER_CONTEXT_ORGANIZATION_LIST,
    FILTER_CONTEXT_S3_BUCKETS,
    FILTER_CONTEXT_SCAN_ENGINE_LIST,
    FILTER_CONTEXT_SCAN_HISTORY,
    FILTER_CONTEXT_SCOPE_LIST,
    FILTER_CONTEXT_SUBSCAN_HISTORY,
    FILTER_CONTEXT_TARGET_LIST,
    FILTER_CONTEXT_WORDLIST_LIST,
)


# --- Table IDs: template and filter partial mapping ---
# When adding or renaming a table, update the corresponding template and filter partial here and in filters.py.

# Template: startScan/templates/startScan/history.html | Filter partial: base/_items/datatables_filters/filters_scan_history.html (id_prefix: scanHistory)
TABLE_ID_SCAN_HISTORY = "scan_history"

# Template: startScan/templates/startScan/subscan_history.html | Filter partial: base/_items/datatables_filters/filters_scan_history.html (id_prefix: subscanHistory)
TABLE_ID_SUBSCAN_HISTORY = "subscan_history"

# Template: targetApp/templates/target/list.html | Filter partial: base/_items/datatables_filters/filters_target_list.html (id_prefix: targetList)
TABLE_ID_TARGET_LIST = "target_list"

# Template: targetApp/templates/scope/list.html | Filter partial: base/_items/datatables_filters/filters_scope_list.html (id_prefix: scopeList)
TABLE_ID_SCOPE_LIST = "scope_list"

# Template: targetApp/templates/organization/list.html | Filter partial: base/_items/datatables_filters/filters_organization_list.html (id_prefix: organizationList)
TABLE_ID_ORGANIZATION_LIST = "organization_list"

# No filter context. Template: startScan/templates/startScan/detail_scan.html (vulnerabilities tab).
TABLE_ID_VULNERABILITIES = "vulnerabilities"

# No filter context. Template: startScan/templates/startScan/detail_scan.html (secrets tab).
TABLE_ID_SECRETS = "secrets"

# No filter context. Template: startScan/templates/startScan/schedule_scan_list.html.
TABLE_ID_SCHEDULED_SCANS = "scheduled_scans"

# Template: scanEngine/templates/scanEngine/wordlist/index.html | Filter partial: base/_items/datatables_filters/filters_wordlist.html (id_prefix: wordlist)
TABLE_ID_WORDLIST_LIST = "wordlist_list"

# Template: scanEngine/templates/scanEngine/index.html | Filter partial: base/_items/datatables_filters/filters_scan_engine.html (id_prefix: scanEngine)
TABLE_ID_SCAN_ENGINE_LIST = "scan_engine_list"

# Template: startScan/templates/startScan/detail_scan.html (S3 tab) | Filter partial: base/_items/datatables_filters/filters_s3_buckets.html
TABLE_ID_S3_BUCKETS = "s3_buckets"

ROW_GROUP_COOKIE_SCAN_HISTORY = "rengine_rowgroup_scan_history"
ROW_GROUP_COOKIE_TARGETS = "rengine_rowgroup_targets"
ROW_GROUP_COOKIE_SCOPE_LIST = "rengine_rowgroup_scope_list"
ROW_GROUP_COOKIE_VULNERABILITIES = "rengine_rowgroup_vulnerabilities"

ROW_GROUP_SELECTOR_SCAN_HISTORY = 'input[name="grouping_scan_history_row"]'
ROW_GROUP_SELECTOR_TARGET = 'input[name="grouping_target_row"]'
ROW_GROUP_SELECTOR_SCOPE = 'input[name="grouping_scope_row"]'
ROW_GROUP_SELECTOR_VULN = 'input[name="grouping_vuln_row"]'
ROW_GROUP_SELECTOR_SUBDOMAIN = 'input[name="grouping_subd_row"]'

DATATABLE_TABLE_CONFIGS: dict[str, dict[str, Any]] = {
    TABLE_ID_SCAN_HISTORY: {
        "table_id": TABLE_ID_SCAN_HISTORY,
        "filter_context": FILTER_CONTEXT_SCAN_HISTORY,
        "row_group_cookie_key": ROW_GROUP_COOKIE_SCAN_HISTORY,
        "row_group_selector": ROW_GROUP_SELECTOR_SCAN_HISTORY,
    },
    TABLE_ID_SUBSCAN_HISTORY: {
        "table_id": TABLE_ID_SUBSCAN_HISTORY,
        "filter_context": FILTER_CONTEXT_SUBSCAN_HISTORY,
        "row_group_cookie_key": None,
        "row_group_selector": None,
    },
    TABLE_ID_TARGET_LIST: {
        "table_id": TABLE_ID_TARGET_LIST,
        "filter_context": FILTER_CONTEXT_TARGET_LIST,
        "row_group_cookie_key": ROW_GROUP_COOKIE_TARGETS,
        "row_group_selector": ROW_GROUP_SELECTOR_TARGET,
    },
    TABLE_ID_SCOPE_LIST: {
        "table_id": TABLE_ID_SCOPE_LIST,
        "filter_context": FILTER_CONTEXT_SCOPE_LIST,
        "row_group_cookie_key": ROW_GROUP_COOKIE_SCOPE_LIST,
        "row_group_selector": ROW_GROUP_SELECTOR_SCOPE,
    },
    TABLE_ID_ORGANIZATION_LIST: {
        "table_id": TABLE_ID_ORGANIZATION_LIST,
        "filter_context": FILTER_CONTEXT_ORGANIZATION_LIST,
        "row_group_cookie_key": None,
        "row_group_selector": None,
    },
    TABLE_ID_VULNERABILITIES: {
        "table_id": TABLE_ID_VULNERABILITIES,
        "filter_context": None,
        "row_group_cookie_key": ROW_GROUP_COOKIE_VULNERABILITIES,
        "row_group_selector": ROW_GROUP_SELECTOR_VULN,
    },
    TABLE_ID_SECRETS: {
        "table_id": TABLE_ID_SECRETS,
        "filter_context": None,
        "row_group_cookie_key": None,
        "row_group_selector": None,
    },
    TABLE_ID_SCHEDULED_SCANS: {
        "table_id": TABLE_ID_SCHEDULED_SCANS,
        "filter_context": None,
        "row_group_cookie_key": None,
        "row_group_selector": None,
    },
    TABLE_ID_WORDLIST_LIST: {
        "table_id": TABLE_ID_WORDLIST_LIST,
        "filter_context": FILTER_CONTEXT_WORDLIST_LIST,
        "row_group_cookie_key": None,
        "row_group_selector": None,
    },
    TABLE_ID_SCAN_ENGINE_LIST: {
        "table_id": TABLE_ID_SCAN_ENGINE_LIST,
        "filter_context": FILTER_CONTEXT_SCAN_ENGINE_LIST,
        "row_group_cookie_key": None,
        "row_group_selector": None,
    },
    TABLE_ID_S3_BUCKETS: {
        "table_id": TABLE_ID_S3_BUCKETS,
        "filter_context": FILTER_CONTEXT_S3_BUCKETS,
        "row_group_cookie_key": None,
        "row_group_selector": None,
    },
}

EXPECTED_FILTER_SELECT_IDS: dict[str, set[str]] = {
    TABLE_ID_SCAN_HISTORY: {
        "filterByOrganization",
        "filterByScope",
        "filterByScanStatus",
        "filterByTarget",
        "filterByScanType",
    },
    TABLE_ID_SUBSCAN_HISTORY: {
        "filterByOrganization",
        "filterByScope",
        "filterByScanStatus",
        "filterByTarget",
        "filterByScanType",
    },
    TABLE_ID_TARGET_LIST: {"filterByOrganization", "filterByScope", "filterByScanPresence"},
    TABLE_ID_SCOPE_LIST: {"filterByOrganization", "filterByScopeType"},
    TABLE_ID_ORGANIZATION_LIST: {"filterByName"},
    TABLE_ID_WORDLIST_LIST: {"filterByName"},
    TABLE_ID_SCAN_ENGINE_LIST: {"filterByEngineName"},
    TABLE_ID_S3_BUCKETS: {"filterByBucketName"},
}
EXPECTED_FILTER_PARAM_NAMES: dict[str, set[str]] = {
    TABLE_ID_SCAN_HISTORY: {
        "filter_organization",
        "filter_scope",
        "filter_status",
        "filter_target",
        "filter_scan_engine",
    },
    TABLE_ID_SUBSCAN_HISTORY: {
        "filter_organization",
        "filter_scope",
        "filter_status",
        "filter_target",
        "filter_scan_engine",
    },
    TABLE_ID_TARGET_LIST: {"filter_organization", "filter_scope", "filter_has_scan"},
    TABLE_ID_SCOPE_LIST: {"filter_organization", "filter_scope_type"},
    TABLE_ID_ORGANIZATION_LIST: {"filter_name"},
    TABLE_ID_WORDLIST_LIST: {"filter_name"},
    TABLE_ID_SCAN_ENGINE_LIST: {"filter_engine_name"},
    TABLE_ID_S3_BUCKETS: {"filter_bucket_name"},
}


def validate_datatable_filter_config() -> list[str]:
    """
    Validate that FILTER_CONTEXT_* and DATATABLE_TABLE_CONFIGS are consistent with expected
    select IDs and param names. Returns a list of error messages; empty list means valid.
    """
    errors: list[str] = []
    for table_id, config in DATATABLE_TABLE_CONFIGS.items():
        ctx = config.get("filter_context")
        if ctx is None:
            continue
        expected_ids = EXPECTED_FILTER_SELECT_IDS.get(table_id)
        expected_params = EXPECTED_FILTER_PARAM_NAMES.get(table_id)
        if expected_ids is None:
            errors.append(f"{table_id}: add EXPECTED_FILTER_SELECT_IDS entry")
            continue
        if expected_params is None:
            errors.append(f"{table_id}: add EXPECTED_FILTER_PARAM_NAMES entry")
            continue
        actual_ids = set(ctx.keys())
        actual_params = set(ctx.values())
        if actual_ids != expected_ids:
            errors.append(f"{table_id}: filter_context keys {actual_ids!r} != expected {expected_ids!r}")
        if actual_params != expected_params:
            errors.append(f"{table_id}: filter_context values {actual_params!r} != expected {expected_params!r}")
    return errors


def get_datatable_table_config(table_id: str) -> dict[str, Any]:
    """
    Return the config dict for a DataTable page (filter_context, row_group_cookie_key, row_group_selector).

    Use in views to pass datatable_filter_select_to_param, datatable_row_group_cookie_key and
    datatable_row_group_selector to templates so the frontend uses a single source of truth.
    """
    return dict(DATATABLE_TABLE_CONFIGS.get(table_id, {}))


def get_datatable_row_group_config(table_id: str) -> dict[str, Any] | None:
    """
    Return a single row-group config dict for the frontend: selector and cookie_key.

    Returns None when row group is disabled for the table.
    """
    cfg = DATATABLE_TABLE_CONFIGS.get(table_id, {})
    selector = cfg.get("row_group_selector")
    cookie_key = cfg.get("row_group_cookie_key")
    if selector and cookie_key:
        return {"selector": selector, "cookie_key": cookie_key}
    return None
