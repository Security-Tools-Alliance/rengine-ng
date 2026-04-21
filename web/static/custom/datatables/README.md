# DataTables helper stack (reNgine-ng)

This folder contains the shared DataTables frontend modules. **Script load order and dependencies must be respected** to avoid subtle runtime errors (e.g. `safeText` undefined, rowGroup or filter logic failing).

## High-level overview and cross-file coupling

**Dependency order (logical):** `escape.js` → `layout.js`, `cookies.js`, `columns.js`, `filters.js`, `config.js`, `filter_ids.js` → `page_wiring.js` (needs filter_ids + filters) → `rowgroup.js` (needs layout + cookies) → `actions.js` (needs escape + config) → `init.js` (needs layout, config, filters, rowgroup, columns) → `tooltips.js`, `column_definitions.js`.

**Backend → frontend mapping (keep in sync when adding tables or filters):**

| Backend (Python) | Frontend (JS) | Role |
|------------------|---------------|------|
| `web/api/helpers/datatables/filters.py` → **FILTER_CONTEXT_*** (e.g. `FILTER_CONTEXT_SCAN_HISTORY`) | `filter_ids.js` → **RENGINE_FILTER_IDS** / **RENGINE_FILTER_IDS_*** (e.g. `RENGINE_FILTER_IDS_SCAN_HISTORY`) | Keys = HTML `<select id="...">`; values (backend) = API param names. Filter partials must use the same select IDs as keys. |
| `web/api/helpers/datatables/table_config.py` → **TABLE_ID_*** / **DATATABLE_TABLE_CONFIGS** | `page_wiring.js` → **RENGINE_PAGE_WIRING** (keys = same TABLE_IDs) | Per-table filter UI: `filteringTextId`, `resetFiltersId`, `filterBadgeSpec`. Use `getRengineDatatableFilterAttachOpts(tableId, tableApi)` so templates stay DRY. |
| Backend passes `datatable_filter_select_to_param` (select id → param) in a script tag | `config.js` → **RENGINE_DATATABLE_FILTER_PARAMS_SCRIPT_ID**; `filters.js` → **getRengineDatatableFilterParams(elementId)** | Templates put the mapping in a `<script id="datatable-filter-params">`; init merges it into `ajax.data` via **buildDatatableFilterPayload**. |

**URL sanitization (security):** All link hrefs must go through **escape.js**: **sanitizeUrlForHref** / **normalizeSafeLinkUrl** (same logic) and **safeLink**. Allowed schemes: `http`, `https`, `mailto`; protocol-relative `//` and relative paths allowed. Any other scheme (e.g. `javascript:`, `data:`, `file:`) is rejected. Do not reimplement or bypass in other files; see comments in `escape.js`.

## Load order (do not rearrange script tags in `base.html`)

Load scripts in this exact order:

| Order | File | Depends on | Purpose |
|-------|------|------------|---------|
| 1 | `escape.js` | (none) | Canonical escaping: `safeText`, `safeAttr`, `safeBadge`, `safeLink`, `safeTooltipTitle`. Required by all renderers and dynamic HTML. |
| 2 | `layout.js` | escape | Scroller options, length menu, `getRengineDatatableLayoutFull`. |
| 3 | `cookies.js` | (none) | Cookie read/write for rowGroup and preferences. |
| 4 | `columns.js` | (none) | `getColumnIndexByName`, `rengineColumnByName`, `getRengineDatatableOrderFromNames`. |
| 5 | `rowgroup.js` | layout, cookies | `getRengineRowGroupInitialState`, rowGroup selector attachment. |
| 6 | `filters.js` | (none) | `getRengineDatatableFilterParams`, `buildRengineDatatableAjaxData`, `attachDatatableFilters`, `populateScanHistoryFilterChoices`. |
| 7 | `config.js` | (none) | Element IDs for filter/rowGroup script tags; `getRengineRowGroupConfigFromScript`, `getRengineRowGroupConfig`. |
| 8 | `filter_ids.js` | (none) | Central filter select IDs per table: `RENGINE_FILTER_IDS_*`, `getFilterSelectIdsForTable(tableId)`. Mirror of Python `FILTER_CONTEXT_*` keys. |
| 9 | `page_wiring.js` | filter_ids, filters | Per-table wiring: `RENGINE_PAGE_WIRING`, `getRengineDatatableFilterAttachOpts(tableId, tableApi, overrides)` for attachDatatableFilters options (filterSelectIds, badge spec, filteringTextId, resetFiltersId). |
| 10 | `actions.js` | escape, config | Action column renderers (subdomain, vulnerability, target); uses `safeAttr`/`safeText`. |
| 11 | `init.js` | layout, config, filters, rowgroup, columns | `getRengineDatatableConfig`, `initServerSideDataTable`, **`initRengineServerSideDataTable`** (main entry), **`initDetailScanServerSideTable`** (detail-scan tables: default scroll 60vh, layout, drawCallback tooltips). |
| 12 | `tooltips.js` | (none) | `getRengineDatatableDrawCallbackTooltips` for drawCallback. |
| 13 | `column_definitions.js` | (none) | Shared column arrays and default order/rowGroup (vuln, subdomain tables). `getSafeTextColumnDef`, `getSafeNumberColumnDef`. |

**Dependency chain (logical):**

- `escape.js` → first (no deps).
- `layout.js`, `cookies.js`, `columns.js`, `filters.js`, `config.js`, `filter_ids.js`, `page_wiring.js` → after escape; page_wiring depends on filter_ids and filters.
- `rowgroup.js` → after layout + cookies.
- `actions.js` → after escape + config (for element IDs).
- `init.js` → after layout, config, filters, rowgroup, columns (wires everything).
- `tooltips.js`, `column_definitions.js` → last (optional enhancements).

## Per-table wiring (filters and badges)

Filter select IDs, badge labels, and element IDs (filteringTextId, resetFiltersId) are centralized in `page_wiring.js` per TABLE_ID (same as backend `api/helpers/datatables/table_config.py`). Use **`getRengineDatatableFilterAttachOpts(tableId, tableApi, overrides)`** to build the options for `attachDatatableFilters` (or `attachRengineDatatableFiltersAndRowGroup`). Templates only pass the table id, the DataTable API, and optional overrides (e.g. `onApply: function() { table.draw(); }`). Adding or renaming a filter requires updating `RENGINE_PAGE_WIRING` and the filter partial only.

## Filter options from API

Scan-history and subscan-history pages populate all four filter selects (Organization, Status, Target, Scan type) from a single API call. Use `populateScanHistoryFilterChoices(projectSlug, filterChoicesUrl, context)` with `context` `'scan_history'` or `'subscan_history'`. The backend `GET /api/scanHistoryFilterChoices/?project=<slug>` returns `{ organizations, scan_status_labels, task_status_labels, targets, scan_engines }`. See wiki `datatables-api-filters.md` for the response format.

## Filter warnings (DEBUG)

When filter helpers receive malformed params they log warnings. To view them without scanning logs: `GET /api/health/datatables-filters/` (only when `DEBUG=True`). Use `?clear=1` to return and clear the list. Documented in wiki `datatables-api-filters.md`. The footer can show a link when `debug` is in the template context (e.g. Django’s `debug` context processor with `INTERNAL_IPS`).

## Backend / frontend contract

- **Filter select IDs** and **query param names** are defined in Python: `web/api/helpers/datatables/` (`filters.py` for `FILTER_CONTEXT_*`, `table_config.py` for `DATATABLE_TABLE_CONFIGS`). The frontend mirror is `filter_ids.js` (`RENGINE_FILTER_IDS_*`, `getFilterSelectIdsForTable(tableId)`). Use these in templates instead of hardcoding select ID arrays. Filter partials under `web/templates/base/_items/datatables_filters/` must use the same `<select id="...">` as the keys of the corresponding `FILTER_CONTEXT_*`. Use `validate_datatable_filter_config()` or the tests in `web/api/tests/test_datatables.py` to catch drift.
- **Column maps** and **table configs** are in `api/helpers/datatables/column_maps.py` and `table_config.py`; keep JS column definitions and backend column maps in sync.

### Column indices vs names

- **Backend** (`column_maps.py`): `DATATABLE_COLUMN_MAP_*` keys are **column indices as strings** (`"0"`, `"1"`, …). They are used for server-side ordering: `order[0][column]` sent by DataTables is an index; the backend maps it to a model field. **Index = position in the frontend `columns` array** (first column = 0).
- **Frontend**: Prefer **name-based** `columnDefs.targets` (e.g. `targets: "http_url"`, `targets: "name"`) instead of numeric indices. Give every column a `name` property (same as `data` when the column is bound to a single field). That way adding or reordering columns does not break render/visibility; only the backend column map must be updated when orderable columns change.
- **When adding or reordering columns**: (1) Update the frontend `columns` array (and add `name` if missing); (2) Update the backend `DATATABLE_COLUMN_MAP_*` for that table so keys still match the new indices for **orderable** columns; (3) Keep `columnDefs` using `targets: "columnName"` so they stay correct. See `column_definitions.js` top docstring for the vuln/subdomain index→name tables and `column_maps.py` for the backend maps.

## Shared column renderers (vulnerability / subdomain)

To reduce duplicated render logic across `detail_scan.html`, `vulnerabilities.html`, and `target/summary.html`, use the shared column defs from `column_definitions.js`:

- **Vulnerability**: `RengineDatatableColumnDefs.getVulnSeverityBadgeColumnDef('severity:name')`, `getVulnHttpUrlLinkColumnDef('http_url:name', { maxLength: 80 })`, `getSafeTextColumnDef('cvss_vec:name')`, `getSafeNumberColumnDef('confidence_nb:name')`. Use with `RENGINE_VULN_DATATABLE_COLUMNS` and action column from `actions.js` (`renderVulnerabilityActions`).
- **Subdomain**: `RengineDatatableColumnDefs.getSubdomainHttpStatusBadgeColumnDef('http_status:name')`, `getBadgeColumnDef`, `getLinkColumnDef` for name/URL. Use with `RENGINE_SUBDOMAIN_DATATABLE_COLUMNS` and `renderSubdomainActions`.

Prefer these over inline `render: function (...) { return '<span class="...">' + ... }` in templates so encoding and styling stay consistent and future changes are in one place.

## Escaping (XSS)

All renderers and any code that builds HTML from server or user data must use the helpers from `escape.js` only: `safeText`, `safeAttr`, `safeBadge`, `safeBadgeWithTooltip` (badge with `title` for tooltips), `safeLink`, `safeTooltipTitle`. Do not assemble HTML with string concatenation or template literals for that data. Use `safeBadgeWithTooltip(title, displayText, badgeClass, iconClass, extraInnerHtml)` for badge+tooltip patterns (e.g. in `detail_scan.js`, `port_display.js`) so encoding stays centralized.

**URL sanitization (single source of truth):** Use `sanitizeUrlForHref(url)` or `normalizeSafeLinkUrl(url)` (same function) for any URL before putting it in an `href` or passing to `safeLink`. Allowed schemes: `http`, `https`, `mailto`; protocol-relative and relative paths allowed. Non-string/non-number input returns `""`. Do not reimplement in other files; see comments in `escape.js`.

**Test harness:** `escape_harness.js` provides minimal unit checks for `safeText`, `safeAttr`, `safeLink`, and (if loaded) `normalizeSafeLinkUrl`. Load it after `escape.js` on any page that has the datatables stack, then run `RengineDatatableEscapeHarness.run()` in the browser console. It verifies null/undefined, angle brackets and quotes, blocked schemes (javascript:, data:), protocol-relative URLs, and mailto handling.
