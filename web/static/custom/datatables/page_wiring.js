/**
 * Central per-table wiring for DataTables filters and attach options.
 *
 * Consumes TABLE_ID (same as backend api/helpers/datatables/table_config.py TABLE_ID_*). RENGINE_PAGE_WIRING keys
 * must match backend table config and filter_ids.js RENGINE_FILTER_IDS keys (scan_history, target_list, etc.).
 * Templates call getRengineDatatableFilterAttachOpts(tableId, tableApi, opts) instead of repeating filterSelectIds,
 * filteringTextId, resetFiltersId, buildBadgeHtml per page.
 *
 * Depends on: filter_ids.js (getFilterSelectIdsForTable), filters.js (buildRengineFilterBadgesHtml).
 * See README "Backend → frontend mapping" for FILTER_CONTEXT_* / TABLE_ID_* → RENGINE_FILTER_IDS / RENGINE_PAGE_WIRING.
 */
(function (window) {
  "use strict";

  const SCAN_HISTORY_BADGES = [
    { selectId: "filterByOrganization", label: "Organization", badgeClass: "badge-soft-primary" },
    { selectId: "filterByScope", label: "Scope", badgeClass: "badge-soft-info" },
    { selectId: "filterByScanStatus", label: "Status", badgeClass: "badge-soft-info" },
    { selectId: "filterByTarget", label: "Target", badgeClass: "badge-soft-primary" },
    { selectId: "filterByScanType", label: "Engine", badgeClass: "badge-soft-primary" },
  ];

  const RENGINE_PAGE_WIRING = {
    scan_history: {
      filteringTextId: "scanHistoryFilteringText",
      resetFiltersId: "scanHistoryResetFilters",
      filterBadgeSpec: SCAN_HISTORY_BADGES,
      clearChipId: "clearFilterChip",
    },
    subscan_history: {
      filteringTextId: "subscanHistoryFilteringText",
      resetFiltersId: "subscanHistoryResetFilters",
      filterBadgeSpec: SCAN_HISTORY_BADGES,
      clearChipId: "clearFilterChip",
    },
    target_list: {
      filteringTextId: "targetListFilteringText",
      resetFiltersId: "targetListResetFilters",
      filterBadgeSpec: [
        { selectId: "filterByOrganization", label: "Organization", badgeClass: "badge-soft-primary" },
        { selectId: "filterByScope", label: "Scope", badgeClass: "badge-soft-info" },
        { selectId: "filterByScanPresence", label: "Scan Status", badgeClass: "badge-soft-warning" },
      ],
      clearChipId: "clearFilterChip",
    },
    scope_list: {
      filteringTextId: "scopeListFilteringText",
      resetFiltersId: "scopeListResetFilters",
      filterBadgeSpec: [
        { selectId: "filterByOrganization", label: "Organization", badgeClass: "badge-soft-primary" },
        { selectId: "filterByScopeType", label: "Type", badgeClass: "badge-soft-info" },
      ],
      clearChipId: "clearFilterChip",
    },
    organization_list: {
      filteringTextId: "organizationListFilteringText",
      resetFiltersId: "organizationListResetFilters",
      filterBadgeSpec: [
        { selectId: "filterByName", label: "Name", badgeClass: "badge-soft-primary" },
      ],
      clearChipId: "clearFilterChip",
    },
    wordlist_list: {
      filteringTextId: "wordlistFilteringText",
      resetFiltersId: "wordlistResetFilters",
      filterBadgeSpec: [
        { selectId: "filterByName", label: "Wordlist Name", badgeClass: "badge-soft-primary" },
      ],
      clearChipId: "clearFilterChip",
    },
    scan_engine_list: {
      filteringTextId: "scanEngineFilteringText",
      resetFiltersId: "scanEngineResetFilters",
      filterBadgeSpec: [
        { selectId: "filterByEngineName", label: "Engine Name", badgeClass: "badge-soft-primary" },
      ],
      clearChipId: "clearFilterChip",
    },
    s3_buckets: {
      filteringTextId: "filteringText",
      resetFiltersId: "resetFilters",
      filterBadgeSpec: [
        { selectId: "filterByBucketName", label: "Bucket Name", badgeClass: "badge-soft-primary" },
      ],
      clearChipId: "clearFilterChip",
    },
  };

  /**
   * Return options for attachDatatableFilters (and optionally attachRengineDatatableFiltersAndRowGroup)
   * for a given table id. Merges central filter IDs, badge spec, and text/reset element IDs with overrides.
   *
   * @param {string} tableId - Table id (e.g. 'scan_history', 'target_list'). Must match backend TABLE_ID_*.
   * @param {DataTable.Api} tableApi - DataTables API instance (for tableApi and onApply default).
   * @param {Object} [overrides] - Optional overrides: tableApi, filterSelectIds, filteringTextId, resetFiltersId,
   *   buildBadgeHtml, onApply, rowGroup. If onApply not provided, defaults to function() { tableApi.draw(); }.
   * @returns {Object} Options object to pass to attachDatatableFilters or attachRengineDatatableFiltersAndRowGroup.
   */
  const getRengineDatatableFilterAttachOpts = function (tableId, tableApi, overrides) {
    const wiring = tableId && RENGINE_PAGE_WIRING[tableId] ? RENGINE_PAGE_WIRING[tableId] : null;
    const getIds = typeof window.getFilterSelectIdsForTable === "function" ? window.getFilterSelectIdsForTable : function () { return []; };
    const filterSelectIds = (overrides && overrides.filterSelectIds) || (wiring ? getIds(tableId) : []);
    const filteringTextId = (overrides && overrides.filteringTextId != null) ? overrides.filteringTextId : (wiring && wiring.filteringTextId) || "filteringText";
    const resetFiltersId = (overrides && overrides.resetFiltersId != null) ? overrides.resetFiltersId : (wiring && wiring.resetFiltersId) || "resetFilters";
    const buildRengineFilterBadgesHtml = typeof window.buildRengineFilterBadgesHtml === "function" ? window.buildRengineFilterBadgesHtml : function () { return ""; };
    const badgeOpts = wiring && wiring.resetFiltersId ? { resetId: resetFiltersId, clearChipId: (wiring.clearChipId || "clearFilterChip") } : { resetId: resetFiltersId, clearChipId: "clearFilterChip" };
    const buildBadgeHtml = (overrides && overrides.buildBadgeHtml) || (wiring && wiring.filterBadgeSpec
      ? function (selected) { return buildRengineFilterBadgesHtml(selected, wiring.filterBadgeSpec, badgeOpts); }
      : undefined);
    const onApply = (overrides && overrides.onApply) || (tableApi ? function () { if (tableApi && tableApi.draw) tableApi.draw(); } : undefined);

    const opts = {
      tableApi: overrides && overrides.tableApi != null ? overrides.tableApi : tableApi,
      filterSelectIds: filterSelectIds,
      filteringTextId: filteringTextId,
      resetFiltersId: resetFiltersId,
      buildBadgeHtml: buildBadgeHtml,
      onApply: onApply,
      initialApplyPolicy: overrides && overrides.initialApplyPolicy ? overrides.initialApplyPolicy : "if-filters-active",
      skipPendingRestoreApply: overrides && overrides.skipPendingRestoreApply === true,
    };
    opts.tableId = tableId;
    if (overrides && overrides.rowGroup != null) opts.rowGroup = overrides.rowGroup;
    return opts;
  };

  window.RENGINE_PAGE_WIRING = RENGINE_PAGE_WIRING;
  window.getRengineDatatableFilterAttachOpts = getRengineDatatableFilterAttachOpts;
})(window);
