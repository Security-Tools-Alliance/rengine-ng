/**
 * Central mapping of DataTable table ID -> filter select element IDs.
 *
 * REQUIRED MAPPING (keep in sync when adding or renaming filters):
 * - Each key in RENGINE_FILTER_IDS (e.g. scan_history, target_list) corresponds to a table/page.
 * - The array value lists the **HTML element IDs** of the <select> filter controls (e.g. "filterByOrganization").
 * - Backend: web/api/helpers/datatables/filters.py defines FILTER_CONTEXT_* with the same select IDs as
 *   keys and API param names as values (e.g. "filterByOrganization" -> "filter_organization").
 * - Templates: the filter partials (e.g. base/_items/datatables_filters/filters_scan_history.html) must
 *   render <select id="filterByOrganization"> (and other IDs) so that buildDatatableFilterPayload can
 *   read selected values and send them under the correct param names. When adding a new filter or table,
 *   add the select ID here, add the same ID -> param in filters.py FILTER_CONTEXT_*, and ensure the
 *   HTML partial includes an element with that id.
 */
(function (window) {
  "use strict";

  const SCAN_HISTORY = [
    "filterByOrganization",
    "filterByScanStatus",
    "filterByTarget",
    "filterByScanType",
  ];
  const SUBSCAN_HISTORY = [
    "filterByOrganization",
    "filterByScanStatus",
    "filterByTarget",
    "filterByScanType",
  ];
  const TARGET_LIST = ["filterByOrganization", "filterByScope"];
  const SCOPE_LIST = ["filterByOrganization", "filterByScopeType"];
  const ORGANIZATION_LIST = ["filterByName"];
  const WORDLIST_LIST = ["filterByName"];
  const SCAN_ENGINE_LIST = ["filterByEngineName"];
  const S3_BUCKETS = ["filterByBucketName"];

  /**
   * Table ID -> filter select IDs. Keep in sync with backend table_config.py TABLE_ID_* and filters.py FILTER_CONTEXT_*.
   * Template / filter partial per table: see table_config.py (Template | Filter partial comments).
   */
  const RENGINE_FILTER_IDS = {
    scan_history: SCAN_HISTORY,
    subscan_history: SUBSCAN_HISTORY,
    target_list: TARGET_LIST,
    scope_list: SCOPE_LIST,
    organization_list: ORGANIZATION_LIST,
    wordlist_list: WORDLIST_LIST,
    scan_engine_list: SCAN_ENGINE_LIST,
    s3_buckets: S3_BUCKETS,
  };

  /**
   * Return the array of filter select IDs for a table, or empty array if none.
   *
   * @param {string} tableId - Table id (e.g. 'scan_history', 'target_list'). Must match backend TABLE_ID_*.
   * @returns {string[]} Select element IDs for attachDatatableFilters / buildBadgeHtml spec.
   */
  const getFilterSelectIdsForTable = function (tableId) {
    if (!tableId || typeof tableId !== "string") return [];
    const ids = RENGINE_FILTER_IDS[tableId];
    return Array.isArray(ids) ? ids.slice() : [];
  };

  window.RENGINE_FILTER_IDS_SCAN_HISTORY = SCAN_HISTORY;
  window.RENGINE_FILTER_IDS_SUBSCAN_HISTORY = SUBSCAN_HISTORY;
  window.RENGINE_FILTER_IDS_TARGET_LIST = TARGET_LIST;
  window.RENGINE_FILTER_IDS_SCOPE_LIST = SCOPE_LIST;
  window.RENGINE_FILTER_IDS_ORGANIZATION_LIST = ORGANIZATION_LIST;
  window.RENGINE_FILTER_IDS_WORDLIST_LIST = WORDLIST_LIST;
  window.RENGINE_FILTER_IDS_SCAN_ENGINE_LIST = SCAN_ENGINE_LIST;
  window.RENGINE_FILTER_IDS_S3_BUCKETS = S3_BUCKETS;
  window.RENGINE_FILTER_IDS = RENGINE_FILTER_IDS;
  window.getFilterSelectIdsForTable = getFilterSelectIdsForTable;
})(window);
