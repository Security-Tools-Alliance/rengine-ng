/**
 * DataTables config: central element IDs for filter/row-group json_script, and row-group merge helpers.
 *
 * Element IDs (use these constants instead of hardcoding; keeps rename in one place):
 * - RENGINE_DATATABLE_FILTER_PARAMS_SCRIPT_ID: id of the script tag that holds select-id -> param-name mapping (backend datatable_filter_select_to_param).
 * - RENGINE_DATATABLE_ROW_GROUP_CONFIG_SCRIPT_ID: id of the script tag that holds row-group backend config { selector, cookie_key }.
 *
 * Filter select IDs (filterByOrganization, filterByScanStatus, etc.) are defined by the backend
 * FILTER_CONTEXT_* in web/api/helpers/datatables/filters.py. The frontend mirror is filter_ids.js
 * (RENGINE_FILTER_IDS_*, getFilterSelectIdsForTable); filter partials and JS must use the same ids.
 */
(function (window) {
  "use strict";

  window.RENGINE_DATATABLE_FILTER_PARAMS_SCRIPT_ID = "datatable-filter-params";
  window.RENGINE_DATATABLE_ROW_GROUP_CONFIG_SCRIPT_ID = "datatable-row-group-config";

  /**
   * Read row-group config from a json-script element. Backend passes { selector, cookie_key }.
   *
   * @param {string} elementId - id of the script tag (e.g. 'datatable-row-group-config').
   * @returns {{ selector: string, cookie_key: string } | null} Backend config or null if missing/invalid.
   */
  const getRengineRowGroupConfigFromScript = function (elementId) {
    if (!elementId || typeof elementId !== "string") return null;
    const el = typeof document !== "undefined" ? document.getElementById(elementId) : null;
    if (!el || !el.textContent || !el.textContent.trim()) return null;
    try {
      const parsed = JSON.parse(el.textContent);
      if (parsed && typeof parsed.selector === "string" && typeof parsed.cookie_key === "string") {
        return { selector: parsed.selector, cookie_key: parsed.cookie_key };
      }
    } catch (e) {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("getRengineRowGroupConfigFromScript: failed to parse JSON", e);
      }
    }
    return null;
  };

  /**
   * Merge backend row-group config (selector, cookie_key) with template opts for initRengineServerSideDataTable.
   *
   * @param {{ selector: string, cookie_key: string }} backendConfig - From getRengineRowGroupConfigFromScript.
   * @param {object} templateOpts - groups, columns, defaultOrderWhenDisabled, rowGroupBaseOpts, snackbarMessage.
   * @returns {object} Full rowGroup option for initRengineServerSideDataTable (selector, cookieKey, groups, columns, ...).
   */
  const getRengineRowGroupConfig = function (backendConfig, templateOpts) {
    if (!backendConfig || !backendConfig.selector) return null;
    const opts = templateOpts || {};
    return {
      selector: backendConfig.selector,
      cookieKey: backendConfig.cookie_key || undefined,
      groups: opts.groups || [],
      columns: opts.columns || [],
      defaultOrderWhenDisabled: opts.defaultOrderWhenDisabled || [["id", "desc"]],
      rowGroupBaseOpts: opts.rowGroupBaseOpts || {},
      snackbarMessage: opts.snackbarMessage,
    };
  };

  window.getRengineRowGroupConfigFromScript = getRengineRowGroupConfigFromScript;
  window.getRengineRowGroupConfig = getRengineRowGroupConfig;
})(window);
