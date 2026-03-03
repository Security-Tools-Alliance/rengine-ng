/**
 * DataTables column helpers: resolve column by name, column visibility for subdomain/vulnerability tables.
 *
 * Column definitions used with getColumnIndexByName or rengineColumnByName must set the "name" property
 * on each column config (e.g. { data: "id", name: "id" }). Missing "name" causes lookups to return -1
 * and visibility/order logic to silently skip the column.
 */
(function (window) {
  "use strict";

  /**
   * @param {Array<string|{name: string}>} columnsOrNames - Array of column names (strings) or column configs. Configs must have .name for correct lookup.
   * @param {string} name - Column name to find.
   * @returns {number} Zero-based index, or -1 if not found. Callers must handle -1.
   */
  const getColumnIndexByName = function (columnsOrNames, name) {
    if (!Array.isArray(columnsOrNames) || columnsOrNames.length === 0) return -1;
    const first = columnsOrNames[0];
    if (typeof first === "string") return columnsOrNames.indexOf(name);
    return columnsOrNames.findIndex(function (c) {
      return c && c.name === name;
    });
  };

  const rengineColumnByName = function (tableApiOrApi, columnName, columnsOptional) {
    const api = tableApiOrApi && tableApiOrApi.api ? tableApiOrApi.api() : tableApiOrApi;
    if (!api || !api.column) return null;
    let columns = columnsOptional;
    if (!Array.isArray(columns) && api.settings && api.settings()[0]) {
      const init = api.settings()[0].init;
      columns = init && init.columns;
    }
    const idx = getColumnIndexByName(columns, columnName);
    return idx >= 0 ? api.column(idx) : null;
  };

  const subdomainDatatableColVisibility = function (tableApi, columns) {
    const api = tableApi && tableApi.api ? tableApi.api() : tableApi;
    const $ = window.jQuery;
    if (!$ || !api || !Array.isArray(columns)) return;
    const colByName = function (name) { return rengineColumnByName(api, name, columns); };
    const setupColumnVisibilityToggle = function (checkboxSelector, columnName, storageKey) {
      const isChecked = $(checkboxSelector).is(":checked");
      const col = colByName(columnName);
      if (col) col.visible(isChecked);
      $(checkboxSelector).on("change", function () {
        const visible = $(this).is(":checked");
        const c = colByName(columnName);
        if (c) c.visible(visible);
        if (storageKey) window.localStorage.setItem(storageKey, visible);
      });
    };
    const portsCol = colByName("ports");
    if (portsCol) {
      const isChecked = $("#sub_ports_filter_checkbox").is(":checked");
      portsCol.visible(isChecked);
      $("input[name=sub_ports_filter_checkbox]").on("change", function () {
        const visible = $(this).is(":checked");
        const c = colByName("ports");
        if (c) c.visible(visible);
        window.localStorage.setItem("sub_ports_filter_checkbox", visible);
      });
    }
    setupColumnVisibilityToggle("input[name=sub_http_status_filter_checkbox]", "http_status", "sub_http_status_filter_checkbox");
    setupColumnVisibilityToggle("input[name=sub_page_title_filter_checkbox]", "page_title", "sub_page_title_filter_checkbox");
    setupColumnVisibilityToggle("input[name=sub_ip_filter_checkbox]", "ip_addresses", "sub_ip_filter_checkbox");
    setupColumnVisibilityToggle("input[name=sub_content_length_filter_checkbox]", "content_length", "sub_content_length_filter_checkbox");
    setupColumnVisibilityToggle("input[name=sub_response_time_filter_checkbox]", "response_time", "sub_response_time_filter_checkbox");
  };

  const vulnerabilityDatatableColVisibility = function (tableApi, columns) {
    const api = tableApi && tableApi.api ? tableApi.api() : tableApi;
    const $ = window.jQuery;
    if (!$ || !api || !Array.isArray(columns)) return;
    const colByName = function (name) { return rengineColumnByName(api, name, columns); };
    if (!$("#vuln_source_checkbox").is(":checked")) { const col = colByName("source"); if (col) col.visible(false); }
    if (!$("#vuln_severity_checkbox").is(":checked")) { const col = colByName("severity"); if (col) col.visible(false); }
    if (!$("#vuln_vulnerable_url_checkbox").is(":checked")) { const col = colByName("http_url"); if (col) col.visible(false); }
    if (!$("#vuln_status_checkbox").is(":checked")) { const col = colByName("open_status"); if (col) col.visible(false); }
  };

  window.getColumnIndexByName = getColumnIndexByName;
  window.rengineColumnByName = rengineColumnByName;
  window.subdomainDatatableColVisibility = subdomainDatatableColVisibility;
  window.vulnerabilityDatatableColVisibility = vulnerabilityDatatableColVisibility;
})(window);
