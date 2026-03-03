/**
 * DataTables filter helpers: multi-select values, buildDatatableFilterPayload, attach filter dropdowns and reset.
 *
 * No module deps; consumed by init.js (buildDatatableFilterPayload merged into ajax.data) and page_wiring.js (buildBadgeHtml).
 * Backend mapping: buildDatatableFilterPayload(selectIdsToParamNames) expects the same map as FILTER_CONTEXT_* in
 * web/api/helpers/datatables/filters.py (keys = select element IDs, values = API param names). Filter partials must
 * render <select id="..."> with those IDs. See filter_ids.js and README "Backend → frontend mapping".
 */
(function (window) {
  "use strict";

  const getMultiSelectValues = function (selectId) {
    const sel = typeof document !== "undefined" ? document.getElementById(selectId) : null;
    if (!sel || !sel.options) return [];
    const out = [];
    for (let i = 0; i < sel.options.length; i++) {
      if (sel.options[i].selected && sel.options[i].value) out.push(sel.options[i].value);
    }
    return out;
  };

  const attachDatatableFilters = function (config) {
    const tableApi = config.tableApi;
    const filterSelectIds = config.filterSelectIds || [];
    const filteringTextId = config.filteringTextId || "filteringText";
    const resetFiltersId = config.resetFiltersId || "resetFilters";
    const buildBadgeHtml = config.buildBadgeHtml;
    const onApply = config.onApply || function () { if (tableApi) tableApi.draw(); };

    const applyFilters = function () {
      const selected = {};
      filterSelectIds.forEach(function (id) { selected[id] = getMultiSelectValues(id); });
      const container = document.getElementById(filteringTextId);
      if (container && typeof buildBadgeHtml === "function") container.innerHTML = buildBadgeHtml(selected);
      onApply();
    };

    filterSelectIds.forEach(function (selectId) {
      const el = document.getElementById(selectId);
      if (el) el.addEventListener("change", applyFilters, false);
    });

    const resetEl = document.getElementById(resetFiltersId);
    if (resetEl) {
      resetEl.addEventListener("click", function (e) {
        e.preventDefault();
        filterSelectIds.forEach(function (id) {
          const sel = document.getElementById(id);
          if (sel) {
            for (let i = 0; i < sel.options.length; i++) sel.options[i].selected = false;
          }
        });
        const container = document.getElementById(filteringTextId);
        if (container) container.innerHTML = "";
        onApply();
        if (window.Snackbar && typeof window.Snackbar.show === "function") {
          window.Snackbar.show({ text: "Filters Reset", pos: "top-center" });
        }
      }, false);
    }
  };

  /**
   * Build HTML for filter badges from selected values and a spec.
   *
   * @param {Object} selected - Map of selectId -> array of selected value strings.
   * @param {Array<{selectId: string, label: string, badgeClass?: string}>} spec - Badge spec per filter.
   * @param {Object} [options] - Optional { resetId, clearChipId } for the clear chip.
   * @returns {string} HTML string of badges plus optional clear chip.
   */
  const buildRengineFilterBadgesHtml = function (selected, spec, options) {
    const safeText = window.safeText;
    const safeAttr = window.safeAttr;
    if (typeof safeText !== "function") return "";
    const opts = options || {};
    const resetId = opts.resetId || "resetFilters";
    const clearChipId = opts.clearChipId || "clearFilterChip";
    const parts = [];
    (spec || []).forEach(function (item) {
      const values = selected && selected[item.selectId];
      if (!Array.isArray(values) || values.length === 0) return;
      const label = item.label || item.selectId;
      const cls = item.badgeClass || "badge-soft-primary";
      const encoded = values.map(function (v) { return safeText(String(v)); }).join(", ");
      parts.push('<span class="badge ' + (typeof safeAttr === "function" ? safeAttr(cls) : cls) + ' me-1">' + safeText(label) + ": " + encoded + "</span>");
    });
    if (parts.length === 0) return "";
    const safeResetId = (typeof safeAttr === "function" ? safeAttr(resetId) : resetId);
    return parts.join("") + ' <span class="badge-link ms-1 js-clear-filter-chip" id="' + clearChipId + '" role="button" tabindex="0" data-reset-id="' + safeResetId + '">X</span>';
  };

  /**
   * Parse filter params from a json-script element (e.g. datatable-filter-params).
   * Returns {} when the element is missing or content is invalid JSON.
   *
   * @param {string} elementId - id of the element whose textContent is JSON (select id -> param name).
   * @returns {Object} selectIdsToParamNames - Map of select id -> API param name.
   */
  const getRengineDatatableFilterParams = function (elementId) {
    if (!elementId || typeof elementId !== "string") {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("getRengineDatatableFilterParams: elementId is missing or not a string");
      }
      return {};
    }
    const el = typeof document !== "undefined" ? document.getElementById(elementId) : null;
    if (!el || !el.textContent) return {};
    try {
      const parsed = JSON.parse(el.textContent);
      return typeof parsed === "object" && parsed !== null ? parsed : {};
    } catch (e) {
      if (typeof console !== "undefined" && console.error) console.error("Failed to parse datatable filter params JSON", e);
      return {};
    }
  };

  /**
   * Build a function for DataTables ajax.data that merges extraData and filter payload.
   * Use in table config: ajax: { url: u, data: buildRengineDatatableAjaxData(filterSelectToParam, { project: slug }) }.
   *
   * @param {Object} filterSelectToParam - Map of select id -> param name (from getRengineDatatableFilterParams).
   * @param {Object} extraData - Key-value pairs to assign to d on every request (e.g. { project: 'x', slug: 'y' }).
   * @returns {function(Object)} data(d) - Side-effects d and returns nothing; use as ajax.data.
   */
  const buildRengineDatatableAjaxData = function (filterSelectToParam, extraData) {
    if (extraData != null && (typeof extraData !== "object" || Array.isArray(extraData))) {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("buildRengineDatatableAjaxData: extraData must be a plain object; got", typeof extraData);
      }
    }
    const payloadFn =
      typeof window.buildDatatableFilterPayload === "function"
        ? function () { return window.buildDatatableFilterPayload(filterSelectToParam); }
        : function () { return {}; };
    return function (d) {
      if (extraData && typeof extraData === "object" && !Array.isArray(extraData)) Object.assign(d, extraData);
      const payload = payloadFn();
      if (payload && Object.keys(payload).length) Object.assign(d, payload);
    };
  };

  /**
   * Build a payload object for DataTables ajax.data from multi-select filters.
   *
   * @param {Object} selectIdsToParamNames - Map of select element id -> API param name.
   * @returns {Object} payload - Object of param name -> selected values array.
   */
  const buildDatatableFilterPayload = function (selectIdsToParamNames) {
    if (selectIdsToParamNames != null && (typeof selectIdsToParamNames !== "object" || Array.isArray(selectIdsToParamNames))) {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("buildDatatableFilterPayload: selectIdsToParamNames must be a plain object; got", typeof selectIdsToParamNames);
      }
      return {};
    }
    const mapping = selectIdsToParamNames || {};
    const payload = {};
    Object.keys(mapping).forEach(function (selectId) {
      const paramName = mapping[selectId];
      if (!paramName || typeof paramName !== "string") {
        if (selectId && typeof console !== "undefined" && console.warn) {
          console.warn("buildDatatableFilterPayload: missing or non-string param name for select id", selectId);
        }
        return;
      }
      const values = getMultiSelectValues(selectId);
      if (Array.isArray(values) && values.length) payload[paramName] = values;
    });
    return payload;
  };

  /**
   * Populate filter <select> elements from API or static options.
   * Avoids empty filters on first load when options are not scraped from table cells.
   *
   * @param {Array<{selectId: string, url?: string, valueKey?: string, labelKey?: string, options?: Array<{value: string, label?: string}>}>} config - Per-select config. Either url (fetch JSON; valueKey/labelKey for array of strings or objects) or options (static list).
   * @param {Object} [urlParams] - Query params to append to each url (e.g. { project: slug }).
   */
  const populateRengineFilterSelects = function (config, urlParams) {
    if (!Array.isArray(config)) return;
    const params = urlParams || {};
    const safeText = window.safeText;
    config.forEach(function (item) {
      const el = typeof document !== "undefined" ? document.getElementById(item.selectId) : null;
      if (!el || !el.options) return;
      if (item.options) {
        item.options.forEach(function (opt) {
          const value = opt.value != null ? opt.value : opt;
          const label = opt.label != null ? opt.label : value;
          const option = document.createElement("option");
          option.value = typeof safeText === "function" ? safeText(value) : value;
          option.textContent = typeof safeText === "function" ? safeText(label) : label;
          el.appendChild(option);
        });
        return;
      }
      if (!item.url) return;
      const url = new URL(item.url, window.location.origin);
      Object.keys(params).forEach(function (k) {
        if (params[k] != null && params[k] !== "") url.searchParams.set(k, params[k]);
      });
      window.fetch(url.toString(), { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          const valueKey = item.valueKey || "value";
          const labelKey = item.labelKey || "label";
          let list;
          if (item.valueKey) {
            if (Object.prototype.hasOwnProperty.call(data, item.valueKey)) {
              list = data[item.valueKey];
            } else {
              if (typeof console !== "undefined" && console && typeof console.warn === "function") {
                console.warn(
                  "Filter options: response missing expected key '%s'. Falling back to default keys.",
                  item.valueKey
                );
              }
            }
          }
          if (!Array.isArray(list)) {
            list = data.targets || data.scan_engines || data.organizations || [];
          }
          if (Array.isArray(list) && list.length > 0 && typeof list[0] === "object" && list[0] !== null) {
            list.forEach(function (o) {
              const option = document.createElement("option");
              const val = o[valueKey] != null ? o[valueKey] : o.name || o;
              const lbl = o[labelKey] != null ? o[labelKey] : o.name || val;
              option.value = typeof safeText === "function" ? safeText(val) : val;
              option.textContent = typeof safeText === "function" ? safeText(lbl) : lbl;
              el.appendChild(option);
            });
          } else {
            list.forEach(function (v) {
              const option = document.createElement("option");
              const str = v != null ? String(v) : "";
              option.value = typeof safeText === "function" ? safeText(str) : str;
              option.textContent = option.value;
              el.appendChild(option);
            });
          }
        })
        .catch(function (e) {
          if (window.console && typeof window.console.warn === "function") {
            window.console.warn("populateRengineFilterSelects failed", url.toString(), e);
          }
        });
    });
  };

  /**
   * Populate scan-history / subscan-history filter selects from a single API call.
   * Fills filterByOrganization, filterByScanStatus, filterByTarget, filterByScanType.
   *
   * @param {string} projectSlug - Current project slug.
   * @param {string} filterChoicesUrl - URL for scanHistoryFilterChoices API (e.g. /api/scanHistoryFilterChoices/).
   * @param {string} [context] - "scan_history" (use scan_status_labels) or "subscan_history" (use task_status_labels) for filterByScanStatus.
   */
  const populateScanHistoryFilterChoices = function (projectSlug, filterChoicesUrl, context) {
    if (!filterChoicesUrl || !projectSlug) return;
    window.fetch(filterChoicesUrl + "?project=" + encodeURIComponent(projectSlug), { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        const safeText = window.safeText;
        const appendOptions = function (selectId, list) {
          const el = document.getElementById(selectId);
          if (!el || !Array.isArray(list)) return;
          list.forEach(function (v) {
            const option = document.createElement("option");
            const str = v != null ? String(v) : "";
            option.value = typeof safeText === "function" ? safeText(str) : str;
            option.textContent = option.value;
            el.appendChild(option);
          });
        };
        appendOptions("filterByOrganization", data.organizations || []);
        const statusLabels = context === "subscan_history"
          ? (data.task_status_labels || [])
          : (data.scan_status_labels || []);
        appendOptions("filterByScanStatus", statusLabels);
        appendOptions("filterByTarget", data.targets || []);
        appendOptions("filterByScanType", data.scan_engines || []);
      })
      .catch(function (e) {
        if (window.console && typeof window.console.warn === "function") {
          window.console.warn("populateScanHistoryFilterChoices failed", filterChoicesUrl, e);
        }
      });
  };

  /**
   * Attach DataTables filters and optionally row group selector in one call.
   * Calls attachDatatableFilters then, if opts.rowGroup is set, attachRengineDatatableRowGroupSelector.
   *
   * @param {Object} tableApi - DataTables API instance (returned by initServerSideDataTable).
   * @param {Object} opts - Options for attachDatatableFilters (tableApi, filterSelectIds, buildBadgeHtml, filteringTextId, resetFiltersId, onApply) and optional rowGroup (selector, groups, columns, cookieKey, defaultOrderWhenDisabled, snackbarMessage, initialGroupFromCookie).
   */
  const attachRengineDatatableFiltersAndRowGroup = function (tableApi, opts) {
    const options = opts || {};
    attachDatatableFilters({
      tableApi: tableApi,
      filterSelectIds: options.filterSelectIds || [],
      filteringTextId: options.filteringTextId || "filteringText",
      resetFiltersId: options.resetFiltersId || "resetFilters",
      buildBadgeHtml: options.buildBadgeHtml,
      onApply: options.onApply,
    });
    const rowGroup = options.rowGroup;
    if (rowGroup && typeof window.attachRengineDatatableRowGroupSelector === "function") {
      window.attachRengineDatatableRowGroupSelector(tableApi, rowGroup);
    }
  };

  if (typeof document !== "undefined" && document.body && document.body.addEventListener) {
    document.body.addEventListener("click", function (e) {
      let el = e.target;
      while (el && el !== document.body) {
        if (el.classList && el.classList.contains("js-clear-filter-chip")) {
          const resetId = el.getAttribute && el.getAttribute("data-reset-id");
          if (resetId) {
            const resetEl = document.getElementById(resetId);
            if (resetEl && typeof resetEl.click === "function") resetEl.click();
          }
          return;
        }
        el = el.parentNode;
      }
    }, false);
  }

  window.getMultiSelectValues = getMultiSelectValues;
  window.getRengineDatatableFilterParams = getRengineDatatableFilterParams;
  window.buildRengineDatatableAjaxData = buildRengineDatatableAjaxData;
  window.attachDatatableFilters = attachDatatableFilters;
  window.buildRengineFilterBadgesHtml = buildRengineFilterBadgesHtml;
  window.buildDatatableFilterPayload = buildDatatableFilterPayload;
  window.populateRengineFilterSelects = populateRengineFilterSelects;
  window.populateScanHistoryFilterChoices = populateScanHistoryFilterChoices;
  window.attachRengineDatatableFiltersAndRowGroup = attachRengineDatatableFiltersAndRowGroup;
})(window);
