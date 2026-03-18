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

  const storage = window.rengineStorage;
  const PENDING_FILTER_VALUES_ATTR = "data-rengine-pending-filter-values";
  const PENDING_FILTER_OBSERVER_ATTR = "data-rengine-pending-filter-observer";
  const getCurrentProjectSlug = function () {
    if (typeof window.getCurrentProjectSlug === "function") {
      return window.getCurrentProjectSlug() || "";
    }
    if (typeof document === "undefined" || !document.body) return "";
    return (document.body.getAttribute("data-project-slug") || "").trim();
  };

  const applyValuesToFilterSelect = function (el, values) {
    if (!el || !el.options || !Array.isArray(values) || values.length === 0) return false;
    let applied = false;
    if (el.multiple) {
      for (let i = 0; i < el.options.length; i++) {
        const opt = el.options[i];
        const shouldSelect = values.indexOf(opt.value) !== -1;
        if (shouldSelect) applied = true;
        opt.selected = shouldSelect;
      }
      return applied;
    }
    const scalar = values[0];
    for (let j = 0; j < el.options.length; j++) {
      if (el.options[j].value === scalar) {
        el.value = scalar;
        return true;
      }
    }
    return false;
  };

  const savePendingFilterValues = function (el, values) {
    if (!el || !Array.isArray(values) || values.length === 0) return false;
    try {
      el.setAttribute(PENDING_FILTER_VALUES_ATTR, JSON.stringify(values));
      return true;
    } catch (e) {
      // ignore malformed values
      return false;
    }
  };

  const consumePendingFilterValues = function (el) {
    if (!el) return null;
    const raw = el.getAttribute(PENDING_FILTER_VALUES_ATTR);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      clearPendingFilterValues(el);
    } catch (e) {
      clearPendingFilterValues(el);
    }
    return null;
  };

  const clearPendingFilterValues = function (el) {
    if (!el) return;
    el.removeAttribute(PENDING_FILTER_VALUES_ATTR);
  };

  const attachPendingFilterObserver = function (el) {
    if (!el || el.getAttribute(PENDING_FILTER_OBSERVER_ATTR) === "1") return;
    if (typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver(function () {
      const pendingValues = consumePendingFilterValues(el);
      if (!pendingValues) return;
      const restored = applyValuesToFilterSelect(el, pendingValues);
      if (!restored) return;
      clearPendingFilterValues(el);
      if (typeof CustomEvent === "function") {
        el.dispatchEvent(new CustomEvent("change", { bubbles: true, detail: { rengineFromPendingRestore: true } }));
      } else {
        el.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    // Some select options are populated asynchronously, so retry restore when child options are inserted.
    observer.observe(el, { childList: true });
    el.setAttribute(PENDING_FILTER_OBSERVER_ATTR, "1");
  };

  const getMultiSelectValues = function (selectId) {
    const sel = typeof document !== "undefined" ? document.getElementById(selectId) : null;
    if (!sel || !sel.options) return [];
    const out = [];
    for (let i = 0; i < sel.options.length; i++) {
      if (sel.options[i].selected && sel.options[i].value) out.push(sel.options[i].value);
    }
    return out;
  };

  const getFilterStorageKey = function (tableId) {
    if (!tableId || typeof tableId !== "string") return null;
    const projectSlug = getCurrentProjectSlug();
    const suffix = projectSlug ? ":" + projectSlug : "";
    return "datatable-filters-" + tableId + suffix;
  };

  const getPersistedDatatableFilterState = function (tableId, filterSelectIds) {
    const key = getFilterStorageKey(tableId);
    if (!key || !Array.isArray(filterSelectIds) || !filterSelectIds.length) return {};
    if (!storage || typeof storage.getJson !== "function") return {};
    let state;
    try {
      state = storage.getJson(key);
    } catch (e) {
      return {};
    }
    if (!state || Array.isArray(state) || typeof state !== "object") return {};
    const normalized = {};
    filterSelectIds.forEach(function (id) {
      if (!id || !Object.prototype.hasOwnProperty.call(state, id)) return;
      const raw = state[id];
      if (Array.isArray(raw)) {
        const values = raw.filter(function (value) { return value != null && String(value) !== ""; }).map(function (value) {
          return String(value);
        });
        if (values.length > 0) normalized[id] = values;
        return;
      }
      if (raw != null && String(raw) !== "") {
        normalized[id] = [String(raw)];
      }
    });
    return normalized;
  };

  const saveDatatableFilterState = function (tableId, filterSelectIds) {
    const key = getFilterStorageKey(tableId);
    if (!key || !Array.isArray(filterSelectIds) || !filterSelectIds.length) return;
    if (!storage || typeof storage.setJson !== "function") return;
    const state = {};
    filterSelectIds.forEach(function (id) {
      const el = typeof document !== "undefined" ? document.getElementById(id) : null;
      if (!el || !el.options) return;
      if (el.multiple) {
        const values = getMultiSelectValues(id);
        if (Array.isArray(values) && values.length) {
          state[id] = values;
        }
      } else {
        const value = el.value || "";
        if (value !== "") {
          state[id] = value;
        }
      }
    });
    if (Object.keys(state).length === 0) {
      if (typeof storage.remove === "function") {
        storage.remove(key);
      }
      return;
    }
    storage.setJson(key, state);
  };

  const restoreDatatableFilterState = function (tableId, filterSelectIds) {
    const state = getPersistedDatatableFilterState(tableId, filterSelectIds);
    if (!state || typeof state !== "object" || Object.keys(state).length === 0) return false;
    let restored = false;
    filterSelectIds.forEach(function (id) {
      const el = typeof document !== "undefined" ? document.getElementById(id) : null;
      if (!el || !el.options) return;
      const stored = state[id];
      if (stored == null) return;
      const values = Array.isArray(stored) ? stored.slice() : [stored];
      const restoredNow = applyValuesToFilterSelect(el, values);
      if (restoredNow) restored = true;
      if (!restoredNow && savePendingFilterValues(el, values)) {
        attachPendingFilterObserver(el);
      }
    });
    return restored;
  };

  const clearSelectIdFromPersistedFilterState = function (selectId) {
    if (!selectId || typeof window === "undefined" || !window.localStorage) return;
    const prefix = "rengine-datatable-filters-";
    try {
      const matchingKeys = [];
      for (let i = 0; i < window.localStorage.length; i++) {
        const rawKey = window.localStorage.key(i);
        if (!rawKey || rawKey.indexOf(prefix) !== 0) continue;
        matchingKeys.push(rawKey);
      }
      matchingKeys.forEach(function (rawKey) {
        const rawState = window.localStorage.getItem(rawKey);
        if (!rawState) return;
        let parsed = null;
        try {
          parsed = JSON.parse(rawState);
        } catch (e) {
          parsed = null;
        }
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
        if (!Object.prototype.hasOwnProperty.call(parsed, selectId)) return;
        delete parsed[selectId];
        if (Object.keys(parsed).length === 0) {
          window.localStorage.removeItem(rawKey);
        } else {
          window.localStorage.setItem(rawKey, JSON.stringify(parsed));
        }
      });
    } catch (e) {
      // ignore storage access errors
    }
  };

  const attachDatatableFilters = function (config) {
    const tableApi = config.tableApi;
    const filterSelectIds = config.filterSelectIds || [];
    const filteringTextId = config.filteringTextId || "filteringText";
    const resetFiltersId = config.resetFiltersId || "resetFilters";
    const buildBadgeHtml = config.buildBadgeHtml;
    const onApply = config.onApply || function () { if (tableApi) tableApi.draw(); };
    const tableId = config.tableId;
    const initialApplyPolicy = config.initialApplyPolicy || "always";
    const initialFilterPayloadApplied = !!(tableApi && tableApi._rengineInitialFilterPayloadApplied === true);
    const effectiveInitialApplyPolicy = initialFilterPayloadApplied ? "never" : initialApplyPolicy;
    const skipPendingRestoreApply = config.skipPendingRestoreApply === true || initialFilterPayloadApplied;

    const applyFilters = function (event) {
      const selected = {};
      filterSelectIds.forEach(function (id) { selected[id] = getMultiSelectValues(id); });
      const container = document.getElementById(filteringTextId);
      if (container && typeof buildBadgeHtml === "function") container.innerHTML = buildBadgeHtml(selected);
      if (tableId) {
        saveDatatableFilterState(tableId, filterSelectIds);
      }
      if (
        skipPendingRestoreApply
        && event
        && event.detail
        && event.detail.rengineFromPendingRestore === true
      ) {
        return;
      }
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
        if (tableId && storage && typeof storage.remove === "function") {
          const key = getFilterStorageKey(tableId);
          if (key) storage.remove(key);
        }
        onApply();
        if (window.Snackbar && typeof window.Snackbar.show === "function") {
          window.Snackbar.show({ text: "Filters Reset", pos: "top-center" });
        }
      }, false);
    }

    if (tableId) {
      restoreDatatableFilterState(tableId, filterSelectIds);
      if (typeof buildBadgeHtml === "function") {
        const selected = {};
        filterSelectIds.forEach(function (id) { selected[id] = getMultiSelectValues(id); });
        const container = document.getElementById(filteringTextId);
        if (container) container.innerHTML = buildBadgeHtml(selected);
      }
      if (effectiveInitialApplyPolicy === "never") return;
      if (effectiveInitialApplyPolicy === "if-filters-active") {
        const hasSelectedFilters = filterSelectIds.some(function (id) {
          const values = getMultiSelectValues(id);
          return Array.isArray(values) && values.length > 0;
        });
        if (!hasSelectedFilters) return;
      }
      onApply();
    }
  };

  /**
   * Build HTML for filter badges from selected values and a spec.
   *
   * @param {Object} selected - Map of selectId -> array of selected value strings.
   * @param {Array<{selectId: string, label: string, badgeClass?: string}>} spec - Badge spec per filter.
   * @returns {string} HTML string of badges (each badge has its own clear cross).
   */
  const buildRengineFilterBadgesHtml = function (selected, spec, options) {
    const safeText = window.safeText;
    const safeAttr = window.safeAttr;
    if (typeof safeText !== "function") return "";
    const parts = [];
    (spec || []).forEach(function (item) {
      const values = selected && selected[item.selectId];
      if (!Array.isArray(values) || values.length === 0) return;
      const label = item.label || item.selectId;
      const cls = item.badgeClass || "badge-soft-primary";
      const encoded = values.map(function (v) { return safeText(String(v)); }).join(", ");
      const selectIdAttr = typeof safeAttr === "function" ? safeAttr(item.selectId) : item.selectId;
      parts.push(
        '<span class="badge ' + (typeof safeAttr === "function" ? safeAttr(cls) : cls) + ' me-1">'
        + safeText(label) + ": " + encoded
        + ' <span class="js-clear-single-filter-chip ms-1" role="button" tabindex="0" data-select-id="'
        + selectIdAttr + '" aria-label="Clear ' + safeText(label) + ' filter">×</span>'
        + "</span>"
      );
    });
    return parts.join("");
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
            const isObj = v && typeof v === "object" && !Array.isArray(v);
            const rawValue = isObj && v.value != null ? v.value : v;
            const rawLabel = isObj && v.label != null ? v.label : rawValue;
            const value = rawValue != null ? String(rawValue) : "";
            const label = rawLabel != null ? String(rawLabel) : value;
            option.value = typeof safeText === "function" ? safeText(value) : value;
            option.textContent = typeof safeText === "function" ? safeText(label) : label;
            el.appendChild(option);
          });
        };
        appendOptions("filterByOrganization", data.organizations || []);
        const statusLabels = context === "subscan_history"
          ? (data.task_status_labels || [])
          : (data.scan_status_labels || []);
        appendOptions("filterByScanStatus", statusLabels);
        appendOptions("filterByTarget", data.targets || []);
        appendOptions("filterByScanType", data.scan_engine_options || data.scan_engines || []);
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
      tableId: options.tableId,
      initialApplyPolicy: options.initialApplyPolicy,
      skipPendingRestoreApply: options.skipPendingRestoreApply,
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
        if (el.classList && el.classList.contains("js-clear-single-filter-chip")) {
          const selectId = el.getAttribute && el.getAttribute("data-select-id");
          if (selectId) {
            const selectEl = document.getElementById(selectId);
            if (selectEl) {
              if (selectEl.multiple && selectEl.options) {
                for (let i = 0; i < selectEl.options.length; i++) {
                  selectEl.options[i].selected = false;
                }
              } else {
                selectEl.value = "";
              }
              clearSelectIdFromPersistedFilterState(selectId);
              selectEl.dispatchEvent(new Event("change", { bubbles: true }));
            }
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
  window.getPersistedDatatableFilterState = getPersistedDatatableFilterState;
  window.populateRengineFilterSelects = populateRengineFilterSelects;
  window.populateScanHistoryFilterChoices = populateScanHistoryFilterChoices;
  window.attachRengineDatatableFiltersAndRowGroup = attachRengineDatatableFiltersAndRowGroup;
})(window);
