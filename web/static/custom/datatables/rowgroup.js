/**
 * DataTables RowGroup: order-by-name, row group options, attach grouping selector, storage-backed initial state.
 *
 * Depends on: layout.js (indirect), columns.js (getColumnIndexByName), rengine_storage.js (rengineStorage).
 * Consumed by init.js (getRengineRowGroupInitialState, attachRengineDatatableRowGroupSelector). Backend passes
 * row-group config (selector, cookie_key) via config.js getRengineRowGroupConfigFromScript; TABLE_ID is from table_config.py.
 */
(function (window) {
  "use strict";

  const getColumnIndexByName = window.getColumnIndexByName;
  const storage = window.rengineStorage;

  const getRowGroupStoredValue = function (key) {
    if (!key || !storage || typeof storage.get !== "function") return null;
    return storage.get(key);
  };

  const setRowGroupStoredValue = function (key, value) {
    if (!key || !storage || typeof storage.set !== "function") return;
    storage.set(key, value == null ? "" : value);
  };

  const normalizeRowGroupLabel = function (group) {
    if (group == null) return "";
    if (typeof group === "string") return group.trim();
    if (typeof group === "number") return String(group);
    const g = group;
    if (typeof g === "object") {
      if (g.display != null && typeof g.display === "string") return g.display.trim();
      if (g.order != null && typeof g.order === "string") return g.order.trim();
      if (g.textContent != null && typeof g.textContent === "string") return g.textContent.trim();
      if (g.innerText != null && typeof g.innerText === "string") return g.innerText.trim();
      if (window.jQuery && (g.nodeType === 1 || g.jquery)) return window.jQuery(g).text().trim();
    }
    return String(group);
  };

  const getRengineDatatableOrderFromNames = function (columns, orderByName) {
    if (!Array.isArray(columns) || !Array.isArray(orderByName)) return [[0, "desc"]];
    const result = [];
    for (let i = 0; i < orderByName.length; i++) {
      const pair = orderByName[i];
      const colName = pair[0];
      const dir = pair[1] === "asc" ? "asc" : "desc";
      const idx = typeof getColumnIndexByName === "function" ? getColumnIndexByName(columns, colName) : -1;
      if (idx >= 0) result.push([idx, dir]);
    }
    return result.length > 0 ? result : [[0, "desc"]];
  };

  const getRengineDatatableRowGroupOptions = function (opts) {
    const dataSrc = opts.dataSrc;
    const rowLabel = opts.rowLabel || "rows";
    const emptyGroupLabel = opts.emptyGroupLabel != null ? opts.emptyGroupLabel : "";
    return {
      rowGroup: {
        dataSrc: dataSrc,
        startRender: function (rows, group) {
          const raw = normalizeRowGroupLabel(group);
          const label = raw !== "" ? raw : emptyGroupLabel;
          const safe = typeof window.safeText === "function" ? window.safeText(label) : label;
          return safe + " (" + rows.count() + " " + rowLabel + ")";
        }
      }
    };
  };

  const getSafeColumnIndex = function (columnNamesOrColumns) {
    if (!Array.isArray(columnNamesOrColumns) || columnNamesOrColumns.length === 0) return -1;
    if (typeof getColumnIndexByName === "function") {
      const idx = getColumnIndexByName(columnNamesOrColumns, "id");
      if (typeof idx === "number" && idx >= 0) return idx;
    }
    const firstNonTechnical = columnNamesOrColumns.findIndex(function (col) {
      if (!col) return false;
      const name = typeof col === "string" ? col : (col.data || col.name || col.title);
      if (!name) return false;
      const lowered = String(name).toLowerCase();
      return lowered !== "select" && lowered !== "checkbox" && lowered !== "action";
    });
    return firstNonTechnical >= 0 ? firstNonTechnical : -1;
  };

  const resolveOrderToIndices = function (orderWhenActive, columnNamesOrColumns) {
    if (!Array.isArray(orderWhenActive)) return [[0, "desc"]];
    if (!columnNamesOrColumns || columnNamesOrColumns.length === 0) return orderWhenActive;
    const safeColumnIndex = getSafeColumnIndex(columnNamesOrColumns);
    const resolved = orderWhenActive
      .map(function (pair) {
        const key = pair[0];
        const dir = pair[1] === "asc" ? "asc" : "desc";
        if (typeof key === "number" && key >= 0 && key < columnNamesOrColumns.length) return [key, dir];
        if (typeof getColumnIndexByName === "function") {
          const idx = getColumnIndexByName(columnNamesOrColumns, String(key));
          if (typeof idx === "number" && idx >= 0) return [idx, dir];
        }
        if (safeColumnIndex >= 0) return [safeColumnIndex, dir];
        return null;
      })
      .filter(function (entry) { return entry !== null; });
    return resolved.length > 0 ? resolved : (safeColumnIndex >= 0 ? [[safeColumnIndex, "desc"]] : [[0, "desc"]]);
  };

  const ordersEqual = function (left, right) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    for (let i = 0; i < left.length; i++) {
      const l = left[i];
      const r = right[i];
      if (!Array.isArray(l) || !Array.isArray(r) || l.length < 2 || r.length < 2) return false;
      if (Number(l[0]) !== Number(r[0])) return false;
      if (String(l[1]).toLowerCase() !== String(r[1]).toLowerCase()) return false;
    }
    return true;
  };

  /**
   * Apply row group selection and optional snackbar feedback.
   *
   * @param {Function} [snackbarMessage] - Callback(option) returning the message string. Must return
   *   raw (unescaped) text; applyRengineRowGroupSelection passes the result through safeText before
   *   Snackbar.show to avoid XSS. Do not return pre-escaped HTML or it will be double-escaped.
   */
  const applyRengineRowGroupSelection = function (api, value, groups, defaultOrderWhenDisabled, snackbarMessage, columnNamesOrColumns, applyDefaultOrderWhenClearing) {
    if (value === "" || value == null) {
      api.rowGroup().disable();
      if (applyDefaultOrderWhenClearing !== false) {
        const orderToApply = resolveOrderToIndices(defaultOrderWhenDisabled, columnNamesOrColumns);
        api.order(orderToApply).draw();
      } else {
        api.draw();
      }
      if (typeof snackbarMessage === "function") {
        const Snackbar = window.Snackbar;
        if (Snackbar && typeof Snackbar.show === "function") {
          let msg = snackbarMessage({ value: "", label: "None" });
          if (typeof window.safeText === "function") msg = window.safeText(msg);
          Snackbar.show({ text: msg, pos: "top-right", duration: 2500 });
        }
      }
      return;
    }
    const option = groups.find(function (g) { return String(g.value) === String(value); });
    let orderWhenActive = option && option.orderWhenActive ? option.orderWhenActive : [[value, "asc"], [1, "desc"]];
    orderWhenActive = resolveOrderToIndices(orderWhenActive, columnNamesOrColumns);
    api.rowGroup().enable();
    api.rowGroup().dataSrc(value);
    api.order(orderWhenActive).draw();
    if (typeof snackbarMessage === "function" && option) {
      const Snackbar = window.Snackbar;
      if (Snackbar && typeof Snackbar.show === "function") {
        let msg = snackbarMessage(option);
        if (typeof window.safeText === "function") msg = window.safeText(msg);
        Snackbar.show({ text: msg, pos: "top-right", duration: 2500 });
      }
    }
  };

  /**
   * Returns a function(option) for snackbar text when row group selection changes.
   * option.value === "" means grouping cleared; otherwise option.label is used in the template.
   * The returned string is escaped in applyRengineRowGroupSelection before Snackbar.show.
   *
   * @param {string} emptyMessage - Message when grouping is cleared (e.g. "Grouping cleared").
   * @param {string} groupedTemplate - Template with {label} placeholder (e.g. "Grouped by {label}").
   * @returns {function(Object): string}
   */
  const getRengineRowGroupSnackbarMessage = function (emptyMessage, groupedTemplate) {
    const tpl = groupedTemplate || "Grouped by {label}";
    const empty = emptyMessage != null ? String(emptyMessage) : "Grouping cleared";
    return function (option) {
      if (!option || option.value === "" || option.value == null) return empty;
      const label = (option.label != null ? String(option.label) : "").trim();
      return tpl.replace(/\{label\}/g, label);
    };
  };

  const groupValueMatches = function (group, stored) {
    if (group == null) return false;
    if (typeof group === "string" || typeof group === "number") return String(group) === String(stored);
    if (group.value != null) return String(group.value) === String(stored);
    if (group.id != null) return String(group.id) === String(stored);
    return false;
  };

  /**
   * Returns initial order and rowGroup config from storage so the first DataTable request
   * uses the correct order/grouping and only one API call is made.
   *
   * @param {string} storageKey - Storage key for persisted group value.
   * @param {Array} groups - Same groups array as for attachRengineDatatableRowGroupSelector (with value, label, orderWhenActive).
   * @param {Array} defaultOrderWhenDisabled - Name-based default order when no group (e.g. [['id', 'desc']]).
   * @param {Array} columns - Column definitions (for resolveOrderToIndices).
   * @param {Object} rowGroupBaseOpts - Options for getRengineDatatableRowGroupOptions (dataSrc, rowLabel, emptyGroupLabel).
   * @returns {{ order: Array, rowGroup: Object, appliedFromStorage: boolean }}
   */
  const getInitialRowGroupStateFromStorage = function (storageKey, groups, defaultOrderWhenDisabled, columns, rowGroupBaseOpts) {
    const orderToApply = resolveOrderToIndices(defaultOrderWhenDisabled, columns);
    const defaultRowGroup = getRengineDatatableRowGroupOptions(rowGroupBaseOpts || {}).rowGroup;
    if (!storageKey || !storage || typeof storage.get !== "function") {
      return { order: orderToApply, rowGroup: defaultRowGroup, appliedFromStorage: false };
    }
    const saved = getRowGroupStoredValue(storageKey);
    const hasMatch = saved != null && saved !== "" && groups.some(function (g) { return groupValueMatches(g, saved); });
    if (!hasMatch) {
      return { order: orderToApply, rowGroup: defaultRowGroup, appliedFromStorage: false };
    }
    const option = groups.find(function (g) { return String(g.value) === String(saved); });
    const orderWhenActive = option && option.orderWhenActive ? option.orderWhenActive : [[saved, "asc"], [1, "desc"]];
    const order = resolveOrderToIndices(orderWhenActive, columns);
    const rowGroupOpts = getRengineDatatableRowGroupOptions(
      Object.assign({}, rowGroupBaseOpts, { dataSrc: saved })
    ).rowGroup;
    return { order: order, rowGroup: rowGroupOpts, appliedFromStorage: true };
  };

  /**
   * Get initial order and rowGroup for first draw (from storage if present, else defaults).
   * Use in list templates to avoid repeating the getInitialRowGroupStateFromStorage ternary.
   *
   * @param {string} storageKey - Storage key for saved group (empty skips persistence).
   * @param {Array} groups - Same groups array as for attachRengineDatatableRowGroupSelector.
   * @param {Array} defaultOrder - Name-based default order when no group (e.g. [['id', 'desc']]).
   * @param {Array} columns - Column definitions (for resolveOrderToIndices).
   * @param {Object} rowGroupBaseOpts - Options for getRengineDatatableRowGroupOptions (dataSrc, rowLabel, emptyGroupLabel).
   * @returns {{ order: Array, rowGroup: Object, appliedFromStorage: boolean }}
   */
  const getRengineRowGroupInitialState = function (storageKey, groups, defaultOrder, columns, rowGroupBaseOpts) {
    const getInitial = window.getInitialRowGroupStateFromStorage;
    if (storageKey && typeof getInitial === "function") {
      return getInitial(storageKey, groups, defaultOrder, columns, rowGroupBaseOpts || {});
    }
    const order =
      typeof window.getRengineDatatableOrderFromNames === "function"
        ? window.getRengineDatatableOrderFromNames(columns, defaultOrder)
        : resolveOrderToIndices(defaultOrder, columns);
    const rowGroup = getRengineDatatableRowGroupOptions(rowGroupBaseOpts || {}).rowGroup;
    return { order: order, rowGroup: rowGroup, appliedFromStorage: false };
  };

  /**
   * Attach row-group radio/select so changing selection enables/disables grouping and optionally applies order.
   *
   * opts.applyDefaultOrderWhenClearing: when true (default), clearing grouping (value === "") applies
   * defaultOrderWhenDisabled; when false, only disables rowGroup and redraws, preserving current user sort.
   *
   * @param {Object} opts
   * @param {string} opts.selector - jQuery selector for the inputs controlling grouping.
   * @param {Array} opts.groups - Group definitions: [{ value, label, orderWhenActive }].
   * @param {Array} opts.defaultOrderWhenDisabled - Name-based default order when no group.
   * @param {Array} opts.columns - Column definitions for resolveOrderToIndices.
   * @param {Array} [opts.columnNames] - Alternate column names array for resolveOrderToIndices.
   * @param {Function} [opts.snackbarMessage] - Optional snackbar message factory.
   * @param {string} [opts.storageKey] - Storage key for persisted group value.
   * @param {string} [opts.cookieKey] - Deprecated alias for storageKey (backwards compatibility).
   * @param {boolean} [opts.applyDefaultOrderWhenClearing] - Whether to apply default order when clearing grouping.
   * @param {boolean} [opts.initialGroupFromCookie] - Whether initial grouping/order was applied from persisted state.
   */
  const attachRengineDatatableRowGroupSelector = function (tableApi, opts) {
    const api = tableApi && tableApi.api ? tableApi.api() : tableApi;
    const selector = opts.selector;
    const groups = opts.groups || [];
    const defaultOrderWhenDisabled = opts.defaultOrderWhenDisabled || [[1, "desc"]];
    const snackbarMessage = opts.snackbarMessage;
    const storageKey = opts.storageKey || opts.cookieKey;
    const columnNamesOrColumns = opts.columns || opts.columnNames;
    const applyDefaultOrderWhenClearing = opts.applyDefaultOrderWhenClearing !== false;
    if (!selector || !api || typeof api.rowGroup !== "function") return;
    const $ = window.jQuery;
    if (!$ || typeof $(selector).on !== "function") return;
    const apply = function (value) {
      applyRengineRowGroupSelection(api, value, groups, defaultOrderWhenDisabled, snackbarMessage, columnNamesOrColumns, applyDefaultOrderWhenClearing);
    };
    $(selector).on("change", function () {
      const value = this.value;
      if (storageKey) setRowGroupStoredValue(storageKey, value === "" || value == null ? "" : value);
      apply(value);
    });
    const orderToApply = resolveOrderToIndices(defaultOrderWhenDisabled, columnNamesOrColumns);
    if (storageKey && storage && typeof storage.get === "function" && typeof storage.set === "function") {
      const saved = getRowGroupStoredValue(storageKey);
      const hasMatch = saved != null && saved !== "" && groups.some(function (g) { return groupValueMatches(g, saved); });
      if (hasMatch) {
        $(selector).filter(function () { return $(this).val() === saved; }).first().prop("checked", true);
        if (!opts.initialGroupFromCookie) {
          apply(saved);
        }
      } else {
        if (saved != null && saved !== "") {
          setRowGroupStoredValue(storageKey, "");
        }
        $(selector).filter('[value=""]').first().prop("checked", true);
        api.rowGroup().disable();
        if (!ordersEqual(api.order(), orderToApply)) {
          api.order(orderToApply);
        }
      }
    } else {
      api.rowGroup().disable();
      if (!ordersEqual(api.order(), orderToApply)) {
        api.order(orderToApply);
      }
    }
  };

  window.normalizeRowGroupLabel = normalizeRowGroupLabel;
  window.getRengineDatatableOrderFromNames = getRengineDatatableOrderFromNames;
  window.getRengineRowGroupInitialState = getRengineRowGroupInitialState;
  window.getRengineDatatableRowGroupOptions = getRengineDatatableRowGroupOptions;
  window.getInitialRowGroupStateFromStorage = getInitialRowGroupStateFromStorage;
  window.getRengineRowGroupSnackbarMessage = getRengineRowGroupSnackbarMessage;
  window.attachRengineDatatableRowGroupSelector = attachRengineDatatableRowGroupSelector;
})(window);
