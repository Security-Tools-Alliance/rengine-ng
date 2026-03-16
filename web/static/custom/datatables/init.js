/**
 * DataTables init: getRengineDatatableConfig, initServerSideDataTable, initRengineServerSideDataTable,
 * initDetailScanServerSideTable, initClientSideDataTable.
 *
 * Depends on: layout.js (getRengineDatatableScrollerOptions, getRengineDatatableLayoutFull, lengthMenu, pageLength),
 * filters.js (buildDatatableFilterPayload, getRengineDatatableFilterParams), rowgroup.js (getRengineRowGroupInitialState,
 * attachRengineDatatableRowGroupSelector), columns.js (getRengineDatatableOrderFromNames), tooltips.js (getRengineDatatableDrawCallbackTooltips).
 * Requires: window.jQuery and jQuery.fn.DataTable. If these are missing, init helpers no-op and log a warning.
 * Backend mapping: filterParamsElId / filterSelectToParam come from FILTER_CONTEXT_* (filters.py); buildDatatableFilterPayload
 * sends selected values as API params. See README "Backend → frontend mapping".
 */
(function (window) {
  "use strict";

  if (typeof window.buildDatatableFilterPayload !== "function") {
    window.buildDatatableFilterPayload = function () { return {}; };
  }
  if (typeof window.attachDatatableFilters !== "function") {
    window.attachDatatableFilters = function () {};
  }

  function requireDataTableGlobals() {
    const $ = window.jQuery;
    if (!$ || typeof $.fn !== "object" || typeof $.fn.DataTable !== "function") {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("rengine DataTables init: jQuery or DataTable plugin not loaded. Ensure script order: jQuery, DataTables, then datatables/*.js.");
      }
      return false;
    }
    const hasLayout = typeof window.getRengineDatatableLayoutFull === "function" || (window.RENGINE_DATATABLE_LAYOUT_FULL != null);
    if (!hasLayout && typeof console !== "undefined" && console.warn) {
      console.warn("rengine DataTables init: getRengineDatatableLayoutFull / RENGINE_DATATABLE_LAYOUT_FULL missing. Load layout.js before init.js.");
    }
    return true;
  }

  function tableIdFromSelector(selector) {
    if (!selector || typeof selector !== "string") return null;
    const s = selector.trim().replace(/^#/, "");
    return s.length > 0 ? s : null;
  }

  const getRengineDatatableConfig = function (tableSelector, options) {
    const opts = options || {};
    const tableId = tableIdFromSelector(tableSelector);
    const scrollY = opts.scrollY || "60vh";
    const scrollerOpts =
      typeof window.getRengineDatatableScrollerOptions === "function"
        ? window.getRengineDatatableScrollerOptions(scrollY)
        : {};
    const pageLength =
      typeof window.getRengineDatatablePageLength === "function"
        ? window.getRengineDatatablePageLength(tableId)
        : 30;
    const baseOptions = {
      serverSide: true,
      processing: true,
      responsive: true,
      ajax: Object.assign({ dataSrc: "data" }, opts.ajax || {}),
      layout:
        typeof window.getRengineDatatableLayoutFull === "function"
          ? window.getRengineDatatableLayoutFull()
          : window.RENGINE_DATATABLE_LAYOUT_FULL,
      lengthMenu:
        typeof window.getRengineDatatableLengthMenu === "function"
          ? window.getRengineDatatableLengthMenu()
          : [[10, 20, 30, 50, 100, 200, 500, 1000, -1], ["10", "20", "30", "50", "100", "200", "500", "1000", "All"]],
      pageLength: pageLength
    };
    const merged = Object.assign({}, baseOptions, scrollerOpts, opts);
    if (merged.ajax && merged.ajax.dataSrc === undefined) merged.ajax.dataSrc = "data";
    merged.__rengineDatatableConfig = true;
    return merged;
  };

  const initServerSideDataTable = function (tableSelector, options) {
    if (!requireDataTableGlobals()) return null;
    const merged =
      options && options.__rengineDatatableConfig
        ? options
        : getRengineDatatableConfig(tableSelector, options);
    const userInitComplete = merged.initComplete;
    merged.initComplete = function () {
      if (typeof window.rengineSafeTooltipInit === "function") {
        window.rengineSafeTooltipInit(
          "[data-toggle=\"tooltip\"]:not([data-bs-toggle=\"dropdown\"]):not([data-toggle=\"dropdown\"])"
        );
      }
      if (typeof userInitComplete === "function") userInitComplete.apply(this, arguments);
    };
    const table = window.jQuery(tableSelector).DataTable(merged);
    const tableId = tableIdFromSelector(tableSelector);
    if (tableId && typeof window.setRengineDatatablePageLength === "function") {
      table.on("length.dt", function (_e, _settings, len) {
        window.setRengineDatatablePageLength(tableId, len);
      });
    }
    return table;
  };

  /**
   * One-call server-side DataTable init with optional filter payload, drawCallback tooltips, and row group.
   * Templates pass a single config; this wrapper merges filter data, sets drawCallback, inits the table, then attaches row group if requested.
   * When rowGroup has cookieKey and rowGroupBaseOpts, initial order/rowGroup are computed from cookie via getRengineRowGroupInitialState.
   *
   * @param {string} tableSelector - CSS selector for the table (e.g. '#scan_history_table').
   * @param {object} options - getRengineDatatableConfig options plus:
   *   - filterSelectToParam: optional object (select id -> param name); merged into ajax.data via buildDatatableFilterPayload.
   *   - filterParamsElId: optional; if set and filterSelectToParam not set, filterSelectToParam = getRengineDatatableFilterParams(filterParamsElId).
   *   - drawCallbackTooltips: optional true or { tooltipTemplate: '...' }; sets drawCallback to getRengineDatatableDrawCallbackTooltips.
   *   - rowGroup: optional { selector, groups, columns, defaultOrderWhenDisabled, snackbarMessage, cookieKey, initialGroupFromCookie } or with rowGroupBaseOpts to auto-compute initial state from cookie.
   *   - orderFromColumns: optional [columns, defaultOrder] for getRengineDatatableOrderFromNames; used when order not set.
   * @returns {DataTable.Api} The DataTable API instance.
   */
  const initRengineServerSideDataTable = function (tableSelector, options) {
    if (!requireDataTableGlobals()) return null;
    const opts = options
      ? Object.assign({}, options, { ajax: options.ajax ? Object.assign({}, options.ajax) : options.ajax })
      : {};
    let filterSelectToParam = opts.filterSelectToParam || null;
    if (!filterSelectToParam && opts.filterParamsElId && typeof window.getRengineDatatableFilterParams === "function") {
      filterSelectToParam = window.getRengineDatatableFilterParams(opts.filterParamsElId);
    }
    const drawCallbackTooltips = opts.drawCallbackTooltips;
    const rowGroup = opts.rowGroup;
    const orderFromColumns = opts.orderFromColumns;

    if (opts.ajax && filterSelectToParam && typeof window.buildDatatableFilterPayload === "function") {
      const baseData = opts.ajax.data;
      opts.ajax = Object.assign({}, opts.ajax, {
        data: function (d) {
          if (typeof baseData === "function") {
            const baseResult = baseData(d);
            if (baseResult && typeof baseResult === "object") {
              Object.assign(d, baseResult);
            }
          } else if (baseData) {
            Object.assign(d, baseData);
          }
          Object.assign(d, window.buildDatatableFilterPayload(filterSelectToParam));
        },
      });
    }

    if (drawCallbackTooltips && typeof window.getRengineDatatableDrawCallbackTooltips === "function") {
      const tooltipOpts = drawCallbackTooltips === true ? {} : drawCallbackTooltips;
      const userDrawCallback = opts.drawCallback;
      const tooltipDrawCallback = window.getRengineDatatableDrawCallbackTooltips(tableSelector, tooltipOpts);
      opts.drawCallback = function (settings) {
        if (typeof tooltipDrawCallback === "function") tooltipDrawCallback.call(this, settings);
        if (typeof userDrawCallback === "function") userDrawCallback.apply(this, arguments);
      };
    }

    let rowGroupAttachOpts = rowGroup;
    if (rowGroup && rowGroup.cookieKey && rowGroup.rowGroupBaseOpts && typeof window.getRengineRowGroupInitialState === "function") {
      const cols = rowGroup.columns || [];
      const defaultOrder = rowGroup.defaultOrderWhenDisabled || [["id", "desc"]];
      const state = window.getRengineRowGroupInitialState(
        rowGroup.cookieKey,
        rowGroup.groups || [],
        defaultOrder,
        cols,
        rowGroup.rowGroupBaseOpts
      );
      opts.order = state.order;
      opts.rowGroup = state.rowGroup;
      rowGroupAttachOpts = Object.assign({}, rowGroup, { initialGroupFromCookie: state.appliedFromCookie });
    } else if (orderFromColumns && opts.order === undefined) {
      const cols = orderFromColumns[0];
      const defaultOrder = orderFromColumns[1] || [["id", "desc"]];
      opts.order =
        typeof window.getRengineDatatableOrderFromNames === "function"
          ? window.getRengineDatatableOrderFromNames(cols, defaultOrder)
          : defaultOrder;
    }

    const table = initServerSideDataTable(tableSelector, opts);

    if (rowGroupAttachOpts && typeof window.attachRengineDatatableRowGroupSelector === "function") {
      window.attachRengineDatatableRowGroupSelector(table, rowGroupAttachOpts);
    }

    return table;
  };

  const initClientSideDataTable = function (tableSelector, extraOptions) {
    if (!requireDataTableGlobals()) return null;
    const opts = extraOptions || {};
    const scrollY = opts.scrollY || "60vh";
    const scrollerOpts =
      typeof window.getRengineDatatableScrollerOptions === "function"
        ? window.getRengineDatatableScrollerOptions(scrollY)
        : {};
    const baseOptions = {
      layout: window.RENGINE_DATATABLE_LAYOUT_WITH_SEARCH,
      lengthMenu:
        typeof window.getRengineDatatableLengthMenu === "function"
          ? window.getRengineDatatableLengthMenu()
          : [[30, 50, 100, -1], ["30", "50", "100", "All"]],
      pageLength:
        typeof window.getRengineDatatablePageLength === "function"
          ? window.getRengineDatatablePageLength()
          : 30,
      initComplete: function () {
        if (typeof window.rengineSafeTooltipInit === "function") {
          window.rengineSafeTooltipInit(
            "[data-toggle=\"tooltip\"]:not([data-bs-toggle=\"dropdown\"]):not([data-toggle=\"dropdown\"])"
          );
        }
      }
    };
    const merged = Object.assign({}, baseOptions, scrollerOpts, opts);
    return window.jQuery(tableSelector).DataTable(merged);
  };

  /**
   * Detail-scan style server-side DataTable: same as initRengineServerSideDataTable but with
   * default scroll (60vh), layout, and drawCallback tooltips so per-table configs stay short.
   * Use for endpoint/subdomain/change tables that share ajax + tooltips + optional row group.
   *
   * @param {string} tableSelector - CSS selector for the table (e.g. '#table-subdomain-changes').
   * @param {object} options - Options for initRengineServerSideDataTable. drawCallbackTooltips
   *   defaults to true; scrollY defaults to "60vh". Pass columns, ajax, order, drawCallback, etc.
   * @returns {DataTable.Api} The DataTable API instance.
   */
  const initDetailScanServerSideTable = function (tableSelector, options) {
    if (!requireDataTableGlobals()) return null;
    const opts = options ? Object.assign({}, options) : {};
    const scrollY = opts.scrollY != null ? opts.scrollY : "60vh";
    const scrollerOpts =
      typeof window.getRengineDatatableScrollerOptions === "function"
        ? window.getRengineDatatableScrollerOptions(scrollY)
        : {};
    const layout =
      typeof window.getRengineDatatableLayoutFull === "function"
        ? window.getRengineDatatableLayoutFull()
        : window.RENGINE_DATATABLE_LAYOUT_FULL;
    if (opts.drawCallbackTooltips === undefined) opts.drawCallbackTooltips = true;
    const merged = Object.assign({}, scrollerOpts, { layout: layout }, opts);
    return initRengineServerSideDataTable(tableSelector, merged);
  };

  window.getRengineDatatableConfig = getRengineDatatableConfig;
  window.initServerSideDataTable = initServerSideDataTable;
  window.initRengineServerSideDataTable = initRengineServerSideDataTable;
  window.initDetailScanServerSideTable = initDetailScanServerSideTable;
  window.initClientSideDataTable = initClientSideDataTable;

  /**
   * Attach a simple global search input to a DataTable instance and place it to the right
   * of the "Results" (length) dropdown in the table's control row.
   * opts: { inputSelector: '#input-id', delayMs?: number }
   */
  window.attachDatatableQuickSearch = function (table, opts) {
    if (!table || !opts || !opts.inputSelector) {
      return;
    }
    const $ = window.jQuery;
    if (!$) {
      return;
    }
    const $input = $(opts.inputSelector);
    if (!$input.length) {
      return;
    }
    const delay = typeof opts.delayMs === "number" ? opts.delayMs : 700;
    let timeoutId = null;
    function triggerSearch() {
      const val = $input.val() || "";
      if (table.search() !== val) {
        table.search(val).draw();
      }
    }
    $input.off(".rengineQuickSearch").on("keyup.rengineQuickSearch change.rengineQuickSearch", function () {
      if (timeoutId !== null) {
        window.clearTimeout(timeoutId);
      }
      timeoutId = window.setTimeout(function () {
        timeoutId = null;
        triggerSearch();
      }, delay);
    });

    if (table.table && typeof table.table === "function") {
      const container = table.table().container();
      if (container) {
        const $container = $(container);
        const $length = $container.find(".dt-length").first();
        if ($length.length) {
          const $searchBlock = $input.closest("div");
          if ($searchBlock.length && !$searchBlock.closest(".dt-container").length) {
            $length.after($searchBlock);
          }
        }
      }
    }
  };

  /**
   * Attach per-column search inputs (header and/or footer) to a DataTable instance.
   *
   * Inputs must live inside the table header/footer and carry a data-column-index attribute:
   *   <input type="text" class="form-control form-control-sm datatable-column-search"
   *          data-column-index="2" placeholder="Search target">
   *
   * With scrollY, DataTables may move thead/tfoot into scroll containers; we resolve them
   * from the table's container so handlers attach to the correct nodes.
   *
   * opts: { tableSelector: '#table-id', delayMs?: number }
   */
  window.attachDatatableColumnSearch = function (table, opts) {
    if (!table || !opts || !opts.tableSelector) {
      return;
    }
    const $ = window.jQuery;
    if (!$) {
      return;
    }
    const delay = typeof opts.delayMs === "number" ? opts.delayMs : 700;
    const $table = $(opts.tableSelector);
    if (!$table.length) {
      return;
    }

    // Resolve thead/tfoot from the DataTable container so we find them even when
    // scrollY has moved them into .dataTables_scrollHead / .dataTables_scrollFoot.
    let $thead = $table.find("thead");
    let $tfoot = $table.find("tfoot");
    if (table.table && typeof table.table === "function") {
      const container = table.table().container();
      if (container && $(container).length) {
        const $wrapper = $(container);
        if (!$thead.length) {
          $thead = $wrapper.find(".dataTables_scrollHead thead, thead");
        }
        if (!$tfoot.length) {
          $tfoot = $wrapper.find(".dataTables_scrollFoot tfoot, tfoot");
        }
      }
    }

    function debounce(fn, wait) {
      let timeoutId = null;
      return function debounced() {
        const ctx = this;
        const args = arguments;
        if (timeoutId !== null) {
          window.clearTimeout(timeoutId);
        }
        timeoutId = window.setTimeout(function () {
          timeoutId = null;
          fn.apply(ctx, args);
        }, wait);
      };
    }

    function attachToInputs($container) {
      if (!$container || !$container.length) {
        return;
      }
      $container
        .find("input.datatable-column-search[data-column-index], select.datatable-column-search[data-column-index]")
        .each(function () {
          const idxAttr = this.getAttribute("data-column-index");
          const colIdx = idxAttr != null ? parseInt(idxAttr, 10) : NaN;
          if (Number.isNaN(colIdx)) {
            return;
          }
          const handler = debounce(function () {
            const val = this.value || "";
            const current = table.column(colIdx).search();
            if (current !== val) {
              table.column(colIdx).search(val).draw();
            }
          }, delay);
          $(this).off(".rengineColumnSearch").on("keyup.rengineColumnSearch change.rengineColumnSearch", handler);
        });
    }

    attachToInputs($thead);
    attachToInputs($tfoot);
  };
})(window);
