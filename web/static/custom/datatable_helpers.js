/**
 * Central helper for DataTables options: layout and scroller settings based on user preference.
 * Use getRengineDatatableLayoutFull() and getRengineDatatableScrollerOptions() when initialising
 * server-side DataTables so they respect the Interface > DataTables display setting.
 */
(function (window) {
  "use strict";

  const useScroller = function () {
    return Boolean(window.RENGINE_DATATABLE_USE_SCROLLER);
  };

  /**
   * Returns the layout object for "full" tables (pageLength, info, paging) based on user preference.
   * With scroller: no info row. With classic: info + paging.
   */
  const getRengineDatatableLayoutFull = function () {
    if (useScroller() && window.RENGINE_DATATABLE_LAYOUT_FULL_SCROLLER) {
      return window.RENGINE_DATATABLE_LAYOUT_FULL_SCROLLER;
    }
    return window.RENGINE_DATATABLE_LAYOUT_FULL_CLASSIC || window.RENGINE_DATATABLE_LAYOUT_FULL;
  };

  /**
   * Returns true if the DataTables Scroller plugin is loaded.
   * @returns {boolean}
   */
  const hasScrollerPlugin = function () {
    return (
      typeof window.jQuery !== "undefined" &&
      typeof window.jQuery.fn !== "undefined" &&
      typeof window.jQuery.fn.DataTable !== "undefined" &&
      typeof window.jQuery.fn.DataTable.Scroller !== "undefined"
    );
  };

  /**
   * Returns extra options for server-side DataTables when user chose Scroller mode.
   * When classic, returns {}. When scroller, returns { scrollY, deferRender: true, scroller: true }.
   * If Scroller plugin is not loaded, falls back to {} and optionally logs a console warning.
   * @param {string} scrollY - CSS height for the table body (e.g. "60vh", "400px").
   */
  const getRengineDatatableScrollerOptions = function (scrollY) {
    if (!useScroller()) {
      return {};
    }
    if (!hasScrollerPlugin()) {
      if (window.console && typeof window.console.warn === "function") {
        window.console.warn(
          "[DataTables] Scroller mode requested (RENGINE_DATATABLE_USE_SCROLLER=true) " +
            "but DataTables Scroller plugin is not loaded. Falling back to classic layout."
        );
      }
      return {};
    }
    const height = typeof scrollY === "string" ? scrollY : "60vh";
    return {
      scrollY: height,
      deferRender: true,
      scroller: true
    };
  };

  /**
   * Returns the user's default page length (rows per page) for DataTables.
   * Set via Interface settings; falls back to 30 if not set.
   * @returns {number}
   */
  const getRengineDatatablePageLength = function () {
    const n = window.RENGINE_DATATABLE_PAGE_LENGTH;
    return typeof n === "number" && n > 0 ? n : 30;
  };

  /**
   * Returns the centralized lengthMenu for DataTables: [ [ values ], [ labels ] ].
   * Values come from server (datatables_page_length_menu_values); -1 is displayed as "All".
   * @returns {[number[], string[]]}
   */
  const getRengineDatatableLengthMenu = function () {
    const values = window.RENGINE_DATATABLE_LENGTH_MENU_VALUES;
    const arr = Array.isArray(values) ? values : [30, 50, 100, 200, 500, 1000, -1];
    const labels = arr.map(function (v) {
      return v === -1 ? "All" : String(v);
    });
    return [arr, labels];
  };

  window.getRengineDatatableLayoutFull = getRengineDatatableLayoutFull;
  window.getRengineDatatableScrollerOptions = getRengineDatatableScrollerOptions;
  window.getRengineDatatablePageLength = getRengineDatatablePageLength;
  window.getRengineDatatableLengthMenu = getRengineDatatableLengthMenu;

  if (window.RENGINE_DATATABLE_USE_SCROLLER && !hasScrollerPlugin()) {
    if (window.console && typeof window.console.warn === "function") {
      window.console.warn(
        "[DataTables] Scroller mode is enabled (RENGINE_DATATABLE_USE_SCROLLER=true) " +
          "but the DataTables Scroller plugin is not loaded. Tables will use classic layout. " +
          "Load the Scroller extension or disable Scroller in Interface settings."
      );
    }
  }
})(window);
