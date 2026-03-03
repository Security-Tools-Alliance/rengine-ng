/**
 * DataTables layout and scroller options (page length, length menu, scroller).
 * Use getRengineDatatableLayoutFull() and getRengineDatatableScrollerOptions() when initialising
 * server-side DataTables so they respect the Interface > DataTables display setting.
 */
(function (window) {
  "use strict";

  const useScroller = function () {
    return Boolean(window.RENGINE_DATATABLE_USE_SCROLLER);
  };

  const getRengineDatatableLayoutFull = function () {
    if (useScroller() && window.RENGINE_DATATABLE_LAYOUT_FULL_SCROLLER) {
      return window.RENGINE_DATATABLE_LAYOUT_FULL_SCROLLER;
    }
    return window.RENGINE_DATATABLE_LAYOUT_FULL_CLASSIC || window.RENGINE_DATATABLE_LAYOUT_FULL;
  };

  const hasScrollerPlugin = function () {
    return (
      typeof window.jQuery !== "undefined" &&
      typeof window.jQuery.fn !== "undefined" &&
      typeof window.jQuery.fn.DataTable !== "undefined" &&
      typeof window.jQuery.fn.DataTable.Scroller !== "undefined"
    );
  };

  const getRengineDatatableScrollerOptions = function (scrollY) {
    if (!useScroller()) return {};
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
    return { scrollY: height, deferRender: true, scroller: true };
  };

  const getRengineDatatablePageLength = function () {
    const n = window.RENGINE_DATATABLE_PAGE_LENGTH;
    return typeof n === "number" && n > 0 ? n : 30;
  };

  const getRengineDatatableLengthMenu = function () {
    const values = window.RENGINE_DATATABLE_LENGTH_MENU_VALUES;
    const arr = Array.isArray(values) ? values : [10, 20, 30, 50, 100, 200, 500, 1000, -1];
    const labels = arr.map(function (v) { return v === -1 ? "All" : String(v); });
    return [arr, labels];
  };

  window.getRengineDatatableLayoutFull = getRengineDatatableLayoutFull;
  window.getRengineDatatableScrollerOptions = getRengineDatatableScrollerOptions;
  window.getRengineDatatablePageLength = getRengineDatatablePageLength;
  window.getRengineDatatableLengthMenu = getRengineDatatableLengthMenu;

  if (window.RENGINE_DATATABLE_USE_SCROLLER && !hasScrollerPlugin() && (window.console && typeof window.console.warn === "function")) {
        window.console.warn(
          "[DataTables] Scroller mode is enabled (RENGINE_DATATABLE_USE_SCROLLER=true) " +
            "but the DataTables Scroller plugin is not loaded. Tables will use classic layout. " +
            "Load the Scroller extension or disable Scroller in Interface settings."
        );
  }
})(window);
