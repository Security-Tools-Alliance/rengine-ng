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

  /**
   * Initialise a client-side DataTable with standard reNgine options (layout, lengthMenu,
   * pageLength, scroller, initComplete tooltips). Use for list pages with server-rendered rows.
   * @param {string} tableSelector - jQuery selector for the table (e.g. "#list_scope_table").
   * @param {object} extraOptions - Optional options merged into the DataTable config. Use scrollY (e.g. "40vh") to override default scroll height.
   * @returns {object} The DataTable instance.
   */
  const initClientSideDataTable = function (tableSelector, extraOptions) {
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
        if (
          typeof window.jQuery !== "undefined" &&
          window.jQuery("[data-toggle=\"tooltip\"]").length
        ) {
          window.jQuery("[data-toggle=\"tooltip\"]").tooltip();
        }
      }
    };
    const merged = Object.assign({}, baseOptions, scrollerOpts, opts);
    return window.jQuery(tableSelector).DataTable(merged);
  };

  /**
   * Confirm then POST to delete URL from row data attribute; on success remove row and show toast.
   * Expects row to have an attribute (default data-delete-url) with the delete endpoint URL.
   * Requires Swal and getCookie in global scope.
   * @param {HTMLElement} btn - Button that triggered the action (row is btn's closest tr).
   * @param {object} options - confirmTitle, confirmText, successMessage, errorMessage, deleteUrlAttr (default "data-delete-url").
   */
  const confirmDeleteRow = function (btn, options) {
    const opts = options || {};
    const deleteUrlAttr = opts.deleteUrlAttr || "data-delete-url";
    const row = window.jQuery(btn).closest("tr");
    const deleteUrl = row.attr(deleteUrlAttr);
    if (!deleteUrl) return;
    const confirmTitle = opts.confirmTitle || "Are you sure?";
    const confirmText = opts.confirmText || "This action cannot be undone!";
    const successMessage = opts.successMessage || "Deleted!";
    const errorMessage = opts.errorMessage || "Could not delete.";

    const swalFn = window.swal && typeof window.swal.fire === "function" ? window.swal.fire : (window.Swal && window.Swal.fire);
    if (typeof swalFn !== "function") return;

    swalFn({
      title: confirmTitle,
      text: confirmText,
      icon: "warning",
      showCancelButton: true,
      confirmButtonText: "Delete",
      confirmButtonColor: "#d33",
      cancelButtonText: "Cancel"
    }).then(function (result) {
      if (result && result.isConfirmed) {
        const getCookie = window.getCookie;
        const csrfToken = typeof getCookie === "function" ? getCookie("csrftoken") : "";
        window
          .fetch(deleteUrl, {
            method: "POST",
            headers: {
              "X-CSRFToken": csrfToken,
              "Content-Type": "application/json"
            },
            body: "{}"
          })
          .then(function (response) {
            return response.json();
          })
          .then(function (data) {
            if (data.status === "true") {
              row.remove();
              swalFn({ title: successMessage, icon: "success" });
            } else {
              swalFn({ title: "Error", text: errorMessage, icon: "error" });
            }
          })
          .catch(function () {
            swalFn({ title: "Error", text: errorMessage, icon: "error" });
          });
      }
    });
  };

  /**
   * Renders the four scan summary badges (Domains, Subdomains, Endpoints, Vulnerabilities)
   * in the same order and style as target summary and scan history.
   * @param {object} opts - domainCount, subdomainCount, endpointCount, vulnerabilityCount (numbers), vulnTooltip (string, optional)
   * @returns {string} HTML for the badge row
   */
  const renderScanSummaryBadges = function (opts) {
    const esc = function (s) {
      const t = String(s == null ? "" : s);
      return t
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    };
    const n = function (v) {
      const num = Number(v);
      return isNaN(num) ? 0 : num;
    };
    const d = n(opts.domainCount);
    const s = n(opts.subdomainCount);
    const e = n(opts.endpointCount);
    const v = n(opts.vulnerabilityCount);
    const vulnTitle = opts.vulnTooltip != null ? esc(opts.vulnTooltip) : "Vulnerabilities";
    return (
      '<span class="badge badge-pills bg-secondary mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Domains"><i class="fe-globe me-1"></i>' +
      d +
      '</span> ' +
      '<span class="badge badge-pills bg-info mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Subdomains"><i class="fe-layers me-1"></i>' +
      s +
      '</span> ' +
      '<span class="badge badge-pills bg-warning mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Endpoints"><i class="fe-link me-1"></i>' +
      e +
      '</span> ' +
      '<span class="badge badge-pills bg-danger mt-1 me-1" data-toggle="tooltip" data-placement="top" title="' +
      vulnTitle +
      '"><i class="fe-alert-triangle me-1"></i>' +
      v +
      "</span>"
    );
  };

  window.getRengineDatatableLayoutFull = getRengineDatatableLayoutFull;
  window.getRengineDatatableScrollerOptions = getRengineDatatableScrollerOptions;
  window.getRengineDatatablePageLength = getRengineDatatablePageLength;
  window.getRengineDatatableLengthMenu = getRengineDatatableLengthMenu;
  window.initClientSideDataTable = initClientSideDataTable;
  window.confirmDeleteRow = confirmDeleteRow;
  window.renderScanSummaryBadges = renderScanSummaryBadges;

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
