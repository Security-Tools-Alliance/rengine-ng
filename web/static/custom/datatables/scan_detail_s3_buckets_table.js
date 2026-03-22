/**
 * S3 buckets server-side DataTable for scan detail.
 */
(function (window) {
  "use strict";

  /**
   * @typedef {Object} ScanDetailS3BucketsConfig
   * @property {string} ajaxUrl
   * @property {string} [tableSelector]
   * @property {string} [filterParamsElementId]
   */

  /**
   * @param {ScanDetailS3BucketsConfig} config
   * @returns {object|null}
   */
  window.initScanDetailS3BucketsDataTable = function (config) {
    const $ = window.jQuery;
    if (!$ || !config || !config.ajaxUrl || typeof window.initServerSideDataTable !== "function") {
      return null;
    }
    const tableSelector = config.tableSelector || "#s3-datatable";
    const filterElId = config.filterParamsElementId || "s3-datatable-filter-params";

    const s3TableColumns = [
      { data: "name", name: "name" },
      { data: "region", name: "region" },
      { data: "provider", name: "provider" },
      { data: "owner", name: "owner" },
      { data: "objects_count", name: "objects_count" },
      { data: "bucket_size", name: "bucket_size" },
      { data: "auth_users_permission", name: "auth_users_permission" },
      { data: "all_users_permission", name: "all_users_permission" },
    ];
    const s3TableOrder = window.getRengineDatatableOrderFromNames
      ? window.getRengineDatatableOrderFromNames(s3TableColumns, [["name", "asc"]])
      : [[0, "asc"]];

    let s3FilterSelectToParam = {};
    const s3FilterParamsEl = document.getElementById(filterElId);
    if (s3FilterParamsEl) {
      try {
        s3FilterSelectToParam = JSON.parse(s3FilterParamsEl.textContent) || {};
      } catch (e) {
        if (typeof console !== "undefined" && console.error) {
          console.error("Failed to parse s3-datatable-filter-params JSON", e);
        }
      }
    }

    const s3Table = window.initServerSideDataTable(
      tableSelector,
      window.getRengineDatatableConfig(tableSelector, {
        ajax: {
          url: config.ajaxUrl,
          data: function (d) {
            if (window.buildDatatableFilterPayload) {
              const payload = window.buildDatatableFilterPayload(s3FilterSelectToParam);
              Object.keys(payload).forEach(function (key) {
                d[key] = payload[key];
              });
            }
          },
        },
        columns: s3TableColumns,
        order: s3TableOrder,
        scrollY: "60vh",
        initComplete: function () {
          if (typeof window.rengineSafeTooltipInit === "function") {
            window.rengineSafeTooltipInit($(tableSelector + " [data-toggle=\"tooltip\"]"));
          }
        },
      }),
    );

    if (window.attachDatatableFilters) {
      window.attachDatatableFilters(
        window.getRengineDatatableFilterAttachOpts("s3_buckets", s3Table, {
          onApply: function () {
            s3Table.draw();
          },
        }),
      );
    }

    return s3Table;
  };
})(window);
