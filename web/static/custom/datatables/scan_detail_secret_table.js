/**
 * Lazy secrets DataTable for scan detail only.
 */
(function (window) {
  "use strict";

  /**
   * @typedef {Object} ScanDetailSecretTableConfig
   * @property {string} ajaxUrl
   * @property {Array} columns secret_datatable_columns from template
   * @property {string} [tabSelector]
   * @property {string} [tableSelector]
   */

  /**
   * @param {ScanDetailSecretTableConfig} config
   */
  window.registerScanDetailSecretTab = function (config) {
    const $ = window.jQuery;
    if (!$ || !config || !config.ajaxUrl || !config.columns) {
      return;
    }
    const tabSelector = config.tabSelector || "#pills-secrets-tab";
    const tableSelector = config.tableSelector || "#secret_results";

    $(tabSelector).on("click", function () {
      if ($.fn.DataTable && $.fn.DataTable.isDataTable(tableSelector)) {
        return;
      }
      const colDefs = window.RengineDatatableColumnDefs || {};
      const secretTable = window.initServerSideDataTable(
        tableSelector,
        window.getRengineDatatableConfig(tableSelector, {
          destroy: true,
          ajax: { url: config.ajaxUrl },
          scrollY: "60vh",
          order: window.getRengineDatatableOrderFromNames
            ? window.getRengineDatatableOrderFromNames(config.columns, [["discovered_date", "desc"]])
            : [[5, "desc"]],
          columns: config.columns,
          columnDefs: [
            { orderable: false, targets: "action:name" },
            colDefs.getSafeTextColumnDef ? colDefs.getSafeTextColumnDef("rule_name:name") : { targets: "rule_name:name" },
            colDefs.getSafeTextColumnDef ? colDefs.getSafeTextColumnDef("matched_at:name") : { targets: "matched_at:name" },
            colDefs.getSafeTextColumnDef ? colDefs.getSafeTextColumnDef("source:name") : { targets: "source:name" },
            colDefs.getSafeTextColumnDef ? colDefs.getSafeTextColumnDef("value:name") : { targets: "value:name" },
            colDefs.getSafeTextColumnDef
              ? colDefs.getSafeTextColumnDef("discovered_date:name")
              : { targets: "discovered_date:name" },
            { targets: "action:name", render: function () { return ""; } },
          ],
        }),
      );
      $("#reload_secrets_table_btn")
        .off("click")
        .on("click", function () {
          if (secretTable && secretTable.ajax) {
            secretTable.ajax.reload();
          }
        });
    });
  };
})(window);
