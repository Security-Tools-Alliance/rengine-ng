/**
 * Lazy initialization for the scan detail page IP DataTable (detail_scan.html).
 * Requires jQuery, DataTable, initServerSideDataTable, getRengineDatatableConfig,
 * window.rengineApplyImportantRowHighlight (init.js),
 * selection_helpers.js (createRengineDatatableIdSelection), RENGINE_IP_DATATABLE_COLUMNS,
 * RengineDatatableColumnDefs.getScanIpTableColumnDefs, rengineColumnByName (columns.js),
 * and global renderBadge (port_display.js).
 */
(function (window) {
  "use strict";

  /**
   * @typedef {Object} DetailScanIpTableConfig
   * @property {string} [tableSelector]
   * @property {string} ajaxUrl
   * @property {number} scanHistoryId
   * @property {string} projectSlug
   * @property {string} getIpDetailsUrl
   * @property {string} querySubdomainsUrl
   * @property {string} listIPsUrl
   * @property {string} downloadFilename
   */

  /**
   * @param {DetailScanIpTableConfig} config
   * @returns {object|null} DataTables API instance, or null.
   */
  window.initDetailScanIpDataTable = function (config) {
    const $ = window.jQuery;
    const DataTableLib = window.DataTable;
    if (!$ || !config || !config.ajaxUrl) {
      return null;
    }
    const tableSelector = config.tableSelector || "#ip_scan_results";
    if (
      DataTableLib &&
      typeof DataTableLib.isDataTable === "function" &&
      DataTableLib.isDataTable(tableSelector)
    ) {
      return window.ipTable || null;
    }
    const ipColumns = window.RENGINE_IP_DATATABLE_COLUMNS || [];
    const defsFactory =
      window.RengineDatatableColumnDefs && window.RengineDatatableColumnDefs.getScanIpTableColumnDefs;
    if (!defsFactory || typeof window.initServerSideDataTable !== "function") {
      return null;
    }
    const columnDefs = defsFactory({
      getIpDetailsUrl: config.getIpDetailsUrl,
      querySubdomainsUrl: config.querySubdomainsUrl,
      scanHistoryId: config.scanHistoryId,
      listIPsUrl: config.listIPsUrl,
      projectSlug: config.projectSlug,
    });
    const order = window.getRengineDatatableOrderFromNames
      ? window.getRengineDatatableOrderFromNames(
          ipColumns,
          window.RENGINE_DATATABLE_IP_DEFAULT_ORDER || [["address", "asc"]],
        )
      : [[1, "asc"]];

    const ipSel =
      typeof window.createRengineDatatableIdSelection === "function"
        ? window.createRengineDatatableIdSelection({
            countBadgeId: "ip_selected_count",
            disabledWhenEmptyIds: ["download_selected_ips_btn"],
          })
        : null;
    const ipSelection = ipSel ? ipSel.ids : new Set();
    const updateIpSelectionUI = ipSel
      ? function () {
          ipSel.refresh();
        }
      : function () {
          const count = ipSelection.size;
          const countBadge = document.getElementById("ip_selected_count");
          if (countBadge) {
            countBadge.textContent = count > 0 ? count + " selected" : "";
            countBadge.style.display = count > 0 ? "" : "none";
          }
          const downloadBtn = document.getElementById("download_selected_ips_btn");
          if (downloadBtn) {
            downloadBtn.classList.toggle("disabled", count === 0);
          }
        };

    window.uncheckIps = function () {
      if (ipSel) {
        ipSel.clear({ rowCheckboxSelector: ".ip_checkbox", headCheckboxId: "head_ip_checkbox" });
      } else {
        ipSelection.clear();
        document.querySelectorAll(".ip_checkbox").forEach(function (cb) {
          cb.checked = false;
        });
        const head = document.getElementById("head_ip_checkbox");
        if (head) {
          head.checked = false;
        }
        updateIpSelectionUI();
      }
    };

    window.showIpEndpointsByAddress = function (address) {
      const safeAddress = address || "";
      $("#pills-endpoints-tab").trigger("click");
      $("#endpoints-search").val(safeAddress);
      $("#endpoints-search-button").trigger("click");
    };

    window.ipTable = window.initServerSideDataTable(
      tableSelector,
      window.getRengineDatatableConfig(tableSelector, {
        destroy: true,
        responsive: true,
        order: order,
        columns: ipColumns,
        columnDefs: columnDefs,
        createdRow: function (row, data) {
          if (typeof window.rengineApplyImportantRowHighlight === "function") {
            window.rengineApplyImportantRowHighlight(row, data);
          }
        },
        drawCallback: function (settings) {
          if (window.getRengineDatatableDrawCallbackTooltips) {
            const fn = window.getRengineDatatableDrawCallbackTooltips(tableSelector, {
              tooltipTemplate:
                '<div class="tooltip status" role="tooltip"><div class="arrow"></div><div class="tooltip-inner"></div></div>',
            });
            if (typeof fn === "function") {
              fn.call(this, settings);
            }
          }
          if (typeof window.initPortsPopovers === "function") {
            window.initPortsPopovers(tableSelector);
          }
        },
        headerCallback: function (e) {
          e.getElementsByTagName("th")[0].innerHTML =
            '<div class="form-check ms-1 form-check-primary"><input type="checkbox" class="float-start form-check-input" id="head_ip_checkbox"><span class="new-control-indicator"></span><span style="visibility:hidden">c</span></div>';
        },
        serverSide: true,
        ajax: {
          url: config.ajaxUrl,
          dataSrc: "data",
        },
      }),
    );

    if (window.attachRengineIpScanTableHandlers) {
      window.attachRengineIpScanTableHandlers(tableSelector);
    }

    const ipTable = window.ipTable;

    $("#ips-search").on("keyup", function () {
      ipTable.search(this.value).draw();
    });
    $("#ip-search-button").on("click", function () {
      ipTable.search($("#ips-search").val()).draw();
    });
    $("#reload_ip_table_btn").on("click", function () {
      ipTable.ajax.reload();
    });
    $(tableSelector).on("change", ".ip_checkbox", function () {
      const id = Number(this.value);
      if (this.checked) {
        ipSelection.add(id);
      } else {
        ipSelection.delete(id);
      }
      updateIpSelectionUI();
    });
    $(tableSelector).on("change", "#head_ip_checkbox", function () {
      const checked = this.checked;
      document.querySelectorAll(".ip_checkbox").forEach(function (cb) {
        cb.checked = checked;
        const id = Number(cb.value);
        if (checked) {
          ipSelection.add(id);
        } else {
          ipSelection.delete(id);
        }
      });
      updateIpSelectionUI();
    });
    $("#download_selected_ips_btn").on("click", function (e) {
      e.preventDefault();
      if (ipSelection.size === 0) {
        return;
      }
      const rowsById = new Map();
      ipTable
        .rows({ search: "applied" })
        .data()
        .toArray()
        .forEach(function (row) {
          rowsById.set(Number(row.id), row);
        });
      const ips = Array.from(ipSelection)
        .map(function (id) {
          return rowsById.get(id);
        })
        .filter(Boolean)
        .map(function (row) {
          return row.address || "";
        })
        .filter(Boolean);
      if (!ips.length) {
        return;
      }
      const dlFn = window.download;
      if (typeof dlFn === "function") {
        dlFn(config.downloadFilename || "selected-ips.txt", ips.join("\n"));
      }
    });

    const rowGroupCols = ipColumns.map(function (c) {
      return { name: c.name };
    });
    if (window.attachRengineDatatableRowGroupSelector) {
      window.attachRengineDatatableRowGroupSelector(ipTable, {
        selector: 'input[name="grouping_ip_row"]',
        groups: window.RENGINE_DATATABLE_IP_ROW_GROUP_GROUPS || [],
        defaultOrderWhenDisabled: window.RENGINE_DATATABLE_IP_DEFAULT_ORDER || [["address", "asc"]],
        columns: rowGroupCols,
        snackbarMessage:
          typeof window.getRengineRowGroupSnackbarMessage === "function"
            ? window.getRengineRowGroupSnackbarMessage("Grouping cleared", "IPs grouped by {label}")
            : undefined,
      });
    }
    if (window.RengineAdvancedSearch && typeof window.RengineAdvancedSearch.registerDataTable === "function") {
      window.RengineAdvancedSearch.registerDataTable("ips", ipTable);
    }

    const colByName = function (name) {
      return window.rengineColumnByName ? window.rengineColumnByName(ipTable, name, ipColumns) : null;
    };
    $("input[name=ip_subdomains_filter_checkbox]").on("change", function () {
      const c = colByName("subdomain_names");
      if (c) {
        c.visible($(this).is(":checked"));
      }
    });
    $("input[name=ip_ports_filter_checkbox]").on("change", function () {
      const c = colByName("ports");
      if (c) {
        c.visible($(this).is(":checked"));
      }
    });
    $("input[name=ip_alive_filter_checkbox]").on("change", function () {
      const c = colByName("alive");
      if (c) {
        c.visible($(this).is(":checked"));
      }
    });
    $("input[name=ip_cdn_filter_checkbox]").on("change", function () {
      const c = colByName("is_cdn");
      if (c) {
        c.visible($(this).is(":checked"));
      }
    });

    return ipTable;
  };
})(window);
