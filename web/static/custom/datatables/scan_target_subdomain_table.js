/**
 * Lazy subdomain DataTable for scan detail and target summary.
 * Requires jQuery, DataTables, initServerSideDataTable, getRengineDatatableConfig,
 * parse_technology, renderBadge, get_response_time_text, mainCheckBoxSelected,
 * toggleMultipleSubdomainButton, getCookie, escape helpers, RengineDatatableColumnDefs, etc.
 */
(function (window) {
  "use strict";

  let subdomainImportantOnlyActive = false;
  let savedSubdomainSearchBeforeImportant = "";

  /**
   * @typedef {Object} ScanTargetSubdomainUrls
   * @property {string} querySubdomains
   * @property {string} endpointsList
   * @property {string} vulnerabilitiesList
   * @property {string} directoriesList
   * @property {string} listSubScans
   * @property {string} getIpDetails
   * @property {string} listIPs
   */

  /**
   * @typedef {Object} ScanTargetSubdomainTableConfig
   * @property {'scan'|'target'} mode
   * @property {string} [tableSelector]
   * @property {string} ajaxUrl
   * @property {string} projectSlug
   * @property {Array} columns
   * @property {Array} lengthMenu
   * @property {number|string} nameColumnTarget
   * @property {boolean} useInlineNote
   * @property {ScanTargetSubdomainUrls} urls
   * @property {number|null} [scanHistoryId]
   * @property {number|null} [endpointModalScanId]
   * @property {number|null} [certificateScanId]
   * @property {number|null} [targetId]
   * @property {boolean} [hasScreenshots]
   * @property {boolean} [registerAdvancedSearch]
   * @property {boolean} [clearSubtaskIpOnSubscan]
   * @property {number} [deleteRemoveParentDepth] jQuery .parent() chain length before .remove()
   * @property {string} [swalDeleteFailIcon]
   */

  /**
   * @param {ScanTargetSubdomainTableConfig} cfg
   * @returns {Array<object>}
   */
  function buildSubdomainColumnDefs(cfg) {
    const urls = cfg.urls;
    const mode = cfg.mode;
    const projectSlug = cfg.projectSlug;
    const scanHistoryId = cfg.scanHistoryId != null ? cfg.scanHistoryId : null;
    const endpointModalScanId = cfg.endpointModalScanId != null ? cfg.endpointModalScanId : null;
    const certificateScanId = cfg.certificateScanId != null ? cfg.certificateScanId : null;
    const targetId = cfg.targetId != null ? cfg.targetId : null;
    const useInlineNote = !!cfg.useInlineNote;
    const nameTarget = cfg.nameColumnTarget;

    function readDomainIdFromDom() {
      const el = document.getElementById("subscan_domain_id");
      if (!el || !el.value) return null;
      const n = parseInt(el.value, 10);
      return Number.isNaN(n) ? null : n;
    }

    function parseTechnologyForRow(row) {
      if (typeof window.parse_technology !== "function") return "";
      const domainId = mode === "scan" ? readDomainIdFromDom() : null;
      return (
        '<div>' +
        window.parse_technology(urls.querySubdomains, row.technologies, "primary", scanHistoryId, domainId) +
        "</div>"
      );
    }

    return [
      {
        orderable: false,
        targets: ["endpoint_count:name", "ports:name", "ip_addresses:name", "content_length:name"],
      },
      {
        targets: [
          "endpoint_count:name",
          "ports:name",
          "technologies:name",
          "http_url:name",
          "cname:name",
          "is_interesting:name",
          "info_count:name",
          "low_count:name",
          "medium_count:name",
          "high_count:name",
          "critical_count:name",
          "todos_count:name",
          "webserver:name",
          "content_type:name",
          "directories_count:name",
          "subscan_count:name",
          "waf:name",
          "attack_surface:name",
          "verified:name",
          "sources:name",
        ],
        visible: false,
        searchable: false,
      },
      {
        targets: ["technologies:name", "cname:name", "is_important:name", "webserver:name", "content_type:name"],
        visible: false,
        searchable: true,
      },
      {
        className: "text-center",
        targets: ["endpoint_count:name", "ports:name", "http_status:name", "content_length:name", "response_time:name"],
      },
      {
        targets: "id:name",
        width: "20px",
        orderable: false,
        render: function (e) {
          return (
            '<div class="form-check ms-1 form-check-primary"><input type="checkbox" name="subdomain_checkbox[' +
            e +
            ']" class="float-start form-check-input subdomain_checkbox" value="' +
            e +
            '" onchange=toggleMultipleSubdomainButton()>\n<span class="new-control-indicator"></span><span style="visibility:hidden">c</span></div>'
          );
        },
      },
      {
        render: function (data, type, row) {
          let badges = "";
          let techBadge = "";
          let interestingBadge = "";
          let contentType = "";
          let webServer = "";
          let wafBadge = "";
          if (row.technologies) {
            techBadge = parseTechnologyForRow(row);
          }
          if (row.is_interesting) {
            interestingBadge =
              "<div><span class='me-1 badge badge-soft-danger' data-toggle=\"tooltip\" data-placement=\"top\" title=\"Interesting Subdomain\">Interesting</span></div>";
          }
          if (row.content_type) {
            const ct = window.safeText ? window.safeText(row.content_type) : row.content_type;
            contentType =
              "<div><span class='mt-1 badge badge-soft-blue bs-tooltip' title=\"Content Type\">" + ct + "</span></div>";
          }
          if (row.webserver) {
            const ws = window.safeText ? window.safeText(row.webserver) : row.webserver;
            webServer =
              "<div><span class='mt-1 badge badge-soft-info bs-tooltip' title=\"Web Server\">" + ws + "</span></div>";
          }
          if (interestingBadge) {
            badges = interestingBadge;
          }
          const todoIcon =
            '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#e7515a" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-file-text"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>';
          let todoBadge = "";
          if (row.todos_count) {
            const sid = window.safeAttr ? window.safeAttr(String(row.id)) : String(row.id);
            const sname = window.safeAttr ? window.safeAttr(row.name) : row.name;
            const tc = window.safeText ? window.safeText(row.todos_count) : row.todos_count;
            todoBadge =
              '<span class="text-danger badge badge-link badge-soft-danger float-end mt-1" onclick="list_subdomain_todos(' +
              sid +
              ", '" +
              sname +
              "')\">" +
              todoIcon +
              "&nbsp;" +
              tc +
              " Todos&nbsp;</span>";
          }
          let endpointCountBadge = "";
          if (row.endpoint_count) {
            const rid = window.safeAttr ? window.safeAttr(String(row.id)) : String(row.id);
            const rname = window.safeAttr ? window.safeAttr(row.name) : row.name;
            const ec = window.safeText ? window.safeText(row.endpoint_count) : row.endpoint_count;
            const epUrl =
              mode === "scan" && window.DETAIL_SCAN_API_ENDPOINTS_LIST
                ? window.DETAIL_SCAN_API_ENDPOINTS_LIST
                : urls.endpointsList;
            endpointCountBadge =
              '<span class="pl-2 pr-2 me-1 badge badge-soft-primary badge-link bs-tooltip" title="Endpoints" onclick="get_endpoint_modal(\'' +
              epUrl +
              "', '" +
              projectSlug +
              "', " +
              (endpointModalScanId != null ? String(endpointModalScanId) : "null") +
              ", " +
              rid +
              ", '" +
              rname +
              "')\">" +
              ec +
              ' <i class=" fas fa-link"></i></span>';
          }
          if (row.waf && row.waf.length) {
            if (mode === "scan") {
              wafBadge =
                '<div><span class="pl-2 pr-2 my-1 badge badge-soft-danger" bs-tooltip" title="WAF Detected by wafw00f!""><i class="fe-cloud-lightning mx-1"></i>WAF Detected</span></div>';
              for (let wi = 0; wi < row.waf.length; wi++) {
                const wafObject = row.waf[wi];
                const wn = wafObject.name || "";
                wafBadge +=
                  '<div><span class="mb-1 badge badge-soft-danger" bs-tooltip">' +
                  (window.safeText ? window.safeText(wafObject.manufacturer) : wafObject.manufacturer) +
                  ": " +
                  (window.safeText ? window.safeText(wn.substring(0, 40) + (wn.length > 40 ? "..." : "")) : wn) +
                  "</span></div>";
              }
            } else {
              wafBadge =
                '<div><span class="pl-2 pr-2 my-1 badge badge-soft-danger" bs-tooltip" title="WAF Detected by wafw00f!""><i class="fe-cloud-lightning mx-1"></i>WAF Detected</span>';
              for (let wi = 0; wi < row.waf.length; wi++) {
                const wafObject = row.waf[wi];
                wafBadge +=
                  '<span class="mx-1 my-1 badge badge-soft-danger" bs-tooltip" title="WAF Manufacturer: ' +
                  (window.safeAttr ? window.safeAttr(wafObject.manufacturer) : wafObject.manufacturer) +
                  '">' +
                  (window.safeText ? window.safeText(wafObject.name) : wafObject.name) +
                  "</span>";
              }
              wafBadge += "</div>";
            }
          }
          let vulnCountBadge = "";
          if (window.RengineDatatableColumnDefs && window.RengineDatatableColumnDefs.getSubdomainVulnCountBadgesHtml) {
            const vulnOpts =
              mode === "scan"
                ? {
                    vulnerabilityListUrl: window.DETAIL_SCAN_API_VULNERABILITIES_LIST || urls.vulnerabilitiesList,
                    scanId: endpointModalScanId,
                  }
                : { vulnerabilityListUrl: urls.vulnerabilitiesList };
            vulnCountBadge = window.RengineDatatableColumnDefs.getSubdomainVulnCountBadgesHtml(row, vulnOpts);
          }
          const copyIcon =
            '<a href="javascript:;" data-clipboard-action="copy" class="action-icon copyable" data-toggle="tooltip" data-placement="top" title="Copy Subdomain!" data-clipboard-target="#subdomain-' +
            row.id +
            '" id="#subdomain-' +
            row.id +
            "\" onclick=\"setTooltip(this.id, 'Copied!')\"> <i class=\"text-primary mdi mdi-content-copy\"></i></a>";
          let directoryCountBadge = "";
          if (row.directories_count) {
            const rid = window.safeAttr ? window.safeAttr(String(row.id)) : String(row.id);
            const rname = window.safeAttr ? window.safeAttr(row.name) : row.name;
            const dc = window.safeText ? window.safeText(row.directories_count) : row.directories_count;
            const dirUrl =
              mode === "scan" && window.DETAIL_SCAN_API_DIRECTORIES_LIST
                ? window.DETAIL_SCAN_API_DIRECTORIES_LIST
                : urls.directoriesList;
            directoryCountBadge =
              '<span class="me-1 badge badge-soft-primary badge-link bs-tooltip" title="Directories" onclick="get_directory_modal(\'' +
              dirUrl +
              "', scan_id=" +
              (endpointModalScanId != null ? String(endpointModalScanId) : "null") +
              ", subdomain_id=" +
              rid +
              ", subdomain_name='" +
              rname +
              "')\">" +
              dc +
              ' <i class="far fa-folder"></i></span>';
          }
          let subscanCountBadge = "";
          if (row.subscan_count) {
            const rid = window.safeAttr ? window.safeAttr(String(row.id)) : String(row.id);
            const rname = window.safeAttr ? window.safeAttr(row.name) : row.name;
            const sc = window.safeText ? window.safeText(row.subscan_count) : row.subscan_count;
            const subUrl =
              mode === "scan" && window.DETAIL_SCAN_API_LIST_SUBSCANS
                ? window.DETAIL_SCAN_API_LIST_SUBSCANS
                : urls.listSubScans;
            subscanCountBadge =
              '<span class="badge me-1 badge-soft-blue badge-link bs-tooltip" title="SubScans" onclick="get_and_render_subscan_history(\'' +
              subUrl +
              "', " +
              rid +
              ", '" +
              rname +
              "')\">" +
              sc +
              ' <i class="fas fa-history"></i></span>';
          }
          let certificateCountBadge = "";
          if (row.certificate_count) {
            const rid = window.safeAttr ? window.safeAttr(String(row.id)) : String(row.id);
            const escapedName = String(row.name).replace(/'/g, "\\'");
            const rnameEsc = window.safeAttr ? window.safeAttr(escapedName) : escapedName;
            const cc = window.safeText ? window.safeText(row.certificate_count) : row.certificate_count;
            const certScanArg = certificateScanId != null ? String(certificateScanId) : "null";
            certificateCountBadge =
              '<span class="me-1 badge badge-soft-secondary badge-link bs-tooltip" title="Certificate(s)" onclick="render_certificate_in_xl_modal(' +
              rid +
              ", '" +
              rnameEsc +
              "', " +
              certScanArg +
              ')\">' +
              cc +
              ' <i class="fas fa-certificate"></i></span>';
          }
          techBadge += contentType;
          techBadge += webServer;
          const endVulnBadge =
            "<div class=\"\">" +
            subscanCountBadge +
            endpointCountBadge +
            directoryCountBadge +
            certificateCountBadge +
            vulnCountBadge +
            "</div>";
          if (row.http_url) {
            if (row.cname) {
              const cnameBadge =
                "<div><span class=\"text-dark\">CNAME<br><span class=\"text-warning\"> ❯ </span>" +
                row.cname.replace(/,/g, "<br><span class=\"text-warning\"> ❯ </span>") +
                "</div>";
              return (
                badges +
                '<div class="clipboard copy-txt"><a href="' +
                row.http_url +
                '" class="text-primary" target="_blank"><span id=\'subdomain-' +
                row.id +
                "'>" +
                data +
                copyIcon +
                " </span></a></div>" +
                cnameBadge +
                wafBadge +
                endVulnBadge +
                techBadge +
                todoBadge
              );
            }
            return (
              badges +
              '<div class="clipboard copy-txt"><a href="' +
              row.http_url +
              '" class="text-primary" target="_blank"><span id=\'subdomain-' +
              row.id +
              "'>" +
              data +
              copyIcon +
              " </span></a></div>" +
              wafBadge +
              endVulnBadge +
              techBadge +
              todoBadge
            );
          }
          return (
            badges +
            '<div class="clipboard copy-txt"><a href="https://' +
            data +
            '" class="text-primary" target="_blank"><span id=\'subdomain-' +
            row.id +
            "'>" +
            data +
            copyIcon +
            " </span></a></div>" +
            wafBadge +
            endVulnBadge +
            techBadge +
            todoBadge
          );
        },
        targets: nameTarget,
      },
      {
        render: function (data, type, row) {
          const sum =
            row.info_count +
            row.low_count +
            row.high_count +
            row.medium_count +
            row.critical_count;
          if (sum > 0) {
            const sid = row.id;
            const sname = row.name;
            const scanArgForVuln =
              endpointModalScanId != null ? String(endpointModalScanId) : "null";
            return (
              "<span class='badge badge-critical bs-tooltip badge-link' title=\"All Vulnerabilities\" onclick=\"get_vulnerability_modal('" +
              urls.vulnerabilitiesList +
              "', scan_id=" +
              scanArgForVuln +
              ", severity=null, subdomain_id=" +
              sid +
              ", subdomain_name='" +
              (window.safeAttr ? window.safeAttr(sname) : sname) +
              "')\">" +
              sum +
              ' <i class="fas fa-bug"></i></span>'
            );
          }
          return "";
        },
        targets: "vuln_count:name",
      },
      {
        render: function (data) {
          if (data >= 200 && data < 300) {
            return "<span class='badge bg-success'>" + data + "</span>";
          }
          if (data >= 300 && data < 400) {
            return "<span class='badge bg-warning'>" + data + "</span>";
          }
          if (data === 0) {
            return "";
          }
          return "<span class='badge bg-danger'>" + data + "</span>";
        },
        targets: "http_status:name",
      },
      {
        render: function (data) {
          if (data) {
            if (mode === "scan" && typeof window.htmlEncode === "function") {
              return window.htmlEncode(data);
            }
            return window.safeText ? window.safeText(data) : data;
          }
          return "";
        },
        targets: "page_title:name",
      },
      {
        render: function (data) {
          let ipBadge = "";
          if (data) {
            const entries = Object.entries(data);
            for (let i = 0; i < entries.length; i++) {
              const value = entries[i][1];
              const addr = value.address;
              const addrJs = window.safeAttr ? window.safeAttr(String(addr)) : String(addr).replace(/'/g, "\\'");
              const argsTail =
                mode === "scan"
                  ? ", " + (scanHistoryId != null ? String(scanHistoryId) : "null") + ")"
                  : ", null, " + (targetId != null ? String(targetId) : "null") + ")";
              if (value.is_cdn) {
                ipBadge +=
                  "<span class='m-1 badge badge-soft-warning badge-link' title=\"CDN IP Address\" onclick=\"get_ip_details('" +
                  urls.getIpDetails +
                  "', '" +
                  urls.querySubdomains +
                  "', '" +
                  addrJs +
                  "'" +
                  argsTail +
                  '">' +
                  addr +
                  "</span>";
              } else {
                ipBadge +=
                  "<span class='m-1 badge badge-soft-primary badge-link' onclick=\"get_ip_details('" +
                  urls.getIpDetails +
                  "', '" +
                  urls.querySubdomains +
                  "', '" +
                  addrJs +
                  "'" +
                  argsTail +
                  '">' +
                  addr +
                  "</span>";
              }
            }
            return ipBadge;
          }
          return "";
        },
        targets: "ip_addresses:name",
      },
      {
        render: function (data, type, row) {
          if (typeof window.renderBadge !== "function") return "";
          return window.renderBadge(data, {
            api_ips_url: urls.listIPs,
            api_subdomains_url: urls.querySubdomains,
            scan_id: scanHistoryId,
            domain_id: mode === "target" ? targetId : null,
            summaryWithPopover: true,
            rowId: row.id,
          });
        },
        targets: "ports:name",
      },
      {
        render: function (data) {
          if (data) {
            return data;
          }
          return 0;
        },
        targets: "content_length:name",
      },
      {
        render: function (data) {
          if (data && typeof window.get_response_time_text === "function") {
            return window.get_response_time_text(data);
          }
          return "";
        },
        targets: "response_time:name",
      },
      {
        render: function (data, type, row) {
          if (window.RengineDatatableActionRenderers && window.RengineDatatableActionRenderers.renderSubdomainActions) {
            return window.RengineDatatableActionRenderers.renderSubdomainActions(row, {
              urls: window.RENGINE_DATATABLE_ACTION_URLS.subdomain,
              projectSlug: projectSlug,
              useInlineNote: useInlineNote,
            });
          }
          return "";
        },
        targets: "action:name",
      },
      {
        render: function (data) {
          if (data === true || data === "true" || data === 1) {
            return "<span class='badge bg-success'>Verified</span>";
          }
          return "<span class='badge bg-secondary'>Not Verified</span>";
        },
        targets: "verified:name",
      },
      {
        render: function (data) {
          if (data && Array.isArray(data) && data.length > 0) {
            return data
              .map(function (source) {
                const t = window.safeText ? window.safeText(source) : source;
                return "<span class='badge badge-soft-info m-1'>" + t + "</span>";
              })
              .join("");
          }
          return "";
        },
        targets: "sources:name",
      },
    ];
  }

  /**
   * @param {ScanTargetSubdomainTableConfig} config
   */
  window.registerScanTargetSubdomainTab = function (config) {
    const $ = window.jQuery;
    if (!$ || !config || !config.ajaxUrl || !config.columns) {
      return;
    }
    const tableSelector = config.tableSelector || "#subdomain_scan_results";
    const mode = config.mode;
    const registerAdvancedSearch = config.registerAdvancedSearch !== false && mode === "scan";
    const clearSubtaskIp = config.clearSubtaskIpOnSubscan !== false && mode === "scan";
    const hasScreenshots = !!config.hasScreenshots;
    const deleteDepth = config.deleteRemoveParentDepth != null ? config.deleteRemoveParentDepth : mode === "scan" ? 4 : 3;
    const swalFailIcon = config.swalDeleteFailIcon || "error";

    $("#pills-subdomain-tab").on("click", function () {
      const DataTableLib = window.DataTable;
      if (mode === "scan") {
        if (DataTableLib && typeof DataTableLib.isDataTable === "function" && DataTableLib.isDataTable(tableSelector)) {
          return false;
        }
      } else if ($.fn.dataTable && $.fn.dataTable.isDataTable(tableSelector)) {
        return false;
      }

      const subdomainScrollerOpts = window.getRengineDatatableScrollerOptions
        ? window.getRengineDatatableScrollerOptions("60vh")
        : {};
      const subdomainLayout = window.getRengineDatatableLayoutFull
        ? window.getRengineDatatableLayoutFull()
        : window.RENGINE_DATATABLE_LAYOUT_FULL;

      const columnDefs = buildSubdomainColumnDefs(config);
      const defaultOrder = window.RENGINE_DATATABLE_SUBDOMAIN_DEFAULT_ORDER || [["content_length", "desc"]];
      const order = window.getRengineDatatableOrderFromNames
        ? window.getRengineDatatableOrderFromNames(config.columns, defaultOrder)
        : [[1, "desc"]];

      const baseOpts = {
        headerCallback: function (e) {
          e.getElementsByTagName("th")[0].innerHTML =
            '<div class="form-check ms-1 form-check-primary"><input type="checkbox" class="float-start form-check-input chk-parent" id="head_checkbox" onclick=mainCheckBoxSelected(this)>\n<span class="new-control-indicator"></span><span style="visibility:hidden">c</span></div>\n';
        },
        destroy: mode === "scan",
        processing: true,
        language:
          mode === "target" && $.fn.DataTable && $.fn.DataTable.defaults
            ? $.extend(true, {}, $.fn.DataTable.defaults.language, { processing: "Fetching Subdomains... Please wait..." })
            : { processing: "Fetching Subdomains... Please wait..." },
        layout: subdomainLayout,
        lengthMenu: config.lengthMenu,
        serverSide: true,
        ajax: {
          url: config.ajaxUrl,
          dataSrc: "data",
        },
        rowGroup: {
          startRender: function (rows, group) {
            return window.safeText(group) + " (" + rows.count() + " Subdomains)";
          },
        },
        order: order,
        columns: config.columns,
        columnDefs: columnDefs,
        initComplete: function () {
          if (window.subdomainDatatableColVisibility) {
            window.subdomainDatatableColVisibility(this.api(), config.columns);
          }
          $(".dtrg-group th:contains('No group')").remove();
        },
        drawCallback: function (settings) {
          window.drawCallback_api = this.api();
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
          $(tableSelector + " .dtrg-group").remove();
          setTimeout(function () {
            $(".dtrg-group th:contains('No group')").remove();
          }, 1);
        },
        rowCallback: function (row, data) {
          if (typeof window.rengineApplyImportantRowHighlight === "function") {
            window.rengineApplyImportantRowHighlight(row, data);
          }
        },
      };

      if (mode === "scan") {
        baseOpts.responsive = true;
        baseOpts.createdRow = function (nRow, aData) {
          $(nRow).attr("id", "subdomain_row_" + aData.id);
        };
      } else {
        baseOpts.stripeClasses = [];
        baseOpts.fnCreatedRow = function (nRow, aData) {
          $(nRow).attr("id", "subdomain_row_" + aData.id);
        };
      }

      const merged = Object.assign({}, baseOpts, subdomainScrollerOpts);
      let subdomainDatatables;
      if (
        mode === "target" &&
        (typeof window.getRengineDatatableConfig !== "function" || typeof window.initServerSideDataTable !== "function")
      ) {
        const fallbackPageLength = window.getRengineDatatablePageLength
          ? window.getRengineDatatablePageLength("subdomain_scan_results")
          : 30;
        subdomainDatatables = $(tableSelector).DataTable(
          Object.assign({}, merged, { pageLength: fallbackPageLength }),
        );
      } else {
        subdomainDatatables = window.initServerSideDataTable(
          tableSelector,
          window.getRengineDatatableConfig(tableSelector, merged),
        );
      }

      if (typeof window.attachRengineDatatableRowGroupSelector === "function") {
        window.attachRengineDatatableRowGroupSelector(subdomainDatatables, {
          selector: 'input[name="grouping_subd_row"]',
          groups: window.RENGINE_DATATABLE_SUBDOMAIN_ROW_GROUP_GROUPS || [],
          defaultOrderWhenDisabled: window.RENGINE_DATATABLE_SUBDOMAIN_DEFAULT_ORDER || [["content_length", "desc"]],
          columns: config.columns,
          snackbarMessage: window.getRengineRowGroupSnackbarMessage(
            "Grouping cleared",
            "Subdomains grouped by {label}",
          ),
        });
      }

      window.subdomain_datatables = subdomainDatatables;
      if (registerAdvancedSearch && window.RengineAdvancedSearch && typeof window.RengineAdvancedSearch.registerDataTable === "function") {
        window.RengineAdvancedSearch.registerDataTable("subdomains", subdomainDatatables);
      } else if (mode === "scan") {
        window.RENGINE_TABLES = window.RENGINE_TABLES || {};
        window.RENGINE_TABLES.subdomains = subdomainDatatables;
      }

      $("#reload_subdomain_table_btn")
        .off("click.subdomainDt")
        .on("click.subdomainDt", function () {
          subdomainDatatables.ajax.reload();
        });

      $("#subdomain-search-button")
        .off("click.subdomainDt")
        .on("click.subdomainDt", function () {
          if (subdomainImportantOnlyActive) {
            subdomainImportantOnlyActive = false;
            $("#load_important_subdomain_table_btn").removeClass("active").attr("aria-pressed", "false");
          }
          subdomainDatatables.search($("#subdomains-search").val()).draw();
        });

      $("#load_important_subdomain_table_btn")
        .off("click.subdomainDt")
        .on("click.subdomainDt", function () {
          const $btn = $(this);
          if (!subdomainImportantOnlyActive) {
            savedSubdomainSearchBeforeImportant = subdomainDatatables.search();
            subdomainImportantOnlyActive = true;
            subdomainDatatables.search("is_important=true").draw();
            $("#subdomains-search").val("");
            $btn.addClass("active").attr("aria-pressed", "true");
          } else {
            subdomainImportantOnlyActive = false;
            subdomainDatatables.search(savedSubdomainSearchBeforeImportant).draw();
            $("#subdomains-search").val(savedSubdomainSearchBeforeImportant);
            $btn.removeClass("active").attr("aria-pressed", "false");
          }
        });

      if (window.subdomainDatatableColVisibility) {
        window.subdomainDatatableColVisibility(subdomainDatatables, config.columns);
      }

      $(tableSelector)
        .off("click.subdomainDt", ".btn-delete-subdomain")
        .on("click.subdomainDt", ".btn-delete-subdomain", function () {
          const subdomainId = $(this).attr("id");
          const payload = { subdomain_ids: [subdomainId] };
          const row = this;
          Swal.fire({
            showCancelButton: true,
            title: "Permanently delete subdomain?",
            text:
              "This permanently removes the subdomain record from the database. Endpoints, vulnerability findings, and other recon data tied to this subdomain are removed as well. The parent domain and target are not deleted. This cannot be undone.",
            icon: "warning",
            confirmButtonText: "Delete",
          }).then(function (result) {
            if (result.isConfirmed) {
              Swal.fire({
                title: "Deleting Subdomain...",
                allowOutsideClick: false,
              });
              swal.showLoading();
              fetch("/api/action/subdomain/delete/", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                  "X-CSRFToken": typeof getCookie === "function" ? getCookie("csrftoken") : window.getCookie && window.getCookie("csrftoken"),
                  "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
              })
                .then(function (response) {
                  return response.json();
                })
                .then(function (response) {
                  swal.close();
                  if (response.status) {
                    let $r = $(row);
                    for (let d = 0; d < deleteDepth; d++) {
                      $r = $r.parent();
                    }
                    $r.remove();
                    Snackbar.show({
                      text: "Subdomain successfully deleted!",
                      pos: "top-right",
                      duration: 2500,
                    });
                  } else {
                    Swal.fire({
                      title: "Could not delete Subdomain!",
                      icon: swalFailIcon,
                    });
                  }
                });
            }
          });
          $('a[data-toggle="tooltip"]').tooltip("hide");
        });

      $(tableSelector)
        .off("click.subdomainDt", ".btn-scan-subdomain")
        .on("click.subdomainDt", ".btn-scan-subdomain", function () {
          $("input[type=checkbox]").prop("checked", false);
          const subdomainId = $(this).attr("id");
          $("#subtask_subdomain_id").val(subdomainId);
          if (clearSubtaskIp) {
            $("#subtask_ip_address_id").val("0");
            $("#subscan-modal").removeData("subscan-ip-label");
          }
          $("#btn-initiate-subtask").attr("multiple-subscan", false);
          $('a[data-toggle="tooltip"]').tooltip("hide");
          if (window.ModalManager) {
            ModalManager.showById(ModalManager.MODAL_IDS.SUBSCAN);
          }
        });

      if (mode === "scan") {
        const column = subdomainDatatables.column("9");
        column.visible(hasScreenshots);
      }
    });
  };
})(window);
