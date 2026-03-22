/**
 * Directories DataTable for scan detail (dir_file_fuzz task).
 * Requires htmlEncode, getRengineDatatableDrawCallbackTooltips, initServerSideDataTable, getRengineDatatableConfig.
 */
(function (window) {
  "use strict";

  /**
   * @typedef {Object} ScanDetailDirectoryTableConfig
   * @property {string} ajaxUrl full subdomain-datatable-list URL with only_directory
   * @property {string} [tabSelector]
   * @property {string} [tableSelector]
   */

  /**
   * @param {ScanDetailDirectoryTableConfig} config
   */
  window.registerScanDetailDirectoryTab = function (config) {
    const $ = window.jQuery;
    if (!$ || !config || !config.ajaxUrl) {
      return;
    }
    const tabSelector = config.tabSelector || "#pills-directories-tab";
    const tableSelector = config.tableSelector || "#directories-table";

    $(tabSelector).on("click", function () {
      const interestingKeywordsArray = [];
      const directoryTableColumns = [
        { data: "id", name: "id" },
        { data: "name", name: "name" },
        { data: "http_status", name: "http_status" },
        { data: "page_title", name: "page_title" },
        { data: "directories", name: "directories" },
        { data: "http_url", name: "http_url" },
        { data: "is_interesting", name: "is_interesting" },
      ];
      const directoryTableOrder = window.getRengineDatatableOrderFromNames
        ? window.getRengineDatatableOrderFromNames(directoryTableColumns, [["http_url", "desc"]])
        : [[5, "desc"]];

      window.initServerSideDataTable(
        tableSelector,
        window.getRengineDatatableConfig(tableSelector, {
          destroy: true,
          scrollY: "50vh",
          ajax: { url: config.ajaxUrl },
          order: directoryTableOrder,
          columns: directoryTableColumns,
          columnDefs: [
            {
              targets: ["http_url:name", "is_interesting:name"],
              visible: false,
              searchable: false,
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
                let interestingBadge = "";
                if (row.http_url) {
                  if (row.is_interesting) {
                    interestingBadge =
                      "<span class='me-1 badge badge-pills badge-soft-danger ms-1' data-toggle=\"tooltip\" data-placement=\"top\" title=\"Interesting Subdomain\">Interesting</span>";
                  }
                  return (
                    '<a href="' +
                    row.http_url +
                    '" class="text-primary" target="_blank">' +
                    data +
                    "</a>" +
                    interestingBadge +
                    "<br>"
                  );
                }
                return (
                  '<a href="https://' +
                  data +
                  '" class="text-primary" target="_blank">' +
                  data +
                  "</a>" +
                  interestingBadge
                );
              },
              targets: "name:name",
            },
            {
              render: function (data) {
                if (data >= 200 && data < 300) {
                  return "<span class='badge badge-pills badge-soft-success'>" + data + "</span>";
                }
                if (data >= 300 && data < 400) {
                  return "<span class='badge badge-pills badge-soft-warning'>" + data + "</span>";
                }
                if (data === 0) {
                  return "";
                }
                return "<span class='badge badge-pills badge-soft-danger'>" + data + "</span>";
              },
              targets: "http_status:name",
            },
            {
              render: function (data) {
                if (data && typeof window.htmlEncode === "function") {
                  return window.htmlEncode(data);
                }
                return data || "";
              },
              targets: "page_title:name",
            },
            {
              render: function (data) {
                if (data) {
                  const reversed = data.reverse();
                  let htmlTreeview = "";
                  if (reversed.length > 1) {
                    htmlTreeview +=
                      '<p class="text-dark">Directory Scan has been performed ' + reversed.length + " times.</p>";
                  }
                  htmlTreeview += '<ul class="list-unstyled">';
                  let itemPos = 0;
                  reversed.forEach(function (item) {
                    let ariaExpanded = "false";
                    let show = "";
                    if (itemPos === 0) {
                      ariaExpanded = "true";
                      show = "hide";
                    }
                    if (item.directory_files.length === 0) {
                      htmlTreeview +=
                        '<li class="mt-1"><span class="text-muted"><i class="fe-folder"></i> No Directories Discovered during the Scan Performed on ' +
                        item.scanned_date +
                        "</span></li>";
                      htmlTreeview +=
                        '<div class="ml-2 collapse ' + show + '" id="dir_' + item.formatted_date_for_id + "_" + item.id + '">';
                    } else {
                      htmlTreeview +=
                        '<li class="mt-1"><a data-bs-toggle="collapse" href="#dir_' +
                        item.formatted_date_for_id +
                        "_" +
                        item.id +
                        '" aria-expanded="' +
                        ariaExpanded +
                        '" aria-controls="dir_' +
                        item.formatted_date_for_id +
                        "_" +
                        item.id +
                        '"><i class="fe-folder-plus"></i> <span class="me-1 badge badge-soft-primary badge-link bs-tooltip" title="Directories">' +
                        item.directory_files.length +
                        ' <i class="far fa-folder"></i></span> found on ' +
                        item.scanned_date +
                        "</a></li>";
                      htmlTreeview +=
                        '<div class="ml-2 collapse ' + show + '" id="dir_' + item.formatted_date_for_id + "_" + item.id + '">';
                      item.directory_files.forEach(function (file) {
                        let interestingBadgeInner = "";
                        interestingKeywordsArray.forEach(function (keyword) {
                          if (file.name.includes(keyword)) {
                            interestingBadgeInner =
                              '<span class="badge badge-soft-danger ms-1 me-1" data-toggle="tooltip" data-placement="top" title="Interesting Directory">Interesting</span>';
                          }
                        });
                        let httpStatusBadge = "";
                        if (file.http_status >= 200 && file.http_status < 300) {
                          httpStatusBadge =
                            "<span class='badge badge-pills badge-soft-success' data-toggle=\"tooltip\" data-placement=\"top\" title=\"HTTP Status\">" +
                            file.http_status +
                            "</span>";
                        } else if (file.http_status >= 300 && file.http_status < 400) {
                          httpStatusBadge =
                            "<span class='badge badge-pills badge-soft-warning' data-toggle=\"tooltip\" data-placement=\"top\" title=\"HTTP Status\">" +
                            file.http_status +
                            "</span>";
                        } else {
                          httpStatusBadge =
                            "<span class='badge badge-pills badge-soft-danger' data-toggle=\"tooltip\" data-placement=\"top\" title=\"HTTP Status\">" +
                            file.http_status +
                            "</span>";
                        }
                        const httpUrl = file.url;
                        let linesWordContent = "";
                        if (file.lines) {
                          linesWordContent += file.lines + " Lines";
                        }
                        if (file.words) {
                          linesWordContent += " " + file.words + " Words";
                        }
                        let linesWordBadge = "";
                        if (linesWordContent.length > 1) {
                          linesWordBadge =
                            '<span class="badge badge-soft-secondary" data-toggle="tooltip" data-placement="top" title="Response Content Status">' +
                            linesWordContent +
                            "</span>";
                        }
                        const enc = window.htmlEncode || function (s) { return s; };
                        htmlTreeview +=
                          '<li class="mt-1"><a href="' +
                          enc(httpUrl) +
                          '" target="_blank">' +
                          enc(atob(file.name)) +
                          " (" +
                          file.length / 100 +
                          ' Kb) <span class="badge badge-soft-primary" data-toggle="tooltip" data-placement="top" title="Content Type">(' +
                          enc(file.content_type) +
                          ")</span> " +
                          httpStatusBadge +
                          "</a>" +
                          interestingBadgeInner +
                          " " +
                          linesWordBadge +
                          "</li>";
                      });
                    }
                    itemPos++;
                    htmlTreeview += "</div>";
                  });
                  htmlTreeview += "</ul>";
                  return htmlTreeview;
                }
                return "";
              },
              targets: "directories:name",
            },
          ],
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
          },
          preDrawCallback: function () {
            return fetch("/api/listInterestingKeywords")
              .then(function (response) {
                return response.json();
              })
              .then(function (data) {
                interestingKeywordsArray.length = 0;
                if (data && Array.isArray(data)) {
                  for (let i = 0; i < data.length; i++) {
                    interestingKeywordsArray.push(data[i]);
                  }
                }
              });
          },
          initComplete: function () {},
          createdRow: function (row, data) {
            if (typeof window.rengineApplyImportantRowHighlight === "function") {
              window.rengineApplyImportantRowHighlight(row, data);
            }
          },
          rowCallback: function () {},
        }),
      );
    });
  };
})(window);
