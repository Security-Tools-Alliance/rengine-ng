/**
 * Delegated click handlers for the scan detail IP DataTable (subtask launch, unlink from scan).
 * Loaded on detail_scan; requires jQuery, Swal/swal, getCookie, Snackbar, RENGINE_DATATABLE_ACTION_URLS.
 * Unlink rows are only rendered when ``RENGINE_DATATABLE_ACTION_URLS.ip.unlinkScanIps`` and scanHistoryId exist
 * (see RengineDatatableActionRenderers.renderIpActions in actions.js).
 */
(function (window) {
  "use strict";

  function getUnlinkScanIpsUrl() {
    var urls = window.RENGINE_DATATABLE_ACTION_URLS;
    if (urls && urls.ip && urls.ip.unlinkScanIps) {
      return urls.ip.unlinkScanIps;
    }
    return "/api/action/scan/unlink_ips/";
  }

  /**
   * @param {string} containerSelector jQuery selector for the table wrapper (e.g. #ip_scan_results).
   */
  function closeSwalOverlays() {
    if (window.Swal && typeof window.Swal.close === "function") {
      window.Swal.close();
    }
  }

  window.attachRengineIpScanTableHandlers = function (containerSelector) {
    var $ = window.jQuery;
    if (!$ || !containerSelector) {
      return;
    }
    var $c = $(containerSelector);

    $c.on("click", ".btn-scan-ip", function () {
      $('input[type=checkbox]').prop("checked", false);
      var ip_id = $(this).attr("id");
      var ip_label = $(this).attr("data-ip-address") || "";
      $("#subtask_subdomain_id").val("0");
      $("#subtask_ip_address_id").val(ip_id);
      $("#subscan-modal").data("subscan-ip-label", ip_label);
      $("#btn-initiate-subtask").attr("multiple-subscan", false);
      $('a[data-toggle="tooltip"]').tooltip("hide");
      if (window.ModalManager) {
        ModalManager.showById(ModalManager.MODAL_IDS.SUBSCAN);
      }
    });

    $c.on("click", ".btn-delete-scan-ip", function () {
      var ip_id = $(this).attr("data-ip-id");
      var scan_hist = $(this).attr("data-scan-history-id");
      var row = this;
      var unlinkUrl = getUnlinkScanIpsUrl();
      var SwalFire = window.Swal && typeof window.Swal.fire === "function" ? window.Swal.fire : null;
      if (!SwalFire) {
        if (window.console && typeof window.console.error === "function") {
          window.console.error("attachRengineIpScanTableHandlers: Swal not available");
        }
        return;
      }
      SwalFire({
        showCancelButton: true,
        title: "Remove IP from scan",
        text:
          "This removes the IP from subdomains in this scan. It does not delete the IP globally if still linked elsewhere.",
        icon: "warning",
        confirmButtonText: "Remove",
      }).then(function (result) {
        if (!result.isConfirmed) {
          return;
        }
        SwalFire({ title: "Removing...", allowOutsideClick: false });
        if (window.swal && typeof window.swal.showLoading === "function") {
          window.swal.showLoading();
        }
        fetch(unlinkUrl, {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": typeof getCookie === "function" ? getCookie("csrftoken") : "",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            ip_address_ids: [parseInt(ip_id, 10)],
            scan_history_id: parseInt(scan_hist, 10),
          }),
        })
          .then(function (r) {
            return r.json().then(function (body) {
              return { ok: r.ok, body: body };
            });
          })
          .then(function (res) {
            closeSwalOverlays();
            if (res.ok && res.body && res.body.status) {
              $(row).closest("tr").remove();
              if (window.Snackbar && typeof window.Snackbar.show === "function") {
                window.Snackbar.show({ text: "IP removed from scan", pos: "top-right", duration: 2500 });
              }
              if (window.ipTable && typeof window.ipTable.ajax === "object") {
                window.ipTable.ajax.reload();
              }
            } else {
              SwalFire({ title: "Could not remove IP", icon: "error" });
            }
          })
          .catch(function (err) {
            closeSwalOverlays();
            if (window.console && typeof window.console.error === "function") {
              window.console.error("unlink IP from scan failed", err);
            }
            SwalFire({
              title: "Could not remove IP",
              text: "Network or server error.",
              icon: "error",
            });
          });
      });
      $('a[data-toggle="tooltip"]').tooltip("hide");
    });
  };
})(window);
