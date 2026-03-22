/**
 * Delegated click handlers for the scan detail IP DataTable (subtask launch, unlink from scan).
 * Loaded on detail_scan; requires jQuery, Swal/swal (via window.fireSweetAlert / window.closeSwalOverlays in custom.js),
 * getCookie, Snackbar, RENGINE_DATATABLE_ACTION_URLS.
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

  function getUnlinkTargetIpsUrl() {
    var urls = window.RENGINE_DATATABLE_ACTION_URLS;
    if (urls && urls.ip && urls.ip.unlinkTargetIps) {
      return urls.ip.unlinkTargetIps;
    }
    return "/api/action/target/unlink_ips/";
  }

  function hasSweetAlertFire() {
    return (
      (window.swal && typeof window.swal.fire === "function") ||
      (window.Swal && typeof window.Swal.fire === "function")
    );
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
      if (!hasSweetAlertFire()) {
        if (window.console && typeof window.console.error === "function") {
          window.console.error("attachRengineIpScanTableHandlers: Swal not available");
        }
        return;
      }
      var confirmPromise = window.fireSweetAlert({
        showCancelButton: true,
        title: "Remove IP from scan",
        text:
          "This removes the IP from subdomains in this scan. It does not delete the IP globally if still linked elsewhere.",
        icon: "warning",
        confirmButtonText: "Remove",
      });
      if (!confirmPromise || typeof confirmPromise.then !== "function") {
        return;
      }
      confirmPromise.then(function (result) {
        if (!result.isConfirmed) {
          return;
        }
        window.fireSweetAlert({ title: "Removing...", allowOutsideClick: false });
        if (window.swal && typeof window.swal.showLoading === "function") {
          window.swal.showLoading();
        } else if (window.Swal && typeof window.Swal.showLoading === "function") {
          window.Swal.showLoading();
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
            window.closeSwalOverlays();
            if (res.ok && res.body && res.body.status) {
              $(row).closest("tr").remove();
              if (window.Snackbar && typeof window.Snackbar.show === "function") {
                window.Snackbar.show({ text: "IP removed from scan", pos: "top-right", duration: 2500 });
              }
              if (window.ipTable && typeof window.ipTable.ajax === "object") {
                window.ipTable.ajax.reload();
              }
            } else {
              window.fireSweetAlert({ title: "Could not remove IP", icon: "error" });
            }
          })
          .catch(function (err) {
            window.closeSwalOverlays();
            if (window.console && typeof window.console.error === "function") {
              window.console.error("unlink IP from scan failed", err);
            }
            window.fireSweetAlert({
              title: "Could not remove IP",
              text: "Network or server error.",
              icon: "error",
            });
          });
      });
      $('a[data-toggle="tooltip"]').tooltip("hide");
    });

    $c.on("click", ".btn-delete-target-ip", function () {
      var ip_id = $(this).attr("data-ip-id");
      var target_id = $(this).attr("data-target-id");
      var row = this;
      var unlinkUrl = getUnlinkTargetIpsUrl();
      if (!hasSweetAlertFire()) {
        if (window.console && typeof window.console.error === "function") {
          window.console.error("attachRengineIpScanTableHandlers: Swal not available");
        }
        return;
      }
      var targetConfirmPromise = window.fireSweetAlert({
        showCancelButton: true,
        title: "Remove IP from target",
        text:
          "This removes the IP from all subdomains across every scan of this target, clears it on endpoints that have a subdomain host, and deletes IP-only endpoints. It does not delete the IP record if still linked elsewhere.",
        icon: "warning",
        confirmButtonText: "Remove",
      });
      if (!targetConfirmPromise || typeof targetConfirmPromise.then !== "function") {
        return;
      }
      targetConfirmPromise.then(function (result) {
        if (!result.isConfirmed) {
          return;
        }
        window.fireSweetAlert({ title: "Removing...", allowOutsideClick: false });
        if (window.swal && typeof window.swal.showLoading === "function") {
          window.swal.showLoading();
        } else if (window.Swal && typeof window.Swal.showLoading === "function") {
          window.Swal.showLoading();
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
            target_id: parseInt(target_id, 10),
          }),
        })
          .then(function (r) {
            return r.json().then(function (body) {
              return { ok: r.ok, body: body };
            });
          })
          .then(function (res) {
            window.closeSwalOverlays();
            if (res.ok && res.body && res.body.status) {
              $(row).closest("tr").remove();
              if (window.Snackbar && typeof window.Snackbar.show === "function") {
                window.Snackbar.show({ text: "IP removed from target", pos: "top-right", duration: 2500 });
              }
              if (window.ipTable && typeof window.ipTable.ajax === "object") {
                window.ipTable.ajax.reload();
              }
            } else {
              window.fireSweetAlert({ title: "Could not remove IP", icon: "error" });
            }
          })
          .catch(function (err) {
            window.closeSwalOverlays();
            if (window.console && typeof window.console.error === "function") {
              window.console.error("unlink IP from target failed", err);
            }
            window.fireSweetAlert({
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
