/**
 * DataTables action column renderers (subdomain, IP, vulnerability, target) and confirmDeleteRow, renderScanSummaryBadges.
 * IP row actions: omit optional controls whose URL is missing from RENGINE_DATATABLE_ACTION_URLS.ip; scan/target
 * unlink delete buttons fall back to default API paths when those keys are absent (see renderIpActions).
 */
(function (window) {
  "use strict";

  const safeAttr = window.safeAttr;
  const safeText = window.safeText;

  const LLM_ATTACK_SURFACE_ROW_KIND = {
    subdomain: "subdomain",
    ip: "ip",
    target: "target",
    scope: "scope",
    organization: "organization"
  };

  /**
   * Single-row LLM attack-surface control (same endpoint as subdomain/IP tables; icon: robot).
   * kindKey must be one of: subdomain, ip, target, scope, organization.
   */
  const renderLlmAttackSurfaceRowButton = function (attackUrl, rowId, kindKey) {
    const kind = LLM_ATTACK_SURFACE_ROW_KIND[kindKey];
    if (!attackUrl || !kind || rowId == null || rowId === "") {
      return "";
    }
    const idNum = Number(rowId);
    if (!Number.isFinite(idNum)) {
      return "";
    }
    return (
      `<a href="javascript:;" class="btn btn-sm btn-soft-primary bs-tooltip" data-toggle="tooltip" data-placement="top" title="LLM attack surface" onclick="show_attack_surface_modal('${safeAttr(attackUrl)}', ${idNum}, '${kind}')"><i class="mdi mdi-robot-outline"></i></a>`
    );
  };

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
      if (!result || !result.isConfirmed) return;
      const getCookie = window.getCookie;
      const csrfToken = typeof getCookie === "function" ? getCookie("csrftoken") : "";
      window.fetch(deleteUrl, {
        method: "POST",
        headers: { "X-CSRFToken": csrfToken, "Content-Type": "application/json" },
        body: "{}"
      }).then(function (response) {
        const contentType = response.headers.get("content-type") || "";
        if (!response.ok) {
          if (contentType.indexOf("application/json") !== -1) {
            return response.json().then(function (data) {
              const serverMessage = (data && (data.error || data.detail || data.message)) || null;
              swalFn({ title: "Error", text: serverMessage || errorMessage, icon: "error" });
              return Promise.reject(new Error("Delete request failed with status " + response.status));
            }).catch(function (parseErr) {
              if (window.console && typeof window.console.error === "function") {
                window.console.error("Failed to parse error JSON from delete response:", parseErr);
              }
              swalFn({ title: "Error", text: errorMessage, icon: "error" });
              return Promise.reject(new Error("Delete request failed"));
            });
          }
          swalFn({ title: "Error", text: errorMessage, icon: "error" });
          return Promise.reject(new Error("Delete request failed with status " + response.status));
        }
        if (contentType.indexOf("application/json") !== -1) {
          return response.json().catch(function (parseErr) {
            if (window.console && typeof window.console.warn === "function") {
              window.console.warn("Delete response JSON parse failed; treating as generic success.", parseErr);
            }
            return {};
          });
        }
        return null;
      }).then(function (data) {
        const isSuccess = data !== null && typeof data === "object" && data.status === "true";
        if (!isSuccess) {
          swalFn({ title: "Error", text: errorMessage, icon: "error" });
          return;
        }
        const table = row.closest("table");
        if (table.length && typeof table.DataTable === "function") {
          try { table.DataTable().row(row).remove().draw(); } catch (e) { row.remove(); }
        } else { row.remove(); }
        swalFn({ title: successMessage, icon: "success" });
      }).catch(function (err) {
        if (window.console && typeof window.console.error === "function") {
          window.console.error("Error during delete request:", err);
        }
      });
    });
  };

  const renderSubdomainActions = function (row, options) {
    const urls = options && options.urls ? options.urls : {};
    const projectSlug = (options && options.projectSlug) || "";
    const useInlineNote = options && options.useInlineNote;
    const safeName = safeAttr(row.name || "");
    const id = row && (row.id != null ? row.id : row.pk);
    const addNoteHtml = useInlineNote
      ? `<button type="button" class="btn btn-sm btn-soft-primary js-add-note-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Add Recon To-do/Note" data-subdomain-id="${id}" data-subdomain-name="${safeName}"><i class="fe-file-plus"></i></button>`
      : `<a href="javascript:;" class="btn btn-sm btn-soft-primary bs-tooltip" data-toggle="tooltip" data-placement="top" title="Add Recon To-do/Note" onclick="add_note_for_subdomain(${id}, '${safeName}', '${safeAttr(projectSlug)}')"><i class="fe-file-plus"></i></a>`;
    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-center mb-2">' +
      renderLlmAttackSurfaceRowButton(urls.attackSurface || "", id, "subdomain") +
      `<button type="button" class="btn btn-sm btn-soft-primary btn-scan-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Further Scan Subdomain" id="${id}"><i class="fe-zap"></i></button>` +
      addNoteHtml +
      `<a href="javascript:;" class="btn btn-sm btn-soft-warning bs-tooltip" data-toggle="tooltip" data-placement="top" title="Mark Important Subdomain" onclick="mark_important_subdomain('${safeAttr(urls.toggleSubdomain || "")}', this, ${id})" id="${id}"><i class="mdi mdi-alert-rhombus-outline"></i></a>` +
      `<a href="javascript:;" class="btn btn-sm btn-soft-danger btn-delete-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Permanently delete subdomain and dependent recon data" id="${id}"><i class="fe-trash-2"></i></a>` +
      "</div>"
    );
  };

  const resolveIpAddressRowId = function (row) {
    return row && (row.id != null ? row.id : row.pk);
  };

  const renderIpActions = function (row, options) {
    const urls = (options && options.urls) || {};
    const projectSlug = (options && options.projectSlug) || "";
    const scanHistoryRaw = options && options.scanHistoryId;
    const safeAddress = safeAttr(String((row && row.address) || ""));
    const id = resolveIpAddressRowId(row);
    if (id == null || id === "") {
      return "";
    }
    const scanHistoryNum =
      scanHistoryRaw !== undefined && scanHistoryRaw !== null && scanHistoryRaw !== ""
        ? Number(scanHistoryRaw)
        : NaN;
    const hasValidScanHistory = !Number.isNaN(scanHistoryNum) && scanHistoryNum > 0;
    const domainIdRaw = options && options.domainId;
    const domainIdNum =
      domainIdRaw !== undefined && domainIdRaw !== null && domainIdRaw !== ""
        ? Number(domainIdRaw)
        : NaN;
    const hasValidDomain = !Number.isNaN(domainIdNum) && domainIdNum > 0;
    const unlinkScanUrl = urls.unlinkScanIps || "/api/action/scan/unlink_ips/";
    const unlinkTargetUrl = urls.unlinkTargetIps || "/api/action/target/unlink_ips/";
    const parts = [];
    const asBtn = renderLlmAttackSurfaceRowButton(urls.attackSurface || "", id, "ip");
    if (asBtn) {
      parts.push(asBtn);
    }
    parts.push(
      `<button type="button" class="btn btn-sm btn-soft-primary btn-scan-ip bs-tooltip" data-toggle="tooltip" data-placement="top" title="Further Scan IP" data-ip-address="${safeAddress}" id="${id}"><i class="fe-zap"></i></button>`
    );
    parts.push(
      `<button type="button" class="btn btn-sm btn-soft-primary js-add-note-ip bs-tooltip" data-toggle="tooltip" data-placement="top" title="Add Recon To-do/Note" data-ip-address-id="${id}" data-ip-address="${safeAddress}" data-project-slug="${safeAttr(projectSlug)}"><i class="fe-file-plus"></i></button>`
    );
    if (urls.toggleIpImportant) {
      parts.push(
        `<a href="javascript:;" class="btn btn-sm btn-soft-warning bs-tooltip" data-toggle="tooltip" data-placement="top" title="Mark Important IP" onclick="mark_important_ip('${safeAttr(urls.toggleIpImportant)}', this, ${id})" id="ip-important-${id}"><i class="mdi mdi-alert-rhombus-outline"></i></a>`
      );
    }
    if (hasValidScanHistory && unlinkScanUrl) {
      parts.push(
        `<a href="javascript:;" class="btn btn-sm btn-soft-danger btn-delete-scan-ip bs-tooltip" data-toggle="tooltip" data-placement="top" title="Unlink IP from this scan (does not delete the IP globally)" data-ip-id="${id}" data-scan-history-id="${safeAttr(String(scanHistoryNum))}"><i class="fe-trash-2"></i></a>`
      );
    } else if (hasValidDomain && unlinkTargetUrl) {
      parts.push(
        `<a href="javascript:;" class="btn btn-sm btn-soft-danger btn-delete-target-ip bs-tooltip" data-toggle="tooltip" data-placement="top" title="Remove IP from this target (all scans; does not delete the IP record if still used elsewhere)" data-ip-id="${id}" data-target-id="${safeAttr(String(domainIdNum))}"><i class="fe-trash-2"></i></a>`
      );
    }
    if (!parts.length) {
      return "";
    }
    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-center mb-2">' + parts.join("") + "</div>"
    );
  };

  const renderVulnerabilityActions = function (row, options) {
    if (!(options && options.showActions)) return "";
    const urls = options && options.urls ? options.urls : {};
    const id = row.id;
    const name = safeAttr(row.name || "");
    const severity = safeAttr(row.severity || "");
    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-center mb-2">' +
      `<a href="javascript:fetch_llm_vuln_details('${safeAttr(urls.llmReport || "")}', ${id}, '${name}');" class="btn btn-sm btn-soft-info" data-toggle="tooltip" data-placement="top" title="Fetch LLM Vulnerability Details"><i class="fe-zap"></i></a>` +
      `<a href="javascript:report_hackerone('${safeAttr(urls.hackeroneReport || "")}', ${id}, '${severity}');" class="btn btn-sm btn-soft-primary" data-toggle="tooltip" data-placement="top" title="Report to Hackerone"><i class="fe-share"></i></a>` +
      `<a href="#" class="btn btn-sm btn-soft-danger btn-delete-vulnerability" id="${id}" data-url="${safeAttr(urls.deleteVulnerability || "")}" data-toggle="tooltip" data-placement="top" title="Permanently delete this vulnerability finding only"><i class="fe-trash-2"></i></a>` +
      "</div>"
    );
  };

  const renderTargetActions = function (row, options) {
    const urls = options && options.urls ? options.urls : {};
    const showFullActions = options && options.showFullActions;
    const id = row.id;
    const asBtn = renderLlmAttackSurfaceRowButton(urls.attackSurface || "", id, "target");
    const targetSummaryUrl = (urls.targetSummaryBase || "") + id;
    const startScanUrl = (urls.startScanBase || "") + id;
    const scheduleScanUrl = (urls.scheduleScanBase || "") + id;
    const updateTargetUrl = (urls.updateTargetBase || "") + id;
    const deleteTargetUrl = (urls.deleteTargetBase || "") + id;
    const safeName = safeAttr(row.name || "");
    if (showFullActions) {
      return (
        '<div class="d-flex flex-wrap gap-1 justify-content-end">' +
        asBtn +
        `<a class="btn btn-sm btn-soft-info" href="${safeAttr(targetSummaryUrl)}" data-toggle="tooltip" data-placement="top" title="Target Summary"><i class="fe-info"></i></a>` +
        `<a href="${safeAttr(startScanUrl)}" class="btn btn-sm btn-soft-primary" data-toggle="tooltip" data-placement="top" title="Initiate Scan"><i class="fe-zap"></i></a>` +
        `<a class="btn btn-sm btn-soft-warning" href="${safeAttr(scheduleScanUrl)}" data-toggle="tooltip" data-placement="top" title="Schedule Scan"><i class="fe-clock"></i></a>` +
        `<a class="btn btn-sm btn-soft-secondary" href="${safeAttr(updateTargetUrl)}" data-toggle="tooltip" data-placement="top" title="Edit Target"><i class="fe-edit-2"></i></a>` +
        `<a class="btn btn-sm btn-soft-danger" href="#" data-toggle="tooltip" data-placement="top" title="Delete target" onclick="delete_target('${safeAttr(deleteTargetUrl)}', '${safeName}'); return false;"><i class="fe-trash-2"></i></a>` +
        "</div>"
      );
    }
    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-end">' +
      asBtn +
      `<a class="btn btn-sm btn-soft-info" href="${safeAttr(targetSummaryUrl)}" data-toggle="tooltip" data-placement="top" title="Target Summary"><i class="fe-info"></i></a>` +
      "</div>"
    );
  };

  const renderScanSummaryBadges = function (opts) {
    const n = function (v) { const num = Number(v); return isNaN(num) ? 0 : num; };
    const d = n(opts.domainCount);
    const s = n(opts.subdomainCount);
    const e = n(opts.endpointCount);
    const v = n(opts.vulnerabilityCount);
    const ipTotal = n(opts.ipAddressCount);
    const ipAlive = n(opts.ipAliveCount);
    const sec = n(opts.secretCount);
    const expl = n(opts.exploitCount);
    const vulnTitleRaw = opts.vulnTooltip != null && opts.vulnTooltip !== "" ? String(opts.vulnTooltip) : "Vulnerabilities";
    const vulnTitle = safeAttr(vulnTitleRaw);
    const secretBadge = '<span class="badge badge-pills badge-soft-warning mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Secrets"><i class="fe-lock me-1"></i>' + sec + '</span> ';
    const exploitBadge = '<span class="badge badge-pills badge-soft-danger mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Exploits"><i class="fe-crosshair me-1"></i>' + expl + '</span> ';
    const ipDiscoveredTitle = "IP addresses (distinct)";
    const ipAliveTitle = "Alive IP addresses";
    const ipTotalBadge =
      '<span class="badge badge-pills badge-soft-dark mt-1 me-1" data-toggle="tooltip" data-placement="top" title="' +
      safeAttr(ipDiscoveredTitle) +
      '"><i class="fe-server me-1"></i>' +
      ipTotal +
      "</span> ";
    const ipAliveBadge =
      '<span class="badge badge-pills badge-soft-success mt-1 me-1" data-toggle="tooltip" data-placement="top" title="' +
      safeAttr(ipAliveTitle) +
      '"><i class="fe-check-circle me-1"></i>' +
      ipAlive +
      "</span> ";
    return (
      '<span class="badge badge-pills bg-secondary mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Domains"><i class="fe-globe me-1"></i>' + d + '</span> ' +
      '<span class="badge badge-pills bg-info mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Subdomains"><i class="fe-layers me-1"></i>' + s + '</span> ' +
      '<span class="badge badge-pills bg-warning mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Endpoints"><i class="fe-link me-1"></i>' + e + '</span> ' +
      '<span class="badge badge-pills bg-danger mt-1 me-1" data-toggle="tooltip" data-placement="top" title="' + vulnTitle + '"><i class="fe-alert-triangle me-1"></i>' + v + "</span> " +
      ipTotalBadge +
      ipAliveBadge +
      secretBadge +
      exploitBadge
    );
  };

  window.confirmDeleteRow = confirmDeleteRow;
  window.renderScanSummaryBadges = renderScanSummaryBadges;
  window.RengineDatatableActionRenderers = {
    renderSubdomainActions: renderSubdomainActions,
    renderIpActions: renderIpActions,
    renderVulnerabilityActions: renderVulnerabilityActions,
    renderTargetActions: renderTargetActions,
    renderLlmAttackSurfaceRowButton: renderLlmAttackSurfaceRowButton,
  };
})(window);
