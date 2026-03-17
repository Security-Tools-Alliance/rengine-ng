/**
 * DataTables action column renderers (subdomain, vulnerability, target) and confirmDeleteRow, renderScanSummaryBadges.
 */
(function (window) {
  "use strict";

  const safeAttr = window.safeAttr;
  const safeText = window.safeText;

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
    const id = row.id;
    const addNoteHtml = useInlineNote
      ? `<button type="button" class="btn btn-sm btn-soft-primary js-add-note-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Add Recon To-do/Note" data-subdomain-id="${id}" data-subdomain-name="${safeName}"><i class="fe-file-plus"></i></button>`
      : `<a href="javascript:;" class="btn btn-sm btn-soft-primary bs-tooltip" data-toggle="tooltip" data-placement="top" title="Add Recon To-do/Note" onclick="add_note_for_subdomain(${id}, '${safeName}', '${safeAttr(projectSlug)}')"><i class="fe-file-plus"></i></a>`;
    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-center mb-2">' +
      `<a href="javascript:;" class="btn btn-sm btn-soft-primary bs-tooltip" data-toggle="tooltip" data-placement="top" title="Show Attack Surface" onclick="show_attack_surface_modal('${safeAttr(urls.attackSurface || "")}', ${id})"><i class="fe-eye"></i></a>` +
      `<button type="button" class="btn btn-sm btn-soft-primary btn-scan-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Further Scan Subdomain" id="${id}"><i class="fe-zap"></i></button>` +
      addNoteHtml +
      `<a href="javascript:;" class="btn btn-sm btn-soft-warning bs-tooltip" data-toggle="tooltip" data-placement="top" title="Mark Important Subdomain" onclick="mark_important_subdomain('${safeAttr(urls.toggleSubdomain || "")}', this, ${id})" id="${id}"><i class="mdi mdi-alert-rhombus-outline"></i></a>` +
      `<a href="javascript:;" class="btn btn-sm btn-soft-danger btn-delete-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Delete Subdomain" id="${id}"><i class="fe-trash-2"></i></a>` +
      "</div>"
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
      `<a href="#" class="btn btn-sm btn-soft-danger btn-delete-vulnerability" id="${id}" data-url="${safeAttr(urls.deleteVulnerability || "")}" data-toggle="tooltip" data-placement="top" title="Delete Vulnerability"><i class="fe-trash-2"></i></a>` +
      "</div>"
    );
  };

  const renderTargetActions = function (row, options) {
    const urls = options && options.urls ? options.urls : {};
    const showFullActions = options && options.showFullActions;
    const id = row.id;
    const targetSummaryUrl = (urls.targetSummaryBase || "") + id;
    const startScanUrl = (urls.startScanBase || "") + id;
    const scheduleScanUrl = (urls.scheduleScanBase || "") + id;
    const updateTargetUrl = (urls.updateTargetBase || "") + id;
    const deleteTargetUrl = (urls.deleteTargetBase || "") + id;
    const safeName = safeAttr(row.name || "");
    if (showFullActions) {
      return (
        '<div class="d-flex flex-wrap gap-1 justify-content-end">' +
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
    const sec = n(opts.secretCount);
    const expl = n(opts.exploitCount);
    const vulnTitleRaw = opts.vulnTooltip != null && opts.vulnTooltip !== "" ? String(opts.vulnTooltip) : "Vulnerabilities";
    const vulnTitle = safeAttr(vulnTitleRaw);
    const secretBadge = '<span class="badge badge-pills badge-soft-warning mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Secrets"><i class="fe-lock me-1"></i>' + sec + '</span> ';
    const exploitBadge = '<span class="badge badge-pills badge-soft-danger mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Exploits"><i class="fe-crosshair me-1"></i>' + expl + '</span> ';
    return (
      '<span class="badge badge-pills bg-secondary mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Domains"><i class="fe-globe me-1"></i>' + d + '</span> ' +
      '<span class="badge badge-pills bg-info mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Subdomains"><i class="fe-layers me-1"></i>' + s + '</span> ' +
      '<span class="badge badge-pills bg-warning mt-1 me-1" data-toggle="tooltip" data-placement="top" title="Endpoints"><i class="fe-link me-1"></i>' + e + '</span> ' +
      '<span class="badge badge-pills bg-danger mt-1 me-1" data-toggle="tooltip" data-placement="top" title="' + vulnTitle + '"><i class="fe-alert-triangle me-1"></i>' + v + "</span> " +
      secretBadge +
      exploitBadge
    );
  };

  window.confirmDeleteRow = confirmDeleteRow;
  window.renderScanSummaryBadges = renderScanSummaryBadges;
  window.RengineDatatableActionRenderers = {
    renderSubdomainActions: renderSubdomainActions,
    renderVulnerabilityActions: renderVulnerabilityActions,
    renderTargetActions: renderTargetActions,
  };
})(window);
