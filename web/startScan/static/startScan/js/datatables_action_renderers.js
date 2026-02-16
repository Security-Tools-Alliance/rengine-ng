/**
 * Centralized DataTables action column renderers.
 * Used by subdomain, vulnerability, and target tables (ajax). URLs are injected by templates.
 */
(function (window) {
  "use strict";

  const escapeAttr = function (s) {
    if (s == null) return "";
    const str = String(s);
    return str
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  };

  const htmlEncode = function (s) {
    return typeof window.htmlEncode === "function" ? window.htmlEncode(s) : escapeAttr(s);
  };

  /**
   * Renders subdomain action buttons (flat list, no dropdown).
   * @param {Object} row - DataTables row (id, name, http_url, http_status).
   * @param {Object} options - { urls: { attackSurface, toggleSubdomain, cmsDetector }, projectSlug, useInlineNote }.
   * @returns {string} HTML for the action cell.
   */
  const renderSubdomainActions = function (row, options) {
    const urls = options && options.urls ? options.urls : {};
    const projectSlug = (options && options.projectSlug) || "";
    const useInlineNote = options && options.useInlineNote;
    const cmsDetectorHttpUrl = row.http_url || "https://" + (row.name || "");
    const safeName = escapeAttr(row.name || "");
    const id = row.id;

    const addNoteHtml = useInlineNote
      ? `<button type="button" class="btn btn-sm btn-soft-primary js-add-note-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Add Recon To-do/Note" data-subdomain-id="${id}" data-subdomain-name="${safeName}"><i class="fe-file-plus"></i></button>`
      : `<a href="javascript:;" class="btn btn-sm btn-soft-primary bs-tooltip" data-toggle="tooltip" data-placement="top" title="Add Recon To-do/Note" onclick="add_note_for_subdomain(${id}, '${safeName}', '${escapeAttr(projectSlug)}')"><i class="fe-file-plus"></i></a>`;

    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-center mb-2">' +
      `<a href="javascript:;" class="btn btn-sm btn-soft-primary bs-tooltip" data-toggle="tooltip" data-placement="top" title="Show Attack Surface" onclick="show_attack_surface_modal('${escapeAttr(urls.attackSurface || "")}', ${id})"><i class="fe-eye"></i></a>` +
      `<button type="button" class="btn btn-sm btn-soft-primary btn-scan-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Further Scan Subdomain" id="${id}"><i class="fe-zap"></i></button>` +
      addNoteHtml +
      `<a href="javascript:;" class="btn btn-sm btn-soft-warning bs-tooltip" data-toggle="tooltip" data-placement="top" title="Mark Important Subdomain" onclick="mark_important_subdomain('${escapeAttr(urls.toggleSubdomain || "")}', this, ${id})" id="${id}"><i class="mdi mdi-alert-rhombus-outline"></i></a>` +
      `<a href="javascript:;" class="btn btn-sm btn-soft-info detect_subdomain_cms_link bs-tooltip" data-toggle="tooltip" data-placement="top" title="Detect CMS" data-http-status="${escapeAttr(row.http_status)}" data-cms-url="${escapeAttr(cmsDetectorHttpUrl)}" data-url="${escapeAttr(urls.cmsDetector || "")}"><i class="fe-grid"></i></a>` +
      `<a href="javascript:;" class="btn btn-sm btn-soft-danger btn-delete-subdomain bs-tooltip" data-toggle="tooltip" data-placement="top" title="Delete Subdomain" id="${id}"><i class="fe-trash-2"></i></a>` +
      "</div>"
    );
  };

  /**
   * Renders vulnerability action buttons when vulnerability has no report (open).
   * @param {Object} row - DataTables row (id, name, severity).
   * @param {Object} options - { urls: { llmReport, hackeroneReport, deleteVulnerability }, showActions } (showActions: true when action column value is falsy).
   * @returns {string} HTML for the action cell or empty string when showActions is false.
   */
  const renderVulnerabilityActions = function (row, options) {
    if (!(options && options.showActions)) return "";
    const urls = options && options.urls ? options.urls : {};
    const id = row.id;
    const name = htmlEncode(row.name || "");
    const severity = htmlEncode(row.severity || "");

    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-center mb-2">' +
      `<a href="javascript:fetch_llm_vuln_details('${escapeAttr(urls.llmReport || "")}', ${id}, '${name}');" class="btn btn-sm btn-soft-info" data-toggle="tooltip" data-placement="top" title="Fetch LLM Vulnerability Details"><i class="fe-zap"></i></a>` +
      `<a href="javascript:report_hackerone('${escapeAttr(urls.hackeroneReport || "")}', ${id}, '${severity}');" class="btn btn-sm btn-soft-primary" data-toggle="tooltip" data-placement="top" title="Report to Hackerone"><i class="fe-share"></i></a>` +
      `<a href="#" class="btn btn-sm btn-soft-danger btn-delete-vulnerability" id="${id}" data-url="${escapeAttr(urls.deleteVulnerability || "")}" data-toggle="tooltip" data-placement="top" title="Delete Vulnerability"><i class="fe-trash-2"></i></a>` +
      "</div>"
    );
  };

  /**
   * Renders target (domain) action buttons. When showFullActions is false, only Target Summary is shown.
   * @param {Object} row - DataTables row (id, name).
   * @param {Object} options - { urls: { targetSummary, startScan, scheduleScan, updateTarget, deleteTarget }, showFullActions }.
   * @returns {string} HTML for the action cell.
   */
  const renderTargetActions = function (row, options) {
    const urls = options && options.urls ? options.urls : {};
    const showFullActions = options && options.showFullActions;
    const id = row.id;
    const targetSummaryUrl = (urls.targetSummaryBase || "") + id;
    const startScanUrl = (urls.startScanBase || "") + id;
    const scheduleScanUrl = (urls.scheduleScanBase || "") + id;
    const updateTargetUrl = (urls.updateTargetBase || "") + id;
    const deleteTargetUrl = (urls.deleteTargetBase || "") + id;
    const safeName = htmlEncode(row.name || "");

    if (showFullActions) {
      return (
        '<div class="d-flex flex-wrap gap-1 justify-content-end">' +
        `<a class="btn btn-sm btn-soft-info" href="${escapeAttr(targetSummaryUrl)}" data-toggle="tooltip" data-placement="top" title="Target Summary"><i class="fe-info"></i></a>` +
        `<a href="${escapeAttr(startScanUrl)}" class="btn btn-sm btn-soft-primary" data-toggle="tooltip" data-placement="top" title="Initiate Scan"><i class="fe-zap"></i></a>` +
        `<a class="btn btn-sm btn-soft-warning" href="${escapeAttr(scheduleScanUrl)}" data-toggle="tooltip" data-placement="top" title="Schedule Scan"><i class="fe-clock"></i></a>` +
        `<a class="btn btn-sm btn-soft-secondary" href="${escapeAttr(updateTargetUrl)}" data-toggle="tooltip" data-placement="top" title="Edit Target"><i class="fe-edit-2"></i></a>` +
        `<a class="btn btn-sm btn-soft-danger" href="#" data-toggle="tooltip" data-placement="top" title="Delete target" onclick="delete_target('${escapeAttr(deleteTargetUrl)}', '${safeName}'); return false;"><i class="fe-trash-2"></i></a>` +
        "</div>"
      );
    }

    return (
      '<div class="d-flex flex-wrap gap-1 justify-content-end">' +
      `<a class="btn btn-sm btn-soft-info" href="${escapeAttr(targetSummaryUrl)}" data-toggle="tooltip" data-placement="top" title="Target Summary"><i class="fe-info"></i></a>` +
      "</div>"
    );
  };

  window.RengineDatatableActionRenderers = {
    renderSubdomainActions: renderSubdomainActions,
    renderVulnerabilityActions: renderVulnerabilityActions,
    renderTargetActions: renderTargetActions,
  };
})(window);
