/**
 * Shared DataTables cell renderers for subdomain and endpoint tables
 * (main and "interesting" variants). Depends on escape.js (safeLink, safeText,
 * safeAttr, safeBadge, sanitizeUrlForHref). Uses parse_technology from custom.js when available.
 * Load after escape.js and column_definitions.js; used by custom.js and detail_scan.js.
 */
(function (window) {
  "use strict";

  const safeText = function (v) {
    return typeof window.safeText === "function" ? window.safeText(v) : (v == null ? "" : String(v));
  };
  const safeAttr = function (v) {
    return typeof window.safeAttr === "function" ? window.safeAttr(v) : (v == null ? "" : String(v));
  };
  const safeLink = function (href, displayText, opts) {
    if (typeof window.safeLink === "function") {
      return window.safeLink(href, displayText || "", opts || {});
    }
    return "<a href=\"#\">" + safeText(displayText) + "</a>";
  };
  const safeBadge = function (displayText, badgeClass, iconClass) {
    if (typeof window.safeBadge === "function") {
      return window.safeBadge(displayText, badgeClass || "", iconClass || "");
    }
    return "<span class=\"" + safeAttr(badgeClass) + "\">" + safeText(displayText) + "</span>";
  };
  const sanitizeUrl = function (url) {
    if (typeof window.sanitizeUrlForHref === "function") {
      return window.sanitizeUrlForHref(url) || "#";
    }
    return url && typeof url === "string" ? url : "#";
  };

  const COPY_ICON_SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"feather feather-copy\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\" ry=\"2\"></rect><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"></path></svg>";

  function getHttpStatusBadge(data) {
    if (data == null || data === "") return "";
    const n = Number(data);
    if (n === 0) return "";
    const display = safeText(String(data));
    const cls = (n >= 200 && n < 300) ? "badge badge-soft-success" : (n >= 300 && n < 400) ? "badge badge-soft-warning" : "badge badge-soft-danger";
    return "<span class=\"" + safeAttr(cls) + "\">" + display + "</span>";
  }

  /**
   * Builds endpoint URL cell HTML: link, tech badges, webserver badge, copy button.
   * @param {Object} row - Data row (id, http_url, techs, webserver).
   * @param {string} endpointSubdomainUrl - Base URL for parse_technology (e.g. subdomains or endpoints API).
   */
  function buildEndpointUrlCellHtml(row, endpointSubdomainUrl) {
    if (!row || typeof row !== "object") return "";
    const techData = row.techs || row.technologies;
    let techBadge = "";
    if (techData && (Array.isArray(techData) ? techData.length > 0 : Object.keys(techData).length > 0) && typeof window.parse_technology === "function" && endpointSubdomainUrl) {
      techBadge = "</br>" + window.parse_technology(endpointSubdomainUrl, techData, "primary", true, false, true);
    }
    let webServer = "";
    if (row.webserver) {
      webServer = safeBadge(row.webserver, "m-1 badge badge-soft-info", "");
    }
    const rawUrl = (row.http_url != null && typeof row.http_url === "string") ? row.http_url : (row.http_url ? String(row.http_url) : "");
    const hrefUrl = sanitizeUrl(rawUrl) || "#";
    const displayText = rawUrl.length > 80 ? rawUrl.slice(0, 77) + "..." : rawUrl;
    const idVal = safeAttr(String(row.id != null ? row.id : ""));
    const linkHtml = safeLink(hrefUrl, displayText, { target: "_blank", className: "text-primary", title: rawUrl });
    const linkWithId = linkHtml.replace("<a ", "<a id=\"url-" + idVal + "\" ");
    const actionIcons = "<div class=\"float-left subdomain-table-action-icons mt-2\"><span class=\"m-1\"><a href=\"javascript:;\" data-clipboard-action=\"copy\" class=\"badge-link text-primary copyable text-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Copy Url!\" data-clipboard-target=\"#url-" + idVal + "\" onclick=\"setTooltip(this.id, 'Copied!')\">" + COPY_ICON_SVG + "</span></a></div>";
    return "<div class=\"clipboard copy-txt\">" + linkWithId + techBadge + webServer + "<br>" + actionIcons + "</div>";
  }

  /**
   * Builds interesting subdomain name cell HTML: optional Interesting badge, link with copy, tech badges.
   * @param {Object} row - Data row (id, name, http_url, is_interesting, technologies, content_type, webserver).
   * @param {Object} options - { querySubdomainsUrl: string } for parse_technology.
   */
  function buildInterestingSubdomainNameCellHtml(row, options) {
    if (!row || typeof row !== "object") return "";
    const opts = options || {};
    const queryUrl = opts.querySubdomainsUrl || "";
    let badges = "";
    if (row.is_interesting) {
      badges = "<div><span class='me-1 badge badge-soft-danger' data-toggle=\"tooltip\" data-placement=\"top\" title=\"Interesting Subdomain\">Interesting</span></div>";
    }
    let techBadge = "";
    if (row.technologies && typeof window.parse_technology === "function" && queryUrl) {
      techBadge = "<div>" + window.parse_technology(queryUrl, row.technologies, "primary", null, null, true) + "</div>";
    }
    if (row.content_type) {
      techBadge += "<div><span class='mt-1 badge badge-soft-blue bs-tooltip' title=\"Content Type\">" + safeText(row.content_type) + "</span></div>";
    }
    if (row.webserver) {
      techBadge += "<div><span class='mt-1 badge badge-soft-info bs-tooltip' title=\"Web Server\">" + safeText(row.webserver) + "</span></div>";
    }
    const href = (row.http_url != null && row.http_url !== "") ? row.http_url : ("https://" + (row.name != null ? row.name : ""));
    const safeHref = sanitizeUrl(href) || "#";
    const data = row.name != null ? row.name : "";
    const idVal = safeAttr(String(row.id != null ? row.id : ""));
    const copyIcon = "<a href=\"javascript:;\" data-clipboard-action=\"copy\" class=\"action-icon copyable\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Copy Subdomain!\" data-clipboard-target=\"#subdomain-" + idVal + "\" id=\"copy-subdomain-" + idVal + "\" onclick=\"setTooltip(this.id, 'Copied!')\"> <i class=\"text-primary mdi mdi-content-copy\"></i></a>";
    const linkPart = "<a href=\"" + (safeHref ? safeAttr(safeHref) : "#") + "\" class=\"text-primary\" target=\"_blank\"><span id=\"subdomain-" + idVal + "\">" + safeText(data) + copyIcon + " </span></a>";
    return badges + "<div class=\"clipboard copy-txt\">" + linkPart + "</div>" + techBadge;
  }

  /**
   * Builds HTTP URL column cell for interesting subdomains: link + copy icon.
   */
  function buildInterestingSubdomainHttpUrlCellHtml(row) {
    if (!row || typeof row !== "object") return "";
    const raw = (row.http_url != null && typeof row.http_url === "string") ? row.http_url : (row.http_url ? String(row.http_url) : "");
    const safeHref = sanitizeUrl(raw) || "#";
    const displayText = raw.length > 80 ? raw.slice(0, 77) + "..." : raw;
    const idVal = safeAttr(String(row.id != null ? row.id : ""));
    const copyTargetId = "subdomain-url-" + idVal;
    const copyIcon = "<a href=\"javascript:;\" data-clipboard-action=\"copy\" class=\"action-icon copyable\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Copy URL!\" data-clipboard-target=\"#" + copyTargetId + "\" onclick=\"setTooltip(this.id, 'Copied!')\"> <i class=\"text-primary mdi mdi-content-copy\"></i></a>";
    const linkHtml = safeLink(safeHref, displayText, { target: "_blank", className: "text-primary", title: raw });
    const hiddenCopySource = "<span id=\"" + copyTargetId + "\" style=\"display:none\">" + safeText(raw) + "</span>";
    return "<div class=\"clipboard copy-txt\">" + linkHtml + " " + copyIcon + hiddenCopySource + "</div>";
  }

  window.RengineDatatableRenderers = {
    getHttpStatusBadge: getHttpStatusBadge,
    buildEndpointUrlCellHtml: buildEndpointUrlCellHtml,
    buildInterestingSubdomainNameCellHtml: buildInterestingSubdomainNameCellHtml,
    buildInterestingSubdomainHttpUrlCellHtml: buildInterestingSubdomainHttpUrlCellHtml
  };
  window.get_http_status_badge = getHttpStatusBadge;
})(window);
