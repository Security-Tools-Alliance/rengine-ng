/**
 * Shared DataTables cell renderers for subdomain and endpoint tables
 * (main and "interesting" variants). Depends on escape.js (safeLink, safeText,
 * safeAttr, safeBadge, sanitizeUrlForHref). Uses parse_technology from custom.js when available.
 * Requires ``rengine_datatable_port_endpoint_pure.js`` (base.html loads it before this file).
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

  const placeholderNoDefaultEndpointData = function () {
    return "<span class=\"badge badge-soft-secondary bs-tooltip\" title=\"No default endpoint technology data\">—</span>";
  };
  const placeholderMissingEndpointDefaultsField = function () {
    return "<span class=\"text-muted bs-tooltip\" title=\"endpoint_defaults_by_port missing from API response (mixed-version deployment); no legacy technologies to display\">—</span>";
  };
  const placeholderTechRendererUnavailable = function () {
    return "<span class=\"badge badge-soft-secondary bs-tooltip\" title=\"Technology data present but renderer unavailable (parse_technology or query URL missing)\">…</span>";
  };

  const normalizeEndpointDefaultsTechnologiesFallback = window.rengineNormalizeEndpointDefaultsTechnologiesFallback;
  const isEffectivelyEmptyHtml = window.rengineIsEffectivelyEmptyHtml;
  const validEndpointDefaultRows = window.rengineValidEndpointDefaultRows;
  const classifyEndpointDefaultsByPortInput = window.rengineClassifyEndpointDefaultsByPortInput;

  const rengineWarnOnce = function (windowFlag, message) {
    if (typeof window !== "undefined" && window[windowFlag]) {
      return;
    }
    if (typeof window !== "undefined") {
      window[windowFlag] = true;
    }
    if (typeof console !== "undefined" && typeof console.warn === "function") {
      console.warn(message);
    }
  };

  const parseTechnologyAvailable = function () {
    return typeof window.parse_technology === "function";
  };

  const renderTechnologyRowBadges = function (row, queryUrl) {
    if (!row || typeof row !== "object") {
      return "";
    }
    let html = "";
    const techs = row.technologies;
    const hasTechs = Array.isArray(techs) && techs.length > 0;
    if (hasTechs && parseTechnologyAvailable() && queryUrl) {
      html += "<div>" + window.parse_technology(queryUrl, techs, "primary", null, null, true) + "</div>";
    } else if (hasTechs) {
      html += "<div>" + placeholderTechRendererUnavailable() + "</div>";
    }
    if (row.content_type) {
      html += "<div><span class='mt-1 badge badge-soft-blue bs-tooltip' title=\"Content Type\">" + safeText(row.content_type) + "</span></div>";
    }
    if (row.webserver) {
      html += "<div><span class='mt-1 badge badge-soft-info bs-tooltip' title=\"Web Server\">" + safeText(row.webserver) + "</span></div>";
    }
    return html;
  };

  const renderEndpointDefaultPortPrefix = function (row, showPortLabel) {
    if (!showPortLabel) {
      return "";
    }
    const portLabel = row.port != null ? String(row.port) : "?";
    return "<div><span class=\"badge badge-soft-dark mt-1 me-1\">:" + safeText(portLabel) + "</span></div>";
  };

  const COPY_ICON_SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"feather feather-copy\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\" ry=\"2\"></rect><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"></path></svg>";

  const getHttpStatusBadge = function (data) {
    if (data == null || data === "") return "";
    const n = Number(data);
    if (n === 0) return "";
    const display = safeText(String(data));
    const cls = (n >= 200 && n < 300) ? "badge badge-soft-success" : (n >= 300 && n < 400) ? "badge badge-soft-warning" : "badge badge-soft-danger";
    return "<span class=\"" + safeAttr(cls) + "\">" + display + "</span>";
  };

  /**
   * Renders per-port default endpoint tech/content-type/webserver badges.
   * `endpointDefaultsByPort` matches `DefaultEndpointTechnologyMixin._serialize_endpoint_defaults_by_port` (API).
   */
  var _rendererEndpointWarnKeys = (typeof RENGINE_CONSOLE_WARN_KEYS !== "undefined" && RENGINE_CONSOLE_WARN_KEYS.rendererEndpoint) || {
    missingEndpointDefaultsByPort: "__rengineWarnOnce_rendererEndpoint_missingEdbp",
    invalidEndpointDefaultsByPort: "__rengineWarnOnce_rendererEndpoint_invalidEdbp"
  };

  const renderEndpointDefaultsByPortBadges = function (endpointDefaultsByPort, options) {
    const opts = options || {};
    const queryUrl = opts.queryUrl || "";
    const showPortLabel = opts.showPortLabel !== false;
    const technologiesFallback = normalizeEndpointDefaultsTechnologiesFallback(opts.technologies);
    const branch = classifyEndpointDefaultsByPortInput(endpointDefaultsByPort);
    if (branch === "missing") {
      rengineWarnOnce(
        _rendererEndpointWarnKeys.missingEndpointDefaultsByPort,
        "renderEndpointDefaultsByPortBadges: endpoint_defaults_by_port is undefined; using legacy technologies fallback. Verify API includes this field (e.g. datatables_always_serialize) and client/server versions match."
      );
      const legacyHtml = renderTechnologyRowBadges(technologiesFallback, queryUrl);
      if (!isEffectivelyEmptyHtml(legacyHtml)) {
        return legacyHtml;
      }
      return placeholderMissingEndpointDefaultsField();
    }
    if (branch === "invalid_type") {
      rengineWarnOnce(
        _rendererEndpointWarnKeys.invalidEndpointDefaultsByPort,
        "renderEndpointDefaultsByPortBadges: endpoint_defaults_by_port is present but not an array; using legacy technologies fallback. This may indicate mixed client/server versions or a serialization issue."
      );
      const legacyHtml = renderTechnologyRowBadges(technologiesFallback, queryUrl);
      if (!isEffectivelyEmptyHtml(legacyHtml)) {
        return legacyHtml;
      }
      return placeholderMissingEndpointDefaultsField();
    }
    let htmlOut;
    if (branch === "empty_valid_rows") {
      htmlOut = renderTechnologyRowBadges(technologiesFallback, queryUrl);
    } else {
      htmlOut = validEndpointDefaultRows(endpointDefaultsByPort)
        .map(function (row) {
          return renderEndpointDefaultPortPrefix(row, showPortLabel) + renderTechnologyRowBadges(row, queryUrl);
        })
        .join("");
    }
    if (isEffectivelyEmptyHtml(htmlOut)) {
      return placeholderNoDefaultEndpointData();
    }
    return htmlOut;
  };

  /**
   * Builds endpoint URL cell HTML: link, tech badges, webserver badge, copy button.
   * @param {Object} row - Data row (id, http_url, techs, webserver).
   * @param {string} endpointSubdomainUrl - Base URL for parse_technology (e.g. subdomains or endpoints API).
   */
  const buildEndpointUrlCellHtml = function (row, endpointSubdomainUrl) {
    if (!row || typeof row !== "object") return "";
    const techData = row.techs || row.technologies;
    let techBadge = "";
    if (techData && (Array.isArray(techData) ? techData.length > 0 : Object.keys(techData).length > 0) && parseTechnologyAvailable() && endpointSubdomainUrl) {
      const scanId = row.scan_history_id != null ? row.scan_history_id : null;
      const domainId = row.domain_id != null ? row.domain_id : null;
      techBadge = "</br>" + window.parse_technology(endpointSubdomainUrl, techData, "primary", scanId, domainId, true);
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
  };

  /**
   * Builds interesting subdomain name cell HTML: optional Interesting badge, link with copy, tech badges.
   * @param {Object} row - Data row (id, name, http_url, is_interesting, technologies, content_type, webserver).
   * @param {Object} options - { querySubdomainsUrl: string } for parse_technology.
   */
  const buildInterestingSubdomainNameCellHtml = function (row, options) {
    if (!row || typeof row !== "object") return "";
    const opts = options || {};
    const queryUrl = opts.querySubdomainsUrl || "";
    let badges = "";
    if (row.is_interesting) {
      badges = "<div><span class='me-1 badge badge-soft-danger' data-toggle=\"tooltip\" data-placement=\"top\" title=\"Interesting Subdomain\">Interesting</span></div>";
    }
    let techBadge = renderEndpointDefaultsByPortBadges(row.endpoint_defaults_by_port, {
      queryUrl: queryUrl,
      showPortLabel: true,
      technologies: row.technologies
    });
    const href = (row.http_url != null && row.http_url !== "") ? row.http_url : ("https://" + (row.name != null ? row.name : ""));
    const safeHref = sanitizeUrl(href) || "#";
    const data = row.name != null ? row.name : "";
    const idVal = safeAttr(String(row.id != null ? row.id : ""));
    const copyIcon = "<a href=\"javascript:;\" data-clipboard-action=\"copy\" class=\"action-icon copyable\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Copy Subdomain!\" data-clipboard-target=\"#subdomain-" + idVal + "\" id=\"copy-subdomain-" + idVal + "\" onclick=\"setTooltip(this.id, 'Copied!')\"> <i class=\"text-primary mdi mdi-content-copy\"></i></a>";
    const linkPart = "<a href=\"" + (safeHref ? safeAttr(safeHref) : "#") + "\" class=\"text-primary\" target=\"_blank\"><span id=\"subdomain-" + idVal + "\">" + safeText(data) + copyIcon + " </span></a>";
    return badges + "<div class=\"clipboard copy-txt\">" + linkPart + "</div>" + techBadge;
  };

  /**
   * Builds HTTP URL column cell for interesting subdomains: link + copy icon.
   */
  const buildInterestingSubdomainHttpUrlCellHtml = function (row) {
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
  };

  window.RengineDatatableRenderers = {
    getHttpStatusBadge: getHttpStatusBadge,
    renderEndpointDefaultsByPortBadges: renderEndpointDefaultsByPortBadges,
    buildEndpointUrlCellHtml: buildEndpointUrlCellHtml,
    buildInterestingSubdomainNameCellHtml: buildInterestingSubdomainNameCellHtml,
    buildInterestingSubdomainHttpUrlCellHtml: buildInterestingSubdomainHttpUrlCellHtml
  };
  window.get_http_status_badge = getHttpStatusBadge;
})(window);
