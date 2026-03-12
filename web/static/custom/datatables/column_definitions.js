/**
 * Shared DataTables column definitions for vulnerability and subdomain tables.
 * Single source of truth so column changes are made in one place only.
 * Must be loaded before any template that uses window.RengineDatatableColumnDefs.
 *
 * Every column object must include a "name" property (same as "data" when used for lookup). getColumnIndexByName
 * and rengineColumnByName use column.name to resolve indices; missing name returns -1 and breaks visibility/order.
 *
 * Column index → name mapping (matches backend DATATABLE_COLUMN_MAP_* keys)
 * -------------------------------------------------------------------------
 * RENGINE_VULN_DATATABLE_COLUMNS (DATATABLE_COLUMN_MAP_VULNERABILITY):
 *   0=id          1=source        2=type           3=name          4=cvss_metrics
 *   5=tags        6=hackerone_report_id             7=severity      8=cvss_score
 *   9=cve_ids     10=cwe_ids      11=http_url       12=description  13=references
 *   14=discovered_date            15=open_status    16=action       17=extracted_results
 *   18=curl_command               19=matcher_name   20=cvss_vec     21=epss_score
 *   22=confidence_nb              23=severity_nb    24=ip           25=reference
 *   Orderable backend cols (DATATABLE_COLUMN_MAP_VULNERABILITY): 1=source, 3=name,
 *     7=severity, 11=http_url, 15=open_status.
 *
 * RENGINE_SUBDOMAIN_DATATABLE_COLUMNS (DATATABLE_COLUMN_MAP_SUBDOMAIN):
 *   0=id          1=name          2=endpoint_count  3=vuln_count    4=http_status
 *   5=page_title  6=ip_addresses  7=ports           8=content_length(not searchable)
 *   9=response_time               10=technologies   11=http_url     12=cname
 *   13=is_interesting             14=info_count     15=low_count    16=medium_count
 *   17=high_count                 18=critical_count 19=todos_count  20=is_important
 *   21=webserver  22=content_type 23=action         24=directories_count
 *   25=subscan_count              26=waf            27=attack_surface
 *   28=verified   29=sources
 *   Orderable backend cols (DATATABLE_COLUMN_MAP_SUBDOMAIN): 0=checked, 1=name,
 *     4=http_status, 5=page_title, 8=content_length, 10=response_time.
 *
 * Consumers:
 * - RENGINE_VULN_DATATABLE_COLUMNS: startScan/vulnerabilities.html, startScan/detail_scan.html (vuln tab),
 *   targetApp/target/summary.html (vuln tab). Backend order map: web.api.helpers.datatables.DATATABLE_COLUMN_MAP_VULNERABILITY.
 * - RENGINE_SUBDOMAIN_DATATABLE_COLUMNS: startScan/subdomains.html, startScan/detail_scan.html (subdomain tab),
 *   targetApp/target/summary.html (subdomain tab). Backend: DATATABLE_COLUMN_MAP_SUBDOMAIN (and endpoint/dir maps as needed).
 * - RENGINE_DATATABLE_VULN_* / RENGINE_DATATABLE_SUBDOMAIN_*: default order and row-group options for the above templates.
 */
(function () {
  "use strict";

  const vulnColumns = [
    { data: "id", name: "id" },
    { data: "source", name: "source", defaultContent: "" },
    { data: "type", name: "type", defaultContent: "" },
    { data: "name", name: "name" },
    { data: "cvss_metrics", name: "cvss_metrics" },
    { data: "tags", name: "tags" },
    { data: "hackerone_report_id", name: "hackerone_report_id" },
    { data: "severity", name: "severity" },
    { data: "cvss_score", name: "cvss_score" },
    { data: "cve_ids", name: "cve_ids" },
    { data: "cwe_ids", name: "cwe_ids" },
    { data: "http_url", name: "http_url" },
    { data: "description", name: "description" },
    { data: "references", name: "references" },
    { data: "discovered_date", name: "discovered_date" },
    { data: "open_status", name: "open_status" },
    { data: "action", name: "action", defaultContent: "", orderable: false, searchable: false },
    { data: "extracted_results", name: "extracted_results" },
    { data: "curl_command", name: "curl_command" },
    { data: "matcher_name", name: "matcher_name" },
    { data: "cvss_vec", name: "cvss_vec" },
    { data: "epss_score", name: "epss_score" },
    { data: "confidence_nb", name: "confidence_nb" },
    { data: "severity_nb", name: "severity_nb" },
    { data: "ip", name: "ip" },
    { data: "reference", name: "reference" },
  ];

  const subdomainColumns = [
    { data: "id", name: "id" },
    { data: "name", name: "name" },
    { data: "endpoint_count", name: "endpoint_count" },
    { data: "vuln_count", name: "vuln_count" },
    { data: "http_status", name: "http_status" },
    { data: "page_title", name: "page_title" },
    { data: "ip_addresses", name: "ip_addresses" },
    { data: "ports", name: "ports" },
    { data: "content_length", name: "content_length", searchable: false },
    { data: "response_time", name: "response_time" },
    { data: "technologies", name: "technologies" },
    { data: "http_url", name: "http_url" },
    { data: "cname", name: "cname" },
    { data: "is_interesting", name: "is_interesting" },
    { data: "info_count", name: "info_count" },
    { data: "low_count", name: "low_count" },
    { data: "medium_count", name: "medium_count" },
    { data: "high_count", name: "high_count" },
    { data: "critical_count", name: "critical_count" },
    { data: "todos_count", name: "todos_count" },
    { data: "is_important", name: "is_important" },
    { data: "webserver", name: "webserver" },
    { data: "content_type", name: "content_type" },
    { data: "action", name: "action", orderable: false, searchable: false, defaultContent: "" },
    { data: "directories_count", name: "directories_count" },
    { data: "subscan_count", name: "subscan_count" },
    { data: "waf", name: "waf" },
    { data: "attack_surface", name: "attack_surface" },
    { data: "verified", name: "verified" },
    { data: "sources", name: "sources" },
  ];

  const secretColumns = [
    { data: "id", name: "id" },
    { data: "rule_name", name: "rule_name" },
    { data: "matched_at", name: "matched_at" },
    { data: "source", name: "source", defaultContent: "" },
    { data: "value", name: "value" },
    { data: "discovered_date", name: "discovered_date" },
    { data: "action", name: "action", defaultContent: "", orderable: false, searchable: false },
  ];

  window.RENGINE_VULN_DATATABLE_COLUMNS = vulnColumns;
  window.RENGINE_SUBDOMAIN_DATATABLE_COLUMNS = subdomainColumns;
  window.RENGINE_SECRET_DATATABLE_COLUMNS = secretColumns;

  /** Default order for vulnerability tables (column name, dir). Used with getRengineDatatableOrderFromNames(columns, this). */
  window.RENGINE_DATATABLE_VULN_DEFAULT_ORDER = [["cvss_score", "desc"]];
  /** Row group options for vulnerability tables. dataSrc/rowLabel must match API; column names in orderWhenActive must exist in RENGINE_VULN_DATATABLE_COLUMNS. */
  window.RENGINE_DATATABLE_VULN_ROW_GROUP_BASE = {
    dataSrc: "severity",
    rowLabel: "Vulnerabilities",
    emptyGroupLabel: "",
  };
  window.RENGINE_DATATABLE_VULN_ROW_GROUP_GROUPS = [
    { value: "", label: "None" },
    { value: "name", label: "Vulnerability Name", orderWhenActive: [["name", "asc"]] },
    { value: "severity", label: "Severity", orderWhenActive: [["severity", "asc"]] },
    { value: "source", label: "Vulnerability Source", orderWhenActive: [["source", "asc"]] },
    { value: "http_url", label: "Vulnerable URL", orderWhenActive: [["http_url", "asc"]] },
  ];

  /** Default order for subdomain tables. Used with getRengineDatatableOrderFromNames(columns, this). */
  window.RENGINE_DATATABLE_SUBDOMAIN_DEFAULT_ORDER = [["content_length", "desc"]];
  /** Row group options for subdomain tables. Column names must exist in RENGINE_SUBDOMAIN_DATATABLE_COLUMNS. */
  window.RENGINE_DATATABLE_SUBDOMAIN_ROW_GROUP_GROUPS = [
    { value: "page_title", label: "Page Title", orderWhenActive: [["page_title", "asc"]] },
    { value: "http_status", label: "HTTP Status", orderWhenActive: [["http_status", "asc"]] },
  ];

  const getCheckboxColumnDef = function (targetName, renderFn) {
    return {
      targets: targetName,
      width: "20px",
      orderable: false,
      render:
        typeof renderFn === "function"
          ? renderFn
          : function (data) {
              const safeVal = window.safeAttr(data);
              return (
                '<div class="form-check mb-2 form-check-primary">' +
                '<input type="checkbox" class="float-start form-check-input" value="' +
                safeVal +
                '">' +
                '<span class="new-control-indicator"></span><span style="visibility:hidden">c</span>' +
                "</div>"
              );
            },
    };
  };

  /**
   * @param {string} targetName - Column target (e.g. 'id:name').
   * @param {object} [options] - Optional overrides; defaults: visible: false, searchable: false so hidden technical columns do not leak into search.
   * @returns {object} DataTables columnDef.
   */
  const getHiddenColumnDef = function (targetName, options) {
    const defaults = { targets: targetName, visible: false, searchable: false };
    return Object.assign({}, defaults, options || {});
  };

  /**
   * Column def that renders cell value as escaped text. Use for plain text (e.g. cvss_vec, ip).
   * Keeps escaping and styling consistent; prefer over inline render in templates.
   *
   * @param {string} targetName - Column target (e.g. 'cvss_vec:name').
   * @returns {object} DataTables columnDef.
   */
  const getSafeTextColumnDef = function (targetName) {
    const safeTextFn = window.safeText;
    return {
      targets: targetName,
      render: function (data) {
        if (data == null || data === "") return "";
        const str = String(data);
        return typeof safeTextFn === "function" ? safeTextFn(str) : str;
      },
    };
  };

  /**
   * Column def that renders numeric or raw value for display (no HTML). Use for numbers (e.g. confidence_nb, severity_nb).
   *
   * @param {string} targetName - Column target (e.g. 'confidence_nb:name').
   * @returns {object} DataTables columnDef.
   */
  const getSafeNumberColumnDef = function (targetName) {
    return {
      targets: targetName,
      render: function (data) {
        return data !== null && data !== undefined ? data : "";
      },
    };
  };

  const getActionColumnDef = function (targetName, orderable) {
    return {
      targets: targetName,
      orderable: orderable === true,
      searchable: false,
      className: "text-center",
    };
  };

  /**
   * @param {string} targetName - Column target (e.g. 'name:name').
   * @param {object} options - className, badgeClass, iconClass, emptyValue, titleField (row key for tooltip title), titleFn(data, row) for custom title, displayFn(data) to transform value before badge.
   */
  const getBadgeColumnDef = function (targetName, options) {
    const opts = options || {};
    const className = opts.className || "";
    const badgeClass = opts.badgeClass || "badge badge-soft-secondary";
    const iconClass = opts.iconClass || "";
    const emptyValue = opts.emptyValue != null ? String(opts.emptyValue) : "";
    const titleField = opts.titleField || null;
    const titleFn = opts.titleFn || null;
    const displayFn = opts.displayFn || null;
    const safeBadgeFn = window.safeBadge;
    const safeAttrFn = window.safeAttr;
    return {
      targets: targetName,
      className: className,
      render: function (data, type, row) {
        if (data == null || data === "") return emptyValue;
        const displayText = typeof displayFn === "function" ? displayFn(data) : data;
        if (displayText == null || displayText === "") return emptyValue;
        const badgeHtml = typeof safeBadgeFn === "function" ? safeBadgeFn(displayText, badgeClass, iconClass) : window.safeText(displayText);
        if (!badgeHtml) return emptyValue;
        let title = "";
        if (typeof titleFn === "function") title = titleFn(data, row);
        else if (titleField && row && row[titleField] != null) title = String(row[titleField]);
        if (title && typeof safeAttrFn === "function") {
          return "<span data-toggle=\"tooltip\" data-placement=\"top\" title=\"" + safeAttrFn(title) + "\">" + badgeHtml + "</span>";
        }
        return badgeHtml;
      },
    };
  };

  const getBadgeDateColumnDef = function (targetName, options) {
    const opts = options || {};
    const className = opts.className || "text-center";
    const badgeClass = opts.badgeClass || "badge badge-soft-primary";
    const titleField = opts.titleField || null;
    const displayField = opts.displayField || null;
    return {
      targets: targetName,
      className: className,
      render: function (data, type, row) {
        const displayRaw = displayField && row ? row[displayField] : data;
        const titleRaw = titleField && row ? row[titleField] : data;
        const display = displayRaw != null && displayRaw !== "" ? displayRaw : "";
        const title = titleRaw != null && titleRaw !== "" ? titleRaw : "";
        return (
          '<span class="' +
          window.safeAttr(badgeClass) +
          '" data-toggle="tooltip" data-placement="top" title="' +
          window.safeAttr(title) +
          '">' +
          window.safeText(display) +
          "</span>"
        );
      },
    };
  };

  /**
   * Returns a column def that renders a safe <a href="...">...</a>. hrefFn and textFn receive (data, type, row).
   * @param {string} targetName - Column target (e.g. 'name:name').
   * @param {function(data, type, row): string} hrefFn - Returns the URL (will be passed through safeAttr).
   * @param {function(data, type, row): string} textFn - Returns the link text (will be passed through safeText).
   * @param {object} [options] - Optional. className, linkOptions passed to safeLink (target, rel, className).
   */
  const getLinkColumnDef = function (targetName, hrefFn, textFn, options) {
    const opts = options || {};
    const safeLinkFn = window.safeLink;
    const safeAttrFn = window.safeAttr;
    const safeTextFn = window.safeText;
    return {
      targets: targetName,
      className: opts.className || "",
      render: function (data, type, row) {
        const href = typeof hrefFn === "function" ? hrefFn(data, type, row) : (data == null ? "" : String(data));
        const text = typeof textFn === "function" ? textFn(data, type, row) : (data == null ? "" : String(data));
        if (typeof safeLinkFn === "function") return safeLinkFn(href, text, opts.linkOptions || {});
        return '<a href="' + (typeof safeAttrFn === "function" ? safeAttrFn(href) : href) + '">' + (typeof safeTextFn === "function" ? safeTextFn(text) : text) + "</a>";
      },
    };
  };

  const severityToClass = { Critical: "badge badge-critical", High: "badge badge-soft-danger", Medium: "badge badge-soft-warning", Low: "badge badge-low", Info: "badge badge-soft-primary", Unknown: "badge badge-soft-info" };

  /**
   * Single source of truth for vulnerability severity badge HTML. Used by getVulnSeverityBadgeColumnDef and get_severity_badge (custom.js).
   * @param {string} severity - Severity label (e.g. "Info", "High").
   * @returns {string} HTML for the badge span.
   */
  const renderSeverityBadgeHtml = function (severity) {
    if (severity == null || severity === "") return "";
    const sev = String(severity);
    const badgeClass = severityToClass[sev] || "badge badge-soft-secondary";
    const display = sev;
    const safeBadgeFn = window.safeBadge;
    const safeTextFn = window.safeText;
    if (typeof safeBadgeFn === "function") return safeBadgeFn(display, badgeClass, "");
    return "<span class=\"" + (typeof window.safeAttr === "function" ? window.safeAttr(badgeClass) : badgeClass) + "\">&nbsp;&nbsp;" + (typeof safeTextFn === "function" ? safeTextFn(display) : display) + "&nbsp;&nbsp;</span>";
  };

  /**
   * Shared vulnerability severity badge column def. Uses renderSeverityBadgeHtml (same as get_severity_badge).
   */
  const getVulnSeverityBadgeColumnDef = function (targetName) {
    return {
      targets: targetName,
      className: "text-center",
      render: function (data, type, row) {
        return renderSeverityBadgeHtml(data);
      },
    };
  };

  /**
   * Shared vulnerability http_url link column def. Uses safeLink/safeAttr/safeText; normalizes URL via normalizeSafeLinkUrl if present.
   */
  const getVulnHttpUrlLinkColumnDef = function (targetName, options) {
    const opts = options || {};
    const safeLinkFn = window.safeLink;
    const safeAttrFn = window.safeAttr;
    const safeTextFn = window.safeText;
    const normalizeUrl = typeof window.normalizeSafeLinkUrl === "function" ? window.normalizeSafeLinkUrl : function (u) { return u == null ? "" : String(u); };
    return {
      targets: targetName,
      render: function (data, type, row) {
        const raw = (data != null && typeof data === "string") ? data : (data != null ? String(data) : "");
        if (!raw) return "";
        const href = normalizeUrl(raw) || raw;
        const text = raw.length > (opts.maxLength || 80) ? raw.slice(0, (opts.maxLength || 77)) + "..." : raw;
        if (typeof safeLinkFn === "function") return safeLinkFn(href, text, { target: "_blank", className: (opts.className || "text-primary"), title: raw });
        return "<a href=\"" + (typeof safeAttrFn === "function" ? safeAttrFn(href) : href) + "\" target=\"_blank\" class=\"" + (opts.className || "text-primary") + "\" title=\"" + (typeof safeAttrFn === "function" ? safeAttrFn(raw) : raw) + "\">" + (typeof safeTextFn === "function" ? safeTextFn(text) : text) + "</a>";
      },
    };
  };

  /**
   * Shared HTTP status badge for subdomain tables. Uses safeBadge/safeText; 2xx=success, 3xx=warning, else danger.
   */
  const getSubdomainHttpStatusBadgeColumnDef = function (targetName) {
    const safeBadgeFn = window.safeBadge;
    const safeTextFn = window.safeText;
    return {
      targets: targetName,
      className: "text-center",
      render: function (data, type, row) {
        if (data == null || data === "") return "";
        const n = Number(data);
        if (n === 0) return "";
        const cls = (n >= 200 && n < 300) ? "badge badge-soft-success" : (n >= 300 && n < 400) ? "badge badge-soft-warning" : "badge badge-soft-danger";
        const display = String(data);
        if (typeof safeBadgeFn === "function") return safeBadgeFn(display, cls, "");
        return "<span class=\"" + (typeof window.safeAttr === "function" ? window.safeAttr(cls) : cls) + "\">" + (typeof safeTextFn === "function" ? safeTextFn(display) : display) + "</span>";
      },
    };
  };

  const severityToNameColor = { Info: "primary", Low: "low", Medium: "warning", High: "danger", Critical: "critical", Unknown: "info" };
  const severityToBadgeColor = { Info: "soft-primary", Low: "soft-warning", Medium: "soft-warning", High: "soft-danger", Critical: "critical", Unknown: "soft-info" };

  /**
   * Rich vulnerability name column: name (bold + severity color) + tags + cvss_metrics + cve_ids + cwe_ids + hackerone_report_id.
   * All output uses safeText/safeAttr/safeLink. Options: cveDetailsUrl (string) for CVE onclick.
   */
  const getVulnNameRichColumnDef = function (targetName, options) {
    const opts = options || {};
    const cveDetailsUrl = opts.cveDetailsUrl || "";
    const safeTextFn = window.safeText;
    const safeAttrFn = window.safeAttr;
    return {
      targets: targetName,
      render: function (data, type, row) {
        const severity = (row && row.severity) ? String(row.severity) : "";
        const color = severityToNameColor[severity] || "primary";
        const badgeColor = severityToBadgeColor[severity] || "soft-primary";
        let tags = "";
        if (row && Array.isArray(row.tags)) {
          row.tags.forEach(function (tag) {
            const tagName = (tag && tag.name) ? (typeof safeTextFn === "function" ? safeTextFn(tag.name) : tag.name) : "";
            tags += '<span class="badge badge-' + (typeof safeAttrFn === "function" ? safeAttrFn(badgeColor) : badgeColor) + ' me-1 mt-1" data-toggle="tooltip" data-placement="top" title="Tags">' + tagName + "</span>";
          });
          tags = "<div>" + tags + "</div>";
        }
        let cvssMetrics = "";
        if (row && row.cvss_metrics) {
          const cvssVal = typeof safeTextFn === "function" ? safeTextFn(row.cvss_metrics) : row.cvss_metrics;
          cvssMetrics = '<div><span class="badge badge-outline-primary mt-1" data-toggle="tooltip" data-placement="top" title="CVSS Metrics">' + cvssVal + "</span></div>";
        }
        let cveCwe = "";
        if (row && (row.cve_ids || row.cwe_ids)) {
          cveCwe = "<br>";
          if (Array.isArray(row.cve_ids)) {
            row.cve_ids.forEach(function (cve) {
              const rawName = cve && cve.name ? String(cve.name).toUpperCase() : "";
              const cveText = typeof safeTextFn === "function" ? safeTextFn(rawName) : rawName;
              const safeUrl = typeof safeAttrFn === "function" ? safeAttrFn(cveDetailsUrl) : cveDetailsUrl;
              const safeId = typeof safeAttrFn === "function" ? safeAttrFn(rawName) : rawName;
              cveCwe += '<a href="#" class="badge badge-outline-primary mt-1 me-1" data-toggle="tooltip" data-placement="top" title="CVE ID" data-cve-details-url="' + safeUrl + '" data-cve-id="' + safeId + '">' + cveText + "</a>";
            });
          }
        }
        if (row && Array.isArray(row.cwe_ids)) {
          row.cwe_ids.forEach(function (cwe) {
            const cweName = cwe && cwe.name ? String(cwe.name).toUpperCase() : "";
            const cweVal = typeof safeAttrFn === "function" ? safeAttrFn(encodeURIComponent(cweName)) : encodeURIComponent(cweName);
            const cweText = typeof safeTextFn === "function" ? safeTextFn(cweName) : cweName;
            cveCwe += '<a href="https://google.com/search?q=' + cweVal + '" target="_blank" class="badge badge-outline-primary mt-1 me-1" data-toggle="tooltip" data-placement="top" title="CWE ID">' + cweText + "</a>";
          });
        }
        let hackerone = "";
        if (row && row.hackerone_report_id) {
          const hId = typeof safeAttrFn === "function" ? safeAttrFn(String(row.hackerone_report_id)) : String(row.hackerone_report_id);
          hackerone = '<div><a class="badge badge-soft-danger mt-1 me-1" href="https://hackerone.com/reports/' + hId + '" target="_blank">Reported to hackerone</a></div>';
        }
        const nameText = data != null ? (typeof safeTextFn === "function" ? safeTextFn(data) : data) : "";
        return '<b class="text-' + (typeof safeAttrFn === "function" ? safeAttrFn(color) : color) + '">' + nameText + "</b>" + cvssMetrics + cveCwe + tags + hackerone;
      },
    };
  };

  /**
   * CVSS score badge: info (<=3.9), warning (3.9-6.9), danger (>6.9).
   */
  const getVulnCvssScoreBadgeColumnDef = function (targetName) {
    const safeBadgeFn = window.safeBadge;
    const safeTextFn = window.safeText;
    return {
      targets: targetName,
      render: function (data, type, row) {
        if (data == null || data === "") return "";
        const n = Number(data);
        let badge = "info";
        if (n > 3.9 && n <= 6.9) badge = "warning";
        else if (n > 6.9) badge = "danger";
        const display = typeof safeTextFn === "function" ? safeTextFn(data) : data;
        if (typeof safeBadgeFn === "function") return safeBadgeFn(display, "badge badge-outline-" + badge, "");
        return '<span class="badge badge-outline-' + badge + '" data-toggle="tooltip" data-placement="top" title="CVSS Score">' + display + "</span>";
      },
    };
  };

  /**
   * Open status: OPEN (truthy) or RESOLVED (falsy). Options: changeStatusUrl (string) to render clickable badge calling vuln_status_change(url, this, rowId, openStatus).
   */
  const getVulnOpenStatusBadgeColumnDef = function (targetName, options) {
    const opts = options || {};
    const changeStatusUrl = opts.changeStatusUrl || "";
    const safeTextFn = window.safeText;
    const safeAttrFn = window.safeAttr;
    return {
      targets: targetName,
      render: function (data, type, row) {
        const isOpen = data === true || data === "true" || data === 1;
        const label = isOpen ? "OPEN" : "RESOLVED";
        const cls = isOpen ? "badge badge-soft-danger" : "badge badge-soft-success";
        const text = typeof safeTextFn === "function" ? safeTextFn(label) : label;
        const badgeHtml = '<span class="vuln-status ' + cls + '">&nbsp;&nbsp;' + text + "&nbsp;&nbsp;</span>";
        if (changeStatusUrl && row && row.id != null) {
          const url = typeof safeAttrFn === "function" ? safeAttrFn(changeStatusUrl) : changeStatusUrl;
          const rowId = typeof safeAttrFn === "function" ? safeAttrFn(String(row.id)) : String(row.id);
          const openVal = typeof safeAttrFn === "function" ? safeAttrFn(String(data)) : String(data);
          return '<span role="button" onclick="vuln_status_change(\'' + url + "', this, " + rowId + ", " + openVal + ');">' + badgeHtml + "</span>";
        }
        return badgeHtml;
      },
    };
  };

  /**
   * Return HTML for subdomain vuln count badges (total, info, low, medium, high, critical).
   * Uses data-* attributes and class js-vuln-modal-trigger; a delegated click listener (see
   * attachVulnModalTriggerListener) reads these and calls get_vulnerability_modal. This avoids
   * fragile onclick string concatenation. Options: vulnerabilityListUrl, scanId (optional; adds data-scan-id for detail scan modal).
   * Requires window.safeAttr and window.safeText (from escape.js); throws if missing to avoid XSS.
   */
  const getSubdomainVulnCountBadgesHtml = function (row, options) {
    const opts = options || {};
    const vulnListUrl = opts.vulnerabilityListUrl || "";
    const scanId = opts.scanId != null && opts.scanId !== "" ? String(opts.scanId) : "";
    const safeAttrFn = window.safeAttr;
    const safeTextFn = window.safeText;
    if (typeof safeAttrFn !== "function" || typeof safeTextFn !== "function") {
      throw new Error("getSubdomainVulnCountBadgesHtml requires window.safeAttr and window.safeText (load escape.js first).");
    }
    const safeAttrVal = function (value) {
      return safeAttrFn(String(value == null ? "" : value));
    };

    if (!row) return "";
    const urlAttr = safeAttrVal(vulnListUrl);
    const idAttr = safeAttrVal(row.id);
    const nameAttr = safeAttrVal(row.name || "");
    const scanIdAttr = scanId ? safeAttrVal(scanId) : "";
    const dataScanId = scanIdAttr ? " data-scan-id=\"" + scanIdAttr + "\"" : "";
    const total = (row.info_count || 0) + (row.low_count || 0) + (row.medium_count || 0) + (row.high_count || 0) + (row.critical_count || 0);
    let html = "";
    if (total > 0) {
      const totalDisplay = safeTextFn(total);
      html += "<span class=\"pl-2 pr-2 me-1 mt-1 badge badge-critical bs-tooltip badge-link js-vuln-modal-trigger\" title=\"All Vulnerabilities\" role=\"button\" tabindex=\"0\" data-vuln-list-url=\"" + urlAttr + "\" data-subdomain-id=\"" + idAttr + "\" data-subdomain-name=\"" + nameAttr + "\"" + dataScanId + ">" + totalDisplay + " <i class=\"fas fa-bug\"></i></span>";
    }
    const parts = [
      [row.info_count, 0, "badge-soft-info", "Info", "Informational Vulnerabilities"],
      [row.low_count, 1, "badge-low", "Low", "Low Severity Vulnerabilities"],
      [row.medium_count, 2, "badge-soft-warning", "Med", "Medium Severity Vulnerabilities"],
      [row.high_count, 3, "badge-soft-danger", "High", "High Severity Vulnerabilities"],
      [row.critical_count, 4, "badge-critical", "Critical", "Critical Vulnerabilities"],
    ];
    parts.forEach(function (p) {
      if (p[0] > 0) {
        const display = safeTextFn(p[0]);
        const title = safeAttrVal(p[4]);
        html += "<span class=\"pl-2 pr-2 me-1 mt-1 badge " + p[2] + " bs-tooltip badge-link js-vuln-modal-trigger\" title=\"" + title + "\" role=\"button\" tabindex=\"0\" data-vuln-list-url=\"" + urlAttr + "\" data-severity-index=\"" + p[1] + "\" data-subdomain-id=\"" + idAttr + "\" data-subdomain-name=\"" + nameAttr + "\"" + dataScanId + ">" + display + " " + p[3] + "</span>";
      }
    });
    return html ? "<div>" + html + "</div>" : "";
  };

  /**
   * Attach a delegated click (and keydown Enter/Space) listener so that elements with class js-vuln-modal-trigger
   * open the vulnerability modal. Reads data-vuln-list-url, data-scan-id, data-severity-index,
   * data-subdomain-id, data-subdomain-name and calls window.get_vulnerability_modal if present.
   * Call once after DOM ready (e.g. from a page that defines get_vulnerability_modal).
   */
  const attachVulnModalTriggerListener = function () {
    const $ = window.jQuery;
    if (!$ || typeof $.fn.on !== "function") return;
    const openFromEl = function (el) {
      if (typeof window.get_vulnerability_modal !== "function") return;
      const url = (el.getAttribute("data-vuln-list-url") || "").trim();
      const scanIdRaw = el.getAttribute("data-scan-id");
      const scanId = (scanIdRaw != null && scanIdRaw !== "") ? scanIdRaw : null;
      const severityRaw = el.getAttribute("data-severity-index");
      const severity = (severityRaw != null && severityRaw !== "") ? parseInt(severityRaw, 10) : null;
      const subdomainId = (el.getAttribute("data-subdomain-id") || "").trim() || null;
      const subdomainName = (el.getAttribute("data-subdomain-name") || "").trim() || null;
      window.get_vulnerability_modal(url, scanId, severity, subdomainId, subdomainName);
    };
    $(document.body).off("click.vulnModalTrigger keydown.vulnModalTrigger", ".js-vuln-modal-trigger").on("click.vulnModalTrigger", ".js-vuln-modal-trigger", function (e) {
      e.preventDefault();
      openFromEl(this);
    }).on("keydown.vulnModalTrigger", ".js-vuln-modal-trigger", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openFromEl(this);
      }
    });
  };

  /**
   * Subdomain vuln count badges column def. Delegates to getSubdomainVulnCountBadgesHtml.
   * Options: vulnerabilityListUrl (string) for get_vulnerability_modal(..., subdomain_id, subdomain_name).
   */
  const getSubdomainVulnCountBadgesColumnDef = function (targetName, options) {
    const opts = options || {};
    return {
      targets: targetName,
      render: function (data, type, row) {
        return getSubdomainVulnCountBadgesHtml(row, opts);
      },
    };
  };

  /**
   * EPSS score badge: info (<=0.2), warning (0.2-0.5), danger (>0.5).
   */
  const getVulnEpssScoreBadgeColumnDef = function (targetName) {
    const safeAttrFn = window.safeAttr;
    const safeTextFn = window.safeText;
    return {
      targets: targetName,
      render: function (data, type, row) {
        if (data === null || data === undefined) return "";
        const score = parseFloat(data);
        if (!Number.isFinite(score)) return "";
        let badge = "info";
        if (score > 0.5) badge = "danger";
        else if (score > 0.2) badge = "warning";
        const display = score.toFixed(4);
        const cls = "badge badge-outline-" + badge;
        return '<span class="' + (typeof safeAttrFn === "function" ? safeAttrFn(cls) : cls) + '" data-toggle="tooltip" data-placement="top" title="EPSS Score">' + (typeof safeTextFn === "function" ? safeTextFn(display) : display) + "</span>";
      },
    };
  };

  window.renderSeverityBadgeHtml = renderSeverityBadgeHtml;
  window.attachVulnModalTriggerListener = attachVulnModalTriggerListener;
  window.RengineDatatableColumnDefs = window.RengineDatatableColumnDefs || {};
  Object.assign(window.RengineDatatableColumnDefs, {
    getCheckboxColumnDef: getCheckboxColumnDef,
    getHiddenColumnDef: getHiddenColumnDef,
    getSafeTextColumnDef: getSafeTextColumnDef,
    getSafeNumberColumnDef: getSafeNumberColumnDef,
    getActionColumnDef: getActionColumnDef,
    getBadgeColumnDef: getBadgeColumnDef,
    getBadgeDateColumnDef: getBadgeDateColumnDef,
    getLinkColumnDef: getLinkColumnDef,
    getVulnSeverityBadgeColumnDef: getVulnSeverityBadgeColumnDef,
    getVulnHttpUrlLinkColumnDef: getVulnHttpUrlLinkColumnDef,
    getSubdomainHttpStatusBadgeColumnDef: getSubdomainHttpStatusBadgeColumnDef,
    getVulnNameRichColumnDef: getVulnNameRichColumnDef,
    getVulnCvssScoreBadgeColumnDef: getVulnCvssScoreBadgeColumnDef,
    getVulnOpenStatusBadgeColumnDef: getVulnOpenStatusBadgeColumnDef,
    getVulnEpssScoreBadgeColumnDef: getVulnEpssScoreBadgeColumnDef,
    getSubdomainVulnCountBadgesColumnDef: getSubdomainVulnCountBadgesColumnDef,
    getSubdomainVulnCountBadgesHtml: getSubdomainVulnCountBadgesHtml,
  });

  if (window.jQuery && typeof window.jQuery.fn.on === "function") {
    window.jQuery(function () {
      attachVulnModalTriggerListener();
    });
  }
})();
