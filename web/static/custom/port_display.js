function portDisplaySafeAttr(s) {
    return (typeof window.safeAttr === "function" ? window.safeAttr(s) : (s == null ? "" : String(s)));
}

function portDisplaySafeText(s) {
    return (typeof window.safeText === "function" ? window.safeText(s) : (s == null ? "" : String(s)));
}

/**
 * Finite non-negative count or NaN (invalid / missing). Prefer this for repeated coercion on hot paths.
 */
function portDisplayCoerceFiniteNonNegativeCount(value) {
    if (value == null || value === "") {
        return NaN;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
        return value >= 0 ? value : NaN;
    }
    const n = Number(value);
    return Number.isFinite(n) && n >= 0 ? n : NaN;
}

/**
 * Non-negative integer for counts, or 0 if missing or not a finite number.
 * Used for IP-address badges: the only association dimension in that payload is subdomains.
 */
function portDisplayFiniteNonNegativeCountOrZero(value) {
    const n = portDisplayCoerceFiniteNonNegativeCount(value);
    return Number.isFinite(n) ? n : 0;
}

/**
 * Association metadata for a port-number badge (not an IP badge).
 *
 * Prefer ip_address_count: distinct IPs exposing this port in the aggregated payload.
 * Fall back to subdomain_count when IP counts are absent so the badge still reflects host coverage.
 *
 * @returns {{ count: number, kind: "ip"|"subdomain"|"none" }}
 */
function portDisplayPickPortRowAssociationCount(element) {
    const ipRaw = portDisplayCoerceFiniteNonNegativeCount(element.ip_address_count);
    const subRaw = portDisplayCoerceFiniteNonNegativeCount(element.subdomain_count);
    if (Number.isFinite(ipRaw)) {
        return { count: ipRaw, kind: "ip" };
    }
    if (Number.isFinite(subRaw)) {
        return { count: subRaw, kind: "subdomain" };
    }
    return { count: 0, kind: "none" };
}

/** Sentinel sort key so invalid / non-finite port values sort after all valid ports. */
const PORT_SORT_MAX_SENTINEL = Number.MAX_SAFE_INTEGER;

/**
 * Numeric sort key for port numbers; non-finite values sort after real ports.
 */
function portDisplayCoercePortSortKey(num) {
    if (typeof num === "number" && Number.isFinite(num)) {
        return num;
    }
    const n = Number(num);
    return Number.isFinite(n) ? n : PORT_SORT_MAX_SENTINEL;
}

/** Strict TCP port parsing lives in rengine_datatable_port_endpoint_pure.js (loaded before this file). */

function portDisplaySafeBadgeWithTooltip(title, displayText, badgeClass, extraInnerHtml) {
    if (typeof window.safeBadgeWithTooltip === "function") {
        const fullClass = "m-1 badge " + (badgeClass != null && badgeClass !== "" ? badgeClass : "") + " bs-tooltip badge-link";
        return window.safeBadgeWithTooltip(title, displayText, fullClass.trim(), "", extraInnerHtml != null ? extraInnerHtml : "");
    }
    const safeTitle = portDisplaySafeAttr(title);
    const safeText = portDisplaySafeText(displayText);
    const safeClass = portDisplaySafeAttr(badgeClass || "");
    const extra = extraInnerHtml != null ? extraInnerHtml : "";
    return "<span class=\"m-1 badge " + safeClass + " bs-tooltip badge-link\" title=\"" + safeTitle + "\">" + safeText + extra + "</span>";
}

/**
 * Renders a safe <a> link. Prefer window.safeLink (escape.js); fallback sanitizes href via
 * window.sanitizeUrlForHref / window.normalizeSafeLinkUrl when available to avoid XSS if script order changes.
 */
function portDisplaySafeLink(href, displayText, opts) {
    if (typeof window.safeLink === "function") {
        const out = window.safeLink(href, displayText != null ? displayText : "", opts || {});
        if (typeof out === "string") return out;
    }
    const sanitize = typeof window.sanitizeUrlForHref === "function" ? window.sanitizeUrlForHref : (typeof window.normalizeSafeLinkUrl === "function" ? window.normalizeSafeLinkUrl : null);
    const safeHref = sanitize ? (sanitize(href) || "#") : "#";
    const safeText = portDisplaySafeText(displayText != null ? displayText : "");
    const o = opts || {};
    let attrs = "href=\"" + portDisplaySafeAttr(safeHref) + "\"";
    if (o.target) attrs += " target=\"" + portDisplaySafeAttr(o.target) + "\"";
    if (o.className) attrs += " class=\"" + portDisplaySafeAttr(o.className) + "\"";
    if (o.title != null) attrs += " title=\"" + portDisplaySafeAttr(o.title) + "\"";
    return "<a " + attrs + ">" + safeText + "</a>";
}

function portDisplayHttpStatusWithInteresting(data, row) {
    const statusHtml = typeof get_http_badge === "function" ? get_http_badge(data) : "";
    if (row && row.is_interesting) {
        return statusHtml + portDisplaySafeBadgeWithTooltip("Interesting", "Interesting", "badge badge-soft-danger ms-1", "");
    }
    return statusHtml || "-";
}

function portDisplaySubdomainLinkCell(data, type, row, urlOverride) {
    const url = urlOverride != null ? urlOverride : (row && row.http_url);
    const cls = (row && row.http_status >= 400) ? "text-danger" : "";
    if (url) {
        return portDisplaySafeLink(url, data != null ? data : "", { target: "_blank", className: cls });
    }
    return portDisplaySafeText(data != null ? data : "-");
}

const PORT_SUMMARY_THRESHOLD = 3;
const PORT_SUMMARY_VISIBLE = 2;

function portDisplayBadgeColorForPortRow(isIp, element) {
    if (isIp) {
        return element.is_cdn ? "warning" : "primary";
    }
    return element.is_uncommon ? "danger" : "primary";
}

function portDisplayBuildTooltipTitleBase(element, isIp) {
    if (isIp) {
        let t = element.is_cdn ? "CDN IP Address" : "IP Address";
        if (element.alive !== undefined) {
            t += "\nAlive: " + (element.alive ? "Yes" : "No");
        }
        return t;
    }
    let t = "Port " + element.number;
    if (element.state) t += "\nState: " + element.state;
    if (element.protocol) t += "\nProtocol: " + element.protocol;
    if (element.host) t += "\nHost: " + element.host;
    if (element.cpes && element.cpes.length > 0) {
        t += "\nCPEs: " + element.cpes.join(", ");
    }
    return t;
}

function portDisplayAppendDescriptionToTitle(title, element) {
    return element.description ? title + " - " + element.description : title;
}

function portDisplayAssociationFieldsForBadge(element, isIp) {
    if (!isIp) {
        const picked = portDisplayPickPortRowAssociationCount(element);
        let associationNames = null;
        let associationLabelSingular = "host";
        let associationLabelPlural = "hosts";
        if (picked.kind === "ip") {
            associationNames =
                element.ip_address_names ||
                (Array.isArray(element.ip_addresses) ? element.ip_addresses : null);
            associationLabelSingular = "IP address";
            associationLabelPlural = "IP addresses";
        } else if (picked.kind === "subdomain") {
            associationNames = element.subdomain_names;
            associationLabelSingular = "subdomain";
            associationLabelPlural = "subdomains";
        }
        return {
            assocNum: picked.count,
            associationNames: associationNames,
            associationLabelSingular: associationLabelSingular,
            associationLabelPlural: associationLabelPlural,
        };
    }
    return {
        assocNum: portDisplayFiniteNonNegativeCountOrZero(element.subdomain_count),
        associationNames: element.subdomain_names,
        associationLabelSingular: "subdomain",
        associationLabelPlural: "subdomains",
    };
}

function portDisplayAppendAssociationLines(title, assocNum, associationNames, singular, plural) {
    if (assocNum <= 0) {
        return title;
    }
    const assocLabel = assocNum === 1 ? singular : plural;
    let out = title + "\nFound on " + assocNum + " " + assocLabel;
    if (associationNames && associationNames.length > 0) {
        out += ":\n• " + associationNames.join("\n• ");
    }
    return out;
}

function portDisplayPortRowMainLabel(element) {
    return element.service_name
        ? element.number + "/" + element.service_name
        : String(element.number != null ? element.number : "");
}

function portDisplayAssociationCountBadgeHtml(assocNum, badgeColor) {
    if (assocNum <= 0) {
        return "";
    }
    if (typeof window.safeBadge === "function") {
        return window.safeBadge(String(assocNum), "badge bg-" + badgeColor + " ms-1", "");
    }
    return "<span class=\"badge bg-" + badgeColor + " ms-1\">" + portDisplaySafeText(String(assocNum)) + "</span>";
}

function buildSinglePortBadgeHtml(element, settings) {
    const is_ip = element.number == null;
    const badge_color = portDisplayBadgeColorForPortRow(is_ip, element);
    const assoc = portDisplayAssociationFieldsForBadge(element, is_ip);
    let title = portDisplayAppendDescriptionToTitle(portDisplayBuildTooltipTitleBase(element, is_ip), element);
    title = portDisplayAppendAssociationLines(
        title,
        assoc.assocNum,
        assoc.associationNames,
        assoc.associationLabelSingular,
        assoc.associationLabelPlural,
    );
    const display_text = is_ip ? (element.address || "") : portDisplayPortRowMainLabel(element);
    const countHtml = portDisplayAssociationCountBadgeHtml(assoc.assocNum, badge_color);

    const portsUrl = portDisplaySafeAttr(settings.api_ports_url || "");
    const subdomainsUrl = portDisplaySafeAttr(settings.api_subdomains_url || "");
    const ipsUrl = portDisplaySafeAttr(settings.api_ips_url || "");
    const scanId = settings.scan_id != null ? portDisplaySafeAttr(String(settings.scan_id)) : "";
    const domainId = settings.domain_id != null ? portDisplaySafeAttr(String(settings.domain_id)) : "";
    const address = portDisplaySafeAttr(element.address || "");
    const port = !is_ip && element.number != null ? portDisplaySafeAttr(String(element.number)) : "";

    return "<span class=\"m-1 badge badge-soft-" + badge_color + " bs-tooltip badge-link js-port-badge-trigger\" title=\"" + portDisplaySafeAttr(title) + "\" role=\"button\" tabindex=\"0\" data-api-ports-url=\"" + portsUrl + "\" data-api-subdomains-url=\"" + subdomainsUrl + "\" data-api-ips-url=\"" + ipsUrl + "\" data-scan-id=\"" + scanId + "\" data-domain-id=\"" + domainId + "\" data-address=\"" + address + "\" data-port=\"" + port + "\" data-is-ip=\"" + (is_ip ? "true" : "false") + "\">" + portDisplaySafeText(display_text) + countHtml + "</span>";
}

function renderBadge(data, settings) {
    const badges = [];

    try {
        const data_obj = typeof data === "string"
            ? JSON.parse(new DOMParser().parseFromString(data, "text/html").documentElement.textContent)
            : data;

        for (const item of data_obj) {
            const items = item.ports || [item];

            for (const element of items) {
                badges.push(buildSinglePortBadgeHtml(element, settings || {}));
            }
        }

        const useSummary = settings && settings.summaryWithPopover && badges.length > PORT_SUMMARY_THRESHOLD;

        if (!useSummary) {
            return badges.join("");
        }

        window._portsPopoverCounter = (window._portsPopoverCounter || 0) + 1;
        const uniqueId = "ports-popover-" + window._portsPopoverCounter;

        const visible = badges.slice(0, PORT_SUMMARY_VISIBLE).join("");
        const moreCount = badges.length - PORT_SUMMARY_VISIBLE;
        const fullHtml = badges.join("");

        const moreLabel = portDisplaySafeText("+" + moreCount + " more");
        const triggerHtml = "<button type=\"button\" class=\"btn btn-link btn-sm p-0 align-baseline js-ports-popover-trigger\" data-bs-toggle=\"popover\" data-popover-content-id=\"" + portDisplaySafeAttr(uniqueId) + "\" title=\"All ports and IPs\">(" + moreLabel + ")</button>";
        const contentHtml = "<div id=\"" + portDisplaySafeAttr(uniqueId) + "\" class=\"d-none ports-popover-content\">" + fullHtml + "</div>";

        return "<span class=\"ports-cell-summary\">" + visible + " <span class=\"ports-more-wrap\">" + triggerHtml + "</span>" + contentHtml + "</span>";
    } catch (e) {
        console.error("Error rendering badge:", e);
        return "";
    }
}

function initPortsPopovers(tableSelector) {
    const $ = window.jQuery;
    const bootstrap = window.bootstrap;
    if (!$ || !tableSelector || !bootstrap || typeof bootstrap.Popover !== "function") return;

    $(tableSelector).find(".js-ports-popover-trigger").each(function () {
        const trigger = this;
        const contentId = trigger.getAttribute("data-popover-content-id");
        if (!contentId) return;

        const contentEl = document.getElementById(contentId);
        if (!contentEl) return;

        const existing = bootstrap.Popover.getInstance(trigger);
        if (existing) existing.dispose();

        const popover = new bootstrap.Popover(trigger, {
            content: contentEl.innerHTML,
            html: true,
            sanitize: false,
            container: "body",
            customClass: "ports-popover"
        });

        const closeOnClickOutside = function (e) {
            const tip = popover.getTipElement && popover.getTipElement();
            const target = e.target;
            if (target === trigger || (trigger && trigger.contains(target))) return;
            if (tip && tip.contains(target)) return;
            popover.hide();
        };

        $(trigger).on("shown.bs.popover", function () {
            setTimeout(function () {
                $(document).on("click.portsPopoverClose", closeOnClickOutside);
            }, 0);
        });

        $(trigger).on("hidden.bs.popover", function () {
            $(document).off("click.portsPopoverClose");
        });
    });
}

function attachPortBadgeTriggerListener() {
    const $ = window.jQuery;
    if (!$ || typeof $.fn.on !== "function") return;
    const parseOptionalId = function (val) {
        if (val == null || val === "") return null;
        const n = parseInt(val, 10);
        return Number.isNaN(n) ? null : n;
    };
    const handlePortBadgeClick = function (el) {
        const isIp = el.getAttribute("data-is-ip") === "true";
        const portsUrl = el.getAttribute("data-api-ports-url") || "";
        const subdomainsUrl = el.getAttribute("data-api-subdomains-url") || "";
        const ipsUrl = el.getAttribute("data-api-ips-url") || "";
        const scanId = parseOptionalId(el.getAttribute("data-scan-id"));
        const domainId = parseOptionalId(el.getAttribute("data-domain-id"));
        if (isIp) {
            const address = el.getAttribute("data-address") || "";
            if (typeof get_ip_details === "function") {
                get_ip_details(portsUrl, subdomainsUrl, address, scanId, domainId);
            }
        } else {
            const portStr = el.getAttribute("data-port") || "";
            const port = parseInt(portStr, 10);
            if (!Number.isNaN(port) && typeof get_port_details === "function") {
                get_port_details(ipsUrl, subdomainsUrl, port, scanId, domainId);
            }
        }
    };
    $(document.body).off("click.portBadge keydown.portBadge", ".js-port-badge-trigger").on("click.portBadge", ".js-port-badge-trigger", function (e) {
        e.preventDefault();
        handlePortBadgeClick(e.currentTarget);
    }).on("keydown.portBadge", ".js-port-badge-trigger", function (e) {
        if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            handlePortBadgeClick(e.currentTarget);
        }
    });
}

/**
 * Legacy path: JSON embedded in HTML (historical templates used |safe + DOMParser).
 * @param {string} str
 * @returns {Array}
 */
function normalizeIpAddressesPayloadFromLegacyHtmlEmbeddedJson(str) {
    if (typeof str !== "string" || !str.trim()) {
        return [];
    }
    try {
        const decoded = new DOMParser().parseFromString(str, "text/html").documentElement.textContent;
        const parsed = JSON.parse(decoded);
        if (!Array.isArray(parsed)) {
            console.warn("Legacy IP widget JSON: root value is not an array");
            return [];
        }
        return parsed;
    } catch (e) {
        console.error("Legacy IP widget JSON parse failed:", e);
        return [];
    }
}

/**
 * Coalesce IP widget payload: arrays from json_script + JSON.parse (current templates), or legacy string.
 * @param {*} raw
 * @returns {Array}
 */
function normalizeIpAddressesPayload(raw) {
    if (Array.isArray(raw)) {
        return raw;
    }
    if (raw == null || raw === "") {
        return [];
    }
    if (typeof raw === "string") {
        return normalizeIpAddressesPayloadFromLegacyHtmlEmbeddedJson(raw);
    }
    console.warn("IP widget payload: expected array or legacy HTML-wrapped JSON string, got", typeof raw);
    return [];
}

function get_ips(ip_addresses, port_url, endpoint_subdomains, scan_id=null, domain_id=null) {
    try {
        const data = normalizeIpAddressesPayload(ip_addresses);
        
        $('#ip-address-count').html(`<span class="badge badge-soft-primary me-1">${data.length}</span>`);
        $('#ip-address').html(renderBadge(
            [{ ports: data }],
            {
                api_ports_url: port_url,
                api_subdomains_url: endpoint_subdomains,
                scan_id: scan_id,
                domain_id: domain_id
            }
        ));
        
        $("body").tooltip({ selector: '[data-toggle=tooltip]' });
    } catch (e) {
        console.error('Error processing IPs:', e);
        $('#ip-address').html('');
        $('#ip-address-count').html('0');
    }
}

/**
 * Build aggregated port badges from embedded IP data (client-side only; no list API call).
 *
 * @param {*} ip_addresses - IP rows with nested `ports` (from `json_script` or legacy HTML-wrapped JSON).
 * @param {string} api_ips_url - Required: passed through to `renderBadge` as `api_ips_url` for port-badge modals.
 * @param {string} api_subdomains_url - Required: passed through to `renderBadge` as `api_subdomains_url`.
 * @param {number|null} scan_id
 * @param {number|null} domain_id
 *
 * Aggregation is intentionally **by port number only**: `service_name` / `description` on each
 * nested port row are ignored so one badge is shown per distinct port with IP coverage counts.
 * Detailed service text belongs in list/modal APIs, not this summary widget.
 */
function get_ports(ip_addresses, api_ips_url, api_subdomains_url, scan_id=null, domain_id=null) {
    try {
        const data = normalizeIpAddressesPayload(ip_addresses);
        
        const portMap = new Map();

        data.forEach(ip => {
            ip.ports.forEach(port => {
                const num = port.number;
                if (num == null || num === "") {
                    return;
                }
                if (!portMap.has(num)) {
                    portMap.set(num, { ipSet: new Set(), is_uncommon: false });
                }
                const entry = portMap.get(num);
                entry.ipSet.add(ip.address);
                if (port.is_uncommon) {
                    entry.is_uncommon = true;
                }
            });
        });

        const ports = Array.from(portMap.entries())
            .map(([number, entry]) => {
                const names = Array.from(entry.ipSet).sort();
                return {
                    number,
                    service_name: "",
                    description: "",
                    is_uncommon: entry.is_uncommon,
                    ip_address_count: names.length,
                    ip_address_names: names
                };
            })
            .sort((a, b) => portDisplayCoercePortSortKey(a.number) - portDisplayCoercePortSortKey(b.number));
        
        // Display the total number of ports
        $('#ports-count').html(`<span class="badge badge-soft-primary me-1">${ports.length}</span>`);
        
        // Display the port badges
        $('#ports').html(renderBadge(
            [{ports: ports}],
            {
                api_ips_url: api_ips_url,
                api_subdomains_url: api_subdomains_url,
                scan_id: scan_id,
                domain_id: domain_id
            }
        ));
        
        // Enable tooltips
        $("body").tooltip({ selector: '[data-toggle=tooltip]' });
    } catch (e) {
        console.error('Error processing ports:', e);
        $('#ports').html('');
        $('#ports-count').html('0');
    }
}

function setupModal(title, tabs, options) {
    const opts = options || {};
    let navHtml = '<ul class="nav nav-tabs nav-bordered" id="modal_tab_nav">';
    let contentHtml = '<div id="modal_tab_content" class="tab-content">';
    tabs.forEach((tab, index) => {
        const isActive = index === 0 ? 'active' : '';
        const expanded = index === 0 ? 'true' : 'false';
        navHtml += `<li class="nav-item"><a class="nav-link ${isActive}" data-bs-toggle="tab" href="#modal_content_${tab.id}" aria-expanded="${expanded}" data-tab-id="${tab.id}"><span id="modal-${tab.id}-count"></span>${tab.label} &nbsp;${tab.loader}</a></li>`;
        contentHtml += `<div class="tab-pane ${isActive ? 'show active' : ''}" id="modal_content_${tab.id}"></div>`;
    });
    navHtml += '</ul>';
    contentHtml += '</div>';
    const bodyHtml = navHtml + contentHtml;
    if (window.ModalManager) {
        ModalManager.showDialog({
            title,
            bodyHtml,
            footerHtml: '',
            dialogClass: opts.dialogClass || null
        });
    }
    $('#modal_tab_nav').off('shown.bs.tab').on('shown.bs.tab', 'a[data-tab-id="subdomain"]', function () {
        setTimeout(() => {
            const containerId = 'modal_content_subdomain';
            if (window.currentModalData) {
                const { port, scan_id, domain_id } = window.currentModalData;
                if (port !== undefined) {
                    loadVisibleScreenshots(containerId, port, scan_id, domain_id);
                } else {
                    loadVisibleScreenshotsForIP(containerId, scan_id, domain_id);
                }
            }
        }, 100);
    });
}

// Load screenshots only for visible rows (port modal)
async function loadVisibleScreenshots(containerId, port, scan_id, domain_id) {
    const $visibleCells = $(`#${containerId} .screenshot-cell[data-loading="true"]:visible`);
    
    $visibleCells.each(async function() {
        const $cell = $(this);
        const subdomainId = $cell.data('subdomain-id');
        const subdomainName = $cell.data('subdomain-name');
        
        if (subdomainId && subdomainName) {
            try {
                // Remove loading indicator
                $cell.removeAttr('data-loading');
                
                // Load screenshot thumbnail
                const screenshots = await getScreenshotThumbnail(subdomainId, subdomainName, port, scan_id, domain_id, true);
                const html = typeof screenshots === "string" ? screenshots : "-";
                $cell.html(html);
            } catch (error) {
                console.error('Error loading screenshot for subdomain:', subdomainName, error);
                $cell.html('-');
            }
        }
    });
}

// Function to fetch and display screenshot thumbnail
async function getScreenshotThumbnail(subdomain_id, subdomain_name, port, scan_id, domain_id = null, disableHoverPreview = false) {
    if (!subdomain_id) {
        return '-';
    }
    const fetchScreenshotsBase = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.fetchScreenshots) || '/api/fetchScreenshots/';
    if (!scan_id && domain_id) {
        try {
            const url = `${fetchScreenshotsBase}?target_id=${domain_id}&subdomain_id=${subdomain_id}&port=${port}`;
            const response = await fetch(url);
            const data = await response.json();
            
            if (data && Object.keys(data).length > 0) {
                return await processScreenshotData(data, port, subdomain_id, subdomain_name, null, domain_id, disableHoverPreview);
            }
        } catch (error) {
            console.error('Error fetching screenshot for target:', error);
        }
    }
    
    // Original logic for scan_id
    if (!scan_id) {
        return '-';
    }
    
    try {
        const url = `${fetchScreenshotsBase}?scan_id=${scan_id}&subdomain_id=${subdomain_id}&port=${port}`;
        const response = await fetch(url);
        const data = await response.json();
        
        if (data && Object.keys(data).length > 0) {
            return await processScreenshotData(data, port, subdomain_id, subdomain_name, scan_id, domain_id, disableHoverPreview);
        } else {
            return '-';
        }
    } catch (error) {
        console.error('Error fetching screenshot:', error);
        return '-';
    }
}

// Helper function to process screenshot data
async function processScreenshotData(data, port, subdomain_id, subdomain_name, scan_id, domain_id, disableHoverPreview = false) {
    let screenshotHtml = '';
    let count = 0;
    
    for (let key in data) {
        const endpoint = data[key];
        
        const screenshotUrl = endpoint.screenshot_url || '';
        if (screenshotUrl && endpoint.port == port) {
            count++;
            if (count <= 2) {
                const thumb = window.ScreenshotDisplay.buildThumbnailHtml({
                    screenshotUrl,
                    httpUrl: endpoint.http_url || '',
                    subdomainId: subdomain_id,
                    subdomainName: subdomain_name || '',
                    port,
                    scanId: scan_id || '',
                    domainId: domain_id || '',
                    disableHover: disableHoverPreview,
                    className: 'screenshot-thumbnail me-1',
                });
                if (thumb) screenshotHtml += thumb;
            }
        }
    }
    
    if (count > 2) {
        screenshotHtml += `<span class="badge badge-soft-info text-xs">+${count - 2}</span>`;
    }
    
    return screenshotHtml || '-';
}

// Helper function to create screenshot preview element (screenshotUrl is the secure display URL from the API)
function createScreenshotPreviewElement(screenshotUrl, httpUrl) {
    const preview = $('<div id="screenshot-preview" class="screenshot-preview"></div>');
    const src = screenshotUrl || '';

    const $urlDiv = $('<div class="screenshot-preview-url"></div>').text(httpUrl);
    const $img = $('<img class="screenshot-preview-img">').attr('src', src).on('error', function () {
        $(this).parent().hide();
    });

    return preview.append($urlDiv).append($img);
}

// Function to show screenshot preview on hover (screenshotUrl is the secure display URL from the API)
function showScreenshotPreview(element, screenshotUrl, httpUrl) {
    // Remove any existing preview
    hideScreenshotPreview();
    
    // Position the preview relative to the thumbnail
    const $element = $(element);
    const elementOffset = $element.offset();
    const elementWidth = $element.outerWidth();
    const elementHeight = $element.outerHeight();
    const previewWidth = 600; // max-width of preview
    const previewHeight = 400; // approximate height
    
    // Check if we're in a table context (endpoints table or modal)
    const isInTable = $element.closest('table').length > 0;
    const isInModal = $element.closest('#modal_content_subdomain').length > 0;
    
    let preview;
    let parentContainer;
    
    if (isInTable && isInModal) {
        // For modals, use absolute positioning relative to the modal content
        const modalContainer = $('#modal_content_subdomain');
        const modalContent = modalContainer.closest('.modal-content');
        parentContainer = modalContent;

        // Make modal content relative if it's not already
        if (modalContent.css('position') === 'static') {
            modalContent.css('position', 'relative');
        }

        preview = createScreenshotPreviewElement(screenshotUrl, httpUrl).css('position', 'absolute');

        parentContainer.append(preview);
        
        // Calculate position relative to modal content
        const modalContentOffset = modalContent.offset();
        const relativeElementLeft = elementOffset.left - modalContentOffset.left;
        const relativeElementTop = elementOffset.top - modalContentOffset.top;
        
        // Position to the left of the thumbnail
        let leftPos = relativeElementLeft - previewWidth - 10;
        let topPos = relativeElementTop - (previewHeight / 2) + (elementHeight / 2);
        
        // Check boundaries within modal
        const modalWidth = modalContent.outerWidth();
        const modalHeight = modalContent.outerHeight();
        
        // If not enough space on the left, show on the right
        if (leftPos < 10) {
            leftPos = relativeElementLeft + elementWidth + 10;
        }
        
        // Make sure it doesn't exceed modal boundaries
        if (leftPos + previewWidth > modalWidth - 10) {
            leftPos = modalWidth - previewWidth - 10;
        }
        
        // Adjust vertical position if needed
        if (topPos < 10) {
            topPos = 10;
        } else if (topPos + previewHeight > modalHeight - 10) {
            topPos = modalHeight - previewHeight - 10;
        }
        
        preview.css({
            left: leftPos,
            top: topPos
        });
        
    } else {
        // For non-modal contexts (endpoints table or other)
        parentContainer = $('body');
        
        preview = createScreenshotPreviewElement(screenshotUrl, httpUrl).css('position', 'fixed');
        
        parentContainer.append(preview);
        
        if (isInTable) {
            // Use viewport coordinates for fixed positioning to avoid scroll drift
            const rect = element.getBoundingClientRect();
            const windowWidth = $(window).width();
            const windowHeight = $(window).height();
            
            // Preferred: left of the thumbnail
            let leftPos = rect.left - previewWidth - 10;
            let topPos = rect.top + (rect.height / 2) - (previewHeight / 2);

            // If not enough space on the left, place to the right
            if (leftPos < 10) {
                leftPos = rect.right + 10;
            }

            // Clamp horizontally within viewport
            if (leftPos + previewWidth > windowWidth - 10) {
                leftPos = Math.max(10, windowWidth - previewWidth - 10);
            }

            // Clamp vertically within viewport
            if (topPos < 10) {
                topPos = 10;
            } else if (topPos + previewHeight > windowHeight - 10) {
                topPos = windowHeight - previewHeight - 10;
            }

            preview.css({
                left: leftPos,
                top: topPos
            });
        } else {
            // For non-table contexts, position relative to element
            let leftPos = elementOffset.left - previewWidth - 10;
            let topPos = elementOffset.top - (previewHeight / 2) + (elementHeight / 2);

            if (leftPos < 10) {
                leftPos = elementOffset.left + elementWidth + 10;
            }

            preview.css({
                left: leftPos,
                top: topPos
            });
        }
    }
}

// Function to hide screenshot preview
function hideScreenshotPreview() {
    $('#screenshot-preview').remove();
    $('.screenshot-thumbnail').off('mousemove.screenshot-preview');
}

// Simple modal to display a single screenshot (screenshotUrl is the secure display URL from the API)
function showScreenshotImageModal(screenshotUrl, httpUrl = '') {
    const src = screenshotUrl || '';
    try {
        $('#xl-modal-title').empty();
        $('#xl-modal-content').empty();
        $('#xl-modal-footer').empty();

        const $content = $('<div class="mb-4 text-center"></div>');
        if (httpUrl) {
            const $linkBlock = $('<div class="mb-2 screenshot-modal-link"></div>');
            const $link = $('<a></a>')
                .attr('href', httpUrl)
                .attr('target', '_blank')
                .attr('rel', 'noopener noreferrer')
                .addClass('text-primary')
                .text(httpUrl);
            $linkBlock.append($link);
            $content.append($linkBlock);
        }
        const $imgContainer = $('<div class="d-flex justify-content-center"></div>');
        const $img = $('<img>')
            .addClass('img-fluid rounded screenshot-popup screenshot-modal-img')
            .attr('src', src)
            .on('click', function () {
                window.open(src, '_blank');
            });
        $imgContainer.append($img);
        $content.append($imgContainer);

        $('#xl-modal-title').html('Screenshot');
        $('#xl-modal-content').html($content);
        if (window.ModalManager) ModalManager.showXlOnly();
    } catch (e) {
        console.error('Error showing screenshot modal:', e);
        if (src) window.open(src, '_blank');
    }
}

/**
 * Registry for one-shot port_display console warnings: stable id → window flag + static message
 * or {@link portDisplayFormatMalformedUrlMessage} context label. Extend here only; call {@link portDisplayWarnOnce}.
 */
var RENGINE_PORT_DISPLAY_WARN_ONCE = (function () {
    var K = (typeof RENGINE_CONSOLE_WARN_KEYS !== "undefined" && RENGINE_CONSOLE_WARN_KEYS.portDisplay) || {
        missingServicesForRequestPort: "__rengineWarnOnce_portDisplay_missingServicesForRequestPort",
        malformedUrlModalIp: "__rengineWarnOnce_portDisplay_malformedUrlModalIp",
        malformedUrlModalSubdomainHttpUrl: "__rengineWarnOnce_portDisplay_malformedUrlModalSubHttpUrl",
        malformedUrlNameColumn: "__rengineWarnOnce_portDisplay_malformedUrlNameColumn"
    };
    return {
        missingServicesForRequestPort: {
            windowKey: K.missingServicesForRequestPort,
            message:
                "Port modal DataTable: row payload lacks services_for_request_port (older API / mixed-version). " +
                "Service cells may show a placeholder; prefetch and serializer support require a matching server version."
        },
        malformedUrlModalIp: {
            windowKey: K.malformedUrlModalIp,
            contextLabel: "portDisplayModalWebSchemeHref(ip)"
        },
        malformedUrlModalSubdomainHttpUrl: {
            windowKey: K.malformedUrlModalSubdomainHttpUrl,
            contextLabel: "portDisplayModalWebSchemeHref(subdomain http_url)"
        },
        malformedUrlNameColumn: {
            windowKey: K.malformedUrlNameColumn,
            contextLabel: "port modal subdomain name column URL rewrite"
        }
    };
}());

function portDisplayFormatMalformedUrlMessage(contextLabel, err) {
    const detail = err && err.message ? err.message : err != null ? String(err) : "";
    return "port_display: URL parse/build failed (" + contextLabel + ")." + (detail ? " " + detail : "");
}

/**
 * Emit a registered one-time warning (see {@link RENGINE_PORT_DISPLAY_WARN_ONCE}).
 * @param {string} warnId - key of {@link RENGINE_PORT_DISPLAY_WARN_ONCE}
 * @param {*} [err] - optional caught value when the entry uses {@link portDisplayFormatMalformedUrlMessage}
 */
function portDisplayWarnOnce(warnId, err) {
    const spec = RENGINE_PORT_DISPLAY_WARN_ONCE[warnId];
    if (!spec || typeof spec !== "object") {
        return;
    }
    const wk = spec.windowKey;
    if (typeof window !== "undefined" && window[wk]) {
        return;
    }
    if (typeof window !== "undefined") {
        window[wk] = true;
    }
    if (typeof console === "undefined" || typeof console.warn !== "function") {
        return;
    }
    let msg;
    if (typeof spec.message === "string") {
        msg = spec.message;
    } else if (spec.contextLabel) {
        msg = portDisplayFormatMalformedUrlMessage(spec.contextLabel, err);
    }
    if (msg) {
        console.warn(msg);
    }
}

/**
 * True if webPorts (numbers or numeric strings from config) includes the given port.
 */
function portDisplayWebPortsArrayIncludesPort(webPorts, portNum) {
    const p = typeof portNum === "number" && Number.isFinite(portNum) ? portNum : parseInt(portNum, 10);
    if (!Number.isFinite(p) || !Array.isArray(webPorts)) {
        return false;
    }
    return webPorts.some(function (wp) {
        return parseInt(wp, 10) === p;
    });
}

/**
 * Normalize IP literal for URL host (IPv6 bracketed; zone id stripped before brackets).
 */
function portDisplayBracketedHostForUrl(addrRaw) {
    const raw = addrRaw != null ? String(addrRaw).trim() : "";
    if (!raw) {
        return null;
    }
    const unbracketed = raw.replace(/^\[|\]$/g, "");
    if (unbracketed.indexOf(":") >= 0) {
        const noZone = unbracketed.split("%")[0];
        return "[" + noZone + "]";
    }
    return unbracketed;
}

/**
 * Build http(s) URL for port-modal DataTable link columns (IP or subdomain tab).
 *
 * @param {"ip"|"subdomain"} rowMode - `ip` uses `row.address`; `subdomain` prefers `row.http_url` then `row.name`.
 */
function portDisplayModalWebSchemeHref(rowMode, row, portStr, webPorts, scheme) {
    if (!row || typeof row !== "object") {
        return null;
    }
    const p = portDisplayParseStrictTcpPortString(portStr);
    if (p === null || !portDisplayWebPortsArrayIncludesPort(webPorts, p)) {
        return null;
    }
    if (rowMode === "ip") {
        const host = portDisplayBracketedHostForUrl(row.address);
        if (!host) {
            return null;
        }
        try {
            const u = new URL(scheme + "://" + host + "/");
            u.port = String(p);
            return u.origin;
        } catch (e) {
            portDisplayWarnOnce("malformedUrlModalIp", e);
            return null;
        }
    }
    if (rowMode !== "subdomain") {
        return null;
    }
    try {
        if (row.http_url) {
            const u = new URL(row.http_url);
            u.protocol = scheme + ":";
            u.port = String(p);
            return u.toString();
        }
    } catch (e) {
        portDisplayWarnOnce("malformedUrlModalSubdomainHttpUrl", e);
    }
    const host = row.name != null ? String(row.name).trim() : "";
    if (!host) {
        return null;
    }
    return scheme + "://" + host + ":" + p;
}

function get_port_details(endpoint_ip_url, endpoint_subdomain_url, port, scan_id=null, domain_id=null) {

    // Store modal data globally for tab click events
    window.currentModalData = { port: port, scan_id: scan_id, domain_id: domain_id };
    const uncommonPortsUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.uncommonWebPorts) || '/api/uncommon-web-ports/';
    $.getJSON(uncommonPortsUrl, function (portsData) {
        const webPorts = [...portsData.uncommon_web_ports, ...portsData.common_web_ports];
        
        let ip_url = `${endpoint_ip_url}?port=${port}`;
        let subdomain_url = `${endpoint_subdomain_url}?port=${port}`;

        if (scan_id) {
            ip_url += `&scan_id=${scan_id}`;
            subdomain_url += `&scan_id=${scan_id}`;
        } else if(domain_id) {
            ip_url += `&target_id=${domain_id}`;
            subdomain_url += `&target_id=${domain_id}`;
        }

        const loaders = {
            ip: `<span class="spinner-border spinner-border-sm me-1" id="ip-modal-loader"></span>`,
            subdomain: `<span class="spinner-border spinner-border-sm me-1" id="subdomain-modal-loader"></span>`
        };

        setupModal(
            `Details for Port: <b>${port}</b>`,
            [
                { id: 'ip', label: 'IP Addresses', loader: loaders.ip },
                { id: 'subdomain', label: 'Subdomains', loader: loaders.subdomain }
            ],
            { dialogClass: 'modal-xl' }
        );

        // IP tab: server-side DataTable
        $('#modal_content_ip').empty()
            .append('<p id="modal_content_ip_info">Loading...</p>')
            .append(
                '<table id="modal_content_ip-datatable" class="table table-striped table-sm">' +
                '<thead><tr><th>IP Address</th><th>Alive</th><th>Service</th><th>HTTP</th><th>HTTPS</th><th>Tags</th></tr></thead><tbody></tbody></table>'
            );
        const ipTableOpts = {
            ajax: {
                url: ip_url,
                data: function (d) {
                    d.port = port;
                    if (scan_id) d.scan_id = scan_id;
                    if (domain_id) d.target_id = domain_id;
                }
            },
            columns: [
                { data: "address", name: "address" },
                { data: "alive", name: "alive" },
                { data: "services_for_request_port", name: "service", orderable: false },
                { data: null, name: "http_link", orderable: false },
                { data: null, name: "https_link", orderable: false },
                { data: "is_cdn", name: "is_cdn", orderable: false }
            ],
            columnDefs: [
                {
                    targets: "address:name",
                    render: function (data, type, row) {
                        const badgeClass = row.is_cdn ? "warning" : "primary";
                        const text = (typeof window.safeText === "function" ? window.safeText(data) : data);
                        return "<span class=\"text-" + badgeClass + "\">" + text + "</span>";
                    }
                },
                {
                    targets: "alive:name",
                    render: function (data) {
                        if (data === true) return "<span class=\"badge badge-soft-success ms-1\">Alive</span>";
                        if (data === false) return "<span class=\"badge badge-soft-secondary ms-1\">Not Alive</span>";
                        return "-";
                    }
                },
                {
                    targets: "service:name",
                    render: function (data, type, row) {
                        if (row && typeof row === "object" && !Object.prototype.hasOwnProperty.call(row, "services_for_request_port")) {
                            portDisplayWarnOnce("missingServicesForRequestPort");
                            return "<span class=\"text-muted\" title=\"Service column unavailable: services_for_request_port not in API response (older server?)\">—</span>";
                        }
                        const t = data != null && data !== "" ? data : "-";
                        return portDisplaySafeText(t);
                    }
                },
                {
                    targets: "http_link:name",
                    orderable: false,
                    render: function (data, type, row) {
                        const href = portDisplayModalWebSchemeHref("ip", row, port, webPorts, "http");
                        if (!href) return "-";
                        return portDisplaySafeLink(href, "HTTP", { target: "_blank", className: "badge badge-soft-primary" });
                    }
                },
                {
                    targets: "https_link:name",
                    orderable: false,
                    render: function (data, type, row) {
                        const href = portDisplayModalWebSchemeHref("ip", row, port, webPorts, "https");
                        if (!href) return "-";
                        return portDisplaySafeLink(href, "HTTPS", { target: "_blank", className: "badge badge-soft-primary" });
                    }
                },
                {
                    targets: "is_cdn:name",
                    render: function (data) {
                        return data ? "<span class=\"badge badge-soft-warning\">CDN</span>" : "";
                    }
                }
            ],
            order: [[0, 'asc']],
            drawCallback: function () {
                const api = this.api();
                const total = (api.page && typeof api.page.info === 'function') ? api.page.info().recordsTotal : 0;
                $('#modal_content_ip_info').text(total + ' IP Addresses have Port ' + port + ' Open');
                $('#modal-ip-count').html('<b>' + total + '</b>&nbsp;&nbsp;');
                $('#ip-modal-loader').remove();
                if (window.ScreenshotDisplay) window.ScreenshotDisplay.attachDelegation('#modal_content_ip');
            }
        };
        if ($.fn.DataTable.isDataTable('#modal_content_ip-datatable')) {
            $('#modal_content_ip-datatable').DataTable().destroy();
        }
        if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
            window.initServerSideDataTable("#modal_content_ip-datatable", window.getRengineDatatableConfig("#modal_content_ip-datatable", ipTableOpts));
        } else {
            if (typeof console !== "undefined" && console.warn) {
                console.warn("port_display: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
            }
            $("#modal_content_ip-datatable").DataTable(Object.assign({ serverSide: true, processing: true }, ipTableOpts));
        }

        // Subdomain tab: server-side DataTable with lazy screenshots
        $('#modal_content_subdomain').empty()
            .append('<p id="modal_content_subdomain_info">Loading...</p>')
            .append(
                '<table id="modal_content_subdomain-datatable" class="table table-striped table-sm">' +
                '<thead><tr><th>Subdomain</th><th>Alive</th><th>Service</th><th>HTTP</th><th>HTTPS</th><th>Tags</th><th>Screenshots</th></tr></thead><tbody></tbody></table>'
            )
            .data('port', port)
            .data('scan_id', scan_id)
            .data('domain_id', domain_id);
        const subTableOpts = {
            ajax: {
                url: subdomain_url,
                data: function (d) {
                    d.port = port;
                    if (scan_id) d.scan_id = scan_id;
                    if (domain_id) d.target_id = domain_id;
                }
            },
            columns: [
                { data: "name", name: "name" },
                { data: "http_status", name: "alive", orderable: false },
                { data: "services_for_request_port", name: "service", orderable: false },
                { data: null, name: "http_link", orderable: false },
                { data: null, name: "https_link", orderable: false },
                { data: "is_cdn", name: "is_cdn", orderable: false },
                { data: null, name: "screenshots", orderable: false }
            ],
            columnDefs: [
                {
                    targets: "name:name",
                    render: function (data, type, row) {
                        let url = row.http_url;
                        if (url && portDisplayWebPortsArrayIncludesPort(webPorts, port)) {
                            try {
                                const u = new URL(url);
                                u.port = port;
                                url = u.toString();
                            } catch (e) {
                                portDisplayWarnOnce("malformedUrlNameColumn", e);
                            }
                        }
                        return portDisplaySubdomainLinkCell(data, type, row, url);
                    }
                },
                {
                    targets: "alive:name",
                    render: function (data) {
                        const st = data != null ? Number(data) : NaN;
                        const alive = Number.isFinite(st) && st > 0;
                        if (alive) return "<span class=\"badge badge-soft-success ms-1\">Alive</span>";
                        if (data === 0 || st === 0) return "<span class=\"badge badge-soft-secondary ms-1\">Not Alive</span>";
                        return "-";
                    }
                },
                {
                    targets: "service:name",
                    render: function (data, type, row) {
                        if (row && typeof row === "object" && !Object.prototype.hasOwnProperty.call(row, "services_for_request_port")) {
                            portDisplayWarnOnce("missingServicesForRequestPort");
                            return "<span class=\"text-muted\" title=\"Service column unavailable: services_for_request_port not in API response (older server?)\">—</span>";
                        }
                        const t = data != null && data !== "" ? data : "-";
                        return portDisplaySafeText(t);
                    }
                },
                {
                    targets: "http_link:name",
                    render: function (data, type, row) {
                        const href = portDisplayModalWebSchemeHref("subdomain", row, port, webPorts, "http");
                        if (!href) return "-";
                        return portDisplaySafeLink(href, "HTTP", { target: "_blank", className: "badge badge-soft-primary" });
                    }
                },
                {
                    targets: "https_link:name",
                    render: function (data, type, row) {
                        const href = portDisplayModalWebSchemeHref("subdomain", row, port, webPorts, "https");
                        if (!href) return "-";
                        return portDisplaySafeLink(href, "HTTPS", { target: "_blank", className: "badge badge-soft-primary" });
                    }
                },
                {
                    targets: "is_cdn:name",
                    render: function (data) {
                        return data ? "<span class=\"badge badge-soft-warning\">CDN</span>" : "";
                    }
                },
                {
                    targets: "screenshots:name",
                    orderable: false,
                    render: function (data, type, row) {
                        const idAttr = portDisplaySafeAttr(String(row.id));
                        const nameAttr = portDisplaySafeAttr(row.name || "");
                        return "<span class=\"screenshot-cell\" data-loading=\"true\" data-subdomain-id=\"" + idAttr + "\" data-subdomain-name=\"" + nameAttr + "\"><span class=\"spinner-border spinner-border-sm\"></span> Loading...</span>";
                    }
                }
            ],
            order: [[0, "asc"]],
            initComplete: function () {
                if (window.ScreenshotDisplay) window.ScreenshotDisplay.attachDelegation("#modal_content_subdomain");
            },
            drawCallback: function () {
                const api = this.api();
                const total = (api.page && typeof api.page.info === "function") ? api.page.info().recordsTotal : 0;
                $("#modal_content_subdomain_info").text(total + " Subdomains have Port " + port + " Open");
                $("#modal-subdomain-count").html("<b>" + total + "</b>&nbsp;&nbsp;");
                $("#subdomain-modal-loader").remove();
                if (window.ScreenshotDisplay) window.ScreenshotDisplay.attachDelegation("#modal_content_subdomain");
                loadVisibleScreenshots("modal_content_subdomain", $("#modal_content_subdomain").data("port"), $("#modal_content_subdomain").data("scan_id"), $("#modal_content_subdomain").data("domain_id"));
            }
        };
        if ($.fn.DataTable.isDataTable("#modal_content_subdomain-datatable")) {
            $("#modal_content_subdomain-datatable").DataTable().destroy();
        }
        if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
            window.initServerSideDataTable("#modal_content_subdomain-datatable", window.getRengineDatatableConfig("#modal_content_subdomain-datatable", subTableOpts));
        } else {
            if (typeof console !== "undefined" && console.warn) {
                console.warn("port_display: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
            }
            $("#modal_content_subdomain-datatable").DataTable(Object.assign({ serverSide: true, processing: true }, subTableOpts));
        }

    });
}

/**
 * Coerce scan/target context IDs to a positive integer or null (invalid, empty, or non-integer strings -> null).
 */
function normalizePositiveIdOrNull(value) {
    if (value == null || value === "") {
        return null;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
        const n = Math.trunc(value);
        return n > 0 ? n : null;
    }
    const t = String(value).trim();
    if (t === "") {
        return null;
    }
    const n = parseInt(t, 10);
    if (!Number.isFinite(n) || n <= 0) {
        return null;
    }
    if (String(n) !== t) {
        return null;
    }
    return n;
}

function get_ip_details(endpoint_ip_url, endpoint_subdomain_url, ip_address, scan_id = null, domain_id = null) {
    scan_id = normalizePositiveIdOrNull(scan_id);
    domain_id = normalizePositiveIdOrNull(domain_id);

    // Store modal data globally for tab click events (no port for IP modals)
    window.currentModalData = { scan_id: scan_id, domain_id: domain_id };
        
        let subdomain_url = `${endpoint_subdomain_url}?ip_address=${ip_address}`;

        if (scan_id) {
            subdomain_url += `&scan_id=${scan_id}`;
        } else if(domain_id) {
            subdomain_url += `&target_id=${domain_id}`;
        }

        const loaders = {
            subdomain: `<span class="spinner-border spinner-border-sm me-1" id="subdomain-modal-loader"></span>`
        };

        setupModal(
            `Details for IP: <b>${ip_address}</b>`,
            [
                { id: 'subdomain', label: 'Subdomains', loader: loaders.subdomain }
            ]
        );

        // Subdomain tab: server-side DataTable with lazy screenshots (ports 80, 443)
        $('#modal_content_subdomain').empty()
            .append('<p id="modal_content_subdomain_info">Loading...</p>')
            .append(
                '<table id="modal_content_subdomain-datatable" class="table table-striped table-sm">' +
                '<thead><tr><th>Subdomain</th><th>Status</th><th>Title</th><th>Screenshots</th></tr></thead><tbody></tbody></table>'
            )
            .data('scan_id', scan_id)
            .data('domain_id', domain_id);
        const ipSubTableOpts = {
            ajax: {
                url: subdomain_url,
                data: function (d) {
                    d.ip_address = ip_address;
                    if (scan_id) d.scan_id = scan_id;
                    if (domain_id) d.target_id = domain_id;
                }
            },
            columns: [
                { data: "name", name: "name" },
                { data: "http_status", name: "http_status" },
                { data: "page_title", name: "page_title" },
                { data: null, name: "screenshots" }
            ],
            columnDefs: [
                { targets: "name:name", render: function (data, type, row) { return portDisplaySubdomainLinkCell(data, type, row); } },
                { targets: "http_status:name", render: function (data, type, row) { return portDisplayHttpStatusWithInteresting(data, row); } },
                { targets: "page_title:name", render: function (data) { return (data && portDisplaySafeText(data)) || "-"; } },
                {
                    targets: "screenshots:name",
                    orderable: false,
                    render: function (data, type, row) {
                        const idAttr = portDisplaySafeAttr(String(row.id));
                        const nameAttr = portDisplaySafeAttr(row.name || "");
                        return "<span class=\"screenshot-cell\" data-loading=\"true\" data-subdomain-id=\"" + idAttr + "\" data-subdomain-name=\"" + nameAttr + "\"><span class=\"spinner-border spinner-border-sm\"></span> Loading...</span>";
                    }
                }
            ],
            order: [[0, "asc"]],
            initComplete: function () {
                if (window.ScreenshotDisplay) window.ScreenshotDisplay.attachDelegation("#modal_content_subdomain");
            },
            drawCallback: function () {
                const api = this.api();
                const total = (api.page && typeof api.page.info === "function") ? api.page.info().recordsTotal : 0;
                $("#modal_content_subdomain_info").text(total + " subdomains are associated with IP " + ip_address);
                $('#modal-subdomain-count').html('<b>' + total + '</b>&nbsp;&nbsp;');
                $('#subdomain-modal-loader').remove();
                if (window.ScreenshotDisplay) window.ScreenshotDisplay.attachDelegation('#modal_content_subdomain');
                loadVisibleScreenshotsForIP('modal_content_subdomain', $('#modal_content_subdomain').data('scan_id'), $('#modal_content_subdomain').data('domain_id'));
            }
        };
        if ($.fn.DataTable.isDataTable('#modal_content_subdomain-datatable')) {
            $('#modal_content_subdomain-datatable').DataTable().destroy();
        }
        if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
            window.initServerSideDataTable("#modal_content_subdomain-datatable", window.getRengineDatatableConfig("#modal_content_subdomain-datatable", ipSubTableOpts));
        } else {
            if (typeof console !== "undefined" && console.warn) {
                console.warn("port_display: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
            }
            $("#modal_content_subdomain-datatable").DataTable(Object.assign({ serverSide: true, processing: true }, ipSubTableOpts));
        }
}

// Load screenshots for common web ports (80, 443) only for visible rows (IP modal)
async function loadVisibleScreenshotsForIP(containerId, scan_id, domain_id) {
    const $visibleCells = $(`#${containerId} .screenshot-cell[data-loading="true"]:visible`);
    
    $visibleCells.each(async function() {
        const $cell = $(this);
        const subdomainId = $cell.data('subdomain-id');
        const subdomainName = $cell.data('subdomain-name');
        
        if (subdomainId && subdomainName) {
            try {
                // Remove loading indicator
                $cell.removeAttr('data-loading');
                
                let combinedScreenshots = '';
                
                // Get screenshots for common web ports (80, 443)
                if (scan_id) {
                    const httpsScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 443, scan_id, domain_id, true);
                    const httpScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 80, scan_id, domain_id, true);
                    if (typeof httpsScreenshots === "string" && httpsScreenshots !== "-") combinedScreenshots += httpsScreenshots;
                    if (typeof httpScreenshots === "string" && httpScreenshots !== "-") combinedScreenshots += httpScreenshots;
                } else if (domain_id) {
                    const httpsScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 443, null, domain_id, true);
                    const httpScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 80, null, domain_id, true);
                    if (typeof httpsScreenshots === "string" && httpsScreenshots !== "-") combinedScreenshots += httpsScreenshots;
                    if (typeof httpScreenshots === "string" && httpScreenshots !== "-") combinedScreenshots += httpScreenshots;
                }
                const html = typeof combinedScreenshots === "string" ? combinedScreenshots : "-";
                $cell.html(html || "-");
            } catch (error) {
                console.error('Error loading screenshots for subdomain:', subdomainName, error);
                $cell.html('-');
            }
        }
    });
}

if (window.jQuery && typeof window.jQuery.fn.on === "function") {
    window.jQuery(function () {
        if (typeof attachPortBadgeTriggerListener === "function") {
            attachPortBadgeTriggerListener();
        }
    });
}
