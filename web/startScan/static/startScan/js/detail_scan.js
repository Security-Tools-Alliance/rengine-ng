function get_ips_from_port(port_number, history_id){
	const el = document.getElementById("detailScanModalLabel");
	if (el) el.textContent = "IPs with port " + (typeof window.safeText === "function" ? window.safeText(port_number) : port_number) + " OPEN";
	fetch('../port/ip/'+port_number+'/'+history_id+'/')
	.then(response => response.json())
	.then(data => render_ips(data));
}

function get_ports_for_ip(ip, history_id){
	const el = document.getElementById("detailScanModalLabel");
	if (el) el.textContent = "Open Ports identified for " + (typeof window.safeText === "function" ? window.safeText(ip) : ip);
	fetch('../ip/ports/'+ip+'/'+history_id+'/')
	.then(response => response.json())
	.then(data => render_ports(data));
}

/**
 * Renders a safe <a> link. Prefer window.safeLink (escape.js); fallback sanitizes href via
 * window.sanitizeUrlForHref / window.normalizeSafeLinkUrl when available. Requires escape.js for full safety.
 */
function detailScanSafeLink(url, displayText, opts) {
	if (typeof window.safeLink === "function") {
		return window.safeLink(url, displayText || "", opts || {});
	}
	const safeAttr = typeof window.safeAttr === "function" ? window.safeAttr : function (s) { return s == null ? "" : String(s); };
	const safeText = typeof window.safeText === "function" ? window.safeText : function (s) { return s == null ? "" : String(s); };
	const sanitize = typeof window.sanitizeUrlForHref === "function" ? window.sanitizeUrlForHref : (typeof window.normalizeSafeLinkUrl === "function" ? window.normalizeSafeLinkUrl : null);
	const safeHref = sanitize ? (sanitize(url) || "#") : "#";
	const text = safeText(displayText != null ? displayText : "");
	const o = opts || {};
	let attrs = "href=\"" + safeAttr(safeHref) + "\"";
	if (o.target) attrs += " target=\"" + safeAttr(o.target) + "\"";
	if (o.className) attrs += " class=\"" + safeAttr(o.className) + "\"";
	if (o.title != null) attrs += " title=\"" + safeAttr(o.title) + "\"";
	return "<a " + attrs + ">" + text + "</a>";
}

function detailScanSafeBadge(displayText, badgeClass, iconClass) {
	if (typeof window.safeBadge === "function") {
		return window.safeBadge(displayText, badgeClass || "", iconClass || "");
	}
	const safeAttr = typeof window.safeAttr === "function" ? window.safeAttr : function (s) { return s == null ? "" : String(s); };
	const safeText = typeof window.safeText === "function" ? window.safeText : function (s) { return s == null ? "" : String(s); };
	const cls = safeAttr(badgeClass || "");
	const icon = (iconClass != null && iconClass !== "") ? "<i class=\"" + safeAttr(iconClass) + " me-1\"></i>" : "";
	return "<span class=\"" + cls + "\">" + icon + safeText(displayText) + "</span>";
}

function detailScanSafeBadgeWithTooltip(title, displayText, badgeClass, iconClass) {
	if (typeof window.safeBadgeWithTooltip === "function") {
		return window.safeBadgeWithTooltip(title, displayText, badgeClass || "", iconClass || "", "");
	}
	const safeAttr = typeof window.safeAttr === "function" ? window.safeAttr : function (s) { return s == null ? "" : String(s); };
	const safeText = typeof window.safeText === "function" ? window.safeText : function (s) { return s == null ? "" : String(s); };
	const cls = safeAttr(badgeClass || "");
	const titleAttr = (title != null && title !== "") ? " title=\"" + safeAttr(title) + "\"" : "";
	const icon = (iconClass != null && iconClass !== "") ? "<i class=\"" + safeAttr(iconClass) + " me-1\"></i>" : "";
	return "<span class=\"" + cls + "\"" + titleAttr + ">" + icon + safeText(displayText) + "</span>";
}

function buildEndpointUrlCellHtml(row, endpointSubdomainUrl) {
	if (window.RengineDatatableRenderers && typeof window.RengineDatatableRenderers.buildEndpointUrlCellHtml === "function") {
		return window.RengineDatatableRenderers.buildEndpointUrlCellHtml(row, endpointSubdomainUrl);
	}
	let techBadge = "";
	if (row["techs"]) {
		techBadge = "</br>" + parse_technology(endpointSubdomainUrl, row["techs"], "primary", true, false, true);
	}
	let webServer = "";
	if (row["webserver"]) {
		webServer = detailScanSafeBadge(row["webserver"], "m-1 badge badge-soft-info", "");
	}
	const rawUrl = (row["http_url"] != null && typeof row["http_url"] === "string") ? row["http_url"] : (row["http_url"] ? String(row["http_url"]) : "");
	const sanitize = typeof window.sanitizeUrlForHref === "function" ? window.sanitizeUrlForHref : (typeof window.normalizeSafeLinkUrl === "function" ? window.normalizeSafeLinkUrl : null);
	const hrefUrl = sanitize ? (sanitize(rawUrl) || "#") : (rawUrl || "#");
	const displayText = rawUrl.length > 80 ? rawUrl.slice(0, 77) + "..." : rawUrl;
	const idVal = typeof window.safeAttr === "function" ? window.safeAttr(String(row["id"])) : String(row["id"]);
	const linkHtml = detailScanSafeLink(hrefUrl, displayText, { target: "_blank", className: "text-primary", title: rawUrl });
	const linkWithId = linkHtml.replace("<a ", "<a id=\"url-" + idVal + "\" ");
	const actionIcons = "<div class=\"float-left subdomain-table-action-icons mt-2\"><span class=\"m-1\"><a href=\"javascript:;\" data-clipboard-action=\"copy\" class=\"badge-link text-primary copyable text-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Copy Url!\" data-clipboard-target=\"#url-" + idVal + "\" onclick=\"setTooltip(this.id, 'Copied!')\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"feather feather-copy\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\" ry=\"2\"></rect><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"></path></svg></span></a></div>";
	return "<div class=\"clipboard copy-txt\">" + linkWithId + techBadge + webServer + "<br>" + actionIcons + "</div>";
}

// normalizeSafeLinkUrl: provided by web/static/custom/datatables/escape.js (load order: escape.js before this script).
// Do not reimplement URL sanitization here; use window.normalizeSafeLinkUrl or window.sanitizeUrlForHref. See escape.js for allowed schemes.

function render_ports(data) {
	let port_badge = "";
	const ip_address_content = document.getElementById("detailScanModalContent");
	Object.entries(JSON.parse(data)).forEach(([key, value]) => {
		const badge_color = value[3] ? "danger" : "info";
		let title = value[3] ? "Uncommon Port - " + value[2] : String(value[2]);
		if (value[4]) title += "\nState: " + value[4];
		if (value[5]) title += "\nProtocol: " + value[5];
		if (value[6]) title += "\nHost: " + value[6];
		if (value[7] && Array.isArray(value[7]) && value[7].length > 0) title += "\nCPEs: " + value[7].join(", ");
		const display = (value[0] != null ? value[0] : "") + "/" + (value[1] != null ? value[1] : "");
		port_badge += detailScanSafeBadgeWithTooltip(title, display, "m-1 badge badge-soft-" + badge_color + " bs-tooltip", "");
	});
	ip_address_content.innerHTML = port_badge;
	$(".bs-tooltip").tooltip();
	return port_badge;
}

function render_ips(data) {
	let ip_badge = "";
	const content = document.getElementById("detailScanModalContent");
	Object.entries(JSON.parse(data)).forEach(([key, value]) => {
		const badge_color = value[1] ? "warning" : "info";
		let title = value[1] ? "CDN IP Address" : "";
		if (value[2] !== undefined) title += value[2] ? "\nAlive: Yes" : "\nAlive: No";
		const display = value[0] != null ? value[0] : "";
		ip_badge += detailScanSafeBadgeWithTooltip(title, display, "m-1 badge badge-soft-" + badge_color + " bs-tooltip", "");
	});
	content.innerHTML = ip_badge;
	$(".bs-tooltip").tooltip();
}


function get_endpoints(endpoint_endpoint_url, endpoint_subdomain_url, project, scan_history_id=null, domain_id=null, gf_tags=null){

    let lookup_url = endpoint_endpoint_url + '?format=datatables&project=' + project;

	if (scan_history_id) {
		lookup_url += `&scan_history=${scan_history_id}`;
	}
	else if (domain_id) {
		lookup_url += `&target_id=${domain_id}`;
	}

	// Store context for screenshot modal when thumbnails lack data-scan-id / data-domain-id
	const $endpointTable = $('#endpoint_results');
	if ($endpointTable.length) {
		$endpointTable.data('context-scan-id', scan_history_id || null);
		$endpointTable.data('context-domain-id', domain_id || null);
	}

	if (gf_tags){
		lookup_url += `&gf_tag=${gf_tags}`
	}

	// Restore Filter column checkboxes from localStorage before building the table
	// so initComplete / endpoint_datatable_col_visibility see the correct state
	const endpointFilterCheckboxIds = [
		'end_http_status_filter_checkbox',
		'end_page_title_filter_checkbox',
		'end_tags_filter_checkbox',
		'end_content_type_filter_checkbox',
		'end_content_length_filter_checkbox',
		'end_response_time_filter_checkbox',
		'end_screenshot_filter_checkbox',
	];
	endpointFilterCheckboxIds.forEach(function (id) {
		const stored = window.localStorage.getItem(id);
		if (stored !== null) {
			const $el = $('#' + id);
			if ($el.length) {
				$el.prop('checked', stored !== 'false');
			}
		}
	});

    // Ensure columns count matches thead
    const endpoint_datatable_columns = [
        { 'data': 'id', 'title': 'ID', 'defaultContent': '', 'visible': false, 'searchable': false, 'className': 'endpoint-id-col dt-col-hidden' },
        {
            'data': 'http_url', 'title': 'HTTP URL', 'defaultContent': '',
            'render': function (data, type, row) {
                return buildEndpointUrlCellHtml(row, endpoint_subdomain_url);
            }
        },
        { 
            'data': 'http_status', 'title': 'Status', 'defaultContent': '',
            'render': function ( data, type, row ) {
                if (data) {
                    return get_http_status_badge(data);
                }
                return '';
            }
        },
        { 'data': 'page_title', 'title': 'Page Title', 'defaultContent': '', 'render': function ( data ) { return (typeof window.safeText === 'function' ? window.safeText(data) : (data || '')); } },
        { 'data': 'matched_gf_patterns', 'title': 'Tags', 'defaultContent': '', 'render': function ( data ) { return data ? parse_comma_values_into_span(data, "danger", outline=true) : ""; } },
        { 'data': 'content_type', 'title': 'Content Type', 'defaultContent': '' },
        { 'data': 'content_length', 'title': 'Content Length', 'searchable': false, 'defaultContent': '' },
        { 'data': 'techs', 'title': 'Technology', 'defaultContent': '', 'visible': false, 'className': 'dt-col-hidden' },
        { 'data': 'webserver', 'title': 'Webserver', 'defaultContent': '', 'visible': false, 'className': 'dt-col-hidden', 'render': function ( data ) { return data ? parse_comma_values_into_span(data, "info") : ""; } },
        { 'data': 'response_time', 'title': 'Response time', 'searchable': false, 'defaultContent': '', 'render': function ( data ) { return data ? get_response_time_text(data) : ""; } },
        {
            'data': 'screenshot_url',
            'title': 'Screenshot',
            'searchable': false,
            'defaultContent': '',
            'render': function (data, type, row) {
                const screenshotUrl = row['screenshot_url'] || '';
                if (!screenshotUrl) return '-';
                let port = 80;
                try {
                    const url = new URL(row['http_url'] || 'http://x');
                    port = url.port || (url.protocol === 'https:' ? 443 : 80);
                } catch (_) {}
                return window.ScreenshotDisplay.buildThumbnailHtml({
                    screenshotUrl,
                    httpUrl: row['http_url'] || '',
                    subdomainId: row['subdomain_id'] || '',
                    subdomainName: row['subdomain_name'] || '',
                    port,
                    scanId: row['scan_history_id'] || '',
                    domainId: row['domain_id'] || '',
                }) || '-';
            },
        },
        { 'data': 'method', 'title': 'Method', 'defaultContent': '', 'visible': false, 'className': 'dt-col-hidden' },
        { 'data': 'words', 'title': 'Words', 'searchable': false, 'defaultContent': '', 'visible': false, 'className': 'dt-col-hidden' },
        { 'data': 'lines', 'title': 'Lines', 'searchable': false, 'defaultContent': '', 'visible': false, 'className': 'dt-col-hidden' },
        { 'data': 'headers', 'title': 'Headers', 'defaultContent': '', 'visible': false, 'className': 'dt-col-hidden', 'render': function ( data ) { return data ? JSON.stringify(data) : ""; } }
    ];
    // If already initialized, destroy cleanly to avoid index drift
    if (DataTable.isDataTable('#endpoint_results')) {
        const existing = $('#endpoint_results').DataTable();
        existing.destroy();
    }
    // Dynamically generate thead based on column definitions to prevent mismatches
    const generateTableHead = function(tableId, columns) {
        const table = document.getElementById(tableId);
        if (!table) { return; }
        const thead = document.createElement('thead');
        const tr = document.createElement('tr');
        columns.forEach(function(col) {
            const th = document.createElement('th');
            th.textContent = col.title || col.data || '';
            if (col.visible === false) {
                th.style.display = 'none';
                if (col.className) {
                    th.className = col.className;
                }
            } else if (col.className) {
                th.className = col.className;
            }
            tr.appendChild(th);
        });
        thead.appendChild(tr);
        const oldThead = table.querySelector('thead');
        if (oldThead) {
            table.removeChild(oldThead);
        }
        table.insertBefore(thead, table.firstChild);
        const tbody = table.querySelector('tbody');
        if (!tbody) {
            table.appendChild(document.createElement('tbody'));
        }
    };

    generateTableHead('endpoint_results', endpoint_datatable_columns);

    // Precompute indices by data name to avoid hard-coded numbers. Use global helper or local fallback so -1 only means "column not found".
    const getColIdx = (cols, name) => {
        if (typeof window.getColumnIndexByName === 'function') return window.getColumnIndexByName(cols, name);
        if (!Array.isArray(cols) || cols.length === 0) return -1;
        const first = cols[0];
        if (typeof first === 'string') return cols.indexOf(name);
        return cols.findIndex((c) => c && c.name === name);
    };
    const colIndexMap = {
        http_status: getColIdx(endpoint_datatable_columns, 'http_status'),
        page_title: getColIdx(endpoint_datatable_columns, 'page_title'),
        matched_gf_patterns: getColIdx(endpoint_datatable_columns, 'matched_gf_patterns'),
        content_type: getColIdx(endpoint_datatable_columns, 'content_type'),
        content_length: getColIdx(endpoint_datatable_columns, 'content_length'),
        response_time: getColIdx(endpoint_datatable_columns, 'response_time'),
    };

    // Validate indices; replace -1 with null to avoid runtime issues
    Object.entries(colIndexMap).forEach(([key, value]) => {
        if (value === -1) {
            console.warn(`Column "${key}" not found in endpoint_datatable_columns. Some DataTable features may not work as expected.`);
            colIndexMap[key] = null;
        }
    });

    // Choose a safe default order column
    const defaultOrderIndex = (
        colIndexMap.content_length ??
        colIndexMap.response_time ??
        0
    );

    const endpointScrollerOpts = window.getRengineDatatableScrollerOptions
        ? window.getRengineDatatableScrollerOptions("60vh")
        : {};
    const endpointLayout = (window.getRengineDatatableLayoutFull && window.getRengineDatatableLayoutFull()) || window.RENGINE_DATATABLE_LAYOUT_FULL;
    const endpointTableOpts = Object.assign({
		destroy: true,
		processing: true,
        autoWidth: false,
        deferRender: true,
		language: { processing: "Processing... Please wait..." },
		layout: endpointLayout,
		lengthMenu: window.getRengineDatatableLengthMenu ? window.getRengineDatatableLengthMenu() : [[10, 20, 30, 50, 100, 200, 500, 1000, -1], ["10", "20", "30", "50", "100", "200", "500", "1000", "All"]],
		responsive: true,
		serverSide: true,
		ajax: { url: lookup_url },
		rowGroup: {
			startRender: function(rows, group) {
				return group + ' (' + rows.count() + ' Endpoints)';
			}
		},
        order: [[ defaultOrderIndex, "desc" ]],
        columns: endpoint_datatable_columns,
		initComplete: function(settings, json) {
			const tbl = $('#endpoint_results').DataTable();
			endpoint_datatable_col_visibility(tbl, endpoint_datatable_columns);
			$(".dtrg-group th:contains('No group')").remove();
			window.ScreenshotDisplay.attachDelegation('#endpoint_results');
		},
		drawCallback: function () {
			$("body").tooltip({ selector: '[data-toggle=tooltip]' });
			$('.badge').tooltip({ template: '<div class="tooltip status" role="tooltip"><div class="arrow"></div><div class="tooltip-inner"></div></div>' });
			$('.dtrg-group').remove();
			$('.bs-tooltip').tooltip();
            const clipboard = new Clipboard('.copyable');
			clipboard.on('success', function(e) {
				setTooltip(e.trigger, 'Copied!');
				hideTooltip(e.trigger);
			});
			setTimeout(function() {
				$(".dtrg-group th:contains('No group')").remove();
			}, 1);
		}
	}, endpointScrollerOpts);
    let endpoint_table;
    if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
        endpoint_table = window.initServerSideDataTable("#endpoint_results", window.getRengineDatatableConfig("#endpoint_results", endpointTableOpts));
    } else {
        if (typeof console !== "undefined" && console.warn) {
            console.warn("detail_scan: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
        }
        endpoint_table = $("#endpoint_results").DataTable(endpointTableOpts);
    }
    if (window.RengineAdvancedSearch && typeof window.RengineAdvancedSearch.registerDataTable === "function") {
        window.RengineAdvancedSearch.registerDataTable("endpoints", endpoint_table);
    } else {
        window.RENGINE_TABLES = window.RENGINE_TABLES || {};
        window.RENGINE_TABLES.endpoints = endpoint_table;
    }

    const endpointSnackbarMsg = typeof window.getRengineRowGroupSnackbarMessage === 'function'
        ? window.getRengineRowGroupSnackbarMessage('Grouping cleared', 'Endpoints grouped by {label}')
        : null;
    const endpointExpandPageLengthWhenGrouping = true;
    const endpointOrdersEqual = function(left, right) {
        if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
        for (let i = 0; i < left.length; i++) {
            const l = left[i];
            const r = right[i];
            if (!Array.isArray(l) || !Array.isArray(r) || l.length < 2 || r.length < 2) return false;
            if (Number(l[0]) !== Number(r[0])) return false;
            if (String(l[1]).toLowerCase() !== String(r[1]).toLowerCase()) return false;
        }
        return true;
    };
    const applyEndpointGrouping = function (value, showSnackbar) {
        const api = $('#endpoint_results').DataTable();
        if (value === '' || value == null) {
            api.rowGroup().disable();
            const contentLengthIdx = getColIdx(endpoint_datatable_columns, 'content_length');
            const responseTimeIdx = getColIdx(endpoint_datatable_columns, 'response_time');
            const defaultIdx = contentLengthIdx >= 0 ? contentLengthIdx : (responseTimeIdx >= 0 ? responseTimeIdx : 0);
            const defaultOrder = [[defaultIdx, 'desc']];
            if (!endpointOrdersEqual(api.order(), defaultOrder)) {
                api.order(defaultOrder).draw();
            }
            if (showSnackbar !== false && typeof Snackbar !== 'undefined' && Snackbar.show) {
                let msg = endpointSnackbarMsg ? endpointSnackbarMsg({ value: '', label: 'None' }) : 'Grouping cleared';
                if (typeof window.htmlEncode === 'function') msg = window.htmlEncode(msg);
                Snackbar.show({ text: msg, pos: 'top-right', duration: 2500 });
            }
            return;
        }
        const col_index = getColIdx(endpoint_datatable_columns, value);
        if (endpointExpandPageLengthWhenGrouping) {
            api.page.len(-1).draw();
        }
        api.order([[col_index, 'asc']]).draw();
        api.rowGroup().dataSrc(value);
        if (showSnackbar !== false && typeof Snackbar !== 'undefined' && Snackbar.show) {
            let msg = endpointSnackbarMsg ? endpointSnackbarMsg({ value: value, label: value }) : ('Endpoints grouped by ' + value);
            if (typeof window.safeText === 'function') msg = window.safeText(msg);
            Snackbar.show({ text: msg, pos: 'top-right', duration: 2500 });
        }
    };
    $('input[name=grouping_endpoint_row]').off('change').on('change', function () {
        if (!this.checked) return;
        applyEndpointGrouping(this.value, true);
    });
    const $checkedEndpointGroup = $('input[name=grouping_endpoint_row]:checked');
    if ($checkedEndpointGroup.length && ($checkedEndpointGroup.val() === '' || $checkedEndpointGroup.val() == null)) {
        applyEndpointGrouping('', false);
    }

    $('#endpoint-search-button').off('click').on('click', function () {
        endpoint_table.search($('#endpoints-search').val()).draw() ;
    });

    const filterBindings = [
        { checkbox: 'end_http_status_filter_checkbox', column: 'http_status' },
        { checkbox: 'end_page_title_filter_checkbox', column: 'page_title' },
        { checkbox: 'end_tags_filter_checkbox', column: 'matched_gf_patterns' },
        { checkbox: 'end_content_type_filter_checkbox', column: 'content_type' },
        { checkbox: 'end_content_length_filter_checkbox', column: 'content_length' },
        { checkbox: 'end_response_time_filter_checkbox', column: 'response_time' },
        { checkbox: 'end_screenshot_filter_checkbox', column: 'screenshot_url' },
    ];
    filterBindings.forEach(binding => {
        const selector = `input[name=${binding.checkbox}]`;
        $(selector).off('change').on('change', function() {
            const idx = getColIdx(endpoint_datatable_columns, binding.column);
            if (idx > -1) {
                endpoint_table.column(idx).visible($(this).is(':checked'));
            }
            window.localStorage.setItem(binding.checkbox, $(this).is(':checked'));
        });
    });
}

function get_subdomain_changes(endpoint, scan_history_id) {
	const opts = {
		destroy: true,
		responsive: true,
		serverSide: true,
		ajax: { url: endpoint + "?scan_id=" + encodeURIComponent(scan_history_id) + "&format=datatables" },
		order: [[3, "desc"]],
		columns: [
			{ data: "name" },
			{ data: "page_title" },
			{ data: "http_status" },
			{ data: "content_length" },
			{ data: "change" },
			{ data: "http_url" },
			{ data: "is_cdn" },
			{ data: "is_interesting" }
		],
		info: false,
		columnDefs: [
			{ targets: [5, 6, 7], visible: false, searchable: false },
			{ className: "text-center", targets: [2, 4] },
			{ targets: 0, render: renderSubdomainChangeNameCell },
			{ targets: 1, render: function (data) { return data ? (typeof window.safeText === "function" ? window.safeText(data) : data) : ""; } },
			{ targets: 2, render: renderHttpStatusBadgeSoft },
			{ targets: 3, render: function (data) { return data ? "<span class=\"text-center\" style=\"display:block; text-align:center; margin:0 auto;\">" + (typeof window.safeText === "function" ? window.safeText(data) : data) + "</span>" : ""; } },
			{ targets: 4, render: renderChangeAddedRemovedBadge }
		],
		drawCallback: function () {
			const api = typeof this.api === "function" ? this.api() : null;
			const pageInfo = api && typeof api.page.info === "function" ? api.page.info() : null;
			const total = pageInfo ? pageInfo.recordsTotal : 0;
			if (total > 0) {
				const totalStr = typeof window.safeText === "function" ? window.safeText(total) : total;
				const badgeHtml = detailScanSafeBadge(totalStr, "badge badge-soft-primary me-1", "");
				$("#subdomain_change_count").empty().html(badgeHtml);
				$(".recon-changes-tab-show").removeAttr("style");
				$("#subdomain_changes_alert").text(total + " Subdomain changes.");
			} else {
				$("#recon_changes_subdomain_div").remove();
			}
			$("#subdomain-changes-loader").remove();
		}
	};
	if ($.fn.DataTable.isDataTable("#table-subdomain-changes")) {
		$("#table-subdomain-changes").DataTable().destroy();
	}
	if (typeof window.initDetailScanServerSideTable === "function") {
		window.initDetailScanServerSideTable("#table-subdomain-changes", opts);
	} else if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
		window.initServerSideDataTable("#table-subdomain-changes", window.getRengineDatatableConfig("#table-subdomain-changes", opts));
	} else {
		if (typeof console !== "undefined" && console.warn) {
			console.warn("detail_scan: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
		}
		$("#table-subdomain-changes").DataTable(opts);
	}
}

function renderSubdomainChangeNameCell(data, type, row) {
	const linkOpts = { className: "text-primary", target: "_blank" };
	let badges = "";
	if (row.is_cdn) badges += detailScanSafeBadge("CDN", "m-1 badge badge-soft-warning", "");
	if (row.is_interesting) badges += detailScanSafeBadge("Interesting", "m-1 badge badge-soft-danger", "");
	if (badges) badges += "<br>";
	const safeTextFn = typeof window.safeText === "function" ? window.safeText : function (s) { return s == null ? "" : String(s); };
	const display = data != null ? data : "";
	if (row.http_url) {
		if (row.cname) {
			const cnameParts = String(row.cname).split(",").map(function (p) { return safeTextFn(p.trim()); }).join("<br><span class=\"text-warning\"> ❯ </span>");
			return badges + detailScanSafeLink(row.http_url, display, linkOpts) + "<br><span class=\"text-dark\">CNAME<br><span class=\"text-warning\"> ❯ </span>" + cnameParts + "</span>";
		}
		return badges + detailScanSafeLink(row.http_url, display, linkOpts);
	}
	return badges + detailScanSafeLink("https://" + (data || ""), display, linkOpts);
}

function renderHttpStatusBadgeSoft(data) {
	if (data >= 200 && data < 300) return detailScanSafeBadge(data, "badge badge-soft-success", "");
	if (data >= 300 && data < 400) return detailScanSafeBadge(data, "badge badge-soft-warning", "");
	if (data == 0) return "";
	return detailScanSafeBadge(data, "badge badge-soft-danger", "");
}

function renderChangeAddedRemovedBadge(data) {
	return data === "added"
		? detailScanSafeBadge("Added", "badge badge-soft-success", "fe-plus-circle")
		: detailScanSafeBadge("Removed", "badge badge-soft-danger", "fe-minus-circle");
}

function get_endpoint_changes(endpoint, scan_history_id) {
	const opts = {
		destroy: true,
		responsive: true,
		serverSide: true,
		ajax: { url: endpoint + "?scan_id=" + encodeURIComponent(scan_history_id) + "&format=datatables" },
		order: [[3, "desc"]],
		columns: [
			{ data: "http_url" },
			{ data: "page_title" },
			{ data: "http_status" },
			{ data: "content_length" },
			{ data: "change" }
		],
		info: false,
		columnDefs: [
			{ className: "text-center", targets: [2] },
			{ targets: 0, render: renderEndpointChangeUrlCell },
			{ targets: 2, render: renderHttpStatusBadgeSoft },
			{ targets: 4, render: renderChangeAddedRemovedBadge }
		],
		drawCallback: function () {
			const api = typeof this.api === "function" ? this.api() : null;
			const pageInfo = api && typeof api.page.info === "function" ? api.page.info() : null;
			const total = pageInfo ? pageInfo.recordsTotal : 0;
			if (total > 0) {
				$("#endpoint_change_count").empty().html(total);
				$(".recon-changes-tab-show").removeAttr("style");
			} else {
				$("#endpoint-changes-div").remove();
			}
			$("#endpoint-changes-loader").remove();
		}
	};
	if ($.fn.DataTable.isDataTable("#table-endpoint-changes")) {
		$("#table-endpoint-changes").DataTable().destroy();
	}
	if (typeof window.initDetailScanServerSideTable === "function") {
		window.initDetailScanServerSideTable("#table-endpoint-changes", opts);
	} else if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
		window.initServerSideDataTable("#table-endpoint-changes", window.getRengineDatatableConfig("#table-endpoint-changes", opts));
	} else {
		if (typeof console !== "undefined" && console.warn) {
			console.warn("detail_scan: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
		}
		$("#table-endpoint-changes").DataTable(opts);
	}
}

function renderEndpointChangeUrlCell(data) {
	const raw = (data && typeof data === "string") ? data : (data ? String(data) : "");
	const hrefUrl = (typeof window.normalizeSafeLinkUrl === "function" ? window.normalizeSafeLinkUrl(raw) : raw) || raw;
	const displayText = raw.length > 80 ? raw.slice(0, 77) + "..." : raw;
	return detailScanSafeLink(hrefUrl, displayText, { target: "_blank", className: "text-primary", title: raw });
}

function get_osint_users(scan_id){
	$.getJSON(`/api/queryOsintUsers/?scan_id=${scan_id}&format=json`, function(data) {
		$('#osint-users-count').empty();
		for (let val in data['users']){
			const user = data['users'][val];
			$("#osint-users").append(`<span class='badge badge-soft-info  m-1'>${user['author']}</span>`);
		}
		$('#osint-users-count').html(`<span class="badge badge-soft-primary">${data['users'].length}</span>`);
		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
	}).fail(function(){
		$('#osint-users-count').empty();
		$("#osint-users").append(`<p>No Users discovered.</p>`);
	});
}

function get_screenshot(endpoint, scan_id){
	const port_array = [];
	const service_array = [];
	const tech_array = [];
	const ip_array = [];
	const gridzyElement = document.querySelector('.gridzy');
	gridzyElement.classList.add('gridzySkinBlank');
	gridzyElement.setAttribute('data-gridzy-layout', 'waterfall');
	gridzyElement.setAttribute('data-gridzy-spaceBetween', 10);
	gridzyElement.setAttribute('data-gridzy-desiredwidth', 350);
	gridzyElement.setAttribute('data-gridzySearchField', "#screenshot-search");
	const interesting_badge = `<span class="m-1 float-end badge  badge-soft-danger">Interesting</span>`;
	// Use the screenshots API endpoint
	$.getJSON(`${endpoint}?scan_id=${scan_id}`, function(data) {
		$("#screenshot-loader").remove();
		$("#filter-screenshot").show();
		for (let subdomain in data) {
			const figure = document.createElement('figure');
			const link = document.createElement('a');
			// return `<a href="/media/`+data+`" data-lightbox="screenshots" data-title="&lt;a target='_blank' href='`+row['http_url']+`'&gt;&lt;h3 style=&quot;color:white&quot;&gt;`+row['name']+`&lt;/h3&gt;&lt;/a&gt;"><img src="/media/`+data+`" class="img-fluid rounded mb-4 mt-4 screenshot" onerror="removeImageElement(this)"></a>`;
			// currently lookup is supported only for http_status, page title & subdomain name,
			const interesting_field = data[subdomain]['is_interesting'] ? 'interesting' : '';
			const ips = data[subdomain]['ip_addresses'];
			let ip_search_values = '';
			for(let ip in ips){
				const ip_address = ips[ip]['address'];
				ip_search_values += ip_address + ' ';
			}
			let search_field = `${data[subdomain]['page_title']} ${data[subdomain]['name']} ${data[subdomain]['http_status']} ${ip_search_values} ${interesting_field}`;
			link.setAttribute('data-lightbox', 'screenshot-gallery');
			const screenshotUrl = data[subdomain]['screenshot_url'] || '';
			link.setAttribute('href', screenshotUrl);
			link.setAttribute('data-title', `<a target='_blank' href='`+data[subdomain]['http_url']+`'><h3 style="color:white">`+data[subdomain]['name']+`</h3></a>`);
			link.classList.add('img-fluid');
			link.classList.add('rounded');
			link.classList.add('screenshot-gallery');
			link.classList.add('mb-4');
			link.classList.add('mt-4');
			link.setAttribute('data-gridzySearchText', search_field);
			const newImage = document.createElement('img');
			newImage.setAttribute('data-gridzylazysrc', screenshotUrl);
			// newImage.setAttribute('data-gridzylazysrc', 'https://placeimg.com/1440/900/any?' + subdomain);
			newImage.setAttribute('height', 500);
			newImage.setAttribute('width', 500);
			newImage.setAttribute('class', 'gridzyImage');
			const figcaption = document.createElement('figcaption');
			figcaption.setAttribute('class', 'gridzyCaption');
			let http_status_badge = 'danger';
			if (data[subdomain]['http_status'] >=200 && data[subdomain]['http_status'] < 300){
				http_status_badge = 'success';
			}
			else if (data[subdomain]['http_status'] >=300 && data[subdomain]['http_status'] < 400){
				http_status_badge = 'warning';
			}
			const page_title = data[subdomain]['page_title'] ? data[subdomain]['page_title'] + '</br>': '' ;
			const portNum = data[subdomain]['port'];
			const showPortInLabel = portNum != null && portNum !== 80 && portNum !== 443;
			const linkLabel = showPortInLabel ? `${data[subdomain]['name']}:${portNum}` : data[subdomain]['name'];
			const linkHref = data[subdomain]['http_url'] || `https://${data[subdomain]['name']}${showPortInLabel ? ':' + portNum : ''}`;
			const subdomain_link = `<a href="${linkHref}" target="_blank">${linkLabel}</a>`;
			const portBadge = (portNum != null && showPortInLabel)
				? `<span class="m-1 float-end badge badge-soft-${data[subdomain]['port_is_uncommon'] === true ? 'danger' : 'primary'}">${portNum}</span>`
				: '';
			let http_status = data[subdomain]['http_status'] ? `<span class="m-1 float-end badge  badge-soft-${http_status_badge}">${data[subdomain]['http_status']}</span>` : '';
			figcaption.innerHTML = data[subdomain]['is_interesting']
				? page_title + subdomain_link + interesting_badge + http_status + portBadge
				: page_title + subdomain_link + http_status + portBadge;
			figure.appendChild(figcaption);
			link.appendChild(newImage);
			link.appendChild(figure);
			gridzyElement.appendChild(link);

			// add http status to filter values
			let filter_values = 'http_' + data[subdomain]['http_status'] + ' ';

			// dynamic filtering menu
			http_status = data[subdomain]['http_status'];
			const http_status_select = document.getElementById('http_select_filter');
			if(!$('#http_select_filter').find("option:contains('" + http_status + "')").length){
				const option = document.createElement('option');
				option.value = ".http_" + http_status;
				option.innerHTML = http_status;
				http_status_select.appendChild(option);
			}

			// ip, port and services filtering (ips already set at start of loop)
			for(let ip in ips){
				const ip_address = ips[ip]['address'];
				filter_values += 'ip_' + ip_address.replace(/\./g,"_") + ' ';
				if (ip_array.indexOf(ip_address) === -1){
					ip_array.push(ip_address);
				}

				const ports = ips[ip]['ports'];
				for(let port in ports){
					const port_number = ips[ip]['ports'][port]['number'];
					const service_name = ips[ip]['ports'][port]['service_name'];

					filter_values += 'port_' + port_number + ' ';
					if (port_array.indexOf(port_number) === -1){
						port_array.push(port_number);
					}

					filter_values += 'service_' + service_name + ' ';
					if (service_array.indexOf(service_name) === -1){
						service_array.push(service_name);
					}
				}
			}

			// technology stack filtering
			const technology = data[subdomain]['technologies'];
			for(let tech in technology){
				const tech_name = technology[tech]['name'];
				filter_values += 'tech_' + tech_name.replace(/ /g,"_").toLowerCase() + ' ';
				if (tech_array.indexOf(tech_name) === -1){
					tech_array.push(tech_name);
				}

			}

			link.setAttribute('class', filter_values);
		}

		// add port and service and tech to options
		const port_select = document.getElementById('ports_select_filter');
		if (port_select) {
			port_array.sort((a, b) => a - b);
			for(let port in port_array){
				if(!$('#ports_select_filter').find("option:contains('" + port_array[port] + "')").length){
					const option = document.createElement('option');
					option.value = ".port_" + port_array[port];
					option.innerHTML = port_array[port];
					port_select.appendChild(option);
				}
			}
		}

		// add ip to select
		const ip_select = document.getElementById('ips_select_filter');
		for(let ip in ip_array){
			if(!$('#ips_select_filter').find("option:contains('" + ip_array[ip] + "')").length){
				const option = document.createElement('option');
				option.value = ".ip_" + ip_array[ip];
				option.innerHTML = ip_array[ip];
				ip_select.appendChild(option);
			}
		}

		service_array.sort();
		const service_select = document.getElementById('services_select_filter');
		if (service_select) {
			for(let service in service_array){
				if(!$('#services_select_filter').find("option:contains('" + service_array[service] + "')").length){
					const option = document.createElement('option');
					option.value = ".service_" + service_array[service];
					option.innerHTML = service_array[service];
					service_select.appendChild(option);
				}
			}
		}

		const tech_select = document.getElementById('tech_select_filter');
		for(let tech in tech_array){
			if(!$('#tech_select_filter').find("option:contains('" + tech_array[tech] + "')").length){
				const option = document.createElement('option');
				option.value = ".tech_" + tech_array[tech].replace(/ /g,"_").toLowerCase();
				option.innerHTML = tech_array[tech];
				tech_select.appendChild(option);
			}
		}

		$(".tagging").select2({
			tags: true
		});
		// search functionality
		const gridzyElements = document.querySelectorAll('.gridzySkinBlank[data-gridzySearchField]');
		let pos = gridzyElements.length;

		while (pos--) {
			(function(gridzyElement) {
				const searchField = document.querySelector(gridzyElement.getAttribute('data-gridzySearchField'));
				const gridzyInstance = gridzyElement.gridzy;
				const gridzyItems = gridzyElement.children;

				const search = function() {
					let pos = gridzyItems.length,
					child,
					itemContent,
					found = false,
					searchValue = searchField.value.toLowerCase();

					if (searchValue) {
						while (pos--) {
							child = gridzyItems[pos];
							itemContent = (child.getAttribute('data-gridzySearchText') || child.innerText).toLowerCase();
							found = -1 < itemContent.search(searchValue);
							child.classList[found ? 'add' : 'remove']('searchResult');
						}
						if (gridzyInstance.getOption('filter') !== '.searchResult') {
							gridzyInstance.setOptions({filter:'.searchResult'});
						}
					} else {
						while (pos--) {
							gridzyItems[pos].classList.remove('searchResult');
						}
						if (gridzyInstance.getOption('filter') !== Gridzy.getDefaultOption('filter')) {
							gridzyInstance.setOptions({filter:null});
						}
					}
				};

				if (searchField) {
					searchField.addEventListener('input', search);
				}
			})(gridzyElements[pos]);
		}

		//filter functionality
		const gridzyInstance = document.querySelector('.gridzySkinBlank').gridzy;
		$('#http_select_filter, #ips_select_filter, #services_select_filter, #ports_select_filter, #tech_select_filter').on('change', function() {
			const values = $(this).val();
			if(values.length && this.id == 'ips_select_filter'){
				const replaces_str = values.map(function(values){return values.replace(/(?<=\..*)\./g, '_');});
				gridzyInstance.setOptions({
					filter: replaces_str
				});
			}
			else if(values.length && this.id != 'ips_select_filter'){
				gridzyInstance.setOptions({
					filter: values
				});
			}
			else{
				gridzyInstance.setOptions({
					filter: '*'
				});
			}
		});
	});
}

function get_metadata(scan_id){
	// populate detail table
	$.getJSON(`/api/queryMetadata/?scan_id=${scan_id}&format=json`, function(data) {
		$('#metadata-count').empty();
		$('#metadata-table-body').empty();
		for (let val in data['metadata']){
			const doc = data['metadata'][val];
			const rand_id = get_randid();
			$('#metadata-table-body').append(`<tr id=${rand_id}></tr>`);
			let filename;
			if (doc['doc_name']) {
				filename = `<a href=${doc['url']} target="_blank" class="text-primary">${truncate(doc['doc_name'], 30)}</a>`;
			}
			else{
				filename = ''
			}
			const subdomain = `<span class='text-muted bs-tooltip' title='Subdomain'>${doc['subdomain']['name']}</span>`;
			$(`#${rand_id}`).append(`<td class="td-content">${filename}</br>${subdomain}</td>`);
			if (doc['author']){
				$(`#${rand_id}`).append(`<td class="td-content text-center">${doc['author']}</td>`);
			}
			else{
				$(`#${rand_id}`).append('<td></td>')
			}
			if (doc['producer'] || doc['creator'] || doc['os']) {
				let metadata = '';
				metadata += doc['producer'] ? 'Software: ' + doc['producer'] : '';
				metadata += doc['creator'] ? '/' + doc['creator'] : 'dsdd';
				metadata += doc['os'] ? `<br> <span class='badge badge-soft-danger'> OS: ` + doc['os'] + '</span>': '';
				if (doc['creation_date']) {
					metadata += `<br>Created On: ${doc['creation_date']}`;
				}
				if (doc['modified_date']) {
					metadata += `<br>Modified On: ${doc['modified_date']}`;
				}
				$(`#${rand_id}`).append(`<td class="td-content">${metadata}</td>`);
			}
			else{
				$(`#${rand_id}`).append('<td></td>')
			}
		}
		$('#metadata-count').html(`<span class="badge badge-soft-primary">${data['metadata'].length}</span>`);
		$('.bs-tooltip').tooltip();
	});
}


function get_emails(scan_id){
	let exposed_count = 0;
	$.getJSON(`/api/queryEmails/?scan_id=${scan_id}&format=json`, function(data) {
		$('#emails-count').empty();
		$('#email-table-body').empty();
		for (let val in data['emails']){
			const email = data['emails'][val];
			const rand_id = get_randid();
			$('#email-table-body').append(`<tr id=${rand_id}></tr>`);
			$(`#${rand_id}`).append(`<td class="td-content">${email['address']}</td>`);
			if (email['password']) {
				$(`#${rand_id}`).append(`<td class="td-content"><span class="badge badge-soft-danger">${email['password']}</span></td>`);
				exposed_count++;
			}
		}
		$('#emails-count').html(`<span class="badge badge-soft-primary">${data['emails'].length}</span>`);
		if (exposed_count > 0 ) {
			$('#exposed_summary').html(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-triangle"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> <span class="badge badge-soft-danger">${exposed_count}</span> Exposed Credentials`);
		}
	});
}


function get_employees(scan_id){
	$.getJSON(`/api/queryEmployees/?scan_id=${scan_id}&format=json`, function(data) {
		$('#employees-count').empty();
		$('#employees-table-body').empty();
		for (let val in data['employees']){
			const emp = data['employees'][val];
			const rand_id = get_randid();
			$('#employees-table-body').append(`<tr id=${rand_id}></tr>`);
			$(`#${rand_id}`).append(`<td class="td-content">${emp['name']}</td>`);
			$(`#${rand_id}`).append(`<td class="td-content">${emp['designation']}</td>`);
		}
		$('#employees-count').html(`<span class="badge badge-soft-primary">${data['employees'].length}</span>`);
	});
}


function get_dorks(scan_id){
	$("#dorking_result_card").hide();
	$.getJSON(`/api/queryDorks/?scan_id=${scan_id}&format=json`, function(data) {
		if ($.isEmptyObject(data['dorks'])) {
			return
		}
		// unhide div
		$("#dork_type_vertical_tablist").empty();
		$("#dork_tab_content").empty();
		$("#dorking_result_card").show();
		let is_first = true;
		for (let val in data['dorks']){
			const dorks = data['dorks'][val];
			let active;
			if (is_first) {
				active = 'active show';
			}
			else {
				active = '';
			}
			$("#dork_type_vertical_tablist").append(`<a class="nav-link ${active} mb-1" id="v-${val}-tab" data-bs-toggle="pill" href="#v-${val}" role="tab" aria-controls="v-${val}" aria-selected="true"> ${convertToCamelCase(val)}</a>`);
			// create tab content
			let tab_content = `<div class="tab-pane fade ${active}" id="v-${val}" role="tabpanel" aria-labelledby="v-${val}-tab"><ul>`;
			for (let dork in dorks) {
				const dork_data = dorks[dork];
				tab_content += `<li><a href="${dork_data.url}" target="_blank">${dork_data.url}</a></li>`;
			}
			tab_content += `</ul></div>`;
			$('#dork_tab_content').append(tab_content);
			is_first = false;
		}
	});
}

//
// function get_dork_summary(scan_id){
// 	$.getJSON(`/api/queryDorkTypes/?scan_id=${scan_id}&format=json`, function(data) {
// 		$('#dork-category-count').empty();
// 		for (const val in data['dorks']){
// 			dork = data['dorks'][val]
// 			$("#osint-dork").append(`<span class='badge badge-soft-info  m-1' data-toggle="tooltip" title="${dork['count']} Results found in this dork category." onclick="get_dork_details('${dork['type']}', ${scan_id})">${dork['type']}</span>`);
// 		}
// 		$('#dork-category-count').html(`<span class="badge badge-soft-primary">${data['dorks'].length}</span>`);
// 		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
// 	});
// }


function get_dork_details(dork_type, scan_id) {
	const title = 'Dorking Results in category: <b>' + dork_type + '</b>';
	const loaderHtml = '<div class="outer-div" id="modal-loader"><span class="inner-div spinner-border text-primary align-self-center loader-sm"></span></div>';
	if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml: loaderHtml, footerHtml: '' });
	const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.queryDorks) || '/api/queryDorks/';
	const url = `${baseUrl}?scan_id=${scan_id}&type=${encodeURIComponent(dork_type)}&format=json`;
	$.getJSON(url, function (data) {
		let listHtml = '<ul id="dork-detail-modal-ul">';
		for (const dork_obj of data.dorks || []) {
			listHtml += `<li><a href="${dork_obj.url}" target="_blank" class="text-primary">${dork_obj.description}</a></li>`;
		}
		listHtml += '</ul>';
		const bodyHtml = `<b>${(data.dorks || []).length} results found in this dork category.</b>${listHtml}`;
		if (window.ModalManager) {
			ModalManager.setDialogTitle(title);
			ModalManager.setDialogLoading(bodyHtml);
		}
	}).fail(function () {
		if (window.ModalManager) ModalManager.setDialogLoading('<p class="text-danger">Error loading dork results.</p>');
	});
}


function get_vulnerability_modal(endpoint_url, scan_id=null, severity=null, subdomain_id=null, subdomain_name=null){
	const title = "Vulnerabilities for " + (subdomain_name || "");
	if (window.ModalManager) {
		ModalManager.setXlTitle(title);
		ModalManager.setXlContent({ bodyHtml: "", footerHtml: "" });
		if (!ModalManager.showXlOnly()) {
			$("#xl-modal-title").html(title);
			$("#xl-modal-content").empty();
			$("#xl-modal-footer").empty();
			ModalManager.showXlOnly();
		}
	} else {
		$("#xl-modal-title").html(title);
		$("#xl-modal-content").empty();
		$("#xl-modal-footer").empty();
		if (window.ModalManager) ModalManager.showXlOnly();
	}
	render_vulnerability_in_xl_modal(endpoint_url, scan_id, severity, subdomain_id, subdomain_name);
	$("body").tooltip({ selector: "[data-toggle=tooltip]" });
}


function get_endpoint_modal(endpoint_url, project, scan_id, subdomain_id, subdomain_name){
	const title = "Endpoints for " + (subdomain_name || "");
	if (window.ModalManager) {
		ModalManager.setXlTitle(title);
		ModalManager.setXlContent({ bodyHtml: "", footerHtml: "" });
		if (!ModalManager.showXlOnly()) {
			$("#xl-modal-title").html(title);
			$("#xl-modal-content").empty();
			$("#xl-modal-footer").empty();
			ModalManager.showXlOnly();
		}
	} else {
		$("#xl-modal-title").html(title);
		$("#xl-modal-content").empty();
		$("#xl-modal-footer").empty();
		if (window.ModalManager) ModalManager.showXlOnly();
	}
	render_endpoint_in_xl_modal(subdomain_id, subdomain_name, endpoint_url, project, scan_id);
	$("body").tooltip({ selector: "[data-toggle=tooltip]" });
}

function get_directory_modal(endpoint_url, scan_id=null, subdomain_id=null, subdomain_name=null){
	const title = "Directories for " + (subdomain_name || "");
	if (window.ModalManager) {
		ModalManager.setXlTitle(title);
		ModalManager.setXlContent({ bodyHtml: "", footerHtml: "" });
		if (!ModalManager.showXlOnly()) {
			$("#xl-modal-title").html(title);
			$("#xl-modal-content").empty();
			$("#xl-modal-footer").empty();
			ModalManager.showXlOnly();
		}
	} else {
		$("#xl-modal-title").html(title);
		$("#xl-modal-content").empty();
		$("#xl-modal-footer").empty();
		if (window.ModalManager) ModalManager.showXlOnly();
	}
	render_directories_in_xl_modal(endpoint_url, scan_id, subdomain_id, subdomain_name);
	$("body").tooltip({ selector: "[data-toggle=tooltip]" });
}

function escapeHtml(text) {
	if (typeof window !== 'undefined' && typeof window.safeText === 'function') {
		return window.safeText(text);
	}
	if (typeof window !== 'undefined' && window.CommandLogHelpers && window.CommandLogHelpers.escapeHtml) {
		return window.CommandLogHelpers.escapeHtml(text);
	}
	if (!text) return '';
	const div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

function getRunnerIcon(runnerType) {
	const normalizedRunnerType = String(runnerType || '').toLowerCase();
	if (normalizedRunnerType === 'scan') {
		return '<i class="fas fa-search me-2 text-primary"></i>';
	} else if (normalizedRunnerType === 'workflow') {
		return '<i class="fas fa-project-diagram me-2 text-info"></i>';
	} else if (normalizedRunnerType === 'task') {
		return '<i class="fas fa-tasks me-2 text-success"></i>';
	}
	return '<i class="fas fa-terminal me-2 text-secondary"></i>';
}

function getStatusBadge(status) {
	if (!status) return '';
	const H = (typeof window !== 'undefined' && window.CommandLogHelpers) || {};
	const info = H.getStatusBadgeInfo ? H.getStatusBadgeInfo(status) : null;
	if (info) {
		return `<span class="badge ${info.class}">${escapeHtml(info.text)}</span>`;
	}
	const s = String(status).toUpperCase();
	let badgeClass = 'secondary';
	let label = s;
	if (s === 'SUCCESS') {
		badgeClass = 'success';
	} else if (s === 'FAILURE' || s === 'FAILED') {
		badgeClass = 'danger';
		label = 'FAILED';
	} else if (s === 'RUNNING') {
		badgeClass = 'primary';
	} else if (s === 'REVOKED') {
		badgeClass = 'danger';
		label = 'ABORTED';
	} else if (s === 'SKIPPED') {
		badgeClass = 'info';
	}
	return `<span class="badge badge-soft-${badgeClass}">${escapeHtml(label)}</span>`;
}

function create_log_element(log) {
	const logElement = document.createElement("div");
	logElement.className = "command-log-entry mb-1";
	logElement.setAttribute("data-command-id", log.id);
	const runnerType = String(log.runner_type || '').toLowerCase();
	const commandName = log.name || log.workflow_name || '';
	if (runnerType) {
		logElement.setAttribute("data-runner-type", runnerType);
	}
	logElement.setAttribute("data-has-parent", (log.has_parent || false) ? 'true' : 'false');
	if (commandName) {
		logElement.setAttribute("data-command-name", commandName);
	}

	const displayName = (log.name && log.name.trim().length > 0) ? log.name : (log.command || 'Unknown');
	const hasParent = log.has_parent || false;
	const effectiveStatus = log.status_string != null && log.status_string !== '' ? log.status_string : log.status;

	// Build hierarchy prefix
	let hierarchyPrefix = '';
	if (hasParent) {
		hierarchyPrefix = '<span class="text-muted">└─</span> ';
	}

	// Get icon based on runner type
	const icon = getRunnerIcon(runnerType);

	// Build header: same structure as command_log.html (header > d-flex align-items-center gap-2 > icon, name, badge, duration)
	let innerFlexContent = `
			${icon}
			<span class="command-log-name fw-bold">
				${hierarchyPrefix}${escapeHtml(displayName)}
			</span>
			${getStatusBadge(effectiveStatus)}
	`;
	const durationSec = (typeof window !== 'undefined' && window.CommandLogHelpers && window.CommandLogHelpers.getDurationSeconds)
		? window.CommandLogHelpers.getDurationSeconds(log)
		: (log.elapsed != null && typeof log.elapsed === 'number' ? log.elapsed : null);
	if (durationSec != null) {
		innerFlexContent += `<span class="text-muted small command-log-header-duration">(${Number(durationSec).toFixed(2)}s)</span>`;
	}
	const headerHTML = `
		<div class="command-log-header" data-bs-toggle="collapse" data-bs-target="#collapse-command-${log.id}" style="cursor: pointer;">
			<div class="d-flex align-items-center gap-2">
				${innerFlexContent}
			</div>
		</div>`;
	
	// Build content
	let contentHTML = '';
	const hasOutput = log.output || (log.formatted_output && log.formatted_output.formatted);
	const hasCommand = log.command;
	const hasDetails = hasOutput || hasCommand || log.time || log.return_code !== null || log.cwd;
	
	if (hasDetails) {
		contentHTML = `<div class="collapse" id="collapse-command-${log.id}">
			<div class="card card-body mt-2">`;
		
		if (hasCommand) {
			contentHTML += `
				<div class="mb-2">
					<strong>Command:</strong>
					<code class="d-block mt-1 p-2 bg-light rounded">${escapeHtml(log.command)}</code>
				</div>`;
		}
		
		if (log.time) {
			contentHTML += `
				<div class="mb-2">
					<strong>Time:</strong> ${escapeHtml(log.time)}
				</div>`;
		}
		
		if (log.end_time) {
			contentHTML += `
				<div class="mb-2">
					<strong>End Time:</strong> ${escapeHtml(log.end_time)}
				</div>`;
		}
		
		const detailDurationSec = (typeof window !== 'undefined' && window.CommandLogHelpers && window.CommandLogHelpers.getDurationSeconds)
			? window.CommandLogHelpers.getDurationSeconds(log)
			: (log.elapsed != null && typeof log.elapsed === 'number' ? log.elapsed : null);
		if (detailDurationSec != null) {
			const durStr = (typeof window !== 'undefined' && window.CommandLogHelpers && window.CommandLogHelpers.formatDuration)
				? window.CommandLogHelpers.formatDuration(detailDurationSec)
				: (typeof log.elapsed === 'number' ? log.elapsed.toFixed(1) + 's' : String(log.elapsed) + 's');
			contentHTML += `
				<div class="mb-2">
					<strong>Duration:</strong> ${escapeHtml(durStr)}
				</div>`;
		}
		
		if (log.return_code !== null && log.return_code !== undefined) {
			const returnCodeClass = log.return_code === 0 ? 'success' : 'danger';
			contentHTML += `
				<div class="mb-2">
					<strong>Return Code:</strong> 
					<span class="badge badge-soft-${returnCodeClass}">${log.return_code}</span>
				</div>`;
		}
		
		if (log.cwd) {
			contentHTML += `
				<div class="mb-2">
					<strong>Working Directory:</strong> <code>${escapeHtml(log.cwd)}</code>
				</div>`;
		}
		
		if (hasOutput) {
			contentHTML += `
				<div class="mb-2">
					<strong>Output:</strong>
					<pre class="command-output mt-2 p-3 bg-dark text-light rounded" style="font-family: 'Courier New', monospace; font-size: 0.875rem; white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">`;
			
			// Use formatted output if available, otherwise use raw output
			if (log.formatted_output && log.formatted_output.formatted) {
				const rawFormatted = log.formatted_output.formatted;
				const safeFormatted = (typeof DOMPurify !== 'undefined' && DOMPurify.sanitize)
					? DOMPurify.sanitize(rawFormatted, { ALLOWED_TAGS: ['span', 'br'], ALLOWED_ATTR: ['class'] })
					: escapeHtml(rawFormatted);
				contentHTML += safeFormatted;
			} else if (log.output) {
				contentHTML += escapeHtml(log.output);
			}
			
			contentHTML += `</pre>
				</div>`;
		}
		
		if (log.errors && Array.isArray(log.errors) && log.errors.length > 0) {
			contentHTML += `
				<div class="mb-2">
					<strong class="text-danger">Errors:</strong>
					<ul class="list-unstyled ms-3">`;
			log.errors.forEach(error => {
				contentHTML += `<li class="text-danger">${escapeHtml(String(error))}</li>`;
			});
			contentHTML += `</ul>
				</div>`;
		}
		
		if (log.warnings && Array.isArray(log.warnings) && log.warnings.length > 0) {
			contentHTML += `
				<div class="mb-2">
					<strong class="text-warning">Warnings:</strong>
					<ul class="list-unstyled ms-3">`;
			log.warnings.forEach(warning => {
				contentHTML += `<li class="text-warning">${escapeHtml(String(warning))}</li>`;
			});
			contentHTML += `</ul>
				</div>`;
		}
		
		contentHTML += `
			</div>
		</div>`;
	}
	
	const combinedHtml = headerHTML + contentHTML;
	logElement.innerHTML = (typeof DOMPurify !== 'undefined' && DOMPurify.sanitize)
		? DOMPurify.sanitize(combinedHtml, { ALLOWED_TAGS: ['div', 'span', 'strong', 'code', 'pre', 'ul', 'li', 'br'], ALLOWED_ATTR: ['class', 'id', 'style', 'data-bs-toggle', 'data-bs-target', 'aria-expanded'] })
		: combinedHtml;
	return logElement;
}

if (typeof window !== 'undefined') {
	window.create_log_element = create_log_element;
}

function get_logs_modal(scan_id = null, activity_id = null, project_slug = null, runner_id = null) {
	const slug = project_slug || (typeof current_project_slug !== 'undefined' ? current_project_slug : '');
	const explicitScanId =
		scan_id != null && scan_id !== '' && !Number.isNaN(parseInt(String(scan_id), 10))
			? parseInt(String(scan_id), 10)
			: null;
	const activityIdNum =
		activity_id != null && activity_id !== '' && !Number.isNaN(parseInt(String(activity_id), 10))
			? parseInt(String(activity_id), 10)
			: null;
	const hasActivityFocus = activityIdNum != null;
	let contextScanId = explicitScanId;
	if (contextScanId == null && !hasActivityFocus) {
		const summaryInput = document.getElementById('summary_identifier_val');
		if (summaryInput && summaryInput.value) {
			const parsed = parseInt(summaryInput.value, 10);
			if (!Number.isNaN(parsed)) {
				contextScanId = parsed;
			}
		}
	}
	const hasScanContext = contextScanId != null;

	let url;
	let title;
	if (hasActivityFocus) {
		url = `/scan/${slug}/logs/?activity_id=${encodeURIComponent(activityIdNum)}`;
		title = `Logs for activity #${activityIdNum}`;
	} else if (hasScanContext) {
		url = `/scan/${slug}/logs/?scan_id=${encodeURIComponent(contextScanId)}`;
		title = `Logs for scan #${contextScanId}`;
	} else {
		url = `/scan/${slug}/logs/`;
		title = 'Logs';
	}

	const loadingTitle = 'Fetching logs...';
	const loadingBody = '<p class="text-muted">Loading...</p>';
	if (window.ModalManager) {
		ModalManager.setXlTitle(loadingTitle);
		ModalManager.setXlLoading(loadingBody);
		ModalManager.setXlContent({ footerHtml: '' });
		if (!ModalManager.showXlOnly()) {
			$('#xl-modal-title').html(loadingTitle);
			$('#xl-modal-content').html(loadingBody);
			$('#xl-modal-footer').html('');
			ModalManager.showXlOnly();
		}
	} else {
		$('#xl-modal-title').html(loadingTitle);
		$('#xl-modal-content').html(loadingBody);
		$('#xl-modal-footer').html('');
		if (window.ModalManager) ModalManager.showXlOnly();
	}

	fetch(url)
		.then(response => {
			if (!response.ok) {
				throw new Error(`HTTP error! status: ${response.status}`);
			}
			return response.text();
		})
		.then(html => {
			const bodyHtml = (html && html.trim()) ? html : '<p class="text-muted">No logs available.</p>';
			if (window.ModalManager) {
				ModalManager.setXlContent({ title, bodyHtml });
			} else {
				$('#xl-modal-title').html(title);
				$('#xl-modal-content').html(bodyHtml);
				if (window.ModalManager) ModalManager.showXlOnly();
			}
			if (hasActivityFocus || hasScanContext) {
				const runnerIdNum =
					runner_id != null &&
					runner_id !== '' &&
					!Number.isNaN(parseInt(String(runner_id), 10))
						? parseInt(String(runner_id), 10)
						: null;
				window.currentLogsModalContext = {
					isOpen: true,
					activity_id: hasActivityFocus ? activityIdNum : null,
					runner_id: hasActivityFocus ? runnerIdNum : null,
					scan_id: hasActivityFocus ? null : contextScanId,
				};
			} else {
				window.currentLogsModalContext = null;
			}
			if (hasActivityFocus) {
				const runExpandCollapses = function () {
					const modalContent = document.getElementById('xl-modal-content');
					if (!modalContent) return;
					const collapseElements = modalContent.querySelectorAll('.collapse');
					collapseElements.forEach(function (collapseElement) {
						const id = collapseElement.id;
						if (!id) return;
						collapseElement.classList.add('show');
						const trigger = modalContent.querySelector(
							'.command-log-header[data-bs-target="#' + id + '"]'
						);
						if (trigger) {
							trigger.setAttribute('aria-expanded', 'true');
						}
						if (typeof bootstrap !== 'undefined' && bootstrap.Collapse) {
							try {
								let bsCollapse = bootstrap.Collapse.getInstance(collapseElement);
								if (!bsCollapse) {
									bsCollapse = new bootstrap.Collapse(collapseElement, { toggle: false });
								}
								bsCollapse.show();
							} catch (e) {
								collapseElement.classList.add('show');
							}
						} else if (typeof $ !== 'undefined' && $.fn.collapse) {
							$(collapseElement).collapse('show');
						}
					});
				};
				setTimeout(function () {
					requestAnimationFrame(runExpandCollapses);
				}, 250);
			}
			$("body").tooltip({ selector: '[data-toggle=tooltip]' });
		})
		.catch(error => {
			console.error('Error fetching logs:', error);
			const errBody = '<p class="text-danger">Error loading logs. Please try again.</p>';
			if (window.ModalManager) {
				ModalManager.setXlContent({ title, bodyHtml: errBody });
			} else {
				$('#xl-modal-title').html(title);
				$('#xl-modal-content').html(errBody);
				if (window.ModalManager) ModalManager.showXlOnly();
			}
			$("body").tooltip({ selector: '[data-toggle=tooltip]' });
		});
}

function add_todo_for_scanhistory_modal(scan_history_id){
	$("#todoTitle").val('');
	$("#todoDescription").val('');

	if (window.ModalManager) ModalManager.showById(ModalManager.MODAL_IDS.ADD_TASK);
	subdomain_dropdown = document.getElementById('todoSubdomainDropdown');
	$.getJSON(`/api/querySubdomains?scan_id=${scan_history_id}&no_lookup_interesting&format=json`, function(data) {
		document.querySelector("#selectedSubdomainCount").innerHTML = data['subdomains'].length + ' Subdomains';
		for (const subdomain in data['subdomains']){
			const subdomain_obj = data['subdomains'][subdomain];
			const option = document.createElement('option');
			option.value = subdomain_obj['id'];
			option.textContent = subdomain_obj['name'];
			subdomain_dropdown.appendChild(option);
		}
	});
}

// listen to save todo event

$(".add-scan-history-todo").click(function(){
	const title = document.getElementById('todoTitle').value;

	const description = document.getElementById('todoDescription').value;

	const data = {
		'title': title,
		'description': description
	};


	const scan_id = parseInt(document.getElementById('summary_identifier_val').value);
	data['scan_history_id'] = scan_id;

	if ($("#todoSubdomainDropdown").val() != 'Choose Subdomain...') {
		data['subdomain_id'] = parseInt($("#todoSubdomainDropdown").val());
	}

	fetch('/api/add/recon_note/', {
		method: 'post',
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	}).then(res => res.json())
	.then(function (response) {
		if (response.status) {
			Snackbar.show({
				text: 'To-do Added.',
				pos: 'top-right',
				duration: 1500,
			});
		}
		else{
			Swal.fire("Error!", "Could not add recon note, " + response.message, "warning", {
				button: "Okay",
			});
		}
		if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.ADD_TASK);
		get_recon_notes(null, scan_id);
	});
});


function add_note_for_subdomain(subdomain_id, subdomain_name, current_project){
	const projectSlug = current_project !== undefined && current_project !== null
		? current_project
		: (document.body.dataset.projectSlug || '');
	$('#todo-modal-subdomain-name').text(subdomain_name);
	$("#subdomainTodoTitle").val('');
	$("#subdomainTodoDescription").val('');
	$('#add-todo-subdomain-submit-button').data('subdomainId', subdomain_id).data('ipAddressId', null).data('projectSlug', projectSlug);
	if (window.ModalManager) ModalManager.showById(ModalManager.MODAL_IDS.ADD_SUBDOMAIN_TASK);
}

function add_note_for_ip_address(ip_address_id, address, current_project){
	const projectSlug = current_project !== undefined && current_project !== null
		? current_project
		: (document.body.dataset.projectSlug || '');
	$('#todo-modal-subdomain-name').text(address || ('IP #' + ip_address_id));
	$("#subdomainTodoTitle").val('');
	$("#subdomainTodoDescription").val('');
	$('#add-todo-subdomain-submit-button').data('ipAddressId', ip_address_id).data('subdomainId', null).data('projectSlug', projectSlug);
	if (window.ModalManager) ModalManager.showById(ModalManager.MODAL_IDS.ADD_SUBDOMAIN_TASK);
}

$(function() {
	$(document.body).on('click', '.js-logs-modal-link', function(e) {
		e.preventDefault();
		const el = e.currentTarget;
		const scanId = el.dataset.scanId ? parseInt(el.dataset.scanId, 10) : null;
		const activityId = el.dataset.activityId ? parseInt(el.dataset.activityId, 10) : null;
		const runnerId = el.dataset.runnerId ? parseInt(el.dataset.runnerId, 10) : null;
		const projectSlug = document.body.dataset.projectSlug || null;
		get_logs_modal(scanId, activityId, projectSlug, runnerId);
	});
	$(document.body).on('click', '.js-add-target-link', function(e) {
		e.preventDefault();
		const el = e.currentTarget;
		const url = el.dataset.addTargetUrl;
		const domain = el.dataset.domain;
		const slug = document.body.dataset.projectSlug || '';
		if (url && domain && typeof add_target === 'function') {
			add_target(url, slug, domain);
		}
	});
	$(document.body).on('click', '.js-add-note-subdomain', function(e) {
		e.preventDefault();
		const el = e.currentTarget;
		const subdomainId = el.dataset.subdomainId ? parseInt(el.dataset.subdomainId, 10) : null;
		const subdomainName = el.dataset.subdomainName || '';
		if (subdomainId !== null) {
			add_note_for_subdomain(subdomainId, subdomainName);
		}
	});
	$(document.body).on('click', '.js-add-note-ip', function(e) {
		e.preventDefault();
		const el = e.currentTarget;
		const ipAddressId = el.dataset.ipAddressId ? parseInt(el.dataset.ipAddressId, 10) : null;
		const address = el.dataset.ipAddress || '';
		const slugAttr = el.getAttribute('data-project-slug');
		const projectSlug = slugAttr !== null ? slugAttr : undefined;
		if (ipAddressId !== null && !isNaN(ipAddressId)) {
			add_note_for_ip_address(ipAddressId, address, projectSlug);
		}
	});
	$('#add-todo-subdomain-submit-button').on('click', function() {
		const subdomainId = $(this).data('subdomainId');
		const ipAddressId = $(this).data('ipAddressId');
		const projectSlug = $(this).data('projectSlug');
		if (projectSlug !== undefined) {
			if (ipAddressId !== undefined && ipAddressId !== null) {
				add_note_for_ip_address_handler(ipAddressId, projectSlug);
			} else if (subdomainId !== undefined && subdomainId !== null) {
				add_note_for_subdomain_handler(subdomainId, projectSlug);
			}
		}
	});
});


function add_note_for_subdomain_handler(subdomain_id, current_project){
	const title = document.getElementById('subdomainTodoTitle').value;
	const description = document.getElementById('subdomainTodoDescription').value;
	const scan_id = parseInt(document.getElementById('summary_identifier_val').value);

	const data = {
		'title': title,
		'description': description,
		'subdomain_id': subdomain_id,
		'project': current_project,
		'scan_history_id': scan_id
	};

	fetch('/api/add/recon_note/', {
		method: 'post',
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	}).then(res => res.json())
	.then(function (response) {

		if (response.status) {
			Snackbar.show({
				text: 'To-do Added.',
				pos: 'top-right',
				duration: 1500,
			});
		}
		else{
			Swal.fire("Error!", response.message, "warning", {
				button: "Okay",
			});
		}
		$('#subdomain_scan_results').DataTable().ajax.reload();
		if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.ADD_SUBDOMAIN_TASK);
	});

}

function add_note_for_ip_address_handler(ip_address_id, current_project){
	const title = document.getElementById('subdomainTodoTitle').value;
	const description = document.getElementById('subdomainTodoDescription').value;
	const scan_id = parseInt(document.getElementById('summary_identifier_val').value);

	const data = {
		'title': title,
		'description': description,
		'ip_address_id': ip_address_id,
		'project': current_project,
		'scan_history_id': scan_id
	};

	fetch('/api/add/recon_note/', {
		method: 'post',
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	}).then(res => res.json())
	.then(function (response) {

		if (response.status) {
			Snackbar.show({
				text: 'To-do Added.',
				pos: 'top-right',
				duration: 1500,
			});
		}
		else{
			Swal.fire("Error!", response.message, "warning", {
				button: "Okay",
			});
		}
		if ($('#ip_scan_results').length && $('#ip_scan_results').DataTable) {
			try { $('#ip_scan_results').DataTable().ajax.reload(); } catch (e) {}
		}
		if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.ADD_SUBDOMAIN_TASK);
	});

}

function download_subdomains(scan_id = null, domain_id = null, domain_name = null) {
	Swal.fire({ title: 'Querying Subdomains...' });
	Swal.showLoading();
	const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.querySubdomains) || '/api/querySubdomains/';
	let url = `${baseUrl}?format=json&no_lookup_interesting`;
	if (scan_id) url += `&scan_id=${scan_id}`;
	else if (domain_id) url += `&target_id=${domain_id}`;
	$.getJSON(url, function (data) {
		Swal.close();
		const list = data.subdomains || [];
		if (list.length) {
			const count = list.length;
			const subdomains = list.map(s => s.name).join('\n');
			const title = `<span class="modal_count">${count}</span> Subdomains for : <b>${domain_name || ''}</b>`.trim() || `<span class="modal_count">${count}</span> Subdomains`;
			const bodyHtml = `<textarea class="form-control clipboard copy-txt" id="all_subdomains_text_area" rows="10" spellcheck="false">${subdomains}</textarea>`;
			const footerHtml = `<a href="javascript:download('subdomains-${domain_name || 'all'}.txt', document.getElementById('all_subdomains_text_area').value);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a><a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`;
			if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml, footerHtml });
		} else {
			Swal.fire('No Subdomains', 'Could not find any subdomains.', 'warning', { button: 'Okay' });
		}
	}).fail(function () {
		Swal.fire('No Subdomains', 'Could not find any subdomains.', 'warning', { button: 'Okay' });
	});
}

function download_interesting_subdomains(project, scan_id = null, domain_id = null, domain_name = null) {
	Swal.fire({ title: 'Querying Interesting Subdomains...' });
	Swal.showLoading();
	const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.queryInterestingSubdomains) || '/api/queryInterestingSubdomains/';
	let url = `${baseUrl}?format=json&project=${encodeURIComponent(project)}`;
	if (scan_id) url += `&scan_id=${scan_id}`;
	else if (domain_id) url += `&target_id=${domain_id}`;
	$.getJSON(url, function (data) {
		Swal.close();
		const list = Array.isArray(data) ? data : [];
		if (list.length) {
			const count = list.length;
			const subdomains = list.map(s => s.name).join('\n');
			const title = `<span class="modal_count">${count}</span> Interesting Subdomains for : <b>${domain_name || ''}</b>`.trim() || `<span class="modal_count">${count}</span> Interesting Subdomains`;
			const bodyHtml = `<textarea class="form-control clipboard copy-txt" id="interesting_subdomains_text_area" rows="10" spellcheck="false">${subdomains}</textarea>`;
			const footerHtml = `<a href="javascript:download('interesting_subdomains-${domain_name || 'all'}.txt', document.getElementById('interesting_subdomains_text_area').value);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a><a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#interesting_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`;
			if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml, footerHtml });
		} else {
			Swal.fire('No Interesting Subdomains', 'Could not find any interesting subdomains.', 'warning', { button: 'Okay' });
		}
	}).fail(function () {
		Swal.fire('No Interesting Subdomains', 'Could not find any interesting subdomains.', 'warning', { button: 'Okay' });
	});
}

function download_interesting_endpoints(scan_id, domain_name) {
	Swal.fire({ title: 'Querying Interesting Endpoints...' });
	Swal.showLoading();
	const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.interestingEndpointsList) || '/api/listInterestingEndpoints/';
	const url = scan_id ? `${baseUrl}?scan_id=${scan_id}&format=json&no_page` : `${baseUrl}?format=json&no_page`;
	$.getJSON(url, function (data) {
		Swal.close();
		const list = Array.isArray(data) ? data : [];
		if (list.length) {
			const count = list.length;
			const endpoints = list.map(e => e.http_url).join('\n');
			const title = `<span class="modal_count">${count}</span> Interesting Endpoints for : <b>${domain_name || ''}</b>`.trim() || `<span class="modal_count">${count}</span> Interesting Endpoints`;
			const bodyHtml = `<textarea class="form-control clipboard copy-txt" id="interesting_endpoints_text_area" rows="10" spellcheck="false">${endpoints}</textarea>`;
			const footerHtml = `<a href="javascript:download('interesting_endpoints-${domain_name || 'all'}.txt', document.getElementById('interesting_endpoints_text_area').value);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a><a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Endpoints!" data-clipboard-target="#interesting_endpoints_text_area"><i class="fe-copy me-1"></i> Copy Endpoints</a>`;
			if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml, footerHtml });
		} else {
			Swal.fire('No Interesting Endpoints', 'Could not find any interesting Endpoints.', 'warning', { button: 'Okay' });
		}
	}).fail(function () {
		Swal.fire('No Interesting Endpoints', 'Could not find any interesting Endpoints.', 'warning', { button: 'Okay' });
	});
}


function download_important_subdomains(scan_id = null, domain_id = null, domain_name = null) {
	Swal.fire({ title: 'Querying Interesting Subdomains...' });
	Swal.showLoading();
	const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.querySubdomains) || '/api/querySubdomains/';
	let url = `${baseUrl}?format=json&no_lookup_interesting&only_important`;
	if (scan_id) url += `&scan_id=${scan_id}`;
	else if (domain_id) url += `&target_id=${domain_id}`;
	$.getJSON(url, function (data) {
		Swal.close();
		const list = (data && data.subdomains) || [];
		if (list.length) {
			const count = list.length;
			const subdomains = list.map(s => s.name).join('\n');
			const title = `<span class="modal_count">${count}</span> Subdomains marked as important : <b>${domain_name || ''}</b>`.trim() || `<span class="modal_count">${count}</span> Subdomains marked as important`;
			const bodyHtml = `<textarea class="form-control clipboard copy-txt" id="all_subdomains_text_area" rows="10" spellcheck="false">${subdomains}</textarea>`;
			const footerHtml = `<a href="javascript:download('important-subdomains-${domain_name || 'all'}.txt', document.getElementById('all_subdomains_text_area').value);" class="m-1 btn btn-primary copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a><a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-dark copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`;
			if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml, footerHtml });
		} else {
			Swal.fire('No Important Endpoints', 'No subdomains has been marked as important.', 'warning', { button: 'Okay' });
		}
	}).fail(function () {
		Swal.fire('No Important Endpoints', 'No subdomains has been marked as important.', 'warning', { button: 'Okay' });
	});
}

function download_endpoints(scan_id = null, domain_id = null, domain_name = '', pattern = null) {
	Swal.fire({ title: 'Querying Endpoints...' });
	Swal.showLoading();
	const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.queryEndpoints) || '/api/queryEndpoints/';
	let url = `${baseUrl}?format=json&only_urls`;
	if (scan_id) url += `&scan_id=${scan_id}`;
	else if (domain_id) url += `&target_id=${domain_id}`;
	if (pattern) url += `&pattern=${encodeURIComponent(pattern)}`;
	$.getJSON(url, function (data) {
		Swal.close();
		const list = (data && data.endpoints) || [];
		const count = list.length;
		const endpoints = list.map(e => e.http_url).join('\n');
		const title = `<span class="modal_count">${count}</span> Endpoints for : <b>${domain_name || ''}</b>`.trim() || `<span class="modal_count">${count}</span> Endpoints`;
		const bodyHtml = `<textarea class="form-control clipboard copy-txt" id="all_endpoints_text_area" rows="10" spellcheck="false">${endpoints}</textarea>`;
		const downloadLabel = domain_name ? `endpoints-${domain_name}.txt` : 'endpoints-all.txt';
		const footerHtml = `<a href="javascript:download('${downloadLabel}', document.getElementById('all_endpoints_text_area').value);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a><a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Endpoints!" data-clipboard-target="#all_endpoints_text_area"><i class="fe-copy me-1"></i> Copy Endpoints</a>`;
		if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml, footerHtml });
	}).fail(function () {});
}

function initiate_subscan(subdomain_ids){
	const data = {};
	const ipRaw = $('#subtask_ip_address_id').val();
	const ipId = ipRaw ? parseInt(ipRaw, 10) : 0;
	if (ipId > 0) {
		data.ip_address_ids = [ipId];
	} else {
		data.subdomain_ids = subdomain_ids;
	}
	
	// Get execution mode from selected card in subscan modal
	const executionMode = $('#subscan-modal .execution-mode-card.selected').data('mode');
	if (!executionMode) {
		Swal.fire({
			title: 'Oops!',
			text: 'Please select an execution mode (Workflow, Tasks, or Scan)!',
			icon: 'error'
		});
		return;
	}
	
	// Get selection based on execution mode from subscan modal container
	const $container = $('#subscan-selection-container');
	
	if (executionMode === 'workflow') {
		const workflowId = $container.find('input[name="workflow_id"]:checked').val();
		if (!workflowId) {
			Swal.fire({
				title: 'Oops!',
				text: 'Please select a workflow!',
				icon: 'error'
			});
			return;
		}
		data['workflow_id'] = parseInt(workflowId);
	} else if (executionMode === 'tasks') {
		const taskNames = [];
		$container.find('input[name="task_ids"]:checked').each(function(){
			const taskType = $(this).attr('data-task-type') || $(this).closest('.task-tile').attr('data-task-type');
			if (taskType) {
				taskNames.push(taskType);
			}
		});
		if (taskNames.length === 0) {
			Swal.fire({
				title: 'Oops!',
				text: 'Please select at least one task!',
				icon: 'error'
			});
			return;
		}
		data['task_names'] = taskNames;
		const selectedTargetsPerTask = {};
		$('#subscan-modal').find('.secator-task-targets-block[data-task-type]').each(function() {
			const taskType = $(this).attr('data-task-type');
			if (!taskType) return;
			const targets = [];
			$(this).find('.subscan-target-checkbox:checked').each(function() {
				targets.push($(this).val());
			});
			selectedTargetsPerTask[taskType] = targets;
		});
		if (Object.keys(selectedTargetsPerTask).length > 0) {
			data['selected_targets_per_task'] = selectedTargetsPerTask;
		}
	} else if (executionMode === 'scan') {
		const scanType = $container.find('input[name="secator_scan_type"]:checked').val();
		if (!scanType) {
			Swal.fire({
				title: 'Oops!',
				text: 'Please select a scan type!',
				icon: 'error'
			});
			return;
		}
		data['secator_scan_type'] = scanType;
	}
	
	// Get secator_config (profiles, proxy, delay, scalar params) from modal, same logic as start scan
	let secatorConfig = { proxy: '', delay: 0, profiles: [] };
	if (window.SecatorScan && typeof window.SecatorScan.collectSecatorConfigFromScope === 'function') {
		secatorConfig = window.SecatorScan.collectSecatorConfigFromScope($('#subscan-modal'));
	}
	data['secator_config'] = secatorConfig;

	const $scanHistoryIdEl = $('#subscan_scan_history_id');
	if ($scanHistoryIdEl.length && $scanHistoryIdEl.val()) {
		data['scan_history_id'] = parseInt($scanHistoryIdEl.val(), 10);
	}

	const workerIdEl = document.querySelector('#subscan-modal select[name="worker_id"]');
	if (workerIdEl && workerIdEl.value && String(workerIdEl.value).trim() !== '') {
		const parsed = parseInt(workerIdEl.value, 10);
		if (!Number.isNaN(parsed) && parsed > 0) {
			data.worker_id = parsed;
		}
	}

	Swal.fire({
		title: 'Initiating subscan...',
		text: 'Using Secator ' + executionMode,
		allowOutsideClick: false
	});
	Swal.showLoading();
	
	fetch('/api/action/initiate/subtask/', {
		method: 'POST',
		credentials: "same-origin",
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	})
	.then(response => response.json())
	.then(function (response) {
		Swal.close();
		if (response['status']) {
			const message = response['message'] || 'Subscan initiated successfully!';
			Snackbar.show({
				text: message,
				pos: 'top-right',
				duration: 3000
			});
			
			// Show detailed results if available
			if (response['results'] && response['results'].length > 0) {
				const successCount = response['results'].filter(r => r.status === 'success').length;
				const errorCount = response['results'].filter(r => r.status === 'error').length;
				
				if (errorCount > 0) {
					Swal.fire({
						title: 'Subscan Results',
						html: `Successfully initiated: ${successCount}<br/>Errors: ${errorCount}`,
						icon: 'warning'
					});
				}
			}
		}
		else{
			Swal.fire({
				title: 'Could not initiate subscan!',
				text: response['error'] || 'Unknown error occurred',
				icon: 'error',
			});
		}
	})
	.catch(function(error) {
		Swal.close();
		Swal.fire({
			title: 'Network Error',
			text: 'Failed to communicate with server',
			icon: 'error'
		});
	});
}


// initiate sub scan
$('#btn-initiate-subtask').on('click', function(){
	if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.SUBSCAN);
	if ($('#btn-initiate-subtask').attr('multiple-subscan') === 'true') {
		const subdomain_item = document.getElementsByClassName("subdomain_checkbox");
		const subdomain_ids = [];
		for (let i = 0; i < subdomain_item.length; i++) {
			if (subdomain_item[i].checked) {
				subdomain_ids.push($(subdomain_item[i]).val());
			}
		}
		initiate_subscan(subdomain_ids);
	}
	else{
		const ipRaw = $('#subtask_ip_address_id').val();
		const ipId = ipRaw ? parseInt(ipRaw, 10) : 0;
		if (ipId > 0) {
			initiate_subscan([]);
		} else {
			const subdomain_id = $('#subtask_subdomain_id').val();
			initiate_subscan([subdomain_id]);
		}
	}
});


$('#subscan-modal').on('shown.bs.modal', function() {
    // Reset modal state
    $('#subscan-modal .execution-mode-card').removeClass('selected');
    $('#subscan-selection-container').empty();
});

// download subdomains
function downloadSelectedSubdomains(domain_name){
	if (!checkedCount()) {
		Swal.fire({
			title: 'Oops! No Subdomains has been selected!',
			icon: 'error',
			padding: '2em'
		})
	} else {
		Swal.fire({
			title: 'Querying Selected Subdomains...'
		});
		Swal.showLoading();

		const subdomain_item = document.getElementsByClassName("subdomain_checkbox");
		const subdomain_ids = [];
		for (let i = 0; i < subdomain_item.length; i++) {
			if (subdomain_item[i].checked) {
				subdomain_ids.push($(subdomain_item[i]).val());
			}
		}
		const data = {'subdomain_ids': subdomain_ids};
		fetch('/api/querySubdomains/', {
			method: 'POST',
			credentials: "same-origin",
			headers: {
				"X-CSRFToken": getCookie("csrftoken"),
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(data)
		})
		.then(response => response.json())
		.then(function (response) {
			Swal.close();
			if (response['status']) {
				if (window.ModalManager) ModalManager.showDialog({});
				$('#modal-dialog-title .modal_count').html(response['results'].length);
				$('#modal-dialog-body').empty();
				let subdomains = '';
				$('#modal-dialog-body').append(`<textarea class="form-control clipboard copy-txt" id="selected_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
				for (const subdomain in response['results']){
					const subdomain_obj = response['results'][subdomain];
					subdomains += subdomain_obj + '\n';
				}
				$('#selected_subdomains_text_area').append(subdomains);
				$("#modal-dialog-footer").empty();
				$("#modal-dialog-footer").append(`<a href="javascript:download('subdomains-${domain_name}.txt', subdomains);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
				$("#modal-dialog-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#selected_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
			}
			else{
				Swal.fire({
					title: 'Oops! Could not download selected subdomains.',
					icon: 'error',
					padding: '2em'
				});
			}
		});
	}
}


function deleteMultipleSubdomains(){
	if (!checkedCount()) {
		Swal.fire({
			title: 'Oops! No Subdomains has been selected!',
			icon: 'error',
			padding: '2em'
		});
	} else {
		// atleast one target is selected
		Swal.fire({
			showCancelButton: true,
			title: 'Are you sure you want to delete ' + checkedCount() + ' Subdomains?',
			text: 'Do you really want to delete these subdomains? This action cannot be undone.',
			icon: 'error',
			confirmButtonText: 'Delete',
		}).then((result) => {
			if (result.isConfirmed) {
				Swal.fire({
					title: 'Deleting Subdomain...',
					allowOutsideClick: false
				});
				Swal.showLoading();

				const subdomain_item = document.getElementsByClassName("subdomain_checkbox");
				const subdomain_ids = [];
				for (let i = 0; i < subdomain_item.length; i++) {
					if (subdomain_item[i].checked) {
						subdomain_ids.push($(subdomain_item[i]).val());
					}
				}
				const data = {'subdomain_ids': subdomain_ids};
				fetch('/api/action/subdomain/delete/', {
					method: 'POST',
					credentials: "same-origin",
					headers: {
						"X-CSRFToken": getCookie("csrftoken"),
						'Content-Type': 'application/json'
					},
					body: JSON.stringify(data)
				})
				.then(response => response.json())
				.then(function (response) {
					Swal.close();
					if (response['status']) {
						// remove all rows
						const table = $('#subdomain_scan_results').DataTable();
						for (let id in subdomain_ids) {
							table.row('#subdomain_row_' + id).remove().draw();
						}
						Snackbar.show({
							text: 'Subdomain successfully deleted!',
							pos: 'top-right',
							duration: 2500
						});
					}
					else{
						Swal.fire({
							title:  'Could not delete Subdomain!',
							icon: 'fail',
						});
					}
				});
			}
		});
	}
}


function initiateMultipleSubscan(){
		$('#btn-initiate-subtask').attr('multiple-subscan', true);
		$('#subtask_ip_address_id').val('0');
		$('#subscan-modal').removeData('subscan-ip-label');
		$('a[data-toggle="tooltip"]').tooltip("hide");
		if (window.ModalManager) ModalManager.showById(ModalManager.MODAL_IDS.SUBSCAN);
}


function show_port_screenshots(subdomain_id, subdomain_name, port, scan_id, domain_id = null, clicked_screenshot_url = '', clicked_http_url = '') {
	// When user clicked a specific thumbnail, show only that screenshot (no API call).
	if (clicked_screenshot_url) {
		window.ScreenshotDisplay.showModal(clicked_screenshot_url, clicked_http_url || '');
		return;
	}

	let effectiveScanId = scan_id;
	let effectiveDomainId = domain_id;
	if ((effectiveScanId == null || effectiveScanId === 'null') && !effectiveDomainId) {
		const $tbl = $('#endpoint_results');
		if ($tbl.length) {
			effectiveScanId = $tbl.data('context-scan-id');
			effectiveDomainId = $tbl.data('context-domain-id');
		}
	}

	let apiUrl = `/api/fetchScreenshots/?subdomain_id=${subdomain_id}&port=${port}`;
	if (effectiveScanId && effectiveScanId !== 'null') {
		apiUrl += `&scan_id=${effectiveScanId}`;
	} else if (effectiveDomainId) {
		apiUrl += `&target_id=${effectiveDomainId}`;
	} else {
		if (window.ModalManager) {
			ModalManager.showXl({ title: 'Error', bodyHtml: '<p class="text-danger">No scan or target information available</p>', footerHtml: '' });
		} else {
			Swal.fire({ title: 'Error', text: 'No scan or target information available', icon: 'error' });
		}
		return;
	}

	const loadingTitle = `Loading screenshots for ${subdomain_name}:${port}...`;
	const loadingBody = '<p class="text-muted">Loading...</p>';
	if (window.ModalManager) {
		ModalManager.setXlTitle(loadingTitle);
		ModalManager.setXlLoading(loadingBody);
		ModalManager.setXlContent({ footerHtml: '' });
		if (!ModalManager.showXlOnly()) {
			$('#xl-modal-title').html(loadingTitle);
			$('#xl-modal-content').html(loadingBody);
			$('#xl-modal-footer').html('');
			ModalManager.showXlOnly();
		}
	} else {
		Swal.fire({ title: loadingTitle, allowOutsideClick: false });
		Swal.showLoading();
	}

	fetch(apiUrl)
		.then(response => response.json())
		.then(data => {
			let modalContent = '';
			let screenshotCount = 0;
			if (data && Object.keys(data).length > 0) {
				for (const key in data) {
					const endpoint = data[key];
					const screenshotUrl = endpoint.screenshot_url || '';
					if (screenshotUrl && endpoint.port == port) {
						screenshotCount++;
						const safeHttpUrl = window.normalizeSafeLinkUrl(endpoint.http_url);
						modalContent += `
						<div class="mb-4 text-center">
							<h6><a href="${window.escapeAttr(safeHttpUrl)}" target="_blank" class="text-primary">${(typeof window.safeText === 'function' ? window.safeText(endpoint.http_url) : endpoint.http_url)}</a></h6>
							<div class="d-flex justify-content-center">
								<img src="${screenshotUrl}" class="img-fluid rounded screenshot-popup"
									 style="max-width: 90%; max-height: 80vh; cursor: pointer; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"
									 onclick="window.open('${screenshotUrl.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}', '_blank')">
							</div>
						</div>
					`;
					}
				}
			}
			const safeSubdomain = (typeof window.safeText === 'function' ? window.safeText(subdomain_name) : subdomain_name);
			const title = screenshotCount > 0
				? `Screenshots for ${safeSubdomain}:${port} (${screenshotCount})`
				: 'No screenshots';
			const bodyHtml = screenshotCount > 0
				? modalContent
				: `<p class="text-muted">No screenshots found for ${safeSubdomain}:${port}</p>`;
			if (window.ModalManager) {
				ModalManager.setXlContent({ title, bodyHtml, footerHtml: '' });
			} else {
				Swal.close();
				if (screenshotCount > 0) {
					$('#xl-modal-title').html(title);
					$('#xl-modal-content').html(modalContent);
					$('#xl-modal-footer').html('');
					if (window.ModalManager) ModalManager.showXlOnly();
				} else {
					Swal.fire({ title: 'No screenshots', text: `No screenshots found for ${subdomain_name}:${port}`, icon: 'info' });
				}
			}
		})
		.catch(error => {
			console.error('Error loading screenshots:', error);
			const errBody = '<p class="text-danger">Unable to load screenshots</p>';
			if (window.ModalManager) {
				ModalManager.setXlContent({ title: 'Error', bodyHtml: errBody, footerHtml: '' });
			} else {
				Swal.close();
				Swal.fire({ title: 'Error', text: 'Unable to load screenshots', icon: 'error' });
			}
		});
}

window.ScreenshotDisplay.thumbnailClickDelegate = show_port_screenshots;

function show_subdomain_screenshots(subdomain_id, subdomain_name, scan_id) {
	const loadingTitle = `Loading screenshots for ${subdomain_name}...`;
	const loadingBody = '<p class="text-muted">Loading...</p>';
	if (window.ModalManager) {
		ModalManager.setXlTitle(loadingTitle);
		ModalManager.setXlLoading(loadingBody);
		ModalManager.setXlContent({ footerHtml: '' });
		if (!ModalManager.showXlOnly()) {
			$('#xl-modal-title').html(loadingTitle);
			$('#xl-modal-content').html(loadingBody);
			$('#xl-modal-footer').html('');
			ModalManager.showXlOnly();
		}
	} else {
		Swal.fire({ title: loadingTitle, allowOutsideClick: false });
		Swal.showLoading();
	}

	fetch(`/api/fetchScreenshots/?scan_id=${scan_id}&subdomain_id=${subdomain_id}`)
		.then(response => response.json())
		.then(data => {
			let modalContent = '';
			let screenshotCount = 0;
			if (data && Object.keys(data).length > 0) {
				for (let key in data) {
					const endpoint = data[key];
					const subdomainScreenshotUrl = endpoint.screenshot_url || '';
					if (subdomainScreenshotUrl) {
						screenshotCount++;
						const safeHttpUrl = window.normalizeSafeLinkUrl(endpoint.http_url);
						modalContent += `
						<div class="mb-4 text-center">
							<h6>
								<a href="${window.escapeAttr(safeHttpUrl)}" target="_blank" class="text-primary">${(typeof window.safeText === 'function' ? window.safeText(endpoint.http_url) : endpoint.http_url)}</a>
								<span class="badge badge-soft-info ms-2">Port ${(typeof window.safeText === 'function' ? window.safeText(String(endpoint.port)) : String(endpoint.port))}</span>
							</h6>
							<div class="d-flex justify-content-center">
								<img src="${subdomainScreenshotUrl}" class="img-fluid rounded screenshot-popup"
									 style="max-width: 90%; max-height: 80vh; cursor: pointer; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"
									 onclick="window.open('${subdomainScreenshotUrl.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}', '_blank')">
							</div>
						</div>
					`;
					}
				}
			}
			const title = screenshotCount > 0
				? `Screenshots for ${subdomain_name} (${screenshotCount})`
				: 'No screenshots';
			const bodyHtml = screenshotCount > 0
				? modalContent
				: `<p class="text-muted">No screenshots found for ${subdomain_name}</p>`;
			if (window.ModalManager) {
				ModalManager.setXlContent({ title, bodyHtml, footerHtml: '' });
			} else {
				Swal.close();
				if (screenshotCount > 0) {
					$('#xl-modal-title').html(title);
					$('#xl-modal-content').html(modalContent);
					$('#xl-modal-footer').html('');
					if (window.ModalManager) ModalManager.showXlOnly();
				} else {
					Swal.fire({ title: 'No screenshots', text: `No screenshots found for ${subdomain_name}`, icon: 'info' });
				}
			}
		})
		.catch(error => {
			console.error('Error loading screenshots:', error);
			const errBody = '<p class="text-danger">Unable to load screenshots</p>';
			if (window.ModalManager) {
				ModalManager.setXlContent({ title: 'Error', bodyHtml: errBody, footerHtml: '' });
			} else {
				Swal.close();
				Swal.fire({ title: 'Error', text: 'Unable to load screenshots', icon: 'error' });
			}
		});
}


