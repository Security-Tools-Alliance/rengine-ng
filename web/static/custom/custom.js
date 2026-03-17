/**
 * Escapes HTML special characters to prevent XSS attacks
 * @param {string} str - The string to escape
 * @return {string} The escaped string
 */
function escapeHtml(str) {
	if (str == null) {
		return '';
	}
	return String(str)
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#x27;')
		.replace(/\//g, '&#x2F;');
}

/**
 * Returns a safe link renderer (href, displayText, opts). Prefer window.safeLink (escape.js).
 * Fallback sanitizes href via window.sanitizeUrlForHref / window.normalizeSafeLinkUrl when available.
 * Ensure escape.js loads before this script for full URL sanitization.
 * @param {string} [defaultClass] - Default class for the anchor (e.g. "text-primary", "text-danger").
 * @returns {function(string, string, object): string}
 */
function getRengineSafeLinkFn(defaultClass) {
	defaultClass = defaultClass || "text-primary";
	if (typeof window.safeLink === "function") return window.safeLink;
	const sanitize = typeof window.sanitizeUrlForHref === "function" ? window.sanitizeUrlForHref : (typeof window.normalizeSafeLinkUrl === "function" ? window.normalizeSafeLinkUrl : null);
	const safeA = typeof window.safeAttr === "function" ? window.safeAttr : function (s) { return s == null ? "" : String(s); };
	const safeT = typeof window.safeText === "function" ? window.safeText : function (s) { return s == null ? "" : String(s); };
	return function (h, t, o) {
		const safeHref = sanitize ? (sanitize(h) || "#") : "#";
		o = o || {};
		const cls = o.className != null ? o.className : defaultClass;
		const title = o.title != null ? " title=\"" + safeA(o.title) + "\"" : "";
		const target = o.target != null ? o.target : "_blank";
		const targetAttr = target ? " target=\"" + safeA(target) + "\"" : "";
		return "<a href=\"" + safeA(safeHref) + "\"" + targetAttr + " class=\"" + safeA(cls) + "\"" + title + ">" + safeT(t != null ? t : "") + "</a>";
	};
}

function checkall(clickchk, relChkbox) {
	const checker = $('#' + clickchk);
	const multichk = $('.' + relChkbox);
	checker.click(function() {
		multichk.prop('checked', $(this).prop('checked'));
	});
}

function multiCheck(tb_var) {
	tb_var.on("change", ".chk-parent", function() {
			const e = $(this).closest("table").find("td:first-child .child-chk"),
				a = $(this).is(":checked");
			$(e).each(function() {
				a ? ($(this).prop("checked", !0), $(this).closest("tr").addClass("active")) : ($(this).prop("checked", !1), $(this).closest("tr").removeClass("active"))
			})
		}),
		tb_var.on("change", "tbody tr .new-control", function() {
			$(this).parents("tr").toggleClass("active")
		})
}

function GetIEVersion() {
	const sAgent = window.navigator.userAgent;
	const Idx = sAgent.indexOf("MSIE");
	// If IE, return version number.
	if (Idx > 0) return parseInt(sAgent.substring(Idx + 5, sAgent.indexOf(".", Idx)));
	// If IE 11 then look for Updated user agent string.
	else if (!!navigator.userAgent.match(/Trident\/7\./)) return 11;
	else return 0; //It is not IE
}

function truncate(str, n) {
	return (str.length > n) ? str.substr(0, n - 1) + '&hellip;' : str;
};

function return_str_if_not_null(val) {
	return val || '';
}
// separate hostname and url
// Referenced from https://stackoverflow.com/questions/736513/how-do-i-parse-a-url-into-hostname-and-path-in-javascript
function getParsedURL(url) {
	const parser = new URL(url);
	return parser.pathname + parser.search;
};

/**
 * Get CSRF token from meta tag (recommended approach when CSRF_COOKIE_HTTPONLY = True)
 * Falls back to cookie method for backward compatibility
 */
function getCSRFToken() {
	// First try to get from meta tag (recommended with CSRF_COOKIE_HTTPONLY = True)
	const metaTag = document.querySelector('meta[name="csrf-token"]');
	if (metaTag) {
		return metaTag.getAttribute('content');
	}
	
	// Fallback to cookie method for backward compatibility
	return getCookieFromDocument('csrftoken');
}

/**
 * Legacy cookie function - kept for backward compatibility
 * Note: Won't work when CSRF_COOKIE_HTTPONLY = True
 */
function getCookie(name) {
	// For CSRF token, use the new method
	if (name === 'csrftoken') {
		return getCSRFToken();
	}
	
	return getCookieFromDocument(name);
}

/**
 * Internal function to get cookie from document.cookie
 */
function getCookieFromDocument(name) {
	let cookieValue = null;
	if (document.cookie && document.cookie !== '') {
		const cookies = document.cookie.split(';');
		for (let i = 0; i < cookies.length; i++) {
			const cookie = cookies[i].trim();
			// Does this cookie string begin with the name we want?
			if (cookie.substring(0, name.length + 1) === (name + '=')) {
				cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
				break;
			}
		}
	}
	return cookieValue;
}

/**
 * Global CSRF Token Configuration for AJAX Requests
 * This ensures all AJAX requests automatically include the CSRF token
 */
function setupCSRFToken() {
	const csrftoken = getCSRFToken();
	
	// Setup for jQuery AJAX requests
	if (typeof $ !== 'undefined' && $.ajaxSetup) {
		$.ajaxSetup({
			beforeSend: function(xhr, settings) {
				// Check if request needs CSRF protection
				if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
					xhr.setRequestHeader("X-CSRFToken", csrftoken);
				}
			}
		});
	}
	
	// Setup for native fetch requests - monkey patch fetch
	if (typeof window !== 'undefined' && window.fetch) {
		const originalFetch = window.fetch;
		window.fetch = function(url, options = {}) {
			// Ensure we have headers object
			options.headers = options.headers || {};
			
			// Add CSRF token for non-safe methods
			const method = (options.method || 'GET').toUpperCase();
			if (!csrfSafeMethod(method) && !isExternalUrl(url) && !options.headers['X-CSRFToken'] && !options.headers['X-Csrftoken']) {
				options.headers['X-CSRFToken'] = csrftoken;
			}
			
			// Ensure credentials are included for same-origin requests
			if (!options.credentials && !isExternalUrl(url)) {
				options.credentials = 'same-origin';
			}
			
			return originalFetch.call(this, url, options);
		};
	}
}

/**
 * Check if HTTP method is safe (doesn't require CSRF protection)
 */
function csrfSafeMethod(method) {
	// These HTTP methods do not require CSRF protection
	return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

/**
 * Check if URL is external (different origin)
 */
function isExternalUrl(url) {
	if (typeof url !== 'string') return false;
	
	// Relative URLs are not external
	if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../')) {
		return false;
	}
	
	// Check if it's an absolute URL with different origin
	try {
		const urlObj = new URL(url, window.location.origin);
		return urlObj.origin !== window.location.origin;
	} catch (e) {
		// If URL parsing fails, assume it's not external
		return false;
	}
}

// Initialize CSRF protection when DOM is ready
$(document).ready(function() {
	setupCSRFToken();

	// Delegated handlers: always off-then-on for namespaced events so PJAX/content reloads
	// do not stack duplicate bindings. Init order: this block runs once on document.ready.
	$(document).off('click.vulnerability_results', '#vulnerability_results tbody tr');
	$(document).on('click.vulnerability_results', '#vulnerability_results tbody tr', function(e) {
		if ($(e.target).is('input[type="checkbox"]') || $(e.target).is('svg') || $(e.target).is('a') || $(e.target).is('th') || $(e.target).is('span')) {
			return;
		}
		if (!$.fn.dataTable.isDataTable('#vulnerability_results')) {
			return;
		}
		const rowData = $('#vulnerability_results').DataTable().row(this).data();
		if (rowData && window.reNgineVuln && typeof window.reNgineVuln.openVulnOffcanvas === "function") {
			window.reNgineVuln.openVulnOffcanvas(rowData);
		}
	});

	$(document).off("click.reportHackerone", ".js-report-hackerone").on("click.reportHackerone", ".js-report-hackerone", function(e) {
		e.preventDefault();
		const el = e.currentTarget;
		const reportUrl = (el.getAttribute && el.getAttribute("data-report-url")) || "";
		const vulnId = (el.getAttribute && el.getAttribute("data-vulnerability-id")) || "";
		const severity = (el.getAttribute && el.getAttribute("data-severity")) || "";
		if (typeof report_hackerone === "function") {
			report_hackerone(reportUrl, vulnId, severity);
		}
	});
});

/**
 * Simplified fetch wrapper that automatically handles CSRF tokens and common options
 * @param {string} url - The URL to fetch
 * @param {Object} options - Fetch options (method, body, headers, etc.)
 * @returns {Promise} - Fetch promise
 */
function secureFetch(url, options = {}) {
	// Set default options
	const defaultOptions = {
		credentials: 'same-origin',
		headers: {
			'Content-Type': 'application/json'
		}
	};
	
	// Merge options with defaults
	const mergedOptions = {
		...defaultOptions,
		...options,
		headers: {
			...defaultOptions.headers,
			...options.headers
		}
	};
	
	// The global fetch wrapper will automatically add CSRF token
	return fetch(url, mergedOptions);
}

/**
 * Debug function to check if CSRF token is available and valid
 * @returns {Object} - Object containing CSRF token status and value
 */
function debugCSRFToken() {
	const token = getCSRFToken();
	const isValid = token && token.length > 0;
	const metaTag = document.querySelector('meta[name="csrf-token"]');
	const cookieToken = getCookieFromDocument('csrftoken');
	
	console.log('CSRF Token Debug:', {
		available: !!token,
		length: token ? token.length : 0,
		value: token ? token.substring(0, 8) + '...' : 'N/A',
		isValid: isValid,
		source: metaTag ? 'meta-tag' : (cookieToken ? 'cookie' : 'none'),
		metaTagExists: !!metaTag,
		cookieAccessible: !!cookieToken,
		httpOnlyMode: !!metaTag && !cookieToken
	});
	
	return {
		available: !!token,
		length: token ? token.length : 0,
		isValid: isValid,
		token: token,
		source: metaTag ? 'meta-tag' : (cookieToken ? 'cookie' : 'none')
	};
}
// Source: https://portswigger.net/web-security/cross-site-scripting/preventing#encode-data-on-output
function htmlEncode(str) {
	return String(str).replace(/[^\w. ]/gi, function(c) {
		return '&#' + c.charCodeAt(0) + ';';
	});
}

/**
 * HTML-escape for safe insertion into the DOM. Uses htmlEncode when available,
 * otherwise a minimal escape for &, <, >, ", ' to avoid XSS if htmlEncode is undefined.
 * @param {*} s - Value to escape (stringified; null/undefined become '').
 * @returns {string} Escaped string safe for HTML context.
 */
function safeHtmlEncode(s) {
	if (s == null) return '';
	const str = String(s);
	if (typeof htmlEncode === 'function') return htmlEncode(str);
	return str
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

/** CVE ID format: CVE-YYYY-NNNNN... (case-insensitive). */
const CVE_ID_PATTERN = /^CVE-\d{4}-\d+$/i;

/**
 * Returns a trimmed, uppercase CVE id string for display/URLs, or "" if null/undefined.
 * Single place for CVE normalization so callers can pass raw values.
 * @param {*} id - Value to normalize (stringified).
 * @returns {string}
 */
function getNormalizedCveId(id) {
	if (id == null) return "";
	return String(id).trim().toUpperCase();
}

/**
 * Returns true if the value matches a valid CVE ID pattern.
 * @param {*} id - Value to check (stringified).
 * @returns {boolean}
 */
function isValidCveId(id) {
	if (id == null) return false;
	return CVE_ID_PATTERN.test(String(id).trim());
}

/**
 * Returns the NVD URL for a valid CVE ID, or null if invalid.
 * Normalizes input internally; use this helper so base URL and encoding stay consistent.
 * @param {*} cveId - CVE identifier (e.g. "CVE-2024-1234"), any case.
 * @returns {string|null} NVD detail URL or null.
 */
function getNvdCveUrl(cveId) {
	const normalizedId = getNormalizedCveId(cveId);
	if (!normalizedId || !isValidCveId(normalizedId)) return null;
	return "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(normalizedId);
}

// Source: https://portswigger.net/web-security/cross-site-scripting/preventing#encode-data-on-output
function jsEscape(str) {
	return String(str).replace(/[^\w. ]/gi, function(c) {
		return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4);
	});
}

function deleteScheduledScan(endpoint_url) {
	swal.queue([{
		title: 'Are you sure you want to delete this?',
		text: "This action can not be undone.",
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Delete',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(endpoint_url, {
				method: 'POST',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken")
				}
			}).then(function(response) {
				return response.json();
			}).then(function(data) {
				// TODO Look for better way
				return location.reload();
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to delete the scheduled task!'
				})
			})
		}
	}])
}

function change_scheduled_task_status(endpoint_url, checkbox) {
	let text_msg;
	if (checkbox.checked) {
		text_msg = 'Schedule Scan Started';
	} else {
		text_msg = 'Schedule Scan Stopped';
	}
	Snackbar.show({
		text: text_msg,
		pos: 'top-right',
		duration: 2500
	});
	return fetch(endpoint_url, {
		method: 'POST',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken")
		}
	})
}

function change_vuln_status(endpoint_url) {
	return fetch(endpoint_url, {
		method: 'POST',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken")
		}
	})
}
// splits really long strings into multiple lines
// Souce: https://stackoverflow.com/a/52395960
function split_into_lines(str, maxWidth) {
	const newLineStr = "</br>";
	let remaining = str;
	let done = false;
	let res = '';
	let found;
	let i;
	do {
		found = false;
		// Inserts new line at first whitespace of the line
		for (i = maxWidth - 1; i >= 0; i--) {
			if (test_white_space(remaining.charAt(i))) {
				res += [remaining.slice(0, i), newLineStr].join('');
				remaining = remaining.slice(i + 1);
				found = true;
				break;
			}
		}
		// Inserts new line at maxWidth position, the word is too long to wrap
		if (!found) {
			res += [remaining.slice(0, maxWidth), newLineStr].join('');
			remaining = remaining.slice(maxWidth);
		}
		if (remaining.length < maxWidth) done = true;
	} while (!done);
	return res + remaining;
}

function test_white_space(x) {
	const white = new RegExp(/^\s$/);
	return white.test(x.charAt(0));
};
// span values function will separate the values by comma and put badge around it
function parse_comma_values_into_span(data, color, outline = null) {
	if (data) {
		const badge = `<span class='badge badge-soft-` + color + ` m-1'>`;
		let data_with_span = "";
		data.split(/\s*,\s*/).forEach(function(split_vals) {
			data_with_span += badge + split_vals + "</span>";
		});
		return data_with_span;
	}
	return '';
}

function get_severity_badge(severity) {
	if (typeof window.renderSeverityBadgeHtml === "function") {
		return window.renderSeverityBadgeHtml(severity);
	}
	switch (severity) {
		case "Info":
			return "<span class='badge badge-soft-primary'>&nbsp;&nbsp;Info&nbsp;&nbsp;</span>";
		case "Low":
			return "<span class='badge badge-low'>&nbsp;&nbsp;Low&nbsp;&nbsp;</span>";
		case "Medium":
			return "<span class='badge badge-soft-warning'>&nbsp;&nbsp;Medium&nbsp;&nbsp;</span>";
		case "High":
			return "<span class='badge badge-soft-danger'>&nbsp;&nbsp;High&nbsp;&nbsp;</span>";
		case "Critical":
			return "<span class='badge badge-critical'>&nbsp;&nbsp;Critical&nbsp;&nbsp;</span>";
		case "Unknown":
			return "<span class='badge badge-soft-info'>&nbsp;&nbsp;Unknown&nbsp;&nbsp;</span>";
		default:
			return "";
	}
}
// Source: https://stackoverflow.com/a/54733055
function typingEffect(words, id, i) {
	let word = words[i].split("");
	const loopTyping = function() {
		if (word.length > 0) {
			let elem = document.getElementById(id);
			elem.setAttribute('placeholder', elem.getAttribute('placeholder') + word.shift());
		} else {
			deletingEffect(words, id, i);
			return false;
		};
		timer = setTimeout(loopTyping, 150);
	};
	loopTyping();
};

function deletingEffect(words, id, i) {
	let word = words[i].split("");
	const loopDeleting = function() {
		if (word.length > 0) {
			word.pop();
			document.getElementById(id).setAttribute('placeholder', word.join(""));
		} else {
			const nextIndex = words.length > (i + 1) ? i + 1 : 0;
			typingEffect(words, id, nextIndex);
			return false;
		};
		timer = setTimeout(loopDeleting, 90);
	};
	loopDeleting();
};

function fullScreenDiv(id, btn) {
	let fullscreen = document.querySelector(id);
	document.fullscreenElement && document.exitFullscreen() || document.querySelector(id).requestFullscreen();
	fullscreen.setAttribute("style", "overflow:auto");
}

function get_randid() {
	return '_' + Math.random().toString(36).substr(2, 9);
}

function delete_all_scan_results(endpoint_url) {
	swal.queue([{
		title: 'Are you sure you want to delete all scan results?',
		text: "You won't be able to revert this!",
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Delete',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(endpoint_url, {
				method: 'POST',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken")
				}
			}).then(function(response) {
				return response.json();
			}).then(function(data) {
				// TODO Look for better way
				return location.reload();
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to delete Delete scan results!'
				})
			})
		}
	}])
}

function delete_all_screenshots(endpoint_url) {
	swal.queue([{
		title: 'Are you sure you want to delete all Screenshots?',
		text: "You won't be able to revert this!",
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Delete',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(endpoint_url, {
				method: 'POST',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken")
				}
			}).then(function(response) {
				return response.json();
			}).then(function(data) {
				// TODO Look for better way
				return location.reload();
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to delete Empty Screenshots!'
				})
			})
		}
	}])
}

function load_image_from_url(src, append_to_id) {
	const img = document.createElement('img');
	img.src = src;
	img.style.width = '100%';
	document.getElementById(append_to_id).appendChild(img);
}

function setTooltip(btn, message) {
	hide_all_tooltips();
	const instance = tippy(document.querySelector(btn));
	instance.setContent(message);
	instance.show();
	setTimeout(function() {
		instance.hide();
	}, 500);
}

function hide_all_tooltips() {
	$(".tooltip").tooltip("hide");
}

function get_response_time_text(response_time) {
	if (response_time) {
		let text_color = 'danger';
		if (response_time < 0.5) {
			text_color = 'success';
		} else if (response_time >= 0.5 && response_time < 1) {
			text_color = 'warning';
		}
		return `<span class="text-${text_color}">${response_time.toFixed(4)}s</span>`;
	}
	return '';
}

function parse_technology(endpoint_url, data, color, scan_id = null, domain_id=null, link=true) {
	const badge = `<span data-toggle="tooltip" title="Technology" class='badge-link badge badge-soft-` + color + ` mt-1 me-1'`;
	let data_with_span = "";
	for (let key in data) {
		let onclick = '';
		let tooltip = `Technology: ${data[key]['name']}`;
		if (data[key]['value']) {
			tooltip += `\nValue: ${data[key]['value']}`;
		}
		if (data[key]['category']) {
			tooltip += `\nCategory: ${data[key]['category']}`;
		}
		if(link) {
			onclick = ` onclick="get_tech_details('${endpoint_url}', '${data[key]['name']}', ${scan_id}, domain_id=null)"`
		}
		data_with_span += badge.replace('title="Technology"', `title="${tooltip}"`) + onclick + `>` + data[key]['name'] + "</span>";
	}
	return data_with_span;
}
// span values function will separate the values by comma and put badge around it
function parse_ip(data, cdn) {
	const badge = cdn
		? `<span class='badge badge-soft-warning m-1 bs-tooltip' title="CDN IP Address">`
		: `<span class='badge badge-soft-primary m-1'>`;
	let data_with_span = "";
	data.split(/\s*,\s*/).forEach(function(split_vals) {
		data_with_span += badge + split_vals + "</span>";
	});
	return data_with_span;
}
//to remove the image element if there is no screenshot captured
function removeImageElement(element) {
	element.parentElement.remove();
}
// https://stackoverflow.com/a/18197341/9338140
function download(filename, text) {
	const element = document.createElement('a');
	element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
	element.setAttribute('download', filename);
	element.style.display = 'none';
	document.body.appendChild(element);
	element.click();
	document.body.removeChild(element);
}

function updateVulnStatus(endpoint_url, element, id, status) {
    const $element = $(element);
    const $row = $element.closest("tr");

    $row.toggleClass("table-success text-strike", status);
    $element.text(status ? 'RESOLVED' : 'OPEN')
        .toggleClass('badge badge-soft-danger', !status)
        .toggleClass('badge badge-soft-success', status)
        .attr('onclick', `vuln_status_change('${endpoint_url}', this, ${id}, ${!status})`);
}

function vuln_status_change(endpoint_url, element, id, status) {
	const updatedEndpointUrl = endpoint_url.replace(/\/0$/, `/${id}`);
    updateVulnStatus(updatedEndpointUrl, element, id, status);
    change_vuln_status(updatedEndpointUrl);
}

function bulk_vuln_status_change(status) {
    $('.vulnerability_checkbox:checked')
        .parents("tr")
        .find('.vuln-status')
        .filter((_, el) => (status && $(el).text() === "OPEN") || (!status && $(el).text() === "RESOLVED"))
        .trigger('click');
}

function toggleMultipleVulnerabilitiesButton(){
	if($('.vulnerability_checkbox:checked').length >= 1){
		if($('.vulnerability_checkbox:checked').length >= 2){
			$('#select_all_checkbox').prop('checked','checked')
		}
		$(".vulnerability_btns").removeClass("disabled")
		$('#vulnaribilities_selected_count').show().text($('.vulnerability_checkbox:checked').length + ' Vulnerabilities Selected x');
	}else{
		$('#select_all_checkbox').prop('checked','')
		$(".vulnerability_btns").addClass("disabled")
		$('#vulnaribilities_selected_count').hide()

	} 
}

function uncheckVulnerabilities(){
	$('.vulnerability_checkbox:checked').trigger('click')
}

function countVulnerabilities (){

}

$('#select_all_checkbox').on('click', function() {
    $("tr").find("[type=checkbox]").prop('checked', $(this).is(':checked'));
	toggleMultipleVulnerabilitiesButton();
});

// Same off-then-on pattern for delete handler (see vulnerability row click above).
$(document).off('click.vulnerability_results', '#vulnerability_results .btn-delete-vulnerability');
$(document).on('click.vulnerability_results', '#vulnerability_results .btn-delete-vulnerability', function () {
	const vulnerability_id = $(this).attr('id');
	const data = {'vulnerability_ids': [vulnerability_id]};
	const endpoint_url = $(this).attr('data-url');
	const row = this;
	Swal.fire({
		showCancelButton: true,
		title: 'Delete Vulnerability!',
		text: 'Do you really want to delete this Vulnerability? This action cannot be undone.',
		icon: 'error',
		confirmButtonText: 'Delete',
	}).then((result) => {
		if (result.isConfirmed) {
			Swal.fire({
				title: 'Deleting Vulnerability...',
				allowOutsideClick: false
			});
			swal.showLoading();
			fetch(endpoint_url, {
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
				swal.close();
				if (response['status']) {
					$(row).parent().parent().parent().remove();
					Snackbar.show({
						text: 'Vulnerability successfully deleted!',
						pos: 'top-right',
						duration: 2500
					});
				}
				else{
					Swal.fire({
						title:  'Could not delete Vulnerability!',
						icon: 'fail',
					});
				}
			});
		}
	});
	$('a[data-toggle="tooltip"]').tooltip("hide");
});


$("#bulk_delete_vulnerabilities").on('click', function () {
	//btn-delete-vulnerability contains vuln id to delete
	const vulnerabilities = $('.vulnerability_checkbox:checked').parents("tr").find('.btn-delete-vulnerability')
	const vulnerabilities_ids = Array();
	const endpoint_url = $(this).attr('data-url');
	Array.from(vulnerabilities).forEach(vuln => {
		vulnerabilities_ids.push($(vuln).attr('id'));
	});		
	const data = {'vulnerability_ids': vulnerabilities_ids};
	Swal.fire({
		showCancelButton: true,
		title: 'Bulk Delete Vulnerabilities!',
		text: 'Do you really want to delete all those Vulnerabilities? This action cannot be undone.',
		icon: 'error',
		confirmButtonText: 'Delete',
	}).then((result) => {
		if (result.isConfirmed) {
			Swal.fire({
				title: 'Deleting Vulnerabilities...',
				allowOutsideClick: false
			});
			swal.showLoading();
			fetch(endpoint_url, {
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
				swal.close();
				if (response['status']) {
					Array.from(vulnerabilities).forEach(vuln => {
						$(vuln).parents('tr').remove();
					});		
					Snackbar.show({
						text: 'Vulnerabilities successfully deleted!',
						pos: 'top-right',
						duration: 2500
					});
				}
				else{
					Swal.fire({
						title:  'Could not delete Vulnerabilities!',
						icon: 'fail',
					});
				}
			});
		}
	});;
	$('a[data-toggle="tooltip').tooltip("hide")
});

function report_hackerone(endpoint_url, vulnerability_id, severity) {
	let message;
	if (severity == 'Info' || severity == 'Low' || severity == 'Medium') {
		message = "We do not recommended sending this vulnerability report to hackerone due to the severity, do you still want to report this?"
	} else {
		message = "This vulnerability report will be sent to Hackerone.";
	}
	const vulnerability_report_api = endpoint_url+ '?vulnerability_id=' + vulnerability_id;
	swal.queue([{
		title: 'Reporting vulnerability to hackerone',
		text: message,
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Report',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(vulnerability_report_api, {
				method: 'GET',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken")
				}
			}).then(function(response) {
				return response.json();
			}).then(function(data) {
				if (data.status == 111) {
					swal.insertQueueStep({
						icon: 'error',
						title: 'Target does not has team_handle to send report to.'
					})
				} else if (data.status == 201) {
					swal.insertQueueStep({
						icon: 'success',
						title: 'Vulnerability report successfully submitted to hackerone.'
					})
				} else if (data.status == 400) {
					swal.insertQueueStep({
						icon: 'error',
						title: 'Invalid Report.'
					})
				} else if (data.status == 401) {
					swal.insertQueueStep({
						icon: 'error',
						title: 'Hackerone authentication failed.'
					})
				} else if (data.status == 403) {
					swal.insertQueueStep({
						icon: 'error',
						title: 'API Key forbidden by Hackerone.'
					})
				} else if (data.status == 423) {
					swal.insertQueueStep({
						icon: 'error',
						title: 'Too many requests.'
					})
				}
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to send vulnerability report to hackerone, check your target team_handle or hackerone configurarions!'
				})
			})
		}
	}])
}

function get_interesting_subdomains(endpoint_url, project, target_id, scan_history_id, renderOptions) {
	let url;
	let nonOrderableTargets;
	if (target_id) {
		url = `${endpoint_url}?project=${project}&target_id=${target_id}&format=datatables`;
		nonOrderableTargets = ["name", "page_title", "http_status", "content_length"];
	} else if (scan_history_id) {
		url = `${endpoint_url}?project=${project}&scan_id=${scan_history_id}&format=datatables`;
		nonOrderableTargets = [];
	}
	const ro = renderOptions || {};
	const querySubdomainsUrl = ro.querySubdomainsUrl || (window.RENGINE_API_URLS && window.RENGINE_API_URLS.querySubdomains) || "";
	function interestingSubdomainsStatusBadge(d) {
		if (d == null || d === "") return "";
		const n = Number(d);
		if (n === 0) return "";
		const display = (typeof window.safeText === "function" ? window.safeText(String(d)) : String(d));
		const cls = (n >= 200 && n < 300) ? "badge badge-soft-success" : (n >= 300 && n < 400) ? "badge badge-soft-warning" : "badge badge-soft-danger";
		return "<span class=\"" + (typeof window.safeAttr === "function" ? window.safeAttr(cls) : cls) + "\">" + display + "</span>";
	}
	const getStatusBadge = (window.RengineDatatableRenderers && typeof window.RengineDatatableRenderers.getHttpStatusBadge === "function")
		? window.RengineDatatableRenderers.getHttpStatusBadge
		: (typeof get_http_status_badge === "function" ? get_http_status_badge : interestingSubdomainsStatusBadge);
	const buildNameCell = (window.RengineDatatableRenderers && typeof window.RengineDatatableRenderers.buildInterestingSubdomainNameCellHtml === "function")
		? window.RengineDatatableRenderers.buildInterestingSubdomainNameCellHtml
		: null;
	const buildUrlCell = (window.RengineDatatableRenderers && typeof window.RengineDatatableRenderers.buildInterestingSubdomainHttpUrlCellHtml === "function")
		? window.RengineDatatableRenderers.buildInterestingSubdomainHttpUrlCellHtml
		: null;
	const scrollOpts = typeof window.getRengineDatatableScrollerOptions === 'function'
		? window.getRengineDatatableScrollerOptions('60vh') : {};
	const opts = {
		ajax: { url: url },
		destroy: true,
		info: false,
		order: [[3, "desc"]],
		columns: [
			{ data: "name", name: "name" },
			{ data: "page_title", name: "page_title" },
			{ data: "http_status", name: "http_status" },
			{ data: "content_length", name: "content_length" },
			{ data: "http_url", name: "http_url" },
			{ data: "technologies", name: "technologies" }
		],
		columnDefs: [
			{ orderable: false, targets: nonOrderableTargets },
			{ className: "text-center", targets: [2, "http_status"] },
			{
				targets: [0, "name"],
				render: function (data, type, row) {
					if (!row) return (typeof window.safeText === "function" ? window.safeText(data) : data) || "";
					if (buildNameCell) {
						return buildNameCell(row, { querySubdomainsUrl: querySubdomainsUrl });
					}
					const href = (row && row.http_url) || ("https://" + (data || ""));
					const text = (typeof window.safeText === "function" ? window.safeText(data) : data);
					return getRengineSafeLinkFn("text-primary")(href, text || "", { target: "_blank", className: "text-primary" });
				}
			},
			{
				targets: [4, "http_url"],
				render: function (data, type, row) {
					if (!row && buildUrlCell) return "";
					if (buildUrlCell) return buildUrlCell(row || {});
					const href = (data && typeof data === "string") ? data : (data ? String(data) : "");
					const text = href.length > 80 ? href.slice(0, 77) + "..." : href;
					return getRengineSafeLinkFn("text-primary")(href, text, { target: "_blank", className: "text-primary", title: href });
				}
			},
			{
				targets: [5, "technologies"],
				render: function (data) {
					if (!data || !querySubdomainsUrl || typeof window.parse_technology !== "function") return (typeof window.safeText === "function" ? window.safeText(data) : data) || "";
					return "<div>" + window.parse_technology(querySubdomainsUrl, data, "primary", null, null, true) + "</div>";
				}
			},
			{
				targets: [2, "http_status"],
				render: function (data) { return getStatusBadge(data); }
			},
			{
				targets: [1, "page_title"],
				render: function (data) { return (typeof window.safeText === "function" ? window.safeText(data) : data) || ""; }
			}
		],
		drawCallback: function () {
			const total = this.api().page.info().recordsTotal;
			if (total === 0) {
				$('#interesting_subdomain_div').empty();
			} else {
				$('.interesting-tab-show').removeAttr('style');
				$('#interesting_subdomain_alert_count').html(total + ' Interesting Subdomains');
				$('#interesting_subdomain_count_badge').empty().html('<span class="badge badge-soft-primary me-1">' + total + '</span>');
			}
			var tableEl = document.getElementById('interesting_subdomains');
			if (typeof Clipboard !== "undefined" && tableEl) {
				var clipboard = new Clipboard(tableEl, { selector: '.copyable' });
				clipboard.on("success", function (e) { if (typeof setTooltip === "function") setTooltip(e.trigger, "Copied!"); });
			}
		}
	};
	const merged = Object.assign({}, scrollOpts, opts);
	if ($.fn.DataTable.isDataTable('#interesting_subdomains')) {
		$('#interesting_subdomains').DataTable().destroy();
	}
	if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
		window.initServerSideDataTable("#interesting_subdomains", window.getRengineDatatableConfig("#interesting_subdomains", merged));
	} else {
		if (typeof console !== "undefined" && console.warn) {
			console.warn("custom: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
		}
		$("#interesting_subdomains").DataTable(Object.assign({ serverSide: true, processing: true, responsive: true, layout: window.RENGINE_DATATABLE_LAYOUT_WITH_SEARCH }, merged));
	}
}

function get_interesting_endpoints(endpoint_url, project, target_id, scan_history_id, renderOptions) {
	let url;
	if (target_id) {
		url = `${endpoint_url}/?project=${project}&target_id=${target_id}&format=datatables`;
	} else if (scan_history_id) {
		url = `${endpoint_url}/?project=${project}&scan_id=${scan_history_id}&format=datatables`;
	}
	const ro = renderOptions || {};
	const endpointSubdomainUrl = ro.endpointSubdomainUrl || (window.RENGINE_API_URLS && window.RENGINE_API_URLS.endpointsList) || (window.RENGINE_API_URLS && window.RENGINE_API_URLS.querySubdomains) || "";
	function interestingEndpointsStatusBadge(d) {
		if (d == null || d === "") return "";
		const n = Number(d);
		if (n === 0) return "";
		const display = (typeof window.safeText === "function" ? window.safeText(String(d)) : String(d));
		const cls = (n >= 200 && n < 300) ? "badge badge-soft-success" : (n >= 300 && n < 400) ? "badge badge-soft-warning" : "badge badge-soft-danger";
		return "<span class=\"" + (typeof window.safeAttr === "function" ? window.safeAttr(cls) : cls) + "\">" + display + "</span>";
	}
	const getStatusBadge = (window.RengineDatatableRenderers && typeof window.RengineDatatableRenderers.getHttpStatusBadge === "function")
		? window.RengineDatatableRenderers.getHttpStatusBadge
		: (typeof get_http_status_badge === "function" ? get_http_status_badge : interestingEndpointsStatusBadge);
	const buildUrlCell = (window.RengineDatatableRenderers && typeof window.RengineDatatableRenderers.buildEndpointUrlCellHtml === "function")
		? window.RengineDatatableRenderers.buildEndpointUrlCellHtml
		: null;
	const scrollOpts = typeof window.getRengineDatatableScrollerOptions === 'function'
		? window.getRengineDatatableScrollerOptions('60vh') : {};
	const opts = {
		ajax: { url: url },
		destroy: true,
		info: false,
		order: [[5, "desc"]],
		columns: [
			{ data: "http_url", name: "http_url" },
			{ data: "page_title", name: "page_title" },
			{ data: "http_status", name: "http_status" },
			{ data: "matched_gf_patterns", name: "matched_gf_patterns" },
			{ data: "content_type", name: "content_type" },
			{ data: "content_length", name: "content_length" },
			{ data: "response_time", name: "response_time" },
			{ data: "screenshot_url", name: "screenshot_url" },
			{ data: "techs", name: "techs", visible: false },
			{ data: "webserver", name: "webserver", visible: false }
		],
		columnDefs: [
			{ className: "text-center", targets: [2, "http_status"] },
			{
				targets: [0, "http_url"],
				render: function (data, type, row) {
					if (!row && buildUrlCell) return "";
					if (buildUrlCell && endpointSubdomainUrl) return buildUrlCell(row, endpointSubdomainUrl);
					const raw = (data && typeof data === "string") ? data : (data ? String(data) : "");
					const displayText = raw.length > 80 ? raw.slice(0, 77) + "..." : raw;
					return getRengineSafeLinkFn("text-primary")(raw, displayText, { target: "_blank", className: "text-primary", title: raw });
				}
			},
			{
				targets: [1, "page_title"],
				render: function (data) {
					return (typeof window.safeText === "function" ? window.safeText(data) : (typeof htmlEncode === "function" ? htmlEncode(data) : data)) || "";
				}
			},
			{
				targets: [2, "http_status"],
				render: function (data) { return getStatusBadge(data); }
			},
			{
				targets: [3, "matched_gf_patterns"],
				render: function (data) {
					return (data != null && typeof parse_comma_values_into_span === "function") ? parse_comma_values_into_span(data, "danger", true) : (typeof window.safeText === "function" ? window.safeText(data) : (data != null ? String(data) : ""));
				}
			},
			{
				targets: [4, "content_type"],
				render: function (data) { return (typeof window.safeText === "function" ? window.safeText(data) : (data != null ? String(data) : "")) || ""; }
			},
			{
				targets: [5, "content_length"],
				render: function (data) { return (data != null && data !== "") ? (typeof window.safeText === "function" ? window.safeText(data) : String(data)) : ""; }
			},
			{
				targets: [6, "response_time"],
				render: function (data) { return (typeof get_response_time_text === "function" && data != null) ? get_response_time_text(data) : (data != null ? String(data) : ""); }
			},
			{
				targets: [7, "screenshot_url"],
				render: function (data, type, row) {
					const screenshotUrl = (row && row.screenshot_url) || data || "";
					if (!screenshotUrl) return "-";
					if (typeof window.ScreenshotDisplay !== "undefined" && typeof window.ScreenshotDisplay.buildThumbnailHtml === "function") {
						let port = 80;
						try {
							const url = new URL((row && row.http_url) || "http://x");
							port = url.port || (url.protocol === "https:" ? 443 : 80);
						} catch (_) {}
						return window.ScreenshotDisplay.buildThumbnailHtml({
							screenshotUrl: screenshotUrl,
							httpUrl: (row && row.http_url) || "",
							subdomainId: (row && row.subdomain_id) || "",
							subdomainName: (row && row.subdomain_name) || "",
							port: port,
							scanId: (row && row.scan_history_id) || "",
							domainId: (row && row.domain_id) || ""
						}) || "-";
					}
					return "-";
				}
			}
		],
		drawCallback: function () {
			const total = this.api().page.info().recordsTotal;
			if (total === 0) {
				$('#interesting_endpoint_div').remove();
			} else {
				$('.interesting-tab-show').removeAttr('style');
				$('#interesting_endpoint_alert_count').html(', ' + total + ' Interesting Endpoints');
				$('#interesting_endpoint_count_badge').empty().html('<span class="badge badge-soft-primary me-1">' + total + '</span>');
			}
			const tableEl = document.getElementById('interesting_endpoints');
			if (typeof Clipboard !== "undefined" && tableEl) {
				const clipboard = new Clipboard(tableEl, { selector: '.copyable' });
				clipboard.on("success", function (e) { if (typeof setTooltip === "function") setTooltip(e.trigger, "Copied!"); });
			}
			if (typeof window.ScreenshotDisplay !== "undefined" && typeof window.ScreenshotDisplay.attachDelegation === "function") {
				window.ScreenshotDisplay.attachDelegation("#interesting_endpoints");
			}
		}
	};
	const merged = Object.assign({}, scrollOpts, opts);
	if ($.fn.DataTable.isDataTable('#interesting_endpoints')) {
		$('#interesting_endpoints').DataTable().destroy();
	}
	if (typeof window.getRengineDatatableConfig === "function" && typeof window.initServerSideDataTable === "function") {
		window.initServerSideDataTable("#interesting_endpoints", window.getRengineDatatableConfig("#interesting_endpoints", merged));
	} else {
		if (typeof console !== "undefined" && console.warn) {
			console.warn("custom: getRengineDatatableConfig/initServerSideDataTable not found; ensure datatables/init.js loads before this script.");
		}
		$("#interesting_endpoints").DataTable(Object.assign({ serverSide: true, processing: true, responsive: true, layout: window.RENGINE_DATATABLE_LAYOUT_WITH_SEARCH }, merged));
	}
}

function get_important_subdomains(endpoint_url, target_id, scan_history_id) {
	let url = `${endpoint_url}?only_important&no_lookup_interesting&format=json`;
	if (target_id) {
		url += `&target_id=${target_id}`;
	} else if (scan_history_id) {
		url += `&scan_id=${scan_history_id}`;
	}
	$.getJSON(url, function(data) {
		$('#important-count').empty();
		$('#important-subdomains-list').empty();
		if (data['subdomains'].length > 0) {
			$('#important-count').html(`<span class="badge badge-soft-primary ms-1 me-1">${data['subdomains'].length}</span>`);
			for (let val in data['subdomains']) {
				const subdomain = data['subdomains'][val];
				const div_id = 'important_' + subdomain['id'];
				const safeSubdomainName = safeHtmlEncode(subdomain['name']);
				$("#important-subdomains-list").append(`
					<div id="${div_id}">
					<p>
					<span id="subdomain_${subdomain['id']}"> ${safeSubdomainName}
					<span class="">
					<a href="javascript:;" data-clipboard-action="copy" class="m-1 float-end badge-link text-info copyable text-primary" data-toggle="tooltip" data-placement="top" title="Copy Subdomain!" data-clipboard-target="#subdomain_${subdomain['id']}">
					<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-copy"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></span>
					</a>
					</span>
					</p>
					</div>
					<hr />
					`);
			}
		} else {
			$('#important-count').html(`<span class="badge badge-soft-primary ms-1 me-1">0</span>`);
			$('#important-subdomains-list').append(`<p>No subdomains marked as important!</p>`);
		}
		$('.bs-tooltip').tooltip();
	});
}

function mark_important_subdomain(url, row, subdomain_id) {
	if (row) {
		const tr = row.closest ? row.closest("tr") : (row.parentNode && row.parentNode.parentNode && row.parentNode.parentNode.parentNode) || null;
		if (tr) {
			if (tr.classList.contains("table-danger")) {
				tr.classList.remove("table-danger");
			} else {
				tr.classList.add("table-danger");
			}
		}
	}

	const data = {'subdomain_id': subdomain_id}

	if ($("#important_subdomain_" + subdomain_id).length == 0) {
		$("#subdomain-" + subdomain_id).prepend(`<span id="important_subdomain_${subdomain_id}"></span>`);
		setTooltip("#subdomain-" + subdomain_id, 'Marked Important!');
	} else {
		$("#important_subdomain_" + subdomain_id).remove();
		setTooltip("#subdomain-" + subdomain_id, 'Marked Un-Important!');
	}
	return fetch(url, {
		method: 'POST',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	});
}

function delete_scan(url) {

	swal.queue([{
		title: 'Are you sure you want to delete this scan history?',
		text: "You won't be able to revert this!",
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Delete',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(url, {
				method: 'POST',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken")
				}
			}).then(function(response) {
				return response.json();
			}).then(function(data) {
				// TODO Look for better way
				return location.reload();
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to delete the scan history!'
				})
			})
		}
	}]);
}

function stop_scan(url, scan_id=null, subscan_id=null, reload_scan_bar=true, reload_location=false) {

	let data;
	if (scan_id) {
		data = {'scan_id': scan_id};
	} else if (subscan_id) {
		data = {'subscan_id': subscan_id};
	} else {
		console.error('stop_scan: either scan_id or subscan_id is required');
		return;
	}
	swal.queue([{
		title: 'Are you sure you want to stop this scan?',
		text: "You won't be able to revert this!",
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Stop',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(url, {
				method: 'POST',
				credentials: "same-origin",
				body: JSON.stringify(data),
				headers: {
					"X-CSRFToken": getCookie("csrftoken"),
					"Content-Type": 'application/json',
				}
			}).then(function(response) {
				if (!response.ok) {
					throw new Error('Network response was not ok');
				}
				return response.json();
			}).then(function(data) {
				// TODO Look for better way
				if (data.status) {
					Snackbar.show({
						text: 'Scan Successfully Aborted.',
						pos: 'top-right',
						duration: 1500
					});
					if (reload_scan_bar) {
						try {
						getScanStatusSidebar();
						} catch (e) {
							console.error('Error reloading scan sidebar:', e);
						}
					}
					if (reload_location) {
						window.location.reload();
					}
					return true;
				} else {
					Snackbar.show({
						text: 'Oops! Could not abort the scan. ' + (data.message || ''),
						pos: 'top-right',
						duration: 1500
					});
					return false;
				}
			}).catch(function(error) {
				console.error('Error stopping scan:', error);
				Snackbar.show({
					text: 'Oops! Unable to stop the scan. ' + (error.message || ''),
					pos: 'top-right',
					duration: 1500
				});
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to stop the scan'
				});
				return false;
			});
		}
	}])
}

function stop_activity(url, activity_id=null, reload_scan_bar=true, reload_location=false) {
	if (!activity_id) {
		Snackbar.show({
			text: 'Activity ID is required',
			pos: 'top-right',
			duration: 1500
		});
		return;
	}

	const data = {'activity_id': activity_id}
	swal.queue([{
		title: 'Are you sure you want to stop this activity?',
		text: "You won't be able to revert this!",
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Stop',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(url, {
				method: 'POST',
				credentials: "same-origin",
				body: JSON.stringify(data),
				headers: {
					"X-CSRFToken": getCookie("csrftoken"),
					"Content-Type": 'application/json',
				}
			}).then(function(response) {
				return response.json();
			}).then(function(data) {
				if (data.status) {
					Snackbar.show({
						text: 'Activity Successfully Stopped.',
						pos: 'top-right',
						duration: 1500
					});
					if (reload_scan_bar) {
						getScanStatusSidebar();
					}
					if (reload_location) {
						window.location.reload();
					}
				} else {
					Snackbar.show({
						text: 'Oops! Could not stop the activity. ' + (data.message || ''),
						pos: 'top-right',
						duration: 1500
					});
				}
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to stop the activity'
				})
			})
		}
	}])
}

function stopAllScans() {
	const url = window.scanStatusApiUrls && window.scanStatusApiUrls.stopScanUrl;
	if (!url) {
		Snackbar.show({ text: 'Stop scan API URL not available.', pos: 'top-right', duration: 3000 });
		return;
	}
	const container = document.querySelector('.right-bar[data-scan-sidebar="true"] #currently_scanning');
	const cards = container ? container.querySelectorAll('.mini-card[id^="scan-card-"]') : [];
	const scanIds = [];
	cards.forEach(function(card) {
		const id = card.id && card.id.replace(/^scan-card-/, '');
		if (id) { scanIds.push(parseInt(id, 10)); }
	});
	if (scanIds.length === 0) {
		Snackbar.show({ text: 'No scans currently running.', pos: 'top-right', duration: 2000 });
		return;
	}
	const btn = document.getElementById('stop-all-scans-btn');
	if (btn) { btn.disabled = true; }
	swal.queue([{
		title: 'Stop all ' + scanIds.length + ' scans?',
		text: 'You won\'t be able to revert this!',
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Stop all',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			const promises = scanIds.map(function(scanId) {
				return fetch(url, {
					method: 'POST',
					credentials: 'same-origin',
					body: JSON.stringify({ scan_id: scanId }),
					headers: {
						'X-CSRFToken': getCookie('csrftoken'),
						'Content-Type': 'application/json'
					}
				}).then(function(r) { return r.json(); });
			});
			return Promise.all(promises).then(function(results) {
				const ok = results.filter(function(r) { return r && r.status; }).length;
				const fail = results.length - ok;
				if (fail > 0) {
					Snackbar.show({ text: 'Stopped ' + ok + ', failed ' + fail + '.', pos: 'top-right', duration: 3000 });
				} else {
					Snackbar.show({ text: 'All scans stopped.', pos: 'top-right', duration: 1500 });
				}
				if (typeof getScanStatusSidebar === 'function') {
					getScanStatusSidebar(null, null, null, null, { reload: true });
				}
			}).finally(function() {
				if (btn) { btn.disabled = false; }
			});
		}
	}]);
}

function stopAllTasks() {
	const url = window.scanStatusApiUrls && window.scanStatusApiUrls.stopActivityUrl;
	if (!url) {
		Snackbar.show({ text: 'Stop activity API URL not available.', pos: 'top-right', duration: 3000 });
		return;
	}
	const container = document.querySelector('.right-bar[data-scan-sidebar="true"] #currently_running_tasks');
	const cards = container ? container.querySelectorAll('.mini-card[data-activity-id]') : [];
	const activityIds = [];
	cards.forEach(function(card) {
		const id = card.getAttribute('data-activity-id');
		if (id) { activityIds.push(parseInt(id, 10)); }
	});
	if (activityIds.length === 0) {
		Snackbar.show({ text: 'No tasks currently running.', pos: 'top-right', duration: 2000 });
		return;
	}
	const btn = document.getElementById('stop-all-tasks-btn');
	if (btn) { btn.disabled = true; }
	swal.queue([{
		title: 'Stop all ' + activityIds.length + ' tasks?',
		text: 'You won\'t be able to revert this!',
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Stop all',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			const promises = activityIds.map(function(activityId) {
				return fetch(url, {
					method: 'POST',
					credentials: 'same-origin',
					body: JSON.stringify({ activity_id: activityId }),
					headers: {
						'X-CSRFToken': getCookie('csrftoken'),
						'Content-Type': 'application/json'
					}
				}).then(function(r) { return r.json(); });
			});
			return Promise.all(promises).then(function(results) {
				const ok = results.filter(function(r) { return r && r.status; }).length;
				const fail = results.length - ok;
				if (fail > 0) {
					Snackbar.show({ text: 'Stopped ' + ok + ', failed ' + fail + '.', pos: 'top-right', duration: 3000 });
				} else {
					Snackbar.show({ text: 'All tasks stopped.', pos: 'top-right', duration: 1500 });
				}
				if (typeof getScanStatusSidebar === 'function') {
					getScanStatusSidebar(null, null, null, null, { reload: true });
				}
			}).finally(function() {
				if (btn) { btn.disabled = false; }
			});
		}
	}]);
}

function extractContent(s) {
	const span = document.createElement('span');
	span.innerHTML = s;
	return span.textContent || span.innerText;
};

function delete_datatable_rows(table_id, rows_id, show_snackbar = true, snackbar_title) {
	// this function will delete the datatables rows after actions such as delete
	// table_id => datatable_id with #
	// rows_ids: list/array => list of all numerical ids to delete, to maintain consistency
	//     rows id will always follow this pattern: datatable_id_row_n
	// show_snackbar = bool => whether to show snackbar or not!
	// snackbar_title: str => snackbar title if show_snackbar = True
	const table = $(table_id).DataTable();
	for (let row in rows_id) {
		table.row(table_id + '_row_' + rows_id[row]).remove().draw();
	}
	Snackbar.show({
		text: snackbar_title,
		pos: 'top-right',
		duration: 1500,
		actionTextColor: '#fff',
		backgroundColor: '#e7515a',
	});
}

function delete_subscan(endpoint_url,subscan_id) {
	// This function will delete the sunscans using rest api
	// Supported method: POST
	const data = {
		'type': 'subscan',
		'rows': [subscan_id]
	}
	swal.queue([{
		title: 'Are you sure you want to delete this subscan?',
		text: "You won't be able to revert this!",
		icon: 'warning',
		showCancelButton: true,
		confirmButtonText: 'Delete',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(endpoint_url, {
				method: 'POST',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken"),
					"Content-Type": "application/json"
				},
				body: JSON.stringify(data)
			}).then(function(response) {
				return response.json();
			}).then(function(response) {
				if (response['status']) {
					delete_datatable_rows('#subscan_history_table', [subscan_id], show_snackbar = true, '1 Subscan Deleted!')
				}
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to delete the scan history!'
				})
			})
		}
	}])
}

function show_subscan_results(endpoint_url, subscan_id) {
	// This function will popup a modal and show the subscan results
	// modal being used is from base
	const api_url = endpoint_url + '?format=json&subscan_id=' + subscan_id;
	Swal.fire({
		title: 'Fetching Results...'
	});
	swal.showLoading();
	fetch(api_url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		swal.close();
		if (response['subscan']['status'] == -1) {
			swal.fire("Error!", "Scan has not yet started! Please wait for other scans to complete...", "warning", {
				button: "Okay",
			});
			return;
		}
		$('#xl-modal-title').empty();
		$('#xl-modal-content').empty();
		$('#xl-modal-footer').empty();
		const taskDisplayNames = {
			port_scan: 'Port Scan',
			naabu: 'Naabu',
			vulnerability_scan: 'Vulnerability Scan',
			nuclei: 'Nuclei',
			fetch_url: 'Fetch URLs',
			httpx: 'Httpx',
			dir_file_fuzz: 'Directory and Files Fuzzing',
			subdomain_discovery: 'Subdomain Discovery',
			subfinder: 'Subfinder',
			dnsx: 'Dnsx',
			screenshot: 'Screenshot'
		};
		const task = response['subscan']['task'] || response['subscan']['type'] || '';
		const task_name = taskDisplayNames[task] || (task ? task.charAt(0).toUpperCase() + task.slice(1) : 'Task');
		$('#xl-modal-title').html(`${task_name} Results on ${response['subscan']['subdomain_name']}`);
		let scan_status = '';
		let badge_color = 'danger';
		if (response['subscan']['status'] == 1) {
			badge_color = 'info';
			scan_status = 'Running';
		}
		else if (response['subscan']['status'] == 0) {
			scan_status = 'Failed';
		} else if (response['subscan']['status'] == 2) {
			scan_status = 'Successful';
			badge_color = 'success';
		} else if (response['subscan']['status'] == 3) {
			scan_status = 'Aborted';
		} else if (response['subscan']['status'] == 4) {
			badge_color = 'info';
			scan_status = 'Finalizing';
		} else {
			scan_status = 'Unknown';
		}
		$('#xl-modal-content').append(`<div>Scan Status: <span class="badge bg-${badge_color}">${scan_status}</span></div>`);
		const engineLabel = response['subscan']['engine'] ? htmlEncode(response['subscan']['engine']) : '—';
		$('#xl-modal-content').append(`<div class="mt-1">Engine Used: <span class="badge bg-primary">${engineLabel}</span></div>`);
		const resultTask = response['subscan']['task'] || response['subscan']['type'];
		const isPortScanResult = resultTask === 'port_scan' || resultTask === 'naabu';
		const isVulnResult = resultTask === 'vulnerability_scan' || resultTask === 'nuclei';
		const isEndpointResult = resultTask === 'fetch_url' || resultTask === 'httpx';
		const isDirFuzzResult = resultTask === 'dir_file_fuzz';
		if (response['result'].length > 0) {
			if (isPortScanResult) {
				$('#xl-modal-content').append(`<div id="port_results_li"></div>`);
				for (let ip in response['result']) {
					const ip_addr = response['result'][ip]['address'];
					const underscore_ip = ip_addr.replaceAll('.', '_');
					const id_name = `ip_${underscore_ip}`;
					$('#port_results_li').append(`<h5>IP Address: ${ip_addr}</br></br>${response['result'][ip]['ports'].length} Ports Open</h5>`);
					$('#port_results_li').append(`<ul id="${id_name}"></ul>`);
					for (let port_obj in response['result'][ip]['ports']) {
						const port = response['result'][ip]['ports'][port_obj];
						let port_color = 'primary';
						if (port["is_uncommon"]) {
							port_color = 'danger';
						}
						$(`#${id_name}`).append(`<li><span class="ms-1 mt-1 me-1 badge badge-soft-${port_color}">${port['number']}</span>/<span class="ms-1 mt-1 me-1 badge badge-soft-${port_color}">${port['service_name']}</span>/<span class="ms-1 mt-1 me-1 badge badge-soft-${port_color}">${port['description']}</span></li>`);
					}
				}
				$('#xl-modal-footer').append(`<span class="text-danger">* Uncommon Ports</span>`);
			} else if (isVulnResult) {
				const vulnUrl = response['vulnerability_url'] || (typeof window.DETAIL_SCAN_API_VULNERABILITIES_LIST !== 'undefined' ? window.DETAIL_SCAN_API_VULNERABILITIES_LIST : '');
				const subId = response['subscan'] && response['subscan']['subdomain'];
				const scanId = response['subscan'] && response['subscan']['scan_history'];
				render_vulnerability_in_xl_modal(vulnUrl, scanId, null, subId, response['subscan']['subdomain_name']);
			} else if (isEndpointResult) {
				const epUrl = response['endpoint_url'] || (typeof window.DETAIL_SCAN_API_ENDPOINTS_LIST !== 'undefined' ? window.DETAIL_SCAN_API_ENDPOINTS_LIST : '');
				const subId = response['subscan'] && response['subscan']['subdomain'];
				const scanId = response['subscan'] && response['subscan']['scan_history'];
				const proj = response['project'] || (typeof window.CURRENT_PROJECT_SLUG !== 'undefined' ? window.CURRENT_PROJECT_SLUG : '');
				render_endpoint_in_xl_modal(subId, response['subscan']['subdomain_name'], epUrl, proj, scanId);
			} else if (isDirFuzzResult) {
				if (response['result'][0]['directory_files'].length == 0) {
					$('#xl-modal-content').append(`
						<div class="alert alert-info mt-2" role="alert">
						<i class="mdi mdi-alert-circle-outline me-2"></i> ${task_name} could not fetch any results.
						</div>
					`);
				} else {
					const dirUrl = response['directories_url'] || (typeof window.DETAIL_SCAN_API_DIRECTORIES_LIST !== 'undefined' ? window.DETAIL_SCAN_API_DIRECTORIES_LIST : '');
					const subId = response['subscan'] && response['subscan']['subdomain'];
					const scanId = response['subscan'] && response['subscan']['scan_history'];
					render_directories_in_xl_modal(dirUrl, scanId, subId, response['subscan']['subdomain_name']);
				}
			}
		} else {
			const noResultsMsg = (response['subscan']['status'] === 2)
				? `${task_name} completed with no findings.`
				: `${task_name} could not fetch any results.`;
			$('#xl-modal-content').append(`
				<div class="alert alert-info mt-2" role="alert">
				<i class="mdi mdi-alert-circle-outline me-2"></i> ${noResultsMsg}
				</div>
				`);
		}
		if (window.ModalManager) ModalManager.showXlOnly();
		$("body").tooltip({
			selector: '[data-toggle=tooltip]'
		});
	});
}

function get_http_status_badge(data) {
	if (data == null || data === "") return "";
	const n = Number(data);
	if (n === 0) return "";
	const safeTextFn = typeof window.safeText === "function" ? window.safeText : function (x) { return x == null ? "" : String(x); };
	const display = safeTextFn(String(data));
	const cls = (n >= 200 && n < 300) ? "badge badge-soft-success" : (n >= 300 && n < 400) ? "badge badge-soft-warning" : "badge badge-soft-danger";
	const safeAttrFn = typeof window.safeAttr === "function" ? window.safeAttr : function (x) { return x; };
	return "<span class=\"" + safeAttrFn(cls) + "\">" + display + "</span>";
}

function render_endpoint_in_xl_modal(subdomain_id, subdomain_name, endpoint_url, project, scan_id) {
	if (!endpoint_url || typeof endpoint_url !== "string" || !endpoint_url.trim()) {
		$("#xl-modal-content").empty().append("<p class=\"text-danger mb-0\">Missing or invalid endpoint URL. Cannot load endpoint data.</p>");
		if (typeof console !== "undefined" && console.warn) console.warn("render_endpoint_in_xl_modal: missing or invalid endpoint_url");
		return;
	}
	$("#xl-modal-content").empty();
	$("#xl-modal-content").append(
		"<div class=\"\"><table id=\"endpoint-modal-datatable\" class=\"table dt-responsive w-100\"><thead><tr>" +
		"<th>HTTP URL</th><th>Status</th><th>Page Title</th><th>Tags</th><th>Content Type</th><th>Content Length</th><th>Response Time</th>" +
		"</tr></thead><tbody></tbody></table></div>"
	);
	if ($.fn.DataTable.isDataTable("#endpoint-modal-datatable")) {
		$("#endpoint-modal-datatable").DataTable().destroy();
		$("#endpoint-modal-datatable").empty();
	}
	const safeLinkFn = getRengineSafeLinkFn("text-primary");
	const safeTextFn = typeof window.safeText === "function" ? window.safeText : function (x) { return x == null ? "" : String(x); };
	const columns = [
		{ data: "http_url", name: "http_url" },
		{ data: "http_status", name: "http_status" },
		{ data: "page_title", name: "page_title" },
		{ data: "matched_gf_patterns", name: "matched_gf_patterns" },
		{ data: "content_type", name: "content_type" },
		{ data: "content_length", name: "content_length" },
		{ data: "response_time", name: "response_time" }
	];
	const httpStatusDef = (window.RengineDatatableColumnDefs && typeof window.RengineDatatableColumnDefs.getSubdomainHttpStatusBadgeColumnDef === "function")
		? window.RengineDatatableColumnDefs.getSubdomainHttpStatusBadgeColumnDef("http_status:name")
		: { targets: "http_status:name", className: "text-center", render: function (data) { return typeof get_http_status_badge === "function" ? get_http_status_badge(data) : (data != null ? data : ""); } };
	const columnDefs = [
		{ targets: "http_url:name", render: function (data, type) { if (type !== "display" || data == null) return data; const raw = String(data); const display = raw.length > 80 ? raw.slice(0, 77) + "..." : raw; return safeLinkFn(raw, display, { target: "_blank", className: "text-primary", title: raw }); } },
		httpStatusDef,
		{ targets: "page_title:name", render: function (data) { return data != null ? safeTextFn(data) : ""; } },
		{ targets: "matched_gf_patterns:name", render: function (data) { return data != null && typeof parse_comma_values_into_span === "function" ? parse_comma_values_into_span(data, "danger", true) : safeTextFn(data); } },
		{ targets: "content_type:name", render: function (data) { return data != null ? safeTextFn(data) : ""; } },
		{ targets: "content_length:name", render: function (data) { return data != null ? safeTextFn(data) : ""; } },
		{ targets: "response_time:name", render: function (data) { return typeof get_response_time_text === "function" ? get_response_time_text(data) : (data != null ? safeTextFn(data) : ""); } }
	];
	const opts = {
		ajax: {
			url: endpoint_url,
			data: function (d) {
				if (project) d.project = project;
				if (scan_id) d.scan_history = scan_id;
				if (subdomain_id) d.subdomain_id = subdomain_id;
			}
		},
		columns: columns,
		columnDefs: columnDefs,
		order: [[5, "desc"]],
		drawCallback: function () { if ($(".dt-paging > .pagination").length) $(".dt-paging > .pagination").addClass("pagination-rounded"); }
	};
	const config = typeof window.getRengineDatatableConfig === "function" ? window.getRengineDatatableConfig("#endpoint-modal-datatable", opts) : opts;
	typeof window.initServerSideDataTable === "function" ? window.initServerSideDataTable("#endpoint-modal-datatable", config) : $("#endpoint-modal-datatable").DataTable(config);
}

function render_vulnerability_in_xl_modal(endpoint_url, scan_id, severity, subdomain_id, subdomain_name) {
	if (!endpoint_url || typeof endpoint_url !== "string" || !endpoint_url.trim()) {
		$("#xl-modal-content").empty().append("<p class=\"text-danger mb-0\">Missing or invalid endpoint URL. Cannot load vulnerability data.</p>");
		if (typeof console !== "undefined" && console.warn) console.warn("render_vulnerability_in_xl_modal: missing or invalid endpoint_url");
		return;
	}
	$("#xl-modal-content").empty();
	$("#xl-modal-content").append(
		"<div class=\"\"><table id=\"vulnerability-modal-datatable\" class=\"table dt-responsive w-100\"><thead><tr>" +
		"<th>Type</th><th>Title</th><th class=\"text-center\">Severity</th><th>CVSS Score</th><th>CVE/CWE</th><th>Vulnerable URL</th><th class=\"text-center dt-no-sorting\">Action</th>" +
		"</tr></thead><tbody></tbody></table></div>"
	);
	if ($.fn.DataTable.isDataTable("#vulnerability-modal-datatable")) {
		$("#vulnerability-modal-datatable").DataTable().destroy();
		$("#vulnerability-modal-datatable").empty();
	}
	const safeLinkFn = getRengineSafeLinkFn("text-danger");
	const safeTextFn = typeof window.safeText === "function" ? window.safeText : function (x) { return x == null ? "" : String(x); };
	const columns = [
		{ data: "type", name: "type" },
		{ data: "name", name: "name" },
		{ data: "severity", name: "severity" },
		{ data: "cvss_score", name: "cvss_score" },
		{ data: "cve_ids", name: "cve_ids", orderable: false },
		{ data: "http_url", name: "http_url" },
		{ data: "id", name: "id", orderable: false }
	];
	const columnDefs = [
		{ targets: 0, render: function (data) { return data != null && data !== "" ? "<span class=\"badge badge-soft-primary\">&nbsp;&nbsp;" + safeTextFn(data).toUpperCase() + "&nbsp;&nbsp;</span>" : ""; } },
		{ targets: 1, render: function (data, type, row) { if (!data) return ""; const n = safeTextFn(data); const sev = row.severity || ""; const color = (sev === "Critical" || sev === "High") ? "danger" : (sev === "Medium" ? "warning" : "primary"); return "<b class=\"text-" + color + "\">" + n + "</b>"; } },
		{ targets: 2, className: "text-center", render: function (data) { return typeof get_severity_badge === "function" ? get_severity_badge(data) : safeTextFn(data); } },
		{ targets: 3, className: "text-center", render: function (data) { if (data == null || data === "") return ""; const b = data > 6.9 ? "danger" : (data > 3.9 ? "warning" : "info"); return "<span class=\"badge badge-outline-" + b + "\">" + safeTextFn(data) + "</span>"; } },
		{ targets: 4, render: function (data, type, row) { const out = []; [].concat(row.cve_ids || [], row.cwe_ids || []).forEach(function (c) { const name = (c && c.name) ? String(c.name).toUpperCase() : ""; if (name) out.push("<a href=\"https://google.com/search?q=" + encodeURIComponent(name) + "\" target=\"_blank\" class=\"badge badge-outline-primary me-1 mt-1\">" + safeTextFn(name) + "</a>"); }); return out.join(" ") || ""; } },
		{ targets: 5, render: function (data) { if (!data) return ""; const url = (typeof window.safeAttr === "function" ? window.safeAttr(data) : data); return url && url.indexOf("http") !== -1 ? safeLinkFn(data, data) : safeTextFn(data); } },
		{ targets: 6, orderable: false, render: function (data, type, row) {
			if (row.hackerone_report_id) return "";
			const reportUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.vulnerabilityReport) || window.REPORT_HACKERONE_URL || "";
			const idVal = (data != null && data !== "") ? String(data) : "";
			const sev = (row && row.severity != null) ? String(row.severity) : "";
			const safeUrl = typeof window.safeAttr === "function" ? window.safeAttr(reportUrl) : reportUrl;
			const safeId = typeof window.safeAttr === "function" ? window.safeAttr(idVal) : idVal;
			const safeSev = typeof window.safeAttr === "function" ? window.safeAttr(sev) : sev;
			return "<div class=\"btn-group mb-2 dropstart\"><a href=\"#\" class=\"text-dark dropdown-toggle float-end\" data-bs-toggle=\"dropdown\"><span class=\"feather fe-more-horizontal\"></span></a><div class=\"dropdown-menu\"><a class=\"dropdown-item js-report-hackerone\" href=\"#\" data-report-url=\"" + safeUrl + "\" data-vulnerability-id=\"" + safeId + "\" data-severity=\"" + safeSev + "\">Report to Hackerone</a></div></div>";
		} }
	];
	const opts = {
		ajax: {
			url: endpoint_url,
			data: function (d) {
				if (scan_id) d.scan_history = scan_id;
				if (severity != null) d.severity = severity;
				if (subdomain_id) d.subdomain_id = subdomain_id;
			}
		},
		columns: columns,
		columnDefs: columnDefs,
		order: [[2, "desc"]],
		drawCallback: function () { if ($(".dt-paging > .pagination").length) $(".dt-paging > .pagination").addClass("pagination-rounded"); }
	};
	const config = typeof window.getRengineDatatableConfig === "function" ? window.getRengineDatatableConfig("#vulnerability-modal-datatable", opts) : opts;
	typeof window.initServerSideDataTable === "function" ? window.initServerSideDataTable("#vulnerability-modal-datatable", config) : $("#vulnerability-modal-datatable").DataTable(config);
}

function render_directories_in_xl_modal(endpoint_url, scan_id, subdomain_id, subdomain_name) {
	if (!endpoint_url || typeof endpoint_url !== "string" || !endpoint_url.trim()) {
		$("#xl-modal-content").empty().append("<p class=\"text-danger mb-0\">Missing or invalid endpoint URL. Cannot load directory data.</p>");
		if (typeof console !== "undefined" && console.warn) console.warn("render_directories_in_xl_modal: missing or invalid endpoint_url");
		return;
	}
	$("#xl-modal-content").empty();
	$("#xl-modal-content").append(
		"<div class=\"\"><table id=\"directory-modal-datatable\" class=\"table dt-responsive w-100\"><thead><tr>" +
		"<th>Base URL</th><th>Directory</th><th class=\"text-center\">HTTP Status</th><th>Content Length</th><th>Lines</th><th>Words</th>" +
		"</tr></thead><tbody></tbody></table></div>"
	);
	if ($.fn.DataTable.isDataTable("#directory-modal-datatable")) {
		$("#directory-modal-datatable").DataTable().destroy();
		$("#directory-modal-datatable").empty();
	}
	const safeLinkFn = getRengineSafeLinkFn("text-primary");
	const safeTextFn = typeof window.safeText === "function" ? window.safeText : function (x) { return x == null ? "" : String(x); };
	const columns = [
		{ data: "url", name: "url" },
		{ data: "name", name: "name" },
		{ data: "http_status", name: "http_status" },
		{ data: "length", name: "length" },
		{ data: "lines", name: "lines" },
		{ data: "words", name: "words" }
	];
	const dirHttpStatusDef = (window.RengineDatatableColumnDefs && typeof window.RengineDatatableColumnDefs.getSubdomainHttpStatusBadgeColumnDef === "function")
		? window.RengineDatatableColumnDefs.getSubdomainHttpStatusBadgeColumnDef("http_status:name")
		: { targets: "http_status:name", className: "text-center", render: function (data) { return typeof get_http_status_badge === "function" ? get_http_status_badge(data) : safeTextFn(data); } };
	const columnDefs = [
		{ targets: "url:name", render: function (data) { if (!data) return ""; try { const origin = new URL(data).origin; return safeLinkFn(origin, origin, { target: "_blank" }); } catch (e) { return safeLinkFn(data, safeTextFn(data), { target: "_blank" }); } } },
		{ targets: "name:name", render: function (data, type, row) { return data != null && row.url ? safeLinkFn(row.url, safeTextFn(data), { target: "_blank" }) : safeTextFn(data); } },
		dirHttpStatusDef,
		{ targets: "length:name", render: function (data) { return safeTextFn(data); } },
		{ targets: "lines:name", render: function (data) { return safeTextFn(data); } },
		{ targets: "words:name", render: function (data) { return safeTextFn(data); } }
	];
	const opts = {
		ajax: {
			url: endpoint_url,
			data: function (d) {
				if (scan_id) d.scan_history = scan_id;
				if (subdomain_id) d.subdomain_id = subdomain_id;
			}
		},
		columns: columns,
		columnDefs: columnDefs,
		order: [[1, "asc"]],
		drawCallback: function () { if ($(".dt-paging > .pagination").length) $(".dt-paging > .pagination").addClass("pagination-rounded"); }
	};
	const config = typeof window.getRengineDatatableConfig === "function" ? window.getRengineDatatableConfig("#directory-modal-datatable", opts) : opts;
	typeof window.initServerSideDataTable === "function" ? window.initServerSideDataTable("#directory-modal-datatable", config) : $("#directory-modal-datatable").DataTable(config);
}

function render_certificate_in_xl_modal(subdomain_id, subdomain_name, scan_id) {
	const enc = typeof htmlEncode === "function" ? htmlEncode : function (x) { return x == null ? "" : String(x); };
	const title = "Certificate(s) for " + (subdomain_name ? enc(subdomain_name) : "");
	$("#xl-modal-title").empty().html(title);
	$("#xl-modal-content").empty();
	$("#xl-modal-footer").empty();
	if (window.ModalManager) {
		ModalManager.setXlTitle(title);
		ModalManager.setXlContent({ bodyHtml: "", footerHtml: "" });
		ModalManager.showXlOnly();
	} else {
		var modalEl = document.getElementById("modal-xl-scroll-dialog");
		if (modalEl && typeof bootstrap !== "undefined" && bootstrap.Modal) {
			var modalInst = bootstrap.Modal.getOrCreateInstance(modalEl);
			modalInst.show();
		}
	}
	$("#xl-modal-content").append("<p class=\"text-muted\"><i class=\"fas fa-spinner fa-spin\"></i> Loading certificate(s)...</p>");
	var apiUrl = (typeof window.DETAIL_SCAN_API_CERTIFICATES_LIST !== "undefined" ? window.DETAIL_SCAN_API_CERTIFICATES_LIST : "") || "";
	if (!apiUrl) {
		$("#xl-modal-content").empty().append("<p class=\"text-danger mb-0\">Certificate API URL not configured.</p>");
		return;
	}
	var params = "subdomain_id=" + encodeURIComponent(String(subdomain_id));
	if (scan_id != null && scan_id !== "") params += "&scan_id=" + encodeURIComponent(String(scan_id));
	var url = apiUrl + (apiUrl.indexOf("?") !== -1 ? "&" : "?") + params;
	fetch(url, {
		method: "GET",
		credentials: "same-origin",
		headers: { "X-CSRFToken": typeof getCookie === "function" ? getCookie("csrftoken") : "", "X-Requested-With": "XMLHttpRequest" }
	}).then(function (resp) { return resp.ok ? resp.json() : Promise.reject(new Error("Request failed")); }).then(function (data) {
		var certs = data && data.certificates ? data.certificates : [];
		$("#xl-modal-content").empty();
		if (certs.length === 0) {
			$("#xl-modal-content").append("<p class=\"text-muted mb-0\">No certificate(s) found for this subdomain.</p>");
			return;
		}
		function formatCert(cert, index) {
			var subjCn = cert.subject_cn != null ? enc(cert.subject_cn) : "—";
			var issuerCn = cert.issuer_cn != null ? enc(cert.issuer_cn) : (cert.issuer != null ? enc(cert.issuer) : "—");
			var notBefore = cert.not_before_display != null ? enc(cert.not_before_display) : (cert.not_before != null ? enc(cert.not_before) : "—");
			var notAfter = cert.not_after_display != null ? enc(cert.not_after_display) : (cert.not_after != null ? enc(cert.not_after) : "—");
			var host = cert.host != null ? enc(cert.host) : "—";
			var fp = cert.fingerprint_sha256 ? enc(cert.fingerprint_sha256) : "";
			var fpShort = fp.length > 24 ? fp.slice(0, 24) + "…" : fp;
			var status = cert.status != null ? enc(cert.status) : "";
			var keysize = cert.keysize != null ? String(cert.keysize) : "—";
			var selfSigned = cert.self_signed === true ? "<span class=\"badge badge-soft-warning\">Self-signed</span>" : "";
			var trusted = cert.trusted === true ? "<span class=\"badge badge-soft-success\">Trusted</span>" : "";
			var expired = cert.is_expired === true ? "<span class=\"badge badge-soft-danger\">Expired</span>" : "";
			var sans = "";
			if (cert.subject_an && Array.isArray(cert.subject_an) && cert.subject_an.length > 0) {
				sans = "<div class=\"mt-1\"><strong>Subject Alternative Names:</strong> <span class=\"text-break\">" + cert.subject_an.map(function (s) { return enc(s); }).join(", ") + "</span></div>";
			}
			var cardTitle = certs.length > 1 ? "Certificate #" + (index + 1) + " – " + host : "Certificate details";
			var html = "<div class=\"card mb-3\"><div class=\"card-header\">" + cardTitle + "</div><div class=\"card-body\">" +
				"<div><strong>Subject CN:</strong> " + subjCn + "</div>" +
				(sans ? sans : "") +
				"<div class=\"mt-1\"><strong>Issuer:</strong> " + issuerCn + "</div>" +
				"<div class=\"mt-1\"><strong>Valid from:</strong> " + notBefore + " <strong>to</strong> " + notAfter + " " + expired + "</div>" +
				"<div class=\"mt-1\">" + selfSigned + " " + trusted + (status ? " <span class=\"badge badge-soft-info\">" + status + "</span>" : "") + " <span class=\"badge badge-outline-secondary\">" + keysize + " bits</span></div>" +
				(fp ? "<div class=\"mt-1 small text-muted\"><strong>Fingerprint (SHA256):</strong> <code title=\"" + fp + "\">" + fpShort + "</code></div>" : "") +
				"</div></div>";
			return html;
		}
		for (var i = 0; i < certs.length; i++) {
			$("#xl-modal-content").append(formatCert(certs[i], i));
		}
	}).catch(function () {
		$("#xl-modal-content").empty().append("<p class=\"text-danger mb-0\">Failed to load certificate(s).</p>");
	});
}

function get_and_render_subscan_history(endpoint, subdomain_id, subdomain_name) {
	const payload = { subdomain_id: subdomain_id };
	fetch(endpoint + '?format=json', {
		method: 'POST',
		credentials: 'same-origin',
		body: JSON.stringify(payload),
		headers: {
			'X-CSRFToken': getCookie('csrftoken'),
			'Content-Type': 'application/json'
		}
	}).then(function (response) { return response.json(); }).then(function (data) {
		if (!data.status) return;
		const title = 'Subscan History for subdomain ' + subdomain_name;
		let cardsHtml = '';
		const results = data.results || [];
		for (let i = 0; i < results.length; i++) {
			const result_obj = results[i];
			const status = result_obj.effective_status !== undefined && result_obj.effective_status !== null
				? result_obj.effective_status : result_obj.status;
			const task_name = typeof get_task_name === 'function' ? get_task_name(result_obj) : (result_obj.formatted_task_name || result_obj.type || 'Unknown');
			const subdomain_label = result_obj.subdomain_name != null && result_obj.subdomain_name !== '' ? result_obj.subdomain_name : '—';
			const engine_label = result_obj.engine != null && result_obj.engine !== '' ? result_obj.engine : '—';
			const hasCompletedAgo = result_obj.completed_ago != null && result_obj.completed_ago !== '';
			const hasTimeTaken = result_obj.time_taken != null && result_obj.time_taken !== '';
			const completed_ago = hasCompletedAgo ? result_obj.completed_ago : null;
			const time_taken = hasTimeTaken ? result_obj.time_taken : null;
			const errMsg = result_obj.error_message != null && result_obj.error_message !== ''
				? `</br><span class="text-danger">Error: ${result_obj.error_message}</span>` : '';

			let color = 'secondary';
			let bg_color = 'bg-soft-secondary';
			let status_badge = '<span class="float-end badge bg-secondary">—</span>';
			if (status === 0) {
				color = 'danger';
				bg_color = 'bg-soft-danger';
				status_badge = '<span class="float-end badge bg-danger">Failed</span>';
			} else if (status === 3) {
				color = 'danger';
				bg_color = 'bg-soft-danger';
				status_badge = '<span class="float-end badge bg-danger">Aborted</span>';
			} else if (status === 2) {
				color = 'success';
				bg_color = 'bg-soft-success';
				status_badge = '<span class="float-end badge bg-success">Task Completed</span>';
			} else if (status === 1) {
				color = 'primary';
				bg_color = 'bg-soft-primary';
				status_badge = '<span class="float-end badge bg-primary">Running</span>';
			} else if (status === 4) {
				color = 'info';
				bg_color = 'bg-soft-info';
				status_badge = '<span class="float-end badge bg-info">Finalizing</span>';
			}
			let statusLine;
			if (status === 1 || status === 4) {
				statusLine = 'In progress';
			} else if (status === 2 && completed_ago && time_taken) {
				statusLine = 'Task Completed ' + completed_ago + ' ago — Took ' + time_taken;
			} else if (status === 2 && completed_ago) {
				statusLine = 'Task Completed ' + completed_ago + ' ago';
			} else if (status === 2 && time_taken) {
				statusLine = 'Took ' + time_taken;
			} else if (completed_ago) {
				statusLine = 'Task Completed ' + completed_ago + ' ago';
			} else if (time_taken) {
				statusLine = 'Took ' + time_taken;
			} else {
				statusLine = '—';
			}
			const safeEngine = typeof htmlEncode === 'function' ? htmlEncode(engine_label) : engine_label;
			const safeTaskName = typeof htmlEncode === 'function' ? htmlEncode(task_name) : task_name;
			const safeSubdomain = typeof htmlEncode === 'function' ? htmlEncode(subdomain_label) : subdomain_label;
			const safeEndpoint = (endpoint || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
			cardsHtml += `<div class="card border-${color} border mini-card"><a href="#" class="text-reset item-hovered" onclick="show_subscan_results('${safeEndpoint}', ${result_obj.id})"><div class="card-header ${bg_color} text-${color} mini-card-header">${safeTaskName} on <b>${safeSubdomain}</b> using engine <b>${safeEngine}</b></div><div class="card-body mini-card-body"><p class="card-text">${status_badge}<span class="">${statusLine}</span>${errMsg}</p></div></a></div>`;
		}
		const bodyHtml = `<div id="subscan_history_table">${cardsHtml}</div>`;
		if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml, footerHtml: '' });
	});
}

function show_quick_add_target_modal() {
	if (window.ModalManager) ModalManager.showById(ModalManager.MODAL_IDS.ADD_TARGET);
}

$(document).on('click', '#add_target_modal', function(){
	// this function will be a onclick for add target button on add_target modal
	if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.ADD_TARGET);
	const endpoint_url = $(this).data('url');
	const current_slug = $(this).data('slug');
	const domain_name = $('#target_name_modal').val();
	const description = $('#target_description_modal').val();
	const h1_handle = $('#h1_handle_modal').val();
	const organization = $('#target_organization_modal').val();
	add_target(endpoint_url, current_slug, domain_name, h1_handle, description, organization);
});


function add_target(endpoint_url, current_slug, domain_name, h1_handle = null, description = null, organization = null) {
	// this function will add domain_name as target
	const add_api = endpoint_url + '?format=json';
	const data = {
		'domain_name': domain_name,
		'h1_team_handle': h1_handle,
		'description': description,
		'organization': organization,
		'slug': current_slug
	};
	swal.queue([{
		title: 'Add Target',
		text: `Would you like to add ${domain_name} as target?`,
		icon: 'info',
		showCancelButton: true,
		confirmButtonText: 'Add Target',
		padding: '2em',
		showLoaderOnConfirm: true,
		preConfirm: function() {
			return fetch(add_api, {
				method: 'POST',
				credentials: "same-origin",
				headers: {
					'X-CSRFToken': getCookie("csrftoken"),
					'Content-Type': 'application/json'
				},
				body: JSON.stringify(data)
			}).then(function(response) {
				return response.json();
			}).then(function(data) {
				if (data.status) {
					swal.queue([{
						title: 'Target Successfully added!',
						text: `Do you wish to initiate the scan on new target?`,
						icon: 'success',
						showCancelButton: true,
						confirmButtonText: 'Initiate Scan',
						padding: '2em',
						showLoaderOnConfirm: true,
						preConfirm: function() {
							window.location = `${data.initiate_scan_url}`;
						}
					}]);
				} else {
					swal.insertQueueStep({
						icon: 'error',
						title: data.message
					});
				}
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to add target !'
				});
			})
		}
	}]);
}


function loadSubscanHistoryWidget(endpoint, scan_history_id = null, domain_id = null, limit = null) {
	// This function will load the subscan history widget
	let data = {};
	if (scan_history_id) {
		data = { 'scan_history_id': scan_history_id };
	}
	if (domain_id) {
		data = { 'domain_id': domain_id };
	}
	if (limit != null) {
		data['limit'] = limit;
	}

	fetch(endpoint + '?format=json', {
		method: 'POST',
		credentials: "same-origin",
		body: JSON.stringify(data),
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			"Content-Type": 'application/json',
		}
	}).then(function(response) {
		return response.json();
	}).then(function(data) {
		$('#subscan_history_widget').empty();
		$('#sub_scan_history_count').empty();
		const totalCount = data['total_count'] !== undefined ? data['total_count'] : (Array.isArray(data['results']) ? data['results'].length : 0);
		if (data['total_count'] !== undefined || (data['status'] && Array.isArray(data['results']))) {
			$('#sub_scan_history_count').append(
				`<span class="badge badge-soft-primary me-1">${totalCount}</span>`
			);
		}
		if (data['status'] && Array.isArray(data['results']) && data['results'].length > 0) {
			for (let result in data['results']) {
				const result_obj = data['results'][result];
				const status = result_obj.effective_status !== undefined && result_obj.effective_status !== null
					? result_obj.effective_status : result_obj.status;
				const task_name = get_task_name(result_obj);
				const subdomain_label = result_obj.subdomain_name != null && result_obj.subdomain_name !== ''
					? result_obj.subdomain_name : '—';
				const hasCompletedAgo = result_obj.completed_ago != null && result_obj.completed_ago !== '';
				const hasTimeTaken = result_obj.time_taken != null && result_obj.time_taken !== '';
				const completed_ago = hasCompletedAgo ? result_obj.completed_ago : null;
				const time_taken = hasTimeTaken ? result_obj.time_taken : null;
				const errMsg = result_obj.error_message != null && result_obj.error_message !== ''
					? `</br><span class="text-danger">Error: ${result_obj.error_message}</span>` : '';

				let color = 'secondary';
				let bg_color = 'bg-soft-secondary';
				let status_badge = '<span class="float-end badge bg-secondary">—</span>';
				if (status === 0) {
					color = 'danger';
					bg_color = 'bg-soft-danger';
					status_badge = '<span class="float-end badge bg-danger">Failed</span>';
				} else if (status === 3) {
					color = 'danger';
					bg_color = 'bg-soft-danger';
					status_badge = '<span class="float-end badge bg-danger">Aborted</span>';
				} else if (status === 2) {
					color = 'success';
					bg_color = 'bg-soft-success';
					status_badge = '<span class="float-end badge bg-success">Task Completed</span>';
				} else if (status === 1) {
					color = 'primary';
					bg_color = 'bg-soft-primary';
					status_badge = '<span class="float-end badge bg-primary">Running</span>';
				} else if (status === 4) {
					color = 'info';
					bg_color = 'bg-soft-info';
					status_badge = '<span class="float-end badge bg-info">Finalizing</span>';
				}

				let statusLine;
				if (status === 1 || status === 4) {
					statusLine = 'In progress';
				} else if (status === 2 && completed_ago && time_taken) {
					statusLine = 'Task Completed ' + completed_ago + ' ago — Took ' + time_taken;
				} else if (status === 2 && completed_ago) {
					statusLine = 'Task Completed ' + completed_ago + ' ago';
				} else if (status === 2 && time_taken) {
					statusLine = 'Took ' + time_taken;
				} else if (completed_ago) {
					statusLine = 'Task Completed ' + completed_ago + ' ago';
				} else if (time_taken) {
					statusLine = 'Took ' + time_taken;
				} else {
					statusLine = '—';
				}

				$('#subscan_history_widget').append(`
					<div class="card border-${color} border mini-card">
					<a href="#" class="text-reset item-hovered" onclick="show_subscan_results(${result_obj['id']})">
					<div class="card-header ${bg_color} text-${color} mini-card-header">
					${task_name} on <b>${subdomain_label}</b>
					</div>
					<div class="card-body mini-card-body">
					<p class="card-text">
					${status_badge}
					<span class="">${statusLine}</span>
					${errMsg}
					</p>
					</div>
					</a>
					</div>
					`);
			}
		} else {
			$('#sub_scan_history_count').append(
				'<span class="badge badge-soft-primary me-1">0</span>'
			);
			$('#subscan_history_widget').append(`
					<div class="alert alert-warning alert-dismissible fade show mt-2" role="alert">
					<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
					No Subscans has been initiated for any subdomains. You can select individual subdomains and initiate subscans like Directory Fuzzing, Vulnerability Scan etc.
					</div>
				`);
		}
	});
}

function get_technologies(endpoint_url, subdomain_endpoint_url, scan_id=null, domain_id=null){
	// this function will fetch and render tech in widget
	const params = [];
	if (scan_id) {
		params.push(`scan_id=${scan_id}`);
	}
	if (domain_id) {
		params.push(`target_id=${domain_id}`);
	}
	params.push('format=json');
	const url = `${endpoint_url}?${params.join('&')}`;

	$.getJSON(url, function(data) {
		$('#technologies-count').empty();
		for (let val in data['technologies']){
			const tech = data['technologies'][val]
			if (scan_id) {
				$("#technologies").append(`<span class='badge badge-soft-primary  m-1 badge-link' data-toggle="tooltip" title="${tech['count']} Subdomains use this technology." onclick="get_tech_details('${subdomain_endpoint_url}', '${tech['name']}', scan_id=${scan_id}, domain_id=null)">${tech['name']}</span>`);
			}
			else if (domain_id) {
				$("#technologies").append(`<span class='badge badge-soft-primary  m-1 badge-link' data-toggle="tooltip" title="${tech['count']} Subdomains use this technology." onclick="get_tech_details('${subdomain_endpoint_url}', '${tech['name']}', scan_id=null, domain_id=${domain_id})">${tech['name']}</span>`);
			}
		}
		const totalCount = data['total_count'] !== undefined ? data['total_count'] : data['technologies'].length;
		const countLabel = totalCount > data['technologies'].length
			? `${data['technologies'].length} (of ${totalCount})`
			: String(data['technologies'].length);
		$('#technologies-count').html(`<span class="badge badge-soft-primary me-1">${countLabel}</span>`);
		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
	});
}

function get_tech_details(endpoint_subdomain_url, tech, scan_id=null, domain_id=null){

	let url = `${endpoint_subdomain_url}?tech=${tech}`;

	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		url += `&target_id=${domain_id}`;
	}

	url += `&format=json`;

	const safeTech = typeof htmlEncode === 'function' ? htmlEncode(tech) : tech;
	const titleHtml = 'Details for Technology: <b>' + safeTech + '</b>';
	const loaderHtml = '<div class="outer-div" id="modal-loader"><span class="inner-div spinner-border text-primary align-self-center loader-sm"></span></div>';
	if (window.ModalManager) {
		ModalManager.showDialog({ title: titleHtml, bodyHtml: loaderHtml, footerHtml: '' });
	} else {
		$('#modal-dialog-title').html(titleHtml);
		$('#modal-dialog-body').html(loaderHtml);
		$('#modal-dialog-footer').empty();
		$('#modal-dialog').modal('show');
	}

	$.getJSON(url, function(data) {
		const interesting_badge = '<span class="m-1 badge badge-soft-danger bs-tooltip" title="Interesting Subdomain">Interesting</span>';
		const subdomains = data['subdomains'] || [];
		let listHtml = '';
		for (let i = 0; i < subdomains.length; i++) {
			const subdomain_obj = subdomains[i];
			const badge_color = subdomain_obj['http_status'] >= 400 ? 'danger' : '';
			const li_id = get_randid();
			const safeName = typeof htmlEncode === 'function' ? htmlEncode(subdomain_obj['name']) : subdomain_obj['name'];
			let liContent = '';
			if (subdomain_obj['http_url']) {
				liContent = `<a href="${subdomain_obj['http_url'].replace(/"/g, '&quot;')}" target="_blank" class="text-${badge_color}">${safeName}</a>`;
			} else {
				liContent = `<span class="text-${badge_color}">${safeName}</span>`;
			}
			if (subdomain_obj['http_status']) {
				const badge = get_http_badge(subdomain_obj['http_status']);
				liContent += badge || '';
			}
			if (subdomain_obj['is_interesting']) {
				liContent += interesting_badge;
			}
			listHtml += `<li id="${li_id}">${liContent}</li>`;
		}
		const bodyHtml = `${subdomains.length} Subdomains are using ${safeTech}<div class="modal-text"><ul>${listHtml}</ul><span class="float-end text-danger">*Subdomains highlighted are 40X HTTP Status</span></div>`;
		$('#modal-dialog-body').html(bodyHtml);
		$('.bs-tooltip').tooltip();
	}).fail(function(){
		$('#modal-dialog-body').html('');
	});
}


function get_http_badge(http_status){
	let badge_color;
	switch (true) {
		case (http_status >= 400):
			badge_color = 'danger';
			break;
		case (http_status >= 300):
			badge_color = 'warning';
			break;
		case (http_status >= 200):
			badge_color = 'success';
			break;
		default:
			badge_color = 'danger';
	}
	if (http_status) {
		const badge = `<span class="badge badge-soft-${badge_color} me-1 ms-1 bs-tooltip" data-placement="top" title="HTTP Status">${http_status}</span>`;
		return badge;
	}
}


function get_most_vulnerable_target(endpoint_url, endpoint_vuln_url, slug=null, scan_id=null, target_id=null, ignore_info=false, limit=50){
	$('#most_vulnerable_target_div').empty();
	$('#most_vulnerable_spinner').append(`<div class="spinner-border text-primary m-2" role="status"></div>`);
	const data = {};
	if (scan_id) {
		data['scan_history_id'] = scan_id;
	}
	else if (target_id) {
		data['target_id'] = target_id;
	}
	if (slug) {
		data['slug'] = slug;
	}
	data['ignore_info'] = ignore_info;
	data['limit'] = limit;

	fetch(endpoint_url, {
		method: 'POST',
		credentials: "same-origin",
		body: JSON.stringify(data),
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			"Content-Type": 'application/json',
		}
	}).then(function(response) {
		return response.json();
	}).then(function(response) {
		$('#most_vulnerable_spinner').empty();
		if (response.status) {
			$('#most_vulnerable_target_div').append(`
				<table class="table table-borderless table-nowrap table-hover table-centered m-0">
				<thead>
				<tr>
				<th class="col-width-60">Target</th>
				<th class="col-width-30">Vulnerabilities Count</th>
				</tr>
				</thead>
				<tbody id="most_vulnerable_target_tbody">
				</tbody>
				</table>
				`);

			for (let res in response.result) {
				const targ_obj = response.result[res];
				const tr = (scan_id || target_id)
					? `<tr onclick="window.location='${endpoint_vuln_url}?subdomain=${targ_obj.name}';" class="clickable-row">`
					: `<tr onclick="window.location='${endpoint_vuln_url}?domain=${targ_obj.name}';" class="clickable-row">`;
				$('#most_vulnerable_target_tbody').append(`
					${tr}
						<td>
							<h5 class="m-0 fw-normal">${targ_obj.name}</h5>
						</td>
						<td>
							<span class="badge badge-outline-danger">${targ_obj.vuln_count} Vulnerabilities</span>
						</td>
					</tr>
				`);
			}
		}
		else{
			$('#most_vulnerable_target_div').append(`
				<div class="mt-4 alert alert-warning">
				Could not find most vulnerable targets.
				</br>
				Once the vulnerability scan is performed, reNgine will identify the most vulnerable targets.</div>
			`);
		}
	});
}


function get_most_common_vulnerability(endpoint_url, endpoint_vuln_url, slug=null, scan_id=null, target_id=null, ignore_info=false, limit=50){
	$('#most_common_vuln_div').empty();
	$('#most_common_vuln_spinner').append(`<div class="spinner-border text-primary m-2" role="status"></div>`);
	const data = {};
	if (scan_id) {
		data['scan_history_id'] = scan_id;
	}
	else if (target_id) {
		data['target_id'] = target_id;
	}
	if (slug) {
		data['slug'] = slug;
	}
	data['ignore_info'] = ignore_info;
	data['limit'] = limit;

	fetch(endpoint_url + '?format=json', {
		method: 'POST',
		credentials: "same-origin",
		body: JSON.stringify(data),
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			"Content-Type": 'application/json',
		}
	}).then(function(response) {
		return response.json();
	}).then(function(response) {
		$('#most_common_vuln_spinner').empty();
		if (response.status) {
			$('#most_common_vuln_div').append(`
				<table class="table table-borderless table-nowrap table-hover table-centered m-0">
					<thead>
						<tr>
							<th class="col-width-60">Vulnerability Name</th>
							<th class="col-width-20">Count</th>
							<th class="col-width-20">Severity</th>
						</tr>
					</thead>
				<tbody id="most_common_vuln_tbody">
				</tbody>
				</table>
			`);

			for (const res in response.result) {
				const vuln_obj = response.result[res];
				let vuln_badge = '';
				switch (vuln_obj.severity) {
					case -1:
						vuln_badge = get_severity_badge('Unknown');
						break;
					case 0:
						vuln_badge = get_severity_badge('Info');
						break;
					case 1:
						vuln_badge = get_severity_badge('Low');
						break;
					case 2:
						vuln_badge = get_severity_badge('Medium');
						break;
					case 3:
						vuln_badge = get_severity_badge('High');
						break;
					case 4:
						vuln_badge = get_severity_badge('Critical');
						break;
					default:
						vuln_badge = get_severity_badge('Unknown');
				}
				$('#most_common_vuln_tbody').append(`
					<tr onclick="window.location='${endpoint_vuln_url}?vulnerability_name=${vuln_obj.name}';" class="clickable-row">
						<td>
							<h5 class="m-0 fw-normal">${vuln_obj.name}</h5>
						</td>
						<td>
							<span class="badge badge-outline-danger">${vuln_obj.count}</span>
						</td>
						<td>
							${vuln_badge}
						</td>
					</tr>
				`);
			}
		} else {
			$('#most_common_vuln_div').append(`
				<div class="mt-4 alert alert-warning">
				Could not find Most Common Vulnerabilities.
				</br>
				Once the vulnerability scan is performed, reNgine will identify the Most Common Vulnerabilities.</div>
			`);
		}
	});
}


function highlight_search(search_keyword, content){
	// this function will send the highlighted text from search keyword
	const reg = new RegExp('('+search_keyword+')', 'gi');
	return content.replace(reg, '<mark>$1</mark>');
}


function validURL(str) {
	// checks for valid http url
	const pattern = new RegExp('^(https?:\\/\\/)?'+ // protocol
		'((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|'+ // domain name
		'((\\\d{1,3}\\.){3}\\d{1,3}))'+ // OR ip (v4) address
		'(\\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*'+ // port and path
		'(\\\?[;&a-z\\d%_.~+=-]*)?'+ // query string
		'(\\\#[-a-z\\d_]*)?$','i'); // fragment locator
	return !!pattern.test(str);
}


function shadeColor(color, percent) {
	//https://stackoverflow.com/a/13532993
	let R = parseInt(color.substring(1,3),16);
	let G = parseInt(color.substring(3,5),16);
	let B = parseInt(color.substring(5,7),16);

	R = parseInt(R * (100 + percent) / 100);
	G = parseInt(G * (100 + percent) / 100);
	B = parseInt(B * (100 + percent) / 100);

	R = (R<255)?R:255;
	G = (G<255)?G:255;
	B = (B<255)?B:255;

	const RR = ((R.toString(16).length==1)?"0"+R.toString(16):R.toString(16));
	const GG = ((G.toString(16).length==1)?"0"+G.toString(16):G.toString(16));
	const BB = ((B.toString(16).length==1)?"0"+B.toString(16):B.toString(16));

	return "#"+RR+GG+BB;
}


function add_project_modal(endpoint_url){
	Swal.fire({
		title: 'Enter the project name',
		input: 'text',
		inputAttributes: {
			autocapitalize: 'off',
			placeholder: 'Your Awesome Project'
		},
		showCancelButton: true,
		confirmButtonText: 'Create Project',
		showLoaderOnConfirm: true,
		preConfirm: (name) => {
			return fetch(`${endpoint_url}?name=${name}`)
				.then(response => {
					if (!response.ok) {
						throw new Error(response.error)
					}
					return response.json()
				})
				.catch(error => {
					Swal.showValidationMessage(
						`Duplicate project name, choose another project name!`
					)
				})
			},
			allowOutsideClick: () => !Swal.isLoading()
		}).then((result) => {
			if (result.isConfirmed) {
				Swal.fire({
					title: `${result.value.project_name} is created.`,
					onClose: reloadPage
				})
			}
		});
}


function reloadPage(){
	location.reload();
}

var reNgineVuln = (window.reNgineVuln = window.reNgineVuln || {});

/**
 * Returns a safe href for vulnerability reference links. Aligns with backend; only http, https, or path-only allowed.
 * @param {string} ref - Raw reference URL
 * @returns {string} Same string if safe, otherwise "#"
 */
reNgineVuln.sanitizeHrefForVulnReference = function (ref) {
	if (ref == null || typeof ref !== "string") return "#";
	const s = ref.trim();
	if (!s) return "#";
	const lower = s.toLowerCase();
	if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("vbscript:") || s.startsWith("//")) {
		return "#";
	}
	if (lower.startsWith("http://") || lower.startsWith("https://")) {
		try {
			new URL(s);
			return s;
		} catch (e) {
			return "#";
		}
	}
	if (s.startsWith("/")) {
		return s;
	}
	return "#";
};

/**
 * Returns the base URL for the vulnerability list API (no cache; recomputed each call so it stays
 * correct after table reload or context change). Used by getVulnerabilityDetailUrl.
 * @returns {string|null} Base URL with trailing slash, or null if not determinable
 */
reNgineVuln.getVulnerabilityListBaseUrl = function () {
	const listBase = window.DETAIL_SCAN_API_VULNERABILITIES_LIST || null;
	let listUrl = listBase;
	if (!listUrl && typeof window.jQuery === "function") {
		const hasTable = window.jQuery("#vulnerability_results").length;
		const hasDataTable = hasTable && window.jQuery("#vulnerability_results").DataTable;
		const dt = hasDataTable ? window.jQuery("#vulnerability_results").DataTable() : null;
		if (dt && dt.settings && dt.settings()[0]) {
			const ajaxCfg = dt.settings()[0].ajax;
			listUrl = typeof ajaxCfg === "string" ? ajaxCfg : (ajaxCfg && ajaxCfg.url);
		}
	}
	if (!listUrl || typeof listUrl !== "string") {
		return null;
	}
	return listUrl.split("?")[0].replace(/\/+$/, "") + "/";
};

/**
 * Returns the API URL to fetch a single vulnerability by id (full serializer including *_display).
 * @param {number|string} vulnId - Vulnerability id
 * @returns {string|null} Detail URL or null if base URL cannot be determined
 */
reNgineVuln.getVulnerabilityDetailUrl = function (vulnId) {
	const base = reNgineVuln.getVulnerabilityListBaseUrl();
	if (!base || vulnId == null) return null;
	return base + encodeURIComponent(String(vulnId)) + "/";
};

/**
 * Returns true if the row has markdown content but is missing pre-rendered HTML (_display).
 */
reNgineVuln.vulnRowNeedsDisplayFetch = function (row) {
	function hasDisplay(val) {
		return val != null && String(val).trim().length > 0;
	}
	return (
		(row.description && !hasDisplay(row.description_display)) ||
		(row.impact && !hasDisplay(row.impact_display)) ||
		(row.remediation && !hasDisplay(row.remediation_display)) ||
		(row.references && !hasDisplay(row.references_display))
	);
};

/**
 * Fetches a single vulnerability by detail API URL. Returns a Promise that resolves to the
 * full vulnerability object on success, or the fallback rowData on failure.
 * @param {string} detailUrl - Full URL for GET /api/.../listVulnerability/{id}/
 * @param {Object} rowData - Fallback object when the request fails
 * @returns {Promise<Object>} Resolves to API response or rowData
 */
reNgineVuln.fetchVulnerabilityByDetailUrl = function (detailUrl, rowData) {
	const getCookie = typeof window.getCookie === "function" ? window.getCookie : function () { return ""; };
	const csrfToken = getCookie("csrftoken") || "";
	return window
		.fetch(detailUrl, {
			method: "GET",
			headers: { "X-CSRFToken": csrfToken, Accept: "application/json" },
			credentials: "same-origin",
		})
		.then(function (response) {
			if (!response.ok) {
				if (window.console && typeof window.console.warn === "function") {
					window.console.warn("fetchVulnerabilityByDetailUrl: non-OK response", {
						url: detailUrl,
						status: response.status,
						statusText: response.statusText,
						rowId: rowData && rowData.id,
					});
				}
				return rowData;
			}
			return response.json();
		})
		.then(function (data) {
			return data != null ? data : rowData;
		})
		.catch(function (error) {
			if (window.console && typeof window.console.warn === "function") {
				window.console.warn("fetchVulnerabilityByDetailUrl: request failed", {
					url: detailUrl,
					error: error,
					rowId: rowData && rowData.id,
				});
			}
			return rowData;
		});
}

/**
 * Opens the vulnerability off-canvas. If the row lacks *_display fields, fetches the full
 * vulnerability from the detail API then renders; otherwise renders immediately.
 * @param {Object} rowData - Row object from DataTable (may lack description_display, etc.)
 */
reNgineVuln.openVulnOffcanvas = function (rowData) {
	if (!rowData || rowData.id == null) {
		reNgineVuln.renderVulnOffcanvas(rowData);
		return;
	}
	if (!reNgineVuln.vulnRowNeedsDisplayFetch(rowData)) {
		reNgineVuln.renderVulnOffcanvas(rowData);
		return;
	}
	if (typeof window.fetch !== "function" || typeof window.DOMPurify === "undefined" || typeof window.DOMPurify.sanitize !== "function") {
		reNgineVuln.renderVulnOffcanvas(rowData);
		return;
	}
	const detailUrl = reNgineVuln.getVulnerabilityDetailUrl(rowData.id);
	if (!detailUrl) {
		if (window.console && typeof window.console.warn === "function") {
			window.console.warn("openVulnOffcanvas: missing detail URL for vulnerability", { rowId: rowData.id });
		}
		reNgineVuln.renderVulnOffcanvas(rowData);
		return;
	}
	reNgineVuln.fetchVulnerabilityByDetailUrl(detailUrl, rowData).then(function (vuln) {
		reNgineVuln.renderVulnOffcanvas(vuln);
	});
};

/**
 * DOMPurify config for vulnerability markdown: from backend (window.VULN_DOMPURIFY_CONFIG) or fallback.
 */
reNgineVuln.getVulnDompurifyConfig = function () {
	const fromBackend = window.VULN_DOMPURIFY_CONFIG;
	if (fromBackend && Array.isArray(fromBackend.ALLOWED_TAGS) && Array.isArray(fromBackend.ALLOWED_ATTR)) {
		return fromBackend;
	}
	return {
		ALLOWED_TAGS: [
			"p", "div", "span", "br", "ul", "ol", "li", "strong", "em", "b", "i", "code", "pre", "a",
			"table", "thead", "tbody", "tr", "th", "td", "h1", "h2", "h3", "h4", "h5", "h6", "dl", "dt", "dd"
		],
		ALLOWED_ATTR: ["href", "title", "id", "class", "aria-label", "aria-expanded", "role", "aria-hidden"]
	};
};

/**
 * Replaces plain http(s) URLs in HTML text nodes with <a href="..." target="_blank" rel="noopener noreferrer">.
 * Only runs in text content (between tags) to avoid altering existing href values.
 * @param {string} html - HTML string (e.g. from renderMarkdownBody)
 * @returns {string} HTML with bare URLs turned into links
 */
reNgineVuln.linkifyUrlsInHtml = function (html) {
	if (typeof html !== "string" || !html) return html;
	const sanitize = reNgineVuln.sanitizeHrefForVulnReference;
	const encode = typeof htmlEncode === "function" ? htmlEncode : function (s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); };
	const urlRegex = /(https?:\/\/[^\s<>"')\]]+)/g;
	return html.replace(/(>)([^<]*?)(<)/g, function (_, open, text, close) {
		return open + text.replace(urlRegex, function (url) {
			const safeHref = sanitize(url);
			return '<a href="' + safeHref + '" target="_blank" rel="noopener noreferrer">' + encode(url) + "</a>";
		}) + close;
	});
};

/**
 * Sanitizes raw or pre-rendered HTML and wraps it in vuln-markdown-body. Use for description, impact,
 * remediation, and references. See reNgine.core.html_sanitization for backend config alignment.
 * @param {string} raw - Raw text (used when display is absent; newlines become <br />)
 * @param {string|undefined} display - Pre-rendered HTML from API, or undefined
 * @returns {string} Wrapped, sanitized HTML
 */
reNgineVuln.renderMarkdownBody = function (raw, display) {
	const html = display
		? display
		: (raw || "").replace(new RegExp("\r?\n", "g"), "<br />");
	if (typeof window.DOMPurify !== "undefined" && typeof window.DOMPurify.sanitize === "function") {
		return `<div class="vuln-markdown-body">${window.DOMPurify.sanitize(html, reNgineVuln.getVulnDompurifyConfig())}</div>`;
	}
	const escaped =
		typeof safeText === "function"
			? safeText(html)
			: String(html)
					.replace(/&/g, "&amp;")
					.replace(/</g, "&lt;")
					.replace(/>/g, "&gt;")
					.replace(/"/g, "&quot;")
					.replace(/'/g, "&#39;");
	return `<div class="vuln-markdown-body">${escaped}</div>`;
};

reNgineVuln.renderVulnOffcanvas = function (vuln) {
	$('#offcanvas').addClass('offcanvas-size-lg');
	let default_color = 'primary';
	let default_badge_color = 'soft-primary';
	switch (vuln.severity) {
		case 'Info':
			default_color = 'primary';
			default_badge_color = 'soft-primary';
			break;
		case 'Low':
			default_color = 'low';
			default_badge_color = 'soft-warning';
			break;
		case 'Medium':
			default_color = 'warning';
			default_badge_color = 'soft-warning';
			break;
		case 'High':
			default_color = 'danger';
			default_badge_color = 'soft-danger';
			break;
		case 'Critical':
			default_color = 'critical';
			default_badge_color = 'critical';
			break;
		case 'Unknown':
			default_color = 'info';
			default_badge_color = 'soft-info';
			break;
		default:
	}
	const offcanvasEl = document.getElementById('offcanvas');
	const offcanvas_title = document.getElementById('offcanvas-title');
	const offcanvas_body = document.getElementById('offcanvas-body');
	if (!offcanvas_title || !offcanvas_body || !offcanvasEl) {
		console.warn('Offcanvas elements not found in DOM');
		return;
	}
	let title_content = '';
	let body = '';
	title_content += `<i class="mdi mdi-bug-outline me-1 text-${default_color}"></i>`;
	title_content += `<span class="badge badge-${default_badge_color} text-${default_color}">${vuln.severity}</span>`;
	title_content += `<span class="text-${default_color} ms-1">${vuln.name}</span>`;

	body += `<p><b>ID: </b>${vuln.id}</p>`;
	body += `<p><b>Discovered on: </b>${vuln.discovered_date}</p>`;
	body += `<p><b>URL: </b><a href="${vuln.http_url}" target="_blank">${vuln.http_url}</a></p>`;
	const type_display = vuln.type ? vuln.type.toUpperCase() : 'N/A';
	const source_display = vuln.source ? vuln.source.toUpperCase() : 'N/A';
	body += `<p><b>Severity: </b>${vuln.severity}<br><b>Type: </b>${type_display}<br><b>Source: </b> ${source_display}</p>`;

	body += `<div class="accordion custom-accordion mt-2">
	<h5 class="m-0 position-relative">
	<a class="custom-accordion-title text-reset d-block"
	data-bs-toggle="collapse" href="#classification"
	aria-expanded="true" aria-controls="collapseNine">
	Vulnerability Classification <i
	class="mdi mdi-chevron-down accordion-arrow"></i>
	</a>
	</h5>
	<div id="classification" class="collapse show mt-2">
	<table>`;

	const cveIds = Array.isArray(vuln.cve_ids) ? vuln.cve_ids : [];
	if (cveIds.length) {
		body += `<tr>
		<td class="col-width-30">
		<b>CVE IDs</b>
		</td>
		<td>`;

		cveIds.forEach(cve => {
			const rawName = cve && cve.name ? String(cve.name) : "";
			const normalizedId = typeof getNormalizedCveId === "function" ? getNormalizedCveId(rawName) : (rawName ? rawName.trim().toUpperCase() : "");
			const cveHref = typeof getNvdCveUrl === "function" ? getNvdCveUrl(rawName) : null;
			const safeText = typeof htmlEncode === "function" ? htmlEncode(normalizedId) : normalizedId;
			if (cveHref) {
				body += `<a href="${cveHref}" target="_blank" rel="noopener noreferrer" class="badge badge-outline-primary me-1 mt-1" data-toggle="tooltip" data-placement="top" title="CVE ID">${safeText}</a>`;
			} else {
				body += `<span class="badge badge-outline-primary me-1 mt-1" data-toggle="tooltip" data-placement="top" title="CVE ID">${safeText}</span>`;
			}
		});

		body += `</td>
		</tr>`;
	}

	if (vuln.cwe_ids != null && vuln.cwe_ids.length) {
		body += `<tr>
		<td class="col-width-30">
		<b>CWE IDs</b>
		</td>
		<td>`;

		vuln.cwe_ids.forEach(cwe => {
			body += `<a href="https://google.com/search?q=${cwe.name.toUpperCase()}" target="_blank" class="badge badge-outline-primary me-1 mt-1" data-toggle="tooltip" data-placement="top" title="CWE ID">${cwe.name.toUpperCase()}</a>`;
		});

		body += `</td>
		</tr>`;
	}

	if (vuln.cvss_score) {
		let badge = 'danger';
		if (vuln.cvss_score > 0.1 && vuln.cvss_score <= 3.9) {
			badge = 'info';
		}
		else if (vuln.cvss_score > 3.9 && vuln.cvss_score <= 6.9) {
			badge = 'warning';
		}

		body += `<tr>
		<td class="col-width-40">
		<b>CVSS Score</b>
		</td>
		<td>
		<span class="badge badge-outline-${badge}" data-toggle="tooltip" data-placement="top" title="CVSS Score">${vuln.cvss_score}</span>
		</td>
		</tr>`
	}

	if (vuln.cvss_metrics) {
		body += `<tr>
		<td class="col-width-30">
		<b>CVSS Metrics</b>
		</td>
		<td>
		${vuln.cvss_metrics}
		</td>
		</tr>`
	}
	body += `</table>
	</div>
	</div>`;

	if (vuln.description) {
		body += `<div class="accordion custom-accordion mt-2">
		<h5 class="m-0 position-relative">
		<a class="custom-accordion-title text-reset d-block"
		data-bs-toggle="collapse" href="#description"
		aria-expanded="true" aria-controls="collapseNine">
		Vulnerability Description <i
		class="mdi mdi-chevron-down accordion-arrow"></i>
		</a>
		</h5>
		<div id="description" class="collapse show mt-2">
		${reNgineVuln.renderMarkdownBody(vuln.description, vuln.description_display)}
		</div>
		</div>`;
	}

	if (vuln.impact) {
		body += `<div class="accordion custom-accordion mt-2">
		<h5 class="m-0 position-relative">
		<a class="custom-accordion-title text-reset d-block"
		data-bs-toggle="collapse" href="#impact"
		aria-expanded="true" aria-controls="collapseNine">
		Vulnerability Impact <i
		class="mdi mdi-chevron-down accordion-arrow"></i>
		</a>
		</h5>
		<div id="impact" class="collapse show mt-2">
		${reNgineVuln.renderMarkdownBody(vuln.impact, vuln.impact_display)}
		</div>
		</div>`;
	}

	if (vuln.remediation) {
		body += `<div class="accordion custom-accordion mt-2">
		<h5 class="m-0 position-relative">
		<a class="custom-accordion-title text-reset d-block"
		data-bs-toggle="collapse" href="#remediation"
		aria-expanded="true" aria-controls="collapseNine">
		Remediation <i
		class="mdi mdi-chevron-down accordion-arrow"></i>
		</a>
		</h5>
		<div id="remediation" class="collapse show mt-2">
		${reNgineVuln.renderMarkdownBody(vuln.remediation, vuln.remediation_display)}
		</div>
		</div>`;
	}

	if (vuln.source == 'nuclei') {
		body += `<div class="accordion custom-accordion mt-2">
		<h5 class="m-0 position-relative">
		<a class="custom-accordion-title text-reset d-block"
		data-bs-toggle="collapse" href="#nuclei_div"
		aria-expanded="true" aria-controls="collapseNine">
		Nuclei Template Details <i
		class="mdi mdi-chevron-down accordion-arrow"></i>
		</a>
		</h5>
		<div id="nuclei_div" class="collapse mt-2">
		<table>
		<tr>
		<td class="col-width-20"><b>Template</b></td>
		<td>${vuln.template}</td>
		</tr>
		<tr>
		<td class="col-width-20"><b>Template URL</b></td>
		<td><a target="_blank" href="${vuln.template_url}">${vuln.template_url}</a></td>
		</tr>
		<tr>
		<td class="col-width-20"><b>Template ID</b></td>
		<td>${vuln.template_id}</td>
		</tr>
		<tr>
		<td class="col-width-20"><b>Matcher Name</b></td>
		<td>${vuln.matcher_name}</td>
		</tr>
		</table>
		</div>
		</div>`;
	}

	if (vuln.curl_command) {
		body += `<div class="accordion custom-accordion mt-2">
		<h5 class="m-0 position-relative">
		<a class="custom-accordion-title text-reset d-block"
		data-bs-toggle="collapse" href="#curl_command"
		aria-expanded="true" aria-controls="collapseNine">
		CURL Command <i
		class="mdi mdi-chevron-down accordion-arrow"></i>
		</a>
		</h5>
		<div id="curl_command" class="collapse show mt-2">
		<code>${htmlEncode(vuln.curl_command)}</code>
		</div>
		</div>`;
	}

	if (vuln.extracted_results != null && vuln.extracted_results.length) {
		body += `<div class="accordion custom-accordion mt-2">
		<h5 class="m-0 position-relative">
		<a class="custom-accordion-title text-reset d-block"
		data-bs-toggle="collapse" href="#extracted"
		aria-expanded="true" aria-controls="collapseNine">
		Extracted Results <i
		class="mdi mdi-chevron-down accordion-arrow"></i>
		</a>
		</h5>
		<div id="extracted" class="collapse show mt-2">
		<ul>`;

		vuln.extracted_results.forEach(result => {
			body += `<li>${htmlEncode(result)}</li>`;
		});

		body += `
		</ul>
		</div>
		</div>`;
	}

	const http_request = vuln.request || '';
	const http_response = vuln.response || '';

	body += `<div class="accordion custom-accordion mt-2">
	<h5 class="m-0 position-relative">
	<a class="custom-accordion-title text-reset d-block"
	data-bs-toggle="collapse" href="#request"
	aria-expanded="true" aria-controls="collapseNine">
	HTTP Request <i
	class="mdi mdi-chevron-down accordion-arrow"></i>
	</a>
	</h5>
	<div id="request" class="collapse mt-2">
	<pre>${http_request}</pre>
	</div>
	</div>`;

	body += `<div class="accordion custom-accordion mt-2">
	<h5 class="m-0 position-relative">
	<a class="custom-accordion-title text-reset d-block"
	data-bs-toggle="collapse" href="#response"
	aria-expanded="true" aria-controls="collapseNine">
	HTTP Response <i
	class="mdi mdi-chevron-down accordion-arrow"></i>
	</a>
	</h5>
	<div id="response" class="collapse mt-2">
	<pre>${http_response}</pre>
	</div>
	</div>`;

	let { references } = vuln;

	// Check if references is a string representation of an array
	if (typeof references === 'string' && references.startsWith('[') && references.endsWith(']')) {
		// Remove the brackets and split by comma
		references = references.slice(1, -1).split(',').map(ref => ref.trim().replace(/^'|'$/g, ''));
	}

	let referencesContent = "";
	if (Array.isArray(references)) {
		referencesContent = "<ul>";
		references.forEach(ref => {
			const safeHref = reNgineVuln.sanitizeHrefForVulnReference(ref);
			const safeText = typeof htmlEncode === "function" ? htmlEncode(safeHref) : safeHref;
			referencesContent += `<li><a href="${safeHref}" target="_blank" rel="noopener noreferrer">${safeText}</a></li>`;
		});
		referencesContent += "</ul>";
	} else {
		referencesContent = reNgineVuln.linkifyUrlsInHtml(
			reNgineVuln.renderMarkdownBody(vuln.references, vuln.references_display)
		);
	}

	body += `<div class="accordion custom-accordion mt-2">
    <h5 class="m-0 position-relative">
        <a class="custom-accordion-title text-reset d-block"
           data-bs-toggle="collapse" href="#references"
           aria-expanded="true" aria-controls="collapseNine">
           References <i class="mdi mdi-chevron-down accordion-arrow"></i>
        </a>
    </h5>
    <div id="references" class="collapse show mt-2">
        ${referencesContent}
    </div>
</div>`;

	if (vuln.is_llm_used) {
		body += `<small class="text-muted float-end">(LLM was used to generate vulnerability details.)</small>`;
	}


	offcanvas_title.innerHTML = title_content;
	offcanvas_body.innerHTML = body;
	if (offcanvasEl && typeof bootstrap !== 'undefined' && bootstrap.Offcanvas) {
		// Same as ModalManager: ensure offcanvas is in body so it displays above tab content and modals
		if (offcanvasEl.parentNode !== document.body) {
			document.body.appendChild(offcanvasEl);
		}
		bootstrap.Offcanvas.getOrCreateInstance(offcanvasEl).show();
	}
}


function showSwalLoader(title, text){
	Swal.fire({
		title: title,
		text: text,
		allowOutsideClick: false,
		allowEscapeKey: false,
		allowEnterKey: false,
		showConfirmButton: false,
		willOpen: () => {
			Swal.showLoading();
		}
	});
}

// Ensures a query param is set exactly once on a URL (works with relative URLs)
function setUrlParam(url, key, value) {
    try {
        const u = new URL(url, window.location.origin);
        u.searchParams.set(key, value);
        return u.pathname + (u.search || '') + (u.hash || '');
    } catch (e) {
        // Fallback simple append/replace
        const hasQuestion = url.includes('?');
        const regex = new RegExp(`([?&])${key}=[^&]*`);
        if (regex.test(url)) {
            // Use a function to preserve the original separator from the match
            return url.replace(regex, (match, sep) => `${sep}${key}=${encodeURIComponent(value)}`);
        }
        return url + (hasQuestion ? '&' : '?') + `${key}=${encodeURIComponent(value)}`;
    }
}

async function send_llm_api_request(endpoint_url, vuln_id){
    const sep = endpoint_url.includes('?') ? '&' : '?';
    const api = `${endpoint_url}${sep}format=json&id=${vuln_id}`;
    try {
        const response = await fetch(api, {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        });
        // Always try to parse JSON to allow UI handling of non-2xx responses
        let data;
        try {
            data = await response.json();
        } catch (jsonError) {
            // Log the error for debugging without masking server-side issues
            console.error('JSON parse error:', jsonError);
            return {
                status: false,
                error: 'Failed to parse server response as JSON',
                details: jsonError.message || jsonError.toString()
            };
        }
        if (!response.ok) {
            // Return structured error so caller can decide next step (e.g., show config dialog)
            return (data && typeof data === 'object')
                ? data
                : { status: false, error: 'Request failed' };
        }
        return data;
    } catch (error) {
        return { status: false, error: 'Network error', details: error.message || error.toString() };
    }
}


async function fetch_llm_vuln_details(endpoint_url, id, title) {
	const loader_title = "Loading...";
	const text = 'Please wait while the LLM is generating vulnerability description.';
	try {
		showSwalLoader(loader_title, text);
        const data = await send_llm_api_request(endpoint_url, id);
		Swal.close();
        if (data.status) {
            render_llm_vuln_modal(data, title, endpoint_url, id);
		}
		else{
			Swal.close();
			if (data.error_code === 'LLM_CONFIG_REQUIRED') {
				showLLMConfigChoiceDialog(endpoint_url, id, title, data);
			} else {
				Swal.fire({
					icon: 'error',
					title: 'Oops...',
					text: data.error,
				});
			}
		}
	} catch (error) {
		console.error(error);
		Swal.close();
		Swal.fire({
			icon: 'error',
			title: 'Oops...',
			text: 'Something went wrong!',
		});
	}
}


function render_llm_vuln_modal(data, title, endpoint_url, vuln_id){
    const safeTitle = DOMPurify.sanitize(String(title || ''), { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    const titleText = 'Vulnerability detail for ' + safeTitle;
    const safeModel = data.llm_model ? DOMPurify.sanitize(String(data.llm_model), { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }) : '';
    const badgeHtml = safeModel ? `<span class="badge bg-soft-primary text-primary mb-3 d-inline-block">Generated by ${safeModel}</span>` : '';
    const bodyHtml = DOMPurify.sanitize(
        badgeHtml +
        '<h4>Description</h4><p>' + (data.description || '') + '</p>' +
        '<h4>Impact</h4><p>' + (data.impact || '') + '</p>' +
        '<h4>Remediation</h4><p>' + (data.remediation || '') + '</p>' +
        '<h4>References</h4><p>' + (data.references || '') + '</p>' +
        '<div class="text-center mt-4"><div class="btn-group" role="group">' +
        '<button class="btn btn-primary" id="btn-regenerate-vuln-llm"><i class="fe-refresh-cw me-1"></i> Generate New Analysis</button>' +
        '<button class="btn btn-danger" id="btn-delete-vuln-llm"><i class="fe-trash-2 me-1"></i> Delete Current Analysis</button>' +
        '</div></div>'
    );

    if (window.ModalManager) {
        ModalManager.showDialog({ title: titleText, bodyHtml: bodyHtml, footerHtml: '' });
    } else {
        $('#modal-dialog-title').text(titleText);
        $('#modal-dialog-body').html(bodyHtml);
        $('#modal-dialog-footer').empty();
        $('#modal-dialog').modal('show');
    }
    $('#modal-dialog .modal-dialog').removeClass('modal-lg').addClass('modal-xl');

    // Bind actions
    $('#btn-regenerate-vuln-llm').off('click').on('click', async () => {
        const $btn = $('#btn-regenerate-vuln-llm');
        const $modal = $('#modal-dialog');
        let $spinner = $modal.find('.modal-spinner');
        if ($spinner.length === 0) {
            $spinner = $('<div class="modal-spinner text-center my-3"><span class="spinner-border" role="status" aria-hidden="true"></span> Regenerating...</div>');
            $modal.find('.modal-footer').prepend($spinner);
        }
        $spinner.show();
        $btn.prop('disabled', true);
        try {
            const forcedUrl = setUrlParam(endpoint_url, 'force_regenerate', 'true');
            await showModelSelectionDialog(forcedUrl, vuln_id, { mode: 'vuln', force_regenerate: true, vuln_title: title });
        } catch (e) {
            console.error(e);
            Swal.fire({ icon: 'error', title: 'Error', text: 'Failed to regenerate analysis.' });
        } finally {
            $spinner.hide();
            $btn.prop('disabled', false);
        }
    });

    $('#btn-delete-vuln-llm').off('click').on('click', async () => {
        try {
            const api = setUrlParam(endpoint_url, 'id', vuln_id);
            const result = await Swal.fire({
                title: 'Delete Analysis?',
                text: 'This will permanently delete the current vulnerability analysis. This action cannot be undone.',
                icon: 'warning', showCancelButton: true,
                confirmButtonColor: '#d33', cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes, delete it!', cancelButtonText: 'Cancel'
            });
            if (!result.isConfirmed) return;

            showSwalLoader('Deleting...', 'Please wait while the analysis is being deleted.');
            const resp = await fetch(api, { method: 'DELETE', headers: { 'X-CSRFToken': getCookie('csrftoken') } });
            const js = await resp.json();
            Swal.close();
            if (js.status) {
                Swal.fire({ icon: 'success', title: 'Deleted!', text: 'The analysis has been deleted successfully.', showConfirmButton: false, timer: 1500 });
                if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.DIALOG);
            } else {
                throw new Error(js.error || 'Failed to delete analysis');
            }
        } catch (e) {
            console.error(e);
            Swal.fire({ icon: 'error', title: 'Error', text: e.message || 'Something went wrong while deleting the analysis!' });
        }
    });
}

// Show configuration choice dialog when LLM config is missing/invalid
function showLLMConfigChoiceDialog(endpoint_url, vuln_id, title, info){
    const options = [];
    if (info && info.is_gpt_selected && info.openai_key_missing) {
        options.push(
            '<button class="btn btn-primary w-100 mb-2" id="btn-add-openai-key" type="button">Add OpenAI API Key</button>'
        );
    }
    if (info && info.ollama_available && info.has_ollama_models) {
        options.push(
            '<button class="btn btn-success w-100 mb-2" id="btn-choose-ollama-model" type="button">Choose Ollama Model</button>'
        );
    }
    options.push(
        '<button class="btn btn-outline-secondary w-100" id="btn-cancel-llm-config" type="button">Cancel</button>'
    );

    const titleText = 'LLM configuration required';
    const bodyHtml = '<p>The current LLM configuration is incomplete. Please choose an option:</p><div class="d-grid gap-2">' + options.join('') + '</div>';
    if (window.ModalManager) {
        ModalManager.showDialog({ title: titleText, bodyHtml: bodyHtml, footerHtml: '' });
    } else {
        $('#modal-dialog-title').text(titleText);
        $('#modal-dialog-body').html(bodyHtml);
        $('#modal-dialog-footer').empty();
        $('#modal-dialog').modal('show');
    }
    $('#modal-dialog .modal-dialog').removeClass('modal-xl').addClass('modal-lg');

    // Bind click handlers safely (no inline JS)
    const chooseBtn = document.getElementById('btn-choose-ollama-model');
    if (chooseBtn) {
        chooseBtn.addEventListener('click', function() {
            if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.DIALOG);
            showModelSelectionDialog(endpoint_url, vuln_id, {
                mode: 'vuln',
                force_regenerate: false,
                vuln_title: title || ''
            });
        });
    }
    
    const addOpenAIBtn = document.getElementById('btn-add-openai-key');
    if (addOpenAIBtn) {
        addOpenAIBtn.addEventListener('click', function() {
            window.location.href = '/scanEngine/api_vault';
        });
    }
    
    const cancelBtn = document.getElementById('btn-cancel-llm-config');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function() {
            if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.DIALOG);
        });
    }
}



function endpoint_datatable_col_visibility(endpoint_table, columns){
    const getIndex = (name) => (typeof window.getColumnIndexByName === 'function' ? window.getColumnIndexByName(columns, name) : -1);
    let idx;
    if(!$('#end_http_status_filter_checkbox').is(":checked")){
        idx = getIndex('http_status');
        if (idx >= 0) endpoint_table.column(idx).visible(false);
    }
    if(!$('#end_page_title_filter_checkbox').is(":checked")){
        idx = getIndex('page_title');
        if (idx >= 0) endpoint_table.column(idx).visible(false);
    }
    if(!$('#end_tags_filter_checkbox').is(":checked")){
        idx = getIndex('matched_gf_patterns');
        if (idx >= 0) endpoint_table.column(idx).visible(false);
    }
    if(!$('#end_content_type_filter_checkbox').is(":checked")){
        idx = getIndex('content_type');
        if (idx >= 0) endpoint_table.column(idx).visible(false);
    }
    if(!$('#end_content_length_filter_checkbox').is(":checked")){
        idx = getIndex('content_length');
        if (idx >= 0) endpoint_table.column(idx).visible(false);
    }
    // Always keep techs and webserver hidden in columns; they are shown inline under HTTP URL
    const idxTechs = getIndex('techs');
    if (idxTechs > -1) {
        endpoint_table.column(idxTechs).visible(false);
    }
    const idxWebserver = getIndex('webserver');
    if (idxWebserver > -1) {
        endpoint_table.column(idxWebserver).visible(false);
    }
    if(!$('#end_response_time_filter_checkbox').is(":checked")){
        idx = getIndex('response_time');
        if (idx >= 0) endpoint_table.column(idx).visible(false);
    }
    if(!$('#end_screenshot_filter_checkbox').is(":checked")){
        idx = getIndex('screenshot_url');
        if (idx >= 0) endpoint_table.column(idx).visible(false);
    }
}


async function send_llm__attack_surface_api_request(endpoint_url, id, force_regenerate = false, check_only = false, llm_model = null) {
    const params = new URLSearchParams({
        subdomain_id: id,
        force_regenerate: force_regenerate,
        check_only: check_only
    });
    
    // Only add llm_model if it's not null
    if (llm_model) {
        params.append('llm_model', llm_model);
    }
    
    const response = await fetch(`${endpoint_url}?${params}`);
    return await response.json();
}

async function regenerateAttackSurface(endpoint_url, id) {
    try {
        // Show model selection dialog with force_regenerate flag
        await showModelSelectionDialog(endpoint_url, id, true);
    } catch (error) {
        console.error(error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: 'Something went wrong while regenerating the analysis.',
        });
    }
}

async function show_attack_surface_modal(endpoint_url, id) {
    try {
        // First check if we have cached results without triggering analysis
        const initialResponse = await send_llm__attack_surface_api_request(endpoint_url, id, false, true);
        
        if (initialResponse.status && initialResponse.description) {
            showAttackSurfaceModal(initialResponse, endpoint_url, id);
            return;
        }
        
        // If no cached results, show model selection
        await showModelSelectionDialog(endpoint_url, id, { mode: 'attack' });
    } catch (error) {
        console.error(error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: 'Something went wrong!',
        });
    }
}

async function showModelSelectionDialog(endpoint_url, id, optsOrForce = false) {
    try {
        // Fetch models from the unified endpoint that combines GPT and Ollama models
        const response = await fetch('/api/tools/llm_models/');
        const data = await response.json();
        
        if (!data.status) {
            throw new Error(data.error || 'Failed to fetch models');
        }

        // Change modal size to xl
        $('#modal-dialog .modal-dialog').removeClass('modal-lg').addClass('modal-xl');

        // Resolve options for reuse in attack surface and vulnerabilities
        let mode = 'attack';
        let force_regenerate = false;
        let vuln_title = '';
        if (typeof optsOrForce === 'boolean') {
            force_regenerate = optsOrForce;
        } else if (optsOrForce && typeof optsOrForce === 'object') {
            mode = optsOrForce.mode || 'attack';
            force_regenerate = !!optsOrForce.force_regenerate;
            vuln_title = optsOrForce.vuln_title || '';
        }

        // Unified confirm handler
        window.confirmLLMModelSelection = async () => {
			const selectedModel = $('input[name="llm_model"]:checked').val();
			if (!selectedModel) {
				Swal.fire({
					title: 'Error',
					text: 'Please select a model',
					icon: 'error'
				});
				return;
			}
		
			try {
				// Update selected model in database first
				const encoded_model = encodeURIComponent(selectedModel);
				const updateResponse = await fetch(`/api/tool/ollama/${encoded_model}/`, {
					method: 'PUT',
					headers: {
						'Content-Type': 'application/json',
						'X-CSRFToken': getCookie('csrftoken')
					},
					body: JSON.stringify({ model: selectedModel })
				});
				
				const updateData = await updateResponse.json();
				if (!updateData.status) {
					throw new Error('Failed to update selected model');
				}
                if (mode === 'attack') {
                    // Then proceed with attack surface analysis
                    const loader_title = 'Loading...';
                    const text = 'Please wait while the LLM is generating attack surface.';
                    showSwalLoader(loader_title, text);
                    const result = await send_llm__attack_surface_api_request(endpoint_url, id, force_regenerate, false, selectedModel);
                    Swal.close();
                    
                    if (result.status) {
                        showAttackSurfaceModal(result, endpoint_url, id);
                    } else {
                        Swal.fire({
                            icon: 'error',
                            title: 'Oops...',
                            text: result.error,
                        });
                    }
                } else {
                    // Vulnerability details flow: close modal and retry fetch
                    if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.DIALOG);
                    await fetch_llm_vuln_details(endpoint_url, id, vuln_title);
                }
            } catch (error) {
                console.error(error);
                Swal.close();
                Swal.fire({
                    icon: 'error',
                    title: 'Oops...',
                    text: 'Something went wrong!',
                });
            }
        };

        // Continue with existing model selection UI code...
        const allModels = data.models;
        const selectedModel = data.selected_model;

        let modelOptions = '';
        allModels.forEach(model => {
            const modelName = model.name;
            const capabilities = model.capabilities || {};
            const isLocal = model.is_local || false;
            
            modelOptions += `
                <div class="col-md-4 mt-2">
                    <div class="card project-box h-100 model-selection-card" 
                         onclick="document.getElementById('${modelName}').click()">
                        <div class="card-body p-2 pt-3 d-flex flex-column">
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="llm_model" 
                                    id="${modelName}" value="${modelName}" 
                                    ${modelName === selectedModel ? 'checked' : ''}>
                                <h5 class="mt-0">
                                    <span class="${modelName === selectedModel ? 'text-success' : ''}">${modelName} 
                                        ${modelName === selectedModel ? '<span class="badge bg-soft-primary text-primary ms-2">Selected</span>' : ''}
                                    </span>
                                </h5>
                                <p>${isLocal ? '<span class="badge bg-soft-success text-success mt-auto">Locally installed model</span>' : '<span class="badge bg-soft-warning text-warning mt-auto">Remote Model - API Key Required</span>'}</p>
                                <p class="mb-1 small flex-grow-1">
                                    <span class="pe-2 text-nowrap d-inline-block">
                                        <i class="mdi mdi-database text-info"></i>
                                        ${isLocal ? 'Local model' : 'OpenAI'}
                                    </span>
                                    ${model.details ? `
                                        <span class="text-nowrap d-inline-block">
                                            <i class="mdi mdi-family-tree text-success"></i>
                                            ${model.details.family}
                                        </span>
                                        <br>
                                        <span class="text-nowrap d-inline-block">
                                            <i class="mdi mdi-numeric text-info"></i>
                                            <b>${model.details.parameter_size}</b> Parameters
                                        </span>
                                    ` : ''}
                                    <br>
                                    <br>
                                    <span class="text-muted w-100 d-inline-block">
                                        <i class="mdi mdi-star text-warning"></i>
                                        Best for:
                                        <ul class="list-unstyled mt-1 ms-3">
                                            ${capabilities.best_for ? capabilities.best_for.map(cap => 
                                                `<li><i class="mdi mdi-check-circle text-success me-1"></i>${cap}</li>`
                                            ).join('') : '<li><i class="mdi mdi-check-circle text-success me-1"></i>General analysis</li>'}
                                        </ul>
                                    </span>
                                </p>
                            </div>
                        </div>
                    </div>
                </div>`;
        });

        const bodyHtml = `
            <div class="mb-3 row">
                <p>Select the LLM model to use:</p>
                ${modelOptions}
            </div>
            <div class="mb-3 text-center">
                <button class="btn btn-primary" type="button" onclick="window.confirmLLMModelSelection()">Continue</button>
            </div>
        `;
        if (window.ModalManager) {
            ModalManager.showDialog({
                title: 'Select LLM Model',
                bodyHtml: bodyHtml,
                footerHtml: ''
            });
        }
    } catch (error) {
        console.error(error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: 'Unable to fetch LLM models. Please check configuration.',
            footer: '<a href="/scanEngine/llm_toolkit/">Configure LLM models</a>'
        });
    }
}

async function deleteAttackSurfaceAnalysis(endpoint_url, id) {
    try {
        const result = await Swal.fire({
            title: 'Delete Analysis?',
            text: "This will permanently delete the current attack surface analysis. This action cannot be undone.",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel'
        });

        if (result.isConfirmed) {
            showSwalLoader("Deleting...", "Please wait while the analysis is being deleted.");
            
            const response = await fetch(`${endpoint_url}?subdomain_id=${id}`, {
                method: 'DELETE',
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            });
            
            const data = await response.json();
            Swal.close();
            
            if (data.status) {
                Swal.fire({
                    icon: 'success',
                    title: 'Deleted!',
                    text: 'The analysis has been deleted successfully.',
                    showConfirmButton: false,
                    timer: 1500
                });
                if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.DIALOG);
            } else {
                throw new Error(data.error || 'Failed to delete analysis');
            }
        }
    } catch (error) {
        console.error(error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message || 'Something went wrong while deleting the analysis!'
        });
    }
}

function showAttackSurfaceModal(data, endpoint_url, id) {
    const header = 'Attack Surface Suggestion for ' + data.subdomain_name;
    const bodyHtml =
        DOMPurify.sanitize(data.description) +
        `<div class="text-center mt-4">
            <div class="btn-group" role="group">
                <button class="btn btn-primary" id="btn-as-regenerate">
                    <i class="fe-refresh-cw me-1"></i>
                    Generate New Analysis
                </button>
                <button class="btn btn-danger" id="btn-as-delete">
                    <i class="fe-trash-2 me-1"></i>
                    Delete Current Analysis
                </button>
            </div>
        </div>`;
    $('#modal-dialog .modal-dialog').removeClass('modal-lg').addClass('modal-xl');
    if (window.ModalManager) {
        ModalManager.showDialog({
            title: escapeHtml(header),
            bodyHtml: bodyHtml,
            footerHtml: ''
        });
    }
    $('#btn-as-regenerate').off('click').on('click', async () => {
        const $btn = $('#btn-as-regenerate');
        const $otherBtn = $('#btn-as-delete');
        const $modal = $('#modal-dialog');
        let $spinner = $modal.find('.modal-spinner');
        if ($spinner.length === 0) {
            $spinner = $('<div class="modal-spinner text-center my-3"><span class="spinner-border" role="status" aria-hidden="true"></span> Regenerating...</div>');
            $modal.find('.modal-footer').prepend($spinner);
        }
        $spinner.show();
        $btn.prop('disabled', true);
        $otherBtn.prop('disabled', true);
        try {
            await regenerateAttackSurface(endpoint_url, id);
        } catch (error) {
            console.error(error);
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Failed to regenerate attack surface analysis. Please try again.'
            });
        } finally {
            $spinner.hide();
            $btn.prop('disabled', false);
            $otherBtn.prop('disabled', false);
        }
    });
    $('#btn-as-delete').off('click').on('click', async () => {
        const $btn = $('#btn-as-delete');
        const $otherBtn = $('#btn-as-regenerate');
        const $modal = $('#modal-dialog');
        let $spinner = $modal.find('.modal-spinner');
        if ($spinner.length === 0) {
            $spinner = $('<div class="modal-spinner text-center my-3"><span class="spinner-border" role="status" aria-hidden="true"></span> Deleting...</div>');
            $modal.find('.modal-footer').prepend($spinner);
        }
        $spinner.show();
        $btn.prop('disabled', true);
        $otherBtn.prop('disabled', true);
        try {
            await deleteAttackSurfaceAnalysis(endpoint_url, id);
        } catch (error) {
            console.error(error);
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Failed to delete attack surface analysis. Please try again.'
            });
        } finally {
            $spinner.hide();
            $btn.prop('disabled', false);
            $otherBtn.prop('disabled', false);
        }
    });
}

function convertToCamelCase(inputString) {
	// Converts camel case string to title
	// Split the input string by underscores
	const words = inputString.split('_');

	// Capitalize the first letter of each word and join them with a space
	return words.map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
}
function handleHashInUrl(){
	// this function handles hash in url used to tab navigation
	const { hash } = window.location;
	if (hash) {
		const targetId = hash.substring(1);
		const tabLink = $(`a[href="#${targetId}"][data-bs-toggle="tab"]`);
		if (tabLink.length) {
			tabLink.tab('show');
			setTimeout(() => {
				tabLink.click();
			}, 100);
		}
	}
}

let _pendingLLMModalCallback = null;

function showLLMModelSelectionModal(callback) {
    _pendingLLMModalCallback = typeof callback === 'function' ? callback : null;
    const ollamaUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.toolOllama) || '/api/tool/ollama/';
    fetch(ollamaUrl)
        .then(response => response.json())
        .then(data => {
            const { models, selected_model: selectedModel } = data;
            let modelOptions = '';
            (models || []).forEach(model => {
                modelOptions += `<div class="form-check"><input class="form-check-input" type="radio" name="llm_model" id="${htmlEncode(model.name)}" value="${htmlEncode(model.name)}" ${model.name === selectedModel ? 'checked' : ''}><label class="form-check-label" for="${htmlEncode(model.name)}">${htmlEncode(model.name)} (${htmlEncode((model.details && model.details.family) || '')})</label></div>`;
            });
            const title = 'Select LLM Model';
            const bodyHtml = `<div class="mb-3"><p>Select the LLM model to use for vulnerability analysis:</p>${modelOptions}</div><div class="mb-3 text-center"><button class="btn btn-primary float-end" type="submit" onclick="selectLLMModel()">Continue</button></div>`;
            if (window.ModalManager) ModalManager.showDialog({ title, bodyHtml, footerHtml: '' });
        });
}

function selectLLMModel() {
    const selectedModel = $('input[name="llm_model"]:checked').val();
    if (!selectedModel) {
        Swal.fire({
            title: 'Error',
            text: 'Please select a model',
            icon: 'error'
        });
        return;
    }
    
    // Update selected model in database
	const encoded_model = encodeURIComponent(selectedModel);
    fetch(`/api/tool/ollama/${encoded_model}/`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({ model: selectedModel })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status) {
            if (window.ModalManager) ModalManager.hide(ModalManager.MODAL_IDS.DIALOG);
            if (_pendingLLMModalCallback) {
                _pendingLLMModalCallback(selectedModel);
                _pendingLLMModalCallback = null;
            } else {
                startScan();
            }
        } else {
            Swal.fire({
                title: 'Error',
                text: 'Unable to set selected model',
                icon: 'error'
            });
        }
    });
}

// Initialize mobile menu when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initMobileMenu();
    initCompactSearch();
});

// Mobile menu functionality
function initMobileMenu() {
    const mobileNavMenu = document.getElementById('mobileNavMenu');
    const mobileHamburger = document.getElementById('mobileHamburger');
    
    // Handle mobile submenu toggles
    const submenuHeaders = document.querySelectorAll('.mobile-submenu-header:not(.mobile-projects-submenu .mobile-submenu-header)');
    
    submenuHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const submenu = this.nextElementSibling;
            if (submenu && submenu.classList.contains('mobile-submenu')) {
                // Toggle active class on header
                this.classList.toggle('active');
                
                // Toggle show class on submenu
                submenu.classList.toggle('show');
            }
        });
    });
    
    // Close mobile menu when clicking outside
    document.addEventListener('click', function(e) {
        if (mobileNavMenu && mobileNavMenu.classList.contains('show') && !mobileNavMenu.contains(e.target) && !mobileHamburger.contains(e.target)) {
            const bsCollapse = new bootstrap.Collapse(mobileNavMenu, {
                toggle: false
            });
            bsCollapse.hide();
        }
    });
}

// Compact search functionality
function initCompactSearch() {
    const searchBtn = document.querySelector('.navbar-custom .app-search .btn');
    const searchForm = document.querySelector('.navbar-custom .app-search');
    const searchInput = document.querySelector('.navbar-custom .app-search .form-control');
    
    if (searchBtn && searchForm && searchInput) {
        // Toggle search field on mobile using Bootstrap classes
        searchBtn.addEventListener('click', function(e) {
            if (window.innerWidth <= 767.98) {
                if (searchForm.classList.contains('search-active')) {
                    // If search is active, submit the form
                    // Don't prevent default, let the form submit
                } else {
                    // If search is not active, open the search
                    e.preventDefault();
                    searchForm.classList.add('search-active');
                    searchInput.classList.remove('d-none');
                    searchInput.classList.add('d-block');
                    searchInput.focus();
                }
            }
        });
        
        // Handle Enter key in search input
        searchInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && window.innerWidth <= 767.98 && searchForm.classList.contains('search-active')) {
                // Let the form submit naturally, don't prevent default
            }
        });
        
        // Handle form submission on mobile
        searchForm.addEventListener('submit', function(e) {
            if (window.innerWidth <= 767.98 && searchForm.classList.contains('search-active')) {
                // Close the search after submission
                setTimeout(function() {
                    searchForm.classList.remove('search-active');
                    searchInput.classList.remove('d-block');
                    searchInput.classList.add('d-none');
                }, 100);
            }
        });
        
        // Close search when clicking outside
        document.addEventListener('click', function(e) {
            if (window.innerWidth <= 767.98 && 
                !searchForm.contains(e.target) && 
                searchForm.classList.contains('search-active')) {
                searchForm.classList.remove('search-active');
                searchInput.classList.remove('d-block');
                searchInput.classList.add('d-none');
            }
        });
        
        // Close search on escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && searchForm.classList.contains('search-active')) {
                searchForm.classList.remove('search-active');
                searchInput.classList.remove('d-block');
                searchInput.classList.add('d-none');
            }
        });
    }
}
