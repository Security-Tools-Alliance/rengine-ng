function checkall(clickchk, relChkbox) {
	var checker = $('#' + clickchk);
	var multichk = $('.' + relChkbox);
	checker.click(function() {
		multichk.prop('checked', $(this).prop('checked'));
	});
}

function multiCheck(tb_var) {
	tb_var.on("change", ".chk-parent", function() {
			var e = $(this).closest("table").find("td:first-child .child-chk"),
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
	var sAgent = window.navigator.userAgent;
	var Idx = sAgent.indexOf("MSIE");
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
	return val ? val : '';
}
// separate hostname and url
// Referenced from https://stackoverflow.com/questions/736513/how-do-i-parse-a-url-into-hostname-and-path-in-javascript
function getParsedURL(url) {
	var parser = new URL(url);
	return parser.pathname + parser.search;
};

function getCookie(name) {
	var cookieValue = null;
	if (document.cookie && document.cookie !== '') {
		var cookies = document.cookie.split(';');
		for (var i = 0; i < cookies.length; i++) {
			var cookie = jQuery.trim(cookies[i]);
			// Does this cookie string begin with the name we want?
			if (cookie.substring(0, name.length + 1) === (name + '=')) {
				cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
				break;
			}
		}
	}
	return cookieValue;
}
// Source: https://portswigger.net/web-security/cross-site-scripting/preventing#encode-data-on-output
function htmlEncode(str) {
	return String(str).replace(/[^\w. ]/gi, function(c) {
		return '&#' + c.charCodeAt(0) + ';';
	});
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
	done = false;
	res = '';
	do {
		found = false;
		// Inserts new line at first whitespace of the line
		for (i = maxWidth - 1; i >= 0; i--) {
			if (test_white_space(str.charAt(i))) {
				res = res + [str.slice(0, i), newLineStr].join('');
				str = str.slice(i + 1);
				found = true;
				break;
			}
		}
		// Inserts new line at maxWidth position, the word is too long to wrap
		if (!found) {
			res += [str.slice(0, maxWidth), newLineStr].join('');
			str = str.slice(maxWidth);
		}
		if (str.length < maxWidth) done = true;
	} while (!done);
	return res + str;
}

function test_white_space(x) {
	const white = new RegExp(/^\s$/);
	return white.test(x.charAt(0));
};
// span values function will separate the values by comma and put badge around it
function parse_comma_values_into_span(data, color, outline = null) {
	if (data) {
		var badge = `<span class='badge badge-soft-` + color + ` m-1'>`;
		var data_with_span = "";
		data.split(/\s*,\s*/).forEach(function(split_vals) {
			data_with_span += badge + split_vals + "</span>";
		});
		return data_with_span;
	}
	return '';
}

function get_severity_badge(severity) {
	switch (severity) {
		case 'Info':
			return "<span class='badge badge-soft-primary'>&nbsp;&nbsp;INFO&nbsp;&nbsp;</span>";
			break;
		case 'Low':
			return "<span class='badge badge-low'>&nbsp;&nbsp;LOW&nbsp;&nbsp;</span>";
			break;
		case 'Medium':
			return "<span class='badge badge-soft-warning'>&nbsp;&nbsp;MEDIUM&nbsp;&nbsp;</span>";
			break;
		case 'High':
			return "<span class='badge badge-soft-danger'>&nbsp;&nbsp;HIGH&nbsp;&nbsp;</span>";
			break;
		case 'Critical':
			return "<span class='badge badge-critical'>&nbsp;&nbsp;CRITICAL&nbsp;&nbsp;</span>";
			break;
		case 'Unknown':
		return "<span class='badge badge-soft-info'>&nbsp;&nbsp;UNKNOWN&nbsp;&nbsp;</span>";
		default:
			return "";
	}
}
// Source: https://stackoverflow.com/a/54733055
function typingEffect(words, id, i) {
	let word = words[i].split("");
	var loopTyping = function() {
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
	var loopDeleting = function() {
		if (word.length > 0) {
			word.pop();
			document.getElementById(id).setAttribute('placeholder', word.join(""));
		} else {
			if (words.length > (i + 1)) {
				i++;
			} else {
				i = 0;
			};
			typingEffect(words, id, i);
			return false;
		};
		timer = setTimeout(loopDeleting, 90);
	};
	loopDeleting();
};

function fullScreenDiv(id, btn) {
	let fullscreen = document.querySelector(id);
	let button = document.querySelector(btn);
	document.fullscreenElement && document.exitFullscreen() || document.querySelector(id).requestFullscreen()
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
	img = document.createElement('img');
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
		var text_color = 'danger';
		if (response_time < 0.5) {
			text_color = 'success'
		} else if (response_time >= 0.5 && response_time < 1) {
			text_color = 'warning'
		}
		return `<span class="text-${text_color}">${response_time.toFixed(4)}s</span>`;
	}
	return '';
}

function parse_technology(endpoint_url, data, color, scan_id = null, domain_id=null, link=true) {
	var badge = `<span data-toggle="tooltip" title="Technology" class='badge-link badge badge-soft-` + color + ` mt-1 me-1'`;
	var data_with_span = "";
	for (var key in data) {
		let onclick = '';
		if(link) {
			onclick = ` onclick="get_tech_details('${endpoint_url}', '${data[key]['name']}', ${scan_id}, domain_id=null)"`
		}
		data_with_span += badge + onclick + `>` + data[key]['name'] + "</span>";
	}
	return data_with_span;
}
// span values function will separate the values by comma and put badge around it
function parse_ip(data, cdn) {
	if (cdn) {
		var badge = `<span class='badge badge-soft-warning m-1 bs-tooltip' title="CDN IP Address">`;
	} else {
		var badge = `<span class='badge badge-soft-primary m-1'>`;
	}
	var data_with_span = "";
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
	var element = document.createElement('a');
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
        .toggleClass('badge-soft-primary', !status)
        .toggleClass('badge-soft-success', status)
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

$("#vulnerability_results").on('click', '.btn-delete-vulnerability', function () {
	var vulnerability_id = $(this).attr('id');
	var data = {'vulnerability_ids': [vulnerability_id]};
	var endpoint_url = $(this).attr('data-url');
	var row = this;
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
	});;
	$('a[data-toggle="tooltip"]').tooltip("hide")
});


$("#bulk_delete_vulnerabilities").on('click', function () {
	//btn-delete-vulnerability contains vuln id to delete
	var vulnerabilities = $('.vulnerability_checkbox:checked').parents("tr").find('.btn-delete-vulnerability')
	var vulnerabilities_ids = Array();
	var endpoint_url = $(this).attr('data-url');
	Array.from(vulnerabilities).forEach(vuln => {
		vulnerabilities_ids.push($(vuln).attr('id'));
	});		
	var data = {'vulnerability_ids': vulnerabilities_ids};
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
	message = ""
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

function get_interesting_subdomains(endpoint_url, project, target_id, scan_history_id) {
	if (target_id) {
		url = `${endpoint_url}?project=${project}&target_id=${target_id}&format=datatables`;
		non_orderable_targets = [0, 1, 2, 3];
	} else if (scan_history_id) {
		url = `${endpoint_url}?project=${project}&scan_id=${scan_history_id}&format=datatables`;
		non_orderable_targets = [];
	}
	var interesting_subdomain_table = $('#interesting_subdomains').DataTable({
		"drawCallback": function(settings, start, end, max, total, pre) {
			// if no interesting subdomains are found, hide the datatable and show no interesting subdomains found badge
			if (this.fnSettings().fnRecordsTotal() == 0) {
				$('#interesting_subdomain_div').empty();
				// $('#interesting_subdomain_div').append(`<div class="card-header bg-primary py-3 text-white">
				// <div class="card-widgets">
				// <a href="#" data-toggle="remove"><i class="mdi mdi-close"></i></a>
				// </div>
				// <h5 class="card-title mb-0 text-white"><i class="mdi mdi-fire-alert me-2"></i>Interesting subdomains could not be identified</h5>
				// </div>
				// <div id="cardCollpase4" class="collapse show">
				// <div class="card-body">
				// reNgine could not identify any interesting subdomains. You can customize interesting subdomain keywords <a href="/scanEngine/interesting/lookup/">from here</a> and this section would be automatically updated.
				// </div>
				// </div>`);
			} else {
				// show nav bar
				$('.interesting-tab-show').removeAttr('style');
				$('#interesting_subdomain_alert_count').html(`${this.fnSettings().fnRecordsTotal()} Interesting Subdomains`)
				$('#interesting_subdomain_count_badge').empty();
				$('#interesting_subdomain_count_badge').html(`<span class="badge badge-soft-primary me-1">${this.fnSettings().fnRecordsTotal()}</span>`);
			}
		},
		"oLanguage": {
			"oPaginate": {
				"sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
				"sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
			},
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"processing": true,
		"dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + "<'table-responsive'tr>" + "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count  mb-sm-0 mb-3'i><'dt--pagination'p>>",
		"destroy": true,
		"bInfo": false,
		"stripeClasses": [],
		'serverSide': true,
		"ajax": url,
		"order": [
			[3, "desc"]
		],
		"lengthMenu": [[50, 100, 200, 500, -1], [50, 100, 200, 500, 'All']],
		"pageLength": 50,
		"columns": [{
			'data': 'name'
		}, {
			'data': 'page_title'
		}, {
			'data': 'http_status'
		}, {
			'data': 'content_length'
		}, {
			'data': 'http_url'
		}, {
			'data': 'technologies'
		}, ],
		"columnDefs": [{
			"orderable": false,
			"targets": non_orderable_targets
		}, {
			"targets": [4],
			"visible": false,
			"searchable": false,
		}, {
			"targets": [5],
			"visible": false,
			"searchable": true,
		}, {
			"className": "text-center",
			"targets": [2]
		}, {
			"render": function(data, type, row) {
				tech_badge = '';
				if (row['technologies']) {
					// tech_badge = `</br>` + parse_technology( endpoint_url, row['technologies'], "primary", outline=true, scan_id=null);
				}
				if (row['http_url']) {
					return `<a href="` + row['http_url'] + `" class="text-primary" target="_blank">` + data + `</a>` + tech_badge;
				}
				return `<a href="https://` + data + `" class="text-primary" target="_blank">` + data + `</a>` + tech_badge;
			},
			"targets": 0
		}, {
			"render": function(data, type, row) {
				// display badge based on http status
				// green for http status 2XX, orange for 3XX and warning for everything else
				if (data >= 200 && data < 300) {
					return "<span class='badge badge-pills badge-soft-success'>" + data + "</span>";
				} else if (data >= 300 && data < 400) {
					return "<span class='badge badge-pills badge-soft-warning'>" + data + "</span>";
				} else if (data == 0) {
					// datatable throws error when no data is returned
					return "";
				}
				return `<span class='badge badge-pills badge-soft-danger'>` + data + `</span>`;
			},
			"targets": 2,
		}, ],
	});
}

function get_interesting_endpoints(endpoint_url, project, target_id, scan_history_id) {
	var non_orderable_targets = [];
	if (target_id) {
		url = `${endpoint_url}/?project=${project}&target_id=${target_id}&format=datatables`;
		// non_orderable_targets = [0, 1, 2, 3];
	} else if (scan_history_id) {
		url = `${endpoint_url}/?project=${project}&scan_id=${scan_history_id}&format=datatables`;
		// non_orderable_targets = [0, 1, 2, 3];
	}
	$('#interesting_endpoints').DataTable({
		"drawCallback": function(settings, start, end, max, total, pre) {
			if (this.fnSettings().fnRecordsTotal() == 0) {
				$('#interesting_endpoint_div').remove();
			} else {
				$('.interesting-tab-show').removeAttr('style');
				$('#interesting_endpoint_alert_count').html(`, ${this.fnSettings().fnRecordsTotal()} Interesting Endpoints`)
				$('#interesting_endpoint_count_badge').empty();
				$('#interesting_endpoint_count_badge').html(`<span class="badge badge-soft-primary me-1">${this.fnSettings().fnRecordsTotal()}</span>`);
			}
		},
		"oLanguage": {
			"oPaginate": {
				"sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
				"sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
			},
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"processing": true,
		"dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + "<'table-responsive'tr>" + "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count  mb-sm-0 mb-3'i><'dt--pagination'p>>",
		'serverSide': true,
		"destroy": true,
		"bInfo": false,
		"ajax": url,
		"order": [
			[3, "desc"]
		],
		"lengthMenu": [5, 10, 20, 50, 100],
		"pageLength": 10,
		"columns": [{
			'data': 'http_url'
		}, {
			'data': 'page_title'
		}, {
			'data': 'http_status'
		}, {
			'data': 'content_length'
		}, ],
		"columnDefs": [{
			"orderable": false,
			"targets": non_orderable_targets
		}, {
			"className": "text-center",
			"targets": [2]
		}, {
			"render": function(data, type, row) {
				var url = split_into_lines(data, 70);
				return "<a href='" + data + "' target='_blank' class='text-primary'>" + url + "</a>";
			},
			"targets": 0
		}, 
		{
			"render": function(data, type, row) {
				return htmlEncode(data);
			},
			"targets": 1
		},
		{
			"render": function(data, type, row) {
				// display badge based on http status
				// green for http status 2XX, orange for 3XX and warning for everything else
				if (data >= 200 && data < 300) {
					return "<span class='badge badge-pills badge-soft-success'>" + data + "</span>";
				} else if (data >= 300 && data < 400) {
					return "<span class='badge badge-pills badge-soft-warning'>" + data + "</span>";
				} else if (data == 0) {
					// datatable throws error when no data is returned
					return "";
				}
				return `<span class='badge badge-pills badge-soft-danger'>` + data + `</span>`;
			},
			"targets": 2,
		}, ],
	});
}

function get_important_subdomains(endpoint_url, target_id, scan_history_id) {
	var url = `${endpoint_url}?only_important&no_lookup_interesting&format=json`;
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
			for (var val in data['subdomains']) {
				subdomain = data['subdomains'][val];
				div_id = 'important_' + subdomain['id'];
				$("#important-subdomains-list").append(`
					<div id="${div_id}">
					<p>
					<span id="subdomain_${subdomain['id']}"> ${subdomain['name']}
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
		parentNode = row.parentNode.parentNode.parentNode.parentNode;
		if (parentNode.classList.contains('table-danger')) {
			parentNode.classList.remove('table-danger');
		} else {
			parentNode.className = "table-danger";
		}
	}

	var data = {'subdomain_id': subdomain_id}

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

	if (scan_id) {
		var data = {'scan_id': scan_id}
	}
	else if (subscan_id) {
		var data = {'subscan_id': subscan_id}
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
						getScanStatusSidebar();
					}
					if (reload_location) {
						window.location.reload();
					}
				} else {
					Snackbar.show({
						text: 'Oops! Could not abort the scan. ' + data.message,
						pos: 'top-right',
						duration: 1500
					});
				}
			}).catch(function() {
				swal.insertQueueStep({
					icon: 'error',
					title: 'Oops! Unable to stop the scan'
				})
			})
		}
	}])
}

function extractContent(s) {
	var span = document.createElement('span');
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
	var table = $(table_id).DataTable();
	for (var row in rows_id) {
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
	var data = {
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
	var api_url = endpoint_url + '?format=json&subscan_id=' + subscan_id;
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
		var task_name = '';
		if (response['subscan']['task'] == 'port_scan') {
			task_name = 'Port Scan';
		} else if (response['subscan']['task'] == 'vulnerability_scan') {
			task_name = 'Vulnerability Scan';
		} else if (response['subscan']['task'] == 'fetch_url') {
			task_name = 'Fetch URLs';
		} else if (response['subscan']['task'] == 'dir_file_fuzz') {
			task_name = 'Directory and Files Fuzzing';
		}
		$('#xl-modal_title').html(`${task_name} Results on ${response['subscan']['subdomain_name']}`);
		var scan_status = '';
		var badge_color = 'danger';
		if (response['subscan']['status'] == 1) {
			var badge_color = 'info';
			scan_status = 'Running';
		}
		else if (response['subscan']['status'] == 0) {
			scan_status = 'Failed';
		} else if (response['subscan']['status'] == 2) {
			scan_status = 'Successful';
			badge_color = 'success';
		} else if (response['subscan']['status'] == 3) {
			scan_status = 'Aborted';
		} else {
			scan_status = 'Unknown';
		}
		$('#xl-modal-content').append(`<div>Scan Status: <span class="badge bg-${badge_color}">${scan_status}</span></div>`);
		$('#xl-modal-content').append(`<div class="mt-1">Engine Used: <span class="badge bg-primary">${htmlEncode(response['subscan']['engine'])}</span></div>`);
		if (response['result'].length > 0) {
			if (response['subscan']['task'] == 'port_scan') {
				$('#xl-modal-content').append(`<div id="port_results_li"></div>`);
				for (var ip in response['result']) {
					var ip_addr = response['result'][ip]['address'];
					var underscore_ip = ip_addr.replaceAll('.', '_');
					var id_name = `ip_${underscore_ip}`;
					$('#port_results_li').append(`<h5>IP Address: ${ip_addr}</br></br>${response['result'][ip]['ports'].length} Ports Open</h5>`);
					$('#port_results_li').append(`<ul id="${id_name}"></ul>`);
					for (var port_obj in response['result'][ip]['ports']) {
						var port = response['result'][ip]['ports'][port_obj];
						var port_color = 'primary';
						if (port["is_uncommon"]) {
							port_color = 'danger';
						}
						$(`#${id_name}`).append(`<li><span class="ms-1 mt-1 me-1 badge badge-soft-${port_color}">${port['number']}</span>/<span class="ms-1 mt-1 me-1 badge badge-soft-${port_color}">${port['service_name']}</span>/<span class="ms-1 mt-1 me-1 badge badge-soft-${port_color}">${port['description']}</span></li>`);
					}
				}
				$('#xl-modal-footer').append(`<span class="text-danger">* Uncommon Ports</span>`);
			} else if (response['subscan']['task'] == 'vulnerability_scan') {
				render_vulnerability_in_xl_modal(vuln_count = response['result'].length, subdomain_name = response['subscan']['subdomain_name'], result = response['result']);
			} else if (response['subscan']['task'] == 'fetch_url') {
				render_endpoint_in_xl_modal(endpoint_count = response['result'].length, subdomain_name = response['subscan']['subdomain_name'], result = response['result']);
			} else if (response['subscan']['task'] == 'dir_file_fuzz') {
				if (response['result'][0]['directory_files'].length == 0) {
					$('#xl-modal-content').append(`
						<div class="alert alert-info mt-2" role="alert">
						<i class="mdi mdi-alert-circle-outline me-2"></i> ${task_name} could not fetch any results.
						</div>
					`);
				} else {
					render_directories_in_xl_modal(response['result'][0]['directory_files'].length, response['subscan']['subdomain_name'], response['result'][0]['directory_files']);
				}
			}
		} else {
			$('#xl-modal-content').append(`
				<div class="alert alert-info mt-2" role="alert">
				<i class="mdi mdi-alert-circle-outline me-2"></i> ${task_name} could not fetch any results.
				</div>
				`);
		}
		$('#modal_xl_scroll_dialog').modal('show');
		$("body").tooltip({
			selector: '[data-toggle=tooltip]'
		});
	});
}

function get_http_status_badge(data) {
	if (data >= 200 && data < 300) {
		return "<span class='badge  badge-soft-success'>" + data + "</span>";
	} else if (data >= 300 && data < 400) {
		return "<span class='badge  badge-soft-warning'>" + data + "</span>";
	} else if (data == 0) {
		// datatable throws error when no data is returned
		return "";
	}
	return "<span class='badge  badge-soft-danger'>" + data + "</span>";
}

function render_endpoint_in_xl_modal(endpoint_count, subdomain_name, result) {
	// This function renders endpoints datatable in xl modal
	// Used in Subscan results and subdomain to endpoints modal
	$('#xl-modal-content').append(`<h5> ${endpoint_count} Endpoints Discovered on subdomain ${subdomain_name}</h5>`);
	$('#xl-modal-content').append(`
		<div class="">
		<table id="endpoint-modal-datatable" class="table dt-responsive w-100">
		<thead>
		<tr>
		<th>HTTP URL</th>
		<th>Status</th>
		<th>Page Title</th>
		<th>Tags</th>
		<th>Content Type</th>
		<th>Content Length</th>
		<th>Response Time</th>
		</tr>
		</thead>
		<tbody id="endpoint_tbody">
		</tbody>
		</table>
		</div>
	`);
	$('#endpoint_tbody').empty();
	for (var endpoint_obj in result) {
		var endpoint = result[endpoint_obj];
		var tech_badge = '';
		var web_server = '';
		if (endpoint['techs']) {
			tech_badge = '<div>' + parse_technology('', endpoint['techs'], "primary", true, false, false);
		}
		if (endpoint['webserver']) {
			web_server = `<span class='m-1 badge badge-soft-info' data-toggle="tooltip" data-placement="top" title="Web Server">${endpoint['webserver']}</span>`;
		}
		var url = split_into_lines(endpoint['http_url'], 70);
		var rand_id = get_randid();
		tech_badge += web_server + '</div>';
		var http_url_td = "<a href='" + endpoint['http_url'] + `' target='_blank' class='text-primary'>` + url + "</a>" + tech_badge;
		$('#endpoint_tbody').append(`
			<tr>
			<td>${http_url_td}</td>
			<td>${get_http_status_badge(endpoint['http_status'])}</td>
			<td>${return_str_if_not_null(htmlEncode(endpoint['page_title']))}</td>
			<td>${parse_comma_values_into_span(endpoint['matched_gf_patterns'], "danger", outline=true)}</td>
			<td>${return_str_if_not_null(endpoint['content_type'])}</td>
			<td>${return_str_if_not_null(endpoint['content_length'])}</td>
			<td>${get_response_time_text(endpoint['response_time'])}</td>
			</tr>
		`);
	}
	$("#endpoint-modal-datatable").DataTable({
		"oLanguage": {
			"oPaginate": {
				"sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
				"sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
			},
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + "<'table-responsive'tr>" + "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count  mb-sm-0 mb-3'i><'dt--pagination'p>>",
		"order": [
			[5, "desc"]
		],
		drawCallback: function() {
			$(".dataTables_paginate > .pagination").addClass("pagination-rounded")
		}
	});
}

function render_vulnerability_in_xl_modal(endpoint_url, vuln_count, subdomain_name, result) {
	// This function will render the vulnerability datatable in xl modal
	$('#xl-modal-content').append(`<h5> ${vuln_count} Vulnerabilities Discovered on subdomain ${subdomain_name}</h5>`);
	$('#xl-modal-content').append(`<ol id="vuln_results_ol" class="list-group list-group-numbered"></ol>`);
	$('#xl-modal-content').append(`
		<div class="">
		<table id="vulnerability-modal-datatable" class="table dt-responsive w-100">
		<thead>
		<tr>
		<th>Type</th>
		<th>Title</th>
		<th class="text-center">Severity</th>
		<th>CVSS Score</th>
		<th>CVE/CWE</th>
		<th>Vulnerable URL</th>
		<th class="text-center dt-no-sorting">Action</th>
		</tr>
		</thead>
		<tbody id="vuln_tbody">
		</tbody>
		</table>
		</div>
		`);
	$('#vuln_tbody').empty();
	for (var vuln in result) {
		var vuln_obj = result[vuln];
		var vuln_type = vuln_obj['type'] ? `<span class="badge badge-soft-primary">&nbsp;&nbsp;${vuln_obj['type'].toUpperCase()}&nbsp;&nbsp;</span>` : '';
		var tags = '';
		var cvss_metrics_badge = '';
		switch (vuln_obj['severity']) {
			case 'Info':
				color = 'primary'
				badge_color = 'soft-primary'
				break;
			case 'Low':
				color = 'low'
				badge_color = 'soft-warning'
				break;
			case 'Medium':
				color = 'warning'
				badge_color = 'soft-warning'
				break;
			case 'High':
				color = 'danger'
				badge_color = 'soft-danger'
				break;
			case 'Critical':
				color = 'critical'
				badge_color = 'critical'
				break;
			default:
		}
		if (vuln_obj['tags']) {
			tags = '<div>';
			vuln_obj['tags'].forEach(tag => {
				tags += `<span class="badge badge-${badge_color} me-1 mb-1" data-toggle="tooltip" data-placement="top" title="Tags">${tag.name}</span>`;
			});
			tags += '</div>';
		}
		if (vuln_obj['cvss_metrics']) {
			cvss_metrics_badge = `<div><span class="badge badge-outline-primary my-1" data-toggle="tooltip" data-placement="top" title="CVSS Metrics">${vuln_obj['cvss_metrics']}</span></div>`;
		}
		var vuln_title = `<b class="text-${color}">` + vuln_obj['name'] + `</b>` + cvss_metrics_badge + tags;
		var badge = 'danger';
		var cvss_score = '';
		if (vuln_obj['cvss_score']) {
			if (vuln_obj['cvss_score'] > 0.1 && vuln_obj['cvss_score'] <= 3.9) {
				badge = 'info';
			} else if (vuln_obj['cvss_score'] > 3.9 && vuln_obj['cvss_score'] <= 6.9) {
				badge = 'warning';
			} else if (vuln_obj['cvss_score'] > 6.9 && vuln_obj['cvss_score'] <= 8.9) {
				badge = 'danger';
			}
			cvss_score = `<span class="badge badge-outline-${badge}" data-toggle="tooltip" data-placement="top" title="CVSS Score">${vuln_obj['cvss_score']}</span>`;
		}
		var cve_cwe_badge = '<div>';
		if (vuln_obj['cve_ids']) {
			vuln_obj['cve_ids'].forEach(cve => {
				cve_cwe_badge += `<a href="https://google.com/search?q=${cve.name.toUpperCase()}" target="_blank" class="badge badge-outline-primary me-1 mt-1" data-toggle="tooltip" data-placement="top" title="CVE ID">${cve.name.toUpperCase()}</a>`;
			});
		}
		if (vuln_obj['cwe_ids']) {
			vuln_obj['cwe_ids'].forEach(cwe => {
				cve_cwe_badge += `<a href="https://google.com/search?q=${cwe.name.toUpperCase()}" target="_blank" class="badge badge-outline-primary me-1 mt-1" data-toggle="tooltip" data-placement="top" title="CWE ID">${cwe.name.toUpperCase()}</a>`;
			});
		}
		cve_cwe_badge += '</div>';
		var http_url = vuln_obj['http_url'].includes('http') ? "<a href='" + htmlEncode(vuln_obj['http_url']) + "' target='_blank' class='text-danger'>" + htmlEncode(vuln_obj['http_url']) + "</a>" : vuln_obj['http_url'];
		var action_icon = vuln_obj['hackerone_report_id'] ? '' : `
		<div class="btn-group mb-2 dropstart">
		<a href="#" class="text-dark dropdown-toggle float-end" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
		<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-more-horizontal"><circle cx="12" cy="12" r="1"></circle><circle cx="19" cy="12" r="1"></circle><circle cx="5" cy="12" r="1"></circle></svg>
		</a>
		<div class="dropdown-menu" style="">
		<a class="dropdown-item" href="javascript:report_hackerone('{% url 'api:vulnerability_report' %}', ${vuln_obj['id']}, '${vuln_obj['severity']}');">Report to Hackerone</a>
		</div>
		</div>`;
		$('#vuln_tbody').append(`
			<tr>
			<td>${vuln_type}</td>
			<td>${vuln_title}</td>
			<td class="text-center">${get_severity_badge(vuln_obj['severity'])}</td>
			<td class="text-center">${cvss_score}</td>
			<td>${cve_cwe_badge}</td>
			<td>${http_url}</td>
			<td>${action_icon}</td>
			</tr>
		`);
	}
	$("#vulnerability-modal-datatable").DataTable({
		"oLanguage": {
			"oPaginate": {
				"sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
				"sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
			},
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + "<'table-responsive'tr>" + "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count  mb-sm-0 mb-3'i><'dt--pagination'p>>",
		"order": [
			[5, "desc"]
		],
		drawCallback: function() {
			$(".dataTables_paginate > .pagination").addClass("pagination-rounded")
		}
	});
}

function render_directories_in_xl_modal(directory_count, subdomain_name, result) {
	$('#xl-modal-content').append(`<h5> ${directory_count} Directories Discovered on subdomain ${subdomain_name}</h5>`);
	$('#xl-modal-content').append(`
		<div class="">
		<table id="directory-modal-datatable" class="table dt-responsive w-100">
		<thead>
		<tr>
		<th>Directory</th>
		<th class="text-center">HTTP Status</th>
		<th>Content Length</th>
		<th>Lines</th>
		<th>Words</th>
		</tr>
		</thead>
		<tbody id="directory_tbody">
		</tbody>
		</table>
		</div>
	`);
	$('#directory_tbody').empty();
	for (var dir_obj in result) {
		var dir = result[dir_obj];
		$('#directory_tbody').append(`
			<tr>
			<td><a href="${dir.url}" target="_blank">${atob(dir.name)}</a></td>
			<td class="text-center">${get_http_status_badge(dir.http_status)}</td>
			<td>${dir.length}</td>
			<td>${dir.lines}</td>
			<td>${dir.words}</td>
			</tr>
		`);
	}
	var interesting_keywords_array = [];
	var dir_modal_table = $("#directory-modal-datatable").DataTable({
		"oLanguage": {
			"oPaginate": {
				"sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
				"sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
			},
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + "<'table-responsive'tr>" + "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count  mb-sm-0 mb-3'i><'dt--pagination'p>>",
		"order": [
			[2, "desc"]
		],
		drawCallback: function() {
			$(".dataTables_paginate > .pagination").addClass("pagination-rounded");
		}
	});
	// TODO: Find interesting dirs
	// fetch("/api/listInterestingKeywords")
	// .then(response => {
	// 	return response.json();
	// })
	// .then(data => {
	// 	interesting_keywords_array = data;
	// 	dir_modal_table.rows().every(function(){
	// 		console.log(this.data());
	// 	});
	// });
}


function get_and_render_subscan_history(endpoint, subdomain_id, subdomain_name) {
	// This function displays the subscan history in a modal for any particular subdomain
	var data = {
		'subdomain_id': subdomain_id
	};

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
		if (data['status']) {
			$('#modal_dialog .modal-title').html('Subscan History for subdomain ' + subdomain_name);
			$('#modal_dialog .modal-text').empty();
			$('#modal_dialog .modal-text').append(`<div id="subscan_history_table"></div>`);

			$('#subscan_history_table').empty();

			for (var result in data['results']) {

				var result_obj = data['results'][result];
				var error_message = '';
				var task_name = result_obj.type;

				if (result_obj.status == 0) {
					color = 'danger';
					bg_color = 'bg-soft-danger';
					status_badge = '<span class="float-end badge bg-danger">Failed</span>';
					error_message = `</br><span class="text-danger">Error: ${result_obj.error_message}`;
				} else if (result_obj.status == 3) {
					color = 'danger';
					bg_color = 'bg-soft-danger';
					status_badge = '<span class="float-end badge bg-danger">Aborted</span>';
				} else if (result_obj.status == 2) {
					color = 'success';
					bg_color = 'bg-soft-success';
					status_badge = '<span class="float-end badge bg-success">Task Completed</span>';
				}

				$('#subscan_history_table').append(`
					<div class="card border-${color} border mini-card">
					<a href="#" class="text-reset item-hovered" onclick="show_subscan_results(${data['endpoint']}, ${result_obj['id']})">
					<div class="card-header ${bg_color} text-${color} mini-card-header">
					${task_name} on <b>${result_obj.subdomain_name}</b> using engine <b>${htmlEncode(result_obj.engine)}</b>
					</div>
					<div class="card-body mini-card-body">
					<p class="card-text">
					${status_badge}
					<span class="">
					Task Completed ${result_obj.completed_ago} ago
					</span>
					Took ${result_obj.time_taken}
					${error_message}
					</p>
					</div>
					</a>
					</div>
					`);
			}


			$('#modal_dialog').modal('show');
		}
	});
}

function fetch_whois(endpoint_url, domain_name, force_reload_whois=false) {
	// this function will fetch WHOIS record for any subdomain and also display
	// snackbar once whois is fetched
	var url = `${endpoint_url}?format=json&ip_domain=${domain_name}`;
	if (force_reload_whois) {
		url+='&is_reload=true'
	}
	$('[data-toggle="tooltip"]').tooltip('hide');
	Snackbar.show({
		text: 'Fetching WHOIS...',
		pos: 'top-right',
		duration: 1500,
	});
	$("#whois_not_fetched_alert").hide();
	$("#whois_fetching_alert").show();
	fetch(url, {}).then(res => res.json())
		.then(function(response) {
			$("#whois_fetching_alert").hide();
			document.getElementById('domain_age').innerHTML = response['domain']['domain_age'] + ' ' + response['domain']['date_created'];
			document.getElementById('ip_address').innerHTML = response['domain']['ip_address'];
			document.getElementById('ip_geolocation').innerHTML = response['domain']['geolocation'];

			document.getElementById('registrant_name').innerHTML = response['registrant']['name'];
			document.getElementById('registrant_organization').innerHTML = response['registrant']['organization'] ? response['registrant']['organization'] : ' ';
			document.getElementById('registrant_address').innerHTML = response['registrant']['address'] + ' ' + response['registrant']['city'] + ' ' + response['registrant']['state'] + ' ' + response['registrant']['country'];
			document.getElementById('registrant_phone_numbers').innerHTML = response['registrant']['tel'];
			document.getElementById('registrant_fax').innerHTML = response['registrant']['fax'];

			Snackbar.show({
				text: 'Whois Fetched...',
				pos: 'top-right',
				duration: 3000
			});

			$("#whois_fetched_alert").show();

			$("#whois_fetched_alert").fadeTo(2000, 500).slideUp(1500, function() {
				$("#whois_fetched_alert").slideUp(500);
			});

		}).catch(function(error) {
			console.log(error);
		});
}

function get_target_whois(endpoint_url, domain_name) {
	var url = `${endpoint_url}?format=json&ip_domain=${domain_name}`
	Swal.fire({
		title: `Fetching WHOIS details for ${domain_name}...`
	});
	swal.showLoading();
	fetch(url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		if (response.status) {
			swal.close();
			display_whois_on_modal(response);
		} else {
			fetch(`${endpoint_url}?format=json&ip_domain=${domain_name}`, {
				method: 'GET',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken"),
					'Content-Type': 'application/json'
				},
			}).then(response => response.json()).then(function(response) {
				if (response.status) {
					swal.close();
					display_whois_on_modal(response);
				} else {
					Swal.fire({
						title: 'Oops!',
						text: `reNgine could not fetch WHOIS records for ${domain_name}!`,
						icon: 'error'
					});
				}
			});
		}
	});
}

function get_domain_whois(whoisLookupUrl, domain_name, addTargetUrl, project_slug, show_add_target_btn=false) {
	// this function will get whois for domains that are not targets, this will
	// not store whois into db nor create target
	var url = `${whoisLookupUrl}?format=json&ip_domain=${domain_name}`
	Swal.fire({
		title: `Fetching WHOIS details for ${domain_name}...`
	});
	$('.modal').modal('hide');
	swal.showLoading();
	fetch(url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		swal.close();
		if (response.status) {
			display_whois_on_modal(response, addTargetUrl, project_slug, show_add_target_btn=show_add_target_btn);
		} else {
			Swal.fire({
				title: 'Oops!',
				text: `reNgine could not fetch WHOIS records for ${domain_name}! ${response['message']}`,
				icon: 'error'
			});
		}
	});
}

function display_whois_on_modal(response, addTargetUrl, project_slug, show_add_target_btn=false) {
	// this function will display whois data on modal, should be followed after get_domain_whois()
	$('#whoisLookupResultModal').modal('show');
	$('#whoisLookupResultModal .modal-body').empty();
	$("#whoisLookupResultModal .modal-footer").empty();

	content = `
	<div class="row mt-3">
		<div class="col-sm-3">
			<div class="nav flex-column nav-pills nav-pills-tab" id="v-pills-tab" role="tablist" aria-orientation="vertical">
				<a class="nav-link active show mb-1" id="v-pills-domain-tab" data-bs-toggle="pill" href="#v-pills-domain" role="tab" aria-controls="v-pills-domain-tab" aria-selected="true">Domain info</a>
				<a class="nav-link mb-1" id="v-pills-whois-tab" data-bs-toggle="pill" href="#v-pills-whois" role="tab" aria-controls="v-pills-whois" aria-selected="false">Whois</a>
				<a class="nav-link mb-1" id="v-pills-nameserver-tab" data-bs-toggle="pill" href="#v-pills-nameserver" role="tab" aria-controls="v-pills-nameserver" aria-selected="false">Nameservers</a>
				<a class="nav-link mb-1" id="v-pills-dns-tab" data-bs-toggle="pill" href="#v-pills-dns" role="tab" aria-controls="v-pills-dns" aria-selected="false">DNS Records</a>
				<a class="nav-link mb-1" id="v-pills-history-tab" data-bs-toggle="pill" href="#v-pills-history" role="tab" aria-controls="v-pills-history"aria-selected="false">Historical Ips</a>
				<a class="nav-link mb-1" id="v-pills-related-tab" data-bs-toggle="pill" href="#v-pills-related" role="tab" aria-controls="v-pills-related" aria-selected="false">Related Domains</a>
				<a class="nav-link mb-1" id="v-pills-similar-tab" data-bs-toggle="pill" href="#v-pills-similar" role="tab" aria-controls="v-pills-similar-tld" aria-selected="false">Related TLDs</a>
			</div>
		</div>
		<div class="col-sm-9">
			<div class="tab-content pt-0">
			<div class="tab-pane fade active show" id="v-pills-domain" role="tabpanel" aria-labelledby="v-pills-domain-tab" data-simplebar style="min-height: 300px;">
				<div class="row">
					<div class="col-4">
						<small class="sub-header">Domain</small>
						<h5>${response.ip_domain}</h5>
					</div>
					<div class="col-4">
						<small class="sub-header">Dnssec</small>
						<h5>${response.dnssec}</h5>
					</div>
					<div class="col-4">
						<small class="sub-header">Geolocation</small>
						<h5>${response.geolocation_iso}
						<span class="ms-2 fi fi-${response.geolocation_iso}"></span></h5>
					</div>
				</div>
				<div class="row">
					<div class="col-4">
						<small class="sub-header">Created</small>
						<h5>${response.created}</h5>
					</div>
					<div class="col-4">
						<small class="sub-header">Updated</small>
						<h5>${response.updated}</h5>
					</div>
					<div class="col-4">
						<small class="sub-header">Expires</small>
						<h5>${response.expires}</h5>
					</div>
				</div>
				<div class="row">
					<div class="col-6">
						<small class="sub-header">Whois Server</small>
						<h5>${response.whois_server}</h5>
					</div>
				</div>
				<div class="row">
					<div class="col-4">
						<small class="sub-header">Registrar Name</small>
						<h5>${response.registrar.name}</h5>
					</div>
					<div class="col-4">
						<smal class="sub-header"l>Registrar Phone</small>
						<h5>${response.registrar.phone}</h5>
					</div>
					<div class="col-4">
						<small class="sub-header">Registrar Email</small>
						<h5>${response.registrar.email}</h5>
					</div>
				</div>`;

				for (var status in response.status) {
					var status_object = response.status[status];
					if (status_object.includes('prohibited')) {
						content += `<span class="badge badge-soft-danger me-1 mt-1">${status_object}</span>`;
					}
					else {
						content += `<span class="badge badge-soft-info mt-1 me-1">${status_object}</span>`;
					}
				}
				content += `
				</div>
				<div class="tab-pane fade" id="v-pills-whois" role="tabpanel" aria-labelledby="v-pills-whois-tab">
					<ul class="nav nav-tabs nav-bordered nav-justified">
						<li class="nav-item">
							<a href="#registrant-tab" data-bs-toggle="tab" aria-expanded="false" class="nav-link active">
								Registrant
							</a>
						</li>
						<li class="nav-item">
							<a href="#admin-tab" data-bs-toggle="tab" aria-expanded="true" class="nav-link">
								Administrative
							</a>
						</li>
						<li class="nav-item">
							<a href="#technical-tab" data-bs-toggle="tab" aria-expanded="false" class="nav-link">
								Technical
							</a>
						</li>
					</ul>
					<div class="tab-content">
						<div class="tab-pane active" id="registrant-tab">
							<div class="table-responsive">
								<table class="table mb-0">
									<tbody>
										<tr class="table-info">
											<td><b>ID</b></td>
											<td><span class="fe-user"></span>&nbsp;${response.registrant.id}</td>
										</tr>
										<tr class="">
											<td><b>Name</b></td>
											<td><span class="fe-user"></span>&nbsp;${response.registrant.name}</td>
										</tr>
										<tr class="table-primary">
											<td><b>Organization</b></td>
											<td><span class="fe-briefcase"></span>&nbsp;${response.registrant.organization}</td>
										</tr>
										<tr class="">
											<td><b>Email</b></td>
											<td><span class="fe-mail"></span>&nbsp;${response.registrant.email}</td>
										</tr>
										<tr class="table-info">
											<td><b>Phone/Fax</b></td>
											<td>
												<span class="fe-phone"></span>&nbsp;${response.registrant.phone}
												<span class="fe-printer"></span>&nbsp;${response.registrant.fax}
											</td>
										</tr>
										<tr class="">
											<td><b>Address</b></td>
											<td><span class="fe-home"></span>&nbsp;${response.registrant.address}</td>
										</tr>
										<tr class="table-danger">
											<td><b>Address</b></td>
											<td><b>City: </b>${response.registrant.city} <b>State: </b>${response.registrant.state} <b>Zip Code: </b>${response.registrant.zipcode} <b>Country:
											</b>${response.registrant.country} </td>
										</tr>
									</tbody>
								</table>
							</div>
						</div>
						<div class="tab-pane" id="admin-tab">
							<div class="table-responsive">
								<table class="table mb-0">
									<tbody>
										<tr class="table-info">
											<td><b>ID</b></td>
											<td><span class="fe-user"></span>&nbsp;${response.admin.id}</td>
										</tr>
										<tr class="">
											<td><b>Name</b></td>
											<td><span class="fe-user"></span>&nbsp;${response.admin.name}</td>
										</tr>
										<tr class="table-primary">
											<td><b>Organization</b></td>
											<td><span class="fe-briefcase"></span>&nbsp;${response.admin.organization}</td>
										</tr>
										<tr class="">
											<td><b>Email</b></td>
											<td><span class="fe-mail"></span>&nbsp;${response.admin.email}</td>
										</tr>
										<tr class="table-info">
											<td><b>Phone/Fax</b></td>
											<td>
												<span class="fe-phone"></span>&nbsp;${response.admin.phone}
												<span class="fe-printer"></span>&nbsp;${response.admin.fax}
											</td>
										</tr>
										<tr class="">
											<td><b>Address</b></td>
											<td><span class="fe-home"></span>&nbsp;${response.admin.address}</td>
										</tr>
										<tr class="table-danger">
											<td><b>Address</b></td>
											<td><b>City: </b>${response.admin.city} <b>State: </b>${response.admin.state} <b>Zip Code: </b>${response.admin.zipcode} <b>Country:
											</b>${response.admin.country} </td>
										</tr>
									</tbody>
								</table>
							</div>
						</div>
						<div class="tab-pane" id="technical-tab">
							<div class="table-responsive">
								<table class="table mb-0">
									<tbody>
										<tr class="table-info">
											<td><b>ID</b></td>
											<td><span class="fe-user"></span>&nbsp;${response.technical_contact.id}</td>
										</tr>
										<tr class="">
											<td><b>Name</b></td>
											<td><span class="fe-user"></span>&nbsp;${response.technical_contact.name}</td>
										</tr>
										<tr class="table-primary">
											<td><b>Organization</b></td>
											<td><span class="fe-briefcase"></span>&nbsp;${response.technical_contact.organization}</td>
										</tr>
										<tr class="">
											<td><b>Email</b></td>
											<td><span class="fe-mail"></span>&nbsp;${response.technical_contact.email}</td>
										</tr>
										<tr class="table-info">
											<td><b>Phone/Fax</b></td>
											<td>
												<span class="fe-phone"></span>&nbsp;${response.technical_contact.phone}
												<span class="fe-printer"></span>&nbsp;${response.technical_contact.fax}
											</td>
										</tr>
										<tr class="">
											<td><b>Address</b></td>
											<td><span class="fe-home"></span>&nbsp;${response.technical_contact.address}</td>
										</tr>
										<tr class="table-danger">
											<td><b>Address</b></td>
											<td><b>City: </b>${response.technical_contact.city} <b>State: </b>${response.technical_contact.state} <b>Zip Code: </b>${response.technical_contact.zipcode} <b>Country:
											</b>${response.technical_contact.country} </td>
										</tr>
									</tbody>
								</table>
							</div>
						</div>
					</div>
				</div>`;

				content += `
				<div class="tab-pane fade" id="v-pills-dns" role="tabpanel" aria-labelledby="v-pills-dns-tab" data-simplebar style="min-height: 300px;">
					<h4>A Records</h4>`;
					for (var a in response.dns.a) {
						var a_object = response.dns.a[a];
						content += `<span class="badge badge-soft-primary me-1 mt-1">${a_object}</span>`;
					}
					content += `<h4>MX Records</h4>`;

					for (var mx in response.dns.mx) {
						var mx_object = response.dns.mx[mx];
						content += `<span class="badge badge-soft-primary me-1 mt-1">${mx_object}</span>`;
					}
					content += `<h4>TXT Records</h4>`;
					for (var txt in response.dns.txt) {
						var txt_object = response.dns.txt[txt];
						content += `<span class="badge badge-soft-secondary me-1 mt-1">${txt_object}</span>`;
					}
					content += `</div>`;

					content += `<div class="tab-pane fade" id="v-pills-history" role="tabpanel" aria-labelledby="v-pills-history-tab" data-simplebar style="max-height: 300px; min-height: 300px;">
						<div class="alert alert-success">${response.historical_ips.length} Historical Ips</div>
						<table id="basic-datatable" class="table dt-responsive w-100">
							<thead>
									<tr>
											<th>IP</th>
											<th>Location</th>
											<th>Owner</th>
											<th>Last Seen</th>
									</tr>
							</thead>
							<tbody>`;

							for (var ip in response.historical_ips) {
								var ip_object = response.historical_ips[ip];
								content += `<tr>
									<td><b>${ip_object.ip}</b></td>
									<td>${ip_object.location}</td>
									<td>${ip_object.owner}</td>
									<td>${ip_object.last_seen}</td>
								</tr>`;
							}

							content +=`
							</tbody>
						</table>
					</div>`;

					content += `<div class="tab-pane fade" id="v-pills-nameserver" role="tabpanel" aria-labelledby="v-pills-nameserver-tab" data-simplebar style="max-height: 300px; min-height: 300px;">`;

					if (response.nameservers && response.nameservers.length > 0) {
						content += `<div class="alert alert-success">${response.nameservers.length} NameServers identified</div>`;
					
						for (var ns in response.nameservers) {
							var ns_object = response.nameservers[ns];
							content += `<span class="badge badge-soft-primary me-1 mt-1">${ns_object}</span>`;
						}
					} else {
						content += `<div class="alert alert-info">No NameServer identified</div>`;
					}
					
					content += `</div><div class="tab-pane fade" id="v-pills-similar" role="tabpanel" aria-labelledby="v-pills-similar-tab" data-simplebar style="max-height: 300px; min-height: 300px;">`;

					if (response.related_tlds.length > 0) {
						for (var domain in response.related_tlds) {
							var dom_object = response.related_tlds[domain];
							content += `<span class="badge badge-soft-primary badge-link waves-effect waves-light me-1" data-toggle="tooltip" title="Add ${dom_object} as target." onclick="add_target('${addTargetUrl}', '${project_slug}', '${dom_object}'')">${dom_object}</span>`;
						}
					}
					else{
						content += `<div class="alert alert-info">No Related TLDs identified</div>`
					}
					content += `</div>`


					content += `<div class="tab-pane fade" id="v-pills-related" role="tabpanel" aria-labelledby="v-pills-related-tab" data-simplebar style="max-height: 300px; min-height: 300px;">`;

					if (response.related_domains.length > 0) {
						for (var domain in response.related_domains) {
							var dom_object = response.related_domains[domain];
							content += `<span class="badge badge-soft-primary badge-link waves-effect waves-light me-1" data-toggle="tooltip" title="Add ${dom_object} as target." onclick="add_target('${addTargetUrl}', '${project_slug}', '${dom_object}')">${dom_object}</span>`;
						}
					}
					else{
						content += `<div class="alert alert-info">No Related Domains identified</div>`
					}
					content += `</div>`

		content += `
			</div>
		</div>
	</div>`;

	if (show_add_target_btn) {
		content += `<div class="text-center">
			<button class="btn btn-primary float-end mt-4" type="submit" onclick="add_target('${addTargetUrl}', '${project_slug}', '${response['ip_domain']}')">Add ${response['ip_domain']} as target</button>
		</div>`
	}

	// Sanitize with DOMPurify before inserting into the DOM
	$('#whoisLookupResultModal .modal-body').append(
		DOMPurify.sanitize(content)
	);
	$('[data-toggle="tooltip"]').tooltip();

}

function show_quick_add_target_modal() {
	$('#addTargetModal').modal('show');
}

$(document).on('click', '#add_target_modal', function(){
	// this function will be a onclick for add target button on add_target modal
	$('#addTargetModal').modal('hide');
	var endpoint_url = $(this).data('url');
	var current_slug = $(this).data('slug');
	var domain_name = $('#target_name_modal').val();
	var description = $('#target_description_modal').val();
	var h1_handle = $('#h1_handle_modal').val();
	var organization = $('#target_organization_modal').val();
	add_target(endpoint_url, current_slug, domain_name, h1_handle = h1_handle, description = description, organization = organization);
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


function loadSubscanHistoryWidget(endpoint, scan_history_id = null, domain_id = null) {
	// This function will load the subscan history widget
	if (scan_history_id) {
		var data = {
			'scan_history_id': scan_history_id
		}
	}

	if (domain_id) {
		var data = {
			'domain_id': domain_id
		}
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
		if (data['status']) {
			$('#sub_scan_history_count').append(`
				<span class="badge badge-soft-primary me-1">${data['results'].length}</span>
			`)
			for (var result in data['results']) {
				var error_message = '';
				var result_obj = data['results'][result];
				var task_name = get_task_name(result_obj);
				if (result_obj.status == 0) {
					color = 'danger';
					bg_color = 'bg-soft-danger';
					status_badge = '<span class="float-end badge bg-danger">Failed</span>';
					error_message = `</br><span class="text-danger">Error: ${result_obj.error_message}`;
				} else if (result_obj.status == 3) {
					color = 'danger';
					bg_color = 'bg-soft-danger';
					status_badge = '<span class="float-end badge bg-danger">Aborted</span>';
				} else if (result_obj.status == 2) {
					color = 'success';
					bg_color = 'bg-soft-success';
					status_badge = '<span class="float-end badge bg-success">Task Completed</span>';
				} else if (result_obj.status == 1) {
					color = 'primary';
					bg_color = 'bg-soft-primary';
					status_badge = '<span class="float-end badge bg-primary">Running</span>';
				}

				$('#subscan_history_widget').append(`
					<div class="card border-${color} border mini-card">
					<a href="#" class="text-reset item-hovered" onclick="show_subscan_results(${result_obj['id']})">
					<div class="card-header ${bg_color} text-${color} mini-card-header">
					${task_name} on <b>${result_obj.subdomain_name}</b>
					</div>
					<div class="card-body mini-card-body">
					<p class="card-text">
					${status_badge}
					<span class="">
					Task Completed ${result_obj.completed_ago} ago
					</span>
					Took ${result_obj.time_taken}
					${error_message}
					</p>
					</div>
					</a>
					</div>
					`);
			}
		} else {
			$('#sub_scan_history_count').append(`
					<span class="badge badge-soft-primary me-1">0</span>
				`)
			$('#subscan_history_widget').append(`
					<div class="alert alert-warning alert-dismissible fade show mt-2" role="alert">
					<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
					No Subscans has been initiated for any subdomains. You can select individual subdomains and initiate subscans like Directory Fuzzing, Vulnerability Scan etc.
					</div>
				`);
		}
	});
}

function get_ips(endpoint, scan_id=null, domain_id=null){
	// this function will fetch and render ips in widget
	var url = `${endpoint}?`;

	if (scan_id) {
		url += `scan_id=${scan_id}`;
	}

	if (domain_id) {
		url += `target_id=${domain_id}`;
	}

	url += `&format=json`;

	$.getJSON(url, function(data) {
		$('#ip-address-count').empty();
		for (var val in data['ips']){
			ip = data['ips'][val]
			badge_color = ip['is_cdn'] ? 'warning' : 'primary';
			if (scan_id) {
				$("#ip-address").append(`<span class='badge badge-soft-${badge_color}  m-1 badge-link' data-toggle="tooltip" title="${ip['ports'].length} Ports Open." onclick="get_ip_details('${ip['address']}', scan_id=${scan_id}, domain_id=null)">${ip['address']}</span>`);
			}
			else if (domain_id) {
				$("#ip-address").append(`<span class='badge badge-soft-${badge_color}  m-1 badge-link' data-toggle="tooltip" title="${ip['ports'].length} Ports Open." onclick="get_ip_details('${ip['address']}', scan_id=null, domain_id=${domain_id})">${ip['address']}</span>`);
			}
			// $("#ip-address").append(`<span class='badge badge-soft-${badge_color}  m-1' data-toggle="modal" data-target="#tabsModal">${ip['address']}</span>`);
		}
		$('#ip-address-count').html(`<span class="badge badge-soft-primary me-1">${data['ips'].length}</span>`);
		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
	});
}


function get_technologies(endpoint_url, scan_id=null, domain_id=null){
	// this function will fetch and render tech in widget
	var url = `${endpoint_url}?`;

	if (scan_id) {
		url += `scan_id=${scan_id}`;
	}

	if (domain_id) {
		url += `target_id=${domain_id}`;
	}

	url += `&format=json`;

	$.getJSON(url, function(data) {
		$('#technologies-count').empty();
		for (var val in data['technologies']){
			tech = data['technologies'][val]
			if (scan_id) {
				$("#technologies").append(`<span class='badge badge-soft-primary  m-1 badge-link' data-toggle="tooltip" title="${tech['count']} Subdomains use this technology." onclick="get_tech_details('${endpoint_url}', '${tech['name']}', scan_id=${scan_id}, domain_id=null)">${tech['name']}</span>`);
			}
			else if (domain_id) {
				$("#technologies").append(`<span class='badge badge-soft-primary  m-1 badge-link' data-toggle="tooltip" title="${tech['count']} Subdomains use this technology." onclick="get_tech_details('${endpoint_url}', '${tech['name']}', scan_id=null, domain_id=${domain_id})">${tech['name']}</span>`);
			}
		}
		$('#technologies-count').html(`<span class="badge badge-soft-primary me-1">${data['technologies'].length}</span>`);
		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
	});
}


function get_ports(endpoint_url, scan_id=null, domain_id=null){
	// this function will fetch and render ports in widget
	var url = `${endpoint_url}?`;

	if (scan_id) {
		url += `scan_id=${scan_id}`;
	}

	if (domain_id) {
		url += `target_id=${domain_id}`;
	}

	url += `&format=json`;
	$.getJSON(url, function(data) {
		$('#ports-count').empty();
		for (var val in data['ports']){
			port = data['ports'][val]
			badge_color = port['is_uncommon'] ? 'danger' : 'primary';
			if (scan_id) {
				$("#ports").append(`<span class='badge badge-soft-${badge_color}  m-1 badge-link' data-toggle="tooltip" title="${port['description']}" onclick="get_port_details('${port['number']}', scan_id=${scan_id}, domain_id=null)">${port['number']}/${port['service_name']}</span>`);
			}
			else if (domain_id){
				$("#ports").append(`<span class='badge badge-soft-${badge_color}  m-1 badge-link' data-toggle="tooltip" title="${port['description']}" onclick="get_port_details('${port['number']}', scan_id=null, domain_id=${domain_id})">${port['number']}/${port['service_name']}</span>`);
			}
		}
		$('#ports-count').html(`<span class="badge badge-soft-primary me-1">${data['ports'].length}</span>`);
		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
	});
}


function get_ip_details(endpoint_port_url, endpoint_subdomain_url, ip_address, scan_id=null, domain_id=null){
	var port_url = `${endpoint_port_url}?ip_address=${ip_address}`;
	var subdomain_url = `${endpoint_subdomain_url}?ip_address=${ip_address}`;

	if (scan_id) {
		port_url += `&scan_id=${scan_id}`;
		subdomain_url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		port_url += `&target_id=${domain_id}`;
		subdomain_url += `&target_id=${domain_id}`;
	}

	port_url += `&format=json`;
	subdomain_url += `&format=json`;

	var interesting_badge = `<span class="m-1 badge  badge-soft-danger bs-tooltip" title="Interesting Subdomain">Interesting</span>`;

	var port_loader = `<span class="inner-div spinner-border text-primary align-self-center loader-sm" id="port-modal-loader"></span>`;
	var subdomain_loader = `<span class="inner-div spinner-border text-primary align-self-center loader-sm" id="subdomain-modal-loader"></span>`;

	// add tab modal title
	$('#modal_dialog .modal-title').html('Details for IP: <b>' + ip_address + '</b>');

	$('#modal_dialog .modal-text').empty();
	$('#modal-tabs').empty();

	$('#modal_dialog .modal-text').append(`<ul class='nav nav-tabs nav-bordered' id="modal_tab_nav"></ul><div id="modal_tab_content" class="tab-content"></div>`);

	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#modal_content_port" aria-expanded="true"><span id="modal-open-ports-count"></span>Open Ports &nbsp;${port_loader}</a></li>`);
	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#modal_content_subdomain" aria-expanded="false"><span id="modal-subdomain-count"></span>Subdomains &nbsp;${subdomain_loader}</a></li>`)

	// add content area
	$('#modal_tab_content').empty();
	$('#modal_tab_content').append(`<div class="tab-pane show active" id="modal_content_port"></div><div class="tab-pane" id="modal_content_subdomain"></div>`);

	$('#modal-open-ports').append(`<div class="modal-text" id="modal-text-open-port"></div>`);
	$('#modal-text-open-port').append(`<ul id="modal-open-port-text"></ul>`);

	$('#modal_content_port').append(`<ul id="modal_port_ul"></ul>`);
	$('#modal_content_subdomain').append(`<ul id="modal_subdomain_ul"></ul>`);

	$.getJSON(port_url, function(data) {
		$('#modal_content_port').empty();
		$('#modal_content_port').append(`<p> IP Addresses ${ip_address} has ${data['ports'].length} Open Ports`);
		$('#modal-open-ports-count').html(`<b>${data['ports'].length}</b>&nbsp;&nbsp;`);
		for (port in data['ports']){
			port_obj = data['ports'][port];
			badge_color = port_obj['is_uncommon'] ? 'danger' : 'info';
			$("#modal_content_port").append(`<li class="mt-1">${port_obj['description']} <b class="text-${badge_color}">(${port_obj['number']}/${port_obj['service_name']})</b></li>`)
		}
		$("#port-modal-loader").remove();
	});

	$('#modal_dialog').modal('show');

	// query subdomains
	$.getJSON(subdomain_url, function(data) {
		$('#modal_content_subdomain').empty();
		$('#modal_content_subdomain').append(`<p>${data['subdomains'].length} Subdomains are associated with IP ${ip_address}`);
		$('#modal-subdomain-count').html(`<b>${data['subdomains'].length}</b>&nbsp;&nbsp;`);
		for (subdomain in data['subdomains']){
			subdomain_obj = data['subdomains'][subdomain];
			badge_color = subdomain_obj['http_status'] >= 400 ? 'danger' : '';
			li_id = get_randid();
			if (subdomain_obj['http_url']) {
				$("#modal_content_subdomain").append(`<li class="mt-1" id="${li_id}"><a href='${subdomain_obj['http_url']}' target="_blank" class="text-${badge_color}">${subdomain_obj['name']}</a></li>`)
			}
			else {
				$("#modal_content_subdomain").append(`<li class="mt-1 text-${badge_color}" id="${li_id}">${subdomain_obj['name']}</li>`);
			}

			if (subdomain_obj['http_status']) {
				$("#"+li_id).append(get_http_badge(subdomain_obj['http_status']));
				$('.bs-tooltip').tooltip();
			}

			if (subdomain_obj['is_interesting']) {
				$("#"+li_id).append(interesting_badge)
			}

		}
		$("#modal-text-subdomain").append(`<span class="float-end text-danger">*Subdomains highlighted are 40X HTTP Status</span>`);
		$("#subdomain-modal-loader").remove();
	});
}

function get_port_details(endpoint_ip_url, endpoint_subdomain_url, port, scan_id=null, domain_id=null){

	var ip_url = `${endpoint_ip_url}?port=${port}`;
	var subdomain_url = `${endpoint_subdomain_url}?port=${port}`;

	if (scan_id) {
		ip_url += `&scan_id=${scan_id}`;
		subdomain_url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		ip_url += `&target_id=${domain_id}`;
		subdomain_url += `&target_id=${domain_id}`;
	}

	ip_url += `&format=json`;
	subdomain_url += `&format=json`;

	var interesting_badge = `<span class="m-1 badge  badge-soft-danger bs-tooltip" title="Interesting Subdomain">Interesting</span>`;
	var ip_spinner = `<span class="spinner-border spinner-border-sm me-1" id="ip-modal-loader"></span>`;
	var subdomain_spinner = `<span class="spinner-border spinner-border-sm me-1" id="subdomain-modal-loader"></span>`;

	$('#modal_dialog .modal-title').html('Details for Port: <b>' + port + '</b>');

	$('#modal_dialog .modal-text').empty();
	$('#modal-tabs').empty();


	$('#modal_dialog .modal-text').append(`<ul class='nav nav-tabs nav-bordered' id="modal_tab_nav"></ul><div id="modal_tab_content" class="tab-content"></div>`);

	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#modal_content_ip" aria-expanded="true"><span id="modal-ip-count"></span>IP Address&nbsp;${ip_spinner}</a></li>`);
	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#modal_content_subdomain" aria-expanded="false"><span id="modal-subdomain-count"></span>Subdomains&nbsp;${subdomain_spinner}</a></li>`)

	// add content area
	$('#modal_tab_content').append(`<div class="tab-pane show active" id="modal_content_ip"></div><div class="tab-pane" id="modal_content_subdomain"></div>`);

	$('#modal_content_ip').append(`<ul id="modal_ip_ul"></ul>`);
	$('#modal_content_subdomain').append(`<ul id="modal_subdomain_ul"></ul>`);

	$('#modal_dialog').modal('show');

	$.getJSON(ip_url, function(data) {
		$('#modal_ip_ul').empty();
		$('#modal_ip_ul').append(`<p>${data['ips'].length} IP Addresses have Port ${port} Open`);
		$('#modal-ip-count').html(`<b>${data['ips'].length}</b>&nbsp;&nbsp;`);
		for (ip in data['ips']){
			ip_obj = data['ips'][ip];
			text_color = ip_obj['is_cdn'] ? 'warning' : '';
			$("#modal_ip_ul").append(`<li class='mt-1 text-${text_color}'>${ip_obj['address']}</li>`)
		}
		$('#modal_ip_ul').append(`<span class="float-end text-warning">*IP Address highlighted are CDN IP Address</span>`);
		$("#ip-modal-loader").remove();
	});

	// query subdomains
	$.getJSON(subdomain_url, function(data) {
		$('#modal_subdomain_ul').empty();
		$('#modal_subdomain_ul').append(`<p>${data['subdomains'].length} Subdomains have Port ${port} Open`);
		$('#modal-subdomain-count').html(`<b>${data['subdomains'].length}</b>&nbsp;&nbsp;`);
		for (subdomain in data['subdomains']){
			subdomain_obj = data['subdomains'][subdomain];
			badge_color = subdomain_obj['http_status'] >= 400 ? 'danger' : '';
			li_id = get_randid();
			if (subdomain_obj['http_url']) {
				$("#modal_subdomain_ul").append(`<li id="${li_id}" class="mt-1"><a href='${subdomain_obj['http_url']}' target="_blank" class="text-${badge_color}">${subdomain_obj['name']}</a></li>`)
			}
			else {
				$("#modal_subdomain_ul").append(`<li class="mt-1 text-${badge_color}" id="${li_id}">${subdomain_obj['name']}</li>`);
			}

			if (subdomain_obj['http_status']) {
				$("#"+li_id).append(get_http_badge(subdomain_obj['http_status']));
				$('.bs-tooltip').tooltip();
			}

			if (subdomain_obj['is_interesting']) {
				$("#"+li_id).append(interesting_badge)
			}

		}
		$("#modal_subdomain_ul").append(`<span class="float-end text-danger">*Subdomains highlighted are 40X HTTP Status</span>`);
		$("#subdomain-modal-loader").remove();
	});
}

function get_tech_details(endpoint_subdomain_url, tech, scan_id=null, domain_id=null){

	var url = `${endpoint_subdomain_url}?tech=${tech}`;

	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		url += `&target_id=${domain_id}`;
	}

	url += `&format=json`;

	var interesting_badge = `<span class="m-1 badge  badge-soft-danger bs-tooltip" title="Interesting Subdomain">Interesting</span>`;
	// render tab modal
	$('#modal_dialog .modal-title').html('Details for Technology: <b>' + tech + '</b>');
	$('#modal_dialog').modal('show');

	$('#modal_dialog .modal-text').empty();
	$('#modal_dialog .modal-footer').empty();
	$('#modal_dialog .modal-text').append(`<div class='outer-div' id="modal-loader"><span class="inner-div spinner-border text-primary align-self-center loader-sm"></span></div>`);
	// query subdomains
	$.getJSON(url, function(data) {
		$('#modal_dialog #modal-loader').empty();
		$('#modal_dialog .modal-text').empty();
		$('#modal_dialog .modal-text').append(`${data['subdomains'].length} Subdomains are using ${tech}`);
		const subdomainList = $('<ul></ul>');
		for (subdomain in data['subdomains']){
			subdomain_obj = data['subdomains'][subdomain];
			badge_color = subdomain_obj['http_status'] >= 400 ? 'danger' : '';
			li_id = get_randid();
			if (subdomain_obj['http_url']) {
				subdomainList.append(`<li id="${li_id}"><a href='${subdomain_obj['http_url']}' target="_blank" class="text-${badge_color}">${subdomain_obj['name']}</a></li>`)
			}
			else {
				subdomainList.append(`<li class="text-${badge_color}" id="${li_id}">${subdomain_obj['name']}</li>`);
			}

			if (subdomain_obj['http_status']) {
				$("#"+li_id).append(get_http_badge(subdomain_obj['http_status']));
				$('.bs-tooltip').tooltip();
			}

			if (subdomain_obj['is_interesting']) {
				$("#"+li_id).append(interesting_badge)
			}

		}
		$("#modal_dialog .modal-text").append(subdomainList);
		$("#modal_dialog .modal-text").append(`<span class="float-end text-danger">*Subdomains highlighted are 40X HTTP Status</span>`);
		$("#subdomain-modal-loader").remove();
	}).fail(function(){
		$('#modal_dialog #modal-loader').empty();
	});
}


function get_http_badge(http_status){
	switch (true) {
		case (http_status >= 400):
		badge_color = 'danger'
		break;
		case (http_status >= 300):
		badge_color = 'warning'
		break;
		case (http_status >= 200):
		badge_color = 'success'
		break;
		default:
		badge_color = 'danger'
	}
	if (http_status) {
		badge = `<span class="badge badge-soft-${badge_color} me-1 ms-1 bs-tooltip" data-placement="top" title="HTTP Status">${http_status}</span>`;
		return badge
	}
}


function get_and_render_cve_details(endpoint_url, cve_id){
	var api_url = `${endpoint_url}?cve_id=${cve_id}&format=json`;
	Swal.fire({
		title: 'Fetching CVE Details...'
	});
	swal.showLoading();
	fetch(api_url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			"Content-Type": "application/json"
		},
	}).then(response => response.json()).then(function(response) {
		swal.close();
		if (response.status) {
			$('#xl-modal-title').empty();
			$('#xl-modal-content').empty();
			$('#xl-modal-footer').empty();
			$('#xl-modal_title').html(`CVE Details of ${cve_id}`);

			var cvss_score_badge = 'danger';

			if (response.result.cvss > 0.1 && response.result.cvss <= 3.9) {
				cvss_score_badge = 'info';
			}
			else if (response.result.cvss > 3.9 && response.result.cvss <= 6.9) {
				cvss_score_badge = 'warning';
			}

			content = `<div class="row mt-3">
				<div class="col-sm-3">
				<div class="nav flex-column nav-pills nav-pills-tab" id="v-pills-tab" role="tablist" aria-orientation="vertical">
				<a class="nav-link active show mb-1" id="v-pills-cve-details-tab" data-bs-toggle="pill" href="#v-pills-cve-details" role="tab" aria-controls="v-pills-cve-details-tab" aria-selected="true">CVE Details</a>
				<a class="nav-link mb-1" id="v-pills-affected-products-tab" data-bs-toggle="pill" href="#v-pills-affected-products" role="tab" aria-controls="v-pills-affected-products-tab" aria-selected="true">Affected Products</a>
				<a class="nav-link mb-1" id="v-pills-affected-versions-tab" data-bs-toggle="pill" href="#v-pills-affected-versions" role="tab" aria-controls="v-pills-affected-versions-tab" aria-selected="true">Affected Versions</a>
				<a class="nav-link mb-1" id="v-pills-cve-references-tab" data-bs-toggle="pill" href="#v-pills-cve-references" role="tab" aria-controls="v-pills-cve-references-tab" aria-selected="true">References</a>
				</div>
				</div>
				<div class="col-sm-9">
				<div class="tab-content pt-0">`;

				content += `
				<div class="tab-pane fade active show" id="v-pills-cve-details" role="tabpanel" aria-labelledby="v-pills-cve-details-tab" data-simplebar style="max-height: 600px; min-height: 600px;">
					<h4 class="header-title">${cve_id}</h4>
					<div class="alert alert-warning" role="alert">
						${response.result.summary}
					</div>
					<span class="badge badge-soft-primary">Assigner: ${response.result.assigner}</span>
					<span class="badge badge-outline-primary">CVSS Vector: ${response.result['cvss-vector']}</span>
					<table class="domain_details_table table table-hover table-borderless">
						<tr style="display: none">
							<th>&nbsp;</th>
							<th>&nbsp;</th>
						</tr>
						<tr>
							<td>CVSS Score</td>
							<td><span class="badge badge-soft-${cvss_score_badge}">${response.result.cvss ? response.result.cvss: "-"}</span></td>
						</tr>
						<tr>
							<td>Confidentiality Impact</td>
							<td>${response.result.impact.confidentiality ? response.result.impact.confidentiality: "N/A"}</td>
						</tr>
						<tr>
							<td>Integrity Impact</td>
							<td>${response.result.impact.integrity ? response.result.impact.integrity: "N/A"}</td>
						</tr>
						<tr>
							<td>Availability Impact</td>
							<td>${response.result.impact.availability ? response.result.impact.availability: "N/A"}</td>
						</tr>
						<tr>
							<td>Access Complexity</td>
							<td>${response.result.access.complexity ? response.result.access.complexity: "N/A"}</td>
						</tr>
						<tr>
							<td>Authentication</td>
							<td>${response.result.access.authentication ? response.result.access.authentication: "N/A"}</td>
						</tr>
						<tr>
							<td>CWE ID</td>
							<td><span class="badge badge-outline-danger">${response.result.cwe ? response.result.cwe: "N/A"}</span></td>
						</tr>
					</table>
				</div>
				`;

				let references = response.result.references;

				// Check if references is a string representation of an array
				if (typeof references === 'string' && references.startsWith('[') && references.endsWith(']')) {
					// Remove the brackets and split by comma
					references = references.slice(1, -1).split(',').map(ref => ref.trim().replace(/^'|'$/g, ''));
				}
				
				// Generate HTML content
				let referencesContent = '';
				if (Array.isArray(references)) {
					referencesContent = '<ul>';
					references.forEach(ref => {
						referencesContent += `<li><a href="${ref}" target="_blank" rel="noopener noreferrer">${ref}</a></li>`;
					});
					referencesContent += '</ul>';
				} else {
					referencesContent = `<p>${references}</p>`;
				}
				
				content += `<div class="tab-pane fade" id="v-pills-cve-references" role="tabpanel" aria-labelledby="v-pills-cve-references-tab" data-simplebar style="max-height: 600px; min-height: 600px;">
					${referencesContent}
				</div>`;
				
				content += `<div class="tab-pane fade" id="v-pills-affected-products" role="tabpanel" aria-labelledby="v-pills-affected-products-tab" data-simplebar style="max-height: 600px; min-height: 600px;">
				<ul>`;

				for (var prod in response.result.vulnerable_product) {
					content += `<li>${response.result.vulnerable_product[prod]}</li>`;
				}

				content += `</ul></div>`;

				content += `<div class="tab-pane fade" id="v-pills-affected-versions" role="tabpanel" aria-labelledby="v-pills-affected-versions-tab" data-simplebar style="max-height: 600px; min-height: 600px;">
				<ul>`;

				for (var conf in response.result.vulnerable_configuration) {
					content += `<li>${response.result.vulnerable_configuration[conf]['id']}</li>`;
				}

				content += `</ul></div>`;

				content += `</div></div></div>`;

			$('#xl-modal-content').append(content);

			$('#modal_xl_scroll_dialog').modal('show');
			$("body").tooltip({
				selector: '[data-toggle=tooltip]'
			});
		}
		else{
			swal.fire("Error!", response.message, "error", {
				button: "Okay",
			});
		}
	});
}


function get_most_vulnerable_target(endpoint_url, endpoint_vuln_url, slug=null, scan_id=null, target_id=null, ignore_info=false, limit=50){
	$('#most_vulnerable_target_div').empty();
	$('#most_vulnerable_spinner').append(`<div class="spinner-border text-primary m-2" role="status"></div>`);
	var data = {};
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
				<th style="width: 60%">Target</th>
				<th style="width: 30%">Vulnerabilities Count</th>
				</tr>
				</thead>
				<tbody id="most_vulnerable_target_tbody">
				</tbody>²
				</table>
				`);

			for (var res in response.result) {
				var targ_obj = response.result[res];
				var tr = `<tr onclick="window.location='${endpoint_vuln_url}?domain=${targ_obj.name}';" style="cursor: pointer;">`;
				if (scan_id || target_id) {
					tr = `<tr onclick="window.location='${endpoint_vuln_url}?subdomain=${targ_obj.name}';" style="cursor: pointer;">`;
				}
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
	var data = {};
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
							<th style="width: 60%">Vulnerability Name</th>
							<th style="width: 20%">Count</th>
							<th style="width: 20%">Severity</th>
						</tr>
					</thead>
				<tbody id="most_common_vuln_tbody">
				</tbody>
				</table>
			`);

			for (var res in response.result) {
				var vuln_obj = response.result[res];
				var vuln_badge = '';
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
					<tr onclick="window.location='${endpoint_vuln_url}?vulnerability_name=${vuln_obj.name}';" style="cursor: pointer;">
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
		}
		else{
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
	var reg = new RegExp('('+search_keyword+')', 'gi');
	return content.replace(reg, '<mark>$1</mark>');
}


function validURL(str) {
	// checks for valid http url
	var pattern = new RegExp('^(https?:\\/\\/)?'+ // protocol
		'((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|'+ // domain name
		'((\\\d{1,3}\\.){3}\\d{1,3}))'+ // OR ip (v4) address
		'(\\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*'+ // port and path
		'(\\\?[;&a-z\\d%_.~+=-]*)?'+ // query string
		'(\\\#[-a-z\\d_]*)?$','i'); // fragment locator
	return !!pattern.test(str);
}


function shadeColor(color, percent) {
	//https://stackoverflow.com/a/13532993
	var R = parseInt(color.substring(1,3),16);
	var G = parseInt(color.substring(3,5),16);
	var B = parseInt(color.substring(5,7),16);

	R = parseInt(R * (100 + percent) / 100);
	G = parseInt(G * (100 + percent) / 100);
	B = parseInt(B * (100 + percent) / 100);

	R = (R<255)?R:255;
	G = (G<255)?G:255;
	B = (B<255)?B:255;

	var RR = ((R.toString(16).length==1)?"0"+R.toString(16):R.toString(16));
	var GG = ((G.toString(16).length==1)?"0"+G.toString(16):G.toString(16));
	var BB = ((B.toString(16).length==1)?"0"+B.toString(16):B.toString(16));

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


function render_vuln_offcanvas(vuln){
	$('#offcanvas').addClass('offcanvas-size-lg');
	var default_color = 'primary';
	var default_badge_color = 'soft-primary';
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
	var offcanvas_title = document.getElementById('offcanvas-title');
	var offcanvas_body = document.getElementById('offcanvas-body');
	var title_content = '';
	var body = '';
	title_content += `<i class="mdi mdi-bug-outline me-1 text-${default_color}"></i>`;
	title_content += `<span class="badge badge-${default_badge_color} text-${default_color}">${vuln.severity}</span>`;
	title_content += `<span class="text-${default_color} ms-1">${vuln.name}</span>`;

	body += `<p><b>ID: </b>${vuln.id}</p>`;
	body += `<p><b>Discovered on: </b>${vuln.discovered_date}</p>`;
	body += `<p><b>URL: </b><a href="${vuln.http_url}" target="_blank">${vuln.http_url}</a></p>`;
	body += `<p><b>Severity: </b>${vuln.severity}<br><b>Type: </b>${vuln.type.toUpperCase()}<br><b>Source: </b> ${vuln.source.toUpperCase()}</p>`;

	if (vuln.description) {
		// Sanitize with DOMPurify before inserting into the DOM
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
		<p>${DOMPurify.sanitize(vuln.description.replace(new RegExp('\r?\n','g'), '<br />'))}</p>
		</div>
		</div>`;
	}

	if (vuln.impact) {
		impact = vuln.impact.replace(new RegExp('\r?\n','g'), '<br />');
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
		<p>${DOMPurify.sanitize(impact)}</p>
		</div>
		</div>`;
	}

	if (vuln.remediation) {
		remediation = vuln.remediation.replace(new RegExp('\r?\n','g'), '<br />');
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
		<p>${DOMPurify.sanitize(remediation)}</p>
		</div>
		</div>`;
	}

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

	if (vuln.cve_ids.length) {
		body += `<tr>
		<td style="width:30%">
		<b>CVE IDs</b>
		</td>
		<td>`;

		vuln.cve_ids.forEach(cve => {
			body += `<a href="#" onclick="get_and_render_cve_details('${cve.name.toUpperCase()}')" class="badge badge-outline-primary me-1 mt-1" data-toggle="tooltip" data-placement="top" title="CVE ID">${cve.name.toUpperCase()}</a>`;
		});

	body += `</td>
		</tr>`
	}

	if (vuln.cwe_ids != null && vuln.cwe_ids.length) {
		body += `<tr>
		<td style="width:30%">
		<b>CWE IDs</b>
		</td>
		<td>`

		vuln.cwe_ids.forEach(cwe => {
			body += `<a href="https://google.com/search?q=${cwe.name.toUpperCase()}" target="_blank" class="badge badge-outline-primary me-1 mt-1" data-toggle="tooltip" data-placement="top" title="CWE ID">${cwe.name.toUpperCase()}</a>`;
		});

	body += `</td>
		</tr>`
	}

	if (vuln.cvss_score) {
		var badge = 'danger';
		if (vuln.cvss_score > 0.1 && vuln.cvss_score <= 3.9) {
			badge = 'info';
		}
		else if (vuln.cvss_score > 3.9 && vuln.cvss_score <= 6.9) {
			badge = 'warning';
		}

		body += `<tr>
		<td style="width:30%">
		<b>CVSS Score</b>
		</td>
		<td>
		<span class="badge badge-outline-${badge}" data-toggle="tooltip" data-placement="top" title="CVSS Score">${vuln.cvss_score}</span>
		</td>
		</tr>`
	}

	if (vuln.cvss_metrics) {
		body += `<tr>
		<td style="width:30%">
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
		<td style="width:20%"><b>Template</b></td>
		<td>${vuln.template}</td>
		</tr>
		<tr>
		<td style="width:20%"><b>Template URL</b></td>
		<td><a target="_blank" href="${vuln.template_url}">${vuln.template_url}</a></td>
		</tr>
		<tr>
		<td style="width:20%"><b>Template ID</b></td>
		<td>${vuln.template_id}</td>
		</tr>
		<tr>
		<td style="width:20%"><b>Matcher Name</b></td>
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

	var http_request = vuln.request ? vuln.request : '';
	var http_response = vuln.response ? vuln.response : '';

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

	let references = vuln.references;

	// Check if references is a string representation of an array
	if (typeof references === 'string' && references.startsWith('[') && references.endsWith(']')) {
		// Remove the brackets and split by comma
		references = references.slice(1, -1).split(',').map(ref => ref.trim().replace(/^'|'$/g, ''));
	}

	// Generate HTML content
	let referencesContent = '';
	if (Array.isArray(references)) {
		referencesContent = '<ul>';
		references.forEach(ref => {
			referencesContent += `<li><a href="${ref}" target="_blank" rel="noopener noreferrer">${ref}</a></li>`;
		});
		referencesContent += '</ul>';
	} else {
		referencesContent = `<p>${references}</p>`;
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
	$('#offcanvas').offcanvas('show');
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

async function send_llm_api_request(endpoint_url, vuln_id){
	const api = `${endpoint_url}?format=json&id=${vuln_id}`;
	try {
		const response = await fetch(api, {
				method: 'GET',
				credentials: "same-origin",
				headers: {
					"X-CSRFToken": getCookie("csrftoken")
				}
		});
		if (!response.ok) {
			throw new Error('Request failed');
		}
		return await response.json();
	} catch (error) {
		throw new Error('Request failed');
	}
}


async function fetch_llm_vuln_details(endpoint_url, id, title) {
	var loader_title = "Loading...";
	var text = 'Please wait while the LLM is generating vulnerability description.';
	try {
		showSwalLoader(loader_title, text);
		const data = await send_llm_api_request(endpoint_url, id);
		Swal.close();
		if (data.status) {
			render_llm_vuln_modal(data, title);
		}
		else{
			Swal.close();
			Swal.fire({
				icon: 'error',
				title: 'Oops...',
				text: data.error,
			});
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


function render_llm_vuln_modal(data, title){
	// Change modal size to xl
	$('#modal_dialog .modal-dialog').removeClass('modal-lg').addClass('modal-xl');

	$('#modal_dialog .modal-title').empty();
	$('#modal_dialog .modal-text').empty();
	$('#modal_dialog .modal-footer').empty();
	$('#modal_dialog .modal-title').html(`Vulnerability detail for ${title}`);

	var modal_content = `
		<h4>Description</h4>
		<p>${data.description}</p>
		<h4>Impact</h4>
		<p>${data.impact}</p>
		<h4>Remediation</h4>
		<p>${data.remediation}</p>
		<h4>References</h4>
		<p>${data.references}</p>
	`;

	// Sanitize with DOMPurify before inserting into the DOM
	$('#modal_dialog .modal-text').append(
		DOMPurify.sanitize(modal_content)
	);
	$('#modal_dialog').modal('show');
}


function get_datatable_col_index(lookup, cols){
	// this function will be used to return index of lookup string and cols are datatables cols
	return cols.findIndex(column => column.data === lookup);
}


function endpoint_datatable_col_visibility(endpoint_table){
	if(!$('#end_http_status_filter_checkbox').is(":checked")){
		endpoint_table.column(2).visible(false);
	}
	if(!$('#end_page_title_filter_checkbox').is(":checked")){
		endpoint_table.column(3).visible(false);
	}
	if(!$('#end_tags_filter_checkbox').is(":checked")){
		endpoint_table.column(4).visible(false);
	}
	if(!$('#end_content_type_filter_checkbox').is(":checked")){
		endpoint_table.column(5).visible(false);
	}
	if(!$('#end_content_length_filter_checkbox').is(":checked")){
		endpoint_table.column(6).visible(false);
	}
	if(!$('#end_response_time_filter_checkbox').is(":checked")){
		endpoint_table.column(9).visible(false);
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
        await showModelSelectionDialog(endpoint_url, id);
    } catch (error) {
        console.error(error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: 'Something went wrong!',
        });
    }
}

async function showModelSelectionDialog(endpoint_url, id, force_regenerate = false) {
    try {
        // Fetch models from the unified endpoint that combines GPT and Ollama models
        const response = await fetch('/api/tools/llm_models');
        const data = await response.json();
        
        if (!data.status) {
            throw new Error(data.error || 'Failed to fetch models');
        }

        // Change modal size to xl
        $('#modal_dialog .modal-dialog').removeClass('modal-lg').addClass('modal-xl');

        // Keep all the existing model selection code
		window.generateAttackSurface = async () => {
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
		
				// Then proceed with attack surface analysis
				var loader_title = "Loading...";
				var text = 'Please wait while the LLM is generating attack surface.';
				showSwalLoader(loader_title, text);
				const data = await send_llm__attack_surface_api_request(endpoint_url, id, force_regenerate, false, selectedModel);
				Swal.close();
                
                if (data.status) {
					showAttackSurfaceModal(data, endpoint_url, id);
                } else {
                    Swal.fire({
                        icon: 'error',
                        title: 'Oops...',
                        text: data.error,
                    });
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
                    <div class="card project-box h-100" style="cursor: pointer" 
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
                                <p>${!isLocal ? '<span class="badge bg-soft-warning text-warning mt-auto">Remote Model - API Key Required</span>' : '<span class="badge bg-soft-success text-success mt-auto">Locally installed model</span>'}</p>
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

        $('#modal_dialog .modal-title').html('Select LLM Model for Attack Surface Analysis');
        $('#modal_dialog .modal-text').empty();
        $('#modal_dialog .modal-text').append(`
            <div class="mb-3 row">
                <p>Select the LLM model to use:</p>
                ${modelOptions}
            </div>
            <div class="mb-3 text-center">
                <button class="btn btn-primary" type="button" onclick="window.generateAttackSurface()">
                    Continue Analysis
                </button>
            </div>
        `);
        
        $('#modal_dialog').modal('show');
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
                $('#modal_dialog').modal('hide');
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
    $('#modal_dialog .modal-dialog').removeClass('modal-lg').addClass('modal-xl');
    $('#modal_dialog .modal-title').html(`Attack Surface Suggestion for ${data.subdomain_name}`);
    $('#modal_dialog .modal-text').empty();
    $('#modal_dialog .modal-text').append(
        DOMPurify.sanitize(data.description) +
        `<div class="text-center mt-4">
            <div class="btn-group" role="group">
                <button class="btn btn-primary" onclick="regenerateAttackSurface('${endpoint_url}', ${id})">
                    <i class="fe-refresh-cw me-1"></i>
                    Generate New Analysis
                </button>
                <button class="btn btn-danger" onclick="deleteAttackSurfaceAnalysis('${endpoint_url}', ${id})">
                    <i class="fe-trash-2 me-1"></i>
                    Delete Current Analysis
                </button>
            </div>
        </div>`
    );
    $('#modal_dialog').modal('show');
}

function convertToCamelCase(inputString) {
	// Converts camel case string to title
	// Split the input string by underscores
	const words = inputString.split('_');

	// Capitalize the first letter of each word and join them with a space
	const camelCaseString = words.map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');

	return camelCaseString;
}
function handleHashInUrl(){
	// this function handles hash in url used to tab navigation
	const hash = window.location.hash;
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

function showLLMModelSelectionModal(callback) {
    $('#modal_dialog .modal-title').html('Select LLM Model');
    $('#modal_dialog .modal-text').empty();
    
    // Get available models
    fetch('/api/tool/ollama/')
        .then(response => response.json())
        .then(data => {
            const models = data.models;
            const selectedModel = data.selected_model;
            
            let modelOptions = '';
            models.forEach(model => {
                modelOptions += `
                    <div class="form-check">
                        <input class="form-check-input" type="radio" name="llm_model" 
                            id="${model.name}" value="${model.name}" 
                            ${model.name === selectedModel ? 'checked' : ''}>
                        <label class="form-check-label" for="${model.name}">
                            ${model.name} (${model.details.family})
                        </label>
                    </div>`;
            });

            $('#modal_dialog .modal-text').append(`
                <div class="mb-3">
                    <p>Select the LLM model to use for vulnerability analysis:</p>
                    ${modelOptions}
                </div>
                <div class="mb-3 text-center">
                    <button class="btn btn-primary float-end" type="submit" onclick="selectLLMModel()">
                        Continue
                    </button>
                </div>
            `);
            
            $('#modal_dialog').modal('show');
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
            $('#modal_dialog').modal('hide');
            // Continue with scan
            startScan();
        } else {
            Swal.fire({
                title: 'Error',
                text: 'Unable to set selected model',
                icon: 'error'
            });
        }
    });
}
