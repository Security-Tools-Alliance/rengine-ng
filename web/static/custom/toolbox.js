function show_whois_lookup_modal(){
	$('#whoisLookupModal').modal('show');
}

$(document).on('click', '#search_whois_toolbox_btn', function(){
	var domain = document.getElementById("whois_domain_name").value;
	var whoisLookupUrl = $(this).data('url');
	var project_slug = $(this).data('slug');
	var addTargetUrl = $(this).data('addtargeturl');
	if (domain) {
		get_domain_whois(whoisLookupUrl, domain, addTargetUrl, project_slug, true);
	}
	else{
		swal.fire("Error!", 'Please enter the domain/IP Address!', "warning", {
			button: "Okay",
		});
	}
});


function cms_detector(){
	$('#cmsDetectorModal').modal('show');
}


$(document).on('click', '#detect_cms_submit_btn', function(){
	var url = document.getElementById("cms_detector_input_url").value;
	var cmsDetectorUrl = $(this).data('url');
	if (!validURL(url)) {
		swal.fire("Error!", 'Please enter a valid URL!', "warning", {
			button: "Okay",
		});
		return;
	}
	cms_detector_api_call(cmsDetectorUrl, url);
});


function cms_detector_api_call(cmsDetectorUrl, url){
	var api_url = `${cmsDetectorUrl}?format=json&url=${url}`
	Swal.fire({
		title: `Detecting CMS`,
		text: `reNgine is detecting CMS on ${url} and this may take a while. Please wait...`,
		allowOutsideClick: false
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
		if (response.status) {
			swal.close();
			$('#modal_title').html('CMS Details for ' + url);
			$('#modal-content').empty();

			content = `
				<div class="d-flex align-items-start mb-3">
					<img class="d-flex me-3 rounded-circle avatar-lg" src="${response.cms_url}/favicon.ico" alt="${response.cms_name}">
					<div class="w-100">
						<h4 class="mt-0 mb-1">${response.cms_name}</h4>
						<a href="${response.cms_url}" class="btn btn-xs btn-primary" target="_blank">Visit CMS</a>
					</div>
				</div>

				<h5 class="mb-3 mt-4 text-uppercase bg-light p-2"><i class="fe-info"></i>&nbsp;CMS Details</h5>
				<div class="">
					<h4 class="font-13 text-muted text-uppercase">CMS Name :</h4>
					<p class="mb-3">${response.cms_name}</p>

					<h4 class="font-13 text-muted text-uppercase mb-1">CMS URL :</h4>
					<p class="mb-3"><a href="${response.cms_url}">${response.cms_url}</a></p>

					<h4 class="font-13 text-muted text-uppercase mb-1">Detection Method :</h4>
					<p class="mb-3">${response.detection_param}</p>

					<h4 class="font-13 text-muted text-uppercase mb-1">URL :</h4>
					<p class="mb-3">
					<small class="text-muted">(Includes redirected URL)</small><br>
					<a href="${response.url}" target="_blank">${response.url}</a>
					</p>`;


			if (response.wp_license) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Wordpress License :</h4>
				<p class="mb-3">
				<a href="${response.wp_license}" target="_blank">${response.wp_license}</a>
				</p>`;
			}

			if (response.wp_readme_file) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Wordpress Readme file :</h4>
				<p class="mb-3">
				<a href="${response.wp_readme_file}" target="_blank">${response.wp_readme_file}</a>
				</p>`;
			}

			if (response.wp_uploads_directory) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Wordpress Uploads Directory :</h4>
				<p class="mb-3">
				<a href="${response.wp_uploads_directory}" target="_blank">${response.wp_uploads_directory}</a>
				</p>`;
			}

			if (response.wp_users) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Wordpress Users :</h4>
				<p class="mb-3">
				${response.wp_users}
				</p>`;
			}

			if (response.wp_version) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Wordpress Version :</h4>
				<p class="mb-3">
				${response.wp_version}
				</p>`;
			}

			if (response.wp_plugins) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Wordpress Plugins :</h4>
				<p class="mb-3">
				${response.wp_plugins}
				</p>`;
			}

			if (response.wp_themes) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Wordpress Themes :</h4>
				<p class="mb-3">
				${response.wp_themes}
				</p>`;
			}

			if (response.joomla_version) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Joomla Version :</h4>
				<p class="mb-3">
				${response.joomla_version}
				</p>`;
			}

			if (response.joomla_debug_mode) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Joomla Debug Mode :</h4>
				<p class="mb-3">
				${response.joomla_debug_mode}
				</p>`;
			}

			if (response.joomla_readme_file) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Joomla Readme File :</h4>
				<p class="mb-3">
				<a href="${response.joomla_readme_file}" target="_blank">${response.joomla_readme_file}</a>
				</p>`;
			}

			if (response.joomla_backup_files) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Joomla Backup Files :</h4>
				<p class="mb-3">
				<a href="${response.joomla_backup_files}" target="_blank">${response.joomla_backup_files}</a>
				</p>`;
			}

			if (response.directory_listing) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Joomla Directory Listing :</h4>
				<p class="mb-3">
				<a href="${response.directory_listing}" target="_blank">${response.directory_listing}</a>
				</p>`;
			}

			if (response.joomla_config_files) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Joomla Config Files :</h4>
				<p class="mb-3">
				<a href="${response.joomla_config_files}" target="_blank">${response.joomla_config_files}</a>
				</p>`;
			}

			if (response.user_registration_url) {
				content += `<h4 class="font-13 text-muted text-uppercase mb-1">Joomla User Registration :</h4>
				<p class="mb-3">
				<a href="${response.user_registration_url}" target="_blank">${response.user_registration_url}</a>
				</p>`;
			}

			content += `<br><a class="mt-2" data-bs-toggle="collapse" href="#response_json" aria-expanded="false" aria-controls="response_json">Response Json <i class="fe-terminal"></i></a>`;
			content += `<div class="collapse" id="response_json"><ul>`;
			content += `<pre><code>${htmlEncode(JSON.stringify(response, null, 4))}</code></pre>`;
			content += '</ul></div>';


			content += '</div>'

			$('#cmsDetectorResultModal #modal-content').append(content);
			$('#cmsDetectorResultModal').modal('show');
		} else {
			Swal.fire({
				title: 'Oops!',
				text: `${response['message']}`,
				icon: 'error'
			});
		}
	});
}


function toolbox_cve_detail(){
	$('#cveDetailModal').modal('show');
}



$(document).on('click', '#cve_detail_submit_btn', function(){
    var cve_id = document.getElementById("cve_id").value;
    var cveDetailsUrl = $(this).data('url');

    if (cve_id) {
        get_and_render_cve_details(cveDetailsUrl, cve_id);
    }
    else{
        swal.fire("Error!", 'Please enter CVE ID!', "warning", {
            button: "Okay",
        });
    }
});


function toolbox_waf_detector(){
	$('#wafDetectorModal').modal('show');
}


$(document).on('click', '#detect_waf_submit_btn', function(){
	var url = document.getElementById("waf_detector_input_url").value;
	var wafDetectorUrl = $(this).data('url');
	if (!validURL(url)) {
		swal.fire("Error!", 'Please enter a valid URL!', "warning", {
			button: "Okay",
		});
		return;
	}
	waf_detector_api_call(wafDetectorUrl, url);
});


function waf_detector_api_call(wafDetectorUrl, url){
	var api_url = `${wafDetectorUrl}?format=json&url=${url}`
	Swal.fire({
		title: `Detecting WAF`,
		text: `reNgine is detecting WAF on ${url} and this may take a while. Please wait...`,
		allowOutsideClick: false
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
		if (response.status) {
			swal.close()
			Swal.fire({
				title: 'WAF Detected!',
				text: `${url} is running ${response.results}`,
				icon: 'info'
			});
		} else {
			Swal.fire({
				title: 'Oops!',
				text: `${response['message']}`,
				icon: 'error'
			});
		}
	});
}
