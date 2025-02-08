function renderPortBadge(port_data, settings) {
    let port_badge = '';
	let ip = [];
    
    try {
		const port_data_obj = {};
        if (typeof port_data === 'string') {
            const decoded = new DOMParser().parseFromString(port_data, "text/html").documentElement.textContent;
            port_data_obj = JSON.parse(decoded);
        }

        for (ip of port_data_obj) {
            const ports = ip.ports || [];
            for (port of ports) {
                const badge_color = port.is_uncommon ? 'danger' : 'primary';
                let title = `Port ${port.number}`;
                
                if (port.description) {
                    title += ` - ${port.description}`;
                }
                if (port.subdomain_count) {
                    title += `\nFound on ${port.subdomain_count} IP${port.subdomain_count > 1 ? 's' : ''}`;
                }
                
                let onclick = `get_port_details('${settings.api_ips_url}', '${settings.api_subdomains_url}', ${port.number}`;
                
                if (settings.scan_id) {
                    onclick += `, ${settings.scan_id}`;
                } else {
                    onclick += `, scan_id=null`;
                }
                
                if (settings.domain_id) {
                    onclick += `, ${settings.domain_id}`;
                } else {
                    onclick += `, domain_id=null`;
                }
                
                onclick += `)`;
                
                port_badge += `<span class='m-1 badge badge-soft-${badge_color} bs-tooltip badge-link' 
                    title='${title}' 
                    onclick="${onclick}">
                    ${port.number}/${port.service_name}
                    ${port.subdomain_count ? `<span class="badge bg-${badge_color} ms-1">${port.subdomain_count}</span>` : ''}
                </span>`;
            }
        }
    } catch (e) {
        console.error('Error rendering port badge:', e);
    }
    
    return port_badge;
}


function get_ips(endpoint, scan_id=null, domain_id=null){
	// this function will fetch and render ips in widget
	let url = `${endpoint}?`;

	if (scan_id) {
		url += `scan_id=${scan_id}`;
	}

	if (domain_id) {
		url += `target_id=${domain_id}`;
	}

	url += `&format=json`;

	$.getJSON(url, function(data) {
		$('#ip-address-count').empty();
		let ip = [];
		let badge_color = '';
		for (const val in data['ips']){
			ip = data['ips'][val]
			badge_color = ip['is_cdn'] ? 'warning' : 'primary';
			if (scan_id) {
				$("#ip-address").append(`<span class='badge badge-soft-${badge_color}  m-1 badge-link' data-toggle="tooltip" title="${ip['ports'].length} Ports Open." onclick="'{% url 'api:listPorts' %}', '{% url 'api:subdomains-list' %}', '${ip['address']}', scan_id=${scan_id}, domain_id=null)">${ip['address']}</span>`);
			}
			else if (domain_id) {
				$("#ip-address").append(`<span class='badge badge-soft-${badge_color}  m-1 badge-link' data-toggle="tooltip" title="${ip['ports'].length} Ports Open." onclick="'{% url 'api:listPorts' %}', '{% url 'api:subdomains-list' %}', '${ip['address']}', scan_id=null, domain_id=${domain_id})">${ip['address']}</span>`);
			}
			// $("#ip-address").append(`<span class='badge badge-soft-${badge_color}  m-1' data-toggle="modal" data-target="#tabsModal">${ip['address']}</span>`);
		}
		$('#ip-address-count').html(`<span class="badge badge-soft-primary me-1">${data['ips'].length}</span>`);
		$("body").tooltip({ selector: '[data-toggle=tooltip]' });
	});
}

function get_ports(ip_addresses, ip_url, subdomain_url, scan_id=null, domain_id=null) {
    try {
        // Décoder les données HTML puis parser le JSON
        const decoded = new DOMParser().parseFromString(ip_addresses, "text/html").documentElement.textContent;
        const data = JSON.parse(decoded);
        
        // Create a Map to store ports and their subdomains
        const portMap = new Map();
        
        // Iterate through all IPs and their ports
        data.forEach(ip => {
            ip.ports.forEach(port => {
                const portKey = JSON.stringify({
                    number: port.number,
                    service_name: port.service_name,
                    description: port.description,
                    is_uncommon: port.is_uncommon
                });
                
                // Initialize or update the Set of subdomains for this port
                if (!portMap.has(portKey)) {
                    portMap.set(portKey, new Set());
                }
                // Add the current IP to the Set of this port
                portMap.get(portKey).add(ip.address);
            });
        });
        
        // Convert the Map to an array of ports with the count of subdomains
        const ports = Array.from(portMap.entries()).map(([portKey, ips]) => {
            const port = JSON.parse(portKey);
            port.subdomain_count = ips.size;
            return port;
        });
        
        // Display the total number of ports
        $('#ports-count').html(`<span class="badge badge-soft-primary me-1">${ports.length}</span>`);
        
        // Display the port badges
        $('#ports').html(renderPortBadge(
            [{ports: ports}],
            {
                api_ips_url: ip_url,
                api_subdomains_url: subdomain_url,
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

function get_port_details(endpoint_ip_url, endpoint_subdomain_url, port, scan_id=null, domain_id=null){

	let ip_url = `${endpoint_ip_url}?port=${port}`;
	let subdomain_url = `${endpoint_subdomain_url}?port=${port}`;

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

	const interesting_badge = `<span class="m-1 badge  badge-soft-danger bs-tooltip" title="Interesting Subdomain">Interesting</span>`;
	const ip_spinner = `<span class="spinner-border spinner-border-sm me-1" id="ip-modal-loader"></span>`;
	const subdomain_spinner = `<span class="spinner-border spinner-border-sm me-1" id="subdomain-modal-loader"></span>`;

	$('#modal_dialog .modal-title').html('Details for Port: <b>' + port + '</b>');

	$('#modal_dialog .modal-text').empty();
	$('#modal-tabs').empty();


	$('#modal_dialog .modal-text').append(`<ul class='nav nav-tabs nav-bordered' id="modal_tab_nav"></ul><div id="modal_tab_content" class="tab-content"></div>`);

	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#modal_content_ip" aria-expanded="true"><span id="modal-ip-count"></span>IP Address&nbsp;${ip_spinner}</a></li>`);
	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#modal_content_subdomain" aria-expanded="false"><span id="modal-subdomain-count"></span>Subdomains&nbsp;${subdomain_spinner}</a></li>`);

	// add content area
	$('#modal_tab_content').append(`<div class="tab-pane show active" id="modal_content_ip"></div><div class="tab-pane" id="modal_content_subdomain"></div>`);

	$('#modal_content_ip').append(`<ul id="modal_ip_ul"></ul>`);
	$('#modal_content_subdomain').append(`<ul id="modal_subdomain_ul"></ul>`);

	$('#modal_dialog').modal('show');

	$.getJSON(ip_url, function(data) {
		$('#modal_ip_ul').empty();
		$('#modal_ip_ul').append(`<p>${data['ips'].length} IP Addresses have Port ${port} Open`);
		$('#modal-ip-count').html(`<b>${data['ips'].length}</b>&nbsp;&nbsp;`);
		let ip = '';
		let text_color = '';
		let li_id = '';
		let ip_array = [];
		for (ip in data['ips']){
			ip_array = data['ips'][ip];
			text_color = ip_array['is_cdn'] ? 'warning' : '';
			li_id = get_randid();
			$("#modal_ip_ul").append(`<li class='mt-1 text-${text_color}' id="${li_id}">${ip_array['address']}</li>`)
		}
		$('#modal_ip_ul').append(`<span class="float-end text-warning">*IP Address highlighted are CDN IP Address</span>`);
		$("#ip-modal-loader").remove();
	});

	// query subdomains
	$.getJSON(subdomain_url, function(data) {
		$('#modal_subdomain_ul').empty();
		$('#modal_subdomain_ul').append(`<p>${data['subdomains'].length} Subdomains have Port ${port} Open`);
		$('#modal-subdomain-count').html(`<b>${data['subdomains'].length}</b>&nbsp;&nbsp;`);
		let subdomain = '';
		let text_color = '';
		let li_id = '';
		let subdomain_array = [];
		for (subdomain in data['subdomains']){
			subdomain_array = data['subdomains'][subdomain];
			text_color = subdomain_array['http_status'] >= 400 ? 'danger' : '';
			li_id = get_randid();
			if (subdomain_array['http_url']) {
				$("#modal_subdomain_ul").append(`<li id="${li_id}" class="mt-1"><a href='${subdomain_array['http_url']}' target="_blank" class="text-${text_color}">${subdomain_array['name']}</a></li>`)
			}
			else {
				$("#modal_subdomain_ul").append(`<li class="mt-1 text-${text_color}" id="${li_id}">${subdomain_array['name']}</li>`);
			}

			if (subdomain_array['http_status']) {
				$("#"+li_id).append(get_http_badge(subdomain_array['http_status']));
				$('.bs-tooltip').tooltip();
			}

			if (subdomain_array['is_interesting']) {
				$("#"+li_id).append(interesting_badge)
			}

		}
		$("#modal_subdomain_ul").append(`<span class="float-end text-danger">*Subdomains highlighted are 40X HTTP Status</span>`);
		$("#subdomain-modal-loader").remove();
	});
}

function get_ip_details(endpoint_port_url, endpoint_subdomain_url, ip_address, scan_id=null, domain_id=null){
	let port_url = `${endpoint_port_url}?ip_address=${ip_address}`;
	let subdomain_url = `${endpoint_subdomain_url}?ip_address=${ip_address}`;

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

	const interesting_badge = `<span class="m-1 badge  badge-soft-danger bs-tooltip" title="Interesting Subdomain">Interesting</span>`;

	const port_loader = `<span class="inner-div spinner-border text-primary align-self-center loader-sm" id="port-modal-loader"></span>`;
	const subdomain_loader = `<span class="inner-div spinner-border text-primary align-self-center loader-sm" id="subdomain-modal-loader"></span>`;

	// add tab modal title
	$('#modal_dialog .modal-title').html('Details for IP: <b>' + ip_address + '</b>');

	$('#modal_dialog .modal-text').empty();
	$('#modal-tabs').empty();

	$('#modal_dialog .modal-text').append(`<ul class='nav nav-tabs nav-bordered' id="modal_tab_nav"></ul><div id="modal_tab_content" class="tab-content"></div>`);

	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#modal_content_port" aria-expanded="true"><span id="modal-open-ports-count"></span>Open Ports &nbsp;${port_loader}</a></li>`);
	$('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#modal_content_subdomain" aria-expanded="false"><span id="modal-subdomain-count"></span>Subdomains &nbsp;${subdomain_loader}</a></li>`);

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
		let port = '';
		let port_array = [];
		for (port in data['ports']){
			port_array = data['ports'][port];
			const badge_color = port_array['is_uncommon'] ? 'danger' : 'info';
			$("#modal_content_port").append(`<li class="mt-1">${port_array['description']} <b class="text-${badge_color}">(${port_array['number']}/${port_array['service_name']})</b></li>`)
		}
		$("#port-modal-loader").remove();
	});

	$('#modal_dialog').modal('show');

	// query subdomains
	$.getJSON(subdomain_url, function(data) {
		$('#modal_content_subdomain').empty();
		$('#modal_content_subdomain').append(`<p>${data['subdomains'].length} Subdomains are associated with IP ${ip_address}`);
		$('#modal-subdomain-count').html(`<b>${data['subdomains'].length}</b>&nbsp;&nbsp;`);
		let subdomain = '';
		let subdomain_array = [];
		for (subdomain in data['subdomains']){
			subdomain_array = data['subdomains'][subdomain];
			const badge_color = subdomain_array['http_status'] >= 400 ? 'danger' : '';
			const li_id = get_randid();
			if (subdomain_array['http_url']) {
				$("#modal_content_subdomain").append(`<li class="mt-1" id="${li_id}"><a href='${subdomain_array['http_url']}' target="_blank" class="text-${badge_color}">${subdomain_array['name']}</a></li>`)
			}
			else {
				$("#modal_content_subdomain").append(`<li class="mt-1 text-${badge_color}" id="${li_id}">${subdomain_array['name']}</li>`);
			}

			if (subdomain_array['http_status']) {
				$("#"+li_id).append(get_http_badge(subdomain_array['http_status']));
				$('.bs-tooltip').tooltip();
			}

			if (subdomain_array['is_interesting']) {
				$("#"+li_id).append(interesting_badge)
			}

		}
		$("#modal-text-subdomain").append(`<span class="float-end text-danger">*Subdomains highlighted are 40X HTTP Status</span>`);
		$("#subdomain-modal-loader").remove();
	});
}
