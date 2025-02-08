function renderBadge(data, settings) {
    let badge = '';
    
    try {
        const data_obj = typeof data === 'string' 
            ? JSON.parse(new DOMParser().parseFromString(data, "text/html").documentElement.textContent)
            : data;

        for (const item of data_obj) {
            const items = item.ports || [item]; // Use ports array for ports, or wrap single item for IPs
            
            for (const element of items) {
                const is_ip = !element.number; // If no port number, it's an IP
                const badge_color = is_ip 
                    ? (element.is_cdn ? 'warning' : 'primary')
                    : (element.is_uncommon ? 'danger' : 'primary');
                
                let title = is_ip 
                    ? (element.is_cdn ? 'CDN IP Address' : 'IP Address')
                    : `Port ${element.number}`;
                
                if (element.description) {
                    title += ` - ${element.description}`;
                }
                if (element.subdomain_count) {
                    title += `\nFound on ${element.subdomain_count} subdomain${element.subdomain_count > 1 ? 's' : ''}`;
                }
                
                let onclick = is_ip
                    ? `get_ip_details('${settings.api_ports_url}', '${settings.api_subdomains_url}', '${element.address}', ${settings.scan_id}, ${settings.domain_id})`
                    : `get_port_details('${settings.api_ips_url}', '${settings.api_subdomains_url}', ${element.number}, ${settings.scan_id}, ${settings.domain_id})`;
                
                const display_text = is_ip 
                    ? element.address
                    : `${element.number}/${element.service_name}`;
                
                badge += `<span class='m-1 badge badge-soft-${badge_color} bs-tooltip badge-link' 
                    title='${title}' 
                    onclick="${onclick}">
                    ${display_text}
                    ${element.subdomain_count ? `<span class="badge bg-${badge_color} ms-1">${element.subdomain_count}</span>` : ''}
                </span>`;
            }
        }
    } catch (e) {
        console.error('Error rendering badge:', e);
        return '';
    }
    
    return badge;
}

function get_ips(ip_addresses, port_url, endpoint_subdomains, scan_id=null, domain_id=null) {
    try {
        const decoded = new DOMParser().parseFromString(ip_addresses, "text/html").documentElement.textContent;
        const data = JSON.parse(decoded);
        
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

function get_ports(ip_addresses, ip_url, subdomain_url, scan_id=null, domain_id=null) {
    try {
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
        $('#ports').html(renderBadge(
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

function get_ip_details(endpoint_ip_url, endpoint_subdomain_url, ip_address, scan_id=null, domain_id=null){
    let ip_url = `${endpoint_ip_url}?ip_address=${ip_address}`;
    let subdomain_url = `${endpoint_subdomain_url}?ip_address=${ip_address}`;

    if (scan_id) {
        ip_url += `&scan_id=${scan_id}`;
        subdomain_url += `&scan_id=${scan_id}`;
    }
    else if(domain_id){
        ip_url += `&target_id=${domain_id}`;
        subdomain_url += `&target_id=${domain_id}`;
    }

    const interesting_badge = `<span class="m-1 badge badge-soft-danger bs-tooltip" title="Interesting Subdomain">Interesting</span>`;
    const port_loader = `<span class="inner-div spinner-border text-primary align-self-center loader-sm" id="port-modal-loader"></span>`;
    const subdomain_loader = `<span class="inner-div spinner-border text-primary align-self-center loader-sm" id="subdomain-modal-loader"></span>`;

    // Setup modal
    $('#modal_dialog .modal-title').html('Details for IP: <b>' + ip_address + '</b>');
    $('#modal_dialog .modal-text').empty();
    $('#modal-tabs').empty();
    $('#modal_dialog .modal-text').append(`<ul class='nav nav-tabs nav-bordered' id="modal_tab_nav"></ul><div id="modal_tab_content" class="tab-content"></div>`);

    $('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#modal_content_port" aria-expanded="true"><span id="modal-open-ports-count"></span>Open Ports &nbsp;${port_loader}</a></li>`);
    $('#modal_tab_nav').append(`<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#modal_content_subdomain" aria-expanded="false"><span id="modal-subdomain-count"></span>Subdomains &nbsp;${subdomain_loader}</a></li>`);

    $('#modal_tab_content').empty();
    $('#modal_tab_content').append(`<div class="tab-pane show active" id="modal_content_port"></div><div class="tab-pane" id="modal_content_subdomain"></div>`);

    // Get IP details including ports
    $.getJSON(ip_url, function(data) {
        $('#modal_content_port').empty();
        const ports = data.ports || [];
        $('#modal_content_port').append(`<p>IP Address ${ip_address} has ${ports.length} Open Ports</p>`);
        $('#modal-open-ports-count').html(`<b>${ports.length}</b>&nbsp;&nbsp;`);
        
        ports.forEach(port => {
            const badge_color = port.is_uncommon ? 'danger' : 'info';
            $("#modal_content_port").append(
                `<li class="mt-1">${port.description} <b class="text-${badge_color}">(${port.number}/${port.service_name})</b></li>`
            );
        });
        $("#port-modal-loader").remove();
    });

    // Get associated subdomains
    $.getJSON(subdomain_url, function(data) {
        $('#modal_content_subdomain').empty();
        const subdomains = data.subdomains || [];
        $('#modal_content_subdomain').append(`<p>${subdomains.length} Subdomains are associated with IP ${ip_address}</p>`);
        $('#modal-subdomain-count').html(`<b>${subdomains.length}</b>&nbsp;&nbsp;`);

        subdomains.forEach(subdomain => {
            const badge_color = subdomain.http_status >= 400 ? 'danger' : '';
            const li_id = get_randid();
            const subdomain_link = subdomain.http_url 
                ? `<a href='${subdomain.http_url}' target="_blank" class="text-${badge_color}">${subdomain.name}</a>`
                : `<span class="text-${badge_color}">${subdomain.name}</span>`;

            $("#modal_content_subdomain").append(`<li class="mt-1" id="${li_id}">${subdomain_link}</li>`);

            if (subdomain.http_status) {
                $(`#${li_id}`).append(get_http_badge(subdomain.http_status));
            }
            if (subdomain.is_interesting) {
                $(`#${li_id}`).append(interesting_badge);
            }
        });

        $("#modal_content_subdomain").append(`<span class="float-end text-danger">*Subdomains highlighted are 40X HTTP Status</span>`);
        $("#subdomain-modal-loader").remove();
    });

    $('#modal_dialog').modal('show');
}
