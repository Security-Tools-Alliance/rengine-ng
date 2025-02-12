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
                    // Add list of subdomain names if available
                    if (element.subdomain_names) {
                        title += ':\n• ' + element.subdomain_names.join('\n• ');
                    }
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
        return badge;
    } catch (e) {
        console.error('Error rendering badge:', e);
        return '';
    }
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

function setupModal(title, tabs) {
    $('#modal_dialog .modal-title').html(title);
    $('#modal_dialog .modal-text').empty();
    $('#modal-tabs').empty();
    $('#modal_dialog .modal-text').append(`<ul class='nav nav-tabs nav-bordered' id="modal_tab_nav"></ul><div id="modal_tab_content" class="tab-content"></div>`);

    tabs.forEach((tab, index) => {
        const isActive = index === 0 ? 'active' : '';
        const expanded = index === 0 ? 'true' : 'false';
        $('#modal_tab_nav').append(`
            <li class="nav-item">
                <a class="nav-link ${isActive}" data-bs-toggle="tab" href="#modal_content_${tab.id}" aria-expanded="${expanded}">
                    <span id="modal-${tab.id}-count"></span>${tab.label} &nbsp;${tab.loader}
                </a>
            </li>
        `);
        $('#modal_tab_content').append(`<div class="tab-pane ${isActive ? 'show active' : ''}" id="modal_content_${tab.id}"></div>`);
    });
}

function createDataTable(containerId, columns, data, rowRenderer) {
    const table = `
        <table class="table table-striped table-sm">
            <thead>
                <tr>
                    ${columns.map(col => `<th>${col}</th>`).join('')}
                </tr>
            </thead>
            <tbody id="${containerId}-table-body">
            </tbody>
        </table>
    `;
    
    $(`#${containerId}`).append(table);
    data.forEach(item => {
        $(`#${containerId}-table-body`).append(rowRenderer(item));
    });
}

function get_port_details(endpoint_ip_url, endpoint_subdomain_url, port, scan_id=null, domain_id=null) {
    $.getJSON('/api/uncommon-web-ports/', function(portsData) {
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
            ]
        );

        // Get IPs
        $.getJSON(ip_url, function(data) {
            $('#modal_content_ip').empty();
            const ips = data.ips || [];
            $('#modal-ip-count').html(`<b>${ips.length}</b>&nbsp;&nbsp;`);

            if (ips.length > 0) {
                $('#modal_content_ip').append(`<p>${ips.length} IP Addresses have Port ${port} Open</p>`);
                createDataTable('modal_content_ip', 
                    ['IP Address', 'HTTP', 'HTTPS', 'Tags'], 
                    ips,
                    (ip) => {
                        const badge_color = ip.is_cdn ? 'warning' : 'primary';
                        const tags = ip.is_cdn ? '<span class="badge badge-soft-warning">CDN</span>' : '';
                        
                        const isWebPort = webPorts.includes(parseInt(port));
                        const httpLink = isWebPort ? 
                            `<a href="http://${ip.address}:${port}" target="_blank" class="badge badge-soft-primary">HTTP</a>` : 
                            '-';
                        const httpsLink = isWebPort ? 
                            `<a href="https://${ip.address}:${port}" target="_blank" class="badge badge-soft-primary">HTTPS</a>` : 
                            '-';

                        return `
                            <tr>
                                <td><span class="text-${badge_color}">${ip.address}</span></td>
                                <td>${httpLink}</td>
                                <td>${httpsLink}</td>
                                <td>${tags}</td>
                            </tr>
                        `;
                    }
                );
            } else {
                $('#modal_content_ip').append("<p>No IP addresses found</p>");
            }
            $("#ip-modal-loader").remove();
        });

        // Get Subdomains
        $.getJSON(subdomain_url, function(data) {
            $('#modal_content_subdomain').empty();
            const subdomains = data.subdomains || [];
            $('#modal-subdomain-count').html(`<b>${subdomains.length}</b>&nbsp;&nbsp;`);

            if (subdomains.length > 0) {
                $('#modal_content_subdomain').append(`<p>${subdomains.length} Subdomains have Port ${port} Open</p>`);
                createDataTable('modal_content_subdomain',
                    ['Subdomain', 'Status', 'Title'],
                    subdomains,
                    (subdomain) => {
                        const badge_color = subdomain.http_status >= 400 ? 'danger' : '';
                        const isWebPort = webPorts.includes(parseInt(port));
                        
                        let subdomain_url = subdomain.http_url;
                        if (isWebPort && subdomain_url) {
                            const url = new URL(subdomain_url);
                            url.port = port;
                            subdomain_url = url.toString();
                        }
                        
                        const subdomain_link = subdomain_url 
                            ? `<a href='${subdomain_url}' target="_blank" class="text-${badge_color}">${subdomain.name}</a>`
                            : `<span class="text-${badge_color}">${subdomain.name}</span>`;

                        let status_tags = '';
                        if (subdomain.http_status) {
                            status_tags += get_http_badge(subdomain.http_status);
                        }
                        if (subdomain.is_interesting) {
                            status_tags += '<span class="badge badge-soft-danger ms-1">Interesting</span>';
                        }

                        return `
                            <tr>
                                <td>${subdomain_link}</td>
                                <td>${status_tags || '-'}</td>
                                <td>${subdomain.page_title ? htmlEncode(subdomain.page_title) : '-'}</td>
                            </tr>
                        `;
                    }
                );
            } else {
                $('#modal_content_subdomain').append("<p>No subdomains found</p>");
            }
            $("#subdomain-modal-loader").remove();
        });

        $('#modal_dialog').modal('show');
    });
}

function get_ip_details(endpoint_ip_url, endpoint_subdomain_url, ip_address, scan_id=null, domain_id=null){
    $.getJSON('/api/uncommon-web-ports/', function(portsData) {
        const webPorts = [...portsData.uncommon_web_ports, ...portsData.common_web_ports];
        
        let ip_url = `${endpoint_ip_url}?ip_address=${ip_address}`;
        let subdomain_url = `${endpoint_subdomain_url}?ip_address=${ip_address}`;

        if (scan_id) {
            ip_url += `&scan_id=${scan_id}`;
            subdomain_url += `&scan_id=${scan_id}`;
        } else if(domain_id) {
            ip_url += `&target_id=${domain_id}`;
            subdomain_url += `&target_id=${domain_id}`;
        }

        const loaders = {
            port: `<span class="spinner-border spinner-border-sm me-1" id="port-modal-loader"></span>`,
            subdomain: `<span class="spinner-border spinner-border-sm me-1" id="subdomain-modal-loader"></span>`
        };

        setupModal(
            `Details for IP: <b>${ip_address}</b>`,
            [
                { id: 'port', label: 'Open Ports', loader: loaders.port },
                { id: 'subdomain', label: 'Subdomains', loader: loaders.subdomain }
            ]
        );

        // Get IP details including ports
        $.getJSON(ip_url, function(data) {
            $('#modal_content_port').empty();
            const ports = data.ports || [];
            $('#modal-port-count').html(`<b>${ports.length}</b>&nbsp;&nbsp;`);
            
            if (ports.length > 0) {
                $('#modal_content_port').append(`<p>IP Address ${ip_address} has ${ports.length} Open Ports</p>`);
                createDataTable('modal_content_port',
                    ['Port', 'Service', 'Description', 'HTTP', 'HTTPS', 'Tags'],
                    ports,
                    (port) => {
                        const badge_color = port.is_uncommon ? 'danger' : 'primary';
                        const tags = port.is_uncommon 
                            ? `<span class="badge badge-soft-danger">Uncommon</span>` 
                            : '';
                        
                        const isWebPort = webPorts.includes(port.number);
                        const httpLink = isWebPort ? 
                            `<a href="http://${ip_address}:${port.number}" target="_blank" class="badge badge-soft-primary">HTTP</a>` : 
                            '-';
                        const httpsLink = isWebPort ? 
                            `<a href="https://${ip_address}:${port.number}" target="_blank" class="badge badge-soft-primary">HTTPS</a>` : 
                            '-';
                        
                        return `
                            <tr>
                                <td><b class="text-${badge_color}">${port.number}</b></td>
                                <td>${port.service_name}</td>
                                <td>${port.description || '-'}</td>
                                <td>${httpLink}</td>
                                <td>${httpsLink}</td>
                                <td>${tags}</td>
                            </tr>
                        `;
                    }
                );
            } else {
                $('#modal_content_port').append("<p>No open ports found</p>");
            }
            $("#port-modal-loader").remove();
        });

        // Get associated subdomains
        $.getJSON(subdomain_url, function(data) {
            $('#modal_content_subdomain').empty();
            const subdomains = data.subdomains || [];
            $('#modal-subdomain-count').html(`<b>${subdomains.length}</b>&nbsp;&nbsp;`);

            if (subdomains.length > 0) {
                $('#modal_content_subdomain').append(`<p>${subdomains.length} subdomains are associated with IP ${ip_address}</p>`);
                createDataTable('modal_content_subdomain',
                    ['Subdomain', 'Status', 'Title'],
                    subdomains,
                    (subdomain) => {
                        const badge_color = subdomain.http_status >= 400 ? 'danger' : '';
                        const subdomain_link = subdomain.http_url 
                            ? `<a href='${subdomain.http_url}' target="_blank" class="text-${badge_color}">${subdomain.name}</a>`
                            : `<span class="text-${badge_color}">${subdomain.name}</span>`;

                        let status_tags = '';
                        if (subdomain.http_status) {
                            status_tags += get_http_badge(subdomain.http_status);
                        }
                        if (subdomain.is_interesting) {
                            status_tags += '<span class="badge badge-soft-danger ms-1">Interesting</span>';
                        }

                        return `
                            <tr>
                                <td>${subdomain_link}</td>
                                <td>${status_tags || '-'}</td>
                                <td>${subdomain.page_title ? htmlEncode(subdomain.page_title) : '-'}</td>
                            </tr>
                        `;
                    }
                );
            } else {
                $('#modal_content_subdomain').append("<p>No subdomains found</p>");
            }
            $("#subdomain-modal-loader").remove();
        });

        $('#modal_dialog').modal('show');
    });
}
