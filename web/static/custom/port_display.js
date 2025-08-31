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
                <a class="nav-link ${isActive}" data-bs-toggle="tab" href="#modal_content_${tab.id}" aria-expanded="${expanded}" data-tab-id="${tab.id}">
                    <span id="modal-${tab.id}-count"></span>${tab.label} &nbsp;${tab.loader}
                </a>
            </li>
        `);
        $('#modal_tab_content').append(`<div class="tab-pane ${isActive ? 'show active' : ''}" id="modal_content_${tab.id}"></div>`);
    });
    
    // Add event listener for subdomain tab clicks to load screenshots
    $('#modal_tab_nav').off('shown.bs.tab').on('shown.bs.tab', 'a[data-tab-id="subdomain"]', function() {
        // Trigger screenshot loading when subdomain tab is shown
        setTimeout(() => {
            const containerId = 'modal_content_subdomain';
            if (window.currentModalData) {
                const { port, scan_id, domain_id } = window.currentModalData;
                
                if (port !== undefined) {
                    // Port modal: use specific port
                    loadVisibleScreenshots(containerId, port, scan_id, domain_id);
                } else {
                    // IP modal: use ports 80, 443
                    loadVisibleScreenshotsForIP(containerId, scan_id, domain_id);
                }
            }
        }, 100);
    });
}

function createDataTable(containerId, columns, data, rowRenderer) {
    const tableId = `${containerId}-datatable`;
    const table = `
        <table id="${tableId}" class="table table-striped table-sm">
            <thead>
                <tr>
                    ${columns.map(col => `<th>${col}</th>`).join('')}
                </tr>
            </thead>
            <tbody>
                ${data.map(item => rowRenderer(item)).join('')}
            </tbody>
        </table>
    `;
    
    $(`#${containerId}`).html(table);
    
    // Initialize DataTable with configuration
    const dataTableConfig = {
        "oLanguage": {
            "oPaginate": {
                "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
                "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
            },
            "sInfo": "Showing page _PAGE_ of _PAGES_",
            "sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
            "sSearchPlaceholder": "Search...",
            "sLengthMenu": "Results : _MENU_"
        },
        "dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + 
               "<'table-responsive'tr>" + 
               "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count mb-sm-0 mb-3'i><'dt--pagination'p>>",
        "pageLength": 25,
        "lengthMenu": [10, 25, 50, 100],
        "order": [[0, "asc"]],
        "drawCallback": function() {
            // Add event delegation for screenshot thumbnails after each draw
            $(`#${containerId}`).off('click.screenshot').on('click.screenshot', '.screenshot-thumbnail', function() {
                const $this = $(this);
                const subdomainId = parseInt($this.data('subdomain-id')) || null;
                const subdomainName = $this.data('subdomain-name');
                const port = parseInt($this.data('port')) || null;
                const scanId = parseInt($this.data('scan-id')) || null;
                const domainId = parseInt($this.data('domain-id')) || null;
                
                show_port_screenshots(subdomainId, subdomainName, port, scanId, domainId);
            });
            
            // Use event delegation for hover events on screenshot thumbnails (if not disabled)
            $(`#${containerId}`).off('mouseenter.screenshot').on('mouseenter.screenshot', '.screenshot-thumbnail:not([data-disable-hover="true"])', function() {
                const $this = $(this);
                showScreenshotPreview(this, $this.data('screenshot-path'), $this.data('http-url'));
            });
            
            $(`#${containerId}`).off('mouseleave.screenshot').on('mouseleave.screenshot', '.screenshot-thumbnail:not([data-disable-hover="true"])', function() {
                hideScreenshotPreview();
            });
        }
    };
    
    // Destroy existing DataTable if it exists
    if ($.fn.DataTable.isDataTable(`#${tableId}`)) {
        $(`#${tableId}`).DataTable().destroy();
    }
    
    // Initialize DataTable
    $(`#${tableId}`).DataTable(dataTableConfig);
}

// Enhanced DataTable function with lazy screenshot loading
function createDataTableWithLazyScreenshots(containerId, columns, data, port, scan_id, domain_id, rowRenderer) {
    const tableId = `${containerId}-datatable`;
    const table = `
        <table id="${tableId}" class="table table-striped table-sm">
            <thead>
                <tr>
                    ${columns.map(col => `<th>${col}</th>`).join('')}
                </tr>
            </thead>
            <tbody>
                ${data.map(item => rowRenderer(item)).join('')}
            </tbody>
        </table>
    `;
    
    $(`#${containerId}`).html(table);
    
    // Initialize DataTable with lazy loading configuration
    const dataTableConfig = {
        "oLanguage": {
            "oPaginate": {
                "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
                "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
            },
            "sInfo": "Showing page _PAGE_ of _PAGES_",
            "sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
            "sSearchPlaceholder": "Search...",
            "sLengthMenu": "Results : _MENU_"
        },
        "dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + 
               "<'table-responsive'tr>" + 
               "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count mb-sm-0 mb-3'i><'dt--pagination'p>>",
        "pageLength": 25,
        "lengthMenu": [10, 25, 50, 100],
        "order": [[0, "asc"]],
        "initComplete": function() {
            // Add event delegation for screenshot thumbnails after initial load
            $(`#${containerId}`).off('click.screenshot').on('click.screenshot', '.screenshot-thumbnail', function() {
                const $this = $(this);
                const subdomainId = parseInt($this.data('subdomain-id')) || null;
                const subdomainName = $this.data('subdomain-name');
                const port = parseInt($this.data('port')) || null;
                const scanId = parseInt($this.data('scan-id')) || null;
                const domainId = parseInt($this.data('domain-id')) || null;
                
                show_port_screenshots(subdomainId, subdomainName, port, scanId, domainId);
            });
            
            // Use event delegation for hover events on screenshot thumbnails (if not disabled)
            $(`#${containerId}`).off('mouseenter.screenshot').on('mouseenter.screenshot', '.screenshot-thumbnail:not([data-disable-hover="true"])', function() {
                const $this = $(this);
                showScreenshotPreview(this, $this.data('screenshot-path'), $this.data('http-url'));
            });
            
            $(`#${containerId}`).off('mouseleave.screenshot').on('mouseleave.screenshot', '.screenshot-thumbnail:not([data-disable-hover="true"])', function() {
                hideScreenshotPreview();
            });
            

        },
        "drawCallback": function() {
            // Load screenshots only for visible rows on page change/search/sort
            loadVisibleScreenshots(containerId, port, scan_id, domain_id);
        }
    };
    
    // Destroy existing DataTable if it exists
    if ($.fn.DataTable.isDataTable(`#${tableId}`)) {
        $(`#${tableId}`).DataTable().destroy();
    }
    
    // Initialize DataTable
    $(`#${tableId}`).DataTable(dataTableConfig);
}

// Function to load screenshots only for visible rows
async function loadVisibleScreenshots(containerId, port, scan_id, domain_id) {
    const $visibleCells = $(`#${containerId} .screenshot-cell[data-loading="true"]:visible`);
    
    $visibleCells.each(async function() {
        const $cell = $(this);
        const $row = $cell.closest('tr');
        const subdomainId = $row.data('subdomain-id');
        const subdomainName = $row.data('subdomain-name');
        
        if (subdomainId && subdomainName) {
            try {
                // Remove loading indicator
                $cell.removeAttr('data-loading');
                
                // Load screenshot thumbnail
                const screenshots = await getScreenshotThumbnail(subdomainId, subdomainName, port, scan_id, domain_id, true);
                
                // Update cell content
                $cell.html(screenshots || '-');
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
    
    // If no scan_id but we have domain_id, try to get screenshots from any scan for this target
    if (!scan_id && domain_id) {
        try {
            const url = `/api/fetchScreenshots/?target_id=${domain_id}&subdomain_id=${subdomain_id}&port=${port}`;
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
        const url = `/api/fetchScreenshots/?scan_id=${scan_id}&subdomain_id=${subdomain_id}&port=${port}`;
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
        
        if (endpoint.screenshot_path && endpoint.port == port) {
            count++;
            if (count <= 2) { // Show max 2 thumbnails
                // Generate unique identifier using timestamp and random
                const timestamp = Date.now();
                const randomId = Math.random().toString(36).substr(2, 9);
                const screenshotImageId = `port-screenshot-${subdomain_id}-${port}-${timestamp}-${randomId}`;
                
                screenshotHtml += `
                    <img id="${screenshotImageId}"
                         src="/media/${escapeHtml(endpoint.screenshot_path)}" 
                         class="screenshot-thumbnail me-1" 
                         data-subdomain-id="${escapeHtml(subdomain_id || '')}"
                         data-subdomain-name="${escapeHtml(subdomain_name || '')}"
                         data-port="${escapeHtml(port || '')}"
                         data-scan-id="${escapeHtml(scan_id || '')}"
                         data-domain-id="${escapeHtml(domain_id || '')}"
                         data-screenshot-path="${escapeHtml(endpoint.screenshot_path)}"
                         data-http-url="${escapeHtml(endpoint.http_url || '')}"
                         data-disable-hover="${disableHoverPreview}"
                         title="Click to view full screenshot"
                         onerror="this.style.display='none'">
                `;
            }
        }
    }
    
    if (count > 2) {
        screenshotHtml += `<span class="badge badge-soft-info text-xs">+${count - 2}</span>`;
    }
    
    return screenshotHtml || '-';
}

// Helper function to create screenshot preview element
function createScreenshotPreviewElement(screenshotPath, httpUrl) {
    const preview = $('<div id="screenshot-preview" class="screenshot-preview"></div>');
    
    const $urlDiv = $('<div class="screenshot-preview-url"></div>').text(httpUrl);
    const $img = $('<img class="screenshot-preview-img">').attr('src', '/media/' + screenshotPath)
        .on('error', function() {
            $(this).parent().hide();
        });
    
    return preview.append($urlDiv).append($img);
}

// Function to show screenshot preview on hover
function showScreenshotPreview(element, screenshotPath, httpUrl) {
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
        
        preview = createScreenshotPreviewElement(screenshotPath, httpUrl).css('position', 'absolute');
        
        modalContent.append(preview);
        
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
        
        preview = createScreenshotPreviewElement(screenshotPath, httpUrl).css('position', 'fixed');
        
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

// Simple modal to display a single screenshot image when no subdomain/scan context is available
function showScreenshotImageModal(screenshotPath, httpUrl = '') {
    try {
        $('#xl-modal-title').empty();
        $('#xl-modal-content').empty();
        $('#xl-modal-footer').empty();

        // Create modal content using DOM manipulation to avoid XSS
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
            .attr('src', '/media/' + screenshotPath)
            .on('click', function() {
                window.open('/media/' + screenshotPath, '_blank');
            });
        $imgContainer.append($img);
        $content.append($imgContainer);

        $('#xl-modal-title').html('Screenshot');
        $('#xl-modal-content').html($content);
        $('#modal_xl_scroll_dialog').modal('show');
    } catch (e) {
        console.error('Error showing screenshot modal:', e);
        window.open('/media/' + screenshotPath, '_blank');
    }
}

function get_port_details(endpoint_ip_url, endpoint_subdomain_url, port, scan_id=null, domain_id=null) {
    // Store settings for use in subdomain rendering
    const settings = { scan_id: scan_id, domain_id: domain_id };
    
    // Store modal data globally for tab click events
    window.currentModalData = { port: port, scan_id: scan_id, domain_id: domain_id };
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
        $.getJSON(subdomain_url, async function(data) {
            $('#modal_content_subdomain').empty();
            const subdomains = data.subdomains || [];
            $('#modal-subdomain-count').html(`<b>${subdomains.length}</b>&nbsp;&nbsp;`);

            if (subdomains.length > 0) {
                $('#modal_content_subdomain').append(`<p>${subdomains.length} Subdomains have Port ${port} Open</p>`);
                
                // Create DataTable immediately without waiting for screenshots
                createDataTableWithLazyScreenshots('modal_content_subdomain',
                    ['Subdomain', 'Status', 'Title', 'Screenshots'],
                    subdomains,
                    port, scan_id, domain_id,
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
                            <tr data-subdomain-id="${subdomain.id}" data-subdomain-name="${subdomain.name}">
                                <td>${subdomain_link}</td>
                                <td>${status_tags || '-'}</td>
                                <td>${subdomain.page_title ? htmlEncode(subdomain.page_title) : '-'}</td>
                                <td class="screenshot-cell" data-loading="true">
                                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                                    Loading...
                                </td>
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
    // Store settings for use in subdomain rendering
    const settings = { scan_id: scan_id, domain_id: domain_id };
    
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

        // Get associated subdomains
    $.getJSON(subdomain_url, async function(data) {
            $('#modal_content_subdomain').empty();
            const subdomains = data.subdomains || [];
            $('#modal-subdomain-count').html(`<b>${subdomains.length}</b>&nbsp;&nbsp;`);

            if (subdomains.length > 0) {
                $('#modal_content_subdomain').append(`<p>${subdomains.length} subdomains are associated with IP ${ip_address}</p>`);
            
                // Create DataTable immediately without waiting for screenshots (IP modal uses ports 80,443)
                createDataTableWithLazyScreenshotsForIP('modal_content_subdomain',
                    ['Subdomain', 'Status', 'Title', 'Screenshots'],
                    subdomains,
                    scan_id, domain_id,
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
                            <tr data-subdomain-id="${subdomain.id}" data-subdomain-name="${subdomain.name}">
                                <td>${subdomain_link}</td>
                                <td>${status_tags || '-'}</td>
                                <td>${subdomain.page_title ? htmlEncode(subdomain.page_title) : '-'}</td>
                                <td class="screenshot-cell" data-loading="true">
                                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                                    Loading...
                                </td>
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
}

// Specialized DataTable function for IP details with lazy loading of screenshots for ports 80,443
function createDataTableWithLazyScreenshotsForIP(containerId, columns, data, scan_id, domain_id, rowRenderer) {
    const tableId = `${containerId}-datatable`;
    const table = `
        <table id="${tableId}" class="table table-striped table-sm">
            <thead>
                <tr>
                    ${columns.map(col => `<th>${col}</th>`).join('')}
                </tr>
            </thead>
            <tbody>
                ${data.map(item => rowRenderer(item)).join('')}
            </tbody>
        </table>
    `;
    
    $(`#${containerId}`).html(table);
    
    // Initialize DataTable with lazy loading configuration
    const dataTableConfig = {
        "oLanguage": {
            "oPaginate": {
                "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>',
                "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>'
            },
            "sInfo": "Showing page _PAGE_ of _PAGES_",
            "sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
            "sSearchPlaceholder": "Search...",
            "sLengthMenu": "Results : _MENU_"
        },
        "dom": "<'dt--top-section'<'row'<'col-12 col-sm-6 d-flex justify-content-sm-start justify-content-center'f><'col-12 col-sm-6 d-flex justify-content-sm-end justify-content-center'l>>>" + 
               "<'table-responsive'tr>" + 
               "<'dt--bottom-section d-sm-flex justify-content-sm-between text-center'<'dt--pages-count mb-sm-0 mb-3'i><'dt--pagination'p>>",
        "pageLength": 25,
        "lengthMenu": [10, 25, 50, 100],
        "order": [[0, "asc"]],
        "initComplete": function() {
            // Add event delegation for screenshot thumbnails after initial load
            $(`#${containerId}`).off('click.screenshot').on('click.screenshot', '.screenshot-thumbnail', function() {
                const $this = $(this);
                const subdomainId = parseInt($this.data('subdomain-id')) || null;
                const subdomainName = $this.data('subdomain-name');
                const port = parseInt($this.data('port')) || null;
                const scanId = parseInt($this.data('scan-id')) || null;
                const domainId = parseInt($this.data('domain-id')) || null;
                
                show_port_screenshots(subdomainId, subdomainName, port, scanId, domainId);
            });
            
            // Use event delegation for hover events on screenshot thumbnails (if not disabled)
            $(`#${containerId}`).off('mouseenter.screenshot').on('mouseenter.screenshot', '.screenshot-thumbnail:not([data-disable-hover="true"])', function() {
                const $this = $(this);
                showScreenshotPreview(this, $this.data('screenshot-path'), $this.data('http-url'));
            });
            
            $(`#${containerId}`).off('mouseleave.screenshot').on('mouseleave.screenshot', '.screenshot-thumbnail:not([data-disable-hover="true"])', function() {
                hideScreenshotPreview();
            });
            

        },
        "drawCallback": function() {
            // Load screenshots for common web ports (80, 443) only for visible rows on page change/search/sort
            loadVisibleScreenshotsForIP(containerId, scan_id, domain_id);
        }
    };
    
    // Destroy existing DataTable if it exists
    if ($.fn.DataTable.isDataTable(`#${tableId}`)) {
        $(`#${tableId}`).DataTable().destroy();
    }
    
    // Initialize DataTable
    $(`#${tableId}`).DataTable(dataTableConfig);
}

// Function to load screenshots for common web ports (80, 443) only for visible rows
async function loadVisibleScreenshotsForIP(containerId, scan_id, domain_id) {
    const $visibleCells = $(`#${containerId} .screenshot-cell[data-loading="true"]:visible`);
    
    $visibleCells.each(async function() {
        const $cell = $(this);
        const $row = $cell.closest('tr');
        const subdomainId = $row.data('subdomain-id');
        const subdomainName = $row.data('subdomain-name');
        
        if (subdomainId && subdomainName) {
            try {
                // Remove loading indicator
                $cell.removeAttr('data-loading');
                
                let combinedScreenshots = '';
                
                // Get screenshots for common web ports (80, 443)
                if (scan_id) {
                    const httpsScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 443, scan_id, domain_id, true);
                    const httpScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 80, scan_id, domain_id, true);
                    
                    if (httpsScreenshots !== '-') {
                        combinedScreenshots += httpsScreenshots;
                    }
                    if (httpScreenshots !== '-') {
                        combinedScreenshots += httpScreenshots;
                    }
                } else if (domain_id) {
                    // Try to get screenshots using domain_id when scan_id is null
                    const httpsScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 443, null, domain_id, true);
                    const httpScreenshots = await getScreenshotThumbnail(subdomainId, subdomainName, 80, null, domain_id, true);
                    
                    if (httpsScreenshots !== '-') {
                        combinedScreenshots += httpsScreenshots;
                    }
                    if (httpScreenshots !== '-') {
                        combinedScreenshots += httpScreenshots;
                    }
                }
                
                // Update cell content
                $cell.html(combinedScreenshots || '-');
            } catch (error) {
                console.error('Error loading screenshots for subdomain:', subdomainName, error);
                $cell.html('-');
            }
        }
    });
}
