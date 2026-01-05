/**
 * WebSocket client for real-time scan status updates.
 * Handles connections and updates for history.html, detail_scan.html, and right_bar.html
 */

// Prevent redeclaration if script is loaded multiple times
(function() {
    'use strict';
    
    // Check if already initialized
    if (window.scanStatusWebSocketInitialized) {
        return;
    }
    window.scanStatusWebSocketInitialized = true;
    
    const scanStatusWebSockets = {};
    const scanStatusReconnectAttempts = {};
    const scanStatusReconnectTimeouts = {};
    const scanStatusOptions = {}; // Store options for each connection to share handlers
    const scanStatusConnecting = {}; // Track connections being established to prevent duplicates
    const MAX_RECONNECT_ATTEMPTS = 10;
    const INITIAL_RECONNECT_DELAY = 1000; // 1 second

/**
 * Connect to scan status WebSocket
 * @param {number|null} scanId - Specific scan ID, or null for project-level
 * @param {string|null} projectSlug - Project slug for project-level updates
 * @param {object} options - Options for update handlers
 * @param {function} options.updateTable - Function to update DataTable (for history.html)
 * @param {function} options.updateDetail - Function to update detail page (for detail_scan.html)
 * @param {function} options.updateSidebar - Function to update sidebar (for right_bar.html)
 * @param {string} options.scanStatusUrl - URL for scan status API endpoint
 * @param {string} options.stopScanUrl - URL for stop scan API endpoint
 * @param {string} options.stopActivityUrl - URL for stop activity API endpoint
 * @param {string} options.fetchSubscanUrl - URL for fetch subscan results API endpoint
 */
const connectScanStatusWebSocket = function(scanId, projectSlug, options) {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let wsUrl;
    let key;
    
    if (scanId) {
        wsUrl = wsProtocol + '//' + window.location.host + '/ws/scan-status/' + scanId + '/';
        key = 'scan-' + scanId;
    } else if (projectSlug) {
        wsUrl = wsProtocol + '//' + window.location.host + '/ws/scan-status/project/' + projectSlug + '/';
        key = 'project-' + projectSlug;
    } else {
        console.error('scan_status_websocket: scanId or projectSlug must be provided');
        return;
    }
    
    // Check if connection already exists and is open or connecting
    const existingSocket = scanStatusWebSockets[key];
    if (existingSocket) {
        const readyState = existingSocket.readyState;
        // WebSocket.CONNECTING = 0, WebSocket.OPEN = 1, WebSocket.CLOSING = 2, WebSocket.CLOSED = 3
        if (readyState === WebSocket.OPEN) {
            // Merge options with existing connection
            if (options) {
                if (!scanStatusOptions[key]) {
                    scanStatusOptions[key] = {};
                }
                // Merge update handlers
                if (options.updateTable && !scanStatusOptions[key].updateTable) {
                    scanStatusOptions[key].updateTable = options.updateTable;
                }
                if (options.updateDetail && !scanStatusOptions[key].updateDetail) {
                    scanStatusOptions[key].updateDetail = options.updateDetail;
                }
                if (options.updateSidebar && !scanStatusOptions[key].updateSidebar) {
                    scanStatusOptions[key].updateSidebar = options.updateSidebar;
                }
                // Store API URLs if provided
                if (options.scanStatusUrl) {
                    scanStatusOptions[key].scanStatusUrl = options.scanStatusUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.scanStatusUrl = options.scanStatusUrl;
                }
                if (options.stopScanUrl) {
                    scanStatusOptions[key].stopScanUrl = options.stopScanUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.stopScanUrl = options.stopScanUrl;
                }
                if (options.stopActivityUrl) {
                    scanStatusOptions[key].stopActivityUrl = options.stopActivityUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.stopActivityUrl = options.stopActivityUrl;
                }
                if (options.fetchSubscanUrl) {
                    scanStatusOptions[key].fetchSubscanUrl = options.fetchSubscanUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.fetchSubscanUrl = options.fetchSubscanUrl;
                }
            }
            return;
        } else if (readyState === WebSocket.CONNECTING) {
            // Connection is being established, merge options and wait for it to open
            if (options) {
                if (!scanStatusOptions[key]) {
                    scanStatusOptions[key] = {};
                }
                // Merge update handlers
                if (options.updateTable && !scanStatusOptions[key].updateTable) {
                    scanStatusOptions[key].updateTable = options.updateTable;
                }
                if (options.updateDetail && !scanStatusOptions[key].updateDetail) {
                    scanStatusOptions[key].updateDetail = options.updateDetail;
                }
                if (options.updateSidebar && !scanStatusOptions[key].updateSidebar) {
                    scanStatusOptions[key].updateSidebar = options.updateSidebar;
                }
                // Store API URLs if provided
                if (options.scanStatusUrl) {
                    scanStatusOptions[key].scanStatusUrl = options.scanStatusUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.scanStatusUrl = options.scanStatusUrl;
                }
                if (options.stopScanUrl) {
                    scanStatusOptions[key].stopScanUrl = options.stopScanUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.stopScanUrl = options.stopScanUrl;
                }
                if (options.stopActivityUrl) {
                    scanStatusOptions[key].stopActivityUrl = options.stopActivityUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.stopActivityUrl = options.stopActivityUrl;
                }
                if (options.fetchSubscanUrl) {
                    scanStatusOptions[key].fetchSubscanUrl = options.fetchSubscanUrl;
                    if (!window.scanStatusApiUrls) {
                        window.scanStatusApiUrls = {};
                    }
                    window.scanStatusApiUrls.fetchSubscanUrl = options.fetchSubscanUrl;
                }
            }
            return;
        } else {
            // Connection is CLOSING or CLOSED, close it properly
            existingSocket.close();
            scanStatusWebSockets[key] = null;
        }
    }
    
    // Check if a connection is being established (race condition protection)
    if (scanStatusConnecting[key]) {
        // Merge options and return
        if (options) {
            if (!scanStatusOptions[key]) {
                scanStatusOptions[key] = {};
            }
            if (options.updateTable && !scanStatusOptions[key].updateTable) {
                scanStatusOptions[key].updateTable = options.updateTable;
            }
            if (options.updateDetail && !scanStatusOptions[key].updateDetail) {
                scanStatusOptions[key].updateDetail = options.updateDetail;
            }
            if (options.updateSidebar && !scanStatusOptions[key].updateSidebar) {
                scanStatusOptions[key].updateSidebar = options.updateSidebar;
            }
            // Store API URLs if provided
            if (options.scanStatusUrl) {
                scanStatusOptions[key].scanStatusUrl = options.scanStatusUrl;
            }
            if (options.stopScanUrl) {
                scanStatusOptions[key].stopScanUrl = options.stopScanUrl;
            }
            if (options.stopActivityUrl) {
                scanStatusOptions[key].stopActivityUrl = options.stopActivityUrl;
            }
            if (options.fetchSubscanUrl) {
                scanStatusOptions[key].fetchSubscanUrl = options.fetchSubscanUrl;
            }
        }
        return;
    }
    
    // Mark that we're connecting
    scanStatusConnecting[key] = true;
    
    // Store options for this connection
    scanStatusOptions[key] = options || {};
    
    // Store API URLs in global object for use by updateRightSidebar
    if (options && (options.scanStatusUrl || options.stopScanUrl || options.stopActivityUrl || options.fetchSubscanUrl)) {
        if (!window.scanStatusApiUrls) {
            window.scanStatusApiUrls = {};
        }
        if (options.scanStatusUrl) {
            window.scanStatusApiUrls.scanStatusUrl = options.scanStatusUrl;
        }
        if (options.stopScanUrl) {
            window.scanStatusApiUrls.stopScanUrl = options.stopScanUrl;
        }
        if (options.stopActivityUrl) {
            window.scanStatusApiUrls.stopActivityUrl = options.stopActivityUrl;
        }
        if (options.fetchSubscanUrl) {
            window.scanStatusApiUrls.fetchSubscanUrl = options.fetchSubscanUrl;
        }
    }
    
    try {
        const socket = new WebSocket(wsUrl);
        scanStatusWebSockets[key] = socket;
        scanStatusReconnectAttempts[key] = 0;
        
        socket.onopen = function(event) {
            scanStatusReconnectAttempts[key] = 0;
            // Clear connecting flag
            scanStatusConnecting[key] = false;
        };
        
        socket.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                // Use stored options for this connection
                handleScanStatusUpdate(data, scanStatusOptions[key]);
            } catch (e) {
                console.error('Error parsing WebSocket message:', e);
            }
        };
        
        socket.onclose = function(event) {
            scanStatusWebSockets[key] = null;
            // Clear connecting flag
            scanStatusConnecting[key] = false;
            
            // Attempt to reconnect if not a normal closure
            if (event.code !== 1000 && scanStatusReconnectAttempts[key] < MAX_RECONNECT_ATTEMPTS) {
                const delay = INITIAL_RECONNECT_DELAY * Math.pow(2, scanStatusReconnectAttempts[key]);
                scanStatusReconnectAttempts[key]++;
                
                scanStatusReconnectTimeouts[key] = setTimeout(function() {
                    connectScanStatusWebSocket(scanId, projectSlug, scanStatusOptions[key]);
                }, delay);
            } else {
                // Clean up options if connection is permanently closed
                delete scanStatusOptions[key];
                delete scanStatusConnecting[key];
            }
        };
        
        socket.onerror = function(error) {
            console.error('Scan status WebSocket error for', key + ':', error);
            // Clear connecting flag on error
            scanStatusConnecting[key] = false;
        };
    } catch (e) {
        console.error('Error creating scan status WebSocket for', key + ':', e);
        // Clear connecting flag on exception
        scanStatusConnecting[key] = false;
    }
};

/**
 * Handle scan status update from WebSocket
 * @param {object} data - Update data from WebSocket
 * @param {object} options - Update handler options
 */
const handleScanStatusUpdate = function(data, options) {
    if (!data || !data.scan_id) {
        return;
    }
    
    // Always update the right sidebar if it exists (for real-time updates)
    // This ensures the sidebar updates even when not explicitly requested
    updateRightSidebar(data);
    
    // Route to appropriate update function based on options
    if (options) {
        if (options.updateTable && typeof options.updateTable === 'function') {
            // Call the provided update function
            options.updateTable(data);
        } else if (options.updateTable && options.table) {
            // Direct table reference
            updateScanRowInTable(options.table, data);
        }
        
        if (options.updateDetail && typeof options.updateDetail === 'function') {
            // Call the provided update function
            options.updateDetail(data);
        } else if (options.updateDetail === true) {
            // Auto-update detail page
            updateScanDetailPage(data);
        }
        
        if (options.updateSidebar && typeof options.updateSidebar === 'function') {
            // Call the provided update function
            options.updateSidebar(data);
        } else if (options.updateSidebar === true) {
            // Auto-update sidebar (already done above, but keep for explicit requests)
            updateRightSidebar(data);
        }
    }
};

/**
 * Update a row in DataTable (for history.html)
 * @param {DataTable} table - DataTable instance
 * @param {object} data - Update data
 */
const updateScanRowInTable = function(table, data) {
    if (!table || !data || !data.scan_id) {
        return;
    }
    
    try {
        // Find the row directly in the DOM by data-scan-id attribute
        const rowNode = document.querySelector('tr[data-scan-id="' + data.scan_id + '"]');
        
        if (!rowNode) {
            // Row not found, might be a new scan that's not yet in the table
            // Check if table is in AJAX mode by checking if ajax.reload exists
            if (table && typeof table.ajax === 'function' && typeof table.ajax.reload === 'function') {
                // Use DataTables ajax.reload() method - simple and efficient
                // Use a debounce mechanism to avoid multiple reloads
                if (!window._scanTableReloadTimeout) {
                    window._scanTableReloadTimeout = {};
                }
                const timeoutKey = 'table_reload';
                if (window._scanTableReloadTimeout[timeoutKey]) {
                    clearTimeout(window._scanTableReloadTimeout[timeoutKey]);
                }
                window._scanTableReloadTimeout[timeoutKey] = setTimeout(function() {
                    table.ajax.reload(null, false); // false = don't reset paging
                    delete window._scanTableReloadTimeout[timeoutKey];
                }, 500); // Short delay to ensure scan is in DB
            } else {
                // For non-AJAX tables, reload the page after a short delay to show new scans
                // Use a debounce mechanism to avoid multiple reloads
                if (!window._scanTablePageReloadTimeout) {
                    window._scanTablePageReloadTimeout = {};
                }
                const timeoutKey = 'page_reload';
                if (window._scanTablePageReloadTimeout[timeoutKey]) {
                    clearTimeout(window._scanTablePageReloadTimeout[timeoutKey]);
                }
                window._scanTablePageReloadTimeout[timeoutKey] = setTimeout(function() {
                    window.location.reload();
                    delete window._scanTablePageReloadTimeout[timeoutKey];
                }, 500); // Short delay to ensure scan is in DB
            }
            return;
        }
        
        // Update status cell using class selector
        const statusCell = $(rowNode).find('.scan-status-cell');
        if (statusCell.length) {
            statusCell.html(getStatusBadgeHtml(data.status, data.current_task, data.scan_type));
        }
        
        // Update progress cell using class selector
        const progressCell = $(rowNode).find('.scan-progress-cell');
        if (progressCell.length) {
            progressCell.html(getProgressBarHtml(data.status, data.progress));
        }
        
        // Update scan engine cell if Secator scan
        if (data.scan_name) {
            const engineCell = $(rowNode).find('.scan-engine-cell');
            if (engineCell.length) {
                const engineHtml = '<span class="badge badge-soft-primary">' + escapeHtml(data.scan_name) + '</span>';
                engineCell.html(engineHtml);
            }
        }
        
        // Update summary cell with findings counts
        if (data.subdomain_count !== undefined || data.endpoint_count !== undefined || data.vulnerability_count !== undefined) {
            const summaryCell = $(rowNode).find('.scan-summary-cell');
            if (summaryCell.length) {
                const subdomainCount = data.subdomain_count !== undefined ? data.subdomain_count : 0;
                const endpointCount = data.endpoint_count !== undefined ? data.endpoint_count : 0;
                const vulnerabilityCount = data.vulnerability_count !== undefined ? data.vulnerability_count : 0;
                
                // Build tooltip for vulnerabilities if we have severity counts
                let vulnTooltip = 'Vulnerabilities';
                if (data.critical_count !== undefined && data.high_count !== undefined && data.medium_count !== undefined) {
                    vulnTooltip = data.critical_count + ' Critical, ' + data.high_count + ' High, ' + data.medium_count + ' Medium Vulnerabilities';
                }
                
                const summaryHtml = '<span class="badge badge-pills bg-info mt-1" data-toggle="tooltip" data-placement="top" title="Subdomains">' + 
                    formatNumber(subdomainCount) + '</span>' +
                    '<span class="badge badge-pills bg-warning mt-1" data-toggle="tooltip" data-placement="top" title="Endpoints">' + 
                    formatNumber(endpointCount) + '</span>' +
                    '<span class="badge badge-pills bg-danger mt-1" data-toggle="tooltip" data-placement="top" title="' + 
                    escapeHtml(vulnTooltip) + '">' + formatNumber(vulnerabilityCount) + '</span>';
                summaryCell.html(summaryHtml);
            }
        }
        
        // Re-initialize tooltips for updated content
        if (typeof $ !== 'undefined' && $.fn.tooltip) {
            $(rowNode).find('[data-toggle="tooltip"]').tooltip();
        }
    } catch (e) {
        console.error('Error updating scan row in table:', e);
    }
};

/**
 * Update detail scan page (for detail_scan.html)
 * @param {object} data - Update data
 */
const updateScanDetailPage = function(data) {
    if (!data || !data.scan_id) {
        return;
    }
    
    try {
        const scanContainer = document.querySelector('[data-scan-id="' + data.scan_id + '"]');
        if (!scanContainer) {
            return;
        }
        
        // Update status badge
        const statusElement = scanContainer.querySelector('.scan-status-badge');
        if (statusElement) {
            const statusHtml = getStatusBadgeHtmlForDetail(data.status, data.current_task);
            statusElement.innerHTML = statusHtml;
        }
        
        // Update progress bar - search within scanContainer and its parent
        let progressElement = scanContainer.querySelector('.scan-progress-bar');
        if (!progressElement) {
            // Fallback: search in the parent card-body
            const cardBody = scanContainer.closest('.card-body');
            if (cardBody) {
                progressElement = cardBody.querySelector('.scan-progress-bar');
            }
        }
        if (!progressElement) {
            // Last fallback: search in the entire document for this scan's progress bar
            const allProgressBars = document.querySelectorAll('.scan-progress-bar');
            for (let i = 0; i < allProgressBars.length; i++) {
                const bar = allProgressBars[i];
                // Check if this progress bar is within the same card-body as scanContainer
                const barCardBody = bar.closest('.card-body');
                const scanCardBody = scanContainer.closest('.card-body');
                if (barCardBody === scanCardBody) {
                    progressElement = bar;
                    break;
                }
            }
        }
        
        if (progressElement) {
            const progress = data.progress || 0;
            
            // Determine width and classes based on status (same logic as getProgressBarHtml)
            let width = progress;
            if (data.status === -1) {
                width = 10;
            } else if (data.status === 2) {
                width = 100; // Always 100% when completed
            } else if (data.status === 4) {
                width = 90; // 90% when finalizing
            } else if (data.status === 0 || data.status === 3) {
                // Use actual progress for failed/aborted
                width = progress;
            }
            
            progressElement.style.width = width + '%';
            progressElement.setAttribute('aria-valuenow', width);
            
            // Update progress bar classes based on status (same as getProgressBarHtml)
            progressElement.className = 'progress-bar scan-progress-bar';
            if (data.status === -1) {
                progressElement.classList.add('bg-warning');
            } else if (data.status === 0 || data.status === 3) {
                progressElement.classList.add('bg-danger');
            } else if (data.status === 1) {
                progressElement.classList.add('bg-primary', 'progress-bar-striped', 'progress-bar-animated');
            } else if (data.status === 2) {
                progressElement.classList.add('bg-success');
            } else if (data.status === 4) {
                progressElement.classList.add('bg-info', 'progress-bar-striped', 'progress-bar-animated');
            } else {
                progressElement.classList.add('bg-danger');
            }
        }
        
        // Update current task
        const taskElement = scanContainer.querySelector('.scan-current-task');
        if (taskElement) {
            if (data.current_task && (data.status === 1 || data.status === 4)) {
                taskElement.textContent = data.current_task;
                taskElement.style.display = '';
            } else {
                taskElement.style.display = 'none';
            }
        }
        
        // Update stats panels
        // Subdomains panel
        if (data.subdomain_count !== undefined || data.alive_count !== undefined) {
            const subdomainPanel = document.querySelector('[data-stats-panel="subdomains"]');
            if (subdomainPanel) {
                const subdomainCountElement = subdomainPanel.querySelector('[data-stat="subdomain-count"]');
                if (subdomainCountElement && data.subdomain_count !== undefined) {
                    updateCounterupElement(subdomainCountElement, data.subdomain_count);
                }
                const aliveCountElement = subdomainPanel.querySelector('[data-stat="alive-count"]');
                if (aliveCountElement && data.alive_count !== undefined) {
                    aliveCountElement.textContent = 'Alive Subdomains: ' + formatNumber(data.alive_count);
                }
            }
        }
        
        // Endpoints panel
        if (data.endpoint_count !== undefined || data.endpoint_alive_count !== undefined) {
            const endpointPanel = document.querySelector('[data-stats-panel="endpoints"]');
            if (endpointPanel) {
                const endpointCountElement = endpointPanel.querySelector('[data-stat="endpoint-count"]');
                if (endpointCountElement && data.endpoint_count !== undefined) {
                    updateCounterupElement(endpointCountElement, data.endpoint_count);
                }
                const endpointAliveCountElement = endpointPanel.querySelector('[data-stat="endpoint-alive-count"]');
                if (endpointAliveCountElement && data.endpoint_alive_count !== undefined) {
                    endpointAliveCountElement.textContent = 'Alive Endpoints: ' + formatNumber(data.endpoint_alive_count);
                }
            }
        }
        
        // Vulnerabilities panel
        if (data.vulnerability_count !== undefined || data.critical_count !== undefined) {
            const vulnPanel = document.querySelector('[data-stats-panel="vulnerabilities"]');
            if (vulnPanel) {
                const vulnCountElement = vulnPanel.querySelector('[data-stat="vulnerability-count"]');
                if (vulnCountElement && data.vulnerability_count !== undefined) {
                    updateCounterupElement(vulnCountElement, data.vulnerability_count);
                }
                
                // Update severity counts
                const severityContainer = vulnPanel.querySelector('[data-stat="vulnerability-severity"]');
                if (severityContainer) {
                    const totalVulnCount = data.vulnerability_count !== undefined ? data.vulnerability_count : 0;
                    if (totalVulnCount > 0) {
                        const criticalCount = data.critical_count !== undefined ? data.critical_count : 0;
                        const highCount = data.high_count !== undefined ? data.high_count : 0;
                        const mediumCount = data.medium_count !== undefined ? data.medium_count : 0;
                        const lowCount = data.low_count !== undefined ? data.low_count : 0;
                        const infoCount = data.info_count !== undefined ? data.info_count : 0;
                        const unknownCount = data.unknown_count !== undefined ? data.unknown_count : 0;
                        
                        const severityHtml = '<p class="text-muted mb-0">' +
                            '<span class="w-title text-danger" data-stat="critical-count">' + formatNumber(criticalCount) + '</span> Critical, ' +
                            '<span class="w-title text-danger" data-stat="high-count">' + formatNumber(highCount) + '</span> High, ' +
                            '<span class="w-title text-danger" data-stat="medium-count">' + formatNumber(mediumCount) + '</span> Medium</span>' +
                            '<br>' +
                            '<span class="w-title text-primary" data-stat="low-count">' + formatNumber(lowCount) + '</span> Low, ' +
                            '<span class="w-title text-primary" data-stat="info-count">' + formatNumber(infoCount) + '</span> Info, and ' +
                            '<span class="w-title text-primary" data-stat="unknown-count">' + formatNumber(unknownCount) + '</span> Unknown Vulnerabilities</span>' +
                            '</p>';
                        severityContainer.innerHTML = severityHtml;
                    } else {
                        severityContainer.innerHTML = '<p class="text-muted mb-0 small">No vulnerabilities found.</p><br>';
                    }
                }
            }
        }
        
        // Update scan name
        if (data.scan_name) {
            const scanEngineSection = scanContainer.parentElement;
            if (scanEngineSection) {
                const scanNameDisplay = scanEngineSection.querySelector('#scan-name-display');
                if (scanNameDisplay) {
                    scanNameDisplay.textContent = data.scan_name;
                }
            }
        }
        
        // Update timeline if timeline data is available
        if (data.timeline && data.timeline.length > 0) {
            updateScanTimeline(data);
        } else if (data.runners && data.runners.length > 0) {
            updateScanTimeline(data);
        }
    } catch (e) {
        console.error('Error updating scan detail page:', e);
    }
};

/**
 * Update scan timeline with runners (for detail_scan.html)
 * @param {object} data - Update data with runners or timeline
 */
const updateScanTimeline = function(data) {
    if (!data || !data.scan_id) {
        return;
    }
    
    try {
        // Try to find timeline container by data-scan-id attribute
        let timelineContainer = document.querySelector('.scan-timeline[data-scan-id="' + data.scan_id + '"]');
        if (!timelineContainer) {
            // Fallback: find by parent container with data-scan-id
            const scanContainer = document.querySelector('[data-scan-id="' + data.scan_id + '"]');
            if (scanContainer) {
                timelineContainer = scanContainer.querySelector('.scan-timeline');
            }
        }
        if (!timelineContainer) {
            return;
        }
        
        // Find the ul element inside track-order-list
        const trackOrderList = timelineContainer.querySelector('.track-order-list');
        if (!trackOrderList) {
            return;
        }
        
        const timelineList = trackOrderList.querySelector('ul.list-unstyled');
        if (!timelineList) {
            return;
        }
        
        // Clear existing timeline items for Secator scans (those with data-runner-id)
        const existingItems = timelineList.querySelectorAll('[data-runner-id]');
        existingItems.forEach(function(item) {
            item.remove();
        });
        
        // Use timeline data if available (preferred), otherwise use runners
        const itemsToRender = data.timeline || [];
        
        if (itemsToRender.length === 0 && data.runners) {
            // Fallback: convert runners to timeline format
            data.runners.forEach(function(runner) {
                const timelineItem = {
                    id: runner.id,
                    title: (runner.runner_type.charAt(0).toUpperCase() + runner.runner_type.slice(1)) + ': ' + runner.runner_name,
                    name: runner.runner_name,
                    status: runner.status_code,
                    time: runner.created_at || runner.updated_at,
                    type: runner.runner_type
                };
                itemsToRender.push(timelineItem);
            });
        }
        
        // Sort by time (newest first)
        itemsToRender.sort(function(a, b) {
            const timeA = new Date(a.time || 0).getTime();
            const timeB = new Date(b.time || 0).getTime();
            return timeB - timeA;
        });
        
        // Add new timeline items
        itemsToRender.forEach(function(item) {
            const listItem = document.createElement('li');
            listItem.setAttribute('data-runner-id', item.id);
            
            // Determine class based on status
            // status: -1 = PENDING, 0 = FAILURE, 1 = RUNNING, 2 = SUCCESS
            if (item.status === 2) {
                listItem.className = 'completed';
            } else if (item.status === 1) {
                listItem.className = 'running';
            } else {
                listItem.className = 'pending';
            }
            
            // Determine badge class and text
            let statusClass = 'badge-soft-secondary';
            let statusText = 'Pending';
            if (item.status === 0 || item.status === -1) {
                statusClass = 'badge-soft-danger';
                statusText = item.status === 0 ? 'Failed' : 'Pending';
            } else if (item.status === 1) {
                statusClass = 'badge-soft-warning';
                statusText = 'In progress';
            } else if (item.status === 2) {
                statusClass = 'badge-soft-success';
                statusText = 'Completed';
            }
            
            // Format time
            let timeText = '';
            if (item.time) {
                try {
                    const timeDate = new Date(item.time);
                    const now = new Date();
                    const diffMs = now - timeDate;
                    const diffSec = Math.floor(diffMs / 1000);
                    const diffMin = Math.floor(diffSec / 60);
                    const diffHour = Math.floor(diffMin / 60);
                    
                    if (diffSec < 60) {
                        timeText = diffSec + ' seconds ago';
                    } else if (diffMin < 60) {
                        timeText = diffMin + ' minutes ago';
                    } else if (diffHour < 24) {
                        timeText = diffHour + ' hours ago';
                    } else {
                        timeText = timeDate.toLocaleString();
                    }
                } catch (e) {
                    timeText = item.time;
                }
            }
            
            listItem.innerHTML = '<h5 class="mt-0 mb-1">' + 
                escapeHtml(item.title || item.name) +
                '<span class="float-end badge ' + statusClass + '">' + statusText + 
                (item.status === 1 ? '<span class="active-dot dot"></span>' : '') +
                '</span></h5>' +
                '<p class="text-muted">' + timeText + 
                (item.time ? '<br><small class="text-muted">' + escapeHtml(item.time) + '</small>' : '') +
                '</p>';
            
            timelineList.appendChild(listItem);
        });
    } catch (e) {
        console.error('Error updating scan timeline:', e);
    }
};

/**
 * Update right sidebar (for right_bar.html)
 * @param {object} data - Update data
 */
const updateRightSidebar = function(data) {
    if (!data || !data.scan_id) {
        return;
    }
    
    try {
        // Check if scan is completed (status 2 = SUCCESS, 3 = ABORTED, 0 = FAILED)
        const isCompleted = data.status === 2 || data.status === 3 || data.status === 0;
        
        // Find scan card in sidebar
        const scanCard = document.querySelector('#scan-card-' + data.scan_id);
        
        // If scan card doesn't exist, it might be a new scan - reload sidebar immediately
        if (!scanCard && typeof getScanStatusSidebar === 'function') {
            // Get project slug from current URL
            let projectSlug = null;
            const urlMatch = window.location.pathname.match(/\/scan\/([^\/]+)\//);
            if (urlMatch) {
                projectSlug = urlMatch[1];
            } else {
                // Try to get from data attribute if available
                const projectElement = document.querySelector('[data-project-slug]');
                if (projectElement) {
                    projectSlug = projectElement.getAttribute('data-project-slug');
                }
            }
            
            if (projectSlug) {
                // Reload sidebar immediately for new scans
                // Get URLs from options if available, otherwise they should be passed from template
                const endpointUrl = window.scanStatusApiUrls?.scanStatusUrl;
                const stopScanUrl = window.scanStatusApiUrls?.stopScanUrl;
                const stopActivityUrl = window.scanStatusApiUrls?.stopActivityUrl;
                const fetchSubscanUrl = window.scanStatusApiUrls?.fetchSubscanUrl;
                if (endpointUrl && stopScanUrl && stopActivityUrl && fetchSubscanUrl) {
                    getScanStatusSidebar(endpointUrl, stopScanUrl, stopActivityUrl, fetchSubscanUrl, projectSlug, false);
                } else {
                    console.warn('scan_status_websocket: API URLs not available. Please ensure URLs are passed from template.');
                }
            }
            return;
        }
        
        if (scanCard) {
            // If scan is completed, remove it from "Currently Scanning" section
            if (isCompleted) {
                // Check if the card is in the "Currently Scanning" section
                const currentlyScanningContainer = document.getElementById('currently_scanning');
                if (currentlyScanningContainer && currentlyScanningContainer.contains(scanCard)) {
                    // Remove the card from "Currently Scanning"
                    scanCard.remove();
                    
                    // Update the count of currently scanning scans
                    // Count remaining scan cards (excluding alert messages)
                    const remainingScanCards = currentlyScanningContainer.querySelectorAll('.mini-card');
                    const remainingScans = remainingScanCards.length;
                    
                    // Update current_scan_count text (the badge inside h5)
                    const currentScanCountElement = document.getElementById('current_scan_count');
                    if (currentScanCountElement) {
                        if (remainingScans > 0) {
                            currentScanCountElement.textContent = remainingScans + ' Scans Currently Running';
                            // Make sure the parent h5 is visible
                            const parentH5 = currentScanCountElement.closest('h5');
                            if (parentH5) {
                                parentH5.style.display = '';
                            }
                        } else {
                            // Clear the count element when no scans are running
                            currentScanCountElement.textContent = '';
                            // Hide the parent h5 element
                            const parentH5 = currentScanCountElement.closest('h5');
                            if (parentH5) {
                                parentH5.style.display = 'none';
                            }
                        }
                    }
                    
                    // Update current_scan_counter badge if it exists (separate badge element)
                    const currentScanCounterElement = document.getElementById('current_scan_counter');
                    if (currentScanCounterElement) {
                        // Always display the counter, set to 0 if no scans
                        currentScanCounterElement.textContent = remainingScans;
                        currentScanCounterElement.style.display = '';
                    }
                    
                    // Show "No Scans are currently running" message if container is empty
                    if (remainingScans === 0) {
                        // Check if there's already an alert or if container is empty
                        const hasAlert = currentlyScanningContainer.querySelector('.alert');
                        const hasH5 = currentlyScanningContainer.querySelector('h5');
                        if (!hasAlert && (!hasH5 || currentlyScanningContainer.children.length <= 1)) {
                            currentlyScanningContainer.innerHTML = '<div class="alert alert-info" role="alert">No Scans are currently running.</div>';
                        }
                    }
                    
                    // Reload the sidebar immediately to show the scan in "Recently Completed"
                    // This ensures the scan appears in the completed section with all details
                    if (typeof getScanStatusSidebar === 'function') {
                        // Get project slug from current URL or from the scan card link
                        let projectSlug = null;
                        const cardLink = scanCard.querySelector('a[href*="/scan/"]');
                        if (cardLink) {
                            const hrefMatch = cardLink.getAttribute('href').match(/\/scan\/([^\/]+)\//);
                            if (hrefMatch) {
                                projectSlug = hrefMatch[1];
                            }
                        }
                        
                        // Fallback: try to get from URL or data attribute
                        if (!projectSlug) {
                            const urlMatch = window.location.pathname.match(/\/scan\/([^\/]+)\//);
                            if (urlMatch) {
                                projectSlug = urlMatch[1];
                            } else {
                                const projectElement = document.querySelector('[data-project-slug]');
                                if (projectElement) {
                                    projectSlug = projectElement.getAttribute('data-project-slug');
                                }
                            }
                        }
                        
                        if (projectSlug) {
                            // Reload sidebar immediately (no delay) to show completed scan
                            // Get URLs from options if available, otherwise they should be passed from template
                            const endpointUrl = window.scanStatusApiUrls?.scanStatusUrl;
                            const stopScanUrl = window.scanStatusApiUrls?.stopScanUrl;
                            const stopActivityUrl = window.scanStatusApiUrls?.stopActivityUrl;
                            const fetchSubscanUrl = window.scanStatusApiUrls?.fetchSubscanUrl;
                            if (endpointUrl && stopScanUrl && stopActivityUrl && fetchSubscanUrl) {
                                getScanStatusSidebar(endpointUrl, stopScanUrl, stopActivityUrl, fetchSubscanUrl, projectSlug, false);
                            } else {
                                console.warn('scan_status_websocket: API URLs not available. Please ensure URLs are passed from template.');
                            }
                        }
                    }
                }
            } else {
                // Scan is still running, update the card content
                // Update status badge
                const statusBadge = scanCard.querySelector('.scan-status');
                if (statusBadge) {
                    let statusText = '';
                    if (data.status === 1) {
                        statusText = 'Scanning';
                    } else if (data.status === 4) {
                        statusText = 'Finalizing';
                    } else if (data.status === -1) {
                        statusText = 'Pending';
                    }
                    statusBadge.innerHTML = statusText;
                }
                
                // Update progress bar
                const progressBar = scanCard.querySelector('.scan-progress-bar');
                if (progressBar) {
                    const progress = data.progress || 0;
                    progressBar.style.width = progress + '%';
                    progressBar.setAttribute('aria-valuenow', progress);
                    
                    // Update progress badge
                    const progressBadge = scanCard.querySelector('.badge-soft-primary.float-end');
                    if (progressBadge && progressBadge.textContent.includes('%')) {
                        progressBadge.textContent = progress + '%';
                    }
                }
                
                // Update findings counts (subdomains, endpoints, vulnerabilities)
                if (data.subdomain_count !== undefined || data.endpoint_count !== undefined || data.vulnerability_count !== undefined) {
                    const subdomainBadge = scanCard.querySelector('.badge-subdomain-count');
                    if (subdomainBadge && data.subdomain_count !== undefined) {
                        subdomainBadge.innerHTML = '&nbsp;&nbsp;' + formatNumber(data.subdomain_count) + '&nbsp;&nbsp;';
                    }
                    
                    const endpointBadge = scanCard.querySelector('.badge-endpoint-count');
                    if (endpointBadge && data.endpoint_count !== undefined) {
                        endpointBadge.innerHTML = '&nbsp;&nbsp;' + formatNumber(data.endpoint_count) + '&nbsp;&nbsp;';
                    }
                    
                    const vulnBadge = scanCard.querySelector('.badge-vuln-count');
                    if (vulnBadge && data.vulnerability_count !== undefined) {
                        vulnBadge.innerHTML = '&nbsp;&nbsp;' + formatNumber(data.vulnerability_count) + '&nbsp;&nbsp;';
                    }
                    
                    // Re-initialize tooltips for updated badges
                    if (typeof $ !== 'undefined' && $.fn.tooltip) {
                        $(scanCard).find('[data-toggle="tooltip"]').tooltip();
                    }
                }
                
                // Update current task display
                if (data.current_task) {
                    const cardHeader = scanCard.querySelector('.card-header');
                    if (cardHeader) {
                        // Check if current task element exists
                        const currentTaskElement = cardHeader.querySelector('small.text-muted.font-weight-bold');
                        if (currentTaskElement) {
                            currentTaskElement.textContent = data.current_task;
                        } else {
                            // Add current task element if it doesn't exist
                            const taskElement = document.createElement('small');
                            taskElement.className = 'text-muted font-weight-bold';
                            taskElement.textContent = data.current_task;
                            taskElement.style.display = 'block';
                            cardHeader.appendChild(taskElement);
                        }
                    }
                }
            }
        }
    } catch (e) {
        console.error('Error updating right sidebar:', e);
    }
};

/**
 * Get HTML for status badge (for table)
 * @param {number} status - Scan status code
 * @param {string} currentTask - Current task name
 * @param {string} scanType - Scan type (legacy or secator)
 * @returns {string} HTML for status badge
 */
const getStatusBadgeHtml = function(status, currentTask, scanType) {
    let badgeClass = 'badge-soft-';
    let badgeText = '';
    let spinner = '';
    
    if (status === -1) {
        badgeClass += 'warning';
        badgeText = 'Pending';
        spinner = '<span class="spinner-border spinner-border-sm"></span> ';
    } else if (status === 0) {
        badgeClass += 'danger';
        badgeText = 'Failed';
    } else if (status === 1) {
        badgeClass += 'info';
        badgeText = 'In Progress';
        spinner = '<span class="spinner-border spinner-border-sm"></span> ';
    } else if (status === 2) {
        badgeClass += 'success';
        badgeText = 'Successful';
    } else if (status === 3) {
        badgeClass += 'danger';
        badgeText = 'Aborted';
    } else if (status === 4) {
        badgeClass += 'primary';
        badgeText = 'Finalizing';
        spinner = '<span class="spinner-border spinner-border-sm"></span> ';
    } else {
        badgeClass += 'danger';
        badgeText = 'Unknown';
    }
    
    let html = '<span class="badge ' + badgeClass + '">' + spinner + badgeText + '</span>';
    
    if (currentTask && (status === 1 || status === 4)) {
        html += '<br><small class="text-muted font-weight-bold">' + escapeHtml(currentTask) + '</small>';
    }
    
    return html;
};

/**
 * Get HTML for status badge (for detail page)
 * @param {number} status - Scan status code
 * @param {string} currentTask - Current task name
 * @returns {string} HTML for status badge
 */
const getStatusBadgeHtmlForDetail = function(status, currentTask) {
    let iconClass = 'mdi mdi-circle text-';
    let badgeClass = 'badge-soft-';
    let badgeText = '';
    
    if (status === -1) {
        iconClass += 'warning';
        badgeClass += 'warning';
        badgeText = 'Pending';
    } else if (status === 0) {
        iconClass += 'danger';
        badgeClass += 'danger';
        badgeText = 'Failed';
    } else if (status === 1) {
        iconClass += 'warning';
        badgeClass += 'warning';
        badgeText = 'In Progress';
    } else if (status === 2) {
        iconClass += 'success';
        badgeClass += 'success';
        badgeText = 'Completed';
    } else if (status === 3) {
        iconClass += 'danger';
        badgeClass += 'danger';
        badgeText = 'Aborted';
    } else if (status === 4) {
        iconClass += 'info';
        badgeClass += 'info';
        badgeText = 'Finalizing';
    } else {
        iconClass += 'danger';
        badgeClass += 'danger';
        badgeText = 'Unknown';
    }
    
    let html = '<span class="' + iconClass + '"></span> <span class="badge ' + badgeClass + '">' + badgeText + '</span>';
    
    if (currentTask && (status === 1 || status === 4)) {
        html += '<br><small class="text-muted font-weight-bold scan-current-task">' + escapeHtml(currentTask) + '</small>';
    }
    
    return html;
};

/**
 * Get HTML for progress bar
 * @param {number} status - Scan status code
 * @param {number} progress - Progress percentage
 * @returns {string} HTML for progress bar
 */
const getProgressBarHtml = function(status, progress) {
    let barClass = 'progress-bar';
    let width = progress || 0;
    
    if (status === -1) {
        barClass += ' bg-warning';
        width = 10;
    } else if (status === 0) {
        barClass += ' bg-danger';
    } else if (status === 1) {
        barClass += ' bg-primary progress-bar-striped progress-bar-animated';
    } else if (status === 2) {
        barClass += ' bg-success';
        width = 100;
    } else if (status === 3) {
        barClass += ' bg-danger progress-bar-striped';
    } else if (status === 4) {
        barClass += ' bg-info progress-bar-striped progress-bar-animated';
        width = 90;
    } else {
        barClass += ' bg-danger';
        width = 100;
    }
    
    return '<div class="progress progress-md mt-1">' +
           '<div class="' + barClass + '" role="progressbar" style="width: ' + width + '%" ' +
           'aria-valuenow="' + width + '" aria-valuemin="0" aria-valuemax="100"></div>' +
           '</div>';
};

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
/**
 * Format number with thousand separators (like Django's intcomma filter)
 * @param {number} num - Number to format
 * @returns {string} Formatted number
 */
const formatNumber = function(num) {
    if (num === null || num === undefined) {
        return '0';
    }
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
};

/**
 * Update counterup element value and trigger animation if needed
 * @param {HTMLElement} element - Element with data-plugin="counterup"
 * @param {number} newValue - New value to set
 */
const updateCounterupElement = function(element, newValue) {
    if (!element) {
        return;
    }
    
    const currentValue = parseInt(element.textContent.replace(/,/g, '')) || 0;
    const formattedValue = formatNumber(newValue);
    
    // If counterup plugin is available, use it to animate
    if (typeof $ !== 'undefined' && $.fn.counterUp) {
        // Update the text content first
        element.textContent = formattedValue;
        // Trigger counterup animation if value changed
        if (currentValue !== newValue) {
            $(element).counterUp({
                delay: 10,
                time: 300
            });
        }
    } else {
        // Fallback: just update the text
        element.textContent = formattedValue;
    }
};

const escapeHtml = function(text) {
    if (!text) {
        return '';
    }
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
};

/**
 * Disconnect all scan status WebSockets
 */
const disconnectAllScanStatusWebSockets = function() {
    for (const key in scanStatusWebSockets) {
        if (scanStatusWebSockets[key]) {
            scanStatusWebSockets[key].close();
            scanStatusWebSockets[key] = null;
        }
    }
    
    for (const key in scanStatusReconnectTimeouts) {
        if (scanStatusReconnectTimeouts[key]) {
            clearTimeout(scanStatusReconnectTimeouts[key]);
            scanStatusReconnectTimeouts[key] = null;
        }
    }
    
    // Clear options and connecting flags
    for (const key in scanStatusOptions) {
        delete scanStatusOptions[key];
    }
    for (const key in scanStatusConnecting) {
        delete scanStatusConnecting[key];
    }
};

    // Clean up on page unload
    window.addEventListener('beforeunload', function() {
        disconnectAllScanStatusWebSockets();
    });
    
    // Expose functions globally so they can be called from other scripts
    window.connectScanStatusWebSocket = connectScanStatusWebSocket;
    window.handleScanStatusUpdate = handleScanStatusUpdate;
    window.updateScanRowInTable = updateScanRowInTable;
    window.updateScanDetailPage = updateScanDetailPage;
    window.updateRightSidebar = updateRightSidebar;
    window.disconnectAllScanStatusWebSockets = disconnectAllScanStatusWebSockets;
})();
