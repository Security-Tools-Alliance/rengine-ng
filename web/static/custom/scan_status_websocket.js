/**
 * WebSocket client for real-time scan status updates.
 * Handles connections and updates for history.html, detail_scan.html, and right_bar.html
 */

var scanStatusWebSockets = {};
var scanStatusReconnectAttempts = {};
var scanStatusReconnectTimeouts = {};
var MAX_RECONNECT_ATTEMPTS = 10;
var INITIAL_RECONNECT_DELAY = 1000; // 1 second

/**
 * Connect to scan status WebSocket
 * @param {number|null} scanId - Specific scan ID, or null for project-level
 * @param {string|null} projectSlug - Project slug for project-level updates
 * @param {object} options - Options for update handlers
 * @param {function} options.updateTable - Function to update DataTable (for history.html)
 * @param {function} options.updateDetail - Function to update detail page (for detail_scan.html)
 * @param {function} options.updateSidebar - Function to update sidebar (for right_bar.html)
 */
function connectScanStatusWebSocket(scanId, projectSlug, options) {
    var wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    var wsUrl;
    var key;
    
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
    
    // Don't reconnect if already connected
    if (scanStatusWebSockets[key] && scanStatusWebSockets[key].readyState === WebSocket.OPEN) {
        return;
    }
    
    // Close existing connection if any
    if (scanStatusWebSockets[key]) {
        scanStatusWebSockets[key].close();
    }
    
    try {
        var socket = new WebSocket(wsUrl);
        scanStatusWebSockets[key] = socket;
        scanStatusReconnectAttempts[key] = 0;
        
        socket.onopen = function(event) {
            console.log('Scan status WebSocket connected: ' + key);
            scanStatusReconnectAttempts[key] = 0;
        };
        
        socket.onmessage = function(event) {
            try {
                var data = JSON.parse(event.data);
                handleScanStatusUpdate(data, options);
            } catch (e) {
                console.error('Error parsing WebSocket message:', e);
            }
        };
        
        socket.onerror = function(error) {
            console.error('Scan status WebSocket error:', error);
        };
        
        socket.onclose = function(event) {
            console.log('Scan status WebSocket closed: ' + key);
            scanStatusWebSockets[key] = null;
            
            // Attempt to reconnect if not a normal closure
            if (event.code !== 1000 && scanStatusReconnectAttempts[key] < MAX_RECONNECT_ATTEMPTS) {
                var delay = INITIAL_RECONNECT_DELAY * Math.pow(2, scanStatusReconnectAttempts[key]);
                scanStatusReconnectAttempts[key]++;
                
                console.log('Reconnecting scan status WebSocket in ' + delay + 'ms (attempt ' + scanStatusReconnectAttempts[key] + ')');
                
                scanStatusReconnectTimeouts[key] = setTimeout(function() {
                    connectScanStatusWebSocket(scanId, projectSlug, options);
                }, delay);
            }
        };
    } catch (e) {
        console.error('Error creating scan status WebSocket:', e);
    }
}

/**
 * Handle scan status update from WebSocket
 * @param {object} data - Update data from WebSocket
 * @param {object} options - Update handler options
 */
function handleScanStatusUpdate(data, options) {
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
}

/**
 * Update a row in DataTable (for history.html)
 * @param {DataTable} table - DataTable instance
 * @param {object} data - Update data
 */
function updateScanRowInTable(table, data) {
    if (!table || !data || !data.scan_id) {
        return;
    }
    
    try {
        // Find the row directly in the DOM by data-scan-id attribute
        var rowNode = document.querySelector('tr[data-scan-id="' + data.scan_id + '"]');
        
        if (!rowNode) {
            // Row not found, might be a new scan that's not yet in the table
            // Check if table is in AJAX mode by checking if ajax.reload exists
            if (table && typeof table.ajax === 'function' && typeof table.ajax.reload === 'function') {
                // Use DataTables ajax.reload() method - simple and efficient
                // Use a debounce mechanism to avoid multiple reloads
                if (!window._scanTableReloadTimeout) {
                    window._scanTableReloadTimeout = {};
                }
                var timeoutKey = 'table_reload';
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
                var timeoutKey = 'page_reload';
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
        var statusCell = $(rowNode).find('.scan-status-cell');
        if (statusCell.length) {
            statusCell.html(getStatusBadgeHtml(data.status, data.current_task, data.scan_type));
        }
        
        // Update progress cell using class selector
        var progressCell = $(rowNode).find('.scan-progress-cell');
        if (progressCell.length) {
            progressCell.html(getProgressBarHtml(data.status, data.progress));
        }
        
        // Update scan engine cell if Secator scan
        if (data.scan_type === 'secator' && data.runners && data.runners.length > 0) {
            var engineCell = $(rowNode).find('.scan-engine-cell');
            if (engineCell.length) {
                var mainRunner = data.runners.find(function(r) {
                    return r.runner_type === 'workflow' || r.runner_type === 'scan';
                });
                if (!mainRunner && data.runners.length > 0) {
                    mainRunner = data.runners[0];
                }
                if (mainRunner) {
                    var engineHtml = '<span class="badge badge-soft-primary">Secator ' + 
                        escapeHtml(mainRunner.runner_type.charAt(0).toUpperCase() + mainRunner.runner_type.slice(1)) + 
                        '</span><br><span class="badge badge-soft-info mt-1">' + 
                        escapeHtml(mainRunner.runner_name || '') + '</span>';
                    engineCell.html(engineHtml);
                }
            }
        }
        
        // Re-initialize tooltips for updated content
        if (typeof $ !== 'undefined' && $.fn.tooltip) {
            $(rowNode).find('[data-toggle="tooltip"]').tooltip();
        }
    } catch (e) {
        console.error('Error updating scan row in table:', e);
    }
}

/**
 * Update detail scan page (for detail_scan.html)
 * @param {object} data - Update data
 */
function updateScanDetailPage(data) {
    if (!data || !data.scan_id) {
        return;
    }
    
    try {
        var scanContainer = document.querySelector('[data-scan-id="' + data.scan_id + '"]');
        if (!scanContainer) {
            return;
        }
        
        // Update status badge
        var statusElement = scanContainer.querySelector('.scan-status-badge');
        if (statusElement) {
            var statusHtml = getStatusBadgeHtmlForDetail(data.status, data.current_task);
            statusElement.innerHTML = statusHtml;
        }
        
        // Update progress bar
        var progressElement = scanContainer.querySelector('.scan-progress-bar');
        if (progressElement) {
            var progress = data.progress || 0;
            
            // Determine width and classes based on status (same logic as getProgressBarHtml)
            var width = progress;
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
        var taskElement = scanContainer.querySelector('.scan-current-task');
        if (taskElement) {
            if (data.current_task && (data.status === 1 || data.status === 4)) {
                taskElement.textContent = data.current_task;
                taskElement.style.display = '';
            } else {
                taskElement.style.display = 'none';
            }
        }
        
        // Update scan engine/name for Secator scans
        if (data.scan_type === 'secator' && data.runners && data.runners.length > 0) {
            var mainRunner = data.runners.find(function(r) {
                return r.runner_type === 'workflow' || r.runner_type === 'scan';
            });
            if (!mainRunner && data.runners.length > 0) {
                mainRunner = data.runners[0];
            }
            if (mainRunner) {
                // Find the scan engine element (h6 with "Scan Engine" text)
                var scanEngineSection = scanContainer.parentElement;
                if (scanEngineSection) {
                    var scanEngineLabel = scanEngineSection.querySelector('h6:contains("Scan Engine")');
                    if (!scanEngineLabel) {
                        // Try to find by text content
                        var h6Elements = scanEngineSection.querySelectorAll('h6');
                        for (var i = 0; i < h6Elements.length; i++) {
                            if (h6Elements[i].textContent.includes('Scan Engine')) {
                                scanEngineLabel = h6Elements[i];
                                break;
                            }
                        }
                    }
                    if (scanEngineLabel) {
                        // Change label to "Scan Name" or keep "Scan Engine"
                        var nextElement = scanEngineLabel.nextElementSibling;
                        if (nextElement && nextElement.tagName === 'SPAN') {
                            nextElement.innerHTML = '<span class="badge badge-soft-primary">Secator ' + 
                                escapeHtml(mainRunner.runner_type.charAt(0).toUpperCase() + mainRunner.runner_type.slice(1)) + 
                                '</span><br><span class="badge badge-soft-info mt-1">' + 
                                escapeHtml(mainRunner.runner_name || '') + '</span>';
                        }
                    }
                }
            }
        }
        
        // Update timeline if runners are available
        if (data.runners && data.runners.length > 0) {
            updateScanTimeline(data);
        }
    } catch (e) {
        console.error('Error updating scan detail page:', e);
    }
}

/**
 * Update scan timeline with runners (for detail_scan.html)
 * @param {object} data - Update data with runners
 */
function updateScanTimeline(data) {
    if (!data || !data.runners || !data.scan_id) {
        return;
    }
    
    try {
        var timelineContainer = document.querySelector('[data-scan-id="' + data.scan_id + '"] .scan-timeline');
        if (!timelineContainer) {
            return;
        }
        
        // Clear existing timeline items for this scan
        var existingItems = timelineContainer.querySelectorAll('[data-runner-id]');
        existingItems.forEach(function(item) {
            item.remove();
        });
        
        // Add new timeline items
        var timelineList = timelineContainer.querySelector('ul');
        if (!timelineList) {
            return;
        }
        
        data.runners.forEach(function(runner) {
            var listItem = document.createElement('li');
            listItem.setAttribute('data-runner-id', runner.id);
            listItem.className = runner.status_code === 2 ? 'completed' : (runner.status_code === 1 ? 'running' : 'pending');
            
            var statusClass = runner.status_code === 0 ? 'badge-soft-danger' : 
                             (runner.status_code === 1 ? 'badge-soft-warning' : 'badge-soft-success');
            var statusText = runner.status_code === 0 ? 'Failed' : 
                            (runner.status_code === 1 ? 'In progress' : 'Completed');
            
            listItem.innerHTML = '<h5 class="mt-0 mb-1">' + 
                escapeHtml(runner.runner_type + ': ' + runner.runner_name) +
                '<span class="float-end badge ' + statusClass + '">' + statusText + 
                (runner.status_code === 1 ? '<span class="active-dot dot"></span>' : '') +
                '</span></h5>' +
                '<p class="text-muted">' + (runner.elapsed || '0s') + ' ago</p>';
            
            timelineList.appendChild(listItem);
        });
    } catch (e) {
        console.error('Error updating scan timeline:', e);
    }
}

/**
 * Update right sidebar (for right_bar.html)
 * @param {object} data - Update data
 */
function updateRightSidebar(data) {
    if (!data || !data.scan_id) {
        return;
    }
    
    try {
        // Check if scan is completed (status 2 = SUCCESS, 3 = ABORTED, 0 = FAILED)
        var isCompleted = data.status === 2 || data.status === 3 || data.status === 0;
        
        // Find scan card in sidebar
        var scanCard = document.querySelector('#scan-card-' + data.scan_id);
        
        // If scan card doesn't exist, it might be a new scan - reload sidebar immediately
        if (!scanCard && typeof getScanStatusSidebar === 'function') {
            // Get project slug from current URL
            var projectSlug = null;
            var urlMatch = window.location.pathname.match(/\/scan\/([^\/]+)\//);
            if (urlMatch) {
                projectSlug = urlMatch[1];
            } else {
                // Try to get from data attribute if available
                var projectElement = document.querySelector('[data-project-slug]');
                if (projectElement) {
                    projectSlug = projectElement.getAttribute('data-project-slug');
                }
            }
            
            if (projectSlug) {
                // Reload sidebar immediately for new scans
                var endpointUrl = '/api/scan_status/';
                var stopScanUrl = '/api/stop_scan/';
                var fetchSubscanUrl = '/api/fetch_subscan_results/';
                getScanStatusSidebar(endpointUrl, stopScanUrl, fetchSubscanUrl, projectSlug, false);
            }
            return;
        }
        
        if (scanCard) {
            // If scan is completed, remove it from "Currently Scanning" section
            if (isCompleted) {
                // Check if the card is in the "Currently Scanning" section
                var currentlyScanningContainer = document.getElementById('currently_scanning');
                if (currentlyScanningContainer && currentlyScanningContainer.contains(scanCard)) {
                    // Remove the card from "Currently Scanning"
                    scanCard.remove();
                    
                    // Update the count of currently scanning scans
                    // Count remaining scan cards (excluding alert messages)
                    var remainingScanCards = currentlyScanningContainer.querySelectorAll('.mini-card');
                    var remainingScans = remainingScanCards.length;
                    
                    // Update current_scan_count text (the badge inside h5)
                    var currentScanCountElement = document.getElementById('current_scan_count');
                    if (currentScanCountElement) {
                        if (remainingScans > 0) {
                            currentScanCountElement.textContent = remainingScans + ' Scans Currently Running';
                            // Make sure the parent h5 is visible
                            var parentH5 = currentScanCountElement.closest('h5');
                            if (parentH5) {
                                parentH5.style.display = '';
                            }
                        } else {
                            // Clear the count element when no scans are running
                            currentScanCountElement.textContent = '';
                            // Hide the parent h5 element
                            var parentH5 = currentScanCountElement.closest('h5');
                            if (parentH5) {
                                parentH5.style.display = 'none';
                            }
                        }
                    }
                    
                    // Update current_scan_counter badge if it exists (separate badge element)
                    var currentScanCounterElement = document.getElementById('current_scan_counter');
                    if (currentScanCounterElement) {
                        // Always display the counter, set to 0 if no scans
                        currentScanCounterElement.textContent = remainingScans;
                        currentScanCounterElement.style.display = '';
                    }
                    
                    // Show "No Scans are currently running" message if container is empty
                    if (remainingScans === 0) {
                        // Check if there's already an alert or if container is empty
                        var hasAlert = currentlyScanningContainer.querySelector('.alert');
                        var hasH5 = currentlyScanningContainer.querySelector('h5');
                        if (!hasAlert && (!hasH5 || currentlyScanningContainer.children.length <= 1)) {
                            currentlyScanningContainer.innerHTML = '<div class="alert alert-info" role="alert">No Scans are currently running.</div>';
                        }
                    }
                    
                    // Reload the sidebar immediately to show the scan in "Recently Completed"
                    // This ensures the scan appears in the completed section with all details
                    if (typeof getScanStatusSidebar === 'function') {
                        // Get project slug from current URL or from the scan card link
                        var projectSlug = null;
                        var cardLink = scanCard.querySelector('a[href*="/scan/"]');
                        if (cardLink) {
                            var hrefMatch = cardLink.getAttribute('href').match(/\/scan\/([^\/]+)\//);
                            if (hrefMatch) {
                                projectSlug = hrefMatch[1];
                            }
                        }
                        
                        // Fallback: try to get from URL or data attribute
                        if (!projectSlug) {
                            var urlMatch = window.location.pathname.match(/\/scan\/([^\/]+)\//);
                            if (urlMatch) {
                                projectSlug = urlMatch[1];
                            } else {
                                var projectElement = document.querySelector('[data-project-slug]');
                                if (projectElement) {
                                    projectSlug = projectElement.getAttribute('data-project-slug');
                                }
                            }
                        }
                        
                        if (projectSlug) {
                            // Reload sidebar immediately (no delay) to show completed scan
                            var endpointUrl = '/api/scan_status/';
                            var stopScanUrl = '/api/stop_scan/';
                            var fetchSubscanUrl = '/api/fetch_subscan_results/';
                            getScanStatusSidebar(endpointUrl, stopScanUrl, fetchSubscanUrl, projectSlug, false);
                        }
                    }
                }
            } else {
                // Scan is still running, update the card content
                // Update status badge
                var statusBadge = scanCard.querySelector('.scan-status');
                if (statusBadge) {
                    var statusText = '';
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
                var progressBar = scanCard.querySelector('.scan-progress-bar');
                if (progressBar) {
                    var progress = data.progress || 0;
                    progressBar.style.width = progress + '%';
                    progressBar.setAttribute('aria-valuenow', progress);
                    
                    // Update progress badge
                    var progressBadge = scanCard.querySelector('.badge-soft-primary.float-end');
                    if (progressBadge && progressBadge.textContent.includes('%')) {
                        progressBadge.textContent = progress + '%';
                    }
                }
                
                // Update current task display
                if (data.current_task) {
                    var cardHeader = scanCard.querySelector('.card-header');
                    if (cardHeader) {
                        // Check if current task element exists
                        var currentTaskElement = cardHeader.querySelector('small.text-muted.font-weight-bold');
                        if (currentTaskElement) {
                            currentTaskElement.textContent = data.current_task;
                        } else {
                            // Add current task element if it doesn't exist
                            var taskElement = document.createElement('small');
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
}

/**
 * Get HTML for status badge (for table)
 * @param {number} status - Scan status code
 * @param {string} currentTask - Current task name
 * @param {string} scanType - Scan type (legacy or secator)
 * @returns {string} HTML for status badge
 */
function getStatusBadgeHtml(status, currentTask, scanType) {
    var badgeClass = 'badge-soft-';
    var badgeText = '';
    var spinner = '';
    
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
    
    var html = '<span class="badge ' + badgeClass + '">' + spinner + badgeText + '</span>';
    
    if (currentTask && (status === 1 || status === 4)) {
        html += '<br><small class="text-muted font-weight-bold">' + escapeHtml(currentTask) + '</small>';
    }
    
    return html;
}

/**
 * Get HTML for status badge (for detail page)
 * @param {number} status - Scan status code
 * @param {string} currentTask - Current task name
 * @returns {string} HTML for status badge
 */
function getStatusBadgeHtmlForDetail(status, currentTask) {
    var iconClass = 'mdi mdi-circle text-';
    var badgeClass = 'badge-soft-';
    var badgeText = '';
    
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
    
    var html = '<span class="' + iconClass + '"></span> <span class="badge ' + badgeClass + '">' + badgeText + '</span>';
    
    if (currentTask && (status === 1 || status === 4)) {
        html += '<br><small class="text-muted font-weight-bold scan-current-task">' + escapeHtml(currentTask) + '</small>';
    }
    
    return html;
}

/**
 * Get HTML for progress bar
 * @param {number} status - Scan status code
 * @param {number} progress - Progress percentage
 * @returns {string} HTML for progress bar
 */
function getProgressBarHtml(status, progress) {
    var barClass = 'progress-bar';
    var width = progress || 0;
    
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
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    if (!text) {
        return '';
    }
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Disconnect all scan status WebSockets
 */
function disconnectAllScanStatusWebSockets() {
    for (var key in scanStatusWebSockets) {
        if (scanStatusWebSockets[key]) {
            scanStatusWebSockets[key].close();
            scanStatusWebSockets[key] = null;
        }
    }
    
    for (var key in scanStatusReconnectTimeouts) {
        if (scanStatusReconnectTimeouts[key]) {
            clearTimeout(scanStatusReconnectTimeouts[key]);
            scanStatusReconnectTimeouts[key] = null;
        }
    }
}

// Clean up on page unload
window.addEventListener('beforeunload', function() {
    disconnectAllScanStatusWebSockets();
});
