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

    if (!window.RENGINE_SCAN_STATUS) {
        const el = document.getElementById('rengine-scan-status');
        if (el && el.textContent) {
            try {
                window.RENGINE_SCAN_STATUS = JSON.parse(el.textContent);
            } catch (e) {
                window.RENGINE_SCAN_STATUS = {};
            }
        } else {
            window.RENGINE_SCAN_STATUS = {};
        }
    }
    const scanStatusWebSocketsMap = new Map();
    const scanStatusReconnectAttemptsMap = new Map();
    const scanStatusReconnectTimeoutsMap = new Map();
    const scanStatusOptionsMap = new Map(); // Store options for each connection to share handlers
    const scanStatusConnectingMap = new Map(); // Track connections being established to prevent duplicates
    const MAX_RECONNECT_ATTEMPTS = 10;
    const INITIAL_RECONNECT_DELAY = 1000; // 1 second

    /**
     * Merge options into an existing scan-status options entry (OPEN, CONNECTING, or race-condition branch).
     * Ensures the entry exists, merges handler and URL options, and updates window.scanStatusApiUrls when URLs are provided.
     */
    const mergeScanStatusOptions = function(optionsMap, key, options) {
        if (!options) {
            return;
        }
        if (!optionsMap.get(key)) {
            optionsMap.set(key, {});
        }
        const entry = optionsMap.get(key);
        if (options.updateTable && !entry.updateTable) {
            entry.updateTable = options.updateTable;
        }
        if (options.updateDetail && !entry.updateDetail) {
            entry.updateDetail = options.updateDetail;
        }
        if (options.updateSidebar && !entry.updateSidebar) {
            entry.updateSidebar = options.updateSidebar;
        }
        if (options.updateSubscanTable && !entry.updateSubscanTable) {
            entry.updateSubscanTable = options.updateSubscanTable;
        }
        if (options.subscanTable && !entry.subscanTable) {
            entry.subscanTable = options.subscanTable;
        }
        const hasUrls = options.scanStatusUrl || options.stopScanUrl || options.stopActivityUrl || options.fetchSubscanUrl;
        if (hasUrls && !window.scanStatusApiUrls) {
            window.scanStatusApiUrls = {};
        }
        if (options.scanStatusUrl) {
            entry.scanStatusUrl = options.scanStatusUrl;
            window.scanStatusApiUrls.scanStatusUrl = options.scanStatusUrl;
        }
        if (options.stopScanUrl) {
            entry.stopScanUrl = options.stopScanUrl;
            window.scanStatusApiUrls.stopScanUrl = options.stopScanUrl;
        }
        if (options.stopActivityUrl) {
            entry.stopActivityUrl = options.stopActivityUrl;
            window.scanStatusApiUrls.stopActivityUrl = options.stopActivityUrl;
        }
        if (options.fetchSubscanUrl) {
            entry.fetchSubscanUrl = options.fetchSubscanUrl;
            window.scanStatusApiUrls.fetchSubscanUrl = options.fetchSubscanUrl;
        }
    };

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
    const existingSocket = scanStatusWebSocketsMap.get(key);
    if (existingSocket) {
        const { readyState } = existingSocket;
        // WebSocket.CONNECTING = 0, WebSocket.OPEN = 1, WebSocket.CLOSING = 2, WebSocket.CLOSED = 3
        if (readyState === WebSocket.OPEN) {
            mergeScanStatusOptions(scanStatusOptionsMap, key, options);
            return;
        } else if (readyState === WebSocket.CONNECTING) {
            mergeScanStatusOptions(scanStatusOptionsMap, key, options);
            return;
        } else {
            // Connection is CLOSING or CLOSED, close it properly and clear any pending reconnect
            const timeoutId = scanStatusReconnectTimeoutsMap.get(key);
            if (timeoutId) {
                clearTimeout(timeoutId);
                scanStatusReconnectTimeoutsMap.delete(key);
            }
            existingSocket.close();
            scanStatusWebSocketsMap.delete(key);
        }
    }
    
    // Check if a connection is being established (race condition protection)
    if (scanStatusConnectingMap.get(key)) {
        mergeScanStatusOptions(scanStatusOptionsMap, key, options);
        return;
    }
    
    // Mark that we're connecting
    scanStatusConnectingMap.set(key, true);
    
    // Store options for this connection
    scanStatusOptionsMap.set(key, options || {});
    
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
        scanStatusWebSocketsMap.set(key, socket);
        scanStatusReconnectAttemptsMap.set(key, 0);
        
        socket.onopen = function(event) {
            scanStatusReconnectAttemptsMap.set(key, 0);
            scanStatusConnectingMap.set(key, false);
            // Refresh sidebar once so status is current (e.g. if BACKGROUND SYNC completed while page was loading)
            if (key.startsWith('project-') && typeof getScanStatusSidebar === 'function') {
                const projectSlug = key.replace(/^project-/, '');
                const endpointUrl = window.scanStatusApiUrls?.scanStatusUrl;
                const stopScanUrl = window.scanStatusApiUrls?.stopScanUrl;
                const stopActivityUrl = window.scanStatusApiUrls?.stopActivityUrl;
                const fetchSubscanUrl = window.scanStatusApiUrls?.fetchSubscanUrl;
                if (endpointUrl && stopScanUrl && stopActivityUrl && fetchSubscanUrl) {
                    getScanStatusSidebar(endpointUrl, stopScanUrl, stopActivityUrl, fetchSubscanUrl, { project: projectSlug, reload: false });
                }
            }
        };
        
        socket.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                // Use stored options for this connection
                handleScanStatusUpdate(data, scanStatusOptionsMap.get(key));
            } catch (e) {
                console.error('Error parsing WebSocket message:', e);
            }
        };
        
        socket.onclose = function(event) {
            scanStatusWebSocketsMap.delete(key);
            // Clear connecting flag
            scanStatusConnectingMap.set(key, false);
            
            // Attempt to reconnect if not a normal closure
            if (event.code !== 1000 && (scanStatusReconnectAttemptsMap.get(key) || 0) < MAX_RECONNECT_ATTEMPTS) {
                const attempts = (scanStatusReconnectAttemptsMap.get(key) || 0) + 1;
                const delay = INITIAL_RECONNECT_DELAY * Math.pow(2, attempts - 1);
                scanStatusReconnectAttemptsMap.set(key, attempts);
                
                scanStatusReconnectTimeoutsMap.set(key, setTimeout(function() {
                    connectScanStatusWebSocket(scanId, projectSlug, scanStatusOptionsMap.get(key));
                }, delay));
            } else {
                // Clean up options and any pending reconnect timeout if connection is permanently closed
                const timeoutId = scanStatusReconnectTimeoutsMap.get(key);
                if (timeoutId) {
                    clearTimeout(timeoutId);
                    scanStatusReconnectTimeoutsMap.delete(key);
                }
                scanStatusOptionsMap.delete(key);
                scanStatusConnectingMap.delete(key);
            }
        };
        
        socket.onerror = function(error) {
            console.error('Scan status WebSocket error for', key + ':', error);
            // Clear connecting flag on error
            scanStatusConnectingMap.set(key, false);
        };
    } catch (e) {
        console.error('Error creating scan status WebSocket for', key + ':', e);
        // Clear connecting flag on exception
        scanStatusConnectingMap.set(key, false);
    }
};

/**
 * Update command outputs in the logs modal in real-time
 * @param {object} data - Update data from WebSocket with commands array
 */
const updateCommandOutputs = function(data) {
    if (!data || !data.commands || !Array.isArray(data.commands) || data.commands.length === 0) {
        return;
    }
    
    // Check if the logs modal is open
    const modal = document.getElementById('modal-xl-scroll-dialog');
    if (!modal) {
        return;
    }
    
    // Check if modal is visible (Bootstrap adds 'show' class and removes 'display: none')
    const isModalOpen = modal.classList.contains('show') && 
                       (typeof $ !== 'undefined' ? $('#modal-xl-scroll-dialog').is(':visible') : 
                        window.getComputedStyle(modal).display !== 'none');
    
    if (!isModalOpen) {
        return;
    }
    
    // Find the modal content container
    const modalContent = document.getElementById('xl-modal-content');
    if (!modalContent) {
        return;
    }

    /**
     * Decide whether we should auto-scroll a specific output container
     * based on the user's current scroll position in that container.
     *
     * We track "auto-scroll enabled" per container via a data attribute
     * so that scrolling in one container does not affect others.
     *
     * @param {HTMLElement} container - The output container being updated
     * @returns {boolean} - true if we should auto-scroll this container
     */
    const shouldAutoScrollContainer = function(container) {
        if (!container) {
            return false;
        }

        const { scrollTop, scrollHeight, clientHeight } = container;

        // Consider "near bottom" if within 100px of bottom
        const nearBottom = (scrollHeight - scrollTop - clientHeight) < 100;

        // Persist per-container preference: if user is near bottom, keep auto-scroll on;
        // if they scroll up, we stop auto-scrolling for this container.
        if (nearBottom) {
            container.dataset.autoScroll = 'true';
        } else if (container.dataset.autoScroll === undefined) {
            container.dataset.autoScroll = 'true';
        } else {
            container.dataset.autoScroll = 'false';
        }

        return container.dataset.autoScroll === 'true';
    };

    /**
     * Auto-scroll a specific output container if appropriate.
     *
     * @param {HTMLElement} container - The output container being updated
     */
    const maybeAutoScrollContainer = function(container) {
        if (!container) {
            return;
        }

        if (shouldAutoScrollContainer(container)) {
            container.scrollTop = container.scrollHeight;
        }
    };
    
    // Filter commands by activity context if modal is opened for specific activity
    let commandsToUpdate = data.commands;
    if (window.currentLogsModalContext) {
        const context = window.currentLogsModalContext;
        commandsToUpdate = data.commands.filter(function(command) {
            // Filter by activity_id if available
            if (context.activity_id && command.activity_id) {
                return command.activity_id === context.activity_id;
            }
            // Filter by runner_id if available
            if (context.runner_id && command.runner_id) {
                return command.runner_id === context.runner_id;
            }
            // If no filter matches, include all commands
            return true;
        });
    }
    
    const H = (typeof window !== 'undefined' && window.CommandLogHelpers) || {};
    const statusToBadge = H.getStatusBadgeInfo || function(s) {
        return { class: 'badge-soft-secondary', text: (s || 'PENDING') + '' };
    };
    const effectiveStatus = H.getEffectiveCommandStatus || function(cmd) {
        return (cmd.status_string != null && cmd.status_string !== '') ? cmd.status_string : cmd.status;
    };
    const escapeHtml = H.escapeHtml || function(text) {
        if (text == null || text === '') return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };
    const formatRelativeTime = H.formatRelativeTime || function(iso) { return iso || ''; };
    const formatDuration = H.formatDuration || function(sec) { return sec != null ? sec.toFixed(1) + 's' : ''; };
    const getDurationSeconds = H.getDurationSeconds || function() { return null; };
    const findDetailRow = H.findDetailRow || function() { return null; };
    const setDetailRow = H.setDetailRow || function() {};
    const setReturnCodeRow = H.setReturnCodeRow || function() {};
    const setDurationRow = H.setDurationRow || function() {};

    const ensureDetailBlock = function(commandElement, command) {
        const collapseId = 'collapse-command-' + command.id;
        let collapseEl = commandElement.querySelector('.collapse#' + collapseId);
        if (collapseEl) {
            const body = collapseEl.querySelector('.card-body');
            if (body) return body;
        }
        const hasAny = command.time || command.end_time != null || command.elapsed != null ||
            command.return_code != null || command.output ||
            (command.formatted_output && command.formatted_output.formatted) ||
            command.command || command.cwd;
        if (!hasAny) return null;
        collapseEl = document.createElement('div');
        collapseEl.className = 'collapse';
        collapseEl.id = collapseId;
        const cardBody = document.createElement('div');
        cardBody.className = 'card card-body mt-2';
        collapseEl.appendChild(cardBody);
        commandElement.appendChild(collapseEl);
        return cardBody;
    };

    /**
     * Find the .command-log-children container for the workflow identified by ancestorId.
     * Uses data-attribute comparison instead of querySelector with escaped strings to avoid
     * breakage on special characters. DOM: each .command-log-group contains one
     * .command-log-entry (scan/workflow/task); workflows have data-command-name set.
     */
    const findWorkflowChildrenContainer = function(container, ancestorId) {
        const groups = container.querySelectorAll('.command-log-group');
        for (let i = 0; i < groups.length; i++) {
            const entry = groups[i].querySelector('.command-log-entry[data-runner-type="workflow"]');
            if (entry && entry.getAttribute('data-command-name') === ancestorId) {
                let children = groups[i].querySelector(':scope > .command-log-children');
                if (!children) {
                    children = document.createElement('div');
                    children.className = 'command-log-children ms-3';
                    groups[i].appendChild(children);
                }
                return children;
            }
        }
        return null;
    };

    /**
     * Insert a new command row into the logs modal. DOM structure:
     * - modalContent contains .command-log-group elements; each group has one .command-log-entry (scan | workflow | task).
     * - Scan groups are at top level. Workflow groups are under the last scan group, inside .command-log-children.
     * - Task groups are under their parent workflow group (matched by ancestor_id === workflow's data-command-name), inside .command-log-children.
     */
    const insertCommandRow = function(cmd) {
        const createEl = typeof window.create_log_element === 'function' ? window.create_log_element : null;
        if (!createEl) {
            return;
        }
        const entryEl = createEl(cmd);
        const runnerType = (cmd.runner_type || '').toLowerCase();

        if (runnerType === 'scan') {
            const wrapper = document.createElement('div');
            wrapper.className = 'command-log-group';
            wrapper.appendChild(entryEl);
            modalContent.appendChild(wrapper);
            return;
        }
        if (runnerType === 'workflow') {
            const wrapper = document.createElement('div');
            wrapper.className = 'command-log-group';
            wrapper.appendChild(entryEl);
            const scanGroups = modalContent.querySelectorAll('.command-log-group');
            let lastScanGroup = null;
            for (let i = scanGroups.length - 1; i >= 0; i--) {
                const entry = scanGroups[i].querySelector('.command-log-entry[data-runner-type="scan"]');
                if (entry) {
                    lastScanGroup = scanGroups[i];
                    break;
                }
            }
            if (!lastScanGroup) {
                modalContent.appendChild(wrapper);
                return;
            }
            let children = lastScanGroup.querySelector(':scope > .command-log-children');
            if (!children) {
                children = document.createElement('div');
                children.className = 'command-log-children ms-3';
                lastScanGroup.appendChild(children);
            }
            children.appendChild(wrapper);
            return;
        }
        if (runnerType === 'task') {
            const ancestorId = cmd.ancestor_id || '';
            const parentChildren = findWorkflowChildrenContainer(modalContent, ancestorId);
            if (parentChildren) {
                parentChildren.appendChild(entryEl);
            } else {
                const wrapper = document.createElement('div');
                wrapper.className = 'command-log-group';
                wrapper.appendChild(entryEl);
                modalContent.appendChild(wrapper);
            }
        } else {
            const wrapper = document.createElement('div');
            wrapper.className = 'command-log-group';
            wrapper.appendChild(entryEl);
            modalContent.appendChild(wrapper);
        }
    };

    // Update each command output and status badge
    commandsToUpdate.forEach(function(command) {
        if (!command.id) {
            return;
        }

        let commandElement = modalContent.querySelector('[data-command-id="' + command.id + '"]');
        if (!commandElement) {
            insertCommandRow(command);
            return;
        }

        const statusForBadge = effectiveStatus(command);
        if (statusForBadge !== undefined && statusForBadge !== null) {
            const header = commandElement.querySelector('.command-log-header');
            if (header) {
                const badge = header.querySelector('.badge');
                if (badge) {
                    const badgeInfo = statusToBadge(statusForBadge);
                    badge.className = 'badge ' + badgeInfo.class;
                    badge.textContent = badgeInfo.text;
                }
            }
        }

        const durationSec = getDurationSeconds(command);
        const header = commandElement.querySelector('.command-log-header');
        if (header) {
            let headerDurationSpan = header.querySelector('.command-log-header-duration');
            if (durationSec != null) {
                const headerDurationStr = '(' + durationSec.toFixed(2) + 's)';
                if (headerDurationSpan) {
                    headerDurationSpan.textContent = headerDurationStr;
                } else {
                    headerDurationSpan = document.createElement('span');
                    headerDurationSpan.className = 'text-muted small command-log-header-duration';
                    headerDurationSpan.textContent = headerDurationStr;
                    const badge = header.querySelector('.badge');
                    (badge ? badge.parentNode : header).appendChild(headerDurationSpan);
                }
            } else if (headerDurationSpan) {
                headerDurationSpan.remove();
            }
        }

        const cardBody = ensureDetailBlock(commandElement, command);
        if (cardBody) {
            setDetailRow(cardBody, 'Time:', command.time ? formatRelativeTime(command.time) : null);
            setDetailRow(cardBody, 'End Time:', command.end_time ? formatRelativeTime(command.end_time) : null);
            setDurationRow(cardBody, durationSec != null ? formatDuration(durationSec) : null);
            setReturnCodeRow(cardBody, command.return_code);
        }

        let outputElement = commandElement.querySelector('.command-output');
        const hasOutput = command.output || (command.formatted_output && command.formatted_output.formatted);
        if (hasOutput && !outputElement && cardBody) {
            const outputWrap = document.createElement('div');
            outputWrap.className = 'mb-2';
            outputWrap.innerHTML = '<strong>Output:</strong>';
            const pre = document.createElement('pre');
            pre.className = 'command-output mt-2 p-3 bg-dark text-light rounded';
            pre.setAttribute('style', 'font-family: \'Courier New\', monospace; font-size: 0.875rem; white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;');
            outputWrap.appendChild(pre);
            cardBody.appendChild(outputWrap);
            outputElement = pre;
        }

        if (outputElement) {
            const statusStr = (command.status_string != null && command.status_string !== '') ? command.status_string : command.status;
            const skipOutputUpdate = command.end_time && statusStr !== 'RUNNING';
            if (!skipOutputUpdate) {
                let outputHtml = '';
                if (command.formatted_output && command.formatted_output.formatted) {
                    outputHtml = command.formatted_output.formatted;
                } else if (command.output) {
                    const div = document.createElement('div');
                    div.textContent = command.output;
                    outputHtml = div.innerHTML;
                }
                if (typeof outputElement._lastRenderedHtml === 'undefined') {
                    outputElement._lastRenderedHtml = '';
                }
                if (outputHtml !== outputElement._lastRenderedHtml) {
                    outputElement.innerHTML = outputHtml;
                    outputElement._lastRenderedHtml = outputHtml;
                    maybeAutoScrollContainer(outputElement);
                }
            }
        }
    });
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
    
    // Update command outputs in real-time if commands are present
    if (data.commands && Array.isArray(data.commands) && data.commands.length > 0) {
        updateCommandOutputs(data);
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

        if (data.subscans && Array.isArray(data.subscans) && data.subscans.length > 0) {
            if (options.updateSubscanTable && typeof options.updateSubscanTable === 'function') {
                options.updateSubscanTable(data);
            } else if (options.updateSubscanTable && options.subscanTable) {
                updateSubscanRowInTable(options.subscanTable, data);
            }
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
                    window._scanTableReloadTimeout = new Map();
                }
                const timeoutKey = 'table_reload';
                if (window._scanTableReloadTimeout.get(timeoutKey)) {
                    clearTimeout(window._scanTableReloadTimeout.get(timeoutKey));
                }
                window._scanTableReloadTimeout.set(timeoutKey, setTimeout(function() {
                    table.ajax.reload(null, false); // false = don't reset paging
                    window._scanTableReloadTimeout.delete(timeoutKey);
                }, 500)); // Short delay to ensure scan is in DB
            } else {
                // For non-AJAX tables, reload the page after a short delay to show new scans
                // Use a debounce mechanism to avoid multiple reloads
                if (!window._scanTablePageReloadTimeout) {
                    window._scanTablePageReloadTimeout = new Map();
                }
                const timeoutKey = 'page_reload';
                if (window._scanTablePageReloadTimeout.get(timeoutKey)) {
                    clearTimeout(window._scanTablePageReloadTimeout.get(timeoutKey));
                }
                window._scanTablePageReloadTimeout.set(timeoutKey, setTimeout(function() {
                    window.location.reload();
                    window._scanTablePageReloadTimeout.delete(timeoutKey);
                }, 500)); // Short delay to ensure scan is in DB
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
                    formatNumber(subdomainCount) + '</span> ' +
                    '<span class="badge badge-pills bg-warning mt-1" data-toggle="tooltip" data-placement="top" title="Endpoints">' + 
                    formatNumber(endpointCount) + '</span> ' +
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
 * Update subscan rows in DataTable (for subscan_history.html).
 * If a subscan has no row in the DOM (new subscan), triggers a page reload with debounce.
 * @param {DataTable} table - DataTable instance
 * @param {object} data - Update data with subscans array
 */
const updateSubscanRowInTable = function(table, data) {
    if (!table || !data || !data.subscans || !Array.isArray(data.subscans)) {
        return;
    }

    try {
        let hasNewSubscan = false;
        data.subscans.forEach(function(item) {
            const subscanId = item.subscan_id;
            if (subscanId == null) {
                return;
            }

            const rowNode = document.querySelector('tr[data-subscan-id="' + subscanId + '"]');
            if (!rowNode) {
                hasNewSubscan = true;
                return;
            }

            const status = item.status != null ? item.status : -1;
            const progress = item.progress != null ? item.progress : 0;
            const currentTask = item.task_name || '';

            const statusCell = $(rowNode).find('.scan-status-cell');
            if (statusCell.length) {
                statusCell.html(getStatusBadgeHtml(status, currentTask, null));
            }

            const progressCell = $(rowNode).find('.scan-progress-cell');
            if (progressCell.length) {
                progressCell.html(getProgressBarHtml(status, progress));
            }

            if (item.scan_engine_used != null && item.scan_engine_used !== '') {
                const engineCell = $(rowNode).find('.scan-engine-cell');
                if (engineCell.length) {
                    const engineHtml = '<span class="badge badge-soft-primary">' + escapeHtml(String(item.scan_engine_used)) + '</span>';
                    engineCell.html(engineHtml);
                }
            }

            if (typeof $ !== 'undefined' && $.fn.tooltip) {
                $(rowNode).find('[data-toggle="tooltip"]').tooltip();
            }
        });

        if (hasNewSubscan && !window._subscanTableReloadTimeout) {
              window._subscanTableReloadTimeout = setTimeout(function() {
                  window.location.reload();
                  window._subscanTableReloadTimeout = null;
              }, 500);
        }
    } catch (e) {
        console.error('Error updating subscan row in table:', e);
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
        
        // Update existing timeline items instead of removing them
        // This preserves Logs links and Stop buttons. Use Map to avoid prototype pollution from item.id/runnerId.
        const existingItemsMap = new Map();
        const existingItems = timelineList.querySelectorAll('[data-runner-id]');
        existingItems.forEach(function(item) {
            const runnerId = item.getAttribute('data-runner-id');
            if (runnerId) {
                existingItemsMap.set(runnerId, item);
            }
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
        
        // Sort: running first, then error, success, aborted, skipped, other; within each group by hierarchy (scan > workflow > task) then most recent first
        const statusConst = window.RENGINE_SCAN_STATUS || {};
        const statusOrder = function(s) {
            if (s === statusConst.RUNNING_TASK || s === statusConst.RUNNING_BACKGROUND) return 0;
            if (s === statusConst.FAILED_TASK) return 1;
            if (s === statusConst.SUCCESS_TASK) return 2;
            if (s === statusConst.ABORTED_TASK) return 3;
            if (s === statusConst.SKIPPED_TASK) return 4;
            return 5; // INITIATED_TASK, other
        };
        const hierarchyOrder = function(type) {
            const t = (type || '').toLowerCase();
            if (t === 'scan') return 0;
            if (t === 'workflow') return 1;
            if (t === 'task') return 2;
            return 3;
        };
        itemsToRender.sort(function(a, b) {
            const orderA = statusOrder(a.status);
            const orderB = statusOrder(b.status);
            if (orderA !== orderB) return orderA - orderB;
            const typeA = hierarchyOrder(a.type || a.runner_type);
            const typeB = hierarchyOrder(b.type || b.runner_type);
            if (typeA !== typeB) return typeA - typeB;
            const timeA = new Date(a.time || 0).getTime();
            const timeB = new Date(b.time || 0).getTime();
            return timeB - timeA;
        });
        
        // Get project slug and URLs from options or global variables
        const projectSlug = data.project_slug || (function() {
            const urlMatch = window.location.pathname.match(/\/scan\/([^\/]+)\//);
            return urlMatch ? urlMatch[1] : null;
        })();
        const stopActivityUrl = (scanStatusOptionsMap.get('scan-' + data.scan_id) && scanStatusOptionsMap.get('scan-' + data.scan_id).stopActivityUrl) || 
                                window.scanStatusApiUrls?.stopActivityUrl || 
                                '/api/stop-activity/';
        const dateTimeFormatOpts = {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        };
        const dateTimeLocale = 'en-US';
        
        // Update or add timeline items; new items are stored in map so we can reorder DOM after
        itemsToRender.forEach(function(item) {
            let listItem = existingItemsMap.get(item.id);
            const isNew = !listItem;
            
            if (isNew) {
                listItem = document.createElement('li');
                listItem.setAttribute('data-runner-id', item.id);
                if (item.activity_id) {
                    listItem.setAttribute('data-activity-id', item.activity_id);
                }
                existingItemsMap.set(item.id, listItem);
            } else if (item.activity_id) {
                listItem.setAttribute('data-activity-id', item.activity_id);
            }
            
            // Determine class based on status
            // status: -1 = PENDING, 0 = FAILURE, 1 = RUNNING, 2 = SUCCESS, 3 = REVOKED, 5 = SKIPPED_TASK
            if (item.status === 2) {
                listItem.className = 'completed';
            } else if (item.status === 1) {
                listItem.className = 'running';
            } else if (item.status === 3) {
                listItem.className = 'aborted';
            } else if (item.status === 0) {
                listItem.className = 'failed';
            } else if (item.status === statusConst.SKIPPED_TASK) {
                listItem.className = 'skipped';
            } else {
                listItem.className = 'pending';
            }
            
            // Determine badge class and text
            let statusClass = 'badge-soft-secondary';
            let statusText = 'Pending';
            if (item.status === 0) {
                statusClass = 'badge-soft-danger';
                statusText = 'Failed';
            } else if (item.status === -1) {
                statusClass = 'badge-soft-secondary';
                statusText = 'Pending';
            } else if (item.status === 1) {
                statusClass = 'badge-soft-info';
                statusText = 'In progress';
            } else if (item.status === 2) {
                statusClass = 'badge-soft-success';
                statusText = 'Completed';
            } else if (item.status === 3) {
                statusClass = 'badge-soft-danger';
                statusText = 'Aborted';
            } else if (item.status === statusConst.SKIPPED_TASK) {
                statusClass = 'badge-soft-info';
                statusText = 'Skipped';
            }
            
            // Format time: relative (e.g. "6 minutes ago") and absolute (e.g. "Feb. 1, 2026, 11:36 p.m.")
            let timeText = '';
            let timeAbsoluteText = '';
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
                        timeText = timeDate.toLocaleString(dateTimeLocale, dateTimeFormatOpts);
                    }
                    timeAbsoluteText = timeDate.toLocaleString(dateTimeLocale, dateTimeFormatOpts);
                } catch (e) {
                    timeText = item.time;
                    timeAbsoluteText = item.time;
                }
            }
            
            // Build progress HTML if available
            let progressHtml = '';
            if (item.progress !== null && item.progress !== undefined) {
                progressHtml = '<p class="text-muted mb-0"><small>Progress: ' + item.progress + '%</small></p>';
            }
            
            // Build stop button HTML if running
            let stopButtonHtml = '';
            if (item.status === 1 && item.activity_id) {
                stopButtonHtml = '<span class="float-end"><a href="#" onclick="stop_activity(\'' + stopActivityUrl + '\', activity_id=' + item.activity_id + ', reload_scan_bar=true, reload_location=true); return false;" class="btn btn-xs btn-soft-danger waves-effect waves-light"><i class="fe-alert-triangle"></i> Stop</a></span>';
            }
            
            // Build logs link HTML
            let logsLinkHtml = '';
            if (item.activity_id && projectSlug) {
                logsLinkHtml = '<span><a href="javascript:get_logs_modal(null, ' + item.activity_id + ', \'' + projectSlug + '\', ' + item.id + ')"><i class="fe-file"></i> Logs</a></span>';
            }
            
            // Build error message HTML if failed
            let errorHtml = '';
            if ((item.status === 0 || item.status === -1) && item.error_message) {
                errorHtml = '<p class="badge badge-soft-danger">Error: ' + escapeHtml(item.error_message) + '</p>';
            }
            
            listItem.innerHTML = '<h5 class="mt-0 mb-1">' + 
                escapeHtml(item.title || item.name) +
                '<span class="float-end badge ' + statusClass + ' mt-1">' + statusText + 
                (item.status === 1 ? '<span class="active-dot dot"></span>' : '') +
                '</span></h5>' +
                '<p class="text-muted mb-0">' + timeText + 
                (timeAbsoluteText ? '<br><small class="text-muted mb-0">' + escapeHtml(timeAbsoluteText) + '</small>' : '') +
                '</p>' +
                progressHtml +
                stopButtonHtml +
                logsLinkHtml +
                errorHtml;
        });

        // Reorder DOM to match sorted order (running first, then by time) so "In progress" moves to top on WebSocket update
        itemsToRender.forEach(function(item) {
            const listItem = existingItemsMap.get(item.id);
            if (listItem) {
                timelineList.appendChild(listItem);
            }
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
        
        // Find scan card in sidebar first to avoid updating wrong element on pages with duplicate IDs
        const sidebar = document.querySelector('.right-bar[data-scan-sidebar="true"]');
        const scanCard = (sidebar && sidebar.querySelector('#scan-card-' + data.scan_id))
            || document.querySelector('#scan-card-' + data.scan_id);
        
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
                    getScanStatusSidebar(endpointUrl, stopScanUrl, stopActivityUrl, fetchSubscanUrl, { project: projectSlug, reload: false });
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
        iconClass += 'info';
        badgeClass += 'info';
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
    if (typeof window !== 'undefined' && window.CommandLogHelpers && window.CommandLogHelpers.escapeHtml) {
        return window.CommandLogHelpers.escapeHtml(text);
    }
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
};

/**
 * Disconnect all scan status WebSockets
 */
const disconnectAllScanStatusWebSockets = function() {
    for (const key of scanStatusWebSocketsMap.keys()) {
        const socket = scanStatusWebSocketsMap.get(key);
        if (socket) {
            socket.close();
            scanStatusWebSocketsMap.delete(key);
        }
    }
    
    for (const key of scanStatusReconnectTimeoutsMap.keys()) {
        const timeoutId = scanStatusReconnectTimeoutsMap.get(key);
        if (timeoutId) {
            clearTimeout(timeoutId);
            scanStatusReconnectTimeoutsMap.delete(key);
        }
    }
    
    // Clear options and connecting flags
    for (const key of scanStatusOptionsMap.keys()) {
        scanStatusOptionsMap.delete(key);
    }
    for (const key of scanStatusConnectingMap.keys()) {
        scanStatusConnectingMap.delete(key);
    }
};

    // Clean up on page unload
    window.addEventListener('beforeunload', function() {
        disconnectAllScanStatusWebSockets();
    });
    
    // Expose functions globally so they can be called from other scripts
    window.connectScanStatusWebSocket = connectScanStatusWebSocket;
    window.handleScanStatusUpdate = handleScanStatusUpdate;
    window.updateCommandOutputs = updateCommandOutputs;
    window.updateScanRowInTable = updateScanRowInTable;
    window.updateSubscanRowInTable = updateSubscanRowInTable;
    window.updateScanDetailPage = updateScanDetailPage;
    window.updateRightSidebar = updateRightSidebar;
    window.disconnectAllScanStatusWebSockets = disconnectAllScanStatusWebSockets;
})();
