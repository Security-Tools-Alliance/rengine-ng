/**
 * Secator Integration JavaScript
 */

// Global Secator object
window.Secator = {
    // Configuration
    config: {
        apiBaseUrl: '/api/',
        csrfToken: null,
        debounceDelay: 500
    },
    
    // Initialize
    init: function() {
        this.config.csrfToken = this.getCookie('csrftoken');
        this.bindEvents();
        this.initializeComponents();
    },
    
    // Bind global events
    bindEvents: function() {
        // Global form submissions
        document.addEventListener('submit', this.handleFormSubmit.bind(this));
        
        // Global AJAX error handling
        document.addEventListener('ajaxError', this.handleAjaxError.bind(this));
    },
    
    // Initialize components
    initializeComponents: function() {
        // Initialize tooltips
        if (typeof $ !== 'undefined' && $.fn.tooltip) {
            $('[data-toggle="tooltip"]').tooltip();
        }
        
        // Initialize modals
        this.initializeModals();
        
        // Initialize filters
        this.initializeFilters();
    },
    
    // Initialize modals
    initializeModals: function() {
        // Auto-focus first input in modals
        $('.modal').on('shown.bs.modal', function() {
            $(this).find('input:first').focus();
        });
        
        // Clear form data when modal is hidden
        $('.modal').on('hidden.bs.modal', function() {
            $(this).find('form')[0]?.reset();
            $(this).find('.alert').remove();
        });
    },
    
    // Initialize filters
    initializeFilters: function() {
        // Debounced search
        let searchTimeout;
        $('.secator-search-input').on('input', function() {
            clearTimeout(searchTimeout);
            const input = this;
            searchTimeout = setTimeout(() => {
                Secator.performSearch(input.value);
            }, Secator.config.debounceDelay);
        });
        
        // Filter dropdowns
        $('.secator-filter-select').on('change', function() {
            Secator.applyFilters();
        });
    },
    
    // Handle form submissions
    handleFormSubmit: function(event) {
        const form = event.target;
        if (form.classList.contains('secator-form')) {
            event.preventDefault();
            this.submitForm(form);
        }
    },
    
    // Utility function for robust AJAX requests
    makeRequest: function(url, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'X-CSRFToken': this.config.csrfToken,
                'Content-Type': 'application/json',
            },
        };
        
        const requestOptions = { ...defaultOptions, ...options };
        
        return fetch(url, requestOptions)
            .then(response => {
                // Check if response is ok (status 200-299)
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                // Check if response is JSON
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    throw new Error('Server returned non-JSON response');
                }
                
                return response.json();
            })
            .catch(error => {
                console.error('AJAX Error:', error);
                
                // Provide user-friendly error messages
                let errorMessage = 'An unexpected error occurred. Please try again.';
                
                if (error.message.includes('HTTP 404')) {
                    errorMessage = 'The requested resource was not found.';
                } else if (error.message.includes('HTTP 403')) {
                    errorMessage = 'You do not have permission to perform this action.';
                } else if (error.message.includes('HTTP 500')) {
                    errorMessage = 'A server error occurred. Please try again later.';
                } else if (error.message.includes('non-JSON')) {
                    errorMessage = 'Server returned an invalid response. Please try again.';
                } else if (error.message.includes('Failed to fetch')) {
                    errorMessage = 'Network error. Please check your connection and try again.';
                }
                
                throw new Error(errorMessage);
            });
    },

    // Submit form via AJAX
    submitForm: function(form) {
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        const url = form.action || form.dataset.action;
        const method = form.method || 'POST';
        
        this.showLoading(form);
        
        this.makeRequest(url, {
            method: method,
            body: JSON.stringify(data),
        })
        .then(data => {
            this.hideLoading(form);
            if (data.status === 'success') {
                this.showSuccess(data.message);
                if (form.dataset.redirect) {
                    window.location.href = form.dataset.redirect;
                } else if (form.dataset.reload) {
                    location.reload();
                }
            } else {
                this.showError(data.message || 'Operation failed');
            }
        })
        .catch(error => {
            this.hideLoading(form);
            this.showError(error.message);
        });
    },
    
    // Perform search
    performSearch: function(query) {
        const url = new URL(window.location);
        if (query) {
            url.searchParams.set('search', query);
        } else {
            url.searchParams.delete('search');
        }
        window.location.href = url.toString();
    },
    
    // Apply filters
    applyFilters: function() {
        const url = new URL(window.location);
        const filters = {};
        
        $('.secator-filter-select').each(function() {
            const filter = this.dataset.filter;
            const value = this.value;
            if (value && value !== 'all') {
                filters[filter] = value;
            }
        });
        
        // Update URL with filters
        Object.keys(filters).forEach(key => {
            url.searchParams.set(key, filters[key]);
        });
        
        // Remove empty filters
        $('.secator-filter-select').each(function() {
            const filter = this.dataset.filter;
            if (!filters[filter]) {
                url.searchParams.delete(filter);
            }
        });
        
        window.location.href = url.toString();
    },
    
    // Show loading state
    showLoading: function(element) {
        const button = element.querySelector('button[type="submit"]');
        if (button) {
            // Store original text if not already stored
            if (!button.dataset.originalText) {
                button.dataset.originalText = button.innerHTML;
            }
            
            button.disabled = true;
            button.innerHTML = '<span class="secator-loading"></span> Loading...';
        }
    },
    
    // Hide loading state
    hideLoading: function(element) {
        const button = element.querySelector('button[type="submit"]');
        if (button) {
            button.disabled = false;
            // Restore original text, fallback to default if not available
            button.innerHTML = button.dataset.originalText || 'Submit';
        }
    },
    
    // Show success message
    showSuccess: function(message) {
        this.showAlert('success', message);
    },
    
    // Show error message
    showError: function(message) {
        this.showAlert('danger', message);
    },
    
    // Show alert
    showAlert: function(type, message) {
        const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
        const alertHtml = `
            <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="close" data-dismiss="alert">
                    <span>&times;</span>
                </button>
            </div>
        `;

        // Find or create a container for alerts
        let alertContainer = document.getElementById('secator-alert-container');
        if (!alertContainer) {
            alertContainer = document.createElement('div');
            alertContainer.id = 'secator-alert-container';
            alertContainer.style.position = 'fixed';
            alertContainer.style.top = '20px';
            alertContainer.style.right = '20px';
            alertContainer.style.zIndex = '9999';
            alertContainer.style.maxWidth = '400px';
            document.body.appendChild(alertContainer);
        }

        // Create a temporary div to hold the alert HTML
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = alertHtml.trim();
        const alertElement = tempDiv.firstChild;

        // Add the alert to the container
        alertContainer.appendChild(alertElement);

        // Auto-dismiss this specific alert after 5 seconds
        setTimeout(() => {
            if (alertElement && alertElement.parentNode) {
                alertElement.classList.remove('show');
                alertElement.classList.add('fade');
                setTimeout(() => {
                    if (alertElement.parentNode) {
                        alertElement.parentNode.removeChild(alertElement);
                    }
                }, 300); // Bootstrap fade out duration
            }
        }, 5000);

        // Allow manual dismissal
        const closeButton = alertElement.querySelector('.close');
        if (closeButton) {
            closeButton.addEventListener('click', function() {
                if (alertElement.parentNode) {
                    alertElement.parentNode.removeChild(alertElement);
                }
            });
        }
    },
    
    // Get cookie value
    getCookie: function(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    },
    
    // Handle AJAX errors
    handleAjaxError: function(event) {
        this.showError('An error occurred while processing your request.');
    },
    
    // Utility functions
    utils: {
        // Format date
        formatDate: function(dateString) {
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        },
        
        // Truncate text
        truncateText: function(text, length = 100) {
            if (text.length <= length) return text;
            return text.substring(0, length) + '...';
        },
        
        // Copy to clipboard
        copyToClipboard: function(text) {
            navigator.clipboard.writeText(text).then(() => {
                Secator.showSuccess('Copied to clipboard!');
            }).catch(() => {
                Secator.showError('Failed to copy to clipboard');
            });
        },
        
        // Download file
        downloadFile: function(content, filename, type = 'text/plain') {
            const blob = new Blob([content], { type: type });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }
    }
};

// Workflow specific functions
window.SecatorWorkflows = {
    // Load built-in workflows
    loadBuiltin: function() {
        if (confirm('This will load built-in Secator workflows. Continue?')) {
            Secator.showAlert('info', 'Loading built-in workflows...');
            
            Secator.makeRequest(Secator.config.apiBaseUrl + 'workflows/load-builtin/', {
                method: 'POST',
            })
            .then(data => {
                if (data.status === 'success') {
                    Secator.showSuccess('Built-in workflows loading started. Please refresh the page in a few moments.');
                } else {
                    Secator.showError(data.message);
                }
            })
            .catch(error => {
                Secator.showError(error.message);
            });
        }
    }
};

// Task specific functions
window.SecatorTasks = {
    // Load built-in tasks
    loadBuiltin: function() {
        if (confirm('This will load built-in Secator tasks. Continue?')) {
            Secator.showAlert('info', 'Loading built-in tasks...');
            
            Secator.makeRequest(Secator.config.apiBaseUrl + 'tasks/load-builtin/', {
                method: 'POST',
            })
            .then(data => {
                if (data.status === 'success') {
                    Secator.showSuccess('Built-in tasks loading started. Please refresh the page in a few moments.');
                } else {
                    Secator.showError(data.message);
                }
            })
            .catch(error => {
                Secator.showError(error.message);
            });
        }
    },
    
    // Get available tasks
    getAvailable: function() {
        return Secator.makeRequest(Secator.config.apiBaseUrl + 'tasks/available/');
    },
    
    // Create task
    create: function(formData) {
        return Secator.makeRequest(Secator.config.apiBaseUrl + 'tasks/create/', {
            method: 'POST',
            body: JSON.stringify(formData),
        });
    },
    
    // Edit task
    edit: function(taskId, formData) {
        return Secator.makeRequest(Secator.config.apiBaseUrl + 'tasks/' + taskId + '/edit/', {
            method: 'PUT',
            body: JSON.stringify(formData),
        });
    },
    
    // Delete task
    delete: function(taskId) {
        return Secator.makeRequest(Secator.config.apiBaseUrl + 'tasks/' + taskId + '/delete/', {
            method: 'DELETE',
        });
    },
    
    // Get task details
    get: function(taskId) {
        return Secator.makeRequest(Secator.config.apiBaseUrl + 'tasks/' + taskId + '/');
    }
};

// Scan specific functions
window.SecatorScans = {
    // Create scan configuration
    create: function(formData) {
        return Secator.makeRequest(Secator.config.apiBaseUrl + 'scans/create/', {
            method: 'POST',
            body: JSON.stringify(formData),
        });
    },
    
    // Get available workflows
    getAvailableWorkflows: function() {
        return Secator.makeRequest(Secator.config.apiBaseUrl + 'workflows/available/');
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    Secator.init();
});

/**
 * Refresh a Secator table body via partial URL (tasks or workflows).
 * Used by tasks.html and workflows.html for dynamic search/filter without page reload.
 *
 * @param {string} partialUrl - URL that returns only tbody HTML (e.g. from Django url tag)
 * @param {string} filterSelectId - ID of the filter <select>
 * @param {string} searchInputId - ID of the search <input>
 * @param {string} tbodyId - ID of the <tbody> to replace
 * @param {number|function(): number} colCount - Number of columns or function returning it (for loading/error row colspan)
 * @param {string} [errorMessage] - Message shown on fetch error
 */
window.refreshSecatorTable = function(partialUrl, filterSelectId, searchInputId, tbodyId, colCount, errorMessage) {
    const filterEl = document.getElementById(filterSelectId);
    const searchEl = document.getElementById(searchInputId);
    const tbody = document.getElementById(tbodyId);
    if (!filterEl || !searchEl || !tbody) return;

    const cols = typeof colCount === 'function' ? colCount() : colCount;
    const filter = filterEl.value;
    const search = (searchEl.value || '').trim();
    const params = new URLSearchParams();
    params.set('filter', filter);
    if (search) params.set('search', search);
    const url = partialUrl + (params.toString() ? '?' + params.toString() : '');

    tbody.innerHTML = '<tr><td colspan="' + cols + '" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading...</td></tr>';
    fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function(response) {
            if (!response.ok) throw new Error('Request failed');
            return response.text();
        })
        .then(function(html) { tbody.innerHTML = html; })
        .catch(function() {
            tbody.innerHTML = '<tr><td colspan="' + cols + '" class="text-center text-danger">' + (errorMessage || 'Error loading data. Please refresh the page.') + '</td></tr>';
        });
};

/**
 * Create a debounced handler that calls refreshSecatorTable after a delay.
 * Used for search input to limit AJAX requests.
 *
 * @param {number} delayMs - Debounce delay in milliseconds
 * @param {string} partialUrl - Same as refreshSecatorTable
 * @param {string} filterSelectId - Same as refreshSecatorTable
 * @param {string} searchInputId - Same as refreshSecatorTable
 * @param {string} tbodyId - Same as refreshSecatorTable
 * @param {number|function(): number} colCount - Same as refreshSecatorTable
 * @param {string} [errorMessage] - Same as refreshSecatorTable
 * @returns {function} Handler that can be called on input/change
 */
window.debouncedRefreshSecatorTable = function(delayMs, partialUrl, filterSelectId, searchInputId, tbodyId, colCount, errorMessage) {
    let timer = null;
    return function() {
        clearTimeout(timer);
        timer = setTimeout(function() {
            window.refreshSecatorTable(partialUrl, filterSelectId, searchInputId, tbodyId, colCount, errorMessage);
        }, delayMs);
    };
};

// Export for use in other scripts
window.SecatorUtils = Secator.utils;
