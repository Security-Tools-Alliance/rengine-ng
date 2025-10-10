/**
 * AJAX Workflow Manager - Système réutilisable pour la gestion des workflows
 * 
 * Ce module fournit un système AJAX complet pour charger, filtrer et paginer
 * les workflows de manière dynamique et performante.
 */

class AjaxWorkflowManager {
    constructor(options = {}) {
        this.apiUrl = options.apiUrl || '/scanEngine/api/workflows/';
        this.containerSelector = options.containerSelector || '#workflows-container';
        this.paginationSelector = options.paginationSelector || '#workflows-pagination';
        this.filtersSelector = options.filtersSelector || '#workflows-filters';
        this.loadingSelector = options.loadingSelector || '#workflows-loading';
        this.searchSelector = options.searchSelector || '#workflow-search';
        this.typeSelector = options.typeSelector || '#workflow-type';
        
        this.currentPage = 1;
        this.currentType = 'all';
        this.currentSearch = '';
        this.perPage = 12;
        
        this.debounceTimeout = null;
        this.debounceDelay = 300;
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.loadWorkflows();
    }
    
    bindEvents() {
        // Search input with debouncing
        $(this.searchSelector).on('input', (e) => {
            clearTimeout(this.debounceTimeout);
            this.debounceTimeout = setTimeout(() => {
                this.currentSearch = e.target.value;
                this.currentPage = 1;
                this.loadWorkflows();
            }, this.debounceDelay);
        });
        
        // Type filter
        $(this.typeSelector).on('change', (e) => {
            this.currentType = e.target.value;
            this.currentPage = 1;
            this.loadWorkflows();
        });
        
        // Pagination
        $(document).on('click', '.pagination-link', (e) => {
            e.preventDefault();
            const page = $(e.target).data('page');
            if (page && page !== this.currentPage) {
                this.currentPage = page;
                this.loadWorkflows();
            }
        });
        
        // Refresh button
        $(document).on('click', '#refresh-workflows', (e) => {
            e.preventDefault();
            this.loadWorkflows();
        });
    }
    
    async loadWorkflows() {
        this.showLoading();
        
        try {
            const params = new URLSearchParams({
                action: 'list',
                type: this.currentType,
                search: this.currentSearch,
                page: this.currentPage,
                per_page: this.perPage
            });
            
            const response = await fetch(`${this.apiUrl}?${params}`, {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json',
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.renderWorkflows(data.workflows);
                this.renderPagination(data.pagination);
                this.updateFilters(data.counts);
                this.updateUrl();
            } else {
                throw new Error(data.message || 'Unknown error');
            }
            
        } catch (error) {
            console.error('Error loading workflows:', error);
            this.showError('Erreur lors du chargement des workflows: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }
    
    renderWorkflows(workflows) {
        const container = $(this.containerSelector);
        
        if (workflows.length === 0) {
            container.html(`
                <div class="col-12">
                    <div class="alert alert-info text-center">
                        <i class="fe-search me-2"></i>
                        Aucun workflow trouvé avec les critères actuels.
                    </div>
                </div>
            `);
            return;
        }
        
        const workflowsHtml = workflows.map(workflow => this.renderWorkflowCard(workflow)).join('');
        container.html(workflowsHtml);
    }
    
    renderWorkflowCard(workflow) {
        const badgeClass = this.getWorkflowBadgeClass(workflow.workflow_type);
        const badgeText = this.getWorkflowBadgeText(workflow.workflow_type);
        
        const tagsHtml = workflow.tags ? workflow.tags.slice(0, 3).map(tag => 
            `<span class="badge bg-primary me-1">${this.escapeHtml(tag)}</span>`
        ).join('') : '';
        
        const useCasesHtml = workflow.use_cases ? workflow.use_cases.slice(0, 3).map(useCase => 
            `<span class="badge bg-secondary me-1">${this.escapeHtml(useCase)}</span>`
        ).join('') : '';
        
        const editButton = workflow.can_edit ? `
            <a href="/scanEngine/workflows/${workflow.workflow_id}/${workflow.workflow_type}/edit/" 
               class="btn btn-sm btn-outline-secondary">
                <i class="fe-edit me-1"></i> Edit
            </a>
        ` : '';
        
        return `
            <div class="col-lg-4 col-md-6 mb-4">
                <div class="card workflow-card h-100 position-relative">
                    <div class="workflow-type-badge badge ${badgeClass}">
                        ${badgeText}
                    </div>
                    
                    <div class="card-body">
                        <h5 class="card-title">${this.escapeHtml(workflow.name)}</h5>
                        <p class="card-text text-muted">${this.escapeHtml(workflow.description || '')}</p>
                        
                        ${workflow.input_type ? `<p class="card-text"><small class="text-muted">Input: ${this.escapeHtml(workflow.input_type)}</small></p>` : ''}
                        
                        ${tagsHtml ? `<div class="mb-2">${tagsHtml}</div>` : ''}
                        ${useCasesHtml ? `<div class="mb-2">${useCasesHtml}</div>` : ''}
                    </div>
                    
                    <div class="card-footer bg-transparent">
                        <div class="d-flex justify-content-between">
                            <a href="/scanEngine/workflows/${workflow.workflow_id}/${workflow.workflow_type}/" 
                               class="btn btn-sm btn-primary">
                                <i class="fe-eye me-1"></i> View
                            </a>
                            ${editButton}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    renderPagination(pagination) {
        const paginationContainer = $(this.paginationSelector);
        
        if (pagination.total_pages <= 1) {
            paginationContainer.html('');
            return;
        }
        
        let paginationHtml = '<nav aria-label="Workflow pagination"><ul class="pagination justify-content-center">';
        
        // First button
        if (pagination.current_page > 1) {
            paginationHtml += `
                <li class="page-item">
                    <a class="page-link pagination-link" href="#" data-page="1">First</a>
                </li>
            `;
        }
        
        // Previous button
        if (pagination.has_previous) {
            paginationHtml += `
                <li class="page-item">
                    <a class="page-link pagination-link" href="#" data-page="${pagination.previous_page}">Previous</a>
                </li>
            `;
        }
        
        // Page numbers with ellipsis
        const totalPages = pagination.total_pages;
        const currentPage = pagination.current_page;
        
        // Show first page
        if (currentPage > 3) {
            paginationHtml += `
                <li class="page-item">
                    <a class="page-link pagination-link" href="#" data-page="1">1</a>
                </li>
            `;
            if (currentPage > 4) {
                paginationHtml += '<li class="page-item disabled"><span class="page-link">...</span></li>';
            }
        }
        
        // Show pages around current page
        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, currentPage + 2);
        
        for (let i = startPage; i <= endPage; i++) {
            const activeClass = i === currentPage ? 'active' : '';
            paginationHtml += `
                <li class="page-item ${activeClass}">
                    <a class="page-link pagination-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        }
        
        // Show last page
        if (currentPage < totalPages - 2) {
            if (currentPage < totalPages - 3) {
                paginationHtml += '<li class="page-item disabled"><span class="page-link">...</span></li>';
            }
            paginationHtml += `
                <li class="page-item">
                    <a class="page-link pagination-link" href="#" data-page="${totalPages}">${totalPages}</a>
                </li>
            `;
        }
        
        // Next button
        if (pagination.has_next) {
            paginationHtml += `
                <li class="page-item">
                    <a class="page-link pagination-link" href="#" data-page="${pagination.next_page}">Next</a>
                </li>
            `;
        }
        
        // Last button
        if (pagination.current_page < totalPages) {
            paginationHtml += `
                <li class="page-item">
                    <a class="page-link pagination-link" href="#" data-page="${totalPages}">Last</a>
                </li>
            `;
        }
        
        paginationHtml += '</ul></nav>';
        
        // Add results info
        const startResult = (pagination.current_page - 1) * this.perPage + 1;
        const endResult = Math.min(pagination.current_page * this.perPage, pagination.total_count);
        
        paginationHtml += `
            <div class="text-center mt-3">
                <small class="text-muted">
                    Affichage de ${startResult} à ${endResult} sur ${pagination.total_count} workflows
                </small>
            </div>
        `;
        
        paginationContainer.html(paginationHtml);
    }
    
    updateFilters(counts) {
        // Update filter tab counts
        $('.filter-tab[data-type="all"] .count').text(counts.total);
        $('.filter-tab[data-type="custom"] .count').text(counts.custom);
        $('.filter-tab[data-type="builtin"] .count').text(counts.builtin);
        $('.filter-tab[data-type="engines"] .count').text(counts.engines);
    }
    
    updateUrl() {
        const params = new URLSearchParams();
        if (this.currentType !== 'all') params.set('type', this.currentType);
        if (this.currentSearch) params.set('search', this.currentSearch);
        if (this.currentPage > 1) params.set('page', this.currentPage);
        
        const newUrl = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
        window.history.replaceState({}, '', newUrl);
    }
    
    showLoading() {
        $(this.loadingSelector).show();
        $(this.containerSelector).addClass('loading');
    }
    
    hideLoading() {
        $(this.loadingSelector).hide();
        $(this.containerSelector).removeClass('loading');
    }
    
    showError(message) {
        const container = $(this.containerSelector);
        container.html(`
            <div class="col-12">
                <div class="alert alert-danger text-center">
                    <i class="fe-alert-triangle me-2"></i>
                    ${this.escapeHtml(message)}
                </div>
            </div>
        `);
    }
    
    getWorkflowBadgeClass(workflowType) {
        switch (workflowType) {
            case 'builtin':
            case 'builtin_engine':
                return 'bg-info';
            case 'custom':
            case 'custom_engine':
                return 'bg-success';
            default:
                return 'bg-secondary';
        }
    }
    
    getWorkflowBadgeText(workflowType) {
        switch (workflowType) {
            case 'builtin':
            case 'builtin_engine':
                return 'Built-in';
            case 'custom':
            case 'custom_engine':
                return 'Custom';
            default:
                return 'Engine';
        }
    }
    
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Public methods for external control
    refresh() {
        this.loadWorkflows();
    }
    
    setFilter(type, search = '') {
        this.currentType = type;
        this.currentSearch = search;
        this.currentPage = 1;
        this.loadWorkflows();
    }
    
    setPage(page) {
        this.currentPage = page;
        this.loadWorkflows();
    }
}

// Export for global use
window.AjaxWorkflowManager = AjaxWorkflowManager;
