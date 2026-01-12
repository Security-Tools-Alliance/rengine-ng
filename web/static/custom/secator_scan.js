/**
 * Secator Scan Interface - Dynamic loading and configuration
 */
(function($) {
  'use strict';

  const SecatorScan = {
    selectedMode: null,
    
    init: function() {
      this.bindEvents();
      this.initializeSubmitButton();
      this.initializeDefaultProfiles();
    },
    
    initializeDefaultProfiles: function() {
      // Initialize hidden input fields with default profile values from active buttons
      const profileTypes = ['speed', 'stealth', 'general', 'network'];
      profileTypes.forEach(type => {
        const $activeBtn = $(`.btn[data-profile-type="${type}"].active`);
        if ($activeBtn.length) {
          const value = $activeBtn.data('profile-value');
          const $hiddenInput = $(`#${type}_profile`);
          if ($hiddenInput.length) {
            $hiddenInput.val(value);
          }
        }
      });
    },
    
    bindEvents: function() {
      // Handle execution mode selection
      $(document).on('click', '.execution-mode-card', this.handleModeSelection.bind(this));
      
      // Handle profiles
      $(document).on('click', '[data-profile-type]', this.handleProfileSelection.bind(this));
      
      // Toggle expert mode
      $(document).on('change', '#expertMode', this.toggleExpertMode);
      
      // Toggle random proxy
      $(document).on('change', '#useRandomProxy', this.toggleRandomProxy);
      
      // Category filter
      $(document).on('click', '.category-filter-btn', this.handleCategoryFilter.bind(this));
      
      // Clear all tasks
      $(document).on('click', '#clear-all-tasks', this.clearAllTasks.bind(this));
      
      // Remove individual task
      $(document).on('click', '.remove-task', this.removeTask.bind(this));
      
      // Handle form submission
      $(document).on('submit', '#start-scan-form', this.handleFormSubmission.bind(this));
    },
    
    handleModeSelection: function(e) {
      const $card = $(e.currentTarget);
      $('.execution-mode-card').removeClass('selected');
      $card.addClass('selected');
      this.selectedMode = $card.data('mode');
      
      // Update hidden input field
      $('#execution_mode').val(this.selectedMode);
      
      // Remove all execution mode classes from body
      $('body').removeClass('execution-mode-workflow execution-mode-tasks execution-mode-scan');
      
      // Add the current execution mode class to body
      if (this.selectedMode) {
        $('body').addClass('execution-mode-' + this.selectedMode);
      }
      
      this.loadSelectionOptions(this.selectedMode);
    },
    
    handleFormSubmission: function(e) {
      e.preventDefault();
      
      const executionMode = $('#execution_mode').val();
      
      if (!executionMode) {
        alert('Please select an execution mode before submitting.');
        return false;
      }
      
      // Disable submit button
      const $submitBtn = $('#start-scan-btn');
      $submitBtn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-2"></i>Starting Scan...');
      
      // Gather form data
      const formData = this.collectFormData();
      
      // Make asynchronous AJAX call to API
      $.ajax({
        url: window.SECATOR_START_SCAN_URL || '/api/action/start/scan/',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(formData),
        headers: {
          'X-CSRFToken': $('input[name="csrfmiddlewaretoken"]').val()
        },
        success: function(response) {
          if (response.status) {
            // Show success message
            Swal.fire({
              icon: 'success',
              title: 'Scan Started',
              text: response.message || 'Scan has been initiated successfully',
              timer: 2000,
              showConfirmButton: false
            }).then(() => {
              // Redirect to scan history (prefer server-provided URL)
              if (window.SCAN_HISTORY_URL) {
                window.location.href = window.SCAN_HISTORY_URL;
              } else if (window.PROJECT_SLUG) {
                window.location.href = `/scan/${window.PROJECT_SLUG}/history`;
              } else {
                const projectSlug = window.location.pathname.split('/')[2];
                window.location.href = `/scan/${projectSlug}/history`;
              }
            });
          } else {
            // Show error message
            Swal.fire({
              icon: 'error',
              title: 'Error',
              text: response.error || 'Failed to start scan'
            });
            $submitBtn.prop('disabled', false).html('<i class="fas fa-play me-2"></i>Start Scan');
          }
        },
        error: function(xhr) {
          const errorMessage = xhr.responseJSON?.error || 'Failed to start scan. Please try again.';
          Swal.fire({
            icon: 'error',
            title: 'Error',
            text: errorMessage
          });
          $submitBtn.prop('disabled', false).html('<i class="fas fa-play me-2"></i>Start Scan');
        }
      });
      
      return false;
    },
    
    collectFormData: function() {
      const executionMode = $('#execution_mode').val();
      const domainId = $('#domain_id').val();
      
      const formData = {
        domain_id: parseInt(domainId),
        execution_mode: executionMode,
        scan_existing_elements: $('#scan_existing_elements').is(':checked'),
        imported_subdomains: $('#importSubdomainFormControlTextarea').val().split('\n').filter(s => s.trim()),
        out_of_scope_subdomains: $('#outOfScopeSubdomainTextarea').val().split('\n').filter(s => s.trim()),
        url_filter: $('#filterPath').val(),
        secator_config: {
          proxy: $('#useRandomProxy').is(':checked') ? null : $('#proxy-input').val(),
          use_random_proxy: $('#useRandomProxy').is(':checked'),
          rate_limit: parseInt($('input[name="rate_limit"]').val()) || 150,
          threads: parseInt($('input[name="threads"]').val()) || 20,
          timeout: parseInt($('input[name="timeout"]').val()) || 300,
          delay: parseInt($('input[name="delay"]').val()) || 0
        },
        speed_profile: $('.btn[data-profile-type="speed"].active').data('profile-value') || 'polite',
        stealth_profile: $('.btn[data-profile-type="stealth"].active').data('profile-value') || 'stealth',
        general_profile: $('.btn[data-profile-type="general"].active').data('profile-value') || 'full',
        network_profile: $('.btn[data-profile-type="network"].active').data('profile-value') || 'all_ports',
        expert_mode: $('#expertMode').is(':checked')
      };
      
      // Add mode-specific parameters
      if (executionMode === 'workflow') {
        formData.workflow_id = parseInt($('input[name="workflow_id"]:checked').val());
      } else if (executionMode === 'tasks') {
        formData.task_ids = $('input[name="task_ids"]:checked').map(function() {
          return parseInt($(this).val());
        }).get();
      } else if (executionMode === 'scan') {
        formData.secator_scan_type = $('input[name="secator_scan_type"]:checked').val();
      }
      
      return formData;
    },
    
    loadSelectionOptions: function(mode) {
      $.ajax({
        url: window.location.pathname,
        type: 'GET',
        data: {
          'ajax': 'true',
          'execution_mode': mode
        },
        beforeSend: function() {
          $('#selection-container').html('<div class="text-center py-4"><i class="fas fa-spinner fa-spin fa-2x"></i></div>');
        },
        success: function(data) {
          $('#selection-container').html(data.html);
          SecatorScan.initializeSelectionListeners();
          // Re-initialize tooltips after dynamic content load
          SecatorScan.initializeTooltips();
          SecatorScan.updateSuggestions(mode);
          
          // Update button state after loading new content
          setTimeout(() => {
            // Trigger a custom event to update button state without causing infinite loop
            $(document).trigger('secator:contentLoaded');
          }, 100);
        },
        error: function() {
          $('#selection-container').html('<div class="alert alert-danger">Error loading options. Please try again.</div>');
        }
      });
    },
    
    initializeTooltips: function() {
      // Initialize Bootstrap tooltips for all elements with data-bs-toggle="tooltip"
      const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
      tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
          delay: { show: 500, hide: 100 },
          html: true,
          boundary: 'viewport'
        });
      });
    },
    
    initializeSelectionListeners: function() {
      // Initialize Bootstrap tooltips
      this.initializeTooltips();
      
      // Handle workflow tiles
      $('#selection-container .workflow-tile').off('click').on('click', function(e) {
        const $tile = $(this);
        const $input = $tile.find('input[type="radio"]');

        // Radio button - single selection
        $('#selection-container .workflow-tile').removeClass('selected');
        $tile.addClass('selected');
        $input.prop('checked', true);
      });
      
        // Handle task tiles
        $('#selection-container .task-tile').off('click').on('click', function(e) {
          e.preventDefault();
          e.stopPropagation();
          
          const $tile = $(this);
          const $input = $tile.find('input[type="checkbox"]');

          // Checkbox - multi selection
          if (!$(e.target).is('input[type="checkbox"]')) {
            $input.prop('checked', !$input.prop('checked'));
          }
          
          if ($input.is(':checked')) {
            $tile.addClass('selected');
          } else {
            $tile.removeClass('selected');
          }
          
          SecatorScan.updateTaskSelection();
        });
      
      // Handle scan type tiles
      $('#selection-container .scan-type-tile').off('click').on('click', function(e) {
        const $tile = $(this);
        const $input = $tile.find('input[type="radio"]');
        
        // Radio button - single selection
        $('#selection-container .scan-type-tile').removeClass('selected');
        $tile.addClass('selected');
        $input.prop('checked', true);
      });
      
      // Handle select all tasks
      $('#select_all_tasks').off('change').on('change', function() {
        const isChecked = $(this).is(':checked');
        $('#selection-container input[name="task_ids"]').prop('checked', isChecked);
        $('#selection-container .task-tile').each(function() {
          if (isChecked) {
            $(this).addClass('selected');
          } else {
            $(this).removeClass('selected');
          }
        });
        SecatorScan.updateTaskSelection();
      });
      
      // Handle direct checkbox changes (fallback)
      $('#selection-container input[name="task_ids"]').off('change').on('change', function() {
        const $tile = $(this).closest('.task-tile');
        if ($(this).is(':checked')) {
          $tile.addClass('selected');
        } else {
          $tile.removeClass('selected');
        }
        SecatorScan.updateTaskSelection();
      });
    },
    
    updateTaskSelection: function() {
      const selectedTasks = $('#selection-container input[name="task_ids"]:checked').length;
      $('#selected-tasks-count, #selected-tasks-count-bottom').text(selectedTasks);
      
      // Update select all checkbox state
      const totalTasks = $('#selection-container input[name="task_ids"]').length;
      const selectAllCheckbox = $('#select_all_tasks');
      if (selectedTasks === 0) {
        selectAllCheckbox.prop('indeterminate', false).prop('checked', false);
      } else if (selectedTasks === totalTasks) {
        selectAllCheckbox.prop('indeterminate', false).prop('checked', true);
      } else {
        selectAllCheckbox.prop('indeterminate', true);
      }
      
      // Update category headers with selected count
      this.updateCategoryHeaders();
      
      // Update selected tasks display
      this.updateSelectedTasksDisplay();
      
      // Trigger button state update
      $(document).trigger('secator:contentLoaded');
    },
    
    updateCategoryHeaders: function() {
      $('.category-tile-with-tasks').each(function() {
        const $tile = $(this);
        const selectedInCategory = $tile.find('input[name="task_ids"]:checked').length;
        const totalInCategory = $tile.find('input[name="task_ids"]').length;
        
        const $count = $tile.find('.category-tile-count');
        if (selectedInCategory > 0) {
          $count.text(`${selectedInCategory}/${totalInCategory} selected`);
          $tile.addClass('has-selection');
        } else {
          $count.text(`${totalInCategory} task${totalInCategory !== 1 ? 's' : ''}`);
          $tile.removeClass('has-selection');
        }
      });
    },
    
    
    updateSuggestions: function(mode) {
      const suggestions = {
        'workflow': 'Recommended: Choose a workflow that matches your target type (web application, network infrastructure, etc.)',
        'tasks': 'Consider: Select multiple tasks for comprehensive reconnaissance. Use categories to organize your selection.',
        'scan': 'Quick scan modes: Choose domain, host, network, subdomain, or URL scan types based on your target.'
      };
      
      const suggestionText = suggestions[mode] || '';
      $('#auto-suggestions').text(suggestionText);
      
      // Show/hide suggestions box
      if (suggestionText) {
        $('.suggestions-box').slideDown();
      } else {
        $('.suggestions-box').slideUp();
      }
    },
    
    handleProfileSelection: function(e) {
      const $btn = $(e.currentTarget);
      const type = $btn.data('profile-type');
      const value = $btn.data('profile-value');
      
      // Deselect other buttons of the same type
      $(`[data-profile-type="${type}"]`).removeClass('active');
      $btn.addClass('active');
      
      // Update hidden input field if it exists
      const $hiddenInput = $(`#${type}_profile`);
      if ($hiddenInput.length) {
        $hiddenInput.val(value);
      }
      
      // Apply profile values (only for speed and stealth as they affect form fields)
      if (type === 'speed' || type === 'stealth') {
        this.applyProfile(type, value);
      }
    },
    
    applyProfile: function(type, value) {
      const profiles = {
        speed: {
          aggressive: { rate_limit: 10000, delay: 0, timeout: 1, retries: 1 },
          insane: { rate_limit: 100000, delay: 0, timeout: 1, retries: 0 },
          polite: { rate_limit: 100, delay: 0, timeout: 10, retries: 5 },
          paranoid: { rate_limit: 5, delay: 5, timeout: 15, retries: 5 }
        },
        stealth: {
          sneaky: { fragment: true, nmap_light_fragment: true },
          stealth: { tcp_syn_stealth: true, nmap_light_tcp_syn_stealth: true, scan_type: 's' },
          tor: { proxy: 'auto' }
        }
      };
      
      const config = profiles[type]?.[value];
      if (config) {
        Object.keys(config).forEach(key => {
          const $input = $(`input[name="${key}"]`);
          if ($input.length) {
            $input.val(config[key]).trigger('change');
            // Visual feedback
            $input.addClass('profile-applied');
            setTimeout(() => $input.removeClass('profile-applied'), 1000);
          }
        });
      }
      
      // Update selected tasks display
      this.updateSelectedTasksDisplay();
    },
    
    toggleExpertMode: function() {
      const isExpert = $(this).is(':checked');
      $('#expertOptions').slideToggle(isExpert);
    },

    toggleRandomProxy: function() {
      const useRandom = $('#useRandomProxy').is(':checked');
      const $proxyInput = $('#proxy-input');
      
      if (useRandom) {
        // Disable manual proxy input and clear it
        $proxyInput.prop('disabled', true).val('').attr('placeholder', 'Using random proxy from settings');
        $proxyInput.addClass('text-muted');
      } else {
        // Enable manual proxy input
        $proxyInput.prop('disabled', false).attr('placeholder', 'socks5://host:port');
        $proxyInput.removeClass('text-muted');
      }
    },
    
    handleCategoryFilter: function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      const $btn = $(e.currentTarget);
      const category = $btn.data('category');
      
      // Handle "All" button - exclusive selection
      if (category === 'all') {
        $('.category-filter-btn').removeClass('active');
        $btn.addClass('active');
        $('.category-separator').removeClass('d-none');
        $('.row[data-category]').removeClass('d-none');
        return;
      }
      
      // Remove "All" active state when selecting specific categories
      $('.category-filter-btn[data-category="all"]').removeClass('active');
      
      // Toggle current button
      $btn.toggleClass('active');
      
      // Show/hide category sections based on active filters
      const activeCategories = $('.category-filter-btn.active:not([data-category="all"])').map(function() {
        return $(this).data('category');
      }).get();
      
      if (activeCategories.length === 0) {
        // If no specific categories are selected, show all
        $('.category-separator').removeClass('d-none');
        $('.row[data-category]').removeClass('d-none');
        $('.category-filter-btn[data-category="all"]').addClass('active');
      } else {
        // Hide all first
        $('.category-separator').addClass('d-none');
        $('.row[data-category]').addClass('d-none');
        
        // Show only active categories
        activeCategories.forEach(function(cat) {
          $(`.category-separator[data-category="${cat}"]`).removeClass('d-none');
          $(`.row[data-category="${cat}"]`).removeClass('d-none');
        });
      }
    },
    
    updateSelectedTasksDisplay: function() {
      const selectedTasks = $('input[name="task_ids"]:checked');
      const $display = $('#selected-tasks-display');
      const $badgesContainer = $('#selected-tasks-badges');
      
      if (selectedTasks.length === 0) {
        $display.hide();
        return;
      }
      
      $display.show();
      $badgesContainer.empty();
      
      selectedTasks.each(function() {
        const $input = $(this);
        const taskId = $input.val();
        const $taskTile = $input.closest('.task-tile');
        const taskName = $taskTile.find('.task-tile-title').text().trim();
        
        // Get parent category from the row's data-category attribute
        const $parentRow = $taskTile.closest('.row[data-category]');
        const parentCategory = $parentRow.data('category');
        
        const badge = $(`
          <span class="badge selected-task-badge" data-task-id="${taskId}" data-category="${parentCategory}">
            ${taskName}
            <i class="fas fa-times remove-task" data-task-id="${taskId}"></i>
          </span>
        `);
        
        $badgesContainer.append(badge);
      });
    },
    
    clearAllTasks: function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      // Uncheck all task checkboxes
      $('input[name="task_ids"]:checked').prop('checked', false);
      
      // Remove visual selection from task tiles
      $('.task-tile').removeClass('selected');
      
      // Update the display
      this.updateSelectedTasksDisplay();
    },
    
    removeTask: function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      const taskId = $(e.currentTarget).data('task-id');
      
      // Uncheck the specific task checkbox
      $(`input[name="task_ids"][value="${taskId}"]`).prop('checked', false);
      
      // Remove visual selection from the specific task tile
      $(`input[name="task_ids"][value="${taskId}"]`).closest('.task-tile').removeClass('selected');
      
      // Update the display
      this.updateSelectedTasksDisplay();
    },

    initializeSubmitButton: function() {
      const $submitBtn = $('#start-scan-btn');
      
      // Check if there's a valid selection
      const hasValidSelection = () => {
        const executionMode = $('.execution-mode-card.selected').data('mode');
        
        let hasSelection = false;
        switch (executionMode) {
          case 'workflow':
            hasSelection = $('input[name="workflow_id"]:checked').length > 0;
            break;
          case 'tasks':
            hasSelection = $('input[name="task_ids"]:checked').length > 0;
            break;
          case 'scan':
            hasSelection = $('input[name="secator_scan_type"]:checked').length > 0;
            break;
          default:
            hasSelection = false;
        }
        return hasSelection;
      };
      
      // Function to update button state
      const updateButtonState = () => {
        const hasExecutionMode = $('.execution-mode-card.selected').length > 0;
        const hasSelection = hasValidSelection();
        
        if (hasExecutionMode && hasSelection) {
          $submitBtn.prop('disabled', false).removeClass('btn-secondary').addClass('btn-primary');
        } else {
          $submitBtn.prop('disabled', true).removeClass('btn-primary').addClass('btn-secondary');
        }
      };
      
      // Bind events to update button state
      $(document).on('change', 'input[name="workflow_id"], input[name="task_ids"], input[name="secator_scan_type"]', updateButtonState);
      $(document).on('click', '.execution-mode-card', updateButtonState);
      
      // Also bind to task tile clicks for individual tasks
      $(document).on('click', '.task-tile', updateButtonState);
      $(document).on('click', '.workflow-tile', updateButtonState);
      $(document).on('click', '.scan-type-tile', updateButtonState);
      
      // Listen for content loaded event
      $(document).on('secator:contentLoaded', updateButtonState);
      
      // Initial state
      updateButtonState();
    }
  };

  // Initialize on document ready
  $(function() {
    SecatorScan.init();
    // Initialize tooltips for profile buttons
    SecatorScan.initializeTooltips();
  });

})(jQuery);
