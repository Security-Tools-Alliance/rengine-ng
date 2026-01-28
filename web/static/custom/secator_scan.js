/**
 * Secator Scan Interface - Dynamic loading and configuration
 */
(function($) {
  'use strict';

  const SecatorScan = {
    selectedMode: null,
    
    init: function() {
      this.bindEvents();
      this.initializeDefaultProfiles();
      this.initializeProfileCategories();
      this.initializeSubmitButtons();
    },
    
    initializeDefaultProfiles: function() {
      // Initialize hidden input fields with default profile values from active buttons or custom selects
      // These hidden inputs are still used for form state management
      const profileMappings = [
        { type: 'speed', hiddenName: 'speed_profile', customSelectName: 'speed_custom_profile' },
        { type: 'evasion', hiddenName: 'stealth_profile', customSelectName: 'evasion_custom_profile' }, // evasion maps to stealth_profile
        { type: 'stealth', hiddenName: 'stealth_profile', customSelectName: 'evasion_custom_profile' }, // legacy support
        { type: 'general', hiddenName: 'general_profile', customSelectName: 'general_custom_profile' },
        { type: 'network', hiddenName: 'network_profile', customSelectName: 'network_custom_profile' }
      ];
      
      $('form').each(function() {
        const $form = $(this);
        if (!$form.find('input[name="execution_mode"]').length) {
          return;
        }

        profileMappings.forEach(mapping => {
          const $hiddenInput = $form.find(`input[name="${mapping.hiddenName}"]`);
          if ($hiddenInput.length && !$hiddenInput.val()) {
            // First check custom select
            const $customSelect = $form.find(`select[name="${mapping.customSelectName}"]`);
            if ($customSelect.length && $customSelect.val()) {
              $hiddenInput.val($customSelect.val());
              return;
            }

            // Then check active button
            const $activeBtn = $form.find(`.btn[data-profile-type="${mapping.type}"].active`).first();
            if ($activeBtn.length) {
              const value = $activeBtn.data('profile-value');
              $hiddenInput.val(value);
            }
          }
        });
      });
    },
    
    bindEvents: function() {
      // Handle execution mode selection
      $(document).on('click', '.execution-mode-card', this.handleModeSelection.bind(this));
      
      // Handle profiles
      $(document).on('click', '[data-profile-type]', this.handleProfileSelection.bind(this));
      
      // Toggle random proxy (supports id_prefix)
      $(document).on('change', '[id$="useRandomProxy"], #useRandomProxy', this.toggleRandomProxy);
      
      // Toggle profile categories (supports id_prefix via suffix matching)
      $(document).on('change', '[id$="useSpeedProfile"], #useSpeedProfile', this.handleProfileCategoryToggle.bind(this));
      $(document).on('change', '[id$="useEvasionProfile"], #useEvasionProfile', this.handleProfileCategoryToggle.bind(this));
      $(document).on('change', '[id$="useGeneralProfile"], #useGeneralProfile', this.handleProfileCategoryToggle.bind(this));
      $(document).on('change', '[id$="useNetworkProfile"], #useNetworkProfile', this.handleProfileCategoryToggle.bind(this));
      
      // Category filter
      $(document).on('click', '.category-filter-btn', this.handleCategoryFilter.bind(this));
      
      // Clear all tasks
      $(document).on('click', '#clear-all-tasks', this.clearAllTasks.bind(this));
      
      // Remove individual task
      $(document).on('click', '.remove-task', this.removeTask.bind(this));
      
      // Handle form submission
      $(document).on('submit', '#start-scan-form', this.handleFormSubmission.bind(this));

      // Keep submit buttons in sync for all forms
      $(document).on(
        'change',
        'input[name="workflow_id"], input[name="task_ids"], input[name="secator_scan_type"]',
        function(e) {
          const $form = $(e.target).closest('form');
          SecatorScan.updateSubmitButtonState($form);
        }
      );
      $(document).on('click', '.execution-mode-card', function(e) {
        const $form = $(e.currentTarget).closest('form');
        SecatorScan.updateSubmitButtonState($form);
      });
      $(document).on('secator:contentLoaded', function() {
        $('form').each(function() {
          SecatorScan.updateSubmitButtonState($(this));
        });
      });
    },
    
    handleModeSelection: function(e) {
      const $card = $(e.currentTarget);
      const $form = $card.closest('form');
      const selectedMode = $card.data('mode');

      $form.find('.execution-mode-card').removeClass('selected');
      $card.addClass('selected');
      this.selectedMode = selectedMode;
      
      // Update hidden input field (scoped to form to avoid duplicate IDs)
      $form.find('input[name="execution_mode"]').val(selectedMode);
      
      // Remove all execution mode classes from body
      $('body').removeClass('execution-mode-workflow execution-mode-tasks execution-mode-scan');
      
      // Add the current execution mode class to body
      if (selectedMode) {
        $('body').addClass('execution-mode-' + selectedMode);
      }
      
      // Update suggestions immediately when mode changes
      this.updateSuggestions(selectedMode, $form);
      
      this.loadSelectionOptions(selectedMode, $form);
      this.updateSubmitButtonState($form);
    },
    
    handleFormSubmission: function(e) {
      e.preventDefault();
      const $form = $(e.currentTarget);
      const executionMode = $form.find('input[name="execution_mode"]').val();
      
      if (!executionMode) {
        alert('Please select an execution mode before submitting.');
        return false;
      }

      if (!window.SECATOR_START_SCAN_URL || !window.SCAN_HISTORY_URL) {
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: 'Missing required configuration. Please reload the page and try again.'
        });
        return false;
      }
      
      // Disable submit button
      const $submitBtn = $form.find('#start-scan-btn');
      $submitBtn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-2"></i>Starting Scan...');
      
      // Gather form data
      const formData = this.collectFormData($form);
      
      // Make asynchronous AJAX call to API
      $.ajax({
        url: window.SECATOR_START_SCAN_URL,
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
              window.location.href = window.SCAN_HISTORY_URL;
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
    
    collectFormData: function($form) {
      const executionMode = $form.find('input[name="execution_mode"]').val();
      const domainId = $form.find('input[name="domain_id"]').val();
      
      // Collect profiles - only if the corresponding switch is enabled
      const profiles = [];
      if ($form.find('[id$="useSpeedProfile"], #useSpeedProfile').is(':checked')) {
        const speedProfile = $form.find('input[name="speed_profile"]').val() || 
                           $form.find('.btn[data-profile-type="speed"].active').data('profile-value') || 
                           $form.find('select[name="speed_custom_profile"]').val();
        if (speedProfile) {
          profiles.push(speedProfile);
        }
      }
      if ($form.find('[id$="useEvasionProfile"], #useEvasionProfile').is(':checked')) {
        const evasionProfile = $form.find('input[name="stealth_profile"]').val() || 
                             $form.find('.btn[data-profile-type="evasion"].active').data('profile-value') || 
                             $form.find('.btn[data-profile-type="stealth"].active').data('profile-value') ||
                             $form.find('select[name="evasion_custom_profile"]').val();
        if (evasionProfile) {
          profiles.push(evasionProfile);
        }
      }
      if ($form.find('[id$="useGeneralProfile"], #useGeneralProfile').is(':checked')) {
        const generalProfile = $form.find('input[name="general_profile"]').val() || 
                            $form.find('.btn[data-profile-type="general"].active').data('profile-value') ||
                            $form.find('select[name="general_custom_profile"]').val();
        if (generalProfile) {
          profiles.push(generalProfile);
        }
      }
      if ($form.find('[id$="useNetworkProfile"], #useNetworkProfile').is(':checked')) {
        const networkProfile = $form.find('input[name="network_profile"]').val() || 
                             $form.find('.btn[data-profile-type="network"].active').data('profile-value') ||
                             $form.find('select[name="network_custom_profile"]').val();
        if (networkProfile) {
          profiles.push(networkProfile);
        }
      }
      
      // Handle proxy - if use_random_proxy is checked, set to null (backend will handle random proxy)
      const useRandomProxy = $form.find('input[name="use_random_proxy"]').is(':checked');
      const proxyValue = useRandomProxy ? null : ($form.find('input[name="proxy"]').val() || '');
      
      const formData = {
        domain_id: parseInt(domainId),
        execution_mode: executionMode,
        scan_existing_elements: $form.find('input[name="scan_existing_elements"]').is(':checked'),
        imported_subdomains: ($form.find('[id$="importSubdomainFormControlTextarea"], #importSubdomainFormControlTextarea').val() || '').split('\n').filter(s => s.trim()),
        out_of_scope_subdomains: ($form.find('[id$="outOfScopeSubdomainTextarea"], #outOfScopeSubdomainTextarea').val() || '').split('\n').filter(s => s.trim()),
        url_filter: $form.find('[id$="filterPath"], #filterPath').val(),
        secator_config: {
          proxy: proxyValue,
          delay: parseInt($form.find('input[name="delay"]').val()) || 0,
          profiles: profiles
        }
      };
      
      // Add mode-specific parameters
      if (executionMode === 'workflow') {
        formData.workflow_id = parseInt($form.find('input[name="workflow_id"]:checked').val());
      } else if (executionMode === 'tasks') {
        formData.task_ids = $form.find('input[name="task_ids"]:checked').map(function() {
          return parseInt($(this).val());
        }).get();
      } else if (executionMode === 'scan') {
        formData.secator_scan_type = $form.find('input[name="secator_scan_type"]:checked').val();
      }
      
      return formData;
    },
    
    loadSelectionOptions: function(mode, $form) {
      $.ajax({
        url: window.location.pathname,
        type: 'GET',
        data: {
          'ajax': 'true',
          'execution_mode': mode
        },
        beforeSend: function() {
          $form.find('#selection-container').html('<div class="text-center py-4"><i class="fas fa-spinner fa-spin fa-2x"></i></div>');
        },
        success: function(data) {
          $form.find('#selection-container').html(data.html);
          SecatorScan.initializeSelectionListeners($form);
          // Re-initialize tooltips after dynamic content load
          SecatorScan.initializeTooltips();
          SecatorScan.updateSuggestions(mode, $form);
          
          // Update button state after loading new content
          setTimeout(() => {
            // Trigger a custom event to update button state without causing infinite loop
            $(document).trigger('secator:contentLoaded');
          }, 100);
        },
        error: function() {
          $form.find('#selection-container').html('<div class="alert alert-danger">Error loading options. Please try again.</div>');
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
    
    initializeSelectionListeners: function($form) {
      // Initialize Bootstrap tooltips
      this.initializeTooltips();

      const $container = $form.find('[id="selection-container"]');
      
      // Handle workflow tiles
      $container.find('.workflow-tile').off('click').on('click', function(e) {
        const $tile = $(this);
        const $input = $tile.find('input[type="radio"]');

        // Radio button - single selection
        $container.find('.workflow-tile').removeClass('selected');
        $tile.addClass('selected');
        $input.prop('checked', true).trigger('change');
      });
      
        // Handle task tiles
        $container.find('.task-tile').off('click').on('click', function(e) {
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
          
          SecatorScan.updateTaskSelection($form);
        });
      
      // Handle scan type tiles
      $container.find('.scan-type-tile').off('click').on('click', function(e) {
        const $tile = $(this);
        const $input = $tile.find('input[type="radio"]');
        
        // Radio button - single selection
        $container.find('.scan-type-tile').removeClass('selected');
        $tile.addClass('selected');
        $input.prop('checked', true).trigger('change');
      });
      
      // Handle select all tasks
      $container.find('input[id="select_all_tasks"]').off('change').on('change', function() {
        const isChecked = $(this).is(':checked');
        $container.find('input[name="task_ids"]').prop('checked', isChecked);
        $container.find('.task-tile').each(function() {
          if (isChecked) {
            $(this).addClass('selected');
          } else {
            $(this).removeClass('selected');
          }
        });
        SecatorScan.updateTaskSelection($form);
      });
      
      // Handle direct checkbox changes (fallback)
      $container.find('input[name="task_ids"]').off('change').on('change', function() {
        const $tile = $(this).closest('.task-tile');
        if ($(this).is(':checked')) {
          $tile.addClass('selected');
        } else {
          $tile.removeClass('selected');
        }
        SecatorScan.updateTaskSelection($form);
      });
    },
    
    updateTaskSelection: function($form) {
      const $container = $form.find('[id="selection-container"]');
      const selectedTasks = $container.find('input[name="task_ids"]:checked').length;
      $container.find('[id="selected-tasks-count"], [id="selected-tasks-count-bottom"]').text(selectedTasks);
      
      // Update select all checkbox state
      const totalTasks = $container.find('input[name="task_ids"]').length;
      const selectAllCheckbox = $container.find('input[id="select_all_tasks"]');
      if (selectedTasks === 0) {
        selectAllCheckbox.prop('indeterminate', false).prop('checked', false);
      } else if (selectedTasks === totalTasks) {
        selectAllCheckbox.prop('indeterminate', false).prop('checked', true);
      } else {
        selectAllCheckbox.prop('indeterminate', true);
      }
      
      // Update category headers with selected count
      this.updateCategoryHeaders($form);
      
      // Update selected tasks display
      this.updateSelectedTasksDisplay($form);
      
      // Trigger button state update
      $(document).trigger('secator:contentLoaded');
    },
    
    updateCategoryHeaders: function($form) {
      const $container = $form.find('[id="selection-container"]');
      $container.find('.category-tile-with-tasks').each(function() {
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
    
    
    updateSuggestions: function(mode, $form) {
      const suggestions = {
        'workflow': 'Recommended: Choose a workflow that matches your target type (web application, network infrastructure, etc.)',
        'tasks': 'Consider: Select multiple tasks for comprehensive reconnaissance. Use categories to organize your selection.',
        'scan': 'Quick scan modes: Choose domain, host, network, subdomain, or URL scan types based on your target.'
      };
      
      const suggestionText = suggestions[mode] || '';
      
      // Try to find suggestions box in form first, then in document if not found
      let $suggestionsBox = $form.find('.suggestions-box');
      if ($suggestionsBox.length === 0) {
        // If not found in form, search in the document (for suggestions outside form structure)
        $suggestionsBox = $('.suggestions-box').first();
      }
      
      // Try multiple selectors for the suggestions element
      let $suggestionsElement = $suggestionsBox.find('[id$="auto-suggestions"], [id="auto-suggestions"]');
      if ($suggestionsElement.length === 0) {
        // Try finding by id prefix pattern
        $suggestionsElement = $('[id$="auto-suggestions"]').first();
      }
      
      if ($suggestionsElement.length) {
        $suggestionsElement.text(suggestionText);
      }
      
      // Show/hide suggestions box
      if ($suggestionsBox.length) {
        if (suggestionText) {
          $suggestionsBox.slideDown();
        } else {
          $suggestionsBox.slideUp();
        }
      }
    },
    
    handleProfileSelection: function(e) {
      const $btn = $(e.currentTarget);
      const type = $btn.data('profile-type');
      const value = $btn.data('profile-value');
      const $form = $btn.closest('form');

      const typeToHiddenName = {
        speed: 'speed_profile',
        evasion: 'stealth_profile',
        stealth: 'stealth_profile',
        general: 'general_profile',
        network: 'network_profile'
      };
      const hiddenName = typeToHiddenName[type] || `${type}_profile`;
      
      // Deselect other buttons of the same type
      $form.find(`[data-profile-type="${type}"]`).removeClass('active');
      $btn.addClass('active');
      
      // Update hidden input field if it exists (scoped to form)
      const $hiddenInput = $form.find(`input[name="${hiddenName}"]`);
      if ($hiddenInput.length) {
        $hiddenInput.val(value);
      }
      
      // Apply profile values (only for speed and stealth as they affect form fields)
      if (type === 'speed' || type === 'stealth') {
        this.applyProfile(type, value, $form);
      }
    },
    
    applyProfile: function(type, value, $form) {
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
          const $input = $form.find(`input[name="${key}"]`);
          if ($input.length) {
            $input.val(config[key]).trigger('change');
            // Visual feedback
            $input.addClass('profile-applied');
            setTimeout(() => $input.removeClass('profile-applied'), 1000);
          }
        });
      }
      
      this.updateSelectedTasksDisplay($form);
      this.updateTaskSelection($form);
    },
    
    toggleRandomProxy: function() {
      const $form = $(this).closest('form');
      const useRandomProxyId = $(this).attr('id');
      const idPrefix = useRandomProxyId.replace('useRandomProxy', '');
      const proxyInputId = idPrefix + 'proxy-input';
      const useRandom = $form.find('#' + useRandomProxyId).is(':checked');
      const $proxyInput = $form.find('#' + proxyInputId);
      
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
    
    getCategorySwitchMap: function() {
      return {
        speed: 'useSpeedProfile',
        evasion: 'useEvasionProfile',
        general: 'useGeneralProfile',
        network: 'useNetworkProfile'
      };
    },
    
    handleProfileCategoryToggle: function(e) {
      const $switch = $(e.currentTarget);
      const category = this.getCategoryFromSwitch($switch);
      const isEnabled = $switch.is(':checked');
      const $form = $switch.closest('form');
      
      this.toggleProfileCategory(category, isEnabled, $form);
    },
    
    getCategoryFromSwitch: function($switch) {
      const id = $switch.attr('id');
      if (!id) return null;
      
      const categorySwitchMap = this.getCategorySwitchMap();
      for (const [category, switchId] of Object.entries(categorySwitchMap)) {
        if (id === switchId || id.endsWith(switchId)) {
          return category;
        }
      }
      return null;
    },
    
    toggleProfileCategory: function(category, isEnabled, $form) {
      const $section = $form.find(`.profile-category-section[data-profile-category="${category}"]`);
      const hiddenInputName = category === 'evasion' ? 'stealth_profile' : category + '_profile';
      const $hiddenInput = $form.find(`input[name="${hiddenInputName}"]`);
      
      if (isEnabled) {
        // Show section and enable controls
        $section.slideDown();
        $section.find('button, select').prop('disabled', false);
        
        // Activate default profile
        this.activateDefaultProfile(category, $form);
      } else {
        // Hide section and disable controls
        $section.slideUp();
        $section.find('button, select').prop('disabled', true);
        
        // Clear hidden input
        if ($hiddenInput.length) {
          $hiddenInput.val('');
        }
        
        // Deselect all buttons in this category
        $section.find('.btn').removeClass('active');
        $section.find('select').val('');
      }
    },
    
    activateDefaultProfile: function(category, $form) {
      const defaultProfiles = {
        'speed': 'polite',
        'evasion': 'stealth',
        'general': 'full',
        'network': 'all_ports'
      };
      
      const defaultProfile = defaultProfiles[category];
      const $section = $form.find(`.profile-category-section[data-profile-category="${category}"]`);
      const hiddenInputName = category === 'evasion' ? 'stealth_profile' : category + '_profile';
      const $hiddenInput = $form.find(`input[name="${hiddenInputName}"]`);
      
      // Check if there's a custom profile with this default value
      const $customSelect = $section.find(`select[id$="${category}_custom_profile"], select[id="${category}_custom_profile"]`);
      const customOption = $customSelect.find(`option[value="${defaultProfile}"]`);
      
      if (customOption.length && customOption.val()) {
        // Use custom profile
        $customSelect.val(defaultProfile).trigger('change');
        if ($hiddenInput.length) {
          $hiddenInput.val(defaultProfile);
        }
      } else {
        // Use builtin profile - find and click the button
        const $defaultButton = $section.find(`.btn[data-profile-value="${defaultProfile}"]`);
        if ($defaultButton.length) {
          $defaultButton.trigger('click');
        } else if ($hiddenInput.length) {
          // Fallback: set hidden input directly
          $hiddenInput.val(defaultProfile);
        }
      }
    },
    
    initializeProfileCategories: function() {
      const self = this;
      const categorySwitchMap = this.getCategorySwitchMap();
      
      $('form').each(function() {
        const $form = $(this);
        if (!$form.find('input[name="execution_mode"]').length) {
          return;
        }
        
        Object.keys(categorySwitchMap).forEach(function(category) {
          const switchId = categorySwitchMap[category];
          const $switch = $form.find(`[id$="${switchId}"], #${switchId}`);
          
          if ($switch.length) {
            const isEnabled = $switch.is(':checked');
            self.toggleProfileCategory(category, isEnabled, $form);
          }
        });
      });
    },
    
    handleCategoryFilter: function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      const $btn = $(e.currentTarget);
      const $container = $btn.closest('[id="selection-container"]');
      const category = $btn.data('category');
      
      // Handle "All" button - exclusive selection
      if (category === 'all') {
        $container.find('.category-filter-btn').removeClass('active');
        $btn.addClass('active');
        $container.find('.category-separator').removeClass('d-none');
        $container.find('.row[data-category]').removeClass('d-none');
        return;
      }
      
      // Remove "All" active state when selecting specific categories
      $container.find('.category-filter-btn[data-category="all"]').removeClass('active');
      
      // Toggle current button
      $btn.toggleClass('active');
      
      // Show/hide category sections based on active filters
      const activeCategories = $container.find('.category-filter-btn.active:not([data-category="all"])').map(function() {
        return $(this).data('category');
      }).get();
      
      if (activeCategories.length === 0) {
        // If no specific categories are selected, show all
        $container.find('.category-separator').removeClass('d-none');
        $container.find('.row[data-category]').removeClass('d-none');
        $container.find('.category-filter-btn[data-category="all"]').addClass('active');
      } else {
        // Hide all first
        $container.find('.category-separator').addClass('d-none');
        $container.find('.row[data-category]').addClass('d-none');
        
        // Show only active categories
        activeCategories.forEach(function(cat) {
          $container.find(`.category-separator[data-category="${cat}"]`).removeClass('d-none');
          $container.find(`.row[data-category="${cat}"]`).removeClass('d-none');
        });
      }
    },
    
    updateSelectedTasksDisplay: function($form) {
      const $container = $form.find('[id="selection-container"]');
      const selectedTasks = $container.find('input[name="task_ids"]:checked');
      const $display = $container.find('[id="selected-tasks-display"]');
      const $badgesContainer = $container.find('[id="selected-tasks-badges"]');
      
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

      const $form = $(e.currentTarget).closest('form');
      const $container = $form.find('[id="selection-container"]');
      
      // Uncheck all task checkboxes
      $container.find('input[name="task_ids"]:checked').prop('checked', false);
      
      // Remove visual selection from task tiles
      $container.find('.task-tile').removeClass('selected');
      
      // Update the display
      this.updateSelectedTasksDisplay($form);
      this.updateTaskSelection($form);
    },
    
    removeTask: function(e) {
      e.preventDefault();
      e.stopPropagation();
      
      const $form = $(e.currentTarget).closest('form');
      const $container = $form.find('[id="selection-container"]');
      const taskId = $(e.currentTarget).data('task-id');
      
      // Uncheck the specific task checkbox
      $container.find(`input[name="task_ids"][value="${taskId}"]`).prop('checked', false);
      
      // Remove visual selection from the specific task tile
      $container.find(`input[name="task_ids"][value="${taskId}"]`).closest('.task-tile').removeClass('selected');
      
      // Update the display
      this.updateSelectedTasksDisplay($form);
      this.updateTaskSelection($form);
    },

    updateSubmitButtonState: function($form) {
      if (!$form || !$form.length) {
        return;
      }

      const $submitBtn = $form.find('#start-scan-btn');
      if (!$submitBtn.length) {
        return;
      }

      const executionMode = $form.find('.execution-mode-card.selected').data('mode');
      const hasExecutionMode = Boolean(executionMode);

      let hasSelection = false;
      switch (executionMode) {
        case 'workflow':
          hasSelection = $form.find('input[name="workflow_id"]:checked').length > 0;
          break;
        case 'tasks':
          hasSelection = $form.find('input[name="task_ids"]:checked').length > 0;
          break;
        case 'scan':
          hasSelection = $form.find('input[name="secator_scan_type"]:checked').length > 0;
          break;
        default:
          hasSelection = false;
      }

      if (hasExecutionMode && hasSelection) {
        $submitBtn.prop('disabled', false).removeClass('btn-secondary').addClass('btn-primary');
      } else {
        $submitBtn.prop('disabled', true).removeClass('btn-primary').addClass('btn-secondary');
      }
    },

    initializeSubmitButtons: function() {
      const self = this;
      $('form').each(function() {
        self.updateSubmitButtonState($(this));
      });
    },

    ensureButtonOutsideAdvancedConfig: function() {
      // Ensure the start scan button is outside advanced-config-section
      const $buttonContainer = $('.start-scan-button-container');
      const $advancedConfigSection = $('.advanced-config-section');
      const $form = $('#start-scan-form');
      
      if ($buttonContainer.length && $advancedConfigSection.length && $form.length) {
        // Check if button is inside advanced-config-section
        if ($advancedConfigSection.find($buttonContainer).length > 0) {
          // Move button outside advanced-config-section
          $buttonContainer.detach();
          $advancedConfigSection.after($buttonContainer);
        }
        
        // Also ensure it's outside select_engine
        const $selectEngine = $('#select_engine');
        if ($selectEngine.length && $selectEngine.find($buttonContainer).length > 0) {
          $buttonContainer.detach();
          $selectEngine.after($buttonContainer);
        }
        
        // Ensure it's inside the form
        if ($buttonContainer.closest('form').length === 0) {
          $form.append($buttonContainer);
        }
      }
    }
  };

  // Initialize on document ready
  $(function() {
    SecatorScan.init();
    // Initialize tooltips for profile buttons
    SecatorScan.initializeTooltips();
    // Ensure button is in correct position
    SecatorScan.ensureButtonOutsideAdvancedConfig();
    
    // Also check after dynamic content loads
    $(document).on('secator:contentLoaded', function() {
      SecatorScan.ensureButtonOutsideAdvancedConfig();
    });
  });

})(jQuery);
