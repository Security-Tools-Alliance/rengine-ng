/**
 * Secator Scan Interface - Selection, form, and facade.
 * Load after: secator/secator_scan_core.js, secator/secator_scan_targets.js, secator/secator_scan_tooltips.js,
 * and all secator helper scripts (compact_list, selection_listeners, selection_ajax, selection_dom, form_submit, input_types_ajax, input_types_tasks).
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') {
    console.warn('SecatorScan: core scripts (secator_scan_core.js, secator_scan_targets.js, secator_scan_tooltips.js) must load before secator_scan.js.');
    return;
  }

  Object.assign(window.SecatorScan, {
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

    handleModeSelection: function(e) {
      const $card = $(e.currentTarget);
      if ($card.closest('#subscan-modal').length) return;
      const $form = $card.closest('form');
      const selectedMode = $card.data('mode');

      $form.find('.execution-mode-card').removeClass('selected');
      $card.addClass('selected');
      this.selectedMode = selectedMode;

      $form.find('input[name="execution_mode"]').val(selectedMode);

      $('body').removeClass('execution-mode-workflow execution-mode-tasks execution-mode-scan');
      if (selectedMode) {
        $('body').addClass('execution-mode-' + selectedMode);
      }

      if (selectedMode === 'workflow') {
        $form.find('input[name="task_ids"]').prop('checked', false);
        $form.find('input[name="secator_scan_type"]').prop('checked', false);
      } else if (selectedMode === 'tasks') {
        $form.find('input[name="workflow_id"]').prop('checked', false);
        $form.find('input[name="secator_scan_type"]').prop('checked', false);
      } else if (selectedMode === 'scan') {
        $form.find('input[name="workflow_id"]').prop('checked', false);
        $form.find('input[name="task_ids"]').prop('checked', false);
      }

      this.updateSuggestions(selectedMode, $form);
      this.loadSelectionOptions(selectedMode, $form);
      this.updateSubmitButtonState($form);
      $form.trigger('secator:executionModeChanged');
    },
    
    // For POST forms (org, multi, schedule): inject selected_targets / selected_targets_per_task before submit.
    // Workflow/scan use selected_targets; tasks use selected_targets_per_task (per-task mapping). Both are sent; backend applies precedence.
    injectSelectedTargetsIntoForm: function(e) {
      const $form = $(e.currentTarget);
      if ($form.attr('id') === 'start-scan-form') return;
      const payload = this.getSelectedTargetsPayload($form);
      let $st = $form.find('input[name="selected_targets"]');
      if (!$st.length) {
        $st = $('<input type="hidden" name="selected_targets">');
        $form.append($st);
      }
      $st.val(JSON.stringify(payload.selected_targets || []));
      let $stpt = $form.find('input[name="selected_targets_per_task"]');
      if (!$stpt.length) {
        $stpt = $('<input type="hidden" name="selected_targets_per_task">');
        $form.append($stpt);
      }
      $stpt.val(JSON.stringify(payload.selected_targets_per_task || {}));
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

      const $submitBtn = $form.find('button[type="submit"]');
      $submitBtn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-2"></i>Starting Scan...');
      const formData = this.collectFormData($form);
      this.submitStartScan(formData, {
        csrfToken: $('input[name="csrfmiddlewaretoken"]').val(),
        $submitBtn: $submitBtn
      });
      return false;
    },

    loadSelectionOptions: function(mode, $form) {
      const containers = this.getSecatorContainers($form);
      const { prefix } = containers;
      this.showSelectionLoading(containers, prefix);
      const requestOptions = this.getSelectionRequestOptions(mode, prefix);
      const self = this;
      $.ajax({
        url: requestOptions.url,
        type: requestOptions.type,
        data: requestOptions.data,
        headers: requestOptions.headers,
        success: function(data) {
          self.applySelectionSuccess(data, containers, mode, $form);
        },
        error: function() {
          self.showSelectionError(containers, prefix);
        }
      });
    },

    buildCompactListForForm: function($html, mode, containers, $form) {
      const self = this;
      const $listContainer = containers.listContainer;
      const $selectionContainer = containers.selectionContainer;
      const $contentRow = containers.contentRow;
      const listItemClass = 'secator-list-item';
      const tasksPlaceholderHtml = '<div class="text-muted text-center py-5"><i class="fas fa-hand-pointer fa-2x mb-3"></i><p>Select one or more tasks from the list</p></div>';

      const showDetail = function($tile, id, itemType) {
        if (itemType === 'task') {
          const $activeItems = $listContainer.find('.' + listItemClass + '.active');
          const parts = [];
          const activeIds = [];
          $activeItems.each(function() {
            const tileHtml = $(this).data('tile-html');
            if (tileHtml) {
              parts.push(tileHtml);
              activeIds.push($(this).attr('data-item-id'));
            }
          });
          const preservedContent = {};
          $selectionContainer.find('.secator-task-selection-card[data-task-id]').each(function() {
            const taskId = $(this).attr('data-task-id');
            if (!taskId) return;
            const $card = $(this);
            const $badges = $card.find('.secator-task-input-types-badges');
            const $proposed = $card.find('.secator-task-proposed-targets');
            const hasBadges = $badges.length && $badges.contents().length;
            const hasProposed = $proposed.length && $proposed.contents().length;
            if (hasBadges || hasProposed) {
              preservedContent[taskId] = {
                badges: hasBadges ? $badges.contents().clone(true) : null,
                proposedTargets: hasProposed ? $proposed.contents().clone(true) : null
              };
            }
          });
          let combinedHtml;
          if (parts.length) {
            combinedHtml = '<div class="row secator-task-selection-row">' + parts.map(function(html, i) {
              const taskId = activeIds[i];
              const safeId = String(taskId).replace(/"/g, '&quot;');
              return '<div class="col-12 col-sm-6 col-xl-4 col-xxl-3 mb-3">' +
                '<div class="secator-task-selection-card border rounded p-2 h-100" data-task-id="' + safeId + '">' +
                html +
                '<div class="secator-task-input-types mt-2 small"><span class="d-block fw-bold mb-1">Required input types</span><span class="secator-task-input-types-badges"></span></div>' +
                '<div class="secator-task-proposed-targets mt-2 small"></div>' +
                '</div></div>';
            }).join('') + '</div>';
          } else {
            combinedHtml = tasksPlaceholderHtml;
          }
          $selectionContainer.html(combinedHtml);
          Object.keys(preservedContent).forEach(function(taskId) {
            const preserved = preservedContent[taskId];
            const $card = $selectionContainer.find('.secator-task-selection-card[data-task-id="' + taskId + '"]');
            if (!$card.length) return;
            if (preserved.badges && preserved.badges.length) {
              $card.find('.secator-task-input-types-badges').empty().append(preserved.badges);
            }
            if (preserved.proposedTargets && preserved.proposedTargets.length) {
              $card.find('.secator-task-proposed-targets').empty().append(preserved.proposedTargets);
            }
          });
          $contentRow.data('list-view-html', combinedHtml);
          $selectionContainer.find('input[name="task_ids"]').prop('checked', false);
          activeIds.forEach(function(taskId) {
            $selectionContainer.find('input[name="task_ids"][value="' + taskId + '"]').prop('checked', true);
          });
        } else {
          const tileHtml = $tile.length ? $tile[0].outerHTML : '';
          $selectionContainer.html(tileHtml);
          const $injected = $selectionContainer.children();
          if (itemType === 'workflow') {
            $injected.find('input[name="workflow_id"]').prop('checked', false);
            $injected.find('input[name="workflow_id"][value="' + id + '"]').prop('checked', true);
          } else if (itemType === 'scan') {
            $injected.find('input[name="secator_scan_type"]').prop('checked', false);
            $injected.find('input[name="secator_scan_type"][value="' + id + '"]').prop('checked', true);
          }
          $contentRow.data('list-view-html', tileHtml);
        }
        self.initializeSelectionListeners($form);
        $(document).trigger('secator:contentLoaded');
        if (window.SECATOR_INPUT_TYPES_TARGETS_URL && containers.prefix) {
          if (itemType === 'workflow' || itemType === 'scan') {
            const $block = $form.find('#' + containers.prefix + '-input-types-targets');
            if ($block.length) $block.show();
            const $single = $form.find('#' + containers.prefix + '-targets-single');
            if ($single.length) $single.show();
          }
          self.fetchInputTypesAndTargetsForForm($form);
        }
      };

      this.buildCompactList($html, mode, {
        listContainer: $listContainer,
        listItemClass: listItemClass,
        storeTaskTileHtml: true,
        showTaskCategories: false,
        onWorkflowClick: function($tile, workflowId) { showDetail($tile, workflowId, 'workflow'); },
        onScanClick: function($tile, scanType) { showDetail($tile, scanType, 'scan'); },
        onTaskClick: function($tile, taskId) {
          self.updateTaskSelection($form);
          showDetail($tile, taskId, 'task');
        }
      });
      if (typeof this.bindListToolbar === 'function') {
        this.bindListToolbar({
          prefix: containers.prefix,
          mode: mode,
          listContainer: $listContainer,
          listItemClass: listItemClass,
          onSelectionChange: function() {
            if (mode === 'tasks') {
              self.updateTaskSelection($form);
              showDetail(null, null, 'task');
              self.initializeSelectionListeners($form);
              $(document).trigger('secator:contentLoaded');
            }
          }
        });
      }
    },

    handleViewToggle: function(view, e) {
      const $btn = $(e.currentTarget);
      const $toggle = $btn.closest('.secator-view-toggle');
      const contentRowSel = $toggle.attr('data-content-row');
      const $contentRow = contentRowSel ? $(contentRowSel) : $btn.closest('[id$="-content-row"]');
      if (!$contentRow.length) return;
      const $form = $contentRow.closest('form');
      let containers = this.getSecatorContainers($form);
      if (!containers.prefix) {
        const rowPrefix = $contentRow.attr('data-secator-id-prefix') || $contentRow.data('secatorIdPrefix');
        if (rowPrefix) {
          containers = {
            prefix: rowPrefix,
            selectionContainer: $contentRow.find('#' + rowPrefix + '-selection-container'),
            listContainer: $contentRow.find('#' + rowPrefix + '-list-container')
          };
        }
      }
      const $listCol = $contentRow.find('.secator-list-col');
      const $selectionContainer = containers.selectionContainer;
      const $gridNodes = $contentRow.data('secator-grid-nodes');
      const listViewHtml = $contentRow.data('list-view-html');

      $toggle.find('.secator-view-list-btn, .secator-view-grid-btn').removeClass('active');
      $btn.addClass('active');

      if (view === 'grid') {
        $contentRow.removeClass('secator-view-list').addClass('secator-view-grid');
        $listCol.hide();
        if ($gridNodes && $gridNodes.length && $selectionContainer.length) {
          $selectionContainer.empty().append($gridNodes);
        }
        this.initializeSelectionListeners($form);
        $(document).trigger('secator:contentLoaded');
      } else {
        $contentRow.removeClass('secator-view-grid').addClass('secator-view-list');
        $listCol.show();
        if ($gridNodes && $gridNodes.length) $gridNodes.detach();
        if ($selectionContainer.length) {
          const raw = listViewHtml || '';
          const safe = (typeof DOMPurify !== 'undefined' && DOMPurify.sanitize) ? DOMPurify.sanitize(raw, { ALLOWED_TAGS: ['div', 'span', 'input', 'label', 'i', 'h6', 'p', 'button', 'a'], ALLOWED_ATTR: ['class', 'id', 'type', 'name', 'value', 'data-task-id', 'data-category', 'href'] }) : raw;
          $selectionContainer.html(safe);
        }
        if (listViewHtml) this.initializeSelectionListeners($form);
        $(document).trigger('secator:contentLoaded');
      }
    },

    /**
     * Renders proposed targets (workflow/scan single list) into preview area and optionally binds toolbar.
     * @param {Object} data - API response { input_types, proposed_targets, total_count, truncated }
     * @param {Object} options - { $badges, $preview, $toolbar, $warning, prefix, checkboxClass, itemWrapperClass, idPrefix, onRendered }
     */
    renderProposedTargets: function(data, options) {
      const {
        $badges,
        $preview,
        $toolbar,
        $warning,
        prefix,
        checkboxClass = 'secator-target-checkbox',
        itemWrapperClass = 'form-check',
        idPrefix = prefix,
        onRendered
      } = options || {};
      if (!$preview || !$preview.length) return;
      const types = data.input_types || [];
      if ($badges && $badges.length) {
        $badges.empty();
        [...new Set(types)].forEach(t => {
          $badges.append($('<span class="badge badge-soft-primary me-1">').text(t));
        });
      }
      const targets = data.proposed_targets || [];
      const totalCount = data.total_count != null ? data.total_count : targets.length;
      if (totalCount === 0) {
        if ($toolbar && $toolbar.length) $toolbar.hide();
        $preview.html('<span class="text-muted">No targets</span>');
        if ($warning && $warning.length) $warning.show();
      } else {
        if ($warning && $warning.length) $warning.hide();
        if ($toolbar && $toolbar.length) $toolbar.show();
        $preview.empty();
        const commonWebPorts = data.common_web_ports || [];
        const uncommonWebPorts = data.uncommon_web_ports || [];
        targets.forEach((t, idx) => {
          const safeVal = String(t).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
          const id = (idPrefix || prefix) + '-tgt-' + idx;
          const { scheme, targetKind } = window.SecatorScan.inferTargetSchemeAndKind(t);
          const $wrap = $('<div>').addClass(itemWrapperClass + ' form-check-sm');
          if (scheme) $wrap.attr('data-scheme', scheme);
          $wrap.attr('data-target-kind', targetKind || '');
          if (targetKind === 'host:port' && typeof window.SecatorScan.getWebPortType === 'function') {
            const webPortType = window.SecatorScan.getWebPortType(t, commonWebPorts, uncommonWebPorts);
            if (webPortType) $wrap.attr('data-web-port-type', webPortType);
          }
          $wrap.append($('<input>').attr({ type: 'checkbox', id: id, value: safeVal }).addClass('form-check-input ' + checkboxClass).prop('checked', true));
          $wrap.append($('<label>').attr('for', id).addClass('form-check-label text-break').text(t));
          $preview.append($wrap);
        });
        const {truncated} = data;
        if (truncated && totalCount > targets.length) {
          const truncatedText = window.SecatorScan.formatTruncatedCount(targets.length, totalCount, { showing: true });
          $preview.append($('<div class="small text-muted mt-1 w-100">').text(truncatedText));
        }
        if ($toolbar && $toolbar.length && prefix && typeof window.SecatorScan.getQuickFilterButtonsHtml === 'function') {
          const $quickFilters = $toolbar.find('#' + prefix + '-targets-quick-filters');
          if ($quickFilters.length) {
            $quickFilters.html(window.SecatorScan.getQuickFilterButtonsHtml(types));
          }
        }
      }
      if (typeof onRendered === 'function') onRendered(data, options);
    },

    /**
     * Fetches input types and proposed targets using a context (form or modal). Single entry for workflow/scan and tasks.
     * @param {Object} context - { $root, prefix, getExecutionMode, getDomainId, getSubdomainIds, getWorkflowId, getScanName, getTaskIds, getSelectionContainer, checkboxClass?, itemWrapperClass?, onUpdateCount?, renderTasksInto? }
     */
    fetchInputTypesAndTargetsWithContext: function(context) {
      const { $root, prefix, getExecutionMode } = context || {};
      if (!$root || !prefix || !window.SECATOR_INPUT_TYPES_TARGETS_URL) return;
      const executionMode = typeof getExecutionMode === 'function' ? getExecutionMode() : null;
      const $block = $root.find('#' + prefix + '-input-types-targets');
      const $single = $root.find('#' + prefix + '-targets-single');
      const $tasksContainer = $root.find('#' + prefix + '-tasks-targets-container');
      const $badges = $root.find('#' + prefix + '-input-types-badges');
      const $preview = $root.find('#' + prefix + '-targets-preview');
      const $toolbar = $root.find('#' + prefix + '-targets-toolbar');
      const $warning = $root.find('#' + prefix + '-targets-warning');
      const $error = $root.find('#' + prefix + '-targets-error');
      const $loading = $root.find('#' + prefix + '-targets-loading');
      if (!$block.length) return;

      const checkboxClass = context.checkboxClass || 'secator-target-checkbox';
      const itemWrapperClass = context.itemWrapperClass || 'form-check';
      const {onUpdateCount} = context;

      if (executionMode === 'tasks') {
        this.fetchInputTypesAndTargetsForTasksWithContext(context);
        return;
      }

      $badges.prev('h6').add($badges).show();
      $single.prev('h6').add($single).show();
      const {getWorkflowId, getScanName} = context;
      const workflowId = typeof getWorkflowId === 'function' ? getWorkflowId() : null;
      const scanName = typeof getScanName === 'function' ? getScanName() : null;
      if (executionMode === 'workflow' && !workflowId) {
        $block.hide();
        return;
      }
      if (executionMode === 'scan' && !scanName) {
        $block.hide();
        return;
      }

      const { getTargetId, getTargetIds, getSubdomainIds } = context;
      let targetId = typeof getTargetId === 'function' ? getTargetId() : '';
      let targetIds = typeof getTargetIds === 'function' ? getTargetIds() : null;
      const $listInput = $root.find && $root.is('form') ? $root.find('input[name="list_of_target_id"]') : $();
      if ($listInput.length && $listInput.val()) {
        const listVal = $listInput.val();
        const parsed = typeof listVal === 'string' ? listVal.split(',').map(function(s) { return s.trim(); }).filter(Boolean) : [];
        if (parsed.length > 1) {
          targetIds = parsed;
          targetId = '';
        } else if (parsed.length === 1 && !targetIds) {
          targetIds = parsed;
          if (!targetId) targetId = parsed[0];
        }
      }
      const subdomainIds = typeof getSubdomainIds === 'function' ? getSubdomainIds() : [];
      const getIpAddressIds = context.getIpAddressIds;
      const ipAddressIds = typeof getIpAddressIds === 'function' ? getIpAddressIds() : [];
      const getScanHistoryId = context.getScanHistoryId;
      const scanHistoryForIps = typeof getScanHistoryId === 'function' ? getScanHistoryId() : '';
      const hasIpContext = ipAddressIds && ipAddressIds.length && scanHistoryForIps;
      if (!targetId && (!targetIds || !targetIds.length) && (!subdomainIds || !subdomainIds.length) && !hasIpContext) {
        $block.show();
        $single.show();
        $tasksContainer.hide().empty();
        $badges.empty();
        $preview.html('<span class="text-muted">Set target or select subdomain(s) to see proposed targets.</span>');
        $warning.add($error).add($loading).hide();
        if (typeof onUpdateCount === 'function') onUpdateCount();
        return;
      }

      const params = {};
      if (targetIds && targetIds.length > 1) {
        params.target_ids = targetIds.join(',');
      } else if (targetIds && targetIds.length === 1) {
        params.target_id = targetIds[0];
      } else if (targetId) {
        params.target_id = targetId;
      }
      if (hasIpContext) {
        params.ip_address_ids = ipAddressIds.join(',');
        params.scan_history_id = scanHistoryForIps;
      } else if (subdomainIds && subdomainIds.length) {
        params.subdomain_ids = subdomainIds.join(',');
      }
      if (executionMode === 'workflow') params.workflow_id = workflowId;
      if (executionMode === 'scan') params.scan_name = scanName;

      $block.show();
      $single.show();
      $tasksContainer.hide().empty();
      $loading.show();
      $warning.add($error).hide();
      $badges.add($preview).empty();

      const self = this;
      this.requestInputTypesTargets(params)
        .done(function(data) {
          $loading.hide();
          self.renderProposedTargets(data, {
            $badges,
            $preview,
            $toolbar,
            $warning,
            prefix,
            checkboxClass,
            itemWrapperClass,
            idPrefix: prefix,
            onRendered: function(data) {
              self.bindTargetsToolbar({
                $root,
                prefix,
                checkboxClass,
                itemWrapperClass,
                onUpdateCount,
                apexHosts: data && data.apex_hosts
              });
              $(document).trigger('secator:contentLoaded');
            }
          });
        })
        .fail(function(xhr) {
          $loading.hide();
          const errMsg = (xhr.responseJSON && xhr.responseJSON.error) ? xhr.responseJSON.error : 'Failed to load targets';
          $error.text(errMsg).show();
          if (typeof onUpdateCount === 'function') onUpdateCount();
        });
    },

    fetchInputTypesAndTargetsForTasksWithContext: function(context) {
      const { $root, prefix, getTaskIds, getDomainId, getSubdomainIds, getSelectionContainer, checkboxClass = 'secator-target-checkbox', itemWrapperClass = 'form-check', onUpdateCount } = context || {};
      if (!$root || !window.SECATOR_INPUT_TYPES_TARGETS_URL) return;
      const taskIds = typeof getTaskIds === 'function' ? getTaskIds() : [];
      if (!taskIds.length) {
        $root.find('#' + prefix + '-input-types-targets').hide();
        return;
      }
      const subdomainIds = typeof getSubdomainIds === 'function' ? getSubdomainIds() : [];
      const getIpAddressIds = context.getIpAddressIds;
      const ipAddressIds = typeof getIpAddressIds === 'function' ? getIpAddressIds() : [];
      const getScanHistoryId = context.getScanHistoryId;
      const scanHistoryForIps = typeof getScanHistoryId === 'function' ? getScanHistoryId() : '';
      const $selectionContainer = typeof getSelectionContainer === 'function' ? getSelectionContainer() : $();
      const $block = $root.find('#' + prefix + '-input-types-targets');
      const $single = $root.find('#' + prefix + '-targets-single');
      const $tasksContainer = $root.find('#' + prefix + '-tasks-targets-container');
      const $badges = $root.find('#' + prefix + '-input-types-badges');
      const $loading = $root.find('#' + prefix + '-targets-loading');
      const $error = $root.find('#' + prefix + '-targets-error');
      const $warning = $root.find('#' + prefix + '-targets-warning');

      const taskNames = {};
      const taskTypes = {};
      $selectionContainer.find('.task-tile').each(function() {
        const $input = $(this).find('input[name="task_ids"]');
        const id = $input.val();
        taskNames[id] = $(this).find('.task-tile-title').text().trim() || id;
        taskTypes[id] = $input.attr('data-task-type') || id;
      });

      $block.show();
      $single.hide();
      $tasksContainer.empty();
      $loading.show();
      $warning.add($error).hide();
      $badges.empty();
      $badges.prev('h6').add($badges).hide();
      $single.prev('h6').add($single).add($tasksContainer).hide();

      const self = this;
      const targetIdForTasks = typeof context.getTargetId === 'function' ? context.getTargetId() : '';
      const baseParams = targetIdForTasks ? { target_id: targetIdForTasks } : {};
      if (ipAddressIds && ipAddressIds.length && scanHistoryForIps) {
        baseParams.ip_address_ids = ipAddressIds.join(',');
        baseParams.scan_history_id = scanHistoryForIps;
      } else if (subdomainIds && subdomainIds.length) {
        baseParams.subdomain_ids = subdomainIds.join(',');
      }
      this.requestInputTypesTargetsForTasks(taskIds, baseParams)
        .done(function() {
          const results = taskIds.length === 1 ? [arguments[0]] : Array.prototype.slice.call(arguments).map(a => a[0]);
          $loading.hide();
          const blocksData = self.buildTaskTargetsBlocksData(results, taskIds, taskNames, taskTypes, prefix, {
            checkboxClass,
            itemWrapperClass,
            inputNamePrefix: 'subscan_target_task_',
            includeTypesSpan: true,
            previewExtraClass: 'subscan-targets-grid'
          });
          self.injectTaskTargetsIntoDom(context, blocksData, taskIds);
          self.bindTaskTargetsToolbar({ $root, prefix, checkboxClass, itemWrapperClass, onUpdateCount });
          $(document).trigger('secator:contentLoaded');
          if (typeof onUpdateCount === 'function') onUpdateCount();
        })
        .fail(function() {
          $loading.hide();
          $error.text('Failed to load targets for one or more tasks').show();
          if (typeof onUpdateCount === 'function') onUpdateCount();
        });
    },

    fetchInputTypesAndTargetsForForm: function($form) {
      const prefix = this.getSecatorIdPrefix($form);
      if (!prefix || !window.SECATOR_INPUT_TYPES_TARGETS_URL) return;
      const containers = this.getSecatorContainers($form);
      const $selectionContainer = containers.selectionContainer;
      let targetId = $form.find('input[name="target_id"]').val();
      const domainId = $form.find('input[name="domain_id"]').val();
      let targetIds = [];
      const $listInput = $form.find('input[name="list_of_target_id"]');
      if ($listInput.length && $listInput.val()) {
        const listVal = $listInput.val();
        targetIds = typeof listVal === 'string' ? listVal.split(',').map(s => s.trim()).filter(Boolean) : [];
        if (!targetId && targetIds.length) targetId = targetIds[0] || '';
      }
      const context = {
        $root: $form,
        prefix,
        getExecutionMode: () => $form.find('input[name="execution_mode"]').val(),
        getTargetId: () => targetId || $form.find('input[name="target_id"]').val(),
        getTargetIds: () => targetIds.length ? targetIds : null,
        getDomainId: () => domainId || $form.find('input[name="domain_id"]').val(),
        getSubdomainIds: () => [],
        getWorkflowId: () => $selectionContainer.find('input[name="workflow_id"]:checked').val(),
        getScanName: () => $selectionContainer.find('input[name="secator_scan_type"]:checked').val(),
        getTaskIds: () => $selectionContainer.find('input[name="task_ids"]:checked').map(function() { return $(this).val(); }).get(),
        getSelectionContainer: () => $selectionContainer,
        renderTasksInto: 'cards'
      };
      if (context.getExecutionMode() === 'tasks') {
        this.fetchInputTypesAndTargetsForFormTasks($form, prefix, context.getTargetId(), context.getTargetIds(), context.getDomainId(), $selectionContainer,
          $form.find('#' + prefix + '-input-types-targets'), $form.find('#' + prefix + '-targets-single'),
          $form.find('#' + prefix + '-tasks-targets-container'), $form.find('#' + prefix + '-input-types-badges'),
          $form.find('#' + prefix + '-targets-preview'), $form.find('#' + prefix + '-targets-toolbar'),
          $form.find('#' + prefix + '-targets-warning'), $form.find('#' + prefix + '-targets-error'),
          $form.find('#' + prefix + '-targets-loading'));
        return;
      }
      this.fetchInputTypesAndTargetsWithContext(context);
    },

    fetchInputTypesAndTargetsForFormTasks: function($form, prefix, targetId, targetIds, domainId, $selectionContainer, $block, $single, $tasksContainer, $badges, $preview, $toolbar, $warning, $error, $loading) {
      const checkedTasks = $selectionContainer.find('input[name="task_ids"]:checked');
      if (!checkedTasks.length) {
        $block.hide();
        $tasksContainer.data('loaded-task-ids', []).data('compact-parts-by-task', {});
        $form.removeData('subscan-task-targets-counts');
        return;
      }
      const taskIds = checkedTasks.map(function() { return $(this).val(); }).get();
      const taskNames = {};
      const taskTypes = {};
      $selectionContainer.find('.task-tile').each(function() {
        const $input = $(this).find('input[name="task_ids"]');
        const id = $input.val();
        taskNames[id] = $(this).find('.task-tile-title').text().trim() || id;
        taskTypes[id] = $input.attr('data-task-type') || id;
      });
      $block.show();
      $single.hide();
      $warning.add($error).hide();
      $single.prev('h6').add($single).add($tasksContainer).hide();

      const self = this;
      const ids = (targetIds && targetIds.length > 1) ? targetIds : null;
      const baseParams = ids ? { target_ids: ids.join(',') } : (targetId ? { target_id: targetId } : {});
      if (Object.keys(baseParams).length === 0) {
        $loading.hide();
        $error.text('Set target to load proposed targets.').show();
        return;
      }

      const alreadyLoaded = $tasksContainer.data('loaded-task-ids') || [];
      const toAdd = taskIds.filter(function(id) { return alreadyLoaded.indexOf(id) === -1; });
      const toRemove = alreadyLoaded.filter(function(id) { return taskIds.indexOf(id) === -1; });
      const cardsLayout = $selectionContainer.find('.secator-task-selection-card[data-task-id]').length > 0;
      const $contentRow = $form.find('#' + prefix + '-content-row');
      if (cardsLayout && $contentRow.hasClass('secator-view-list')) {
        $block.hide();
      }

      if (toRemove.length > 0) {
        if (cardsLayout) {
          toRemove.forEach(function(taskId) {
            $selectionContainer.find('.secator-task-selection-card[data-task-id="' + taskId + '"]').parent().remove();
          });
        } else {
          toRemove.forEach(function(taskId) {
            $tasksContainer.find('.secator-task-targets-block[data-task-id="' + taskId + '"]').parent().remove();
          });
        }
        let compactByTask = $tasksContainer.data('compact-parts-by-task') || {};
        toRemove.forEach(function(taskId) { delete compactByTask[taskId]; });
        $tasksContainer.data('compact-parts-by-task', compactByTask);
        $tasksContainer.data('loaded-task-ids', taskIds);
        const badgeHtml = taskIds.map(function(id) { return compactByTask[id] || ''; }).filter(Boolean).join('');
        $badges.html(badgeHtml);
        if ($badges.prev('h6').length) $badges.prev('h6').add($badges).show();
        let counts = $form.data('subscan-task-targets-counts') || {};
        toRemove.forEach(function(taskId) { delete counts[taskId]; });
        $form.data('subscan-task-targets-counts', counts);
      }

      if (toAdd.length === 0) {
        $loading.hide();
        if (taskIds.length) {
          if (!cardsLayout) $tasksContainer.show();
          self.bindTaskTargetsToolbarForForm($form, prefix);
        }
        $(document).trigger('secator:contentLoaded');
        return;
      }

      const context = { $root: $form, prefix, getSelectionContainer: () => $selectionContainer };
      const taskOptions = {
        checkboxClass: 'secator-target-checkbox',
        itemWrapperClass: 'form-check',
        inputNamePrefix: 'secator_target_task_',
        includeTypesSpan: false
      };

      if (alreadyLoaded.length === 0) {
        $tasksContainer.empty();
        $badges.empty();
        if ($badges.prev('h6').length) $badges.prev('h6').add($badges).show();
        $loading.show();
        self.requestInputTypesTargetsForTasks(taskIds, baseParams)
          .done(function() {
            const results = taskIds.length === 1 ? [arguments[0]] : Array.prototype.slice.call(arguments).map(function(a) { return a[0]; });
            $loading.hide();
            const blocksData = self.buildTaskTargetsBlocksData(results, taskIds, taskNames, taskTypes, prefix, taskOptions);
            self.injectTaskTargetsIntoDom(context, blocksData, taskIds);
            $tasksContainer.data('loaded-task-ids', taskIds);
            const compactByTask = {};
            blocksData.compactParts.forEach(function(html, i) { compactByTask[taskIds[i]] = html; });
            $tasksContainer.data('compact-parts-by-task', compactByTask);
            self.bindTaskTargetsToolbarForForm($form, prefix);
            $(document).trigger('secator:contentLoaded');
          })
          .fail(function() {
            $loading.hide();
            $badges.prev('h6').add($badges).show();
            $single.prev('h6').add($single).show();
            $error.text('Failed to load targets for one or more tasks').show();
          });
        return;
      }

      if (cardsLayout) {
        $loading.show();
        self.requestInputTypesTargetsForTasks(toAdd, baseParams)
          .done(function() {
            const results = toAdd.length === 1 ? [arguments[0]] : Array.prototype.slice.call(arguments).map(function(a) { return a[0]; });
            $loading.hide();
            const newBlocksData = self.buildTaskTargetsBlocksData(results, toAdd, taskNames, taskTypes, prefix, taskOptions);
            toAdd.forEach(function(taskId, idx) {
              const $card = $selectionContainer.find('.secator-task-selection-card[data-task-id="' + taskId + '"]');
              const $badgesSpan = $card.find('.secator-task-input-types-badges');
              if ($badgesSpan.length && newBlocksData.compactParts[idx]) {
                $badgesSpan.html(newBlocksData.compactParts[idx]);
              }
              const $proposedTargets = $card.find('.secator-task-proposed-targets');
              if ($proposedTargets.length && newBlocksData.taskBlocksHtml[idx]) {
                $proposedTargets.html('<span class="d-block fw-bold mb-1">Proposed targets</span>' + newBlocksData.taskBlocksHtml[idx]);
              }
            });
            let counts = $form.data('subscan-task-targets-counts') || {};
            toAdd.forEach(function(taskId, idx) { counts[taskId] = newBlocksData.counts[taskId]; });
            $form.data('subscan-task-targets-counts', counts);
            let compactByTask = $tasksContainer.data('compact-parts-by-task') || {};
            toAdd.forEach(function(taskId, idx) { compactByTask[taskId] = newBlocksData.compactParts[idx]; });
            $tasksContainer.data('compact-parts-by-task', compactByTask);
            $tasksContainer.data('loaded-task-ids', taskIds);
            const badgeHtml = taskIds.map(function(id) { return compactByTask[id] || ''; }).filter(Boolean).join('');
            $badges.html(badgeHtml);
            if ($badges.prev('h6').length) $badges.prev('h6').add($badges).show();
            self.bindTaskTargetsToolbarForForm($form, prefix);
            $(document).trigger('secator:contentLoaded');
          })
          .fail(function() {
            $loading.hide();
            $badges.prev('h6').add($badges).show();
            $single.prev('h6').add($single).show();
            $error.text('Failed to load targets for one or more tasks').show();
          });
        return;
      }

      $loading.show();
      $tasksContainer.show();
      self.requestInputTypesTargetsForTasks(toAdd, baseParams)
        .done(function() {
          const results = toAdd.length === 1 ? [arguments[0]] : Array.prototype.slice.call(arguments).map(function(a) { return a[0]; });
          $loading.hide();
          const newBlocksData = self.buildTaskTargetsBlocksData(results, toAdd, taskNames, taskTypes, prefix, taskOptions);
          const $row = $tasksContainer.find('.secator-task-selection-row');
          const existingColsByTaskId = {};
          $row.children().each(function() {
            const $col = $(this);
            const tid = $col.find('.secator-task-targets-block').attr('data-task-id');
            if (tid) existingColsByTaskId[tid] = $col.detach();
          });
          $row.empty();
          const colClass = 'col-12 col-sm-6 col-xl-4 col-xxl-3 mb-3';
          taskIds.forEach(function(taskId) {
            if (existingColsByTaskId[taskId]) {
              $row.append(existingColsByTaskId[taskId]);
            } else {
              const idx = toAdd.indexOf(taskId);
              const blockHtml = newBlocksData.taskBlocksHtml[idx];
              $row.append($('<div class="' + colClass + '"></div>').html(blockHtml || ''));
            }
          });
          let counts = $form.data('subscan-task-targets-counts') || {};
          toAdd.forEach(function(taskId, idx) { counts[taskId] = newBlocksData.counts[taskId]; });
          $form.data('subscan-task-targets-counts', counts);
          let compactByTask = $tasksContainer.data('compact-parts-by-task') || {};
          toAdd.forEach(function(taskId, idx) { compactByTask[taskId] = newBlocksData.compactParts[idx]; });
          $tasksContainer.data('compact-parts-by-task', compactByTask);
          $tasksContainer.data('loaded-task-ids', taskIds);
          const badgeHtml = taskIds.map(function(id) { return compactByTask[id] || ''; }).filter(Boolean).join('');
          $badges.html(badgeHtml);
          if ($badges.prev('h6').length) $badges.prev('h6').add($badges).show();
          self.bindTaskTargetsToolbarForForm($form, prefix);
          $(document).trigger('secator:contentLoaded');
        })
        .fail(function() {
          $loading.hide();
          $badges.prev('h6').add($badges).show();
          $single.prev('h6').add($single).show();
          $error.text('Failed to load targets for one or more tasks').show();
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

    initializeTooltipsWithin: function(container) {
      // Initialize Bootstrap tooltips only inside the given container (selector or element).
      // Disposes existing instances first so subscan modal can re-init after AJAX inject.
      if (typeof bootstrap === 'undefined' || !bootstrap.Tooltip) return;
      const root = typeof container === 'string' ? document.querySelector(container) : container;
      if (!root) return;
      const tooltipTriggerList = [].slice.call(root.querySelectorAll('[data-bs-toggle="tooltip"]'));
      tooltipTriggerList.forEach(function (tooltipTriggerEl) {
        const existing = bootstrap.Tooltip.getInstance(tooltipTriggerEl);
        if (existing) existing.dispose();
        new bootstrap.Tooltip(tooltipTriggerEl, {
          delay: { show: 500, hide: 100 },
          html: true,
          boundary: 'viewport',
          container: container
        });
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
      const $container = this.getSecatorContainers($form).selectionContainer;
      if (!$container || !$container.length) return;
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
      const $scope = $form.length ? $form : $switch.closest('#subscan-modal');
      if (!$scope.length) return;
      this.toggleProfileCategory(category, isEnabled, $scope);
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
        // Show section and enable controls; clear inline height/padding/margin left by slideDown so section can grow with content
        $section.slideDown(200, function() {
          $section.css({ height: '', paddingTop: '', marginTop: '', paddingBottom: '', marginBottom: '' });
        });
        $section.find('button, select').prop('disabled', false);
        // Show custom profile select when it has options (modal may not have run inline script in section context)
        $section.find('select[id$="_custom_profile"]').each(function() {
          if (this.options && this.options.length > 1) {
            $(this).show();
          }
        });
        // Activate default profile
        this.activateDefaultProfile(category, $form);
      } else {
        // Hide section and disable controls; clear inline styles and force hide so section and buttons are fully hidden
        $section.slideUp(200, function() {
          $section.css({ height: '', paddingTop: '', marginTop: '', paddingBottom: '', marginBottom: '', overflow: '' });
          $section.hide();
        });
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

      const initScope = function ($scope) {
        Object.keys(categorySwitchMap).forEach(function(category) {
          const switchId = categorySwitchMap[category];
          const $switch = $scope.find(`[id$="${switchId}"], #${switchId}`);
          if ($switch.length) {
            const isEnabled = $switch.is(':checked');
            self.toggleProfileCategory(category, isEnabled, $scope);
          }
        });
      };

      $('form').each(function() {
        const $form = $(this);
        if (!$form.find('input[name="execution_mode"]').length) return;
        initScope($form);
      });
      $('#subscan-modal').each(function() {
        initScope($(this));
      });
    },
    
    handleCategoryFilter: function(e) {
      e.preventDefault();
      e.stopPropagation();

      const $btn = $(e.currentTarget);
      const $container = $btn.closest('.secator-selection-container');
      if (!$container.length) return;

      const category = $btn.data('category');
      if (category === 'all') {
        this.getCategoryFilterBtns($container).removeClass('active');
        $btn.addClass('active');
        this.getCategorySeparators($container).removeClass('d-none');
        this.getCategoryRows($container).removeClass('d-none');
        return;
      }

      this.getCategoryFilterBtnAll($container).removeClass('active');
      $btn.toggleClass('active');

      const activeCategories = this.getCategoryFilterBtnsActive($container).map(function() {
        return $(this).data('category');
      }).get();

      if (activeCategories.length === 0) {
        this.getCategorySeparators($container).removeClass('d-none');
        this.getCategoryRows($container).removeClass('d-none');
        this.getCategoryFilterBtnAll($container).addClass('active');
      } else {
        this.getCategorySeparators($container).addClass('d-none');
        this.getCategoryRows($container).addClass('d-none');
        activeCategories.forEach(cat => {
          this.getCategorySeparatorFor($container, cat).removeClass('d-none');
          this.getCategoryRowsFor($container, cat).removeClass('d-none');
        });
      }
    },
    
    updateSelectedTasksDisplay: function($form) {
      const $container = this.getSecatorContainers($form).selectionContainer;
      if (!$container || !$container.length) return;
      const selectedTasks = $container.find('input[name="task_ids"]:checked');
      const $display = $container.find('[id="selected-tasks-display"], [id$="-selected-tasks-display"]');
      const $badgesContainer = $container.find('[id="selected-tasks-badges"], [id$="-selected-tasks-badges"]');
      
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
        
        const safeTaskName = (typeof htmlEncode === 'function' ? htmlEncode(taskName) : taskName);
        const safeCategory = (typeof htmlEncode === 'function' ? htmlEncode(parentCategory) : parentCategory);
        const badge = $(`
          <span class="badge selected-task-badge" data-task-id="${taskId}" data-category="${safeCategory}">
            ${safeTaskName}
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
      const $container = this.getSecatorContainers($form).selectionContainer;
      
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
      const $container = this.getSecatorContainers($form).selectionContainer;
      if (!$container || !$container.length) return;
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

      const $submitBtn = $form.find('button[type="submit"]');
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
      $('.start-scan-button-container').each(function() {
        const $container = $(this);
        const $form = $container.closest('form');
        if (!$form.length) return;

        let $section = $container.closest('.advanced-config-section');
        if (!$section.length) $section = $container.closest('#select_engine');
        if ($section.length && $section.closest('form')[0] === $form[0]) {
          $container.detach();
          $section.after($container);
        }
      });
    }
  });

  const { SecatorScan } = window;
  const {
    bindTargetsToolbarForForm,
    bindTaskTargetsToolbarForForm,
    fetchInputTypesAndTargetsForForm,
    fetchInputTypesAndTargetsForFormTasks,
    getSecatorIdPrefix,
    getSecatorContainers,
    loadSelectionOptions,
    buildCompactListForForm,
    handleViewToggle,
    initializeSelectionListeners,
    updateTaskSelection
  } = SecatorScan;
  SecatorScan.targetsToolbar = { bindTargetsToolbarForForm, bindTaskTargetsToolbarForForm };
  SecatorScan.inputTypesService = { fetchInputTypesAndTargetsForForm, fetchInputTypesAndTargetsForFormTasks };
  SecatorScan.selectionLayout = {
    getSecatorIdPrefix,
    getSecatorContainers,
    loadSelectionOptions,
    buildCompactListForForm,
    handleViewToggle,
    initializeSelectionListeners,
    updateTaskSelection
  };

  $(function() {
    SecatorScan.init();
    SecatorScan.initializeTooltips();
    SecatorScan.ensureButtonOutsideAdvancedConfig();
    $(document).on('secator:contentLoaded', function() {
      SecatorScan.ensureButtonOutsideAdvancedConfig();
    });

    // Off-then-on for namespaced handlers to avoid duplicate bindings on PJAX/content reloads.
    $(document).off('click.secator_scan', '.scan-workflow-toggle');
    $(document).on('click.secator_scan', '.scan-workflow-toggle', function(e) {
      e.stopPropagation();
    });
    $(document).off('click.secator_scan', '.scan-expand-all');
    $(document).on('click.secator_scan', '.scan-expand-all', function(e) {
      e.stopPropagation();
      const $tile = $(this).closest('.scan-type-tile');
      $tile.find('.scan-workflow-collapse').each(function() {
        if (typeof bootstrap !== 'undefined' && bootstrap.Collapse) {
          const collapseInstance = bootstrap.Collapse.getOrCreateInstance(this, { toggle: false });
          collapseInstance.show();
        }
      });
    });
    $(document).off('click.secator_scan', '.scan-collapse-all');
    $(document).on('click.secator_scan', '.scan-collapse-all', function(e) {
      e.stopPropagation();
      const $tile = $(this).closest('.scan-type-tile');
      $tile.find('.scan-workflow-collapse').each(function() {
        if (typeof bootstrap !== 'undefined' && bootstrap.Collapse) {
          const collapseInstance = bootstrap.Collapse.getOrCreateInstance(this, { toggle: false });
          collapseInstance.hide();
        }
      });
    });
  });
})(jQuery);
