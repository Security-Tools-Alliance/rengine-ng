/**
 * Secator Scan - Input types tasks: multi-task GET, build blocks data, inject into DOM
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  Object.assign(window.SecatorScan, {
    requestInputTypesTargetsForTasks: function(taskIds, baseParams) {
      const baseUrl = window.SECATOR_INPUT_TYPES_TARGETS_URL || '';
      const sep = baseUrl.indexOf('?') !== -1 ? '&' : '?';
      const csrfToken = $('input[name="csrfmiddlewaretoken"]').val();
      const promises = taskIds.map(taskId => {
        const params = Object.assign({}, baseParams, { task_id: taskId });
        return $.ajax({
          url: baseUrl + sep + $.param(params),
          type: 'GET',
          headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRFToken': csrfToken }
        });
      });
      return $.when.apply($, promises);
    },

    buildTaskTargetsBlocksData: function(results, taskIds, taskNames, taskTypes, prefix, options) {
      const checkboxClass = (options && options.checkboxClass) || 'secator-target-checkbox';
      const itemWrapperClass = (options && options.itemWrapperClass) || 'form-check';
      const inputNamePrefix = (options && options.inputNamePrefix) || 'secator_target_task_';
      const includeTypesSpan = options && options.includeTypesSpan !== false;
      const previewExtraClass = (options && options.previewExtraClass) || '';

      const compactParts = [];
      const taskBlocksHtml = [];
      const counts = {};
      const previewClass = 'secator-task-targets-preview small' + (previewExtraClass ? ' ' + previewExtraClass : '');

      results.forEach((data, i) => {
        const taskId = taskIds[i];
        const taskName = taskNames[taskId] || taskId;
        const taskType = taskTypes[taskId] || taskId;
        const types = (data && data.input_types) ? data.input_types : [];
        const uniqueTypes = [...new Set(types)];
        compactParts.push('<span class="me-2"><strong class="small">' + taskName + '</strong>: <span class="badge badge-soft-primary small">' + (uniqueTypes.join('</span> <span class="badge badge-soft-primary small">') || '—') + '</span></span>');
        const targets = (data && data.proposed_targets) ? data.proposed_targets : [];
        const totalCount = (data && data.total_count != null) ? data.total_count : targets.length;
        const truncated = data && data.truncated;
        const commonWebPorts = (data && data.common_web_ports) ? data.common_web_ports : [];
        const uncommonWebPorts = (data && data.uncommon_web_ports) ? data.uncommon_web_ports : [];
        let previewHtml = '';
        targets.forEach((t, idx) => {
          const safeVal = String(t).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
          const id = prefix + '-task-' + taskId + '-tgt-' + idx;
          const name = inputNamePrefix + taskId;
          const { scheme, targetKind } = window.SecatorScan.inferTargetSchemeAndKind(t);
          const dataScheme = scheme ? ' data-scheme="' + scheme + '"' : '';
          const dataKind = ' data-target-kind="' + (targetKind || '') + '"';
          let dataWebPortType = '';
          if (targetKind === 'host:port' && typeof window.SecatorScan.getWebPortType === 'function') {
            const webPortType = window.SecatorScan.getWebPortType(t, commonWebPorts, uncommonWebPorts);
            if (webPortType) dataWebPortType = ' data-web-port-type="' + webPortType + '"';
          }
          previewHtml += '<div class="' + itemWrapperClass + ' form-check form-check-sm"' + dataScheme + dataKind + dataWebPortType + '><input class="form-check-input ' + checkboxClass + '" type="checkbox" data-task-id="' + taskId + '" data-task-type="' + taskType + '" name="' + name + '" id="' + id + '" value="' + safeVal + '" checked><label class="form-check-label text-break" for="' + id + '">' + t + '</label></div>';
        });
        if (truncated && totalCount > targets.length) {
          const truncatedText = window.SecatorScan.formatTruncatedCount(targets.length, totalCount);
          previewHtml += '<div class="small text-muted mt-1 w-100">' + truncatedText + '</div>';
        }
        counts[taskId] = targets.length;
        const typesSpan = includeTypesSpan ? ' <span class="secator-task-types"></span>' : '';
        const quickFiltersButtonsHtml = window.SecatorScan.getQuickFilterButtonsHtml ? window.SecatorScan.getQuickFilterButtonsHtml(types) : '';
        const quickFiltersHtml = '<div class="secator-task-quick-filters d-flex flex-wrap align-items-center gap-1" title="Filter by type (toggle to filter)">' + quickFiltersButtonsHtml + '</div>';
        const blockHtml = '<div class="secator-task-targets-block border rounded p-2 mb-2 bg-light" data-task-id="' + taskId + '" data-task-type="' + taskType + '">' +
          '<div class="d-flex justify-content-between align-items-center mb-1 small"><strong>' + taskName + '</strong>' + typesSpan + '</div>' +
          '<div class="d-flex flex-wrap align-items-center gap-2 mb-1 small">' +
          '<input type="text" class="form-control form-control-sm secator-task-filter" placeholder="Filter..." style="max-width:160px" data-task-id="' + taskId + '" autocomplete="off">' +
          quickFiltersHtml +
          '<button type="button" class="btn btn-outline-secondary btn-sm secator-task-select-all" data-task-id="' + taskId + '">Select all</button>' +
          '<button type="button" class="btn btn-outline-secondary btn-sm secator-task-deselect-all" data-task-id="' + taskId + '">Deselect all</button>' +
          '<span class="secator-task-count-text text-muted"></span></div>' +
          '<div class="' + previewClass + '" style="max-height:180px;overflow-y:auto">' + (previewHtml || '<span class="text-muted">—</span>') + '</div></div>';
        taskBlocksHtml.push(blockHtml);
      });
      return { compactParts, taskBlocksHtml, counts };
    },

    injectTaskTargetsIntoDom: function(context, blocksData, taskIds) {
      const { $root, prefix, getSelectionContainer } = context;
      const { compactParts, taskBlocksHtml, counts } = blocksData;
      const $tasksContainer = $root.find('#' + prefix + '-tasks-targets-container');
      const $badges = $root.find('#' + prefix + '-input-types-badges');
      const selectionContainer = typeof getSelectionContainer === 'function' ? getSelectionContainer() : null;
      const injectIntoCards =
        selectionContainer &&
        selectionContainer.find('.secator-task-selection-card[data-task-id]').length > 0;

      if (injectIntoCards) {
        taskIds.forEach(function(taskId, i) {
          const $card = selectionContainer.find('.secator-task-selection-card[data-task-id="' + taskId + '"]');
          const $badgesSpan = $card.find('.secator-task-input-types-badges');
          if ($badgesSpan.length && compactParts[i]) {
            $badgesSpan.html(compactParts[i]);
          }
          const $proposedTargets = $card.find('.secator-task-proposed-targets');
          if ($proposedTargets.length && taskBlocksHtml[i]) {
            $proposedTargets.html('<span class="d-block fw-bold mb-1">Proposed targets</span>' + taskBlocksHtml[i]);
          }
        });
        $tasksContainer.hide().empty();
        const $contentRow = $root.find('#' + prefix + '-content-row');
        if ($contentRow.hasClass('secator-view-list')) {
          $root.find('#' + prefix + '-input-types-targets').hide();
        }
      } else {
        if (prefix === 'subscan') {
          $root.find('#' + prefix + '-input-types-targets').show();
        }
        $badges.html(compactParts.join(''));
        const tasksRowHtml = '<div class="row secator-task-selection-row">' +
          taskBlocksHtml.map(block => '<div class="col-12 col-sm-6 col-xl-4 col-xxl-3 mb-3">' + block + '</div>').join('') +
          '</div>';
        $tasksContainer.html(tasksRowHtml).show();
      }
      $root.data('subscan-task-targets-counts', counts);
    }
  });
})(jQuery);
