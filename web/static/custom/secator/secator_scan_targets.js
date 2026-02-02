/**
 * Secator Scan - Targets: input types, targets toolbar, selected targets payload
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  Object.assign(window.SecatorScan, {
    getSelectedTargetsPayload: function($form) {
      const prefix = this.getSecatorIdPrefix($form);
      const executionMode = $form.find('input[name="execution_mode"]').val();
      const result = { selected_targets: [], selected_targets_per_task: {} };
      if (!prefix) return result;
      const $targetsPreview = $form.find('#' + prefix + '-targets-preview');
      const $tasksTargetsContainer = $form.find('#' + prefix + '-tasks-targets-container');
      if ($targetsPreview.length && (executionMode === 'workflow' || executionMode === 'scan')) {
        result.selected_targets = $targetsPreview.find('.secator-target-checkbox:checked').map(function() {
          return $(this).val();
        }).get();
      }
      if (executionMode === 'tasks') {
        const $blocks = $form.find('.secator-task-targets-block');
        $blocks.each(function() {
          const taskType = $(this).data('task-type');
          const vals = $(this).find('.secator-target-checkbox:checked').map(function() {
            return $(this).val();
          }).get();
          if (taskType && vals.length) result.selected_targets_per_task[taskType] = vals;
        });
      }
      return result;
    },

    /**
     * Bind select-all / deselect-all / filter and count for a targets preview area.
     * @param {Object} options - { $root, prefix, [checkboxClass], [itemWrapperClass], [onUpdateCount] }
     * @param {jQuery} options.$root - Form or modal root containing the targets UI
     * @param {string} options.prefix - ID prefix (e.g. 'subscan', 'start_scan_')
     * @param {string} [options.checkboxClass='secator-target-checkbox'] - Class on target checkboxes
     * @param {string} [options.itemWrapperClass='form-check'] - Class on item wrapper (for filter visibility)
     * @param {function} [options.onUpdateCount] - Called after count update (e.g. checkSubscanSelection)
     */
    bindTargetsToolbar: function(options) {
      const {
        $root,
        prefix,
        checkboxClass = 'secator-target-checkbox',
        itemWrapperClass = 'form-check',
        onUpdateCount
      } = options || {};
      if (!$root || !prefix) return;

      const ns = 'secatorScanTargetsToolbar.' + prefix;
      const { $preview, $filter, $countText } = this.getTargetsToolbarElements($root, prefix);
      if (!$preview.length) return;

      const checkboxSel = '.' + checkboxClass;
      const itemWrapperSel = '.' + itemWrapperClass;
      const updateCount = function() {
        const total = $preview.find(checkboxSel).length;
        const checked = $preview.find(checkboxSel + ':checked').length;
        if ($countText.length) $countText.text(window.SecatorScan.formatSelectedCount(checked, total));
        if (typeof onUpdateCount === 'function') onUpdateCount();
      };

      $root.off('click.' + ns, '#' + prefix + '-targets-select-all');
      $root.off('click.' + ns, '#' + prefix + '-targets-deselect-all');
      if ($filter.length) {
        $root.off('input.' + ns, '#' + prefix + '-targets-filter');
      }
      $root.off('change.' + ns, '#' + prefix + '-targets-preview ' + checkboxSel);

      $root.on('click.' + ns, '#' + prefix + '-targets-select-all', function() {
        $preview.find(checkboxSel).prop('checked', true);
        $preview.find('.secator-task-target-item, ' + itemWrapperSel).show();
        updateCount();
      });
      $root.on('click.' + ns, '#' + prefix + '-targets-deselect-all', function() {
        $preview.find(checkboxSel).prop('checked', false);
        updateCount();
      });
      if ($filter.length) {
        $root.on('input.' + ns, '#' + prefix + '-targets-filter', function() {
          const q = $(this).val().trim().toLowerCase();
          $preview.find(itemWrapperSel).each(function() {
            const label = $(this).find('label').text().toLowerCase();
            $(this).toggle(!q || label.indexOf(q) !== -1);
          });
          updateCount();
        });
      }
      $root.on('change.' + ns, '#' + prefix + '-targets-preview ' + checkboxSel, updateCount);
      updateCount();
    },

    bindTargetsToolbarForForm: function($form, prefix) {
      this.bindTargetsToolbar({
        $root: $form,
        prefix: prefix,
        checkboxClass: 'secator-target-checkbox',
        itemWrapperClass: 'form-check'
      });
    },

    /**
     * Bind select-all / deselect-all / filter and count for per-task targets blocks.
     * @param {Object} options - { $root, prefix, [checkboxClass], [itemWrapperClass], [onUpdateCount] }
     */
    bindTaskTargetsToolbar: function(options) {
      const {
        $root,
        prefix,
        checkboxClass = 'secator-target-checkbox',
        itemWrapperClass = 'form-check',
        onUpdateCount
      } = options || {};
      if (!$root || !prefix) return;

      const taskNs = 'secatorTaskTargetsToolbar-' + prefix;
      const checkboxSel = '.' + checkboxClass;
      const itemWrapperSel = '.' + itemWrapperClass;
      const updateTaskCounts = function() {
        $root.find('.secator-task-targets-block').each(function() {
          const checked = $(this).find(checkboxSel + ':checked').length;
          const total = $(this).find(checkboxSel).length;
          $(this).find('.secator-task-count-text').text(window.SecatorScan.formatSelectedCount(checked, total));
        });
        if (typeof onUpdateCount === 'function') onUpdateCount();
      };
      $root.off('click.' + taskNs, '.secator-task-select-all');
      $root.off('click.' + taskNs, '.secator-task-deselect-all');
      $root.off('input.' + taskNs, '.secator-task-filter');
      $root.off('change.' + taskNs, '.secator-task-targets-block ' + checkboxSel);

      $root.on('click.' + taskNs, '.secator-task-select-all', function() {
        const taskId = $(this).data('task-id');
        $root.find('.secator-task-targets-block[data-task-id="' + taskId + '"] ' + checkboxSel).prop('checked', true);
        $root.find('.secator-task-targets-block[data-task-id="' + taskId + '"] ' + itemWrapperSel).show();
        $root.find('.secator-task-filter[data-task-id="' + taskId + '"]').val('');
        updateTaskCounts();
      });
      $root.on('click.' + taskNs, '.secator-task-deselect-all', function() {
        const taskId = $(this).data('task-id');
        $root.find('.secator-task-targets-block[data-task-id="' + taskId + '"] ' + checkboxSel).prop('checked', false);
        updateTaskCounts();
      });
      $root.on('input.' + taskNs, '.secator-task-filter', function() {
        const taskId = $(this).data('task-id');
        const q = $(this).val().trim().toLowerCase();
        $root.find('.secator-task-targets-block[data-task-id="' + taskId + '"] ' + itemWrapperSel).each(function() {
          const label = $(this).find('label').text().toLowerCase();
          $(this).toggle(!q || label.indexOf(q) !== -1);
        });
      });
      $root.on('change.' + taskNs, '.secator-task-targets-block ' + checkboxSel, updateTaskCounts);
      updateTaskCounts();
    },

    bindTaskTargetsToolbarForForm: function($form, prefix) {
      this.bindTaskTargetsToolbar({
        $root: $form,
        prefix: prefix,
        checkboxClass: 'secator-target-checkbox',
        itemWrapperClass: 'form-check'
      });
    }
  });
})(jQuery);
