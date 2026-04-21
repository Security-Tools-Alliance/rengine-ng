/**
 * Secator Scan - Selection listeners: workflow/task/scan tile and checkbox handlers
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  Object.assign(window.SecatorScan, {
    initializeSelectionListeners: function($form) {
      this.initializeTooltips();
      const $container = this.getSecatorContainers($form).selectionContainer;
      if (!$container || !$container.length) return;

      $container.find('.workflow-tile').off('click').on('click', function(e) {
        const $tile = $(this);
        const $input = $tile.find('input[type="radio"]');
        $container.find('.workflow-tile').removeClass('selected');
        $tile.addClass('selected');
        $input.prop('checked', true).trigger('change');
      });

      $container.find('.task-tile').off('click').on('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        const $tile = $(this);
        const $input = $tile.find('input[type="checkbox"]');
        const clickedCheckbox = $(e.target).is('input[type="checkbox"]');
        if (!clickedCheckbox) {
          $input.prop('checked', !$input.prop('checked'));
        }
        if ($input.is(':checked')) {
          $tile.addClass('selected');
        } else {
          $tile.removeClass('selected');
        }
        window.SecatorScan.updateTaskSelection($form);
        if (!clickedCheckbox) {
          $input.trigger('change');
        }
      });

      $container.find('.scan-type-tile').off('click').on('click', function(e) {
        const $tile = $(this);
        const $input = $tile.find('input[type="radio"]');
        $container.find('.scan-type-tile').removeClass('selected');
        $tile.addClass('selected');
        $input.prop('checked', true).trigger('change');
      });

      $container.find('input[id="select_all_tasks"], [id$="-select_all_tasks"]').off('change').on('change', function() {
        const isChecked = $(this).is(':checked');
        $container.find('input[name="task_ids"]').prop('checked', isChecked);
        $container.find('.task-tile').each(function() {
          if (isChecked) {
            $(this).addClass('selected');
          } else {
            $(this).removeClass('selected');
          }
        });
        window.SecatorScan.updateTaskSelection($form);
      });

      $container.find('input[name="task_ids"]').off('change').on('change', function() {
        const $tile = $(this).closest('.task-tile');
        if ($(this).is(':checked')) {
          $tile.addClass('selected');
        } else {
          $tile.removeClass('selected');
        }
        window.SecatorScan.updateTaskSelection($form);
      });
    }
  });
})(jQuery);
