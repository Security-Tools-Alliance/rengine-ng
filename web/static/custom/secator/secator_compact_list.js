/**
 * Secator Scan - Compact list: build workflow/scan/tasks list from selection HTML
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  Object.assign(window.SecatorScan, {
    /**
     * Build compact list (workflow / scan / tasks) from selection HTML. Shared by form and modal.
     * @param {jQuery} $html - Parsed HTML from selection API
     * @param {string} mode - 'workflow' | 'scan' | 'tasks'
     * @param {Object} options - { listContainer, listItemClass, onWorkflowClick, onScanClick, onTaskClick, [storeTaskTileHtml], [showTaskCategories] }
     */
    buildCompactList: function($html, mode, options) {
      const {
        listContainer: $listContainer,
        listItemClass = 'secator-list-item',
        onWorkflowClick,
        onScanClick,
        onTaskClick,
        storeTaskTileHtml = false,
        showTaskCategories = false
      } = options || {};
      if (!$listContainer || !$listContainer.length) return;
      $listContainer.empty();

      const emptyWorkflow = '<div class="alert alert-warning small">No workflows available</div>';
      const emptyScan = '<div class="alert alert-warning small">No scan types available</div>';
      const emptyTasks = '<div class="alert alert-warning small">No tasks available</div>';

      if (mode === 'workflow') {
        const $workflows = $html.find('.workflow-tile');
        if (!$workflows.length) {
          $listContainer.html(emptyWorkflow);
          return;
        }
        const seenWorkflowIds = {};
        $workflows.each(function() {
          const $tile = $(this);
          const workflowId = $tile.find('input[type="radio"]').val();
          if (seenWorkflowIds[workflowId]) return;
          seenWorkflowIds[workflowId] = true;
          const title = $tile.find('.workflow-tile-title').text().trim();
          const desc = $tile.find('.workflow-tile-description').text().trim();
          const icon = $tile.attr('data-secator-icon') || $tile.data('secatorIcon') || 'project-diagram';
          const safeTitle = (typeof htmlEncode === 'function' ? htmlEncode(title) : title);
          const safeDesc = (typeof htmlEncode === 'function' ? htmlEncode(desc || 'No description') : (desc || 'No description'));
          const safeIcon = (typeof icon === 'string' && /^[a-z0-9-]+$/i.test(icon)) ? icon : 'project-diagram';
          const $item = $('<div>').addClass(listItemClass).attr({ 'data-item-id': workflowId, 'data-item-type': 'workflow' })
            .html(`<div class="d-flex align-items-stretch"><div class="secator-list-item-icon"><i class="fas fa-${safeIcon}"></i></div><div class="flex-grow-1 min-w-0"><h6 class="mb-1 small fw-bold">${safeTitle}</h6><p class="mb-0 small text-muted">${safeDesc}</p></div><i class="fas fa-chevron-right text-muted ms-2 align-self-center"></i></div>`);
          $item.on('click', function() {
            $listContainer.find('.' + listItemClass).removeClass('active');
            $item.addClass('active');
            if (typeof onWorkflowClick === 'function') onWorkflowClick($tile, workflowId);
          });
          $listContainer.append($item);
        });
        return;
      }
      if (mode === 'scan') {
        const $scans = $html.find('.scan-type-tile');
        if (!$scans.length) {
          $listContainer.html(emptyScan);
          return;
        }
        $scans.each(function() {
          const $tile = $(this);
          const scanType = $tile.find('input[type="radio"]').val();
          const title = $tile.find('.scan-type-tile-title').text().trim();
          const desc = $tile.find('.scan-type-tile-description').text().trim();
          const icon = $tile.attr('data-secator-icon') || $tile.data('secatorIcon') || 'search';
          const safeTitle = (typeof htmlEncode === 'function' ? htmlEncode(title) : title);
          const safeDesc = (typeof htmlEncode === 'function' ? htmlEncode(desc || 'No description') : (desc || 'No description'));
          const safeIcon = (typeof icon === 'string' && /^[a-z0-9-]+$/i.test(icon)) ? icon : 'search';
          const $item = $('<div>').addClass(listItemClass).attr({ 'data-item-id': scanType, 'data-item-type': 'scan' })
            .html(`<div class="d-flex align-items-stretch"><div class="secator-list-item-icon"><i class="fas fa-${safeIcon}"></i></div><div class="flex-grow-1 min-w-0"><h6 class="mb-1 small fw-bold">${safeTitle}</h6><p class="mb-0 small text-muted">${safeDesc}</p></div><i class="fas fa-chevron-right text-muted ms-2 align-self-center"></i></div>`);
          $item.on('click', function() {
            $listContainer.find('.' + listItemClass).removeClass('active');
            $item.addClass('active');
            if (typeof onScanClick === 'function') onScanClick($tile, scanType);
          });
          $listContainer.append($item);
        });
        return;
      }
      if (mode === 'tasks') {
        let $rows = $html.find('.row[data-category]');
        if (!$rows.length) $rows = $html.find('[data-category]');
        if (!$rows.length) {
          $listContainer.html(emptyTasks);
          return;
        }
        $rows.each(function() {
          const $row = $(this);
          const category = $row.attr('data-category');
          if (showTaskCategories && category) {
            const catLabel = (typeof htmlEncode === 'function' ? htmlEncode(category) : category).replace(/^./, c => c.toUpperCase());
            const $header = $('<div>').addClass('subscan-list-category-header')
              .append($('<strong>').addClass('small text-muted').text(catLabel));
            $listContainer.append($header);
          }
          $row.find('.task-tile').each(function() {
            const $tile = $(this);
            const taskId = $tile.find('input[name="task_ids"]').val();
            const title = $tile.find('.task-tile-title').text().trim();
            const desc = $tile.find('.task-tile-description').text().trim();
            const icon = $tile.attr('data-secator-icon') || $tile.data('secatorIcon') || 'folder';
            const tileHtml = $tile[0].outerHTML;
            const $item = $('<div>').addClass(listItemClass).attr({ 'data-item-id': taskId, 'data-item-type': 'task' });
            if (storeTaskTileHtml) $item.data('tile-html', tileHtml);
            const safeTitle = typeof htmlEncode === 'function' ? htmlEncode(title) : title;
            const safeDesc = typeof htmlEncode === 'function' ? htmlEncode(desc || 'No description') : (desc || 'No description');
            const safeIcon = (typeof icon === 'string' && /^[a-z0-9-]+$/i.test(icon)) ? icon : 'folder';
            $item.html(`<div class="d-flex align-items-stretch"><div class="secator-list-item-icon"><i class="fas fa-${safeIcon}"></i></div><div class="flex-grow-1 min-w-0"><h6 class="mb-1 small fw-bold">${safeTitle}</h6><p class="mb-0 small text-muted">${safeDesc}</p></div><i class="fas fa-chevron-right text-muted ms-2 align-self-center"></i></div>`);
            $item.on('click', function() {
              $item.toggleClass('active');
              if (typeof onTaskClick === 'function') onTaskClick($tile, taskId);
            });
            $listContainer.append($item);
          });
        });
      }
    }
  });
})(jQuery);
