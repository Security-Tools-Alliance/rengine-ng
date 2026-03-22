/**
 * Secator Scan - Compact list: build workflow/scan/tasks list from selection HTML
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  const LIST_CATEGORY_ICONS = {
    'dns': 'search-location',
    'url': 'link',
    'user': 'users',
    'vuln': 'exclamation-triangle',
    'port': 'network-wired',
    'secret': 'key',
    'pattern': 'search',
    'exploit': 'crosshairs',
    'ip': 'map-marked-alt',
    'waf': 'shield-alt'
  };

  const listCategoryIcon = function (category) {
    if (!category || typeof category !== 'string') return 'tag';
    const key = category.toLowerCase().split('/')[0];
    return LIST_CATEGORY_ICONS[key] || 'tag';
  };

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
        const workflowEntries = [];
        $workflows.each(function() {
          const $tile = $(this);
          const workflowId = $tile.find('input[type="radio"]').val();
          if (seenWorkflowIds[workflowId]) return;
          seenWorkflowIds[workflowId] = true;
          const title = $tile.find('.workflow-tile-title').text().trim();
          workflowEntries.push({ $tile, workflowId, title });
        });
        workflowEntries.sort(function(a, b) { return (a.title || '').localeCompare(b.title || '', undefined, { sensitivity: 'base' }); });
        workflowEntries.forEach(function(entry) {
          const $tile = entry.$tile;
          const workflowId = entry.workflowId;
          const title = entry.title;
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
        const scanEntries = [];
        $scans.each(function() {
          const $tile = $(this);
          const scanType = $tile.find('input[type="radio"]').val();
          const title = $tile.find('.scan-type-tile-title').text().trim();
          scanEntries.push({ $tile, scanType, title });
        });
        scanEntries.sort(function(a, b) { return (a.title || '').localeCompare(b.title || '', undefined, { sensitivity: 'base' }); });
        scanEntries.forEach(function(entry) {
          const $tile = entry.$tile;
          const scanType = entry.scanType;
          const title = entry.title;
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
        const taskEntries = [];
        $rows.each(function() {
          const $row = $(this);
          const category = $row.attr('data-category') || '';
          $row.find('.task-tile').each(function() {
            const $tile = $(this);
            const taskId = $tile.find('input[name="task_ids"]').val();
            const title = $tile.find('.task-tile-title').text().trim();
            taskEntries.push({ $tile, taskId, category, title });
          });
        });
        taskEntries.sort(function(a, b) { return (a.title || '').localeCompare(b.title || '', undefined, { sensitivity: 'base' }); });
        let lastCategory = null;
        taskEntries.forEach(function(entry) {
          const $tile = entry.$tile;
          const taskId = entry.taskId;
          const category = entry.category;
          const title = entry.title;
          if (showTaskCategories && category && category !== lastCategory) {
            lastCategory = category;
            const catLabel = (typeof htmlEncode === 'function' ? htmlEncode(category) : category).replace(/^./, function(c) { return c.toUpperCase(); });
            const $header = $('<div>').addClass('subscan-list-category-header')
              .append($('<strong>').addClass('small text-muted').text(catLabel));
            $listContainer.append($header);
          }
          const desc = $tile.find('.task-tile-description').text().trim();
          const icon = $tile.attr('data-secator-icon') || $tile.data('secatorIcon') || 'folder';
          const tileHtml = $tile[0].outerHTML;
          const $item = $('<div>').addClass(listItemClass).attr({ 'data-item-id': taskId, 'data-item-type': 'task' });
          if (category) $item.attr('data-category', category);
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
      }
    },

    /**
     * Bind list toolbar: search, category filters (tasks only), select all / deselect all, count.
     * @param {Object} options - { prefix, mode, listContainer, listItemClass, onSelectionChange }
     */
    bindListToolbar: function(options) {
      const {
        prefix,
        mode,
        listContainer: $listContainer,
        listItemClass = 'secator-list-item',
        onSelectionChange
      } = options || {};
      if (!prefix || !$listContainer || !$listContainer.length) return;

      const $root = $listContainer.closest('[id$="-content-row"]').length ? $listContainer.closest('[id$="-content-row"]') : $(document);
      const $toolbar = $root.find('#' + prefix + '-list-toolbar');
      const $search = $root.find('#' + prefix + '-list-search');
      const $categoryFilters = $root.find('#' + prefix + '-list-category-filters');
      const $selectAll = $root.find('#' + prefix + '-list-select-all');
      const $deselectAll = $root.find('#' + prefix + '-list-deselect-all');
      const $countText = $root.find('#' + prefix + '-list-count-text');

      const itemSelector = '.' + listItemClass;
      const isTasks = mode === 'tasks';

      if ($listContainer.find(itemSelector).length === 0) {
        $toolbar.hide();
        return;
      }
      $toolbar.show();
      $categoryFilters.empty();
      if (isTasks) {
        const categories = [];
        const seen = {};
        $listContainer.find(itemSelector + '[data-category]').each(function() {
          const cat = $(this).attr('data-category');
          if (cat && !seen[cat]) {
            seen[cat] = true;
            categories.push(cat);
          }
        });
        categories.sort(function(a, b) { return (a || '').localeCompare(b || '', undefined, { sensitivity: 'base' }); });
        categories.forEach(function(cat) {
          const icon = listCategoryIcon(cat);
          const $btn = $('<button type="button" class="btn btn-outline-secondary btn-sm secator-list-category-btn"></button>');
          $btn.attr('data-category', cat);
          $btn.attr('title', cat);
          $btn.attr('aria-label', 'Filter: ' + cat);
          $btn.html('<i class="fas fa-' + icon + '"></i>');
          $categoryFilters.append($btn);
        });
        $selectAll.show();
        $deselectAll.show();
        $countText.show();
      } else {
        $selectAll.hide();
        $deselectAll.hide();
        $countText.hide();
      }

      const updateListCount = function () {
        if (!isTasks) return;
        const $visible = $listContainer.find(itemSelector + ':visible');
        const visibleCount = $visible.length;
        const visibleChecked = $visible.filter('.active').length;
        const totalCount = $listContainer.find(itemSelector).length;
        const filterActive = ($search.val() || '').trim() !== '' || $categoryFilters.find('.secator-list-category-btn.active').length > 0;
        let text = '';
        if (typeof window.SecatorScan !== 'undefined' && window.SecatorScan.formatSelectedCountWithFilter) {
          text = window.SecatorScan.formatSelectedCountWithFilter(
            $listContainer.find(itemSelector + '.active').length,
            totalCount,
            filterActive,
            visibleChecked,
            visibleCount
          );
        } else {
          text = visibleChecked + ' of ' + (filterActive ? visibleCount : totalCount) + ' selected';
        }
        $countText.text(text);
      };

      const applyListFilter = function () {
        const query = ($search.val() || '').trim().toLowerCase();
        const activeCategories = [];
        $categoryFilters.find('.secator-list-category-btn.active').each(function() {
          activeCategories.push($(this).attr('data-category'));
        });
        const hasCategoryFilter = isTasks && activeCategories.length > 0;

        $listContainer.find(itemSelector).each(function() {
          const $item = $(this);
          if ($item.hasClass('subscan-list-category-header')) return;
          const text = ($item.find('h6').text() + ' ' + $item.find('p').text()).toLowerCase();
          const matchSearch = !query || text.indexOf(query) !== -1;
          const cat = $item.attr('data-category');
          const matchCategory = !hasCategoryFilter || (cat && activeCategories.indexOf(cat) !== -1);
          $item.toggle(matchSearch && matchCategory);
        });
        $listContainer.find('.subscan-list-category-header').each(function() {
          const $header = $(this);
          const $nextHeader = $header.nextAll('.subscan-list-category-header').first();
          const $between = $nextHeader.length ? $header.nextUntil($nextHeader) : $header.nextAll();
          const anyVisible = $between.filter(itemSelector).filter(':visible').length > 0;
          $header.toggle(anyVisible);
        });
        updateListCount();
      };

      $search.off('input.seclist keyup.seclist').on('input.seclist keyup.seclist', function() { applyListFilter(); });

      $categoryFilters.off('click.seclist').on('click.seclist', '.secator-list-category-btn', function() {
        $(this).toggleClass('active');
        applyListFilter();
      });

      $selectAll.off('click.seclist').on('click.seclist', function() {
        $listContainer.find(itemSelector + ':visible').addClass('active');
        updateListCount();
        if (typeof onSelectionChange === 'function') onSelectionChange();
      });

      $deselectAll.off('click.seclist').on('click.seclist', function() {
        $listContainer.find(itemSelector + ':visible').removeClass('active');
        updateListCount();
        if (typeof onSelectionChange === 'function') onSelectionChange();
      });

      $listContainer.off('click.seclist', itemSelector).on('click.seclist', itemSelector, function() {
        if (isTasks) {
          setTimeout(function() { updateListCount(); }, 0);
        }
      });

      $search.val('');
      $categoryFilters.find('.secator-list-category-btn').removeClass('active');
      applyListFilter();
    }
  });
})(jQuery);
