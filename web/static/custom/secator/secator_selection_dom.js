/**
 * Secator Scan - Selection DOM: apply selection HTML response (list, view toggle, listeners)
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  const PLACEHOLDER_HTML = '<div class="text-muted text-center py-5"><i class="fas fa-hand-pointer fa-2x mb-3"></i><p>Select an item from the list to view details</p></div>';

  Object.assign(window.SecatorScan, {
    applySelectionSuccess: function(data, containers, mode, $form) {
      const { html } = data;
      if (!html) {
        const { prefix } = containers;
        window.SecatorScan.showSelectionError(containers, prefix);
        return;
      }
      const {
        listContainer: $listContainer,
        selectionContainer: $selectionContainer,
        contentRow: $contentRow,
        prefix
      } = containers;

      if ($listContainer.length && $contentRow.length) {
        const $gridNodes = $(html);
        $contentRow.data('secator-grid-nodes', $gridNodes).data('list-view-html', PLACEHOLDER_HTML);
        window.SecatorScan.buildCompactListForForm($gridNodes, mode, containers, $form);
        $contentRow.show().css('display', '').removeAttr('aria-hidden');
        const hasItems = $listContainer.find('.secator-list-item, .subscan-list-item').length > 0;
        if (prefix) {
          window.SecatorScan.setViewToggleVisible(prefix, hasItems);
        }
        if ($contentRow.hasClass('secator-view-grid')) {
          $selectionContainer.empty().append($gridNodes);
          $contentRow.find('.secator-list-col').hide();
          window.SecatorScan.initializeSelectionListeners($form);
        } else {
          $selectionContainer.html(PLACEHOLDER_HTML);
        }
      } else {
        $selectionContainer.empty().append($(html));
      }

      window.SecatorScan.initializeSelectionListeners($form);
      window.SecatorScan.initializeTooltips();
      window.SecatorScan.updateSuggestions(mode, $form);
      setTimeout(function() {
        $(document).trigger('secator:contentLoaded');
        if (window.SECATOR_INPUT_TYPES_TARGETS_URL && prefix) {
          window.SecatorScan.fetchInputTypesAndTargetsForForm($form);
        }
      }, 100);
    }
  });
})(jQuery);
