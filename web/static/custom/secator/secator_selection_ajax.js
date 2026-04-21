/**
 * Secator Scan - Selection AJAX: request options, loading and error UI for workflow/scan/tasks list
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  const LOADING_HTML = '<div class="text-center py-4"><i class="fas fa-spinner fa-spin fa-2x"></i></div>';
  const ERROR_HTML = '<div class="alert alert-danger">Error loading options. Please try again.</div>';

  Object.assign(window.SecatorScan, {
    getSelectionRequestOptions: function(mode, prefix) {
      const useApi = Boolean(window.SECATOR_SELECTION_URL && prefix);
      const url = useApi
        ? `${window.SECATOR_SELECTION_URL}?execution_mode=${encodeURIComponent(mode)}&id_prefix=${encodeURIComponent(prefix)}`
        : window.location.pathname;
      const data = useApi ? {} : { ajax: 'true', execution_mode: mode };
      const headers = useApi
        ? { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRFToken': $('input[name="csrfmiddlewaretoken"]').val() }
        : {};
      return { url, type: 'GET', data, headers };
    },

    showSelectionLoading: function(containers, prefix) {
      const { listContainer: $listContainer, selectionContainer: $selectionContainer } = containers;
      if (prefix) {
        window.SecatorScan.setViewToggleVisible(prefix, false);
      }
      if ($listContainer && $listContainer.length) {
        $listContainer.html(LOADING_HTML);
        $selectionContainer.html(LOADING_HTML);
      } else {
        $selectionContainer.html(LOADING_HTML);
      }
    },

    showSelectionError: function(containers, prefix) {
      const { listContainer: $listContainer, selectionContainer: $selectionContainer } = containers;
      if (prefix) {
        window.SecatorScan.setViewToggleVisible(prefix, false);
      }
      if ($listContainer && $listContainer.length) {
        $listContainer.html(ERROR_HTML);
        $selectionContainer.html('');
      } else {
        $selectionContainer.html(ERROR_HTML);
      }
    }
  });
})(jQuery);
