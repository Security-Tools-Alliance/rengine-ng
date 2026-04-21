/**
 * Secator Scan - Input types AJAX: GET input types and proposed targets (workflow or scan)
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  Object.assign(window.SecatorScan, {
    /**
     * Performs GET request for input types and proposed targets. No DOM updates.
     * @param {Object} params - { target_id?|domain_id?, subdomain_ids?, workflow_id?|scan_name? }
     * @returns {jQuery.Promise}
     */
    requestInputTypesTargets: function(params) {
      const baseUrl = window.SECATOR_INPUT_TYPES_TARGETS_URL || '';
      const sep = baseUrl.indexOf('?') !== -1 ? '&' : '?';
      const url = baseUrl + sep + $.param(params);
      const csrfToken = $('input[name="csrfmiddlewaretoken"]').val();
      return $.ajax({
        url: url,
        type: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRFToken': csrfToken }
      });
    }
  });
})(jQuery);
