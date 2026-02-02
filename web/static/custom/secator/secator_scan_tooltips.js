/**
 * Secator Scan - Tooltips and button placement
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  Object.assign(window.SecatorScan, {
    initializeTooltips: function() {
      if (typeof bootstrap === 'undefined' || !bootstrap.Tooltip) return;
      const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
      tooltipTriggerList.forEach(function(tooltipTriggerEl) {
        const existing = bootstrap.Tooltip.getInstance(tooltipTriggerEl);
        if (existing) existing.dispose();
        new bootstrap.Tooltip(tooltipTriggerEl, {
          delay: { show: 500, hide: 100 },
          html: true,
          boundary: 'viewport'
        });
      });
    },

    initializeTooltipsWithin: function(container) {
      if (typeof bootstrap === 'undefined' || !bootstrap.Tooltip) return;
      const root = typeof container === 'string' ? document.querySelector(container) : container;
      if (!root) return;
      const tooltipTriggerList = [].slice.call(root.querySelectorAll('[data-bs-toggle="tooltip"]'));
      tooltipTriggerList.forEach(function(tooltipTriggerEl) {
        const existing = bootstrap.Tooltip.getInstance(tooltipTriggerEl);
        if (existing) existing.dispose();
        new bootstrap.Tooltip(tooltipTriggerEl, {
          delay: { show: 500, hide: 100 },
          html: true,
          boundary: 'viewport',
          container: root
        });
      });
    },

    ensureButtonOutsideAdvancedConfig: function() {
      const $buttonContainer = $('.start-scan-button-container');
      const $advancedConfigSection = $('.advanced-config-section');
      const $form = $('#start-scan-form');

      if (!$buttonContainer.length || !$advancedConfigSection.length || !$form.length) return;

      if ($advancedConfigSection.find($buttonContainer).length > 0) {
        $buttonContainer.detach();
        $advancedConfigSection.after($buttonContainer);
      }

      const $selectEngine = $('#select_engine');
      if ($selectEngine.length && $selectEngine.find($buttonContainer).length > 0) {
        $buttonContainer.detach();
        $selectEngine.after($buttonContainer);
      }

      if ($buttonContainer.closest('form').length === 0) {
        $form.append($buttonContainer);
      }
    }
  });
})(jQuery);
