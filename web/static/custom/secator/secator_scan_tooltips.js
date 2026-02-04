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
})(jQuery);
