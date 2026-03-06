/**
 * Secator Scan - Core: prefix, containers, helpers, init, bindEvents
 */
(function($) {
  'use strict';

  const SecatorScan = {
    selectedMode: null,

    getSecatorIdPrefix: function($form) {
      const prefix = $form.attr('data-secator-id-prefix') || $form.data('secatorIdPrefix') || '';
      return (typeof prefix === 'string' && prefix.length) ? prefix : null;
    },

    getSecatorContainers: function($form) {
      const prefix = this.getSecatorIdPrefix($form);
      const result = { prefix, listContainer: null, selectionContainer: null, detailContainer: null, contentRow: null };
      if (!prefix) {
        const $legacy = $form.find('[id="selection-container"]');
        if ($legacy.length) {
          result.selectionContainer = $legacy;
        }
        return result;
      }
      result.contentRow = $form.find('#' + prefix + '-content-row');
      result.listContainer = $form.find('#' + prefix + '-list-container');
      result.selectionContainer = $form.find('#' + prefix + '-selection-container');
      result.detailContainer = $form.find('#' + prefix + '-detail-container');
      if (!result.selectionContainer.length) {
        result.selectionContainer = $form.find('[id="selection-container"]');
      }
      return result;
    },

    getCategoryFilterBtnAll: function($container) {
      return $container.find('.category-filter-btn[data-category="all"]');
    },

    getCategoryFilterBtns: function($container) {
      return $container.find('.category-filter-btn');
    },

    getCategoryFilterBtnsActive: function($container) {
      return $container.find('.category-filter-btn.active:not([data-category="all"])');
    },

    getCategoryRows: function($container) {
      return $container.find('.row[data-category]');
    },

    getCategorySeparators: function($container) {
      return $container.find('.category-separator');
    },

    getCategorySeparatorFor: function($container, category) {
      return $container.find('.category-separator[data-category="' + category + '"]');
    },

    getCategoryRowsFor: function($container, category) {
      return $container.find('.row[data-category="' + category + '"]');
    },

    getProfileSwitchSelector: function(profileKey) {
      const idSuffixes = { speed: 'useSpeedProfile', evasion: 'useEvasionProfile', general: 'useGeneralProfile', network: 'useNetworkProfile' };
      const suffix = idSuffixes[profileKey];
      return suffix ? '[id$="' + suffix + '"], #' + suffix : null;
    },

    getProfileValue: function($form, profileKey) {
      const config = {
        speed: { hiddenName: 'speed_profile', profileTypes: ['speed'], customSelectName: 'speed_custom_profile' },
        evasion: { hiddenName: 'stealth_profile', profileTypes: ['evasion', 'stealth'], customSelectName: 'evasion_custom_profile' },
        general: { hiddenName: 'general_profile', profileTypes: ['general'], customSelectName: 'general_custom_profile' },
        network: { hiddenName: 'network_profile', profileTypes: ['network'], customSelectName: 'network_custom_profile' }
      };
      const c = config[profileKey];
      if (!c) return null;
      const hiddenVal = $form.find('input[name="' + c.hiddenName + '"]').val();
      if (hiddenVal) return hiddenVal;
      for (let i = 0; i < c.profileTypes.length; i++) {
        const v = $form.find('.btn[data-profile-type="' + c.profileTypes[i] + '"].active').data('profile-value');
        if (v) return v;
      }
      return $form.find('select[name="' + c.customSelectName + '"]').val() || null;
    },

    getTargetsToolbarElements: function($form, prefix) {
      return {
        $preview: $form.find('#' + prefix + '-targets-preview'),
        $filter: $form.find('#' + prefix + '-targets-filter'),
        $countText: $form.find('#' + prefix + '-targets-count-text')
      };
    },

    setViewToggleVisible: function(prefix, visible) {
      if (!prefix) return;
      const $toggle = $(document).find('.secator-view-toggle[data-content-row="#' + prefix + '-content-row"]');
      if (visible) {
        $toggle.addClass('secator-view-toggle-visible');
      } else {
        $toggle.removeClass('secator-view-toggle-visible');
      }
    },

    formatTruncatedCount: function(shown, total, options) {
      const showing = (options && options.showing) === true;
      const prefix = showing ? 'showing first ' : 'first ';
      return '(' + prefix + shown + ' of ' + total + ')';
    },

    formatSelectedCount: function(checked, total) {
      return checked + ' of ' + total + ' selected';
    },

    /**
     * Format count text when a filter may be active. When filtered, shows both
     * how many are selected for scan (global) and how many selected in the current view.
     * @param {number} globalChecked - Total checked (will be sent to scan)
     * @param {number} totalCount - Total items
     * @param {boolean} filterActive - Whether a filter is applied
     * @param {number} [visibleChecked] - Checked among visible (when filter active)
     * @param {number} [visibleCount] - Visible items count (when filter active)
     */
    formatSelectedCountWithFilter: function(globalChecked, totalCount, filterActive, visibleChecked, visibleCount) {
      if (!filterActive) {
        return this.formatSelectedCount(globalChecked, totalCount);
      }
      const viewPart = visibleCount != null && visibleChecked != null
        ? visibleChecked + ' of ' + visibleCount + ' in view'
        : '';
      const scanPart = globalChecked + ' selected for scan';
      return viewPart ? scanPart + ' · ' + viewPart : scanPart;
    },

    init: function() {
      this.bindEvents();
      this.initializeSubmitButtons();
    },

    bindEvents: function() {
      $(document).on('click', '.execution-mode-card', this.handleModeSelection.bind(this));
      $(document).on('change', '[id$="useRandomProxy"], #useRandomProxy', this.toggleRandomProxy);
      $(document).on('click', '.category-filter-btn', this.handleCategoryFilter.bind(this));
      $(document).on('click', '#clear-all-tasks', this.clearAllTasks.bind(this));
      $(document).on('click', '.remove-task', this.removeTask.bind(this));
      $(document).on('submit', '#start-scan-form', this.handleFormSubmission.bind(this));
      $(document).on('submit', 'form[data-secator-id-prefix]', this.injectSelectedTargetsIntoForm.bind(this));
      $(document).on('click', '.secator-view-list-btn', this.handleViewToggle.bind(this, 'list'));
      $(document).on('click', '.secator-view-grid-btn', this.handleViewToggle.bind(this, 'grid'));
      $(document).on(
        'change',
        'input[name="workflow_id"], input[name="task_ids"], input[name="secator_scan_type"]',
        function(e) {
          const $form = $(e.target).closest('form');
          window.SecatorScan.updateSubmitButtonState($form);
          if (window.SecatorScan.getSecatorIdPrefix($form) && window.SECATOR_INPUT_TYPES_TARGETS_URL) {
            window.SecatorScan.fetchInputTypesAndTargetsForForm($form);
          }
        }
      );
      $(document).on('click', '.execution-mode-card', function(e) {
        const $form = $(e.currentTarget).closest('form');
        window.SecatorScan.updateSubmitButtonState($form);
      });
      $(document).on('secator:contentLoaded', function() {
        $('form').each(function() {
          window.SecatorScan.updateSubmitButtonState($(this));
        });
      });
    }
  };

  window.SecatorScan = SecatorScan;
  window.ScanParamsProfilesInitialized = true;
})(jQuery);
