/**
 * Secator Scan - Targets: input types, targets toolbar, selected targets payload
 * Infers target scheme/kind from value (aligned with Secator autodetect_type).
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  const HOST_PORT_RE = /^(.+):(\d+)$/;
  const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)$/;
  const IPV6_RE = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$/;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
  const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
  const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

  const inferTargetSchemeAndKind = function (value) {
    const s = String(value).trim();
    if (!s) return { scheme: null, targetKind: 'str' };
    const lower = s.toLowerCase();
    if (lower.startsWith('https://')) return { scheme: 'https', targetKind: 'url' };
    if (lower.startsWith('http://')) return { scheme: 'http', targetKind: 'url' };
    if (lower.startsWith('gs://')) return { scheme: 'gcs_url', targetKind: 'gcs_url' };
    if (s.indexOf('/') !== -1) {
      const parts = s.split('/');
      if (parts.length === 2) {
        const prefix = parts[0].trim();
        const suffix = parseInt(parts[1], 10);
        if (!isNaN(suffix) && ((IPV4_RE.test(prefix) && suffix >= 0 && suffix <= 32) || (IPV6_RE.test(prefix) && suffix >= 0 && suffix <= 128))) {
          return { scheme: null, targetKind: 'cidr_range' };
        }
      }
    }
    if (IPV4_RE.test(s) || IPV6_RE.test(s) || s === 'localhost') return { scheme: null, targetKind: 'ip' };
    if (DOMAIN_RE.test(s)) return { scheme: null, targetKind: 'host' };
    const hostPortMatch = s.match(HOST_PORT_RE);
    if (hostPortMatch) {
      const host = hostPortMatch[1];
      const port = parseInt(hostPortMatch[2], 10);
      if (port >= 1 && port <= 65535 && (DOMAIN_RE.test(host) || IPV4_RE.test(host) || host === 'localhost')) {
        return { scheme: null, targetKind: 'host:port' };
      }
    }
    if (/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(s)) return { scheme: null, targetKind: 'mac' };
    if (EMAIL_RE.test(s)) return { scheme: null, targetKind: 'email' };
    if (/^[A-Za-z]{2}[0-9]{2}\s?[A-Za-z0-9]{4}\s?[A-Za-z0-9]{4}\s?[A-Za-z0-9]{4}\s?[A-Za-z0-9]{0,4}$/.test(s.replace(/\s/g, ''))) return { scheme: null, targetKind: 'iban' };
    if (UUID_RE.test(s)) return { scheme: null, targetKind: 'uuid' };
    if (SLUG_RE.test(lower)) return { scheme: null, targetKind: 'slug' };
    return { scheme: null, targetKind: 'url' };
  };

  /**
   * Simple two-label domain heuristic used as a fallback when the backend
   * does not send apex_hosts.
   *
   * Only checks for exactly two labels with non-empty parts. Does NOT use the
   * Public Suffix List and does NOT handle multi-part TLDs (e.g. co.uk, com.au).
   * Prefer apexHosts from the API (tldextract-based) when available.
   */
  const isSimpleTwoLabelDomain = function (value) {
    const s = String(value).trim();
    if (!s) return false;
    const parts = s.split('.');
    return parts.length === 2 && parts[0].length > 0 && parts[1].length > 0;
  };

  const QUICK_FILTER_ORDER = ['http', 'https', 'email', 'url', 'host', 'tld', 'host:port', 'ip', 'cidr_range', 'common_web_port', 'uncommon_web_port'];
  const INPUT_TYPES_TO_QUICK_FILTERS = {
    url: ['http', 'https', 'url'],
    host: ['host', 'tld'],
    'host:port': ['host:port', 'common_web_port', 'uncommon_web_port'],
    host_port: ['host:port', 'common_web_port', 'uncommon_web_port'],
    ip: ['ip'],
    cidr_range: ['cidr_range'],
    email: ['email']
  };
  const QUICK_FILTER_BUTTONS = {
    http: { icon: 'fa-link', title: 'HTTP URLs', ariaLabel: 'Filter: HTTP URLs' },
    https: { icon: 'fa-lock', title: 'HTTPS URLs', ariaLabel: 'Filter: HTTPS URLs' },
    email: { icon: 'fa-envelope', title: 'Email', ariaLabel: 'Filter: Email' },
    url: { icon: 'fa-globe', title: 'URL (any scheme)', ariaLabel: 'Filter: URL' },
    host: { icon: 'fa-server', title: 'Host', ariaLabel: 'Filter: Host' },
    tld: { icon: 'fa-flag', title: 'TLDs only (apex domains)', ariaLabel: 'Filter: TLDs only' },
    'host:port': { icon: 'fa-plug', title: 'Host:port', ariaLabel: 'Filter: Host:port' },
    ip: { icon: 'fa-network-wired', title: 'IP address', ariaLabel: 'Filter: IP' },
    cidr_range: { icon: 'fa-th-large', title: 'CIDR range', ariaLabel: 'Filter: CIDR range' },
    common_web_port: { icon: 'fa-globe-americas', title: 'Common web ports', ariaLabel: 'Filter: Common web ports' },
    uncommon_web_port: { icon: 'fa-code-branch', title: 'Uncommon web ports', ariaLabel: 'Filter: Uncommon web ports' }
  };

  const getWebPortType = function (value, commonWebPorts, uncommonWebPorts) {
    if (!value || typeof value !== 'string') return '';
    const m = value.trim().match(HOST_PORT_RE);
    if (!m) return '';
    const port = parseInt(m[2], 10);
    if (isNaN(port) || port < 1 || port > 65535) return '';
    const common = Array.isArray(commonWebPorts) ? commonWebPorts : [];
    const uncommon = Array.isArray(uncommonWebPorts) ? uncommonWebPorts : [];
    if (common.indexOf(port) !== -1) return 'common';
    if (uncommon.indexOf(port) !== -1) return 'uncommon';
    return '';
  };

  const getQuickFilterKeysForInputTypes = function (inputTypes) {
    const show = new Set();
    (inputTypes || []).forEach(function(it) {
      const keys = INPUT_TYPES_TO_QUICK_FILTERS[it];
      if (keys) keys.forEach(function(k) { show.add(k); });
    });
    return QUICK_FILTER_ORDER.filter(function(k) { return show.has(k); });
  };

  const getQuickFilterButtonsHtml = function (inputTypes) {
    const keys = getQuickFilterKeysForInputTypes(inputTypes);
    return keys.map(function(k) {
      const c = QUICK_FILTER_BUTTONS[k];
      if (!c) return '';
      return '<button type="button" class="btn btn-outline-secondary btn-sm" data-quick-filter="' + k + '" title="' + c.title + '" aria-label="' + c.ariaLabel + '"><i class="fas ' + c.icon + '"></i></button>';
    }).join('');
  };

  const updateQuickFiltersVisibility = function ($toolbar, prefix, inputTypes) {
    if (!$toolbar || !$toolbar.length || !prefix) return;
    const keysToShow = getQuickFilterKeysForInputTypes(inputTypes);
    const $container = $toolbar.find('#' + prefix + '-targets-quick-filters');
    if (!$container.length) return;
    $container.find('[data-quick-filter]').each(function() {
      const key = $(this).attr('data-quick-filter');
      $(this).toggle(key && keysToShow.indexOf(key) !== -1);
    });
  };

  Object.assign(window.SecatorScan, {
    inferTargetSchemeAndKind: inferTargetSchemeAndKind,
    getWebPortType: getWebPortType,
    getQuickFilterKeysForInputTypes: getQuickFilterKeysForInputTypes,
    getQuickFilterButtonsHtml: getQuickFilterButtonsHtml,
    updateQuickFiltersVisibility: updateQuickFiltersVisibility,

    getSelectedTargetsPayload: function($form) {
      const prefix = this.getSecatorIdPrefix($form);
      const executionMode = $form.find('input[name="execution_mode"]').val();
      const result = { selected_targets: [], selected_targets_per_task: {} };
      if (!prefix) return result;
      const $targetsPreview = $form.find('#' + prefix + '-targets-preview');
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
        onUpdateCount,
        apexHosts
      } = options || {};
      if (!$root || !prefix) return;

      const ns = 'secatorScanTargetsToolbar.' + prefix;
      const { $preview, $filter, $countText } = this.getTargetsToolbarElements($root, prefix);
      if (!$preview.length) return;

      const $quickFilters = $root.find('#' + prefix + '-targets-quick-filters');
      const checkboxSel = '.' + checkboxClass;
      const itemWrapperSel = '.' + (itemWrapperClass || 'form-check').trim().split(/\s+/).filter(Boolean).join('.');

      const applyFilter = function() {
        const q = $filter.length ? $filter.val().trim().toLowerCase() : '';
        const activeKinds = [];
        if ($quickFilters.length) {
          $quickFilters.find('.btn.active').each(function() {
            const k = $(this).attr('data-quick-filter');
            if (k) activeKinds.push(k);
          });
        }
        $preview.find(itemWrapperSel).each(function() {
          const $w = $(this);
          const labelMatch = !q || $w.find('label').text().toLowerCase().indexOf(q) !== -1;
          const kind = $w.attr('data-target-kind') || '';
          const scheme = $w.attr('data-scheme') || '';
          const webPortType = $w.attr('data-web-port-type') || '';
          let kindMatch = true;
          if (activeKinds.length > 0) {
            kindMatch = activeKinds.some(function(k) {
              if (k === 'url') return kind === 'url';
              if (k === 'http' || k === 'https') return scheme === k;
              if (k === 'common_web_port') return webPortType === 'common';
              if (k === 'uncommon_web_port') return webPortType === 'uncommon';
              if (k === 'tld') {
                const val = $w.find(checkboxSel).val();
                return kind === 'host' && (apexHosts && apexHosts.length ? apexHosts.indexOf(val) !== -1 : isSimpleTwoLabelDomain(val));
              }
              return kind === k;
            });
          }
          $w.toggle(labelMatch && kindMatch);
        });
      };

      const updateCount = function() {
        const total = $preview.find(checkboxSel).length;
        const globalChecked = $preview.find(checkboxSel + ':checked').length;
        const filterActive = ($filter.length && $filter.val().trim() !== '') || ($quickFilters.length && $quickFilters.find('.btn.active').length > 0);
        const $visibleWrappers = $preview.find(itemWrapperSel + ':visible');
        const visibleCount = $visibleWrappers.length;
        const visibleChecked = filterActive ? $visibleWrappers.find(checkboxSel + ':checked').length : null;
        if ($countText.length) {
          $countText.text(window.SecatorScan.formatSelectedCountWithFilter(globalChecked, total, filterActive, visibleChecked, visibleCount));
        }
        if (typeof onUpdateCount === 'function') onUpdateCount();
      };

      $root.off('click.' + ns, '#' + prefix + '-targets-select-all');
      $root.off('click.' + ns, '#' + prefix + '-targets-deselect-all');
      $root.off('click.' + ns, '#' + prefix + '-targets-quick-filters .btn');
      if ($filter.length) {
        $root.off('input.' + ns, '#' + prefix + '-targets-filter');
      }
      $root.off('change.' + ns, '#' + prefix + '-targets-preview ' + checkboxSel);

      $root.on('click.' + ns, '#' + prefix + '-targets-select-all', function() {
        $preview.find(itemWrapperSel + ':visible').each(function() {
          $(this).find(checkboxSel).prop('checked', true);
        });
        updateCount();
      });
      $root.on('click.' + ns, '#' + prefix + '-targets-deselect-all', function() {
        $preview.find(itemWrapperSel + ':visible').each(function() {
          $(this).find(checkboxSel).prop('checked', false);
        });
        updateCount();
      });
      $root.on('click.' + ns, '#' + prefix + '-targets-quick-filters .btn', function() {
        $(this).toggleClass('active');
        applyFilter();
        updateCount();
      });
      if ($filter.length) {
        $root.on('input.' + ns, '#' + prefix + '-targets-filter', function() {
          applyFilter();
          updateCount();
        });
      }
      $root.on('change.' + ns, '#' + prefix + '-targets-preview ' + checkboxSel, updateCount);
      applyFilter();
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
      const itemWrapperSel = '.' + (itemWrapperClass || 'form-check').trim().split(/\s+/).filter(Boolean).join('.');

      const applyFilterForBlock = function($block) {
        const $filter = $block.find('.secator-task-filter');
        const $quickFilters = $block.find('.secator-task-quick-filters');
        const q = $filter.length ? $filter.val().trim().toLowerCase() : '';
        const activeKinds = [];
        if ($quickFilters.length) {
          $quickFilters.find('.btn.active').each(function() {
            const k = $(this).attr('data-quick-filter');
            if (k) activeKinds.push(k);
          });
        }
        $block.find(itemWrapperSel).each(function() {
          const $w = $(this);
          const labelMatch = !q || $w.find('label').text().toLowerCase().indexOf(q) !== -1;
          const kind = $w.attr('data-target-kind') || '';
          const scheme = $w.attr('data-scheme') || '';
          const webPortType = $w.attr('data-web-port-type') || '';
          let kindMatch = true;
          if (activeKinds.length > 0) {
            const apexHostsBlock = $block.data('apexHosts');
            kindMatch = activeKinds.some(function(k) {
              if (k === 'url') return kind === 'url';
              if (k === 'http' || k === 'https') return scheme === k;
              if (k === 'common_web_port') return webPortType === 'common';
              if (k === 'uncommon_web_port') return webPortType === 'uncommon';
              if (k === 'tld') {
                const val = $w.find(checkboxSel).val();
                return kind === 'host' && (apexHostsBlock && apexHostsBlock.length ? apexHostsBlock.indexOf(val) !== -1 : isSimpleTwoLabelDomain(val));
              }
              return kind === k;
            });
          }
          $w.toggle(labelMatch && kindMatch);
        });
      };

      const updateTaskCounts = function() {
        $root.find('.secator-task-targets-block').each(function() {
          const $block = $(this);
          const $filter = $block.find('.secator-task-filter');
          const $quickFilters = $block.find('.secator-task-quick-filters');
          const total = $block.find(checkboxSel).length;
          const globalChecked = $block.find(checkboxSel + ':checked').length;
          const $visibleWrappers = $block.find(itemWrapperSel + ':visible');
          const visibleCount = $visibleWrappers.length;
          const filterActive = ($filter.length && $filter.val().trim() !== '') || ($quickFilters.length && $quickFilters.find('.btn.active').length > 0);
          const visibleChecked = filterActive ? $visibleWrappers.find(checkboxSel + ':checked').length : null;
          $block.find('.secator-task-count-text').text(window.SecatorScan.formatSelectedCountWithFilter(globalChecked, total, filterActive, visibleChecked, visibleCount));
        });
        if (typeof onUpdateCount === 'function') onUpdateCount();
      };

      $root.off('click.' + taskNs, '.secator-task-select-all');
      $root.off('click.' + taskNs, '.secator-task-deselect-all');
      $root.off('click.' + taskNs, '.secator-task-quick-filters .btn');
      $root.off('input.' + taskNs, '.secator-task-filter');
      $root.off('change.' + taskNs, '.secator-task-targets-block ' + checkboxSel);

      $root.on('click.' + taskNs, '.secator-task-select-all', function() {
        const taskId = $(this).data('task-id');
        const $block = $root.find('.secator-task-targets-block[data-task-id="' + taskId + '"]');
        $block.find(itemWrapperSel + ':visible').each(function() {
          $(this).find(checkboxSel).prop('checked', true);
        });
        updateTaskCounts();
      });
      $root.on('click.' + taskNs, '.secator-task-deselect-all', function() {
        const taskId = $(this).data('task-id');
        const $block = $root.find('.secator-task-targets-block[data-task-id="' + taskId + '"]');
        $block.find(itemWrapperSel + ':visible').each(function() {
          $(this).find(checkboxSel).prop('checked', false);
        });
        updateTaskCounts();
      });
      $root.on('click.' + taskNs, '.secator-task-quick-filters .btn', function() {
        const $block = $(this).closest('.secator-task-targets-block');
        $(this).toggleClass('active');
        applyFilterForBlock($block);
        updateTaskCounts();
      });
      $root.on('input.' + taskNs, '.secator-task-filter', function() {
        const $block = $(this).closest('.secator-task-targets-block');
        applyFilterForBlock($block);
        updateTaskCounts();
      });
      $root.on('change.' + taskNs, '.secator-task-targets-block ' + checkboxSel, updateTaskCounts);
      $root.find('.secator-task-targets-block').each(function() {
        applyFilterForBlock($(this));
      });
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
