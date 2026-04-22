/**
 * Scan params block: profile toggles and effective-params live preview.
 *
 * Logical modules (in order in file):
 * 1. Profiles UI: category toggles (speed, evasion, general, network), sync of hidden
 *    inputs and custom selects, initProfileCategories, onSwitchChange, profile button/select handlers.
 *    On scan launch pages, secator_scan_core.js + secator_scan.js handle profile toggling;
 *    this script handles it on org/scope/target forms that include _scan_params_block.html.
 * 2. Draft collection: getFieldPrefix, collectDraft, buildScanParamsPreviewPayloadFromRoot.
 * 3. AJAX preview: block-root driven (no parent traversal). getFormForRoot, getScopeForRoot,
 *    triggerEffectivePreview(root), scheduleEffectivePreview(root) per-root debounce, bindEffectiveLiveUpdate.
 *
 * Each .profile-selector is guarded by data-scan-params-initialized to avoid double-binding.
 */
(function () {
  'use strict';

  // ========== Profiles UI: category maps and handlers ==========
  const CATEGORY_SWITCH_MAP = {
    speed: 'useSpeedProfile',
    evasion: 'useEvasionProfile',
    general: 'useGeneralProfile',
    network: 'useNetworkProfile'
  };

  const CATEGORY_HIDDEN_MAP = {
    speed: 'speed_profile',
    evasion: 'stealth_profile',
    general: 'general_profile',
    network: 'network_profile'
  };

  const getFormScope = function ($el) {
    const $form = $el.closest('form');
    return $form.length ? $form : $(document);
  };

  const CATEGORY_CUSTOM_SELECT = {
    speed: 'speed_custom_profile',
    evasion: 'evasion_custom_profile',
    general: 'general_custom_profile',
    network: 'network_custom_profile'
  };

  const syncProfileHiddensFromVisibleUI = function ($scope) {
    Object.keys(CATEGORY_SWITCH_MAP).forEach(function (category) {
      const switchId = CATEGORY_SWITCH_MAP[category];
      const $switch = $scope.find('[id$="' + switchId + '"], #' + switchId).first();
      if (!$switch.length || !$switch.is(':checked')) return;
      const $section = $switch.closest('.profile-category-container').find('.profile-category-section');
      if (!$section.length) return;
      let val = '';
      const $activeBtn = $section.find('.btn.active[data-profile-value]');
      if ($activeBtn.length) val = ($activeBtn.attr('data-profile-value') || '').trim();
      if (!val) {
        const selectName = CATEGORY_CUSTOM_SELECT[category];
        if (selectName) {
          const selVal = $section.find('select[name="' + selectName + '"], select[id$="' + selectName + '"]').first().val();
          if (selVal && String(selVal).trim()) val = String(selVal).trim();
        }
      }
      if (val) {
        const hiddenName = CATEGORY_HIDDEN_MAP[category];
        const $hidden = $scope.find('input[name="' + hiddenName + '"]');
        if ($hidden.length) $hidden.val(val);
      }
    });
  };

  const toggleCategory = function (category, isEnabled, $scope, $container) {
    const $root = ($container && $container.length) ? $container : $scope;
    const $section = $root.find('.profile-category-section[data-profile-category="' + category + '"]').first();
    const hiddenName = CATEGORY_HIDDEN_MAP[category];
    const $hidden = $scope.find('input[name="' + hiddenName + '"]').first();

    if (isEnabled) {
      $section.slideDown(200, function () {
        $section.css({ height: '', paddingTop: '', marginTop: '', paddingBottom: '', marginBottom: '' });
        const initialVal = ($hidden.attr('data-initial-profile-value') || $hidden.attr('value') || $hidden.val() || '').toString().trim();
        if (initialVal && $hidden.length) {
          $hidden.val(initialVal);
          const selectName = CATEGORY_CUSTOM_SELECT[category];
          const $customSelect = $section.find('select[name="' + selectName + '"], select[id$="' + category + '_custom_profile"]').first();
          if ($customSelect.length) {
            $customSelect.val(initialVal);
          }
        }
        if (initialVal) {
          const $builtinBtn = $section.find('button[data-profile-type][data-profile-value]').filter(function () {
            return $(this).attr('data-profile-type') === category && $(this).attr('data-profile-value') === initialVal;
          }).first();
          if ($builtinBtn.length) {
            const $group = $builtinBtn.closest('.btn-group');
            if ($group.length) {
              $group.find('button').each(function () {
                resetBuiltinButtonClasses($(this), category);
              });
            }
            $builtinBtn.addClass(CATEGORY_BUTTON_CLASS[category] || '').addClass('active');
            const $sel = $section.find('select[name="' + CATEGORY_CUSTOM_SELECT[category] + '"], select[id$="' + category + '_custom_profile"]').first();
            if ($sel.length) { $sel.val(''); }
            const $descDiv = $section.find('div[id$="' + category + '_custom_description"]');
            if ($descDiv.length) { $descDiv.hide().text(''); }
          } else {
            const $sel = $section.find('select[name="' + CATEGORY_CUSTOM_SELECT[category] + '"], select[id$="' + category + '_custom_profile"]').first();
            const $descDiv = $section.find('div[id$="' + category + '_custom_description"]');
            if ($sel.length && $descDiv.length && $sel.val()) {
              const opt = $sel.find('option:selected');
              const desc = opt.length && opt.attr('data-description') ? opt.attr('data-description') : '';
              $descDiv.text(desc).show();
            }
          }
        }
        syncProfileHiddensFromVisibleUI($scope);
        const $blockRoot = $container.closest('[data-scan-params-block-root="true"]');
        if ($blockRoot.length) scheduleEffectivePreview($blockRoot[0]);
      });
      $section.find('button, select').prop('disabled', false);
      $section.find('select[id$="_custom_profile"]').each(function () {
        if (this.options && this.options.length > 1) {
          $(this).css('display', 'block');
        }
      });
    } else {
      if ($hidden.length && $hidden.val()) {
        $hidden.attr('data-initial-profile-value', $hidden.val());
      }
      $section.slideUp(200, function () {
        $section.css({ height: '', paddingTop: '', marginTop: '', paddingBottom: '', marginBottom: '', overflow: '' });
        $section.hide();
      });
      $section.find('button, select').prop('disabled', true);
      $section.find('select[id$="_custom_profile"]').css('display', 'none');
      if ($hidden.length) $hidden.val('');
      $section.find('select').val('');
    }
  };

  const initProfileCategories = function () {
    $('.profile-selector').each(function () {
      const $selector = $(this);
      if ($selector.attr('data-scan-params-initialized')) return;
      $selector.attr('data-scan-params-initialized', '1');

      const $scope = getFormScope($selector);
      const $wrapper = $selector.closest('[data-scan-params-level]');
      const entityCategoriesStr = ($wrapper.length && $wrapper.attr('data-scan-params-entity-profile-categories')) || '';
      const entityProfileCategories = entityCategoriesStr
        ? entityCategoriesStr.split(',').map(function (s) { return s.trim(); }).filter(Boolean)
        : [];

      Object.keys(CATEGORY_SWITCH_MAP).forEach(function (category) {
        const switchId = CATEGORY_SWITCH_MAP[category];
        const $switch = $selector.find('[id$="' + switchId + '"]').first();
        const hiddenName = CATEGORY_HIDDEN_MAP[category];
        const $hidden = $scope.find('input[name="' + hiddenName + '"]').first();

        const serverValue = $hidden.length ? ($hidden.attr('value') || '').toString().trim() : '';
        const isEntityOverride = entityProfileCategories.indexOf(category) !== -1;
        const hasExplicitValue = serverValue !== '' && isEntityOverride;
        if (hasExplicitValue && $hidden.length) {
          $hidden.attr('data-initial-profile-value', serverValue);
        }

        if ($switch.length) {
          if (hasExplicitValue) {
            $switch.prop('checked', true);
            toggleCategory(category, true, $scope, $selector);
          } else {
            toggleCategory(category, $switch.is(':checked'), $scope, $selector);
          }
        }
      });
    });
  };

  const onSwitchChange = function (e) {
    const $switch = $(e.currentTarget);
    const id = $switch.attr('id') || '';
    let category = null;

    Object.keys(CATEGORY_SWITCH_MAP).forEach(function (cat) {
      if (id === CATEGORY_SWITCH_MAP[cat] || id.endsWith(CATEGORY_SWITCH_MAP[cat])) {
        category = cat;
      }
    });
    if (!category) return;

    const $scope = getFormScope($switch);
    const $selector = $switch.closest('.profile-selector');
    toggleCategory(category, $switch.is(':checked'), $scope, $selector);
    if (!$switch.is(':checked')) {
      const hiddenName = CATEGORY_HIDDEN_MAP[category];
      if (hiddenName) {
        const $hidden = $scope.find('input[name="' + hiddenName + '"]');
        if ($hidden.length) $hidden.val('');
      }
      const $blockRoot = $switch.closest('[data-scan-params-block-root="true"]');
      if ($blockRoot.length) scheduleEffectivePreview($blockRoot[0]);
    }
  };

  const CATEGORY_BUTTON_CLASS = {
    speed: 'btn-primary',
    evasion: 'btn-secondary',
    general: 'btn-info',
    network: 'btn-success'
  };

  const SOLID_TO_OUTLINE = {
    'btn-primary': 'btn-outline-primary',
    'btn-secondary': 'btn-outline-secondary',
    'btn-info': 'btn-outline-info',
    'btn-success': 'btn-outline-success'
  };

  const resetBuiltinButtonClasses = function ($btn, category) {
    $btn.removeClass('active');
    const solidClass = CATEGORY_BUTTON_CLASS[category];
    if (solidClass) {
      $btn.removeClass(solidClass).removeClass(SOLID_TO_OUTLINE[solidClass] || '');
      $btn.addClass(SOLID_TO_OUTLINE[solidClass] || '');
    }
  };

  const onBuiltinProfileButtonClick = function (e) {
    const $btn = $(e.currentTarget);
    const category = $btn.attr('data-profile-type');
    const value = $btn.attr('data-profile-value');
    if (!category || !value) return;

    const $selector = $btn.closest('.profile-selector');
    const $scope = getFormScope($selector);
    const hiddenName = CATEGORY_HIDDEN_MAP[category];
    const $hidden = $scope.find('input[name="' + hiddenName + '"]');

    const $section = $selector.find('.profile-category-section[data-profile-category="' + category + '"]');
    if ($section.length) {
      $section.find('button[data-profile-type="' + category + '"]').each(function () {
        resetBuiltinButtonClasses($(this), category);
      });
    }
    $btn.addClass(CATEGORY_BUTTON_CLASS[category] || '').addClass('active');

    const $customSelect = $section.find('select[id$="' + category + '_custom_profile"]');
    if ($customSelect.length) {
      $customSelect.val('');
    }
    const $descDiv = $section.find('div[id$="' + category + '_custom_description"]');
    if ($descDiv.length) {
      $descDiv.hide().text('');
    }
    if ($hidden.length) $hidden.val(value);
    const $blockRoot = $selector.closest('[data-scan-params-block-root="true"]');
    if ($blockRoot.length) scheduleEffectivePreview($blockRoot[0]);
  };

  const CUSTOM_SELECT_SUFFIX_MAP = {
    speed: 'speed_custom_profile',
    evasion: 'evasion_custom_profile',
    general: 'general_custom_profile',
    network: 'network_custom_profile'
  };

  const getCategoryFromCustomSelect = function ($select) {
    const name = ($select.attr('name') || $select.attr('id') || '').toLowerCase();
    let out = null;
    Object.keys(CUSTOM_SELECT_SUFFIX_MAP).forEach(function (cat) {
      if (name.indexOf(CUSTOM_SELECT_SUFFIX_MAP[cat]) !== -1) out = cat;
    });
    return out;
  };

  const onCustomProfileSelectChange = function (e) {
    const $select = $(e.currentTarget);
    const category = getCategoryFromCustomSelect($select);
    if (!category) return;

    const $selector = $select.closest('.profile-selector');
    const $scope = getFormScope($selector);
    const hiddenName = CATEGORY_HIDDEN_MAP[category];
    const $hidden = $scope.find('input[name="' + hiddenName + '"]');
    const value = $select.val() || '';

    const $section = $selector.find('.profile-category-section[data-profile-category="' + category + '"]');
    const $builtins = $section.find('.btn-group button');
    $builtins.each(function () {
      resetBuiltinButtonClasses($(this), category);
    });

    const $descDiv = $section.find('div[id$="' + category + '_custom_description"]');
    if (value && $descDiv.length) {
      const opt = $select.find('option:selected');
      const desc = opt.length && opt.attr('data-description') ? opt.attr('data-description') : '';
      $descDiv.text(desc).show();
    } else if ($descDiv.length) {
      $descDiv.text('').hide();
    }
    if ($hidden.length) $hidden.val(value);
    const $blockRoot = $selector.closest('[data-scan-params-block-root="true"]');
    if ($blockRoot.length) scheduleEffectivePreview($blockRoot[0]);
  };

  // ========== Draft collection: field prefix, collectDraft, buildScanParamsPreviewPayloadFromRoot ==========
  const SCALAR_PARAMS = [
    'threads', 'rate_limit', 'timeout', 'retries', 'delay', 'depth',
    'follow_redirect', 'proxy', 'user_agent', 'header'
  ];

  const PROFILE_HIDDEN_NAMES = ['speed_profile', 'stealth_profile', 'general_profile', 'network_profile'];
  const PROFILE_CATEGORY_MAP = { speed_profile: 'speed', stealth_profile: 'evasion', general_profile: 'general', network_profile: 'network' };

  const getFieldPrefix = function (level) {
    if (level === 'target') return 'override_';
    return '';
  };

  /**
   * Parse header text (one "name": "value" per line) into an object for preview/save.
   * Falls back to JSON.parse for legacy JSON input.
   */
  const parseHeaderTextToObject = function (text) {
    const v = (text || '').trim();
    if (!v) return null;
    const lines = v.split('\n');
    const obj = {};
    let hasValidLine = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      if (line.indexOf('": "') === -1 || !line.startsWith('"')) {
        try {
          return JSON.parse(v);
        } catch (e) {
          return null;
        }
      }
      const colonMatch = line.indexOf('": "');
      const key = line.slice(1, colonMatch).trim();
      const valuePart = line.slice(colonMatch + 4);
      if (!valuePart.endsWith('"')) {
        try {
          return JSON.parse(v);
        } catch (e) {
          return null;
        }
      }
      const value = valuePart.slice(0, -1).replace(/\\\\/g, '\\').replace(/\\"/g, '"');
      obj[key] = value;
      hasValidLine = true;
    }
    return hasValidLine ? obj : null;
  };

  const collectDraft = function ($scope, level) {
    const prefix = getFieldPrefix(level);
    const draft = {};
    SCALAR_PARAMS.forEach(function (param) {
      const name = prefix + param;
      const $input = $scope.find('input[name="' + name + '"], select[name="' + name + '"], textarea[name="' + name + '"]');
      if ($input.length) {
        const raw = $input.val();
        const v = raw !== undefined && raw !== null ? String(raw).trim() : '';
        if (v === '') {
          draft[param] = null;
        } else {
          if (param === 'threads' || param === 'rate_limit' || param === 'timeout' || param === 'retries' || param === 'depth') {
            const n = parseInt(v, 10);
            draft[param] = !isNaN(n) ? n : v;
          } else if (param === 'delay') {
            const f = parseFloat(v);
            draft[param] = !isNaN(f) ? f : v;
          } else if (param === 'follow_redirect') {
            draft[param] = v === 'True' || v === 'true' || v === '1';
          } else if (param === 'header') {
            const o = parseHeaderTextToObject(v);
            draft[param] = typeof o === 'object' && o !== null ? o : null;
          } else {
            draft[param] = v;
          }
        }
      }
    });
    const profiles = {};
    PROFILE_HIDDEN_NAMES.forEach(function (hiddenName) {
      const $h = $scope.find('input[name="' + hiddenName + '"]');
      if ($h.length) {
        let val = $h.val();
        if (!val || String(val).trim() === '') val = $h.attr('value') || '';
        if (val && String(val).trim()) {
          const cat = PROFILE_CATEGORY_MAP[hiddenName];
          if (cat) profiles[cat] = String(val).trim();
        }
      }
    });
    if (Object.keys(profiles).length) draft.profiles = profiles;
    const $workerSelect = $scope.find(
      'select[name="worker_id"], input[name="worker_id"], select[name="default_worker"]'
    );
    if ($workerSelect.length) {
      const workerVal = $workerSelect.val();
      if (workerVal !== undefined && workerVal !== null && String(workerVal).trim() !== '') {
        const wid = parseInt(workerVal, 10);
        if (!isNaN(wid)) {
          draft.worker_id = wid;
        }
      }
    }
    return draft;
  };

  // ========== AJAX preview: block-root driven (no parent traversal) ==========
  /**
   * Resolve the form element for the block root: by data-scan-params-form-id or closest form.
   * @param {Element} root - Block root element (data-scan-params-block-root).
   * @returns {Element|null} Form element or null.
   */
  const getFormForRoot = function (root) {
    const formId = root.getAttribute && root.getAttribute('data-scan-params-form-id');
    if (formId) {
      const form = document.getElementById(formId);
      if (form) return form;
    }
    return root.closest ? root.closest('form') : null;
  };

  /**
   * Scope for draft collection and CSRF: the form if found, otherwise the block root.
   * @param {Element} root - Block root element.
   * @returns {jQuery} jQuery wrapper of form or root.
   */
  const getScopeForRoot = function (root) {
    const form = getFormForRoot(root);
    return form ? $(form) : $(root);
  };

  /**
   * Build preview payload from block root data attributes and draft collected from scope.
   * @param {Element} root - Block root element.
   * @returns {{ level: string, project_slug: string, organization_id: string|null, scope_id: string|null, target_id: string|null, draft: object }|null}
   */
  const buildScanParamsPreviewPayloadFromRoot = function (root) {
    const level = (root.getAttribute('data-scan-params-level') || '').trim();
    if (!level) return null;
    const $scope = getScopeForRoot(root);
    const draft = collectDraft($scope, level);
    let organizationId = root.getAttribute('data-scan-params-organization-id') || '';
    if (level === 'scope' && !organizationId) {
      const $orgSelect = $scope.find('select[name="organization"], select[id="id_organization"]');
      if ($orgSelect.length) organizationId = $orgSelect.val() || '';
    }
    return {
      level: level,
      project_slug: root.getAttribute('data-scan-params-project-slug') || (typeof window.PROJECT_SLUG !== 'undefined' ? window.PROJECT_SLUG : ''),
      organization_id: organizationId || null,
      scope_id: root.getAttribute('data-scan-params-scope-id') || null,
      target_id: root.getAttribute('data-scan-params-target-id') || $scope.find('input[name="target_id"]').val() || null,
      draft: draft
    };
  };

  const getCsrfToken = function ($scope) {
    const $tok = $scope.find('input[name="csrfmiddlewaretoken"]');
    if ($tok.length) return $tok.val();
    const $docTok = $(document).find('input[name="csrfmiddlewaretoken"]').first();
    if ($docTok.length) return $docTok.val();
    return typeof window.CSRF_TOKEN !== 'undefined' ? window.CSRF_TOKEN : '';
  };

  const effectivePreviewRequestIdMap = new Map();
  const effectivePreviewDebounceMap = new Map();

  let _rootKeyCounter = 0;

  /**
   * Return a stable string key for the block root, assigning one if absent.
   * Using a string key rather than the DOM node avoids orphaned Map entries
   * if the root element is ever recreated.
   * @param {Element} root
   * @returns {string}
   */
  const getRootKey = function (root) {
    let key = root.getAttribute('data-scan-params-root-key');
    if (!key) {
      key = 'sp-root-' + (++_rootKeyCounter);
      root.setAttribute('data-scan-params-root-key', key);
    }
    return key;
  };

  /**
   * Remove Map entries for a completed or removed root.
   * Call after a request resolves (success or error) so that entries do not
   * accumulate on pages where roots are rendered dynamically.
   * @param {string} rootKey
   */
  const cleanupRootState = function (rootKey) {
    effectivePreviewRequestIdMap.delete(rootKey);
    effectivePreviewDebounceMap.delete(rootKey);
  };

  const triggerEffectivePreview = function (root) {
    if (!root || !root.querySelector) return;
    const container = root.querySelector('#scan-params-effective-container');
    if (!container) return;

    const previewUrl = root.getAttribute('data-scan-params-preview-url') ||
      (typeof window.SCAN_PARAMS_EFFECTIVE_PREVIEW_URL !== 'undefined' ? window.SCAN_PARAMS_EFFECTIVE_PREVIEW_URL : null);
    if (!previewUrl) return;

    const payload = buildScanParamsPreviewPayloadFromRoot(root);
    if (!payload) return;

    const $scope = getScopeForRoot(root);
    const rootKey = getRootKey(root);
    const requestId = (effectivePreviewRequestIdMap.get(rootKey) || 0) + 1;
    effectivePreviewRequestIdMap.set(rootKey, requestId);

    const csrfToken = getCsrfToken($scope);
    const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
    if (csrfToken) headers['X-CSRFToken'] = csrfToken;

    const $container = $(container);
    $.ajax({
      url: previewUrl,
      type: 'POST',
      data: JSON.stringify(payload),
      headers: headers,
      success: function (html) {
        if (requestId !== effectivePreviewRequestIdMap.get(rootKey)) return;
        cleanupRootState(rootKey);
        if (!root) return;
        if (html && typeof html === 'string') {
          $container.replaceWith(html);
          const newContainer = root.querySelector('#scan-params-effective-container');
          if (newContainer && typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
            const tooltipTriggerList = [].slice.call(newContainer.querySelectorAll('[data-bs-toggle="tooltip"]'));
            tooltipTriggerList.forEach(function (el) {
              const existing = bootstrap.Tooltip.getInstance(el);
              if (existing) existing.dispose();
              new bootstrap.Tooltip(el, { boundary: 'viewport' });
            });
          }
        }
      },
      error: function () {
        if (requestId !== effectivePreviewRequestIdMap.get(rootKey)) return;
        cleanupRootState(rootKey);
      }
    });
  };

  const scheduleEffectivePreview = function (root) {
    if (!root) return;
    const rootKey = getRootKey(root);
    const entry = effectivePreviewDebounceMap.get(rootKey);
    if (entry && entry.timer) clearTimeout(entry.timer);
    const timer = setTimeout(function () {
      effectivePreviewDebounceMap.delete(rootKey);
      triggerEffectivePreview(root);
    }, 350);
    effectivePreviewDebounceMap.set(rootKey, { timer: timer });
  };

  const bindEffectiveLiveUpdate = function () {
    const roots = document.querySelectorAll('[data-scan-params-block-root="true"]');
    roots.forEach(function (root) {
      const container = root.querySelector('#scan-params-effective-container');
      const previewUrl = root.getAttribute('data-scan-params-preview-url') ||
        (typeof window.SCAN_PARAMS_EFFECTIVE_PREVIEW_URL !== 'undefined' ? window.SCAN_PARAMS_EFFECTIVE_PREVIEW_URL : null);
      if (!container || !previewUrl) return;

      const $scope = getScopeForRoot(root);
      const level = (root.getAttribute('data-scan-params-level') || '').trim();
      const prefix = getFieldPrefix(level);
      const selInputs = SCALAR_PARAMS.map(function (p) {
        return 'input[name="' + prefix + p + '"], select[name="' + prefix + p + '"], textarea[name="' + prefix + p + '"]';
      }).join(', ');
      const profileSel = PROFILE_HIDDEN_NAMES.map(function (n) { return 'input[name="' + n + '"]'; }).join(', ');
      const workerSel =
        'select[name="worker_id"], input[name="worker_id"], select[name="default_worker"]';

      $scope.on('input change', selInputs + ', ' + profileSel + ', ' + workerSel, function () {
        scheduleEffectivePreview(root);
      });
    });
  };

  /**
   * Rebuild the "Run on worker" dropdown from scope form: Allow Local checkbox and
   * Workers multi-select. When only one option is allowed, pre-select it.
   * Show/hide the Default worker row when 2+ options. Call on load and on change of
   * Allow Local and Workers. Uses data-scope-worker-sync on the form as hook when present.
   */
  const syncScopeWorkerDropdown = function (scopeForm) {
    const form = scopeForm || document.querySelector('form[data-scope-worker-sync]');
    if (!form) return;
    const workersMulti = form.querySelector('[id="id_workers"]');
    const workerIdSelect =
      form.querySelector('select[name="default_worker"]') ||
      form.querySelector('select[name="worker_id"]');
    if (!workersMulti || workersMulti.tagName !== 'SELECT' || !workerIdSelect) return;
    if (!form.contains(workerIdSelect)) return;

    const allowLocalEl = form.querySelector('[id="id_allow_local_worker"]');
    const allowLocal = !allowLocalEl || allowLocalEl.checked;

    const selected = [];
    const opts = workersMulti.options;
    for (let i = 0; i < opts.length; i++) {
      const opt = opts[i];
      if (opt.selected && opt.value) {
        selected.push({ value: opt.value, text: opt.text.trim() || opt.value });
      }
    }

    const currentVal = workerIdSelect.value;
    workerIdSelect.innerHTML = '';
    if (allowLocal) {
      const localOpt = document.createElement('option');
      localOpt.value = '';
      localOpt.textContent = 'Local (this server)';
      workerIdSelect.appendChild(localOpt);
    }
    selected.forEach(function (item) {
      const opt = document.createElement('option');
      opt.value = item.value;
      opt.textContent = item.text;
      workerIdSelect.appendChild(opt);
    });

    const optionsCount = (allowLocal ? 1 : 0) + selected.length;
    const stillValid = (allowLocal && (currentVal === '' || currentVal === null)) ||
      selected.some(function (item) { return item.value === currentVal; });
    if (stillValid) {
      workerIdSelect.value = currentVal;
    } else if (optionsCount === 1) {
      workerIdSelect.selectedIndex = 0;
    } else {
      workerIdSelect.value = '';
    }

    const defaultWorkerField =
      form.querySelector('select[name="default_worker"]') ||
      form.querySelector('[id="id_default_worker"]');
    const defaultWorkerWrap =
      (defaultWorkerField && defaultWorkerField.closest('.worker-select')) ||
      (defaultWorkerField && defaultWorkerField.closest('.row'));
    if (defaultWorkerWrap) {
      defaultWorkerWrap.style.display = optionsCount >= 2 ? '' : 'none';
    }
  }

  /**
   * Bind sync of "Run on worker" dropdown to scope Allow Local checkbox and Workers multi-select.
   * Runs only when a form with data-scope-worker-sync exists; elements are resolved within that form.
   */
  const initScopeWorkerSync = function () {
    const scopeForm = document.querySelector('form[data-scope-worker-sync]');
    if (!scopeForm) return;
    const workersMulti = scopeForm.querySelector('[id="id_workers"]');
    const workerIdSelect =
      scopeForm.querySelector('select[name="default_worker"]') ||
      scopeForm.querySelector('select[name="worker_id"]');
    if (!workersMulti || !workerIdSelect) return;
    syncScopeWorkerDropdown(scopeForm);
    $(scopeForm).off('change.scanParamsScopeWorker', '#id_workers');
    $(scopeForm).on('change.scanParamsScopeWorker', '#id_workers', function () {
      syncScopeWorkerDropdown(scopeForm);
    });
    $(scopeForm).off('change.scanParamsScopeWorker', '#id_allow_local_worker');
    $(scopeForm).on('change.scanParamsScopeWorker', '#id_allow_local_worker', function () {
      syncScopeWorkerDropdown(scopeForm);
    });
    if (typeof $.fn.select2 !== 'undefined') {
      $(scopeForm).off('select2:select.scanParamsScopeWorker select2:unselect.scanParamsScopeWorker', '#id_workers');
      $(scopeForm).on('select2:select.scanParamsScopeWorker select2:unselect.scanParamsScopeWorker', '#id_workers', function () {
        syncScopeWorkerDropdown(scopeForm);
      });
    }
  };

  /**
   * Sync profile switch checkboxes from current hidden input values.
   * Use when showing a block (e.g. subscan modal advanced section) so the switch state
   * matches the stored profile value (avoids "profile displayed but switch off" after reopen).
   */
  const syncProfileSwitchesFromHiddenValues = function ($scope) {
    if (!$scope || !$scope.length) return;
    $scope.find('.profile-selector').each(function () {
      const $selector = $(this);
      const $blockRoot = $selector.closest('[data-scan-params-block-root="true"]');
      const $scopeForFind = $blockRoot.length ? $blockRoot : getFormScope($selector);
      Object.keys(CATEGORY_SWITCH_MAP).forEach(function (category) {
        const hiddenName = CATEGORY_HIDDEN_MAP[category];
        const $hidden = $scopeForFind.find('input[name="' + hiddenName + '"]').first();
        const hasValue = $hidden.length && String($hidden.val()).trim() !== '';
        const $switch = $selector.find('[id$="' + CATEGORY_SWITCH_MAP[category] + '"]').first();
        if ($switch.length) {
          $switch.prop('checked', hasValue);
          toggleCategory(category, hasValue, $scopeForFind, $selector);
        }
      });
    });
  };

  window.ScanParams = {
    schedulePreview: scheduleEffectivePreview,
    syncScopeWorkerDropdown: syncScopeWorkerDropdown,
    initScopeWorkerSync: initScopeWorkerSync,
    syncProfileSwitchesFromHiddenValues: syncProfileSwitchesFromHiddenValues
  };

  $(document).ready(function () {
    $(document).on('change',
      '[id$="useSpeedProfile"], #useSpeedProfile, ' +
      '[id$="useEvasionProfile"], #useEvasionProfile, ' +
      '[id$="useGeneralProfile"], #useGeneralProfile, ' +
      '[id$="useNetworkProfile"], #useNetworkProfile',
      onSwitchChange
    );

    $(document).on('click', '.profile-selector button[data-profile-type][data-profile-value]', onBuiltinProfileButtonClick);
    $(document).on('change', '.profile-selector select[name="speed_custom_profile"], .profile-selector select[name="evasion_custom_profile"], .profile-selector select[name="general_custom_profile"], .profile-selector select[name="network_custom_profile"]', onCustomProfileSelectChange);

    initProfileCategories();
    bindEffectiveLiveUpdate();
    initScopeWorkerSync();
  });
})();
