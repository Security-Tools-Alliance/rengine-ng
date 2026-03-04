/**
 * Scan params block: profile toggles and effective-params live preview.
 *
 * Logical modules (in order in file):
 * 1. Profiles UI: category toggles (speed, evasion, general, network), sync of hidden
 *    inputs and custom selects, initProfileCategories, onSwitchChange, profile button/select handlers.
 *    On scan launch pages, secator_scan_core.js + secator_scan.js handle profile toggling;
 *    this script handles it on org/scope/target forms that include _scan_params_block.html.
 * 2. Draft collection: getFieldPrefix, collectDraft, buildScanParamsPreviewPayload (centralized
 *    payload for level, ids, draft from form/data-* attributes).
 * 3. AJAX preview: getPreviewUrl, getCsrfToken, triggerEffectivePreview (request-id guard),
 *    scheduleEffectivePreview (debounce), bindEffectiveLiveUpdate.
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

  function syncProfileHiddensFromVisibleUI($scope) {
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
  }

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
        syncProfileHiddensFromVisibleUI($scope);
        triggerEffectivePreview();
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

      Object.keys(CATEGORY_SWITCH_MAP).forEach(function (category) {
        const switchId = CATEGORY_SWITCH_MAP[category];
        const $switch = $selector.find('[id$="' + switchId + '"]').first();
        const hiddenName = CATEGORY_HIDDEN_MAP[category];
        const $hidden = $scope.find('input[name="' + hiddenName + '"]').first();

        const serverValue = $hidden.length ? ($hidden.attr('value') || '').toString().trim() : '';
        const hasExplicitValue = serverValue !== '';
        if (hasExplicitValue && $hidden.length) {
          $hidden.attr('data-initial-profile-value', serverValue);
        }

        if ($switch.length) {
          toggleCategory(category, $switch.is(':checked'), $scope, $selector);
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
      scheduleEffectivePreview();
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

    const $group = $btn.closest('.btn-group');
    if ($group.length) {
      $group.find('button').each(function () {
        resetBuiltinButtonClasses($(this), category);
      });
    }
    $btn.addClass(CATEGORY_BUTTON_CLASS[category] || '').addClass('active');

    const $section = $selector.find('.profile-category-section[data-profile-category="' + category + '"]');
    const $customSelect = $section.find('select[id$="' + category + '_custom_profile"]');
    if ($customSelect.length) {
      $customSelect.val('');
    }
    const $descDiv = $section.find('div[id$="' + category + '_custom_description"]');
    if ($descDiv.length) {
      $descDiv.hide().text('');
    }
    if ($hidden.length) $hidden.val(value);
    scheduleEffectivePreview();
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
    scheduleEffectivePreview();
  };

  // ========== Draft collection: field prefix, collectDraft, buildScanParamsPreviewPayload ==========
  const SCALAR_PARAMS = [
    'threads', 'rate_limit', 'timeout', 'retries', 'delay', 'depth',
    'follow_redirect', 'proxy', 'user_agent', 'request_headers'
  ];

  const PROFILE_HIDDEN_NAMES = ['speed_profile', 'stealth_profile', 'general_profile', 'network_profile'];
  const PROFILE_CATEGORY_MAP = { speed_profile: 'speed', stealth_profile: 'evasion', general_profile: 'general', network_profile: 'network' };

  function getFieldPrefix(level) {
    if (level === 'target') return 'override_';
    return '';
  }

  function collectDraft($scope, level) {
    const prefix = getFieldPrefix(level);
    const draft = {};
    SCALAR_PARAMS.forEach(function (param) {
      const name = prefix + param;
      const $input = $scope.find('input[name="' + name + '"], select[name="' + name + '"], textarea[name="' + name + '"]');
      if ($input.length) {
        const val = $input.val();
        if (val !== undefined && val !== null && String(val).trim() !== '') {
          let v = val.trim();
          if (param === 'threads' || param === 'rate_limit' || param === 'timeout' || param === 'retries' || param === 'depth') {
            const n = parseInt(v, 10);
            if (!isNaN(n)) draft[param] = n;
          } else if (param === 'delay') {
            const f = parseFloat(v);
            if (!isNaN(f)) draft[param] = f;
          } else if (param === 'follow_redirect') {
            draft[param] = v === 'True' || v === 'true' || v === '1';
          } else if (param === 'request_headers') {
            try {
              const o = JSON.parse(v);
              if (typeof o === 'object' && o !== null) draft[param] = o;
            } catch (e) { /* ignore */ }
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
    return draft;
  }

  /**
   * Build the payload object for the scan params effective preview API from the form or wrapper.
   * Centralizes level, project_slug, organization_id, scope_id, target_id, draft so forms and
   * JS stay in sync without duplicating data-* attribute names.
   * @param {jQuery} $formOrWrapper - Element with data-scan-params-level (and optional ids).
   * @returns {{ level: string, project_slug: string, organization_id: string|null, scope_id: string|null, target_id: string|null, draft: object }|null}
   *   Payload or null if level missing.
   */
  function buildScanParamsPreviewPayload($formOrWrapper) {
    const level = ($formOrWrapper.attr('data-scan-params-level') || '').trim();
    if (!level) return null;
    const $scope = $formOrWrapper.is('form') ? $formOrWrapper : $formOrWrapper.find('form').first().addBack().first();
    const draft = collectDraft($scope, level);
    let organizationId = $formOrWrapper.attr('data-scan-params-organization-id') || '';
    if (level === 'scope' && !organizationId) {
      const $orgSelect = $scope.find('select[name="organization"], select[id="id_organization"]');
      if ($orgSelect.length) organizationId = $orgSelect.val() || '';
    }
    return {
      level: level,
      project_slug: $formOrWrapper.attr('data-scan-params-project-slug') || (typeof window.PROJECT_SLUG !== 'undefined' ? window.PROJECT_SLUG : ''),
      organization_id: organizationId || null,
      scope_id: $formOrWrapper.attr('data-scan-params-scope-id') || null,
      target_id: $formOrWrapper.attr('data-scan-params-target-id') || $scope.find('input[name="target_id"]').val() || null,
      draft: draft
    };
  }

  // ========== AJAX preview: URL, CSRF, request-id guard, debounce, bind ==========
  function getPreviewUrl($formOrWrapper) {
    const url = $formOrWrapper.attr('data-scan-params-preview-url') ||
      (typeof window.SCAN_PARAMS_EFFECTIVE_PREVIEW_URL !== 'undefined' ? window.SCAN_PARAMS_EFFECTIVE_PREVIEW_URL : null);
    return url;
  }

  function getCsrfToken($scope) {
    const $tok = $scope.find('input[name="csrfmiddlewaretoken"]');
    return $tok.length ? $tok.val() : (typeof window.CSRF_TOKEN !== 'undefined' ? window.CSRF_TOKEN : '');
  }

  let latestEffectivePreviewRequestId = 0;

  function triggerEffectivePreview() {
    const $container = $('#scan-params-effective-container');
    if (!$container.length) return;

    const $formOrWrapper = $container.closest('form[id], form[data-scan-params-level], [data-scan-params-level]').first();
    if (!$formOrWrapper.length) return;

    const level = $formOrWrapper.attr('data-scan-params-level');
    if (!level) return;

    const previewUrl = getPreviewUrl($formOrWrapper);
    if (!previewUrl) return;

    const requestId = ++latestEffectivePreviewRequestId;
    const payload = buildScanParamsPreviewPayload($formOrWrapper);
    if (!payload) return;

    const $scope = $formOrWrapper.is('form') ? $formOrWrapper : $formOrWrapper.find('form').first().addBack().first();
    const csrfToken = getCsrfToken($scope);
    const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
    if (csrfToken) headers['X-CSRFToken'] = csrfToken;

    $.ajax({
      url: previewUrl,
      type: 'POST',
      data: JSON.stringify(payload),
      headers: headers,
      success: function (html) {
        if (requestId !== latestEffectivePreviewRequestId) return;
        if (html && typeof html === 'string') {
          $container.replaceWith(html);
          const newContainer = document.getElementById('scan-params-effective-container');
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
        if (requestId !== latestEffectivePreviewRequestId) return;
      }
    });
  }

  let effectivePreviewDebounceTimer = null;
  function scheduleEffectivePreview() {
    if (effectivePreviewDebounceTimer) clearTimeout(effectivePreviewDebounceTimer);
    effectivePreviewDebounceTimer = setTimeout(function () {
      effectivePreviewDebounceTimer = null;
      triggerEffectivePreview();
    }, 350);
  }

  function bindEffectiveLiveUpdate() {
    const $container = $('#scan-params-effective-container');
    if (!$container.length) return;
    const $formOrWrapper = $container.closest('form[data-scan-params-level], [data-scan-params-level]').first();
    if (!$formOrWrapper.length) return;
    if (!getPreviewUrl($formOrWrapper)) return;

    const $scope = $formOrWrapper.is('form') ? $formOrWrapper : $formOrWrapper.find('form').first().addBack().first();
    const prefix = getFieldPrefix($formOrWrapper.attr('data-scan-params-level'));
    const selInputs = SCALAR_PARAMS.map(function (p) {
      return 'input[name="' + prefix + p + '"], select[name="' + prefix + p + '"], textarea[name="' + prefix + p + '"]';
    }).join(', ');
    const profileSel = PROFILE_HIDDEN_NAMES.map(function (n) { return 'input[name="' + n + '"]'; }).join(', ');

    $scope.on('input change', selInputs + ', ' + profileSel, function () {
      scheduleEffectivePreview();
    });
  }

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
  });
})();
