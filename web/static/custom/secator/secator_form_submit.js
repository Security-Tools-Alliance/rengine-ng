/**
 * Secator Scan - Form submit: collectFormData, submitStartScan (POST and callbacks)
 */
(function($) {
  'use strict';

  if (typeof window.SecatorScan === 'undefined') return;

  Object.assign(window.SecatorScan, {
    submitStartScan: function(formData, options) {
      const { csrfToken, $submitBtn, onSuccess, onError } = options || {};
      const defaultResetBtn = () => {
        if ($submitBtn && $submitBtn.length) {
          $submitBtn.prop('disabled', false).html('<i class="fas fa-play me-2"></i>Start Scan');
        }
      };
      $.ajax({
        url: window.SECATOR_START_SCAN_URL,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(formData),
        headers: { 'X-CSRFToken': csrfToken },
        success: function(response) {
          if (response.status) {
            Swal.fire({
              icon: 'success',
              title: 'Scan Started',
              text: response.message || 'Scan has been initiated successfully',
              timer: 2000,
              showConfirmButton: false
            }).then(() => {
              window.location.href = window.SCAN_HISTORY_URL;
            });
          } else {
            Swal.fire({
              icon: 'error',
              title: 'Error',
              text: response.error || 'Failed to start scan'
            });
            defaultResetBtn();
          }
          if (typeof onSuccess === 'function') onSuccess(response);
        },
        error: function(xhr) {
          const errorMessage = xhr.responseJSON?.error || 'Failed to start scan. Please try again.';
          Swal.fire({
            icon: 'error',
            title: 'Error',
            text: errorMessage
          });
          defaultResetBtn();
          if (typeof onError === 'function') onError(xhr);
        }
      });
    },

    /**
     * Build secator_config (profiles, proxy, delay, scalar params) from any scope
     * (form or modal). Shared by start scan form and subscan modal.
     */
    collectSecatorConfigFromScope: function($scope) {
      if (!$scope || !$scope.length) {
        return { proxy: '', delay: 0, profiles: [] };
      }
      const profileKeys = ['speed', 'evasion', 'general', 'network'];
      const profiles = profileKeys
        .filter(key => {
          const sel = this.getProfileSwitchSelector(key);
          return sel && $scope.find(sel).is(':checked');
        })
        .map(key => this.getProfileValue($scope, key))
        .filter(Boolean);

      const useRandomProxy = $scope.find('input[name="use_random_proxy"]').is(':checked');
      const proxyValue = useRandomProxy ? null : ($scope.find('input[name="proxy"], input[name="override_proxy"]').val() || '');

      const scalarParamNames = ['threads', 'rate_limit', 'timeout', 'retries', 'delay', 'depth', 'follow_redirect', 'proxy', 'user_agent', 'header'];
      const secatorConfig = {
        proxy: proxyValue,
        delay: (function() {
          const v = $scope.find('input[name="delay"], input[name="override_delay"]').val();
          const n = parseInt(v, 10);
          return isNaN(n) ? 0 : n;
        })(),
        profiles: profiles
      };
      scalarParamNames.forEach(function(param) {
        if (param === 'proxy' || param === 'delay') return;
        const prefixed = 'override_' + param;
        const $el = $scope.find('input[name="' + param + '"], select[name="' + param + '"], textarea[name="' + param + '"], input[name="' + prefixed + '"], select[name="' + prefixed + '"], textarea[name="' + prefixed + '"]');
        if (!$el.length) return;
        const raw = $el.val();
        if (raw === undefined || raw === null || String(raw).trim() === '') return;
        const v = String(raw).trim();
        if (param === 'threads' || param === 'rate_limit' || param === 'timeout' || param === 'retries' || param === 'depth') {
          const n = parseInt(v, 10);
          if (!isNaN(n)) secatorConfig[param] = n;
        } else if (param === 'follow_redirect') {
          secatorConfig[param] = v === 'True' || v === 'true' || v === '1';
        } else if (param === 'header') {
          try {
            const o = JSON.parse(v);
            if (typeof o === 'object' && o !== null) secatorConfig[param] = o;
          } catch (e) { /* skip invalid JSON */ }
        } else {
          secatorConfig[param] = v;
        }
      });
      return secatorConfig;
    },

    collectFormData: function($form) {
      const executionMode = $form.find('input[name="execution_mode"]').val();
      const targetId = $form.find('input[name="target_id"]').val();

      const secatorConfig = this.collectSecatorConfigFromScope($form);

      const formData = {
        execution_mode: executionMode,
        imported_subdomains: ($form.find('[id$="importSubdomainFormControlTextarea"], #importSubdomainFormControlTextarea').val() || '').split('\n').filter(s => s.trim()),
        out_of_scope_subdomains: ($form.find('[id$="outOfScopeSubdomainTextarea"], #outOfScopeSubdomainTextarea').val() || '').split('\n').filter(s => s.trim()),
        url_filter: $form.find('[id$="filterPath"], #filterPath').val(),
        secator_config: secatorConfig
      };
      if (targetId) formData.target_id = parseInt(targetId, 10);

      if (executionMode === 'workflow') {
        formData.workflow_id = parseInt($form.find('input[name="workflow_id"]:checked').val());
      } else if (executionMode === 'tasks') {
        formData.task_ids = $form.find('input[name="task_ids"]:checked').map(function() {
          return parseInt($(this).val());
        }).get();
      } else if (executionMode === 'scan') {
        formData.secator_scan_type = $form.find('input[name="secator_scan_type"]:checked').val();
      }

      const workerIdVal = $form.find('select[name="worker_id"]').val();
      if (workerIdVal && String(workerIdVal).trim() !== '') {
        const parsed = parseInt(workerIdVal, 10);
        if (!Number.isNaN(parsed)) formData.worker_id = parsed;
      }

      const prefix = this.getSecatorIdPrefix($form);
      if (prefix) {
        const $targetsPreview = $form.find(`#${prefix}-targets-preview`);
        if ($targetsPreview.length && (executionMode === 'workflow' || executionMode === 'scan')) {
          const selected = $targetsPreview.find('.secator-target-checkbox:checked').map(function() {
            return $(this).val();
          }).get();
          if (selected.length) formData.selected_targets = selected;
        }
        if (executionMode === 'tasks') {
          const perTask = {};
          const $blocks = $form.find('.secator-task-targets-block');
          $blocks.each(function() {
            const taskType = $(this).data('task-type');
            const vals = $(this).find('.secator-target-checkbox:checked').map(function() {
              return $(this).val();
            }).get();
            if (taskType && vals.length) perTask[taskType] = vals;
          });
          if (Object.keys(perTask).length) formData.selected_targets_per_task = perTask;
        }
      }

      return formData;
    }
  });
})(jQuery);
