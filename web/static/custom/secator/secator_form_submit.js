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

    collectFormData: function($form) {
      const executionMode = $form.find('input[name="execution_mode"]').val();
      const domainId = $form.find('input[name="domain_id"]').val();

      const profileKeys = ['speed', 'evasion', 'general', 'network'];
      const profiles = profileKeys
        .filter(key => {
          const sel = this.getProfileSwitchSelector(key);
          return sel && $form.find(sel).is(':checked');
        })
        .map(key => this.getProfileValue($form, key))
        .filter(Boolean);

      const useRandomProxy = $form.find('input[name="use_random_proxy"]').is(':checked');
      const proxyValue = useRandomProxy ? null : ($form.find('input[name="proxy"]').val() || '');

      const formData = {
        domain_id: parseInt(domainId),
        execution_mode: executionMode,
        imported_subdomains: ($form.find('[id$="importSubdomainFormControlTextarea"], #importSubdomainFormControlTextarea').val() || '').split('\n').filter(s => s.trim()),
        out_of_scope_subdomains: ($form.find('[id$="outOfScopeSubdomainTextarea"], #outOfScopeSubdomainTextarea').val() || '').split('\n').filter(s => s.trim()),
        url_filter: $form.find('[id$="filterPath"], #filterPath').val(),
        secator_config: {
          proxy: proxyValue,
          delay: parseInt($form.find('input[name="delay"]').val()) || 0,
          profiles: profiles
        }
      };

      if (executionMode === 'workflow') {
        formData.workflow_id = parseInt($form.find('input[name="workflow_id"]:checked').val());
      } else if (executionMode === 'tasks') {
        formData.task_ids = $form.find('input[name="task_ids"]:checked').map(function() {
          return parseInt($(this).val());
        }).get();
      } else if (executionMode === 'scan') {
        formData.secator_scan_type = $form.find('input[name="secator_scan_type"]:checked').val();
      }

      const prefix = this.getSecatorIdPrefix($form);
      if (prefix) {
        const $targetsPreview = $form.find(`#${prefix}-targets-preview`);
        const $tasksTargetsContainer = $form.find(`#${prefix}-tasks-targets-container`);
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
