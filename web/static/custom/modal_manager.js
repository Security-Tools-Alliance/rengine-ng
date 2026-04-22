/**
 * Centralized modal display for reNgine-ng.
 * Use this API instead of direct DOM selectors or jQuery .modal('show'/'hide').
 * For any modal already in the DOM, use ModalManager.showById(id) and ModalManager.hide(id).
 * Prefer ModalManager.showDialog / ModalManager.showXl for the generic dialog/XL modals.
 * Use setXlTitle / setXlContent / setXlLoading to update XL modal content without re-opening.
 */
(function (global) {
  'use strict';

  const MODAL_IDS = {
    DIALOG: 'modal-dialog',
    XL: 'modal-xl-scroll-dialog',
    SUBSCAN: 'subscan-modal',
    ADD_TASK: 'addTaskModal',
    ADD_SUBDOMAIN_TASK: 'addSubdomainTaskModal',
    ADD_TARGET: 'addTargetModal',
    GENERATE_REPORT: 'generateReportModal',
    ADD_MODEL: 'addModelModal',
    DELETE_CONFIRM: 'deleteConfirmModal',
    NEW_API_KEY: 'newApiKeyModal',
    TODO_SHOW_LIST_ITEM: 'todoShowListItem'
  };

  const MODAL_DIALOG_TITLE = 'modal-dialog-title';
  const MODAL_DIALOG_BODY = 'modal-dialog-body';
  const MODAL_DIALOG_FOOTER = 'modal-dialog-footer';
  const XL_MODAL_TITLE = 'xl-modal-title';
  const XL_MODAL_CONTENT = 'xl-modal-content';
  const XL_MODAL_FOOTER = 'xl-modal-footer';

  const $ = global.jQuery || global.$;
  if (!$) {
    return;
  }

  const DIALOG_SIZE_CLASSES = 'modal-sm modal-lg modal-xl modal-full-width';
  const DIALOG_SIZE_CLASS_LIST = DIALOG_SIZE_CLASSES.split(/\s+/);

  // Last runtime size class applied via showDialog({ dialogClass }); stripped on reset / next open.
  let lastAppliedDialogSizeClass = null;

  const BASELINE_DATA_KEY = 'rengineBaselineDialogSize';

  const detectTemplateDialogSize = function ($inner) {
    const parts = ($inner.attr('class') || '').split(/\s+/).filter(Boolean);
    for (let i = 0; i < DIALOG_SIZE_CLASS_LIST.length; i++) {
      if (parts.indexOf(DIALOG_SIZE_CLASS_LIST[i]) >= 0) {
        return DIALOG_SIZE_CLASS_LIST[i];
      }
    }
    return '';
  };

  /**
   * Baseline size class from the template for this .modal-dialog node (captured once per DOM node).
   * Avoids a single global snapshot when multiple templates or replacements exist; re-captures if the node is replaced.
   */
  const getBaselineDialogSizeClass = function ($inner) {
    if ($inner.data(BASELINE_DATA_KEY) === undefined) {
      $inner.data(BASELINE_DATA_KEY, detectTemplateDialogSize($inner));
    }
    const v = $inner.data(BASELINE_DATA_KEY);
    return typeof v === 'string' && v ? v : '';
  };

  const resetDialogInnerToDefaultSize = function () {
    const $dialog = $('#' + MODAL_IDS.DIALOG);
    if (!$dialog.length) return;
    const $inner = $dialog.find('.modal-dialog').first();
    if (!$inner.length) return;
    if (lastAppliedDialogSizeClass) {
      $inner.removeClass(lastAppliedDialogSizeClass);
      lastAppliedDialogSizeClass = null;
    }
    $inner.removeClass(DIALOG_SIZE_CLASSES);
    const baseline = getBaselineDialogSizeClass($inner);
    if (baseline) {
      $inner.addClass(baseline);
    }
  };

  const ensureModalInBody = function (id) {
    const el = document.getElementById(id);
    if (el && el.parentNode !== document.body) {
      document.body.appendChild(el);
    }
    return !!el;
  };

  const showDialog = function (options) {
    const opts = options || {};
    ensureModalInBody(MODAL_IDS.DIALOG);
    const $dialog = $('#' + MODAL_IDS.DIALOG);
    if (!$dialog.length) return;
    const $inner = $dialog.find('.modal-dialog').first();
    if ($inner.length) {
      getBaselineDialogSizeClass($inner);
      $dialog.off('hidden.bs.modal.rengineDialogSize');
      if (lastAppliedDialogSizeClass) {
        $inner.removeClass(lastAppliedDialogSizeClass);
        lastAppliedDialogSizeClass = null;
      }
      $inner.removeClass(DIALOG_SIZE_CLASSES);
      if (opts.dialogClass) {
        $inner.addClass(opts.dialogClass);
        lastAppliedDialogSizeClass = opts.dialogClass;
        $dialog.one('hidden.bs.modal.rengineDialogSize', function () {
          resetDialogInnerToDefaultSize();
        });
      } else {
        const baseline = getBaselineDialogSizeClass($inner);
        if (baseline) {
          $inner.addClass(baseline);
        }
      }
    }
    $('#' + MODAL_DIALOG_TITLE).html(opts.title !== undefined ? opts.title : '');
    $('#' + MODAL_DIALOG_BODY).html(opts.bodyHtml !== undefined ? opts.bodyHtml : '');
    $('#' + MODAL_DIALOG_FOOTER).html(opts.footerHtml !== undefined ? opts.footerHtml : '');
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
      const modal = bootstrap.Modal.getOrCreateInstance($dialog[0]);
      modal.show();
    } else {
      $dialog.modal('show');
    }
  };

  const showXl = function (options) {
    const opts = options || {};
    const el = document.getElementById(MODAL_IDS.XL);
    if (!el) {
      return false;
    }
    $('#' + XL_MODAL_TITLE).html(opts.title !== undefined ? opts.title : '');
    $('#' + XL_MODAL_CONTENT).html(opts.bodyHtml !== undefined ? opts.bodyHtml : '');
    $('#' + XL_MODAL_FOOTER).html(opts.footerHtml !== undefined ? opts.footerHtml : '');
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
      const modal = bootstrap.Modal.getOrCreateInstance(el);
      modal.show();
    } else {
      $(el).modal('show');
    }
    return true;
  };

  const hasXlModal = function () {
    return !!document.getElementById(MODAL_IDS.XL);
  };

  const showXlOnly = function () {
    const el = document.getElementById(MODAL_IDS.XL);
    if (!el) {
      return false;
    }
    if (el.parentNode !== document.body) {
      document.body.appendChild(el);
    }
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
      bootstrap.Modal.getOrCreateInstance(el).show();
    } else {
      $(el).modal('show');
    }
    return true;
  };

  const hide = function (modalId) {
    if (typeof modalId !== 'string') return;
    const id = modalId.replace(/^#/, '');
    if (!id) return;
    const el = document.getElementById(id);
    if (el && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
      bootstrap.Modal.getOrCreateInstance(el).hide();
    } else {
      $('#' + id).modal('hide');
    }
  };

  const showById = function (modalId) {
    const id = typeof modalId === 'string' ? modalId.replace(/^#/, '') : '';
    if (!id) return false;
    if (!ensureModalInBody(id)) {
      return false;
    }
    const el = document.getElementById(id);
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
      bootstrap.Modal.getOrCreateInstance(el).show();
    } else {
      $(el).modal('show');
    }
    return true;
  };

  const setDialogLoading = function (html) {
    $('#' + MODAL_DIALOG_BODY).html(html || '');
  };

  const setDialogTitle = function (title) {
    $('#' + MODAL_DIALOG_TITLE).html(title !== undefined && title !== null ? title : '');
  };

  const setDialogFooter = function (html) {
    $('#' + MODAL_DIALOG_FOOTER).html(html !== undefined && html !== null ? html : '');
  };

  const setXlLoading = function (html) {
    $('#' + XL_MODAL_CONTENT).html(html || '');
  };

  const setXlTitle = function (title) {
    $('#' + XL_MODAL_TITLE).html(title !== undefined && title !== null ? title : '');
  };

  const setXlContent = function (options) {
    const opts = options || {};
    if (opts.title !== undefined) {
      $('#' + XL_MODAL_TITLE).html(opts.title);
    }
    if (opts.bodyHtml !== undefined) {
      $('#' + XL_MODAL_CONTENT).html(opts.bodyHtml);
    }
    if (opts.footerHtml !== undefined) {
      $('#' + XL_MODAL_FOOTER).html(opts.footerHtml);
    }
  };

  global.ModalManager = {
    MODAL_IDS,
    MODAL_DIALOG_TITLE,
    MODAL_DIALOG_BODY,
    MODAL_DIALOG_FOOTER,
    XL_MODAL_TITLE,
    XL_MODAL_CONTENT,
    XL_MODAL_FOOTER,
    ensureModalInBody,
    showDialog,
    showXl,
    hide,
    showById,
    hasXlModal,
    showXlOnly,
    setDialogLoading,
    setDialogTitle,
    setDialogFooter,
    setXlLoading,
    setXlTitle,
    setXlContent
  };

  document.addEventListener('DOMContentLoaded', function () {
    [MODAL_IDS.DIALOG, MODAL_IDS.XL].forEach(function (id) {
      ensureModalInBody(id);
    });
  });
})(typeof window !== 'undefined' ? window : this);
