/**
 * Shared numeric row-id selection for server-side DataTables (bulk actions, export).
 * Aligns badge + disabled-button behaviour across tables (e.g. scan detail IP tab).
 */
(function (window) {
  "use strict";

  /**
   * @param {object} config
   * @param {string} [config.countBadgeId] - Element showing "N selected" (hidden when empty).
   * @param {string[]} [config.disabledWhenEmptyIds] - Button IDs that get class "disabled" when selection is empty.
   * @returns {{ ids: Set<number>, refresh: function, clear: function }}
   */
  window.createRengineDatatableIdSelection = function (config) {
    const cfg = config || {};
    const countBadgeId = cfg.countBadgeId || "";
    const disabledIds = cfg.disabledWhenEmptyIds || [];
    const ids = new Set();

    function refresh() {
      const n = ids.size;
      const badge = countBadgeId ? document.getElementById(countBadgeId) : null;
      if (badge) {
        badge.textContent = n > 0 ? String(n) + " selected" : "";
        badge.style.display = n > 0 ? "" : "none";
      }
      disabledIds.forEach(function (bid) {
        const el = document.getElementById(bid);
        if (el) {
          el.classList.toggle("disabled", n === 0);
        }
      });
    }

    /**
     * @param {object} [opts]
     * @param {string} [opts.rowCheckboxSelector] - e.g. ".ip_checkbox"
     * @param {string} [opts.headCheckboxId] - e.g. "head_ip_checkbox"
     */
    function clear(opts) {
      ids.clear();
      const o = opts || {};
      if (o.rowCheckboxSelector) {
        document.querySelectorAll(o.rowCheckboxSelector).forEach(function (cb) {
          cb.checked = false;
        });
      }
      if (o.headCheckboxId) {
        const head = document.getElementById(o.headCheckboxId);
        if (head) {
          head.checked = false;
        }
      }
      refresh();
    }

    return { ids: ids, refresh: refresh, clear: clear };
  };
})(window);
