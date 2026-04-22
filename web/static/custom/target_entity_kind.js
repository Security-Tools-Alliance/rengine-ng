/**
 * Central attack-surface / scan entity kinds for UI and LLM API wiring.
 * Loaded before custom.js; custom.js may override window.RENGINE_ATTACK_SURFACE_ENTITY_*.
 */
(function (window) {
  "use strict";

  var DEFAULT_SUBDOMAIN = "subdomain";
  var DEFAULT_IP = "ip";
  var DEFAULT_TARGET = "target";
  var DEFAULT_SCOPE = "scope";
  var DEFAULT_ORGANIZATION = "organization";
  var DEFAULT_SCAN_HISTORY = "scan_history";

  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_SUBDOMAIN === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_SUBDOMAIN = DEFAULT_SUBDOMAIN;
  }
  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_IP === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_IP = DEFAULT_IP;
  }
  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_TARGET === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_TARGET = DEFAULT_TARGET;
  }
  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_SCOPE === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_SCOPE = DEFAULT_SCOPE;
  }
  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_ORGANIZATION === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_ORGANIZATION = DEFAULT_ORGANIZATION;
  }
  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_SCAN_HISTORY === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_SCAN_HISTORY = DEFAULT_SCAN_HISTORY;
  }

  window.RengineTargetEntityKind = {
    subdomain: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_SUBDOMAIN;
    },
    ip: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_IP;
    },
    target: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_TARGET;
    },
    scope: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_SCOPE;
    },
    organization: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_ORGANIZATION;
    },
    scan_history: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_SCAN_HISTORY;
    },
    /**
     * Protocol kinds for LLM / API XOR must stay the literals below. Do not compare kind
     * to this.ip() / this.subdomain() — window globals can be mis-set to the same value.
     */
    isIp: function (kind) {
      return kind === DEFAULT_IP;
    },
    isSubdomain: function (kind) {
      return kind === DEFAULT_SUBDOMAIN;
    },
    llmQueryParamForKind: function (kind) {
      var KIND_IP = window.RENGINE_ATTACK_SURFACE_ENTITY_IP;
      var KIND_TARGET = window.RENGINE_ATTACK_SURFACE_ENTITY_TARGET;
      var KIND_SCOPE = window.RENGINE_ATTACK_SURFACE_ENTITY_SCOPE;
      var KIND_ORGANIZATION = window.RENGINE_ATTACK_SURFACE_ENTITY_ORGANIZATION;
      var KIND_SUBDOMAIN = window.RENGINE_ATTACK_SURFACE_ENTITY_SUBDOMAIN;
      var KIND_SCAN_HISTORY = window.RENGINE_ATTACK_SURFACE_ENTITY_SCAN_HISTORY;
      switch (kind) {
        case KIND_IP:
          return "ip_address_id";
        case KIND_TARGET:
          return "target_id";
        case KIND_SCOPE:
          return "scope_id";
        case KIND_ORGANIZATION:
          return "organization_id";
        case KIND_SUBDOMAIN:
          return "subdomain_id";
        case KIND_SCAN_HISTORY:
          return "scan_history_id";
        default:
          return null;
      }
    },
    /**
     * Key on RENGINE_DATATABLE_ACTION_URLS.target for the LLM attack-surface API URL
     * (must match api.helpers.datatables.actions.build_datatable_action_urls).
     */
    datatableTargetAttackSurfaceUrlKey: "attackSurface",
    attackSurfaceApiUrlFromDatatableUrls: function () {
      var urls = window.RENGINE_DATATABLE_ACTION_URLS;
      var key = window.RengineTargetEntityKind.datatableTargetAttackSurfaceUrlKey;
      if (!urls || !urls.target || !urls.target[key]) {
        return null;
      }
      return urls.target[key];
    }
  };
})(window);
