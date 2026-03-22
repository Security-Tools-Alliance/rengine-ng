/**
 * Central attack-surface / scan entity kinds (subdomain vs IP) for UI and LLM API wiring.
 * Loaded before custom.js; custom.js may override window.RENGINE_ATTACK_SURFACE_ENTITY_*.
 */
(function (window) {
  "use strict";

  var DEFAULT_SUBDOMAIN = "subdomain";
  var DEFAULT_IP = "ip";

  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_SUBDOMAIN === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_SUBDOMAIN = DEFAULT_SUBDOMAIN;
  }
  if (typeof window.RENGINE_ATTACK_SURFACE_ENTITY_IP === "undefined") {
    window.RENGINE_ATTACK_SURFACE_ENTITY_IP = DEFAULT_IP;
  }

  window.RengineTargetEntityKind = {
    subdomain: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_SUBDOMAIN;
    },
    ip: function () {
      return window.RENGINE_ATTACK_SURFACE_ENTITY_IP;
    },
    /**
     * Protocol kinds for LLM / API XOR must stay the literals "subdomain" and "ip".
     * Do not compare kind to this.ip() / this.subdomain() — window globals can be
     * mis-set to the same value, which would classify every row as IP for query params.
     */
    isIp: function (kind) {
      return kind === DEFAULT_IP;
    },
    isSubdomain: function (kind) {
      return kind === DEFAULT_SUBDOMAIN;
    },
    llmQueryParamForKind: function (kind) {
      return kind === DEFAULT_IP ? "ip_address_id" : "subdomain_id";
    }
  };
})(window);
