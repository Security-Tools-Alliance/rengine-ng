(function () {
  "use strict";
  /** Field ids must stay lowercase; must match backend ADVANCED_SEARCH_FIELD_CATALOG. */
  var R = (window.RengineAdvancedSearch = window.RengineAdvancedSearch || {});

  R.BOUND_ATTR = "data-rengine-advanced-search-bound";

  var ADVANCED_SEARCH_PROFILES = {
    subdomains: {
      wrapperId: "subdomain-search-input",
      inputId: "subdomains-search",
      buttonId: "subdomain-search-button",
      suggestionBoxId: "subdomains-autocom-box",
      contextLabel: "subdomains",
      tableId: "subdomain_scan_results",
      tableGlobal: "subdomain_datatables",
      fields: [
        "name",
        "page_title",
        "http_status",
        "is_important",
        "technology",
        "port",
        "webserver",
        "ip_address",
        "content_length",
      ],
    },
    endpoints: {
      wrapperId: "endpoint-search-input",
      inputId: "endpoints-search",
      buttonId: "endpoint-search-button",
      suggestionBoxId: "endpoints-autocom-box",
      contextLabel: "endpoints",
      tableId: "endpoint_results",
      tableGlobal: "endpoint_table",
      fields: [
        "http_url",
        "http_status",
        "page_title",
        "gf_pattern",
        "content_type",
        "content_length",
        "technology",
        "webserver",
      ],
    },
    vulnerabilities: {
      wrapperId: "vulnerability-search-input",
      inputId: "vulnerability-search",
      buttonId: "vulnerability-search-button",
      suggestionBoxId: "vulnerability-autocom-box",
      contextLabel: "vulnerabilities",
      tableId: "vulnerability_results",
      tableGlobal: "vulnerability_table",
      fields: [
        "name",
        "tag",
        "severity",
        "cvss_score",
        "http_url",
        "status",
        "description",
      ],
    },
  };

  R.registry = R.registry || {};
  R.registry.profiles = ADVANCED_SEARCH_PROFILES;
  R.registry.version = 1;

  R.getProfiles = function () {
    return (R.registry && R.registry.profiles) || {};
  };

  R.registerDataTable = function (contextKey, tableApi) {
    if (!contextKey || !tableApi) return;
    window.RENGINE_TABLES = window.RENGINE_TABLES || {};
    window.RENGINE_TABLES[contextKey] = tableApi;
  };

  R.getDataTable = function (contextKey) {
    var reg = window.RENGINE_TABLES || {};
    return contextKey ? reg[contextKey] : reg;
  };

  window.RENGINE_ADVANCED_SEARCH_PROFILES = ADVANCED_SEARCH_PROFILES;

  R.getCurrentProjectSlug = function () {
    if (typeof window.getCurrentProjectSlug === "function") {
      return window.getCurrentProjectSlug() || "";
    }
    if (!document || !document.body) return "";
    return (document.body.getAttribute("data-project-slug") || "").trim();
  };

  R.getStorageKey = function (baseKey) {
    var slug = R.getCurrentProjectSlug();
    return slug ? baseKey + ":" + slug : baseKey;
  };

  R.getDatatableSearchStorageKey = function (tableId) {
    if (!tableId) return "";
    return R.getStorageKey("rengine-datatable-search-" + tableId);
  };

  R.resolveTableApi = function (config) {
    if (typeof config.getTableApi === "function") {
      return config.getTableApi();
    }
    return config.tableApi || null;
  };

  R.profileToConfig = function (profile, contextKey) {
    if (!profile || !profile.tableGlobal) return null;
    var tableGlobal = profile.tableGlobal;
    var apiCtx = String(profile.contextApiKey || contextKey || "").trim();
    return {
      wrapperId: profile.wrapperId,
      inputId: profile.inputId,
      buttonId: profile.buttonId,
      suggestionBoxId: profile.suggestionBoxId,
      contextLabel: profile.contextLabel,
      tableId: profile.tableId,
      fields: profile.fields,
      debounceMs: profile.debounceMs,
      contextApiKey: apiCtx,
      getTableApi: function () {
        var api = R.getDataTable(contextKey);
        if (api) return api;
        return window[tableGlobal] || null;
      },
    };
  };
})();
