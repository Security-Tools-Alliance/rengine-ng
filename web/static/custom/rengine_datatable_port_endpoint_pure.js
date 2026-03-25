/**
 * Pure helpers shared by port_display.js and datatables/renderers_subdomain_endpoint.js.
 * Loaded from base.html before those scripts. Node can require() this file for unit tests.
 */
(function (global) {
  "use strict";

  function portDisplayParseStrictTcpPortString(portStr) {
    const s = portStr == null ? "" : String(portStr).trim();
    if (!/^[0-9]+$/.test(s)) {
      return null;
    }
    const p = Number(s);
    if (!Number.isFinite(p) || p < 1 || p > 65535) {
      return null;
    }
    return p;
  }

  function rengineNormalizeEndpointDefaultsTechnologiesFallback(raw) {
    if (Array.isArray(raw)) {
      return { technologies: raw, content_type: "", webserver: "" };
    }
    if (raw && typeof raw === "object") {
      return raw;
    }
    return null;
  }

  function rengineIsEffectivelyEmptyHtml(html) {
    return !html || !String(html).replace(/\s/g, "");
  }

  function rengineValidEndpointDefaultRows(endpointDefaultsByPort) {
    if (!Array.isArray(endpointDefaultsByPort)) {
      return [];
    }
    return endpointDefaultsByPort.filter(function (row) {
      return !!row && typeof row === "object";
    });
  }

  function rengineClassifyEndpointDefaultsByPortInput(endpointDefaultsByPort) {
    if (endpointDefaultsByPort === undefined || endpointDefaultsByPort === null) {
      return "missing";
    }
    if (!Array.isArray(endpointDefaultsByPort)) {
      return "invalid_type";
    }
    if (rengineValidEndpointDefaultRows(endpointDefaultsByPort).length === 0) {
      return "empty_valid_rows";
    }
    return "non_empty";
  }

  global.portDisplayParseStrictTcpPortString = portDisplayParseStrictTcpPortString;
  global.rengineNormalizeEndpointDefaultsTechnologiesFallback = rengineNormalizeEndpointDefaultsTechnologiesFallback;
  global.rengineIsEffectivelyEmptyHtml = rengineIsEffectivelyEmptyHtml;
  global.rengineValidEndpointDefaultRows = rengineValidEndpointDefaultRows;
  global.rengineClassifyEndpointDefaultsByPortInput = rengineClassifyEndpointDefaultsByPortInput;
})(typeof globalThis !== "undefined" ? globalThis : this);

if (typeof module !== "undefined" && module.exports) {
  const g = globalThis;
  module.exports = {
    portDisplayParseStrictTcpPortString: g.portDisplayParseStrictTcpPortString,
    rengineNormalizeEndpointDefaultsTechnologiesFallback: g.rengineNormalizeEndpointDefaultsTechnologiesFallback,
    rengineIsEffectivelyEmptyHtml: g.rengineIsEffectivelyEmptyHtml,
    rengineValidEndpointDefaultRows: g.rengineValidEndpointDefaultRows,
    rengineClassifyEndpointDefaultsByPortInput: g.rengineClassifyEndpointDefaultsByPortInput,
  };
}
