(function () {
  "use strict";
  const R = window.RengineAdvancedSearch;
  if (!R) return;

  const JOINERS = ["&", "|", " AND ", " OR "];
  const OPERATORS = ["=", "!=", "!", ">", "<"];
  const FILTER_ICON = '<i class="fe-filter"></i>';

  R.renderSuggestionItem = function (token, contextLabel) {
    const t = String(token);
    const detail =
      token === "="
        ? "Equals"
        : token === "!=" || token === "!"
          ? "Not equals / exclude"
          : token === ">"
            ? "Greater than"
            : token === "<"
              ? "Lower than"
              : token === "&" || t.indexOf("AND") >= 0
                ? "AND (higher priority than OR)"
                : token === "|" || t.indexOf("OR") >= 0
                  ? "OR"
                  : token === "("
                    ? "Open group"
                    : token === ")"
                      ? "Close group"
                      : "Search in " + contextLabel;
    let searchInLabel = "Search in " + contextLabel;
    let badgeColor = detail === searchInLabel ? "info" : "warning";
    let safeAttr =
      typeof window.safeAttr === "function"
        ? window.safeAttr
        : function (s) {
            return String(s).replace(/"/g, "&quot;");
          };
    const safeText =
      typeof window.safeText === "function"
        ? window.safeText
        : function (s) {
            return String(s);
          };
    return (
      '<li class="text-dark rengine-advanced-search-suggestion" data-token="' +
      safeAttr(String(token)) +
      '"><div class="row"><div class="col-6"><span class="text-' +
      badgeColor +
      '">' +
      FILTER_ICON +
      "</span>&nbsp;" +
      safeText(String(token)) +
      '</div><div class="col-6 text-dark">' +
      safeText(detail) +
      "</div></div></li>"
    );
  };

  const getLastSegment = function (value) {
    const v = String(value || "");
    const parts = v.split(/\s+OR\s+|\s+AND\s+|[&|]/gi);
    return parts.length ? String(parts[parts.length - 1] || "").trim() : "";
  };

  let clauseLooksComplete = function (seg) {
    if (!seg) return false;
    let fieldAndValuePattern =
      /^[\w.-]+\s*(?:!=|[=!><])\s*(?:(?:"(?:[^"\\]|\\.)*")|(?:'[^']*')|\S+)/i;
    return fieldAndValuePattern.test(seg);
  };

  R.getSuggestionPool = function (query, fields) {
    const value = String(query || "");
    const seg = getLastSegment(value);
    const lastChar = value.slice(-1);
    const depth = (value.match(/\(/g) || []).length - (value.match(/\)/g) || []).length;

    if (fields.indexOf(seg) > -1) {
      return OPERATORS.slice();
    }
    if (lastChar === ")" || (clauseLooksComplete(seg) && lastChar !== "(")) {
      const j = JOINERS.slice();
      if (depth > 0) j.push(")");
      return j;
    }
    if (OPERATORS.indexOf(lastChar) > -1 || /[=!><]$/.test(value.trimEnd()) || /!=$/.test(value.slice(-2))) {
      return JOINERS.slice();
    }
    if (/[&|]$/.test(value.trimEnd()) || /\sAND\s*$/i.test(value) || /\sOR\s*$/i.test(value)) {
      const pool = fields.slice();
      if (depth === 0) pool.unshift("(");
      return pool;
    }
    if (!seg) {
      const start = fields.slice();
      if (depth === 0) start.unshift("(");
      return start;
    }
    return fields.filter(function (field) {
      return String(field).toLowerCase().includes(seg.toLowerCase());
    });
  };
})();
