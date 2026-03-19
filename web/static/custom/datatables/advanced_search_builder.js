(function () {
  "use strict";
  var R = window.RengineAdvancedSearch;
  if (!R) return;

  R.getCsrfToken = function () {
    if (typeof window.getCookie === "function") return window.getCookie("csrftoken") || "";
    var m = document.cookie.match(/csrftoken=([^;]+)/);
    return m ? m[1] : "";
  };

  R.formatBuilderValueLiteral = function (rawValue) {
    return '"' + String(rawValue || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  };

  R.getAdvancedSearchScopeQuery = function (config) {
    var api = R.resolveTableApi(config);
    if (!api || typeof api.settings !== "function") return "";
    var st = api.settings()[0];
    if (!st || !st.ajax) return "";
    var ajax = st.ajax;
    var url = typeof ajax === "string" ? ajax : ajax.url;
    if (typeof url === "function") {
      try {
        url = url.call(st.oInstance || api);
      } catch (_e) {
        url = "";
      }
    }
    if (!url || typeof url !== "string") return "";
    try {
      var u = new URL(url, window.location.origin);
      var sp = new URLSearchParams(u.search);
      sp.delete("format");
      return sp.toString();
    } catch (_e2) {
      return "";
    }
  };

  R.destroyBuilderValueSelect2 = function (valueEl) {
    if (!valueEl || !window.jQuery || !window.jQuery.fn.select2) return;
    var $el = window.jQuery(valueEl);
    if ($el.data("select2")) {
      $el.select2("destroy");
    }
  };

  R.initBuilderValueSelect2 = function (valueEl, dropdownParent) {
    if (!valueEl || !window.jQuery || !window.jQuery.fn.select2) return;
    var $el = window.jQuery(valueEl);
    var parent =
      dropdownParent && window.jQuery(dropdownParent).length
        ? window.jQuery(dropdownParent)
        : window.jQuery(document.body);
    $el.select2({
      tags: true,
      placeholder: "value",
      allowClear: false,
      width: "10rem",
      dropdownParent: parent,
    });
  };

  function fillBuilderValueOptions(valueEl, vals) {
    valueEl.innerHTML = "";
    var emptyOpt = document.createElement("option");
    emptyOpt.value = "";
    emptyOpt.textContent = "—";
    valueEl.appendChild(emptyOpt);
    vals.forEach(function (v) {
      var o = document.createElement("option");
      o.value = String(v);
      o.textContent = String(v);
      valueEl.appendChild(o);
    });
  }

  function optionExists(valueEl, val) {
    var s = String(val);
    for (var i = 0; i < valueEl.options.length; i++) {
      if (valueEl.options[i].value === s) return true;
    }
    return false;
  }

  R.loadAdvancedSearchBuilderValues = function (config, fieldName, valueEl, builderHost) {
    if (!valueEl || !config || !config.contextApiKey || !fieldName) return;
    var isInput = valueEl.tagName === "INPUT";
    var datalistId = config.wrapperId + "-builder-datalist";
    var datalistEl = document.getElementById(datalistId);
    var $jq = !isInput && window.jQuery ? window.jQuery(valueEl) : null;
    var hasSelect2 = $jq && $jq.data("select2");

    if (!isInput && !hasSelect2) {
      R.destroyBuilderValueSelect2(valueEl);
      valueEl.innerHTML = "";
      var loading = document.createElement("option");
      loading.value = "";
      loading.textContent = "Loading…";
      valueEl.appendChild(loading);
    } else if (isInput && valueEl) {
      valueEl.placeholder = "Loading…";
    }

    var scopeQs = R.getAdvancedSearchScopeQuery(config);
    var url =
      "/api/advancedSearch/values/?context=" +
      encodeURIComponent(config.contextApiKey) +
      "&field=" +
      encodeURIComponent(fieldName) +
      "&limit=500" +
      (scopeQs ? "&" + scopeQs : "");

    fetch(url, { credentials: "same-origin" })
      .then(function (r) {
        return r.ok ? r.json() : { values: [] };
      })
      .then(function (data) {
        var vals = data.values || [];
        if (isInput && datalistEl) {
          datalistEl.innerHTML = "";
          vals.forEach(function (v) {
            var o = document.createElement("option");
            o.value = String(v);
            datalistEl.appendChild(o);
          });
          valueEl.placeholder = "value";
          return;
        }
        if (hasSelect2 && $jq) {
          var prevVal = $jq.val();
          fillBuilderValueOptions(valueEl, vals);
          if (prevVal != null && prevVal !== "" && optionExists(valueEl, prevVal)) {
            $jq.val(prevVal);
          } else {
            $jq.val(null);
          }
          $jq.trigger("change");
          return;
        }
        valueEl.innerHTML = "";
        fillBuilderValueOptions(valueEl, vals);
        R.initBuilderValueSelect2(valueEl, builderHost || valueEl.closest(".rengine-advanced-search-builder"));
      })
      .catch(function () {
        if (isInput && valueEl) {
          valueEl.placeholder = "value";
          return;
        }
        if (hasSelect2 && $jq) {
          fillBuilderValueOptions(valueEl, []);
          $jq.val(null).trigger("change");
          return;
        }
        valueEl.innerHTML = "";
        var errOpt = document.createElement("option");
        errOpt.value = "";
        errOpt.textContent = "(load failed)";
        valueEl.appendChild(errOpt);
        R.initBuilderValueSelect2(valueEl, builderHost || valueEl.closest(".rengine-advanced-search-builder"));
      });
  };

  R.readBuilderValueInput = function (valueEl) {
    if (!valueEl) return "";
    if (valueEl.tagName === "INPUT") {
      return String(valueEl.value || "").trim();
    }
    if (window.jQuery && window.jQuery.fn.select2 && window.jQuery(valueEl).data("select2")) {
      var v = window.jQuery(valueEl).val();
      return v != null ? String(v).trim() : "";
    }
    return String(valueEl.value || "").trim();
  };

  R.clearBuilderValueInput = function (valueEl) {
    if (!valueEl) return;
    if (valueEl.tagName === "INPUT") {
      valueEl.value = "";
      return;
    }
    R.destroyBuilderValueSelect2(valueEl);
    valueEl.innerHTML = "";
    var emptyOpt = document.createElement("option");
    emptyOpt.value = "";
    emptyOpt.textContent = "—";
    valueEl.appendChild(emptyOpt);
    R.initBuilderValueSelect2(valueEl, valueEl.closest(".rengine-advanced-search-builder"));
  };

  R.refreshAdvancedSearchBuilderFieldSelects = function () {
    var profiles = R.getProfiles();
    Object.keys(profiles).forEach(function (ctxKey) {
      var p = profiles[ctxKey];
      if (!p || !p.wrapperId) return;
      var fields = Array.isArray(p.fields) ? p.fields : [];
      var host = document.getElementById(p.wrapperId + "-builder");
      if (!host) return;
      var row = host.querySelector(".d-flex");
      if (!row) return;
      var selects = row.querySelectorAll("select.form-select-sm");
      if (!selects.length) return;
      var fieldSel = selects[0];
      var cur = fieldSel.value;
      fieldSel.innerHTML = "";
      fields.forEach(function (f) {
        var o = document.createElement("option");
        o.value = f;
        o.textContent = f;
        fieldSel.appendChild(o);
      });
      if (fields.indexOf(cur) >= 0) {
        fieldSel.value = cur;
      } else if (fields.length) {
        fieldSel.selectedIndex = 0;
      }
      var valueEl = document.getElementById(p.wrapperId + "-builder-value");
      if (valueEl) {
        var cfg = R.profileToConfig(p, ctxKey);
        if (cfg) {
          R.loadAdvancedSearchBuilderValues(cfg, fieldSel.value, valueEl, host);
        }
      }
    });
  };

  R.fetchAdvancedSearchFieldsCache = function (callback) {
    var keys = Object.keys(R.getProfiles());
    var pending = keys.length;
    if (!pending) {
      if (typeof callback === "function") callback();
      return;
    }
    keys.forEach(function (ctx) {
      fetch("/api/advancedSearch/fields/?context=" + encodeURIComponent(ctx), { credentials: "same-origin" })
        .then(function (r) {
          return r.ok ? r.json() : null;
        })
        .then(function (data) {
          if (data && data.fields && R.getProfiles()[ctx]) {
            R.getProfiles()[ctx].fields = data.fields.map(function (f) {
              return f.name;
            });
          }
        })
        .catch(function () {})
        .finally(function () {
          pending -= 1;
          if (pending <= 0) {
            R.refreshAdvancedSearchBuilderFieldSelects();
            if (typeof callback === "function") callback();
          }
        });
    });
  };
})();
