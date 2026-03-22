(function () {
  "use strict";
  const R = window.RengineAdvancedSearch;
  if (!R) return;

  R.getCsrfToken = function () {
    if (typeof window.getCookie === "function") return window.getCookie("csrftoken") || "";
    const m = document.cookie.match(/csrftoken=([^;]+)/);
    return m ? m[1] : "";
  };

  R.formatBuilderValueLiteral = function (rawValue) {
    return '"' + String(rawValue || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  };

  R.getAdvancedSearchScopeQuery = function (config) {
    let api = R.resolveTableApi(config);
    if (!api || typeof api.settings !== "function") return "";
    let st = api.settings()[0];
    if (!st || !st.ajax) return "";
    let ajax = st.ajax;
    let url = typeof ajax === "string" ? ajax : ajax.url;
    if (typeof url === "function") {
      try {
        url = url.call(st.oInstance || api);
      } catch (_e) {
        url = "";
      }
    }
    if (!url || typeof url !== "string") return "";
    try {
      const u = new URL(url, window.location.origin);
      const sp = new URLSearchParams(u.search);
      sp.delete("format");
      return sp.toString();
    } catch (_e2) {
      return "";
    }
  };

  R.destroyBuilderValueSelect2 = function (valueEl) {
    if (!valueEl || !window.jQuery || !window.jQuery.fn.select2) return;
    let $el = window.jQuery(valueEl);
    if ($el.data("select2")) {
      $el.select2("destroy");
    }
  };

  R.initBuilderValueSelect2 = function (valueEl, dropdownParent) {
    if (!valueEl || !window.jQuery || !window.jQuery.fn.select2) return;
    let $el = window.jQuery(valueEl);
    let parent =
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

  const fillBuilderValueOptions = function (valueEl, vals) {
    valueEl.innerHTML = "";
    let emptyOpt = document.createElement("option");
    emptyOpt.value = "";
    emptyOpt.textContent = "—";
    valueEl.appendChild(emptyOpt);
    vals.forEach(function (v) {
      let o = document.createElement("option");
      o.value = String(v);
      o.textContent = String(v);
      valueEl.appendChild(o);
    });
  };

  const optionExists = function (valueEl, val) {
    let s = String(val);
    for (let i = 0; i < valueEl.options.length; i++) {
      if (valueEl.options[i].value === s) return true;
    }
    return false;
  };

  R.loadAdvancedSearchBuilderValues = function (config, fieldName, valueEl, builderHost) {
    if (!valueEl || !config || !config.contextApiKey || !fieldName) return;
    let isInput = valueEl.tagName === "INPUT";
    let datalistId = config.wrapperId + "-builder-datalist";
    let datalistEl = document.getElementById(datalistId);
    let $jq = !isInput && window.jQuery ? window.jQuery(valueEl) : null;
    let hasSelect2 = $jq && $jq.data("select2");

    if (!isInput && !hasSelect2) {
      R.destroyBuilderValueSelect2(valueEl);
      valueEl.innerHTML = "";
      let loading = document.createElement("option");
      loading.value = "";
      loading.textContent = "Loading…";
      valueEl.appendChild(loading);
    } else if (isInput && valueEl) {
      valueEl.placeholder = "Loading…";
    }

    let scopeQs = R.getAdvancedSearchScopeQuery(config);
    let url =
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
        let vals = data.values || [];
        if (isInput && datalistEl) {
          datalistEl.innerHTML = "";
          vals.forEach(function (v) {
            let o = document.createElement("option");
            o.value = String(v);
            datalistEl.appendChild(o);
          });
          valueEl.placeholder = "value";
          return;
        }
        if (hasSelect2 && $jq) {
          let prevVal = $jq.val();
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
        let errOpt = document.createElement("option");
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
      let v = window.jQuery(valueEl).val();
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
    let emptyOpt = document.createElement("option");
    emptyOpt.value = "";
    emptyOpt.textContent = "—";
    valueEl.appendChild(emptyOpt);
    R.initBuilderValueSelect2(valueEl, valueEl.closest(".rengine-advanced-search-builder"));
  };

  R.refreshAdvancedSearchBuilderFieldSelects = function () {
    let profiles = R.getProfiles();
    Object.keys(profiles).forEach(function (ctxKey) {
      let p = profiles[ctxKey];
      if (!p || !p.wrapperId) return;
      let fields = Array.isArray(p.fields) ? p.fields : [];
      let host = document.getElementById(p.wrapperId + "-builder");
      if (!host) return;
      let row = host.querySelector(".d-flex");
      if (!row) return;
      let selects = row.querySelectorAll("select.form-select-sm");
      if (!selects.length) return;
      let fieldSel = selects[0];
      let cur = fieldSel.value;
      fieldSel.innerHTML = "";
      fields.forEach(function (f) {
        let o = document.createElement("option");
        o.value = f;
        o.textContent = f;
        fieldSel.appendChild(o);
      });
      if (fields.indexOf(cur) >= 0) {
        fieldSel.value = cur;
      } else if (fields.length) {
        fieldSel.selectedIndex = 0;
      }
      let valueEl = document.getElementById(p.wrapperId + "-builder-value");
      if (valueEl) {
        let cfg = R.profileToConfig(p, ctxKey);
        if (cfg) {
          R.loadAdvancedSearchBuilderValues(cfg, fieldSel.value, valueEl, host);
        }
      }
    });
  };

  R.fetchAdvancedSearchFieldsCache = function (callback) {
    let keys = Object.keys(R.getProfiles());
    let pending = keys.length;
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
