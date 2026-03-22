(function (window) {
  "use strict";
  let R = window.RengineAdvancedSearch;
  if (!R) return;

  let applyTableSearch = function (config, inputEl, storageKey) {
    let value = String((inputEl && inputEl.value) || "");
    let tableApi = R.resolveTableApi(config);
    if (!tableApi || typeof tableApi.search !== "function") return;
    if (tableApi.search() === value) return;
    tableApi.search(value).draw();
    if (storageKey && window.rengineStorage && typeof window.rengineStorage.setJson === "function") {
      window.rengineStorage.setJson(storageKey, value);
    }
  };

  let restorePersistedValue = function (inputEl, storageKey) {
    if (!storageKey || !window.rengineStorage || typeof window.rengineStorage.getJson !== "function") return;
    try {
      let saved = window.rengineStorage.getJson(storageKey);
      if (typeof saved === "string" && saved.length) {
        inputEl.value = saved;
      }
    } catch (_err) {
      // ignore storage failures
    }
  };

  let attachAdvancedDatatableSearch = function (config) {
    if (!config || !config.wrapperId || !config.inputId || !config.buttonId) return null;
    let wrapper = document.getElementById(config.wrapperId);
    let input = document.getElementById(config.inputId);
    let button = document.getElementById(config.buttonId);
    if (!wrapper || !input || !button) return null;
    let suggestionBox = config.suggestionBoxId
      ? document.getElementById(config.suggestionBoxId)
      : wrapper.querySelector(".autocom-box");
    if (!suggestionBox) return null;

    let fields = Array.isArray(config.fields) ? config.fields : [];
    let contextLabel = String(config.contextLabel || "results");
    let debounceMs = Number.isFinite(config.debounceMs) ? config.debounceMs : 250;
    let storageKey = config.tableId
      ? R.getDatatableSearchStorageKey(config.tableId)
      : config.storageKeyBase
        ? R.getStorageKey(config.storageKeyBase)
        : "";

    restorePersistedValue(input, storageKey);

    let suggestionIndex = -1;
    let skipEnterKeyupApply = false;

    let clearSuggestionHighlight = function () {
      suggestionBox.querySelectorAll(".rengine-advanced-search-suggestion").forEach(function (n) {
        n.classList.remove("rengine-advanced-search-suggestion-active");
      });
    };

    let setSuggestionHighlight = function (idx) {
      let items = suggestionBox.querySelectorAll(".rengine-advanced-search-suggestion");
      clearSuggestionHighlight();
      suggestionIndex = idx;
      if (idx >= 0 && idx < items.length) {
        items[idx].classList.add("rengine-advanced-search-suggestion-active");
        items[idx].scrollIntoView({ block: "nearest", behavior: "smooth" });
      }
    };

    let renderSuggestions = function () {
      suggestionIndex = -1;
      let pool = R.getSuggestionPool(input.value, fields);
      let html = pool.map(function (token) {
        return R.renderSuggestionItem(token, contextLabel);
      });
      suggestionBox.innerHTML = html.join("");
      wrapper.classList.add("active");
      suggestionBox.querySelectorAll(".rengine-advanced-search-suggestion").forEach(function (node) {
        node.addEventListener("click", function () {
          let token = node.getAttribute("data-token") || "";
          input.value = String(input.value || "") + token;
          input.focus();
          renderSuggestions();
        });
      });
    };

    let hideSuggestions = function () {
      suggestionIndex = -1;
      clearSuggestionHighlight();
      wrapper.classList.remove("active");
    };

    let timer = null;
    let queueSearch = function () {
      if (timer !== null) window.clearTimeout(timer);
      timer = window.setTimeout(function () {
        timer = null;
        applyTableSearch(config, input, storageKey);
      }, debounceMs);
    };

    button.addEventListener("click", function () {
      hideSuggestions();
      applyTableSearch(config, input, storageKey);
    });

    input.addEventListener("click", function () {
      renderSuggestions();
    });

    input.addEventListener("keydown", function (ev) {
      let key = ev.key || "";
      let active = wrapper.classList.contains("active");
      let items = suggestionBox.querySelectorAll(".rengine-advanced-search-suggestion");
      if (active && items.length) {
        if (key === "ArrowDown") {
          ev.preventDefault();
          let nextDn =
            suggestionIndex < 0 ? 0 : Math.min(suggestionIndex + 1, items.length - 1);
          setSuggestionHighlight(nextDn);
          return;
        }
        if (key === "ArrowUp") {
          ev.preventDefault();
          let nextUp =
            suggestionIndex <= 0 ? items.length - 1 : suggestionIndex - 1;
          setSuggestionHighlight(nextUp);
          return;
        }
        if (key === "Enter") {
          if (suggestionIndex >= 0 && suggestionIndex < items.length) {
            ev.preventDefault();
            skipEnterKeyupApply = true;
            let tok = items[suggestionIndex].getAttribute("data-token") || "";
            input.value = String(input.value || "") + tok;
            renderSuggestions();
            queueSearch();
          }
          return;
        }
        if (key === "Escape") {
          ev.preventDefault();
          hideSuggestions();
          return;
        }
      }
    });

    input.addEventListener("keyup", function (event) {
      let key = event.key || "";
      if (key === "ArrowDown" || key === "ArrowUp") {
        return;
      }
      if (key === "Enter" || key === "Escape") {
        if (key === "Enter" && skipEnterKeyupApply) {
          skipEnterKeyupApply = false;
          return;
        }
        hideSuggestions();
        applyTableSearch(config, input, storageKey);
        return;
      }
      renderSuggestions();
      queueSearch();
    });
    input.addEventListener("change", function () {
      renderSuggestions();
      queueSearch();
    });

    if (!window.rengineAdvancedSearchDocClickRegistered) {
      window.rengineAdvancedSearchDocClickRegistered = true;
      window.rengineAdvancedSearchCleanupTargets = function () {
        if (!window.rengineAdvancedSearchClickTargets) return;
        window.rengineAdvancedSearchClickTargets = window.rengineAdvancedSearchClickTargets.filter(function (t) {
          return (
            t &&
            t.wrapper &&
            (t.wrapper.isConnected === true || (document.body && document.body.contains(t.wrapper)))
          );
        });
      };
      document.addEventListener("click", function (event) {
        if (typeof window.rengineAdvancedSearchCleanupTargets === "function") {
          window.rengineAdvancedSearchCleanupTargets();
        }
        let targets = window.rengineAdvancedSearchClickTargets;
        if (!targets || !targets.length) return;
        for (let ti = 0; ti < targets.length; ti++) {
          let t = targets[ti];
          if (!t || !t.wrapper || typeof t.hide !== "function") continue;
          if (!t.wrapper.contains(event.target)) {
            t.hide();
          }
        }
      });
    }
    window.rengineAdvancedSearchClickTargets = window.rengineAdvancedSearchClickTargets || [];
    if (typeof window.rengineAdvancedSearchCleanupTargets === "function") {
      window.rengineAdvancedSearchCleanupTargets();
    }
    window.rengineAdvancedSearchClickTargets = window.rengineAdvancedSearchClickTargets.filter(function (x) {
      return x.wrapperId !== config.wrapperId;
    });
    window.rengineAdvancedSearchClickTargets.push({
      wrapperId: config.wrapperId,
      wrapper: wrapper,
      hide: hideSuggestions,
    });

    if (input.value) {
      let retries = 25;
      let applyWhenReady = function () {
        let tableApi = R.resolveTableApi(config);
        if (tableApi && typeof tableApi.search === "function") {
          applyTableSearch(config, input, storageKey);
          return;
        }
        retries -= 1;
        if (retries > 0) {
          window.setTimeout(applyWhenReady, 120);
        }
      };
      window.setTimeout(applyWhenReady, 0);
    }

    let contextApiKey = config.contextApiKey || "";
    let feedbackEl = document.getElementById(config.wrapperId + "-validate");
    if (!feedbackEl) {
      feedbackEl = document.createElement("div");
      feedbackEl.id = config.wrapperId + "-validate";
      feedbackEl.className = "small mt-1 px-3 rengine-advanced-search-validate";
      feedbackEl.setAttribute("aria-live", "polite");
      wrapper.appendChild(feedbackEl);
    }
    let validateTimer = null;
    let validateAbortCtrl = null;
    let validateSeq = 0;
    let runValidate = function () {
      if (!contextApiKey) return;
      let expr = String(input.value || "").trim();
      if (!expr) {
        if (validateAbortCtrl && typeof validateAbortCtrl.abort === "function") {
          try {
            validateAbortCtrl.abort();
          } catch (_a) {}
        }
        validateAbortCtrl = null;
        feedbackEl.textContent = "";
        feedbackEl.className = "small mt-1 px-3 rengine-advanced-search-validate";
        return;
      }
      if (validateAbortCtrl && typeof validateAbortCtrl.abort === "function") {
        try {
          validateAbortCtrl.abort();
        } catch (_b) {}
      }
      validateAbortCtrl =
        typeof AbortController !== "undefined" ? new AbortController() : null;
      let seq = (validateSeq += 1);
      let signal = validateAbortCtrl ? validateAbortCtrl.signal : undefined;
      fetch("/api/advancedSearch/validate/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": R.getCsrfToken(),
        },
        body: JSON.stringify({ expression: expr, context: contextApiKey }),
        signal: signal,
      })
        .then(function (r) {
          return r.json();
        })
        .then(function (data) {
          if (seq !== validateSeq) return;
          if (!data) return;
          if (!data.valid) {
            let msg =
              data.error_detail && String(data.error_detail).trim()
                ? String(data.error_detail)
                : data.error
                  ? String(data.error)
                  : "Invalid expression";
            feedbackEl.textContent = msg;
            feedbackEl.className = "small mt-1 px-3 text-danger rengine-advanced-search-validate";
          } else {
            let w = data.warnings && data.warnings.length;
            feedbackEl.textContent = w ? "Note: " + data.warnings.join("; ") : "";
            feedbackEl.className = w
              ? "small mt-1 px-3 text-warning rengine-advanced-search-validate"
              : "small mt-1 px-3 rengine-advanced-search-validate";
          }
        })
        .catch(function (err) {
          if (err && err.name === "AbortError") return;
          if (seq !== validateSeq) return;
          if (String(expr || "").trim()) {
            feedbackEl.textContent = "Validation unavailable";
            feedbackEl.className = "small mt-1 px-3 text-muted rengine-advanced-search-validate";
          }
        });
    };
    input.addEventListener("keyup", function () {
      if (!contextApiKey) return;
      if (validateTimer) window.clearTimeout(validateTimer);
      validateTimer = window.setTimeout(runValidate, 450);
    });

    let builderHost = document.getElementById(config.wrapperId + "-builder");
    if (!builderHost && contextApiKey) {
      builderHost = document.createElement("details");
      builderHost.className = "mt-2 small px-3 rengine-advanced-search-builder";
      let summ = document.createElement("summary");
      summ.textContent = "Build filter";
      builderHost.appendChild(summ);
      let row = document.createElement("div");
      row.className = "d-flex flex-wrap align-items-center gap-2 mt-1 mb-0";
      let selF = document.createElement("select");
      selF.className = "form-select form-select-sm";
      selF.style.maxWidth = "10rem";
      fields.forEach(function (f) {
        let o = document.createElement("option");
        o.value = f;
        o.textContent = f;
        selF.appendChild(o);
      });
      let selO = document.createElement("select");
      selO.className = "form-select form-select-sm";
      selO.style.maxWidth = "5rem";
      ["=", "!=", "!", ">", "<"].forEach(function (op) {
        let o = document.createElement("option");
        o.value = op;
        o.textContent = op;
        selO.appendChild(o);
      });
      let selV;
      if (window.jQuery && window.jQuery.fn.select2) {
        selV = document.createElement("select");
        selV.className = "form-select form-select-sm rengine-advanced-search-builder-value";
      } else {
        let dl = document.createElement("datalist");
        dl.id = config.wrapperId + "-builder-datalist";
        row.appendChild(dl);
        selV = document.createElement("input");
        selV.type = "text";
        selV.className = "form-control form-control-sm";
        selV.setAttribute("list", dl.id);
        selV.placeholder = "value";
      }
      selV.id = config.wrapperId + "-builder-value";
      selV.setAttribute("aria-label", "Filter value");
      selV.style.width = "10rem";
      selV.style.maxWidth = "10rem";
      let joinWrap = document.createElement("div");
      joinWrap.className = "d-flex align-items-center gap-1";
      let joinLbl = document.createElement("span");
      joinLbl.className = "text-muted text-nowrap small";
      joinLbl.textContent = "Then";
      let selJoin = document.createElement("select");
      selJoin.className = "form-select form-select-sm";
      selJoin.setAttribute("aria-label", "Combine with AND or OR");
      selJoin.style.minWidth = "6.5rem";
      selJoin.style.maxWidth = "12rem";
      [
        { value: "&", text: "AND (&)" },
        { value: "|", text: "OR (|)" },
      ].forEach(function (j) {
        let jo = document.createElement("option");
        jo.value = j.value;
        jo.textContent = j.text;
        selJoin.appendChild(jo);
      });
      joinWrap.appendChild(joinLbl);
      joinWrap.appendChild(selJoin);
      let btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-sm btn-soft-primary mb-0";
      btn.textContent = "Append";
      btn.addEventListener("click", function () {
        let f = selF.value;
        let op = selO.value;
        let v = R.readBuilderValueInput(selV);
        if (!v) return;
        let piece = f + op + R.formatBuilderValueLiteral(v);
        let cur = String(input.value || "").trim();
        let joiner = selJoin.value === "|" ? "|" : "&";
        input.value = cur ? cur + joiner + piece : piece;
        R.clearBuilderValueInput(selV);
        R.loadAdvancedSearchBuilderValues(config, selF.value, selV, builderHost);
        runValidate();
        applyTableSearch(config, input, storageKey);
      });
      let loadValuesTimer = null;
      selF.addEventListener("change", function () {
        if (loadValuesTimer) window.clearTimeout(loadValuesTimer);
        loadValuesTimer = window.setTimeout(function () {
          R.loadAdvancedSearchBuilderValues(config, selF.value, selV, builderHost);
        }, 100);
      });
      builderHost.addEventListener("toggle", function () {
        if (builderHost.open) {
          R.loadAdvancedSearchBuilderValues(config, selF.value, selV, builderHost);
        }
      });
      row.appendChild(selF);
      row.appendChild(selO);
      row.appendChild(selV);
      row.appendChild(joinWrap);
      row.appendChild(btn);
      builderHost.appendChild(row);
      wrapper.appendChild(builderHost);
      R.loadAdvancedSearchBuilderValues(config, selF.value, selV, builderHost);
    }

    let appendHost = button.parentElement;
    if (appendHost && !appendHost.querySelector(".rengine-advanced-search-clear")) {
      let clearBtn = document.createElement("button");
      clearBtn.type = "button";
      clearBtn.className =
        "btn btn-sm rengine-advanced-search-clear d-inline-flex align-items-center justify-content-center px-2";
      clearBtn.setAttribute("aria-label", "Clear filter and reset table search");
      clearBtn.title = "Clear filter";
      clearBtn.innerHTML =
        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
      appendHost.insertBefore(clearBtn, button);
      clearBtn.addEventListener("click", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        input.value = "";
        hideSuggestions();
        applyTableSearch(config, input, storageKey);
        if (contextApiKey) {
          runValidate();
        }
        input.blur();
      });
    }

    return {
      apply: function () {
        applyTableSearch(config, input, storageKey);
      },
      renderSuggestions: renderSuggestions,
    };
  };

  window.initRengineAdvancedDatatableSearch = function () {
    let profiles = R.getProfiles();
    Object.keys(profiles).forEach(function (key) {
      let profile = profiles[key];
      let wrapper = profile && document.getElementById(profile.wrapperId);
      if (!wrapper || wrapper.getAttribute(R.BOUND_ATTR) === "1") return;
      let cfg = R.profileToConfig(profile, key);
      if (!cfg) return;
      attachAdvancedDatatableSearch(cfg);
      wrapper.setAttribute(R.BOUND_ATTR, "1");
    });
  };

  let syncAdvancedSearchInputsToTables = function () {
    let profiles = R.getProfiles();
    Object.keys(profiles).forEach(function (key) {
      let profile = profiles[key];
      if (!profile) return;
      let inp = document.getElementById(profile.inputId);
      let api = R.getDataTable(key) || window[profile.tableGlobal];
      if (!inp || !api || typeof api.search !== "function") return;
      let val = String(inp.value || "");
      if (!val.length) return;
      if (api.search() !== val) {
        api.search(val).draw();
      }
    });
  };

  window.attachAdvancedDatatableSearch = attachAdvancedDatatableSearch;

  let _advancedSearchInitOnce = false;
  let scheduleInit = function () {
    let runInitOnce = function () {
      if (_advancedSearchInitOnce) return;
      _advancedSearchInitOnce = true;
      window.setTimeout(function () {
        window.initRengineAdvancedDatatableSearch();
      }, 0);
    };
    R.fetchAdvancedSearchFieldsCache(runInitOnce);
    window.setTimeout(runInitOnce, 900);
    window.addEventListener("load", function () {
      window.initRengineAdvancedDatatableSearch();
      window.setTimeout(syncAdvancedSearchInputsToTables, 0);
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scheduleInit);
  } else {
    scheduleInit();
  }
})(window);
