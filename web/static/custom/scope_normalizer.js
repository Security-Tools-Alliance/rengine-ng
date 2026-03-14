/**
 * Scope normalizer UI: XHR helpers and event wiring for the scope form.
 * Call initScopeNormalizer(config) with normalizeUrl and optional element id overrides.
 *
 * Expected DOM IDs (scope form template must provide these, or pass overrides in config):
 *   rawId:           scope-normalizer-raw       (textarea for pasted scope)
 *   resultId:        scope-normalizer-result    (div for normalize result summary)
 *   errorId:         scope-normalizer-error     (div for error message)
 *   btnId:           scope-normalizer-btn       (Normalize button)
 *   applyBtnId:      scope-normalizer-apply-btn (Apply to form button)
 *   restrictId:      id_restrict_findings_to_target (checkbox)
 *   allowedHostsId:  id_allowed_finding_hosts   (textarea)
 *   pendingInputId:  pending_normalizer_targets (hidden input)
 *   previewDivId:    scope-normalizer-pending-preview (alert div)
 *   previewSummaryId: scope-normalizer-pending-summary (span for preview text)
 */
(function (global) {
  "use strict";

  var DEFAULT_IDS = {
    rawId: "scope-normalizer-raw",
    resultId: "scope-normalizer-result",
    errorId: "scope-normalizer-error",
    btnId: "scope-normalizer-btn",
    applyBtnId: "scope-normalizer-apply-btn",
    restrictId: "id_restrict_findings_to_target",
    allowedHostsId: "id_allowed_finding_hosts",
    pendingInputId: "pending_normalizer_targets",
    previewDivId: "scope-normalizer-pending-preview",
    previewSummaryId: "scope-normalizer-pending-summary",
  };

  var CSRF_ERROR_MSG = "CSRF token not found. Please reload the page and try again.";

  function getCsrfToken() {
    var name = "csrftoken";
    var cookies = document.cookie ? document.cookie.split(";") : [];
    for (var i = 0; i < cookies.length; i++) {
      var c = cookies[i].trim();
      if (c.indexOf(name + "=") === 0) {
        return c.substring(name.length + 1);
      }
    }
    var input = document.querySelector('input[name="csrfmiddlewaretoken"]');
    if (input && input.value) {
      return input.value;
    }
    throw new Error(CSRF_ERROR_MSG);
  }

  function postJson(url, data, onOk, onErr) {
    var token;
    try {
      token = getCsrfToken();
    } catch (e) {
      onErr(e && e.message ? e.message : CSRF_ERROR_MSG);
      return;
    }
    if (typeof fetch === "undefined") {
      var xhr = new XMLHttpRequest();
      xhr.open("POST", url, true);
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("X-CSRFToken", token);
      xhr.setRequestHeader("Accept", "application/json");
      xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            onOk(JSON.parse(xhr.responseText));
          } catch (err) {
            onErr("Invalid response");
          }
        } else {
          try {
            var j = JSON.parse(xhr.responseText);
            onErr(j.error || xhr.statusText);
          } catch (err) {
            onErr(xhr.statusText || "Request failed");
          }
        }
      };
      xhr.onerror = function () {
        onErr("Network error");
      };
      xhr.send(JSON.stringify(data));
      return;
    }
    var responseHandled = {};
    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": token,
        Accept: "application/json",
      },
      body: JSON.stringify(data),
    })
      .then(function (res) {
        if (res.ok) {
          return res.json();
        }
        return res.json().then(
          function (j) {
            onErr(j && j.error ? j.error : res.statusText);
            return Promise.reject(responseHandled);
          },
          function () {
            onErr(res.statusText || "Request failed");
            return Promise.reject(responseHandled);
          }
        );
      })
      .then(function (json) {
        onOk(json);
      })
      .catch(function (err) {
        if (err === responseHandled) {
          return;
        }
        onErr(err && err.message ? err.message : "Network error");
      });
  }

  function showResult(data, resultEl) {
    var domainCount = (data.domain_targets && data.domain_targets.length) || 0;
    var ipCount = (data.ip_targets && data.ip_targets.length) || 0;
    var hostCount = (data.allowed_finding_hosts && data.allowed_finding_hosts.length) || 0;
    resultEl.textContent =
      "Domain targets: " + domainCount + ", IP targets: " + ipCount + ", Allowed hosts: " + hostCount;
    resultEl.style.display = "block";
  }

  function createChangeEvent() {
    if (typeof Event === "function") {
      return new Event("change", { bubbles: true });
    }
    try {
      var e = document.createEvent("HTMLEvents");
      e.initEvent("change", true, false);
      return e;
    } catch (err) {
      return null;
    }
  }

  /**
   * Initialize the scope normalizer block.
   * Apply to form uses normalize only (no target creation); pending targets are stored and created when the scope is saved.
   * @param {Object} config - { normalizeUrl, [rawId], [resultId], ... } optional overrides for DEFAULT_IDS
   */
  function initScopeNormalizer(config) {
    var normalizeUrl = config.normalizeUrl;
    var ids = Object.assign({}, DEFAULT_IDS, config);
    var rawInput = document.getElementById(ids.rawId);
    var resultDiv = document.getElementById(ids.resultId);
    var errorDiv = document.getElementById(ids.errorId);
    var btn = document.getElementById(ids.btnId);
    var applyBtn = document.getElementById(ids.applyBtnId);
    var restrictCb = document.getElementById(ids.restrictId);
    var allowedHostsInput = document.getElementById(ids.allowedHostsId);
    var pendingInput = document.getElementById(ids.pendingInputId);
    var previewDiv = document.getElementById(ids.previewDivId);
    var previewSummary = document.getElementById(ids.previewSummaryId);

    if (!rawInput || !resultDiv || !errorDiv || !btn || !applyBtn) {
      return;
    }

    btn.addEventListener("click", function () {
      var raw = rawInput.value ? rawInput.value.trim() : "";
      if (!raw) {
        errorDiv.textContent = "Paste some scope text first.";
        errorDiv.style.display = "block";
        resultDiv.style.display = "none";
        return;
      }
      errorDiv.style.display = "none";
      resultDiv.style.display = "none";
      postJson(
        normalizeUrl,
        { raw: raw },
        function (data) {
          showResult(data, resultDiv);
        },
        function (msg) {
          errorDiv.textContent = msg;
          errorDiv.style.display = "block";
          resultDiv.style.display = "none";
        }
      );
    });

    applyBtn.addEventListener("click", function () {
      var raw = rawInput.value ? rawInput.value.trim() : "";
      if (!raw) {
        errorDiv.textContent = "Paste some scope text first.";
        errorDiv.style.display = "block";
        return;
      }
      errorDiv.style.display = "none";
      postJson(
        normalizeUrl,
        { raw: raw },
        function (data) {
          showResult(data, resultDiv);
          if (restrictCb) {
            restrictCb.checked = true;
            var changeEvCb = createChangeEvent();
            if (changeEvCb && restrictCb.dispatchEvent) {
              restrictCb.dispatchEvent(changeEvCb);
            }
          }
          if (data.allowed_finding_hosts && data.allowed_finding_hosts.length && allowedHostsInput) {
            var existing = (allowedHostsInput.value || "")
              .split(/\r?\n/)
              .map(function (s) {
                return s.trim().toLowerCase();
              })
              .filter(Boolean);
            var seen = {};
            existing.forEach(function (h) {
              seen[h] = true;
            });
            data.allowed_finding_hosts.forEach(function (h) {
              var key = (h && h.trim && h.trim()) ? h.trim().toLowerCase() : "";
              if (key && !seen[key]) {
                seen[key] = true;
                existing.push(key);
              }
            });
            allowedHostsInput.value = existing.join("\n");
          }
          var domainTargets = data.domain_targets && data.domain_targets.length ? data.domain_targets : [];
          var ipTargets = data.ip_targets && data.ip_targets.length ? data.ip_targets : [];
          if (pendingInput) {
            pendingInput.value =
              domainTargets.length || ipTargets.length
                ? JSON.stringify({ domain_targets: domainTargets, ip_targets: ipTargets })
                : "";
          }
          if (previewDiv && previewSummary && (domainTargets.length || ipTargets.length)) {
            var parts = [];
            if (domainTargets.length) {
              parts.push(domainTargets.length + " domain target(s): " + domainTargets.slice(0, 5).join(", ") + (domainTargets.length > 5 ? " …" : ""));
            }
            if (ipTargets.length) {
              parts.push(ipTargets.length + " IP target(s): " + ipTargets.slice(0, 5).join(", ") + (ipTargets.length > 5 ? " …" : ""));
            }
            previewSummary.textContent = parts.join("; ");
            previewDiv.style.display = "block";
          } else if (previewDiv) {
            previewDiv.style.display = "none";
          }
        },
        function (msg) {
          errorDiv.textContent = msg;
          errorDiv.style.display = "block";
        }
      );
    });
  }

  global.initScopeNormalizer = initScopeNormalizer;
})(this);
