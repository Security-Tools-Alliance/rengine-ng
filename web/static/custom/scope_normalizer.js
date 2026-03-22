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

  const DEFAULT_IDS = {
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

  const CSRF_ERROR_MSG = "CSRF token not found. Please reload the page and try again.";

  const getCsrfToken = function () {
    const name = "csrftoken";
    const cookies = document.cookie ? document.cookie.split(";") : [];
    for (const cRaw of cookies) {
      const c = cRaw.trim();
      if (c.indexOf(name + "=") === 0) {
        return c.substring(name.length + 1);
      }
    }
    const input = document.querySelector('input[name="csrfmiddlewaretoken"]');
    if (input && input.value) {
      return input.value;
    }
    throw new Error(CSRF_ERROR_MSG);
  };

  const postJson = function (url, data, onOk, onErr) {
    let token;
    try {
      token = getCsrfToken();
    } catch (e) {
      onErr(e && e.message ? e.message : CSRF_ERROR_MSG);
      return;
    }
    if (typeof fetch === "undefined") {
      const xhr = new XMLHttpRequest();
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
            const j = JSON.parse(xhr.responseText);
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
    const responseHandled = {};
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
  };

  const showResult = function (data, resultEl) {
    const {
      domain_targets: domainTargetsList = [],
      ip_targets: ipTargetsList = [],
      cidr_targets: cidrTargetsList = [],
      url_targets: urlTargetsList = [],
      allowed_finding_hosts: allowedHostsList = [],
    } = data || {};
    const domainCount = (domainTargetsList && domainTargetsList.length) || 0;
    const ipCount = (ipTargetsList && ipTargetsList.length) || 0;
    const cidrCount = (cidrTargetsList && cidrTargetsList.length) || 0;
    const urlCount = (urlTargetsList && urlTargetsList.length) || 0;
    const hostCount = (allowedHostsList && allowedHostsList.length) || 0;
    resultEl.textContent =
      "Domain targets: " +
      domainCount +
      ", IP targets: " +
      ipCount +
      ", CIDR targets: " +
      cidrCount +
      ", URL targets: " +
      urlCount +
      ", Allowed hosts: " +
      hostCount;
    resultEl.style.display = "block";
  };

  const createChangeEvent = function () {
    if (typeof Event === "function") {
      return new Event("change", { bubbles: true });
    }
    try {
      const e = document.createEvent("HTMLEvents");
      e.initEvent("change", true, false);
      return e;
    } catch (err) {
      return null;
    }
  };

  /**
   * Initialize the scope normalizer block.
   * Apply to form uses normalize only (no target creation); pending targets are stored and created when the scope is saved.
   * @param {Object} config - { normalizeUrl, [rawId], [resultId], ... } optional overrides for DEFAULT_IDS
   */
  const initScopeNormalizer = function (config) {
    const { normalizeUrl } = config;
    const ids = Object.assign({}, DEFAULT_IDS, config);
    const {
      rawId,
      resultId,
      errorId,
      btnId,
      applyBtnId,
      restrictId,
      allowedHostsId,
      pendingInputId,
      previewDivId,
      previewSummaryId,
    } = ids;
    const rawInput = document.getElementById(rawId);
    const resultDiv = document.getElementById(resultId);
    const errorDiv = document.getElementById(errorId);
    const btn = document.getElementById(btnId);
    const applyBtn = document.getElementById(applyBtnId);
    const restrictCb = document.getElementById(restrictId);
    const allowedHostsInput = document.getElementById(allowedHostsId);
    const pendingInput = document.getElementById(pendingInputId);
    const previewDiv = document.getElementById(previewDivId);
    const previewSummary = document.getElementById(previewSummaryId);

    if (!rawInput || !resultDiv || !errorDiv || !btn || !applyBtn) {
      return;
    }

    btn.addEventListener("click", function () {
      const raw = rawInput.value ? rawInput.value.trim() : "";
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
      const raw = rawInput.value ? rawInput.value.trim() : "";
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
            const changeEvCb = createChangeEvent();
            if (changeEvCb && restrictCb.dispatchEvent) {
              restrictCb.dispatchEvent(changeEvCb);
            }
          }
          if (data.allowed_finding_hosts && data.allowed_finding_hosts.length && allowedHostsInput) {
            const existing = (allowedHostsInput.value || "")
              .split(/\r?\n/)
              .map(function (s) {
                return s.trim().toLowerCase();
              })
              .filter(Boolean);
            const seen = {};
            existing.forEach(function (h) {
              seen[h] = true;
            });
            data.allowed_finding_hosts.forEach(function (h) {
              const key = h && h.trim && h.trim() ? h.trim().toLowerCase() : "";
              if (key && !seen[key]) {
                seen[key] = true;
                existing.push(key);
              }
            });
            allowedHostsInput.value = existing.join("\n");
          }
          const domainTargets = data.domain_targets && data.domain_targets.length ? data.domain_targets : [];
          const ipTargets = data.ip_targets && data.ip_targets.length ? data.ip_targets : [];
          const cidrTargets = data.cidr_targets && data.cidr_targets.length ? data.cidr_targets : [];
          const urlTargets = data.url_targets && data.url_targets.length ? data.url_targets : [];
          const hasPending =
            domainTargets.length ||
            ipTargets.length ||
            cidrTargets.length ||
            urlTargets.length;
          if (pendingInput) {
            pendingInput.value = hasPending
              ? JSON.stringify({
                  domain_targets: domainTargets,
                  ip_targets: ipTargets,
                  cidr_targets: cidrTargets,
                  url_targets: urlTargets,
                })
              : "";
          }
          if (previewDiv && previewSummary && hasPending) {
            const parts = [];
            if (domainTargets.length) {
              parts.push(domainTargets.length + " domain target(s): " + domainTargets.slice(0, 5).join(", ") + (domainTargets.length > 5 ? " …" : ""));
            }
            if (ipTargets.length) {
              parts.push(ipTargets.length + " IP target(s): " + ipTargets.slice(0, 5).join(", ") + (ipTargets.length > 5 ? " …" : ""));
            }
            if (cidrTargets.length) {
              parts.push(cidrTargets.length + " CIDR target(s): " + cidrTargets.slice(0, 5).join(", ") + (cidrTargets.length > 5 ? " …" : ""));
            }
            if (urlTargets.length) {
              parts.push(urlTargets.length + " URL target(s): " + urlTargets.slice(0, 5).join(", ") + (urlTargets.length > 5 ? " …" : ""));
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
  };

  global.initScopeNormalizer = initScopeNormalizer;
})(this);
