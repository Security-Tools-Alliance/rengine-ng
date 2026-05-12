/**
 * update_progress.js — In-app update flow for reNgine-ng Admin Settings.
 *
 * Exposed on window.RengineUpdate with two public entry points:
 *   checkForUpdateInCard()   — refresh version info in the update card
 *   startUpdateFlow()        — trigger the update and stream progress
 *
 * URLs are read from data-* attributes on #update-card to avoid hardcoding
 * (see rengine-ng-frontend.md conventions).
 *
 * Security: all server-supplied strings are passed through htmlEncode before
 * being inserted into the DOM (Rule 4.1 / Rule 4.2).
 */

(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------

  const RECONNECT_MAX_ATTEMPTS = 18;  // ~3 min with exponential backoff capped at 15 s
  const RECONNECT_BASE_MS       = 2000;
  const RECONNECT_CAP_MS        = 15000;

  // ---------------------------------------------------------------------------
  // Internal state
  // ---------------------------------------------------------------------------

  let _ws             = null;
  let _reconnectTimer = null;
  let _reconnectCount = 0;
  let _isUpdating     = false;

  // ---------------------------------------------------------------------------
  // URL helpers (injected via data-* on #update-card)
  // ---------------------------------------------------------------------------

  function _card() {
    return document.getElementById("update-card");
  }

  function _url(attr) {
    const card = _card();
    return card ? card.dataset[attr] : null;
  }

  // ---------------------------------------------------------------------------
  // HTML escaping (Rule 4.1 – use the single central htmlEncode from custom.js)
  // ---------------------------------------------------------------------------

  function _encode(str) {
    if (typeof htmlEncode === "function") {
      return htmlEncode(str);
    }
    // Fallback in case custom.js loads after this file
    const d = document.createElement("div");
    d.textContent = String(str == null ? "" : str);
    return d.innerHTML;
  }

  // ---------------------------------------------------------------------------
  // Card sections
  // ---------------------------------------------------------------------------

  function _section(id) {
    return document.getElementById(id);
  }

  function _show(id) {
    const el = _section(id);
    if (el) el.classList.remove("d-none");
  }

  function _hide(id) {
    const el = _section(id);
    if (el) el.classList.add("d-none");
  }

  function _setText(id, text) {
    const el = _section(id);
    if (el) el.textContent = text;
  }

  function _setHtml(id, html) {
    const el = _section(id);
    if (el) el.innerHTML = html;
  }

  // ---------------------------------------------------------------------------
  // Check for updates (populates the card; does NOT use the global modal)
  // ---------------------------------------------------------------------------

  function checkForUpdateInCard() {
    const checkUrl = _url("checkUrl");
    if (!checkUrl) return;

    const btn = document.getElementById("btn-check-update");
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Checking...';
    }

    _hide("update-result");
    _hide("update-action-section");
    _hide("update-error");

    fetch(checkUrl)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<i class="fe-refresh-cw me-1"></i>Check for Updates';
        }

        if (!data.status) {
          const msg = data.description === "RateLimited"
            ? "GitHub rate limit hit. Please try again in an hour."
            : "Could not check for updates. Please try again later.";
          _setHtml("update-error-msg", _encode(msg));
          _show("update-error");
          return;
        }

        _show("update-result");

        _setText(
          "update-current-version",
          data.current_version || "—"
        );
        _setText(
          "update-latest-version",
          data.latest_version  || "—"
        );

        if (data.update_available) {
          _show("update-badge-new");
          _hide("update-badge-current");
          if (data.changelog) {
            _setHtml("update-changelog-body", "<pre class='mb-0' style='white-space:pre-wrap;'>" + _encode(data.changelog) + "</pre>");
            _show("update-changelog-section");
          }
          _show("update-action-section");
        } else {
          _hide("update-badge-new");
          _show("update-badge-current");
          _hide("update-changelog-section");
          _hide("update-action-section");
        }
      })
      .catch(function () {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<i class="fe-refresh-cw me-1"></i>Check for Updates';
        }
        _setHtml("update-error-msg", "Network error while checking for updates.");
        _show("update-error");
      });
  }

  // ---------------------------------------------------------------------------
  // Progress modal helpers
  // ---------------------------------------------------------------------------

  function _modalEl() {
    return document.getElementById("update-progress-modal");
  }

  function _appendLog(line, cls) {
    const log = document.getElementById("update-log");
    if (!log) return;
    const div = document.createElement("div");
    if (cls) div.className = cls;
    div.textContent = line;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  function _setProgressBar(pct, label) {
    const bar = document.getElementById("update-progress-bar");
    if (!bar) return;
    bar.style.width = pct + "%";
    bar.setAttribute("aria-valuenow", pct);
    if (label) bar.textContent = label;
  }

  function _openModal() {
    const el = _modalEl();
    if (!el) return;
    const log = document.getElementById("update-log");
    if (log) log.innerHTML = "";
    _setProgressBar(0, "");
    const bsModal = bootstrap.Modal.getOrCreateInstance(el);
    bsModal.show();
  }

  function _closeModal() {
    const el = _modalEl();
    if (!el) return;
    const bsModal = bootstrap.Modal.getInstance(el);
    if (bsModal) bsModal.hide();
  }

  // ---------------------------------------------------------------------------
  // WebSocket progress streaming
  // ---------------------------------------------------------------------------

  const STEP_LABELS = {
    validate:          "Validating repository…",
    stopping_services: "Stopping services…",
    pulling_code:      "Pulling latest code…",
    pulling_images:    "Pulling images…",
    building_images:   "Building images…",
    starting_services: "Starting updated services…",
    complete:          "Update complete!",
  };

  const STEP_PCT = {
    validate:          10,
    stopping_services: 25,
    pulling_code:      45,
    pulling_images:    60,
    building_images:   60,
    starting_services: 80,
    complete:          100,
  };

  function _handleProgressEvent(payload) {
    const step    = payload.step    || "";
    const message = payload.message || "";
    const status  = payload.status  || "";

    const label = STEP_LABELS[step] || step;
    const pct   = STEP_PCT[step]    || 0;

    _setProgressBar(pct, label);
    _appendLog(message, status === "error" ? "text-danger" : null);

    if (status === "complete") {
      _appendLog("Service is restarting. Please wait…", "text-warning fw-bold");
      _startReconnectPolling(payload.new_version || "");
    } else if (status === "error") {
      _isUpdating = false;
      _appendLog("Update failed. Check the server logs for details.", "text-danger fw-bold");
      const dismiss = document.getElementById("btn-close-progress-modal");
      if (dismiss) dismiss.disabled = false;
    }
  }

  function _connectWs() {
    const wsUrl = _url("wsUrl");
    if (!wsUrl) return;

    _ws = new WebSocket(wsUrl);

    _ws.onmessage = function (evt) {
      let payload;
      try {
        payload = JSON.parse(evt.data);
      } catch (e) {
        return;
      }
      _handleProgressEvent(payload);
    };

    _ws.onerror = function () {
      // Handled by onclose
    };

    _ws.onclose = function () {
      _ws = null;
      if (_isUpdating) {
        // Web container may have stopped; switch to reconnect polling
        _appendLog("Connection lost. Service is restarting…", "text-warning");
        _setProgressBar(85, "Restarting services…");
        _startReconnectPolling("");
      }
    };
  }

  // ---------------------------------------------------------------------------
  // Reconnection polling after web container restarts
  // ---------------------------------------------------------------------------

  function _startReconnectPolling(expectedVersion) {
    if (_reconnectTimer) return;
    _reconnectCount = 0;
    _pollStatus(expectedVersion);
  }

  function _pollStatus(expectedVersion) {
    const statusUrl = _url("statusUrl");
    if (!statusUrl) return;

    fetch(statusUrl)
      .then(function (r) {
        if (!r.ok) throw new Error("not ready");
        return r.json();
      })
      .then(function (data) {
        const updateStatus = data.update_status || data.status;

        if (updateStatus === "complete" || data.freshly_updated) {
          const newVer = data.new_version || expectedVersion || "";
          _onUpdateComplete(newVer, statusUrl);
        } else if (updateStatus === "error") {
          _isUpdating = false;
          _appendLog("Update failed on the server side. Please check the logs.", "text-danger fw-bold");
        } else {
          // Still running or idle — schedule next poll
          _scheduleNextPoll(expectedVersion);
        }
      })
      .catch(function () {
        // Server not reachable yet — keep polling
        _scheduleNextPoll(expectedVersion);
      });
  }

  function _scheduleNextPoll(expectedVersion) {
    _reconnectCount++;
    if (_reconnectCount > RECONNECT_MAX_ATTEMPTS) {
      _isUpdating = false;
      _appendLog("Timed out waiting for service restart. Please refresh the page.", "text-danger fw-bold");
      return;
    }
    const delay = Math.min(
      RECONNECT_BASE_MS * Math.pow(1.5, _reconnectCount - 1),
      RECONNECT_CAP_MS
    );
    _reconnectTimer = setTimeout(function () {
      _reconnectTimer = null;
      _pollStatus(expectedVersion);
    }, delay);
  }

  function _onUpdateComplete(newVersion, statusUrl) {
    _isUpdating = false;
    _setProgressBar(100, "Complete!");
    _appendLog(
      "Successfully updated" + (newVersion ? " to " + newVersion : "") + "!",
      "text-success fw-bold"
    );

    // Acknowledge the flag so the next page load does not re-show it
    fetch(statusUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRFToken": getCookie("csrftoken") },
    }).catch(function () {});

    // Reload after a short pause so the UI picks up the new version
    setTimeout(function () {
      _closeModal();
      window.location.reload();
    }, 3000);
  }

  // ---------------------------------------------------------------------------
  // Trigger the update
  // ---------------------------------------------------------------------------

  function startUpdateFlow() {
    if (_isUpdating) return;

    const triggerUrl = _url("triggerUrl");
    if (!triggerUrl) return;

    const installType = (function () {
      const radios = document.querySelectorAll('input[name="install_type"]');
      for (const r of radios) {
        if (r.checked) return r.value;
      }
      return "prebuilt";
    })();

    _isUpdating = true;
    _openModal();

    const dismiss = document.getElementById("btn-close-progress-modal");
    if (dismiss) dismiss.disabled = true;

    _appendLog("Triggering update (" + _encode(installType) + ")…");
    _setProgressBar(5, "Starting…");

    fetch(triggerUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken"),
      },
      body: JSON.stringify({ install_type: installType }),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.status) {
          _isUpdating = false;
          _appendLog("Error: " + _encode(data.message || "Failed to queue update."), "text-danger");
          if (dismiss) dismiss.disabled = false;
          return;
        }
        _appendLog("Update queued. Connecting to progress stream…");
        _connectWs();
      })
      .catch(function () {
        _isUpdating = false;
        _appendLog("Network error while triggering update.", "text-danger");
        if (dismiss) dismiss.disabled = false;
      });
  }

  // ---------------------------------------------------------------------------
  // Freshly-updated banner on page load (called from admin.html)
  // ---------------------------------------------------------------------------

  function checkFreshlyUpdated() {
    const statusUrl = _url("statusUrl");
    if (!statusUrl) return;

    fetch(statusUrl)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.freshly_updated) {
          const ver = data.new_version ? (" to " + _encode(data.new_version)) : "";
          Snackbar.show({ text: "reNgine-ng updated" + ver + "!", pos: "top-right", duration: 6000 });
          // Acknowledge so the banner only appears once
          fetch(statusUrl, {
            method: "POST",
            credentials: "same-origin",
            headers: { "X-CSRFToken": getCookie("csrftoken") },
          }).catch(function () {});
        }
      })
      .catch(function () {});
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  window.RengineUpdate = {
    checkForUpdateInCard: checkForUpdateInCard,
    startUpdateFlow:      startUpdateFlow,
    checkFreshlyUpdated:  checkFreshlyUpdated,
  };
})();
