(function () {
    const TUNNEL = "tunnel";
    const CLASSIC = "classic";

    const root = document.getElementById("worker-form-root");
    if (!root) {
        return;
    }

    const authType = document.getElementById(root.dataset.authTypeId || "");
    const apiAccessType = document.getElementById(root.dataset.apiAccessTypeId || "");
    const httpsPullCheckbox = document.getElementById(root.dataset.httpsPullAgentId || "");

    const intro = document.getElementById("worker-form-intro");
    const sshSection = document.getElementById("ssh-section");
    const sshLead = document.getElementById("ssh-section-lead");
    const manualNotice = document.getElementById("manual-deploy-pull-notice");
    const apiHint = document.getElementById("worker-form-api-status-hint");
    const keyRow = document.getElementById("ssh-key-row");
    const pwdRow = document.getElementById("ssh-password-row");
    const apiTunnelRow = document.getElementById("api-tunnel-row");
    const apiUrlRow = document.getElementById("api-url-row");
    const httpsPullRow = document.getElementById("https-pull-agent-row");
    const httpsPullVerifySslRow = document.getElementById("https-pull-verify-ssl-row");
    const btnCheck = document.getElementById("btn-check-connection");
    const btnInstallKey = document.getElementById("btn-install-public-key");

    const hasRequiredWorkerElements = function () {
        return !!apiAccessType;
    };

    const getWorkerFormState = function () {
        if (!hasRequiredWorkerElements()) {
            return {
                isTunnel: false,
                isClassic: false,
                pullOn: false,
                hideSsh: false,
            };
        }

        const apiMode = apiAccessType.value || "";
        const pullOn = !!(httpsPullCheckbox && httpsPullCheckbox.checked);
        return {
            isTunnel: apiMode === TUNNEL,
            isClassic: apiMode === CLASSIC,
            pullOn: pullOn,
            hideSsh: apiMode === CLASSIC && pullOn,
        };
    };

    const getCsrfToken = function () {
        const csrfInput = document.querySelector("[name=csrfmiddlewaretoken]");
        if (csrfInput && csrfInput.value) {
            return csrfInput.value;
        }
        if (document.cookie && document.cookie !== "") {
            for (const cookie of document.cookie.split(";")) {
                const [name, value] = cookie.trim().split("=");
                if (name === "csrftoken") {
                    return decodeURIComponent(value || "");
                }
            }
        }
        return "";
    };

    const toggleAuth = function () {
        if (!authType || !keyRow || !pwdRow) {
            return;
        }
        const isKey = authType.value === "key";
        keyRow.style.display = isKey ? "" : "none";
        pwdRow.style.display = isKey ? "none" : "";
    };

    const applyApiAccessRows = function (state) {
        if (!hasRequiredWorkerElements()) {
            return;
        }
        if (apiTunnelRow) {
            apiTunnelRow.style.display = state.isTunnel ? "" : "none";
        }
        if (apiUrlRow) {
            apiUrlRow.style.display = state.isTunnel ? "none" : "";
        }
        if (httpsPullRow) {
            httpsPullRow.style.display = state.isTunnel ? "none" : "";
        }
        if (httpsPullVerifySslRow) {
            httpsPullVerifySslRow.style.display = state.isClassic && state.pullOn ? "" : "none";
        }
    };

    const applySshVisibility = function (state) {
        if (sshSection) {
            sshSection.style.display = state.hideSsh ? "none" : "";
        }
        if (manualNotice) {
            manualNotice.classList.toggle("d-none", !state.hideSsh);
        }
        if (sshLead && !state.hideSsh) {
            sshLead.textContent = state.isTunnel
                ? "Required: reverse SSH tunnel from the worker to reNgine-ng. Also used to deploy and manage the container."
                : "Optional for HTTPS classic without pull agent: use Deploy / Sync / Restart on the workers list. Hidden when pull agent is enabled.";
        }
    };

    const applyIntroText = function (state) {
        if (intro) {
            if (state.hideSsh) {
                intro.textContent =
                    "Pull-agent mode: the worker calls reNgine-ng API over HTTPS for findings and scan jobs. Deploy manually using the bundle ZIP; SSH is not required.";
            } else if (state.isTunnel) {
                intro.textContent =
                    "Tunnel mode: the worker reaches reNgine-ng API through a reverse SSH tunnel. SSH is required for tunnel setup, deploy, and management.";
            } else {
                intro.textContent =
                    "Classic HTTPS: the worker uses your public API URL. Use SSH from the workers list to deploy and push updates, unless you switch to pull agent.";
            }
        }
        if (apiHint) {
            apiHint.classList.toggle("d-none", !state.hideSsh);
        }
    };

    const applyActionButtons = function (state) {
        if (btnCheck) {
            const showCheck = !state.hideSsh && (state.isTunnel || state.isClassic);
            btnCheck.style.display = showCheck ? "" : "none";
        }
        if (btnInstallKey) {
            btnInstallKey.style.display =
                !state.hideSsh && authType && authType.value === "password" ? "" : "none";
        }
    };

    const updateLayout = function () {
        if (!hasRequiredWorkerElements()) {
            return;
        }
        const state = getWorkerFormState();
        applyApiAccessRows(state);
        applySshVisibility(state);
        applyIntroText(state);
        applyActionButtons(state);
        toggleAuth();
    };

    const handleCheckConnection = function () {
        const resultDiv = document.getElementById("check-connection-result");
        if (!btnCheck || !resultDiv) {
            return;
        }

        const url = btnCheck.getAttribute("data-url");
        const csrfToken = getCsrfToken();
        btnCheck.addEventListener("click", function () {
            btnCheck.disabled = true;
            resultDiv.style.display = "block";
            resultDiv.innerHTML = '<span class="text-muted">Checking...</span>';
            fetch(url, {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "X-CSRFToken": csrfToken,
                    "Content-Type": "application/json",
                },
                body: "{}",
            })
                .then(function (r) {
                    return r.json().then(function (data) {
                        return { ok: r.ok, data: data };
                    });
                })
                .then(function (res) {
                    if (res.data.ok === true) {
                        resultDiv.innerHTML =
                            '<span class="text-success"><i class="fas fa-check-circle"></i> SSH and API checks succeeded.</span>';
                    } else {
                        resultDiv.innerHTML =
                            '<span class="text-danger"><i class="fas fa-times-circle"></i> ' +
                            (res.data.error || "Check failed.") +
                            "</span>";
                    }
                })
                .catch(function () {
                    resultDiv.innerHTML =
                        '<span class="text-danger"><i class="fas fa-times-circle"></i> Check failed.</span>';
                })
                .finally(function () {
                    btnCheck.disabled = false;
                });
        });
    };

    const handleInstallPublicKey = function () {
        const installKeyResult = document.getElementById("install-key-result");
        if (!btnInstallKey || !installKeyResult) {
            return;
        }

        const installUrl = btnInstallKey.getAttribute("data-url");
        const csrfToken = getCsrfToken();
        btnInstallKey.addEventListener("click", function () {
            btnInstallKey.disabled = true;
            installKeyResult.style.display = "block";
            installKeyResult.innerHTML = '<span class="text-muted">Installing key...</span>';
            fetch(installUrl, {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "X-CSRFToken": csrfToken,
                    "Content-Type": "application/json",
                },
                body: "{}",
            })
                .then(function (r) {
                    return r.json().then(function (data) {
                        return { ok: r.ok, data: data };
                    });
                })
                .then(function (res) {
                    if (res.data.ok === true) {
                        installKeyResult.innerHTML =
                            '<span class="text-success"><i class="fas fa-check-circle"></i> Key installed. Reloading...</span>';
                        window.location.reload();
                    } else {
                        installKeyResult.innerHTML =
                            '<span class="text-danger"><i class="fas fa-times-circle"></i> ' +
                            (res.data.error || "Install failed.") +
                            "</span>";
                        btnInstallKey.disabled = false;
                    }
                })
                .catch(function () {
                    installKeyResult.innerHTML =
                        '<span class="text-danger"><i class="fas fa-times-circle"></i> Install failed.</span>';
                    btnInstallKey.disabled = false;
                });
        });
    };

    if (authType) {
        authType.addEventListener("change", updateLayout);
    }
    if (apiAccessType) {
        apiAccessType.addEventListener("change", updateLayout);
    }
    if (httpsPullCheckbox) {
        httpsPullCheckbox.addEventListener("change", updateLayout);
    }

    updateLayout();
    handleCheckConnection();
    handleInstallPublicKey();
})();
