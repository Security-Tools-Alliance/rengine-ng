/**
 * Shared helpers for command log UI: duration, status, detail rows.
 * Used by scan_status_websocket.js and detail_scan.js (create_log_element).
 */
(function(global) {
    "use strict";

    const escapeHtml = function (text) {
        if (text == null || text === "") return "";
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    };

    const parseIsoDate = function (isoString) {
        if (isoString == null || isoString === "") return null;
        const d = new Date(isoString);
        return isNaN(d.getTime()) ? null : d;
    };

    const formatRelativeTime = function (isoString) {
        const date = parseIsoDate(isoString);
        if (!date) return isoString || "";
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);
        if (diffSec < 0) return isoString;
        if (diffSec < 10) return "now";
        if (diffSec < 60) return diffSec + " seconds ago";
        if (diffSec < 120) return "a minute ago";
        if (diffMin < 60) return diffMin + " minutes ago";
        if (diffMin < 120) return "an hour ago";
        if (diffHour < 24) return diffHour + " hours ago";
        if (diffDay === 1) return "yesterday";
        if (diffDay < 7) return diffDay + " days ago";
        return isoString;
    };

    const formatDuration = function (seconds) {
        if (seconds == null || seconds < 0 || isNaN(seconds)) return "";
        if (seconds < 1) return (seconds * 1000).toFixed(0) + "ms";
        if (seconds < 60) return seconds.toFixed(1) + "s";
        const min = Math.floor(seconds / 60);
        const sec = Math.floor(seconds % 60);
        if (min < 60) return (sec > 0 ? min + "m " + sec + "s" : min + "m");
        const hour = Math.floor(min / 60);
        const m = min % 60;
        return (m > 0 ? hour + "h " + m + "m" : hour + "h");
    };

    /**
     * Derive duration in seconds from a command payload.
     * Precedence: (1) cmd.elapsed if valid number; (2) end_time - time if both present;
     * (3) now - time if only time present (running duration); (4) null otherwise.
     */
    const getDurationSeconds = function (cmd) {
        if (cmd.elapsed != null && typeof cmd.elapsed === "number" && !isNaN(cmd.elapsed)) {
            return cmd.elapsed;
        }
        const start = parseIsoDate(cmd.time);
        if (!start) return null;
        const end = parseIsoDate(cmd.end_time);
        if (end) return (end.getTime() - start.getTime()) / 1000;
        return (Date.now() - start.getTime()) / 1000;
    };

    /**
     * Return badge class and display text for a status string.
     * @returns {{ class: string, text: string }}
     */
    const getStatusBadgeInfo = function (status) {
        const s = (status || "").toUpperCase();
        if (s === "SUCCESS") return { class: "badge-soft-success", text: "SUCCESS" };
        if (s === "FAILURE" || s === "FAILED") return { class: "badge-soft-danger", text: "FAILED" };
        if (s === "RUNNING") return { class: "badge-soft-primary", text: "RUNNING" };
        if (s === "REVOKED") return { class: "badge-soft-danger", text: "ABORTED" };
        if (s === "SKIPPED") return { class: "badge-soft-info", text: "SKIPPED" };
        return { class: "badge-soft-secondary", text: s || "PENDING" };
    };

    const getEffectiveCommandStatus = function (cmd) {
        const s = cmd.status_string;
        return s != null && s !== "" ? s : cmd.status;
    };

    const findDetailRow = function (cardBody, label) {
        const blocks = cardBody.querySelectorAll(".mb-2");
        for (let i = 0; i < blocks.length; i++) {
            const strong = blocks[i].querySelector("strong");
            if (strong && strong.textContent.indexOf(label) === 0) {
                return blocks[i];
            }
        }
        return null;
    };

    const setDetailRow = function (cardBody, label, value) {
        if (value == null) return;
        const row = findDetailRow(cardBody, label);
        const valueStr = String(value);
        if (row) {
            const strong = row.querySelector("strong");
            const labelText = strong ? strong.textContent : label;
            row.innerHTML = "<strong>" + escapeHtml(labelText) + "</strong> " + escapeHtml(valueStr);
        } else {
            const div = document.createElement("div");
            div.className = "mb-2";
            div.innerHTML = "<strong>" + escapeHtml(label) + "</strong> " + escapeHtml(valueStr);
            cardBody.appendChild(div);
        }
    };

    const setReturnCodeRow = function (cardBody, returnCode) {
        if (returnCode == null) return;
        const row = findDetailRow(cardBody, "Return Code:");
        const badgeClass = returnCode === 0 ? "badge-soft-success" : "badge-soft-danger";
        const html =
            "<strong>Return Code:</strong> <span class=\"badge " +
            badgeClass +
            "\">" +
            escapeHtml(String(returnCode)) +
            "</span>";
        if (row) {
            row.innerHTML = html;
        } else {
            const div = document.createElement("div");
            div.className = "mb-2";
            div.innerHTML = html;
            cardBody.appendChild(div);
        }
    };

    const setDurationRow = function (cardBody, durationStr) {
        if (durationStr == null || durationStr === "") return;
        const row = findDetailRow(cardBody, "Duration:");
        const html = "<strong>Duration:</strong> " + escapeHtml(durationStr);
        if (row) {
            row.innerHTML = html;
        } else {
            const endTimeRow = findDetailRow(cardBody, "End Time:");
            const div = document.createElement("div");
            div.className = "mb-2";
            div.innerHTML = html;
            if (endTimeRow && endTimeRow.nextSibling) {
                cardBody.insertBefore(div, endTimeRow.nextSibling);
            } else {
                cardBody.appendChild(div);
            }
        }
    };

    const CommandLogHelpers = {
        escapeHtml,
        parseIsoDate,
        formatRelativeTime,
        formatDuration,
        getDurationSeconds,
        getStatusBadgeInfo,
        getEffectiveCommandStatus,
        findDetailRow,
        setDetailRow,
        setReturnCodeRow,
        setDurationRow,
    };

    global.CommandLogHelpers = CommandLogHelpers;
})(typeof window !== "undefined" ? window : this);
