/**
 * Cookie helpers for DataTables (e.g. row group selection persistence).
 */
(function (window) {
  "use strict";

  const getRengineCookie = function (name) {
    const doc = typeof document !== "undefined" ? document : null;
    if (!doc || !doc.cookie) return null;
    const parts = doc.cookie.split(";");
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i].trim();
      const eq = part.indexOf("=");
      if (eq > 0 && part.substring(0, eq).trim() === name) {
        return decodeURIComponent(part.substring(eq + 1).trim());
      }
    }
    return null;
  };

  const setRengineCookie = function (name, value) {
    const doc = typeof document !== "undefined" ? document : null;
    if (!doc) return;
    const maxAge = 365 * 24 * 60 * 60;
    doc.cookie = name + "=" + encodeURIComponent(value) + "; path=/; max-age=" + maxAge + "; SameSite=Lax";
  };

  window.getRengineCookie = getRengineCookie;
  window.setRengineCookie = setRengineCookie;
})(window);
