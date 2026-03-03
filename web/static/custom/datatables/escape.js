/**
 * Escaping helpers for DataTables renderers and dynamic HTML.
 *
 * Must be loaded before any other DataTables helper or inline renderer code.
 * Scripts that depend on safeLink, sanitizeUrlForHref, or normalizeSafeLinkUrl can assert
 * load order by checking window.__rengineEscapeLoaded === true before building links.
 *
 * Usage:
 * - Displayed text content (inside elements): use safeText(value).
 * - HTML attribute values (title, href, data-*, etc.): use safeAttr(value).
 * - Badge with optional icon: use safeBadge(displayText, badgeClass, iconClass).
 * - Safe link: use safeLink(href, displayText, options) for <a href="...">...</a>.
 * - URL for href (before building a link): use sanitizeUrlForHref(url) or normalizeSafeLinkUrl(url). Same logic; do not reimplement elsewhere.
 * - Tooltip title attribute: use safeAttr(value) or safeTooltipTitle(value) for title="...".
 *
 * URL sanitization (security-critical, single source of truth):
 * - Allowed schemes: http, https, mailto. Protocol-relative (//host) and relative paths (no scheme) allowed.
 * - Rejected: javascript:, data:, vbscript:, file:, and any other scheme. Non-string/non-number input returns "".
 * - Do not add ad-hoc URL checks in other files; extend this module only.
 */
(function (window) {
  "use strict";

  /**
   * Encode for safe insertion into HTML text content. Escapes &, <, >, ", ' (minimal set
   * to prevent XSS). For attribute values use safeAttr/escapeAttr.
   */
  const htmlEncode = function (str) {
    const s = String(str == null ? "" : str);
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  };

  const escapeAttr = function (s) {
    if (s == null) return "";
    const str = String(s);
    return str
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  };

  const safeText = function (value) {
    return htmlEncode(value == null ? "" : value);
  };

  const safeAttr = function (value) {
    return escapeAttr(value);
  };

  /** Alias for safeAttr for tooltip title attributes. Use for title="..." in badges and links. */
  const safeTooltipTitle = function (value) {
    return escapeAttr(value == null ? "" : value);
  };

  /**
   * Returns a badge span with optional icon. Use for consistent encoding of badge content and attributes.
   * @param {string} displayText - Text inside the badge (encoded as text).
   * @param {string} [badgeClass] - CSS class for the span (e.g. "badge badge-soft-secondary").
   * @param {string} [iconClass] - Optional icon class (e.g. "fe-briefcase"); if set, adds <i class="... me-1"></i> before text.
   * @returns {string} HTML string for the badge span.
   */
  const safeBadge = function (displayText, badgeClass, iconClass) {
    const cls = badgeClass != null && badgeClass !== "" ? escapeAttr(badgeClass) : "";
    const icon = iconClass != null && iconClass !== "" ? "<i class=\"" + escapeAttr(iconClass) + " me-1\"></i>" : "";
    const text = htmlEncode(displayText == null ? "" : displayText);
    return "<span class=\"" + cls + "\">" + icon + text + "</span>";
  };

  /**
   * Badge span with tooltip (title attribute). Use for badges that need a title for bs-tooltip.
   * @param {string} title - Tooltip text (encoded for title attribute).
   * @param {string} displayText - Text inside the badge (encoded as text).
   * @param {string} [badgeClass] - Full CSS class (e.g. "m-1 badge badge-soft-primary bs-tooltip").
   * @param {string} [iconClass] - Optional icon class; if set, adds <i class="... me-1"></i> before text.
   * @param {string} [extraInnerHtml] - Optional safe HTML appended after text (e.g. inner badge); must be built from safe helpers.
   * @returns {string} HTML string for the badge span.
   */
  const safeBadgeWithTooltip = function (title, displayText, badgeClass, iconClass, extraInnerHtml) {
    const titleAttr = title != null && title !== "" ? " title=\"" + escapeAttr(title) + "\"" : "";
    const cls = badgeClass != null && badgeClass !== "" ? escapeAttr(badgeClass) : "";
    const icon = iconClass != null && iconClass !== "" ? "<i class=\"" + escapeAttr(iconClass) + " me-1\"></i>" : "";
    const text = htmlEncode(displayText == null ? "" : displayText);
    const extra = extraInnerHtml != null ? extraInnerHtml : "";
    return "<span class=\"" + cls + "\"" + titleAttr + ">" + icon + text + extra + "</span>";
  };

  /**
   * Allowed URL schemes for href sanitization (single source of truth; do not duplicate in other files).
   * - Leading whitespace before the scheme is ignored.
   * - Relative URLs (no scheme) and fragment-only (#...) are allowed.
   * - Protocol-relative URLs (//host/...) are normalized to https:.
   * - Only an explicit allowlist of schemes is permitted: http, https, mailto.
   */
  const HAS_SCHEME = /^\s*[a-zA-Z][a-zA-Z0-9+.-]*:/;
  const ALLOWED_SCHEME_OR_PROTOCOL_RELATIVE = /^\s*(https?|mailto):/i;
  const PROTOCOL_RELATIVE = /^\s*\/\//;

  /**
   * Single source of truth for URL sanitization before use in href or safeLink.
   * Non-string/non-number input: returns "" (and logs a warning in dev). Strips HTML tags and normalizes whitespace.
   * Allowed: http, https, mailto; protocol-relative (//) normalized to https:; relative paths and # kept.
   * mailto: is normalized: query string (?) stripped; address part must not contain spaces or single/double quotes (rejected otherwise).
   * Rejected: javascript:, data:, vbscript:, file:, or any other scheme (returns "").
   * Do not reimplement this logic elsewhere; extending link rendering must go through this function.
   *
   * @param {*} url - URL string, number (coerced to string), or other (returns "").
   * @returns {string} Sanitized URL string, or "" if disallowed or invalid input.
   */
  const sanitizeUrlForHref = function (url) {
    if (url != null && typeof url !== "string" && typeof url !== "number") {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("sanitizeUrlForHref: expected string or number; got", typeof url);
      }
      return "";
    }
    let raw = String(url == null ? "" : url)
      .replace(/<[^>]*>/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (!raw) return "";
    if (HAS_SCHEME.test(raw)) {
      if (/^\s*(javascript|data|vbscript|file):/i.test(raw)) return "";

      if (/^\s*mailto:/i.test(raw)) {
        let mailtoBody = raw.replace(/^\s*mailto:/i, "");
        const qIndex = mailtoBody.indexOf("?");
        if (qIndex !== -1) mailtoBody = mailtoBody.slice(0, qIndex);
        mailtoBody = mailtoBody.trim();
        if (!mailtoBody || /[\s"']/.test(mailtoBody)) return "";
        return "mailto:" + mailtoBody;
      }

      if (ALLOWED_SCHEME_OR_PROTOCOL_RELATIVE.test(raw)) return raw;
      if (PROTOCOL_RELATIVE.test(raw)) return "https:" + raw;
      return "";
    }
    if (raw.indexOf("//") === 0) return "https:" + raw;
    if (raw.charAt(0) === "/") return raw;
    if (raw.charAt(0) === "#") return raw;
    return "https://" + raw;
  };

  /**
   * Returns a safe <a href="...">...</a> string. Encodes href and display text.
   * Security: href is sanitized via sanitizeUrlForHref (allowlist: http, https, mailto; protocol-relative and relative allowed).
   * Any other scheme is replaced with '#'.
   * @param {string} href - URL for the link (sanitized; disallowed schemes become '#').
   * @param {string} displayText - Link text (encoded via safeText).
   * @param {object} [options] - Optional. target: '_blank', rel: 'noopener', className: '...', title: '...'.
   * @returns {string} HTML string for the anchor.
   */
  const safeLink = function (href, displayText, options) {
    const opts = options || {};
    const sanitized = sanitizeUrlForHref(href);
    const safeHref = (sanitized === "" ? "#" : sanitized);
    let attrs = "href=\"" + escapeAttr(safeHref) + "\"";
    if (opts.target) attrs += " target=\"" + escapeAttr(opts.target) + "\"";
    if (opts.rel) attrs += " rel=\"" + escapeAttr(opts.rel) + "\"";
    if (opts.className) attrs += " class=\"" + escapeAttr(opts.className) + "\"";
    if (opts.title != null && opts.title !== "") attrs += " title=\"" + escapeAttr(opts.title) + "\"";
    const text = htmlEncode(displayText == null ? "" : displayText);
    return "<a " + attrs + ">" + text + "</a>";
  };

  window.htmlEncode = htmlEncode;
  window.escapeAttr = escapeAttr;
  window.htmlEncodeForRenderers = htmlEncode;
  window.safeText = safeText;
  window.safeAttr = safeAttr;
  window.safeTooltipTitle = safeTooltipTitle;
  window.safeBadge = safeBadge;
  window.safeBadgeWithTooltip = safeBadgeWithTooltip;
  window.safeLink = safeLink;
  window.sanitizeUrlForHref = sanitizeUrlForHref;
  window.normalizeSafeLinkUrl = sanitizeUrlForHref;
  window.__rengineEscapeLoaded = true;
})(window);

