/**
 * Minimal test harness for escape helpers (safeText, safeAttr, safeLink) and normalizeSafeLinkUrl / sanitizeUrlForHref (same implementation in escape.js).
 * Run in browser console after loading escape.js:
 *   RengineDatatableEscapeHarness.run()
 * Verifies edge cases: null/undefined, malformed strings, protocol-relative URLs, blocked schemes.
 */
(function (window) {
  "use strict";

  const assert = function (condition, name, expected, actual) {
    return { pass: !!condition, name: name, expected: expected, actual: actual };
  };

  const run = function () {
    const results = [];
    const safeText = window.safeText;
    const safeAttr = window.safeAttr;
    const safeLink = window.safeLink;
    const normalizeSafeLinkUrl = window.normalizeSafeLinkUrl;

    if (typeof safeText !== "function") {
      results.push(assert(false, "safeText available", "function", typeof safeText));
    } else {
      results.push(assert(safeText(null) === "", "safeText(null)", "", safeText(null)));
      results.push(assert(safeText(undefined) === "", "safeText(undefined)", "", safeText(undefined)));
      results.push(assert(safeText("") === "", "safeText(empty string)", "", safeText("")));
      results.push(assert(safeText("<script>").indexOf("<") === -1 && safeText("<script>").indexOf("&lt;") !== -1, "safeText(angle brackets)", "escaped", safeText("<script>")));
      results.push(assert(safeText('"\'&').indexOf("&quot;") !== -1, "safeText(quotes/amp)", "escaped", safeText('"\'&')));
      results.push(assert(safeText(123) === "123", "safeText(number)", "123", safeText(123)));
    }

    if (typeof safeAttr !== "function") {
      results.push(assert(false, "safeAttr available", "function", typeof safeAttr));
    } else {
      results.push(assert(safeAttr(null) === "", "safeAttr(null)", "", safeAttr(null)));
      results.push(assert(safeAttr('"').indexOf("&quot;") !== -1, "safeAttr(double quote)", "escaped", safeAttr('"')));
      results.push(assert(safeAttr("<") === "&lt;", "safeAttr(angle)", "&lt;", safeAttr("<")));
    }

    if (typeof safeLink !== "function") {
      results.push(assert(false, "safeLink available", "function", typeof safeLink));
    } else {
      const jslink = safeLink("javascript:alert(1)", "click");
      results.push(assert(jslink.indexOf("href=\"#\"") !== -1 || jslink.indexOf("href='#'") !== -1, "safeLink(javascript: blocked)", "href=#", jslink));
      const datalink = safeLink("  data:text/html,<script>", "x");
      results.push(assert(datalink.indexOf("href=\"#\"") !== -1 || datalink.indexOf("href='#'") !== -1, "safeLink(data: blocked)", "href=#", datalink));
      const httplink = safeLink("https://example.com", "Example");
      results.push(assert(httplink.indexOf("example.com") !== -1, "safeLink(https allowed)", "contains url", httplink));
      results.push(assert(safeLink("mailto:a@b.com", "Mail").indexOf("mailto:") !== -1, "safeLink(mailto allowed)", "contains mailto", safeLink("mailto:a@b.com", "Mail")));
      results.push(assert(safeLink("", "x").indexOf("href=\"#\"") !== -1, "safeLink(empty -> #)", "href=#", safeLink("", "x")));
      const filelink = safeLink("file:///etc/passwd", "file");
      results.push(assert(filelink.indexOf("href=\"#\"") !== -1, "safeLink(file: blocked)", "href=#", filelink));
      results.push(assert(safeLink("//example.com/path", "x").indexOf("//example.com") !== -1, "safeLink(protocol-relative allowed)", "contains url", safeLink("//example.com/path", "x")));
    }

    if (typeof normalizeSafeLinkUrl === "function") {
      results.push(assert(normalizeSafeLinkUrl("https://example.com") === "https://example.com", "normalizeSafeLinkUrl(https)", "https://example.com", normalizeSafeLinkUrl("https://example.com")));
      results.push(assert(normalizeSafeLinkUrl("//example.com").indexOf("https:") === 0, "normalizeSafeLinkUrl(protocol-relative)", "https:", normalizeSafeLinkUrl("//example.com")));
      results.push(assert(normalizeSafeLinkUrl("mailto:a@b.com") === "mailto:a@b.com", "normalizeSafeLinkUrl(mailto)", "mailto:a@b.com", normalizeSafeLinkUrl("mailto:a@b.com")));
      results.push(assert(normalizeSafeLinkUrl("javascript:alert(1)") === "", "normalizeSafeLinkUrl(javascript blocked)", "", normalizeSafeLinkUrl("javascript:alert(1)")));
      results.push(assert(normalizeSafeLinkUrl(null) === "", "normalizeSafeLinkUrl(null)", "", normalizeSafeLinkUrl(null)));
      results.push(assert(normalizeSafeLinkUrl(undefined) === "", "normalizeSafeLinkUrl(undefined)", "", normalizeSafeLinkUrl(undefined)));
      const badInput = normalizeSafeLinkUrl({});
      results.push(assert(badInput === "" || (typeof badInput === "string" && badInput.length >= 0), "normalizeSafeLinkUrl(object)", "empty or string", String(badInput)));
    } else {
      results.push(assert(true, "normalizeSafeLinkUrl (skipped)", "n/a", "not loaded"));
    }

    const failed = results.filter(function (r) { return !r.pass; });
    if (typeof console !== "undefined" && console.log) {
      results.forEach(function (r) {
        if (r.pass) console.log("[PASS] " + r.name);
        else console.warn("[FAIL] " + r.name, "expected:", r.expected, "actual:", r.actual);
      });
      if (failed.length) console.warn("RengineDatatableEscapeHarness: " + failed.length + " failed");
      else console.log("RengineDatatableEscapeHarness: all " + results.length + " passed");
    }
    return { passed: results.length - failed.length, failed: failed.length, results: results };
  };

  window.RengineDatatableEscapeHarness = { run: run };
})(window);
