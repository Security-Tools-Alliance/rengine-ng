/**
 * Preview custom scan assets (GF patterns, Nuclei templates) via GetFileContents API.
 * Base URL is set by the tool settings template (window.RENGINE_API_URLS.getFileContents).
 * Uses fetch when jQuery is not available.
 */
const ALLOWED_ASSET_TYPES = Object.freeze({ gf_pattern: "gf_pattern", nuclei_template: "nuclei_template" });

const load_asset_preview = (assetType, name) => {
  const allowed = ALLOWED_ASSET_TYPES[assetType];
  if (!allowed) {
    if (typeof Swal !== "undefined") Swal.fire("Error!", "Unsupported asset type for preview.", "error", { button: "Okay" });
    else console.error("Unsupported asset type for preview:", assetType);
    return;
  }
  const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.getFileContents) || "";
  if (!baseUrl) {
    if (typeof Swal !== "undefined") Swal.fire("Error!", "Preview URL not configured.", "error", { button: "Okay" });
    else console.error("Preview URL not configured.");
    return;
  }
  const url = `${baseUrl}?${allowed}&name=${encodeURIComponent(name)}&format=json`;

  const showLoading = () => {
    if (typeof Swal !== "undefined") {
      Swal.fire({ title: `Loading ${name}...` });
      if (Swal.showLoading) Swal.showLoading();
    }
  };
  const closeLoading = () => {
    if (typeof Swal !== "undefined" && Swal.close) Swal.close();
  };
  const handleSuccess = (response) => {
    closeLoading();
    if (response.status) {
      const title = (assetType === "gf_pattern" ? "GF Pattern: " : "Nuclei Template: ") + (typeof htmlEncode === "function" ? htmlEncode(name) : name);
      const bodyHtml = `<pre>${typeof htmlEncode === "function" ? htmlEncode(response.content) : response.content}</pre>`;
      if (window.ModalManager && ModalManager.showDialog) ModalManager.showDialog({ title, bodyHtml, footerHtml: "" });
      else if (typeof Swal !== "undefined") Swal.fire({ title, html: bodyHtml });
    } else {
      if (typeof Swal !== "undefined") Swal.fire("Error!", response.message || "Failed to load.", "error", { button: "Okay" });
      else console.error(response.message || "Failed to load.");
    }
  };
  const handleError = (msg) => {
    closeLoading();
    if (typeof Swal !== "undefined") Swal.fire("Error!", msg, "error", { button: "Okay" });
    else console.error(msg);
  };

  showLoading();
  if (typeof $ !== "undefined" && $.getJSON) {
    $.getJSON(url).done(handleSuccess).fail(() => handleError("Error loading asset."));
  } else if (typeof fetch !== "undefined") {
    fetch(url, { credentials: "same-origin" })
      .then((resp) => {
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.json();
      })
      .then(handleSuccess)
      .catch(() => handleError("Error loading asset."));
  } else {
    handleError("Unable to load asset preview: neither jQuery nor fetch is available.");
  }
};
