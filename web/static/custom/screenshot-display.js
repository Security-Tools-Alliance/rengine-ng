/**
 * Centralized screenshot display helper.
 * All screenshot images use screenshot_url from the API (served via Django ServeScanFile); no direct file paths.
 */
(function () {
    let documentErrorHandlerAttached = false;

    /** Data attribute names (suffix after "data-") for thumbnail img; use when building HTML or reading .data(). */
    const THUMBNAIL_DATA_ATTRS = Object.freeze({
        SCREENSHOT_URL: 'screenshot-url',
        HTTP_URL: 'http-url',
        SUBDOMAIN_ID: 'subdomain-id',
        SUBDOMAIN_NAME: 'subdomain-name',
        PORT: 'port',
        SCAN_ID: 'scan-id',
        DOMAIN_ID: 'domain-id',
        DISABLE_HOVER: 'disable-hover',
    });

    /** Delegate call signature: (subdomainId, subdomainName, port, scanId, domainId, screenshotUrl, httpUrl). */
    const THUMBNAIL_CLICK_DELEGATE_ARG_ORDER = Object.freeze([
        'subdomainId', 'subdomainName', 'port', 'scanId', 'domainId', 'screenshotUrl', 'httpUrl',
    ]);

    const attachThumbnailErrorHandlerOnce = () => {
        if (documentErrorHandlerAttached) return;
        documentErrorHandlerAttached = true;
        document.addEventListener(
            "error",
            (e) => {
                const el = e.target;
                if (
                    el &&
                    el.nodeName === "IMG" &&
                    el.classList &&
                    el.classList.contains("screenshot-thumbnail")
                ) {
                    el.style.display = "none";
                }
            },
            true
        );
    };

    /** Escape string for safe use in double-quoted HTML attribute values (XSS-safe). */
    const escapeAttr = (s) => {
        if (s == null || s === '') return '';
        const str = String(s);
        return str
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    };

    window.ScreenshotDisplay = {
        /**
         * Build HTML for a screenshot thumbnail img. Uses only screenshotUrl (from API).
         * Thumbnail appearance is defined by the .screenshot-thumbnail class in CSS (e.g. custom.css).
         * @param {Object} options - screenshotUrl, httpUrl, subdomainId, subdomainName, port, scanId, domainId, disableHover, imageId (optional), className, style (optional override)
         *   When imageId is provided it is used as the img id for stable IDs (debugging, test hooks); otherwise a random id is generated.
         * @returns {string} HTML string for the img element
         */
        buildThumbnailHtml(options) {
            const {
                screenshotUrl = '',
                httpUrl = '',
                subdomainId = '',
                subdomainName = '',
                port = '',
                scanId = '',
                domainId = '',
                disableHover = false,
                imageId: providedImageId,
                className = 'screenshot-thumbnail',
                style = '',
            } = options;
            const imageId =
                (providedImageId !== undefined && providedImageId !== null && providedImageId !== '')
                    ? String(providedImageId)
                    : `screenshot-${Math.random().toString(36).substr(2, 9)}`;
            if (!screenshotUrl) return '';
            const styleAttr = style ? ` style="${escapeAttr(style)}"` : '';
            const a = THUMBNAIL_DATA_ATTRS;
            return `<img id="${escapeAttr(imageId)}"
                src="${escapeAttr(screenshotUrl)}"
                class="${escapeAttr(className)}"${styleAttr}
                data-${a.SCREENSHOT_URL}="${escapeAttr(screenshotUrl)}"
                data-${a.HTTP_URL}="${escapeAttr(httpUrl)}"
                data-${a.SUBDOMAIN_ID}="${escapeAttr(String(subdomainId))}"
                data-${a.SUBDOMAIN_NAME}="${escapeAttr(subdomainName)}"
                data-${a.PORT}="${escapeAttr(String(port))}"
                data-${a.SCAN_ID}="${escapeAttr(String(scanId))}"
                data-${a.DOMAIN_ID}="${escapeAttr(String(domainId))}"
                data-${a.DISABLE_HOVER}="${disableHover ? 'true' : 'false'}"
                title="Click to view full screenshot">`;
        },

        _createPreviewElement(screenshotUrl, httpUrl) {
            const src = screenshotUrl || '';
            const preview = $('<div id="screenshot-preview" class="screenshot-preview"></div>');
            const $urlDiv = $('<div class="screenshot-preview-url"></div>').text(httpUrl || '');
            const $img = $('<img class="screenshot-preview-img">').attr('src', src).on('error', function () {
                $(this).parent().hide();
            });
            return preview.append($urlDiv).append($img);
        },

        showPreview(element, screenshotUrl, httpUrl) {
            this.hidePreview();
            const $element = $(element);
            const elementOffset = $element.offset();
            const elementWidth = $element.outerWidth();
            const elementHeight = $element.outerHeight();
            const previewWidth = 600;
            const previewHeight = 400;
            const isInTable = $element.closest('table').length > 0;
            const isInModal = $element.closest('#modal_content_subdomain').length > 0;
            let preview;
            let parentContainer;

            if (isInTable && isInModal) {
                const modalContent = $('#modal_content_subdomain').closest('.modal-content');
                parentContainer = modalContent;
                if (modalContent.css('position') === 'static') modalContent.css('position', 'relative');
                preview = this._createPreviewElement(screenshotUrl, httpUrl).css('position', 'absolute');
                parentContainer.append(preview);
                const modalContentOffset = modalContent.offset();
                let leftPos = elementOffset.left - modalContentOffset.left - previewWidth - 10;
                let topPos = elementOffset.top - modalContentOffset.top - (previewHeight / 2) + (elementHeight / 2);
                const modalWidth = modalContent.outerWidth();
                const modalHeight = modalContent.outerHeight();
                if (leftPos < 10) leftPos = elementOffset.left - modalContentOffset.left + elementWidth + 10;
                if (leftPos + previewWidth > modalWidth - 10) leftPos = modalWidth - previewWidth - 10;
                if (topPos < 10) topPos = 10;
                else if (topPos + previewHeight > modalHeight - 10) topPos = modalHeight - previewHeight - 10;
                preview.css({ left: leftPos, top: topPos });
            } else {
                parentContainer = $('body');
                preview = this._createPreviewElement(screenshotUrl, httpUrl).css('position', 'fixed');
                parentContainer.append(preview);
                if (isInTable) {
                    const rect = element.getBoundingClientRect();
                    const windowWidth = $(window).width();
                    const windowHeight = $(window).height();
                    let leftPos = rect.left - previewWidth - 10;
                    let topPos = rect.top + (rect.height / 2) - (previewHeight / 2);
                    if (leftPos < 10) leftPos = rect.right + 10;
                    if (leftPos + previewWidth > windowWidth - 10) leftPos = Math.max(10, windowWidth - previewWidth - 10);
                    if (topPos < 10) topPos = 10;
                    else if (topPos + previewHeight > windowHeight - 10) topPos = windowHeight - previewHeight - 10;
                    preview.css({ left: leftPos, top: topPos });
                } else {
                    let leftPos = elementOffset.left - previewWidth - 10;
                    let topPos = elementOffset.top - (previewHeight / 2) + (elementHeight / 2);
                    if (leftPos < 10) leftPos = elementOffset.left + elementWidth + 10;
                    preview.css({ left: leftPos, top: topPos });
                }
            }
        },

        hidePreview() {
            $('#screenshot-preview').remove();
            $('.screenshot-thumbnail').off('mousemove.screenshot-preview');
        },

        showModal(screenshotUrl, httpUrl = '') {
            const src = screenshotUrl || '';
            try {
                $('#xl-modal-title').empty();
                $('#xl-modal-content').empty();
                $('#xl-modal-footer').empty();
                const $content = $('<div class="mb-4 text-center"></div>');
                if (httpUrl) {
                    const $link = $('<a></a>').attr('href', httpUrl).attr('target', '_blank').attr('rel', 'noopener noreferrer').addClass('text-primary').text(httpUrl);
                    $content.append($('<div class="mb-2 screenshot-modal-link"></div>').append($link));
                }
                const $img = $('<img>').addClass('img-fluid rounded screenshot-popup screenshot-modal-img').attr('src', src).on('click', function () { window.open(src, '_blank'); });
                $content.append($('<div class="d-flex justify-content-center"></div>').append($img));
                $('#xl-modal-title').html('Screenshot');
                $('#xl-modal-content').html($content);
                if (window.ModalManager) window.ModalManager.showXlOnly();
            } catch (e) {
                console.error('Error showing screenshot modal:', e);
                if (src) window.open(src, '_blank');
            }
        },

        /**
         * Optional delegate for thumbnail click when port-level screenshot modal is available.
         * Signature: (subdomainId, subdomainName, port, scanId, domainId, screenshotUrl, httpUrl) - see THUMBNAIL_CLICK_DELEGATE_ARG_ORDER.
         */
        thumbnailClickDelegate: null,

        /** Data attribute names for thumbnail img; use for building HTML or reading .data(). */
        THUMBNAIL_DATA_ATTRS,

        /** Argument order for thumbnail click delegate: subdomainId, subdomainName, port, scanId, domainId, screenshotUrl, httpUrl. */
        THUMBNAIL_CLICK_DELEGATE_ARG_ORDER,

        /**
         * Attach event delegation for .screenshot-thumbnail inside containerSelector.
         * Click: use injected delegate, or global show_port_screenshots, or single-image modal; hover: show/hide preview.
         * Image load error: one document-level capturing listener hides broken thumbnails (attached once).
         * @param {string} containerSelector - jQuery selector for the container
         * @param {Object} [options] - optional: { onThumbnailClick: (subdomainId, subdomainName, port, scanId, domainId, screenshotUrl, httpUrl) => void }
         */
        attachDelegation(containerSelector, options = {}) {
            attachThumbnailErrorHandlerOnce();
            const $container = $(containerSelector);
            if (!$container.length) return;

            const openPortScreenshots =
                typeof options.onThumbnailClick === 'function'
                    ? options.onThumbnailClick
                    : typeof window.ScreenshotDisplay.thumbnailClickDelegate === 'function'
                      ? window.ScreenshotDisplay.thumbnailClickDelegate
                      : typeof window.show_port_screenshots === 'function'
                        ? window.show_port_screenshots
                        : null;

            const a = THUMBNAIL_DATA_ATTRS;
            $container.off('click.screenshot').on('click.screenshot', '.screenshot-thumbnail', function () {
                const subdomainId = parseInt($(this).data(a.SUBDOMAIN_ID), 10) || null;
                const subdomainName = $(this).data(a.SUBDOMAIN_NAME);
                const port = parseInt($(this).data(a.PORT), 10) || null;
                const scanId = parseInt($(this).data(a.SCAN_ID), 10) || null;
                const domainId = parseInt($(this).data(a.DOMAIN_ID), 10) || null;
                const screenshotUrl = $(this).data(a.SCREENSHOT_URL) || '';
                const httpUrl = $(this).data(a.HTTP_URL) || '';
                if (openPortScreenshots) {
                    openPortScreenshots(subdomainId, subdomainName, port, scanId, domainId, screenshotUrl, httpUrl);
                } else {
                    window.ScreenshotDisplay.showModal(screenshotUrl, httpUrl);
                }
            });
            $container.off('mouseenter.screenshot').on('mouseenter.screenshot', `.screenshot-thumbnail:not([data-${a.DISABLE_HOVER}="true"])`, function () {
                window.ScreenshotDisplay.showPreview(this, $(this).data(a.SCREENSHOT_URL), $(this).data(a.HTTP_URL));
            });
            $container.off('mouseleave.screenshot').on('mouseleave.screenshot', `.screenshot-thumbnail:not([data-${a.DISABLE_HOVER}="true"])`, function () {
                window.ScreenshotDisplay.hidePreview();
            });
        },
    };

    // Global aliases for backward compatibility
    window.showScreenshotPreview = function (element, screenshotUrl, httpUrl) {
        window.ScreenshotDisplay.showPreview(element, screenshotUrl, httpUrl);
    };
    window.hideScreenshotPreview = function () {
        window.ScreenshotDisplay.hidePreview();
    };
    window.showScreenshotImageModal = function (screenshotUrl, httpUrl) {
        window.ScreenshotDisplay.showModal(screenshotUrl, httpUrl);
    };
})();
