/**
 * Central namespace for window keys used with one-shot console warnings.
 * Load before `rengine_datatable_port_endpoint_pure.js`, `port_display.js`, and
 * `datatables/renderers_subdomain_endpoint.js` (see `base.html`).
 * Add new keys here with a unique prefix; read from `RENGINE_CONSOLE_WARN_KEYS` in each module.
 */
var RENGINE_CONSOLE_WARN_KEYS = {
    portDisplay: {
        missingServicesForRequestPort: "__rengineWarnOnce_portDisplay_missingServicesForRequestPort",
        malformedUrlModalIp: "__rengineWarnOnce_portDisplay_malformedUrlModalIp",
        malformedUrlModalSubdomainHttpUrl: "__rengineWarnOnce_portDisplay_malformedUrlModalSubHttpUrl",
        malformedUrlNameColumn: "__rengineWarnOnce_portDisplay_malformedUrlNameColumn"
    },
    rendererEndpoint: {
        missingEndpointDefaultsByPort: "__rengineWarnOnce_rendererEndpoint_missingEdbp",
        invalidEndpointDefaultsByPort: "__rengineWarnOnce_rendererEndpoint_invalidEdbp"
    }
};
