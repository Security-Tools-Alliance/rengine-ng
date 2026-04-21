"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const purePath = path.join(__dirname, "..", "..", "..", "static", "custom", "rengine_datatable_port_endpoint_pure.js");
if (!fs.existsSync(purePath)) {
  throw new Error("Expected pure helpers at " + purePath);
}

const {
  portDisplayParseStrictTcpPortString,
  rengineNormalizeEndpointDefaultsTechnologiesFallback,
  rengineIsEffectivelyEmptyHtml,
  rengineValidEndpointDefaultRows,
  rengineClassifyEndpointDefaultsByPortInput,
} = require(purePath);

test("portDisplayParseStrictTcpPortString accepts strict digit strings in range", () => {
  assert.equal(portDisplayParseStrictTcpPortString("443"), 443);
  assert.equal(portDisplayParseStrictTcpPortString("1"), 1);
  assert.equal(portDisplayParseStrictTcpPortString("65535"), 65535);
  assert.equal(portDisplayParseStrictTcpPortString(" 80 "), 80);
});

test("portDisplayParseStrictTcpPortString rejects prefixes and out-of-range", () => {
  assert.equal(portDisplayParseStrictTcpPortString("443xyz"), null);
  assert.equal(portDisplayParseStrictTcpPortString(""), null);
  assert.equal(portDisplayParseStrictTcpPortString("0"), null);
  assert.equal(portDisplayParseStrictTcpPortString("65536"), null);
  assert.equal(portDisplayParseStrictTcpPortString(null), null);
});

test("rengineNormalizeEndpointDefaultsTechnologiesFallback", () => {
  assert.deepEqual(rengineNormalizeEndpointDefaultsTechnologiesFallback([{ id: 1 }]), {
    technologies: [{ id: 1 }],
    content_type: "",
    webserver: "",
  });
  assert.deepEqual(rengineNormalizeEndpointDefaultsTechnologiesFallback({ technologies: [], x: 1 }), {
    technologies: [],
    x: 1,
  });
  assert.equal(rengineNormalizeEndpointDefaultsTechnologiesFallback(null), null);
});

test("rengineIsEffectivelyEmptyHtml", () => {
  assert.equal(rengineIsEffectivelyEmptyHtml(""), true);
  assert.equal(rengineIsEffectivelyEmptyHtml("  \n\t "), true);
  assert.equal(rengineIsEffectivelyEmptyHtml("<span>x</span>"), false);
});

test("rengineValidEndpointDefaultRows filters non-objects", () => {
  assert.deepEqual(rengineValidEndpointDefaultRows([1, null, { a: 1 }]), [{ a: 1 }]);
  assert.deepEqual(rengineValidEndpointDefaultRows("x"), []);
});

test("rengineClassifyEndpointDefaultsByPortInput branch coverage", () => {
  assert.equal(rengineClassifyEndpointDefaultsByPortInput(undefined), "missing");
  assert.equal(rengineClassifyEndpointDefaultsByPortInput(null), "missing");
  assert.equal(rengineClassifyEndpointDefaultsByPortInput({}), "invalid_type");
  assert.equal(rengineClassifyEndpointDefaultsByPortInput([]), "empty_valid_rows");
  assert.equal(rengineClassifyEndpointDefaultsByPortInput([null, 1, "x"]), "empty_valid_rows");
  assert.equal(rengineClassifyEndpointDefaultsByPortInput([{ port: 443 }]), "non_empty");
});
