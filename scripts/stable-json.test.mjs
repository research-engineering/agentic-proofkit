import assert from "node:assert/strict";
import test from "node:test";

import {stableJSONStringify} from "./stable-json.mjs";

test("stableJSONStringify sorts object keys without HTML escaping", () => {
  assert.equal(
    stableJSONStringify({z: "<&>", a: [{y: "\u2028", x: 1}]}),
    `{"a":[{"x":1,"y":"\\u2028"}],"z":"<&>"}`,
  );
});

test("stableJSONStringify rejects unsupported values", () => {
  assert.throws(() => stableJSONStringify({missing: undefined}), /unsupported stable JSON value type/);
  assert.throws(() => stableJSONStringify(Number.NaN), /must be finite/);
});
