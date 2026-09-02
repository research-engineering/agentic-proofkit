import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";

import {
  createUTF8StrictStreamDecoder,
  decodeUTF8Strict,
  isUnsafeScalar,
  redactDiagnosticValue,
  stableJSONStringify,
} from "./stable-json.mjs";

const unicodePolicyCorpus = JSON.parse(readFileSync(
  new URL("../internal/kernel/unicodepolicy/testdata/unsafe-scalar-ranges.v1.json", import.meta.url),
  "utf8",
));

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

test("stableJSONStringify escapes unsafe scalars and preserves scalar key order", () => {
  assert.equal(
    stableJSONStringify({value: "\u007f\u0085\u200b\u2028\u2029\u{e0001}", "\u{10000}": "supplementary", "\ue000": "bmp"}),
    `{"value":"\\u007f\\u0085\\u200b\\u2028\\u2029\\udb40\\udc01","\ue000":"bmp","\u{10000}":"supplementary"}`,
  );
});

test("stable JSON Unicode corpus", () => {
  const cases = [
    ["alpha", `{"value":"alpha"}`],
    ["<&>", `{"value":"<&>"}`],
    ["\u{1f600}", `{"value":"\u{1f600}"}`],
    ["e\u0301", `{"value":"e\u0301"}`],
    ["\b\t\n\f\r", `{"value":"\\b\\t\\n\\f\\r"}`],
    ["\0", `{"value":"\\u0000"}`],
    ["\u007f", `{"value":"\\u007f"}`],
    ["\u0085", `{"value":"\\u0085"}`],
    ["\u200b", `{"value":"\\u200b"}`],
    ["\u{e0001}", `{"value":"\\udb40\\udc01"}`],
    ["\u2028", `{"value":"\\u2028"}`],
    ["\u2029", `{"value":"\\u2029"}`],
  ];
  for (const [value, expected] of cases) {
    const encoded = stableJSONStringify({value});
    assert.equal(encoded, expected);
    assert.equal(JSON.parse(encoded).value, value);
  }
  assert.equal(stableJSONStringify({"\u200b": "value"}), `{"\\u200b":"value"}`);
  assert.equal(
    stableJSONStringify({"\u{10000}": "supplementary", "\ue000": "bmp"}),
    `{"\ue000":"bmp","\u{10000}":"supplementary"}`,
  );
});

test("stable JSON Unicode table classifies every scalar and complement", () => {
  assert.equal(unicodePolicyCorpus.schemaVersion, 1);
  assert.equal(unicodePolicyCorpus.unicodeVersion, "17.0.0");
  const ranges = unicodePolicyCorpus.ranges.map(({start, end, step}) => [start, end, step]);
  const expected = new Set();
  for (const [start, end, step] of ranges) {
    for (let value = start; value <= end; value += step) expected.add(value);
  }
  for (let value = 0; value <= 0x10ffff; value += 1) {
    if (value >= 0xd800 && value <= 0xdfff) continue;
    assert.equal(isUnsafeScalar(value), expected.has(value), `U+${value.toString(16).padStart(4, "0")}`);
  }
});

test("stableJSONStringify rejects every unpaired surrogate class", () => {
  for (const value of ["\ud800", "\udc00", "\ud800a"]) {
    assert.throws(() => stableJSONStringify({value}), /Unicode scalar values/);
    assert.throws(() => stableJSONStringify({[value]: "key"}), /Unicode scalar values/);
  }
});

test("stableJSONStringify rejects every unpaired surrogate code unit in keys and values", () => {
  for (let unit = 0xd800; unit <= 0xdfff; unit += 1) {
    const value = String.fromCharCode(unit);
    assert.throws(() => stableJSONStringify({value}), /Unicode scalar values/);
    assert.throws(() => stableJSONStringify({[value]: "key"}), /Unicode scalar values/);
  }
});

test("stableJSONStringify admits every valid UTF-16 surrogate pair in keys and values", () => {
  for (let high = 0xd800; high <= 0xdbff; high += 1) {
    for (let low = 0xdc00; low <= 0xdfff; low += 1) {
      const value = String.fromCharCode(high, low);
      stableJSONStringify({value});
      stableJSONStringify({[value]: "key"});
    }
  }
});

test("diagnostic whole-value redaction", () => {
  const fixed = "<redacted-diagnostic-value>";
  const families = [
    ["authorization_header", ["request failed: Authorization: Basic ", "YWxpY2U6c2VjcmV0"].join("")],
    ["bearer_token", ["Bearer ", "abcdefghijklmnopqrstuvwxyz"].join("")],
    ["api_key_label", ["api", "_key=", "abc123456789"].join("")],
    ["access_token_label", ["access", "-token=", "abcdefghijklmnopqrstuvwxyz"].join("")],
    ["password_label", ["pass", "wd=", "abcdefghijklmnopqrstuvwxyz"].join("")],
    ["github_pat", ["github", "_pat_", "abcdefghijklmnopqrstuvwxyz"].join("")],
    ["github_ghp", ["gh", "p_", "123456789012345678901234567890123456"].join("")],
    ["openai_key", ["sk", "-proj-", "abcdefghijklmnop"].join("")],
    ["slack_token", ["xox", "b-", "1234567890-", "abcdefghijklmnop"].join("")],
    ["gitlab_token", ["gl", "pat-", "abcdefghijklmnop"].join("")],
    ["url_credentials", ["https://user:", "password", "@example.test/repo.git"].join("")],
    ["private_key_header", ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].join("")],
    ["jwt_like", ["eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjMifQ", ".", "signature"].join("")],
  ];
  const separators = ["\0", "\u007f", "\u0085", "\u200b", "\u{e0001}", "\u2028", "\u2029"];
  for (const [name, secret] of families) {
    const wrapped = `prefix ${secret} suffix`;
    assert.equal(redactDiagnosticValue(wrapped), fixed, `${name} contiguous`);
    for (const separator of separators) {
      for (const offset of [Math.floor(wrapped.length / 3), Math.floor(wrapped.length / 2), Math.floor(wrapped.length * 2 / 3)]) {
        assert.equal(redactDiagnosticValue(wrapped.slice(0, offset) + separator + wrapped.slice(offset)), fixed, `${name} split`);
      }
    }
  }
  assert.equal(redactDiagnosticValue("safe diagnostic"), "safe diagnostic");
  assert.equal(redactDiagnosticValue("x".repeat(520)), "x".repeat(512) + "...<truncated-diagnostic>");
  assert.equal(redactDiagnosticValue("\ud800"), fixed);
});

test("decodeUTF8Strict rejects malformed bytes without exposing them", () => {
  assert.equal(decodeUTF8Strict(Buffer.from("valid"), "fixture"), "valid");
  assert.throws(
    () => decodeUTF8Strict(Buffer.from([0x67, 0x68, 0x70, 0x5f, 0xff]), "fixture"),
    (error) => error.message === "fixture is not valid UTF-8" && !error.message.includes("ghp_"),
  );
});

test("createUTF8StrictStreamDecoder preserves split scalars and rejects malformed tails", () => {
  const valid = createUTF8StrictStreamDecoder("stream fixture");
  assert.equal(valid.write(Buffer.from([0xf0, 0x9f])), "");
  assert.equal(valid.write(Buffer.from([0x98, 0x80])), "\u{1f600}");
  assert.equal(valid.finish(), "");

  const malformed = createUTF8StrictStreamDecoder("stream fixture");
  assert.equal(malformed.write(Buffer.from([0x67, 0x68, 0x70, 0x5f, 0xc3])), "ghp_");
  assert.throws(
    () => malformed.finish(),
    (error) => error.message === "stream fixture is not valid UTF-8" && !error.message.includes("ghp_"),
  );
});
