import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_BOOTSTRAP_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const baseline = JSON.parse(readFileSync(new URL("internal/app/testdata/bootstrap-native-observations.json", root), "utf8"));
assert.equal(baseline.head, "a669af21ac94eb9de3d68b4f76906bf193dd855b");
assert.equal(baseline.observations.length, 22);
const definitions = ["input", "output"].map(direction => contract.contractDefinitions.find(x => x.definitionId === `proofkit.self-check.${direction}.v1.json-schema`));
assert.ok(definitions.every(Boolean), "both bootstrap structural owners exist");
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const [inputValid, outputValid] = definitions.map(x => ajv.compile(x.fieldTree.variants[0].schema));
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-bootstrap-")); binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120000, env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });
const hash = text => createHash("sha256").update(text).digest("hex");
function invoke(inputJSON, args = []) {
  const r = spawnSync(binary, ["self-check", "--input", "-", ...args], {input: inputJSON, encoding: "utf8", timeout: 10000, maxBuffer: 1 << 20});
  assert.equal(r.error, undefined); assert.equal(r.signal, null); return r;
}
function expected(kind) {
  return {
    diagnostics: [{key: "inputKind", value: kind}],
    nonClaims: ["Go self-check does not replace the full package gate.", "Go self-check does not execute native witnesses, read repository state, approve merge, or publish artifacts."],
    reportId: "proofkit.go-runtime.self-check", reportKind: "proofkit.go-runtime.self-check",
    ruleResults: [{diagnostics: [], message: "Go bootstrap runtime parsed explicit JSON input and emitted a deterministic report.", ruleId: "proofkit.go-runtime.self-check.explicit-input", status: "passed"}],
    schemaVersion: 1, state: "passed", summary: {inputKind: kind},
  };
}
const kinds = {object: "object", "arbitrary-version": "object", array: "array", "nested-array": "array", null: "null", true: "boolean", false: "boolean", string: "string", "empty-string": "string", integer: "number", negative: "number", fraction: "number", exponent: "number", "large-integer": "number", "large-exponent": "number"};

test("bootstrap arbitrary JSON roots preserve exact predecessor streams and independent meaning", () => {
  assert.equal(definitions[0].rootType, "json_value");
  const variant = definitions[0].fieldTree.variants[0];
  assert.equal(variant.rootKind, "json_value");
  assert.deepEqual(variant.allowedFields, []); assert.deepEqual(variant.requiredFields, []);
  for (const row of baseline.observations) {
    const r = invoke(row.inputJSON, row.args);
    assert.equal(r.status, row.exitCode, row.name);
    assert.equal(hash(r.stdout), row.stdoutSHA256, `${row.name}/stdout`);
    assert.equal(hash(r.stderr), row.stderrSHA256, `${row.name}/stderr`);
    if (Object.hasOwn(kinds, row.name)) {
      assert.equal(r.status, 0); assert.equal(r.stderr, "");
      // Original number lexemes reach the CLI unchanged; JS parsing is used only
      // for the unconstrained schema, not numeric value/precision evidence.
      assert.equal(inputValid(JSON.parse(row.inputJSON)), true, `${row.name}/input`);
      const value = JSON.parse(r.stdout);
      assert.deepEqual(value, expected(kinds[row.name]), `${row.name}/meaning`);
      assert.equal(outputValid(value), true, `${row.name}/output`);
    } else {
      assert.equal(r.status, 1); assert.equal(r.stdout, ""); assert.notEqual(r.stderr, "");
    }
  }
});

test("bootstrap schemaVersion is arbitrary input data and caller values remain undisclosed", () => {
  for (const schemaVersion of [null, false, 0, 2, "future", [], {x: 1}]) {
    const input = {schemaVersion, extra: {nested: [false, null, "text"]}};
    assert.equal(inputValid(input), true, "arbitrary schemaVersion input");
    const r = invoke(JSON.stringify(input)); assert.equal(r.status, 0); assert.equal(r.stderr, "");
    assert.deepEqual(JSON.parse(r.stdout), expected("object"));
  }
  const sensitive = ["api_", "key=", "synthetic-fixture-only"].join("");
  const r = invoke(JSON.stringify(sensitive)); assert.equal(r.status, 0); assert.equal(r.stderr, "");
  assert.deepEqual(JSON.parse(r.stdout), expected("string"));
  assert.equal(r.stdout.includes(sensitive), false);
});

test("bootstrap output fields, constants and tuple cardinalities have independent negative controls", () => {
  const r = invoke("{}"); assert.equal(r.status, 0);
  const value = JSON.parse(r.stdout);
  const at = (object, path) => path.reduce((x, key) => x[key], object);
  const records = [[], ["summary"], ["diagnostics", 0], ["ruleResults", 0]];
  for (const path of records) {
    const unknown = structuredClone(value); at(unknown, path).foreign = true;
    assert.equal(outputValid(unknown), false, `${path}/foreign`);
    for (const [key, original] of Object.entries(at(value, path))) {
      for (const mode of ["missing", "null", "wrong-type"]) {
        const bad = structuredClone(value), record = at(bad, path);
        if (mode === "missing") delete record[key];
        if (mode === "null") record[key] = null;
        if (mode === "wrong-type") record[key] = typeof original === "string" ? 0 : "wrong-type";
        assert.equal(outputValid(bad), false, `${path}/${key}/${mode}`);
      }
    }
  }
  for (const [path, key] of [[[], "reportId"], [[], "reportKind"], [[], "state"], [["summary"], "inputKind"], [["diagnostics", 0], "key"], [["diagnostics", 0], "value"], [["ruleResults", 0], "ruleId"], [["ruleResults", 0], "status"], [["ruleResults", 0], "message"]]) {
    const bad = structuredClone(value); at(bad, path)[key] = "foreign-value";
    assert.equal(outputValid(bad), false, `${path}/${key}/domain`);
  }
  for (const version of [0, 2, 1.5]) {
    const bad = structuredClone(value); bad.schemaVersion = version;
    assert.equal(outputValid(bad), false, "output version");
  }
  for (const path of [["diagnostics"], ["ruleResults"], ["nonClaims"], ["ruleResults", 0, "diagnostics"]]) {
    const original = at(value, path);
    if (original.length) {
      const short = structuredClone(value); at(short, path).pop();
      assert.equal(outputValid(short), false, `${path}/short`);
    }
    for (const item of [null, 0, "foreign", original[0] ?? {}]) {
      const long = structuredClone(value); at(long, path).push(item);
      assert.equal(outputValid(long), false, `${path}/long`);
    }
  }
  for (let i = 0; i < 2; i++) {
    const bad = structuredClone(value); bad.nonClaims[i] = "Different statement.";
    assert.equal(outputValid(bad), false, `nonClaims/${i}/literal`);
  }
  const swapped = structuredClone(value); swapped.nonClaims.reverse();
  assert.equal(outputValid(swapped), false, "nonClaims/order");
});
