import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_RECEIPT_ADMISSION_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const families = [
  ["proof-receipt-admission", "proof-receipt-native-observations.json", ["dependencyDigest", "exitCode", "lockfileDigest", "provenanceRef"]],
  ["receipt-producer-admission", "receipt-producer-native-observations.json", ["provenanceRef"]],
].map(([command, file, optionals]) => {
  const validators = Object.fromEntries(["input", "output"].map(direction => {
    const definition = contract.contractDefinitions.find(row => row.definitionId === `proofkit.${command}.${direction}.v1.json-schema`);
    assert.ok(definition, `${command}/${direction}`);
    return [direction, ajv.compile(definition.fieldTree.variants[0].schema)];
  }));
  return {command, optionals, rows: JSON.parse(readFileSync(new URL(`internal/app/testdata/${file}`, root), "utf8")), ...validators};
});
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-receipt-admission-"));
  binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120_000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });

function native(family, input, expected, label) {
  const result = spawnSync(binary, [family.command, "--input", "-"], {
    input: typeof input === "string" ? input : JSON.stringify(input), encoding: "utf8", timeout: 10_000, maxBuffer: 2 << 20,
  });
  assert.equal(result.error, undefined, label);
  assert.equal(result.signal, null, label);
  assert.equal(result.status, expected === "passed" ? 0 : 1, `${label}: ${result.stderr}`);
  if (expected === "rejected") {
    assert.equal(result.stdout, "", label);
    assert.match(result.stderr, /^(?:proof receipt admission|receipt producer admission)/, label);
    return;
  }
  assert.equal(result.stderr, "", label);
  const output = JSON.parse(result.stdout);
  assert.equal(output.state, expected, label);
  assert.equal(family.output(output), true, `${label}: ${ajv.errorsText(family.output.errors)}`);
  return output;
}
function pair(family, input, expected, label) {
  assert.equal(family.input(input), expected !== "rejected", `${label}: ${ajv.errorsText(family.input.errors)}`);
  return native(family, input, expected, label);
}
function at(value, path) { return path.reduce((record, key) => record[key], value); }
function objectPaths(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [...(Array.isArray(value) ? [] : [path]), ...Object.entries(value).flatMap(([key, child]) => objectPaths(child, [...path, key]))];
}
function arrayPaths(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [...(Array.isArray(value) ? [path] : []), ...Object.entries(value).flatMap(([key, child]) => arrayPaths(child, [...path, key]))];
}

test("pre-schema receipt/producer carriers preserve actual native wire observations", () => {
  for (const family of families) for (const row of family.rows) {
    assert.deepEqual(pair(family, row.input, row.exitCode === 0 ? "passed" : "failed", `${family.command}/${row.case}`), row.output);
  }
});

test("every optional concrete branch and finite vocabulary has a native-valid positive", () => {
  const proof = families[0], producer = families[1];
  for (const key of ["dependencyDigest", "lockfileDigest", "provenanceRef"]) {
    const input = structuredClone(proof.rows[0].input);
    input.receipts[0][key] = key === "provenanceRef" ? "artifacts/proofkit/provenance.json" : "sha256:" + "a".repeat(64);
    pair(proof, input, "passed", `${key}/concrete`);
    for (const invalid of key === "provenanceRef" ? [""] : ["", "sha256:" + "a".repeat(63), "sha256:" + "A".repeat(64)]) {
      input.receipts[0][key] = invalid;
      pair(proof, input, "rejected", `${key}/invalid-concrete`);
    }
  }
  for (const kind of ["artifact", "log", "report"]) {
    const input = structuredClone(proof.rows[0].input);
    input.receipts[0].artifactRefs[0].kind = kind;
    pair(proof, input, "passed", `artifact-kind/${kind}`);
  }
  for (const level of ["advisory", "merge_satisfying"]) {
    const input = structuredClone(proof.rows[0].input);
    input.receipts[0].producerAdmissionClass = level;
    input.receipts[0].provenanceRef = "artifacts/proofkit/provenance.json";
    pair(proof, input, "passed", `proof-producer-class/${level}`);
    const policy = structuredClone(producer.rows[0].input);
    policy.producers[0].admissionLevel = level;
    policy.receipts[0].satisfiesMergeObligation = false;
    pair(producer, policy, "passed", `producer-admission/${level}`);
  }
});

test("every native string and text-list item rejects empty content", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of objectPaths(baseline)) for (const [key, value] of Object.entries(at(baseline, path))) {
      if (typeof value !== "string") continue;
      const input = structuredClone(baseline);
      at(input, path)[key] = "";
      pair(family, input, "rejected", `${family.command}/${path}/${key}/empty-string`);
    }
    for (const path of arrayPaths(baseline)) {
      const items = at(baseline, path);
      if (items.length ? typeof items[0] !== "string" : path.at(-1) !== "nonClaims") continue;
      const input = structuredClone(baseline);
      const parent = at(input, path.slice(0, -1));
      parent[path.at(-1)] = [""];
      pair(family, input, "rejected", `${family.command}/${path}/empty-item`);
    }
  }
});

test("output free text and ref strings cannot lose their nonempty guard", () => {
  for (const family of families) for (const row of family.rows) {
    const baseline = row.output;
    for (const path of objectPaths(baseline)) for (const [key, value] of Object.entries(at(baseline, path))) {
      if (typeof value !== "string") continue;
      const output = structuredClone(baseline);
      at(output, path)[key] = "";
      assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/${key}/empty-string`);
    }
    for (const path of arrayPaths(baseline)) {
      if (!at(baseline, path).some(item => typeof item === "string")) continue;
      const output = structuredClone(baseline);
      at(output, path).push("");
      assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/empty-item`);
    }
  }
});

test("every native input member is closed, typed and has precise presence/null semantics", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of objectPaths(baseline)) {
      const unknown = structuredClone(baseline);
      at(unknown, path).extra = true;
      pair(family, unknown, "rejected", `${family.command}/${path}/unknown`);
      for (const [key, value] of Object.entries(at(baseline, path))) {
        for (const mode of ["missing", "null", "wrong-type"]) {
          const input = structuredClone(baseline), record = at(input, path);
          if (mode === "missing") delete record[key];
          if (mode === "null") record[key] = null;
          if (mode === "wrong-type") record[key] = value === null ? {} : typeof value === "string" ? 42 : "wrong-type";
          const optional = path.length === 2 && path[0] === "receipts" && family.optionals.includes(key);
          const allowed = optional && mode !== "wrong-type";
          const failed = key === "exitCode" || (key === "provenanceRef" && family.command === "receipt-producer-admission");
          pair(family, input, allowed ? failed ? "failed" : "passed" : "rejected", `${family.command}/${path}/${key}/${mode}`);
        }
      }
    }
  }
});

test("array requirements distinguish empty, nonempty and distinct inventories", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of arrayPaths(baseline)) {
      const empty = structuredClone(baseline);
      at(empty, path).length = 0;
      const key = path.at(-1), proof = family.command === "proof-receipt-admission";
      const required = proof ? ["receipts", "evidenceRefs", "witnessSelectors"].includes(key) : key === "nonClaims";
      if (!proof && path.length === 1 && ["environmentClasses", "receiptKinds"].includes(key)) {
        assert.equal(family.input(empty), true, "empty vocabulary is structural, membership is native");
        native(family, empty, "rejected", `${key}/native membership`);
      } else {
        const expected = required ? "rejected" : key === "artifactRefs" && proof ? "failed" : !proof && (key === "producers" || path[0] === "producers" && ["environmentClasses", "receiptKinds"].includes(key)) ? "failed" : "passed";
        pair(family, empty, expected, `${family.command}/${path}/empty`);
      }
      const items = at(baseline, path);
      if (!items.length) continue;
      const duplicate = structuredClone(baseline);
      at(duplicate, path).push(structuredClone(items[0]));
      pair(family, duplicate, "rejected", `${family.command}/${path}/duplicate`);
    }
  }
});

test("receipt scalar domains cover enums, identifiers, digests and both exit endpoints", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of objectPaths(baseline)) for (const [key, value] of Object.entries(at(baseline, path))) {
      let invalid;
      if (key.endsWith("Id") || ["environmentClass", "receiptKind", "runnerClass", "runnerIdentity", "subjectRef"].includes(key)) invalid = "bad value";
      if (key.endsWith("Digest") && value !== null) invalid = "sha256:" + "A".repeat(64);
      if (["status", "admissionLevel", "producerAdmissionClass", "kind"].includes(key)) invalid = "foreign";
      if (["startedAt", "finishedAt"].includes(key)) invalid = "2026-06-26T10:00:00+00:00";
      if (key === "schemaVersion") invalid = 2;
      if (invalid === undefined) continue;
      const input = structuredClone(baseline);
      at(input, path)[key] = invalid;
      pair(family, input, "rejected", `${family.command}/${path}/${key}/domain`);
    }
    for (const id of ["a".repeat(256), "a".repeat(257), "id "]) {
      const input = structuredClone(baseline);
      input.receipts[0].receiptId = id;
      pair(family, input, id.length === 256 ? "passed" : "rejected", `${family.command}/ID-bound`);
    }
  }
  const proof = families[0];
  for (const value of [0, 255, -1, 256, 1.5]) {
    const input = structuredClone(proof.rows[0].input);
    input.receipts[0].exitCode = value;
    pair(proof, input, value === 0 ? "passed" : value === 255 ? "failed" : "rejected", `exitCode/${value}`);
  }
});

test("native-only canonical, privacy and relation rules remain separate from schema shape", () => {
  for (const family of families) {
    const input = structuredClone(family.rows[0].input);
    const encoded = JSON.stringify(input);
    for (const token of ["1.0", "1e0"]) native(family, encoded.replace('"schemaVersion":1', `"schemaVersion":${token}`), "rejected", `version/${token}`);
    const unknown = structuredClone(input);
    unknown.receipts[0].producerId = "producer.unknown";
    pair(family, unknown, family.command === "proof-receipt-admission" ? "passed" : "failed", "unknown-producer is not a schema error");
    const secret = structuredClone(input);
    secret.nonClaims = ["api_key=" + "synthetic-canary-only".repeat(3)];
    native(family, secret, "rejected", "private text fails closed");
  }
  const family = families[0], input = structuredClone(family.rows[0].input);
  for (const token of ["-0", "1.0", "1e0"]) {
    const encoded = JSON.stringify(input).replace('"exitCode":0', `"exitCode":${token}`);
    native(family, encoded, token === "-0" ? "passed" : "rejected", `exitCode/${token}`);
  }
  input.receipts[0].startedAt = "2026-02-30T10:00:00Z";
  assert.equal(family.input(input), true, "grammar is not calendar validity");
  native(family, input, "rejected", "invalid calendar");
});

test("output members, tuples and numerical domains reject independent corruptions", () => {
  for (const family of families) for (const row of family.rows) {
    const baseline = row.output;
    for (const path of objectPaths(baseline)) {
      const unknown = structuredClone(baseline);
      at(unknown, path).extra = true;
      assert.equal(family.output(unknown), false, `${family.command}/${path}/unknown`);
      for (const [key, value] of Object.entries(at(baseline, path))) {
        for (const mode of ["missing", "wrong-type"]) {
          const output = structuredClone(baseline);
          if (mode === "missing") delete at(output, path)[key];
          else at(output, path)[key] = value === null ? {} : typeof value === "string" ? 42 : "wrong-type";
          assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/${key}/${mode}`);
        }
      }
    }
    for (const key of Object.keys(baseline.summary)) for (const value of [-1, 1.5]) {
      const output = structuredClone(baseline);
      output.summary[key] = value;
      assert.equal(family.output(output), false, `${family.command}/${key}/${value}`);
    }
    if (family.command === "proof-receipt-admission") {
      for (const key of ["evidenceRefCount", "receiptCount"]) {
        const output = structuredClone(baseline);
        output.summary[key] = 0;
        assert.equal(family.output(output), false, `${key}/positive-minimum`);
      }
      const empty = structuredClone(baseline);
      empty.diagnostics[1].value = [];
      assert.equal(family.output(empty), false, "receipt diagnostics cannot be empty");
    }
    for (const path of objectPaths(baseline)) for (const [key, value] of Object.entries(at(baseline, path))) {
      if (typeof value !== "string") continue;
      let invalid;
      if (["key", "message", "reportKind", "ruleId", "state", "status", "producerAdmissionClass"].includes(key)) invalid = "foreign";
      if (key.endsWith("Id") || ["environmentClass", "receiptKind", "runnerClass", "subjectRef"].includes(key)) invalid = "bad value";
      if (invalid === undefined) continue;
      const output = structuredClone(baseline);
      at(output, path)[key] = invalid;
      assert.equal(family.output(output), false, `${family.command}/${path}/${key}/domain`);
    }
    for (const key of ["diagnostics", "ruleResults"]) for (const mode of ["short", "long"]) {
      const output = structuredClone(baseline);
      if (mode === "short") output[key].pop(); else output[key].push(structuredClone(output[key][0]));
      assert.equal(family.output(output), false, `${family.command}/${key}/${mode}`);
    }
    const boundary = structuredClone(baseline);
    boundary.ruleResults[0].status = "failed";
    assert.equal(family.output(boundary), false, "boundary cannot fail");
    const identity = structuredClone(baseline);
    identity.reportKind = "proofkit.foreign";
    assert.equal(family.output(identity), false, "exact owner identity");
  }
});

test("output nonClaims preserves required denials, caller collisions and cardinality", () => {
  for (const family of families) {
    const baseline = family.rows[0].output;
    const builtin = baseline.nonClaims.filter(value => value.startsWith(family.command === "proof-receipt-admission" ? "Proof receipt admission" : "Receipt producer admission"));
    for (const value of builtin) {
      const output = structuredClone(baseline);
      output.nonClaims = output.nonClaims.filter(item => item !== value);
      output.nonClaims.push("A synthetic extra denial cannot replace an owner denial.");
      assert.equal(family.output(output), false, "each builtin denial is required independently");
    }
    const empty = structuredClone(baseline);
    empty.nonClaims = [];
    assert.equal(family.output(empty), false, "nonClaims has a minimum cardinality");
    if (family.command === "receipt-producer-admission") {
      const callerOmitted = structuredClone(baseline);
      callerOmitted.nonClaims = builtin;
      assert.equal(family.output(callerOmitted), false, "builtin presence cannot replace the required caller cardinality");
    }
    const duplicate = family.rows.find(row => row.case === "builtin-collision").output;
    assert.ok(new Set(duplicate.nonClaims).size < duplicate.nonClaims.length);
    assert.equal(family.output(duplicate), true, "builtin/caller collision remains admitted");
  }
});
