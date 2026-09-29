import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {after, before} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const families = [
  ["receipt-currentness-scope", "receipt-currentness-native-observations.json"],
  ["receipt-trust-class", "receipt-trust-native-observations.json"],
].map(([command, file]) => {
  const validators = Object.fromEntries(["input", "output"].map(direction => {
    const definition = contract.contractDefinitions.find(value => value.definitionId === `proofkit.${command}.${direction}.v1.json-schema`);
    assert.ok(definition, `${command}/${direction} is published`);
    return [direction, ajv.compile(definition.fieldTree.variants[0].schema)];
  }));
  // Exact int64 observations are exercised by the Go CLI witness without
  // JavaScript Number conversion. This validator does not claim exact int64 math.
  const rows = JSON.parse(readFileSync(new URL(`internal/app/testdata/${file}`, root), "utf8"))
    .filter(row => row.case !== "int64-rank");
  return {command, rows, ...validators};
});
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-receipt-structure-"));
  binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120_000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });

function native(family, input, outcome, label) {
  const result = spawnSync(binary, [family.command, "--input", "-"], {
    input: typeof input === "string" ? input : JSON.stringify(input),
    encoding: "utf8", timeout: 10_000, maxBuffer: 2 << 20,
  });
  assert.equal(result.error, undefined, label);
  assert.equal(result.signal, null, label);
  assert.equal(result.status, outcome === "passed" ? 0 : 1, `${label}: ${result.stderr}`);
  if (outcome === "rejected") {
    assert.equal(result.stdout, "", label);
    assert.match(result.stderr, /^receipt (?:currentness-scope|trust-class)/, label);
    return;
  }
  assert.equal(result.stderr, "", label);
  const report = JSON.parse(result.stdout);
  assert.equal(report.state, outcome, label);
  assert.equal(family.output(report), true, `${label}: ${ajv.errorsText(family.output.errors)}`);
  return report;
}

function pair(family, input, outcome, label) {
  assert.equal(family.input(input), outcome !== "rejected", `${label}: ${ajv.errorsText(family.input.errors)}`);
  return native(family, input, outcome, label);
}

function at(value, path) { return path.reduce((record, key) => record[key], value); }
function wrongReceiptType(value) { return value === null ? {} : typeof value === "string" ? 42 : "wrong-type"; }
function objectPaths(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [...(Array.isArray(value) ? [] : [path]), ...Object.entries(value).flatMap(([key, child]) => objectPaths(child, [...path, key]))];
}
function arrayPaths(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [...(Array.isArray(value) ? [path] : []), ...Object.entries(value).flatMap(([key, child]) => arrayPaths(child, [...path, key]))];
}

test("pre-schema native observations fit both published receipt directions", () => {
  for (const family of families) for (const row of family.rows) {
    const report = pair(family, row.input, row.exitCode === 0 ? "passed" : "failed", `${family.command}/${row.case}`);
    assert.deepEqual(report, row.output, "historical wire observation is preserved");
  }
});

test("each native receipt object has required, closed, typed members", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of objectPaths(baseline)) {
      const unknown = structuredClone(baseline);
      at(unknown, path).extra = true;
      pair(family, unknown, "rejected", `${family.command}/${path}/extra`);
      for (const key of Object.keys(at(baseline, path))) {
        for (const mode of ["missing", "null", "wrong-type"]) {
          const input = structuredClone(baseline);
          const record = at(input, path);
          if (mode === "missing") delete record[key];
          if (mode === "null") record[key] = null;
          if (mode === "wrong-type") record[key] = typeof record[key] === "string" ? 42 : "wrong-type";
          const nullable = ["currentScopeDigest", "recordedScopeDigest", "provenanceRef"].includes(key);
          const outcome = mode === "null" && nullable ? (key === "provenanceRef" ? "failed" : "passed") : "rejected";
          pair(family, input, outcome, `${family.command}/${path}/${key}/${mode}`);
        }
      }
    }
    for (const path of arrayPaths(baseline)) {
      const duplicate = structuredClone(baseline);
      const items = at(duplicate, path);
      assert.ok(items.length > 0, `${path} seed provides a distinguishing item`);
      items.push(structuredClone(items[0]));
      pair(family, duplicate, "rejected", `${family.command}/${path}/duplicate`);
      const empty = structuredClone(baseline);
      at(empty, path).length = 0;
      const optional = path.at(-1) === "artifactRefs";
      pair(family, empty, optional ? "failed" : "rejected", `${family.command}/${path}/empty`);
    }
  }
});

test("receipt scalar domains are not merely non-null types", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of objectPaths(baseline)) for (const [key, value] of Object.entries(at(baseline, path))) {
      let invalid;
      if (key.endsWith("Id") || ["proofRouteRef", "checkClass", "scopeClass", "environmentClass", "riskClass", "receiptKind"].includes(key)) invalid = "bad value";
      if (key.includes("Digest")) invalid = "sha256:" + "A".repeat(64);
      if (["admissionState", "producerAdmissionClass", "receiptStatus"].includes(key)) invalid = "foreign";
      if (key === "schemaVersion") invalid = 2;
      if (key === "rank") invalid = 0;
      if (invalid === undefined) continue;
      assert.notEqual(value, invalid);
      const input = structuredClone(baseline);
      at(input, path)[key] = invalid;
      pair(family, input, "rejected", `${family.command}/${path}/${key}/domain`);
    }
    for (const value of ["id ", "a".repeat(257)]) {
      const input = structuredClone(baseline);
      input.obligationReceipts[0].obligationId = value;
      pair(family, input, "rejected", "raw ID boundary");
    }
    const longest = structuredClone(baseline);
    longest.obligationReceipts[0].obligationId = "a".repeat(256);
    const report = pair(family, longest, "passed", "long raw ID and prefixed rule ID");
    assert.ok(report.ruleResults[0].ruleId.length > 256);
    const pathSpaces = structuredClone(baseline);
    pathSpaces.obligationReceipts[0].evidenceRefs = [" "];
    pair(family, pathSpaces, "passed", "untrimmed valid POSIX path");
  }
});

test("normalized identifier lists preserve Go whitespace and native class bounds", () => {
  const family = families[1];
  for (const key of ["allowedEnvironmentClasses", "allowedReceiptKinds"]) {
    const input = structuredClone(family.rows[0].input);
    const value = input.proofClasses[0][key][0];
    const pad = "\u0085\u00a0\u1680\u2000\u2028\u202f\u205f\u3000 \t\r\n";
    input.proofClasses[0][key] = [pad + value + pad];
    pair(family, input, "passed", `${key}/trim`);
    for (const invalid of ["a b", "a".repeat(257), " ", "\ufeff" + value]) {
      input.proofClasses[0][key] = [invalid];
      pair(family, input, "rejected", `${key}/domain`);
    }
  }
  for (const key of ["allowedProducerAdmissionLevels", "allowedReceiptStatuses"]) {
    const input = structuredClone(family.rows[0].input);
    input.trustClasses[0][key] = ["foreign"];
    pair(family, input, "rejected", `${key}/enum`);
  }
  const bounded = structuredClone(family.rows[0].input);
  const seed = bounded.trustClasses[0];
  bounded.trustClasses = Array.from({length: 4096}, (_, i) => ({...seed, rank: i + 1, trustClassId: i === 0 ? seed.trustClassId : `trust.t${i}`}));
  pair(family, bounded, "passed", "exact native trust-class maximum");
  bounded.trustClasses.push({...seed, rank: 4097, trustClassId: "trust.excess"});
  pair(family, bounded, "rejected", "bounded trust classes without duplicate excuse");
});

test("receipt output objects, report variants and domains reject structural corruption", () => {
  for (const family of families) for (const row of family.rows) {
    const baseline = row.output;
    for (const path of objectPaths(baseline)) {
      for (const [key, value] of Object.entries(at(baseline, path))) {
        const output = structuredClone(baseline);
        at(output, path)[key] = wrongReceiptType(value);
        assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/${key}/type`);
      }
      for (const key of [...Object.keys(at(baseline, path)), "extra"]) {
        const output = structuredClone(baseline);
        if (key === "extra") at(output, path)[key] = true; else delete at(output, path)[key];
        assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/${key}`);
      }
    }
    for (const path of arrayPaths(baseline)) {
      const items = at(baseline, path);
      if (items.length === 0) {
        // Empty receipt collections are string/state lists, not numeric lists.
        const output = structuredClone(baseline);
        at(output, path).push(42);
        assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/empty-item-type`);
      }
      for (const [index, value] of items.entries()) {
        const output = structuredClone(baseline);
        at(output, path)[index] = wrongReceiptType(value);
        assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/${index}/item-type`);
      }
    }
    for (const [path, invalid] of [
      [["reportKind"], "foreign"], [["schemaVersion"], 2], [["state"], "skipped"],
      [["reportId"], "bad id"], [["summary", "failedObligationCount"], -1],
      [["ruleResults", 0, "ruleId"], "unprefixed"], [["ruleResults", 0, "status"], "warning"],
      [["diagnostics", 1, "value", 0, "decisionCandidateStates"], ["satisfied"]],
    ]) {
      const output = structuredClone(baseline);
      at(output, path.slice(0, -1))[path.at(-1)] = invalid;
      assert.equal(family.output(output), false, `${family.command}/${path}/domain`);
    }
    const reversed = structuredClone(baseline);
    reversed.diagnostics.reverse();
    assert.equal(family.output(reversed), false, "diagnostic positions are fixed");
    const omittedBoundary = structuredClone(baseline);
    omittedBoundary.nonClaims = omittedBoundary.nonClaims.map((value, index) => index === 0 ? "replacement" : value);
    assert.equal(family.output(omittedBoundary), false, "builtin nonClaim required independently of count");
  }
});

test("receipt state algebra and multi-obligation ordering reach the published output", () => {
  const currentness = families[0];
  for (const stale of [false, true]) for (const unknown of [false, true]) {
    const input = structuredClone(currentness.rows[0].input);
    const receipt = input.obligationReceipts[0];
    if (stale) receipt.currentnessChecks[0].currentDigest = "sha256:" + "b".repeat(64);
    if (unknown) receipt.scopeChecks[0].admissionState = "unknown_current_scope";
    const report = pair(currentness, input, stale || unknown ? "failed" : "passed", `currentness/${stale}/${unknown}`);
    assert.deepEqual(report.diagnostics[1].value[0].decisionCandidateStates,
      [...(stale ? ["stale_receipt"] : []), ...(unknown ? ["unknown_scope"] : [])]);
  }
  const trust = families[1];
  for (const producer of [false, true]) for (const invalid of [false, true]) {
    const input = structuredClone(trust.rows[0].input);
    const receipt = input.obligationReceipts[0];
    if (producer) receipt.proofClassId = "unknown.proof";
    if (invalid) receipt.provenanceRef = null;
    const report = pair(trust, input, producer || invalid ? "failed" : "passed", `trust/${producer}/${invalid}`);
    assert.deepEqual(report.diagnostics[1].value[0].decisionCandidateStates,
      [...(producer ? ["invalid_producer"] : []), ...(invalid ? ["invalid_receipt"] : [])]);
  }
  for (const family of families) {
    const input = structuredClone(family.rows[0].input);
    const receipt = input.obligationReceipts[0];
    receipt.obligationId = "obligation.z";
    input.obligationReceipts.push({...structuredClone(receipt), obligationId: "obligation.a"});
    const report = pair(family, input, "passed", "two obligations sorted independently of input order");
    assert.deepEqual(report.diagnostics[1].value.map(value => value.obligationId), ["obligation.a", "obligation.z"]);
    assert.deepEqual(report.ruleResults.map(value => value.ruleId), [`proofkit.${family.command}.obligation.a`, `proofkit.${family.command}.obligation.z`]);
  }
});

test("native-only rules are not confused with structural completeness", () => {
  for (const family of families) {
    const input = structuredClone(family.rows[0].input);
    input.nonClaims = ["claim", " claim "];
    assert.equal(family.input(input), true);
    native(family, input, "rejected", "normalized duplicate");
    const raw = JSON.stringify(family.rows[0].input).replace('"schemaVersion":1', '"schemaVersion":1.0');
    assert.equal(family.input(JSON.parse(raw)), true);
    native(family, raw, "rejected", "noncanonical number spelling");
  }
  const family = families[1];
  const input = structuredClone(family.rows[0].input);
  input.proofClasses[0].minimumTrustClassId = "unknown.class";
  assert.equal(family.input(input), true);
  native(family, input, "rejected", "unresolved minimum trust class");
  input.proofClasses[0].minimumTrustClassId = input.trustClasses[0].trustClassId;
  input.obligationReceipts[0].proofClassId = "unknown.class";
  pair(family, input, "failed", "unknown obligation proof class is an admitted failed report");
  input.obligationReceipts[0].trustClassId = "unknown.trust";
  const unknown = pair(family, input, "failed", "all unavailable class facts are nullable");
  const diagnostic = unknown.diagnostics[1].value[0];
  for (const key of ["actualTrustRank", "minimumTrustClassId", "minimumTrustRank", "riskClass"]) assert.equal(diagnostic[key], null);
});
