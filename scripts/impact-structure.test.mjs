import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {composeInput, impactInput, obligation} from "./impact-fixtures.mjs";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_IMPACT_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const impact = "impact", compose = "requirement-impact-input-compose";
const validators = new Map();
for (const name of [impact, compose]) for (const direction of ["input", "output"]) {
  const ref = contract.commands.find(row => row.command === name)[`${direction}Contract`].rootDefinitionRef;
  const definition = contract.contractDefinitions.find(row => row.definitionId === ref);
  assert.equal(definition.fieldTree.kind, "structural_json_schema");
  assert.match(JSON.stringify(definition.fieldTree), /^[\x00-\x7F]*$/);
  const ajv = new Ajv2020({strict: false, validateFormats: false});
  validators.set(`${name}/${direction}`, ajv.compile({oneOf: definition.fieldTree.variants.map(row => row.schema)}));
}
let directory, binary, subjects;
const hash = path => createHash("sha256").update(readFileSync(path)).digest("hex");
function identity(path) {
  const metadata = execFileSync("go", ["version", "-m", path], {encoding: "utf8", timeout: 10000});
  const revision = /^\s*build\tvcs\.revision=([0-9a-f]{40})$/m.exec(metadata)?.[1];
  const modified = /^\s*build\tvcs\.modified=(true|false)$/m.exec(metadata)?.[1];
  assert.ok(revision && modified);
  return {sha256: hash(path), revision, modified: modified === "true"};
}
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-impact-")); binary = join(directory, "proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"],
    {cwd: root, timeout: 120000, maxBuffer: 2 << 20, env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"}});
  if (process.env.PROOFKIT_IMPACT_BASELINE) {
    subjects = {kind: "proofkit.impact-comparison-subjects", baseline: identity(process.env.PROOFKIT_IMPACT_BASELINE),
      candidate: identity(binary), testSourceSHA256: hash(new URL(import.meta.url)), fixtureSHA256: hash(new URL("impact-fixtures.mjs", import.meta.url))};
    console.log(JSON.stringify(subjects));
  }
});
after(() => {
  try {
    if (subjects) {
      assert.equal(hash(binary), subjects.candidate.sha256);
      assert.equal(hash(process.env.PROOFKIT_IMPACT_BASELINE), subjects.baseline.sha256);
    }
  } finally { if (directory) rmSync(directory, {recursive: true, force: true}); }
});
function validates(name, direction, value, expected = true, label = "") {
  const check = validators.get(`${name}/${direction}`);
  assert.equal(check(value), expected, `${name}/${direction}/${label}: ${JSON.stringify(check.errors)}`);
}
function native(name, value, {exit = 0, report = true, carrier = "stdin", extra = []} = {}) {
  let args = [name, "--input", "-", ...extra], input = typeof value === "string" ? value : JSON.stringify(value);
  if (carrier === "pointer") {
    const path = join(directory, "input.json"); writeFileSync(path, JSON.stringify({payload: value}));
    args = [name, "--input", path, "--input-pointer", "/payload", ...extra]; input = "";
  } else if (carrier === "compact") args.unshift("--json-layout", "compact");
  const invoke = file => spawnSync(file, args, {input, encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
  const result = invoke(binary);
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  assert.equal(result.status, exit, `${name}: ${result.stderr}`);
  if (subjects) {
    const previous = invoke(process.env.PROOFKIT_IMPACT_BASELINE);
    assert.equal(previous.error, undefined);
    assert.deepEqual([result.status, result.signal, result.stdout, result.stderr],
      [previous.status, previous.signal, previous.stdout, previous.stderr], "native predecessor observation changed");
  }
  if (!report) { assert.equal(result.stdout, ""); assert.notEqual(result.stderr, ""); return; }
  assert.equal(result.stderr, ""); const output = JSON.parse(result.stdout);
  validates(name, "output", output); return output;
}
const at = (value, path) => path.reduce((node, key) => node[key], value);
function entries(value, path = []) {
  if (!value || typeof value !== "object") return [];
  return [[path, value], ...Object.entries(value).flatMap(([key, child]) => entries(child, [...path, key]))];
}
const badNative = {exit: 1, report: false};
const member = input => input.currentRequirementSources[0].groups[0].members[0];

test("impact and composer whole CLI routes preserve stdin pointer compact and chain identity", () => {
  for (const [name, input] of [[impact, impactInput()], [impact, impactInput(true)], [compose, composeInput()]]) {
    validates(name, "input", input); const output = native(name, input);
    for (const carrier of ["pointer", "compact"]) assert.deepEqual(native(name, input, {carrier}), output);
    if (name === impact) {
      assert.equal(output.impactState, "ok"); assert.equal(output.schemaVersion, 2);
    } else {
      validates(impact, "input", output); assert.equal(native(impact, output).impactState, "ok");
      assert.deepEqual(output.changedRequirementIds, []); assert.deepEqual(output.obligationCatalog, []);
    }
    native(name, input, {...badNative, extra: ["--agent-envelope"]});
  }
  const output = native(impact, impactInput(true));
  assert.deepEqual(output.obligations[0].changeReasons, ["proof_binding_changed", "proof_witness_changed", "requirement_changed"]);
  assert.equal(output.obligations[0].witnessRoutes.length, 2);
});

test("composition covers new adoption requirement binding and witness changes", () => {
  for (const mode of ["new", "requirement", "binding", "witness"]) {
    const input = composeInput();
    if (mode === "new") { delete input.baseRequirementSources; delete input.baseCompactProofContract; }
    if (mode === "requirement") member(input).statementCompletion = "A changed requirement retains its proof routes.";
    if (mode === "binding") {
      input.currentCompactProofContract.bindings[0][4] = "impact.changed_owner";
      input.changedPathSources[0].paths.push("docs/contracts/impact.json"); input.changedPathSources[0].paths.sort();
    }
    if (mode === "witness") input.changedPathSources[0].paths = ["tests/impact_test.go"];
    validates(compose, "input", input); const composed = native(compose, input); validates(impact, "input", composed);
    const output = native(impact, composed); assert.equal(output.obligations.length, 1);
    const expected = mode === "new" ? ["requirement_changed"] :
      [mode === "requirement" ? "requirement_changed" : mode === "binding" ? "proof_binding_changed" : "proof_witness_changed"];
    assert.deepEqual(output.obligations[0].changeReasons, expected, mode);
  }
  const nullable = composeInput(); nullable.baseRequirementSources = null; nullable.baseCompactProofContract = null;
  delete nullable.headCommit; validates(compose, "input", nullable);
  assert.equal(native(compose, nullable).headCommit, null);
});

test("admission and evaluation failures are separate composer and impact outcomes", () => {
  for (const mode of ["preexisting", "policy", "uncovered", "unbound", "generated", "missing-binding"]) {
    const input = composeInput();
    if (mode === "preexisting") input.preexistingFailures = ["Synthetic failure."];
    if (mode === "policy") input.generatedArtifactPolicyState.state = "caller.pending";
    if (mode === "uncovered") input.generatedArtifactPolicyState.uncoveredGeneratedPaths = ["docs/generated.md"];
    if (mode === "unbound") input.changedPathSources[0].paths = ["tests/unbound.go"];
    if (mode === "generated") input.changedPathSources[0].paths = ["docs/generated.md"];
    if (mode === "missing-binding") {
      member(input).statementCompletion = "A changed requirement requires a missing proof route.";
      input.currentCompactProofContract.bindings = [];
    }
    validates(compose, "input", input); const composed = native(compose, input);
    validates(impact, "input", composed); const output = native(impact, composed, {exit: 1});
    assert.equal(output.impactState, "failed"); assert.ok(output.failures.length, mode);
    if (mode === "unbound") assert.deepEqual(output.unboundProofChanges, [{path: "tests/unbound.go", rationale: ""}]);
  }
});

test("nullable optional and nonempty fields preserve the distinct parent and child domains", () => {
  for (const nonClaims of [undefined, null, []]) {
    const input = impactInput(); if (nonClaims === undefined) delete input.nonClaims; else input.nonClaims = nonClaims;
    validates(impact, "input", input); assert.ok(native(impact, input).nonClaims.length);
  }
  const missing = impactInput(); delete missing.headCommit;
  validates(impact, "input", missing, false); native(impact, missing, badNative);
  const composed = native(compose, composeInput());
  for (const nonClaims of [undefined, null, []]) {
    const changed = structuredClone(composed); if (nonClaims === undefined) delete changed.nonClaims; else changed.nonClaims = nonClaims;
    validates(compose, "output", changed, false); validates(impact, "input", changed); native(impact, changed);
  }
  for (const path of [["nonClaims"], ["changedPathSources"], ["currentRequirementSources"], ["proofLikePathPolicy", "nonClaims"]]) {
    const input = composeInput(); at(input, path.slice(0, -1))[path.at(-1)] = [];
    validates(compose, "input", input, false, path.join("/")); native(compose, input, badNative);
  }
  const empty = composeInput(); empty.changedPathSources[0].paths = [];
  empty.generatedArtifactRules[0].sourcePathPatterns = []; empty.localEnvironmentPolicy.localEnvironmentClasses = [];
  validates(compose, "input", empty); native(compose, empty);
});

test("nested impact objects require every owned member and reject unknown fields", () => {
  const input = impactInput(true);
  for (const [path, value] of entries(input)) {
    if (Array.isArray(value)) {
      const bad = structuredClone(input); at(bad, path).push(false);
      validates(impact, "input", bad, false, path.join("/")); native(impact, bad, badNative);
    } else {
      const unknown = structuredClone(input); at(unknown, path).unknownField = true;
      validates(impact, "input", unknown, false, path.join("/")); native(impact, unknown, badNative);
      for (const key of Object.keys(value)) {
        if (!path.length && key === "nonClaims") continue;
        const bad = structuredClone(input); delete at(bad, path)[key];
        validates(impact, "input", bad, false, [...path, key].join("/")); native(impact, bad, badNative);
      }
    }
  }
});

test("composer records and both reused child owners stay closed", () => {
  const input = composeInput();
  for (const path of [[], ["changedPathSources", 0], ["localEnvironmentPolicy"], ["proofLikePathPolicy"],
    ["generatedArtifactPolicyState"], ["generatedArtifactRules", 0], ["currentRequirementSources", 0],
    ["baseRequirementSources", 0], ["baseCompactProofContract"], ["currentCompactProofContract"]]) {
    const bad = structuredClone(input); at(bad, path).unknownField = true;
    validates(compose, "input", bad, false, path.join("/")); native(compose, bad, badNative);
  }
  for (const key of Object.keys(input)) {
    if (["baseRequirementSources", "baseCompactProofContract", "headCommit"].includes(key)) continue;
    const bad = structuredClone(input); delete bad[key]; validates(compose, "input", bad, false, key); native(compose, bad, badNative);
  }
  for (const key of ["baseRequirementSources", "currentRequirementSources"]) {
    const bad = composeInput(); bad[key][0].schemaVersion = 1;
    validates(compose, "input", bad, false, key); native(compose, bad, badNative);
  }
  for (const key of ["baseCompactProofContract", "currentCompactProofContract"]) {
    const bad = composeInput(); bad[key].bindings[0][7][3] = -1;
    validates(compose, "input", bad, false, key); native(compose, bad, badNative);
  }
});

test("output records reject missing unknown malformed and out of domain fields", () => {
  const failed = impactInput(); failed.preexistingFailures = ["Synthetic failure."]; failed.proofLikePaths = ["tests/unbound.go"];
  const changed = composeInput(); member(changed).statementCompletion = "Changed requirements retain their witnesses.";
  for (const [name, output] of [[impact, native(impact, impactInput(true))], [impact, native(impact, failed, {exit: 1})], [compose, native(compose, changed)]]) {
    for (const [path, value] of entries(output)) {
      if (Array.isArray(value)) {
        const bad = structuredClone(output); at(bad, path).push(false); validates(name, "output", bad, false, path.join("/"));
      } else {
        const unknown = structuredClone(output); at(unknown, path).unknownField = true; validates(name, "output", unknown, false);
        for (const key of Object.keys(value)) {
          if (!path.length && key === "unboundProofChangeRationale") continue;
          const bad = structuredClone(output); delete at(bad, path)[key]; validates(name, "output", bad, false, [...path, key].join("/"));
          if (value[key] !== null && typeof value[key] === "object") continue;
          const wrong = structuredClone(output); at(wrong, path)[key] = {};
          validates(name, "output", wrong, false, [...path, key].join("/"));
        }
      }
    }
  }
  for (const [path, value] of [[["impactState"], "unknown"], [["obligations", 0, "changeReasons"], ["unknown"]],
    [["obligations", 0, "changeReasons"], []], [["obligations", 0, "declaredWitnessRoutes"], []]]) {
    const output = native(impact, impactInput(true)); at(output, path.slice(0, -1))[path.at(-1)] = value;
    validates(impact, "output", output, false, path.join("/"));
  }
});

test("digest whitespace and Unicode nonblank text follow native admission", () => {
  const input = impactInput(true);
  const padded = value => `\u0085 ${value.slice(0, 7)}\u2003${value.slice(7)}\t`;
  input.changedBindingRecordIds = input.changedBindingRecordIds.map(padded);
  for (const record of [input.obligationCatalog[0], ...input.obligationCatalog[0].declaredWitnessRoutes, ...input.changedWitnessPathCoverage[0].routes]) {
    record.bindingRecordId = padded(record.bindingRecordId);
    if (record.witnessRouteId) record.witnessRouteId = padded(record.witnessRouteId);
  }
  validates(impact, "input", input); assert.deepEqual(native(impact, input), native(impact, impactInput(true)));
  for (const value of ["", " \t\n", "\u0085", "\u2003"]) {
    const bad = impactInput(); bad.baseCommit = value;
    validates(impact, "input", bad, false); native(impact, bad, badNative);
  }
  for (const value of ["\uFEFF", "\u0085revision\u0085"]) {
    const valid = impactInput(); valid.baseCommit = value; validates(impact, "input", valid); native(impact, valid);
  }
  const bad = impactInput(true); bad.changedBindingRecordIds = ["sha256:" + "G".repeat(64)];
  validates(impact, "input", bad, false); native(impact, bad, badNative);
});

test("numeric role and cardinality bounds reject isolated malformed neighbors", () => {
  for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, "0", null]) {
    const bad = impactInput(true); bad.obligationCatalog[0].declaredWitnessRoutes[0].resolutionOrderIndex = value;
    validates(impact, "input", bad, false); native(impact, bad, badNative);
  }
  const maximum = impactInput(true);
  for (const route of [...maximum.obligationCatalog[0].declaredWitnessRoutes, ...maximum.changedWitnessPathCoverage[0].routes]) route.resolutionOrderIndex = Number.MAX_SAFE_INTEGER;
  validates(impact, "input", maximum); native(impact, maximum);
  for (const token of ["-0", "0.0", "0e0"]) {
    const bytes = JSON.stringify(impactInput(true)).replaceAll('"resolutionOrderIndex":0', `"resolutionOrderIndex":${token}`);
    validates(impact, "input", JSON.parse(bytes)); native(impact, bytes, badNative);
  }
  for (const mode of ["role", "one-route", "three-routes", "empty-commands", "empty-environments", "empty-coverage"]) {
    const bad = impactInput(true), record = bad.obligationCatalog[0];
    if (mode === "role") record.declaredWitnessRoutes[0].role = "unknown";
    if (mode === "one-route") record.declaredWitnessRoutes.pop();
    if (mode === "three-routes") record.declaredWitnessRoutes.push(structuredClone(record.declaredWitnessRoutes[0]));
    if (mode === "empty-commands") record.commands = [];
    if (mode === "empty-environments") record.requiredEnvironmentClasses = [];
    if (mode === "empty-coverage") bad.changedWitnessPathCoverage[0].routes = [];
    validates(impact, "input", bad, false, mode); native(impact, bad, badNative);
  }
});

test("arbitrary policy IDs text environments and more than two coverage routes remain valid", () => {
  const input = impactInput(true); input.obligationCatalog[0].blockingStatus = "caller.custom";
  input.obligationCatalog[0].requiredEnvironmentClasses.push("custom environment");
  for (const route of input.obligationCatalog[0].declaredWitnessRoutes) { route.environmentClasses = []; route.verifyCommands = []; }
  const another = obligation("REQ-IMPACT-002"); input.obligationCatalog.push(another);
  input.changedWitnessPathCoverage[0].routes.push(...another.declaredWitnessRoutes.map(
    ({environmentClasses: _environments, verifyCommands: _commands, ...route}) => route));
  input.changedWitnessPathCoverage[0].routes.sort((a, b) => a.witnessRouteId < b.witnessRouteId ? -1 : 1);
  validates(impact, "input", input); const output = native(impact, input);
  assert.equal(output.obligations.length, 2); assert.equal(output.obligations.find(row => row.requirementId === "REQ-IMPACT-001").blockingStatus, "caller.custom");
  const wide = impactInput(true); wide.obligationCatalog[0].declaredMutationResistanceClaimId = "a".repeat(256);
  validates(impact, "input", wide); native(impact, wide);
  wide.obligationCatalog[0].declaredMutationResistanceClaimId += "a";
  validates(impact, "input", wide, false); native(impact, wide, badNative);
});

test("native-only joins ordering privacy and base pairing remain separately enforced", () => {
  for (const mode of ["identity", "order", "selector", "privacy"]) {
    const input = impactInput(true);
    if (mode === "identity") input.obligationCatalog[0].bindingRecordId = "sha256:" + "0".repeat(64);
    if (mode === "order") input.obligationCatalog[0].declaredWitnessRoutes.reverse();
    if (mode === "selector") input.changedWitnessPathCoverage[0].path = "tests/other.go";
    if (mode === "privacy") input.nonClaims = ["api_key=" + "fixture".repeat(8)];
    validates(impact, "input", input); native(impact, input, badNative);
  }
  const input = composeInput(); delete input.baseCompactProofContract;
  validates(compose, "input", input); native(compose, input, badNative);
  const duplicates = composeInput(); duplicates.preexistingFailures = ["Synthetic failure.", "Synthetic failure."];
  validates(compose, "input", duplicates); native(compose, duplicates, badNative);
  const broader = impactInput(); broader.preexistingFailures = duplicates.preexistingFailures;
  validates(impact, "input", broader); assert.deepEqual(native(impact, broader, {exit: 1}).failures, ["Synthetic failure."]);
  for (const name of [impact, compose]) native(name, '{"schemaVersion":2,"schemaVersion":2}', badNative);
});
