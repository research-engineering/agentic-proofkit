import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url), command = "spec-overview-claims";
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_OVERVIEW_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const baseline = JSON.parse(readFileSync(new URL("internal/app/testdata/overview-claims-native-observations.json", root), "utf8"));
assert.equal(baseline.head, "0a6a9e91c953880384ae641a57c8bee1a97fcf7a");
assert.equal(baseline.tree, "74e161dff94a11de672038579723aab378a121ac");
assert.equal(baseline.observations.length, 46);
const binding = contract.commands.find(x => x.command === command);
assert.equal(binding.inputContract.contractId, "proofkit.spec-overview-claims.input.v2");
assert.equal(binding.outputContract.contractId, "proofkit.spec-overview-claims.output.v1");
assert.deepEqual(binding.inputContract.pathRelations, [{relationKind: "derived_repo_path_v1", sourceField: "specPackagePath", suffix: "/requirements.v2.json", targetField: "requirementsPath"}]);
const ajv = new Ajv2020({strict: false, validateFormats: false});
const validators = Object.fromEntries(["input", "output"].map(direction => {
  const id = `proofkit.${command}.${direction}.v${direction === "input" ? 2 : 1}.json-schema`;
  const definition = contract.contractDefinitions.find(x => x.definitionId === id);
  assert.ok(definition, `${direction}/owner`);
  assert.equal(binding[direction + "Contract"].rootDefinitionRef, id);
  return [direction, ajv.compile(definition.fieldTree.variants[0].schema)];
}));
const builtin = [
  "Spec overview claim boundary reports do not approve merge, release, rollout, or production readiness.",
  "Spec overview claim boundary reports do not own requirement meaning.",
  "Spec overview claim boundary reports do not prove extractor completeness.",
  "Spec overview claim boundary reports do not read Markdown files.",
  "Spec overview claim boundary reports do not validate requirement source records.",
];
const predecessorHelp = "Usage:\n  agentic-proofkit spec-overview-claims --input <path|-> [--input-pointer <pointer>]\n\nInstalled invocation:\n  agentic-proofkit spec-overview-claims --input <path|-> [--input-pointer <pointer>]\n\nCommand ID:\n  spec-overview-claims\n\nRoute:\n  spec-overview-claims\n\nInput:\n  Requires explicit caller-owned JSON input through --input <path|->; stdin is only read when --input - is selected.\n\nOutput modes:\n  json\n\nScope class:\n  explicit_caller_input\n\nAllowed flags:\n  --input\n  --input-pointer\n\nInput schema summary:\n  schemaVersion=1\n  root-shape-only definition proofkit.spec-overview-claims.input.v1.root-shape; nested fields, types, and cardinalities are non-claims\n  requirementsPath equals specPackagePath plus the requirement-source filename suffix\n\nPublic contract:\n  CLI command routing, root JSON shapes, output modes, exit codes, and flags are owned by proofkit/cli-contract.v2.json.\n  Nested field semantics remain owned by native command admission.\n";
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-overview-")); binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120000, env: {...process.env, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off"},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
function invoke(input, argv = [command, "--input", "-"]) {
  const result = spawnSync(binary, argv, {input, encoding: "utf8", timeout: 10000, maxBuffer: 2 << 20});
  assert.equal(result.error, undefined); assert.equal(result.signal, null); return result;
}
function reportSemantics(input, output) {
  const claims = input.claims, known = new Set(input.requirementIds), pathFailures = [], citationFailures = [];
  if (input.overviewPath.trim() !== input.specPackagePath.trim() + "/overview.md") pathFailures.push("overviewPath must equal specPackagePath/overview.md");
  if (input.requirementsPath.trim() !== input.specPackagePath.trim() + "/requirements.v2.json") pathFailures.push("requirementsPath must equal specPackagePath/requirements.v2.json");
  for (const claim of claims) {
    if (claim.claimKind === "durable_claim" && claim.citedRequirementIds.length === 0) citationFailures.push(`durable overview claim must cite at least one requirement id: ${claim.claimId}`);
    for (const id of claim.citedRequirementIds) if (!known.has(id)) citationFailures.push(`overview claim cites unknown requirement id ${id}: ${claim.claimId}`);
    if (claim.claimKind !== "durable_claim" && claim.citedRequirementIds.length > 0) citationFailures.push(`non-durable overview claim must not carry requirement citations: ${claim.claimId}`);
  }
  const failures = [...pathFailures, ...citationFailures].sort();
  const durable = claims.filter(x => x.claimKind === "durable_claim"), cited = durable.filter(x => x.citedRequirementIds.length > 0);
  assert.equal(output.reportKind, "proofkit.spec-overview-claims"); assert.equal(output.reportId, input.boundaryId);
  assert.equal(output.schemaVersion, 1); assert.equal(output.state, failures.length ? "failed" : "passed");
  assert.deepEqual(output.summary, {citedDurableClaimCount: cited.length, claimCount: claims.length,
    durableClaimCount: durable.length, extractionRefCount: input.extractionRefs.length, failureCount: failures.length,
    nonNormativeClaimCount: claims.length - durable.length, requirementIdCount: input.requirementIds.length,
    uncitedDurableClaimCount: durable.length - cited.length});
  assert.deepEqual(output.diagnostics, [{key: "failures", value: failures}, {key: "overview", value: {
    overviewPath: input.overviewPath.trim(), requirementsPath: input.requirementsPath.trim(), specPackagePath: input.specPackagePath.trim()}}]);
  assert.deepEqual(output.ruleResults, [
    {ruleId: "proofkit.spec-overview-claims.boundary", message: "spec overview claim boundaries are validated from caller-provided extraction facts", values: pathFailures},
    {ruleId: "proofkit.spec-overview-claims.citations", message: "durable overview claims must cite known requirement ids and non-durable claims must remain non-normative", values: citationFailures},
  ].map(({values, ...rule}) => ({...rule, status: values.length ? "failed" : "passed",
    diagnostics: values.sort().map((value, i) => ({key: `failure.${String(i + 1).padStart(3, "0")}`, value}))})));
  assert.deepEqual(output.nonClaims, [...builtin, ...input.nonClaims.map(x => x.trim())].sort());
}

test("overview boundary preserves predecessor streams, process classes and native meanings", () => {
  for (const row of baseline.observations) {
    const result = invoke(row.input, row.argv);
    assert.equal(result.status, row.exitCode, row.name);
    if (row.help) {
      assert.equal(hash(predecessorHelp), row.stdoutSHA256, `${row.name}/predecessor-help`);
      const expected = predecessorHelp.replace(
        "root-shape-only definition proofkit.spec-overview-claims.input.v1.root-shape; nested fields, types, and cardinalities are non-claims",
        "structural JSON Schema definition proofkit.spec-overview-claims.input.v2.json-schema; canonicalization and semantic validity remain native admission obligations",
      ).replace("\n\nPublic contract:", "\n  root fields: boundaryId, claims[], extractionRefs[], nonClaims[], overviewPath, requirementIds[], requirementsPath, sourceId, specPackagePath\n\nPublic contract:");
      assert.equal(result.stdout, expected, `${row.name}/declared-help-delta`);
    } else assert.equal(hash(result.stdout), row.stdoutSHA256, `${row.name}/stdout`);
    assert.equal(hash(result.stderr), row.stderrSHA256, `${row.name}/stderr`);
    if (!row.report) continue;
    const raw = JSON.parse(row.input), input = row.name === "pointer" ? raw.boundary : raw;
    // The exact boundary token is checked by native stdin, never by JS rounding.
    if (!row.input.includes('"lineNumber":9223372036854775807')) assert.equal(validators.input(input), true, `${row.name}/input`);
    const output = JSON.parse(result.stdout);
    assert.equal(validators.output(output), true, `${row.name}/output`); reportSemantics(input, output);
  }
});

const at = (value, path) => path.reduce((current, key) => current[key], value);
function paths(value, path = [], rows = []) {
  rows.push({path, value});
  if (value && typeof value === "object") for (const [key, child] of Object.entries(value)) paths(child, [...path, Array.isArray(value) ? Number(key) : key], rows);
  return rows;
}
function replace(value, path, replacement) {
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = replacement; return copy;
}
test("overview nested structures reject required null type cardinality tuple and domain drift", () => {
  const input = JSON.parse(baseline.observations[0].input), output = JSON.parse(invoke(JSON.stringify(input)).stdout);
  for (const [direction, value] of [["input", input], ["output", output]]) {
    const valid = validators[direction]; assert.equal(valid(value), true);
    for (const {path, value: original} of paths(value)) {
      if (original && !Array.isArray(original) && typeof original === "object") {
        const unknown = structuredClone(value); at(unknown, path).foreign = true;
        assert.equal(valid(unknown), false, `${direction}/${path}/unknown`);
        for (const key of Object.keys(original)) {
          const missing = structuredClone(value); delete at(missing, path)[key];
          assert.equal(valid(missing), false, `${direction}/${path}/${key}/missing`);
        }
      }
      if (!path.length) continue;
      assert.equal(valid(replace(value, path, null)), false, `${direction}/${path}/null`);
      assert.equal(valid(replace(value, path, typeof original === "string" ? 0 : "wrong-type")), false, `${direction}/${path}/type`);
      if (typeof original === "string") assert.equal(valid(replace(value, path, "")), false, `${direction}/${path}/blank`);
      if (typeof original === "number") {
        assert.equal(valid(replace(value, path, -1)), false, `${direction}/${path}/negative`);
        assert.equal(valid(replace(value, path, 1.5)), false, `${direction}/${path}/fraction`);
      }
    }
  }
  for (const path of [["requirementIds"], ["extractionRefs"], ["nonClaims"], ["claims", 0, "detectedMarkers"], ["claims", 0, "nonClaims"]]) assert.equal(validators.input(replace(input, path, [])), false, `${path}/nonempty`);
  for (const path of [["claims"], ["claims", 0, "citedRequirementIds"]]) assert.equal(validators.input(replace(input, path, [])), true, `${path}/empty-admitted`);
  for (const key of ["diagnostics", "ruleResults"]) {
    assert.equal(validators.output({...output, [key]: output[key].slice(0, 1)}), false, `${key}/short`);
    assert.equal(validators.output({...output, [key]: [...output[key], output[key][0]]}), false, `${key}/long`);
    assert.equal(validators.output({...output, [key]: [...output[key]].reverse()}), false, `${key}/order`);
  }
  for (const wrong of ["foreign", " durable_claim "]) assert.equal(validators.input(replace(input, ["claims", 0, "claimKind"], wrong)), false, "kind/domain");
  for (const wrong of ["sha256:" + "A".repeat(64), "sha256:" + "0".repeat(63), "sha256:" + "0".repeat(64) + "\n"]) assert.equal(validators.input(replace(input, ["claims", 0, "lineDigest"], wrong)), false, "digest/domain");
  assert.equal(validators.input(replace(input, ["claims", 0, "lineNumber"], 0)), false, "lineNumber/zero");
  assert.equal(validators.input(replace(input, ["requirementIds", 0], "OTHER-001")), false, "requirement/prefix");
  assert.equal(validators.input({...input, boundaryId: "a".repeat(257)}), false, "id/bound");
  assert.equal(validators.input({...input, boundaryId: "foreign/id"}), false, "id/grammar");
  for (const path of [["schemaVersion"], ["reportKind"], ["state"], ["ruleResults", 0, "ruleId"], ["ruleResults", 0, "message"], ["ruleResults", 0, "status"]]) {
    const original = at(output, path);
    assert.equal(validators.output(replace(output, path, typeof original === "number" ? 2 : "foreign-value")), false, `${path}/fixed-domain`);
  }
  for (const key of ["requirementIdCount", "extractionRefCount"]) assert.equal(validators.output(replace(output, ["summary", key], 0)), false, `${key}/positive`);
  assert.equal(validators.output({...output, nonClaims: output.nonClaims.filter(x => x !== builtin[0])}), false, "builtin/required");
  const failed = JSON.parse(invoke(baseline.observations.find(x => x.name === "unknown-citation").input).stdout);
  assert.equal(validators.output(replace(failed, ["ruleResults", 1, "diagnostics", 0, "key"], "failure.1")), false, "failure/key-domain");
});

test("overview structural validity does not replace path citation count ordering or privacy semantics", () => {
  const valid = JSON.parse(baseline.observations[0].input);
  for (const name of ["both-paths-wrong", "uncited-durable", "unknown-citation", "example_or_rationale-cited", "quoted_or_code-cited", "section_heading-cited"]) {
    const row = baseline.observations.find(x => x.name === name), input = JSON.parse(row.input);
    assert.equal(validators.input(input), true); const result = invoke(row.input);
    assert.equal(result.status, 1); assert.equal(JSON.parse(result.stdout).state, "failed");
  }
  for (const name of ["duplicate-claim", "unsorted-requirements", "duplicate-marker-after-trim", "unsafe-path"]) {
    const row = baseline.observations.find(x => x.name === name);
    assert.equal(validators.input(JSON.parse(row.input)), true); const result = invoke(row.input);
    assert.equal(result.status, 1); assert.equal(result.stdout, ""); assert.notEqual(result.stderr, "");
  }
  const overlapRow = baseline.observations.find(x => x.name === "builtin-overlap");
  const overlap = JSON.parse(invoke(overlapRow.input).stdout);
  assert.equal(validators.output(overlap), true, "builtin-overlap/multiplicity"); assert.equal(overlap.nonClaims.filter(x => x === builtin[3]).length, 2);
  const output = JSON.parse(invoke(JSON.stringify(valid)).stdout);
  for (const changed of [{...output, state: "failed"}, replace(output, ["summary", "claimCount"], 2)]) {
    assert.equal(validators.output(changed), true); assert.throws(() => reportSemantics(valid, changed), assert.AssertionError);
  }
  const mixed = structuredClone(valid);
  mixed.claims = ["section_heading", "durable_claim", "quoted_or_code", "example_or_rationale"].map((claimKind, i) => ({
    ...structuredClone(valid.claims[0]), claimId: `claim.mixed_${i}`, claimKind,
    citedRequirementIds: claimKind === "durable_claim" ? ["REQ-EXAMPLE-001"] : [],
  }));
  assert.equal(validators.input(mixed), true);
  const mixedResult = invoke(JSON.stringify(mixed)); assert.equal(mixedResult.status, 0);
  const mixedOutput = JSON.parse(mixedResult.stdout); assert.equal(validators.output(mixedOutput), true);
  reportSemantics(mixed, mixedOutput);
  const sensitive = ["api_", "key=", "synthetic-fixture-value"].join("");
  for (const path of [["nonClaims", 0], ["claims", 0, "dispositionRationale"], ["claims", 0, "detectedMarkers", 0], ["claims", 0, "nonClaims", 0]]) {
    const input = replace(valid, path, sensitive); assert.equal(validators.input(input), true);
    const result = invoke(JSON.stringify(input)); assert.equal(result.status, 1); assert.equal(result.stdout, "");
    assert.equal(result.stderr.includes("synthetic-fixture-value"), false); assert.notEqual(result.stderr, "");
  }
});
