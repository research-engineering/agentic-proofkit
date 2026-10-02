import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_BOUNDARY_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const corpus = JSON.parse(readFileSync(new URL("internal/app/testdata/boundary-native-observations.json", root), "utf8"));
assert.equal(corpus.length, 18);
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const families = [
  {command: "custom-rule-boundary", list: "rules", id: "ruleId", variableRule: 1, emptyArrays: ["commandRefs"], enums: {
    boundaryRole: ["local_diagnostics_only"], credentialPolicy: ["live", "local_secret", "none"],
    genericDecisionEffect: ["downgrade", "no_downgrade", "satisfy"], genericFindingEffect: ["append_only", "downgrade", "suppress"],
    networkPolicy: ["external", "none"], severity: ["error", "info", "warning"],
    "remediation.kind": ["command_ref", "documentation_ref", "human_review"], "useLimit.scope": ["module_scoped", "package_scoped", "profile_scoped"],
  }},
  {command: "document-lifecycle-boundary", list: "documents", id: "documentId", variableRule: 0, emptyArrays: ["freshnessCheckRefs", "sourceRefs"], enums: {
    authorityRole: ["durable_meaning", "generated_lookup", "historical_evidence", "navigation", "open_work_truth", "presentation_only", "proof_route", "temporary_pr_reasoning", "workflow_memory"],
    kind: ["context", "decision_record", "design_doc", "generated_lookup", "implementation_plan", "proof_binding", "rendered_view", "requirement_records", "router", "skill", "spec_overview", "work_ledger"],
    lifecycleState: ["active_pr_local", "archived_historical", "current", "merged_retained"],
    routingRole: ["historical_reference", "lookup_projection", "none", "owner_surface", "presentation_view", "primary_router", "pr_local_input", "restore_surface"],
  }},
  {command: "rendered-artifact-freshness", list: "artifacts", id: "artifactId", variableRule: 0, emptyArrays: [], enums: {
    artifactFormat: ["html", "json", "markdown", "text"], artifactKind: ["generated_lookup", "rendered_view"],
    authority: ["canonical_source", "durable_meaning", "lookup_only", "presentation_only"],
  }},
].map(family => ({...family, rows: corpus.filter(row => row.command === family.command), ...Object.fromEntries(["input", "output"].map(direction => {
  const definition = contract.contractDefinitions.find(row => row.definitionId === `proofkit.${family.command}.${direction}.v1.json-schema`);
  assert.ok(definition, `${family.command}/${direction}`);
  return [direction, ajv.compile(definition.fieldTree.variants[0].schema)];
}))}));
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-boundary-schema-"));
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
  if (expected === "rejected") {
    assert.equal(result.status, 1, label);
    assert.equal(result.stdout, "", label);
    assert.notEqual(result.stderr, "", label);
    return result;
  }
  assert.ok(result.status === 0 || result.status === 1, label);
  assert.equal(result.stderr, "", `${label}: ${result.stderr}`);
  const output = JSON.parse(result.stdout);
  assert.equal(output.reportKind, `proofkit.${family.command}`, label);
  assert.equal(output.state, result.status === 0 ? "passed" : "failed", label);
  if (expected) assert.equal(output.state, expected, label);
  assert.equal(family.output(output), true, `${label}: ${ajv.errorsText(family.output.errors)}`);
  return output;
}
function pair(family, input, expected, label) {
  assert.equal(family.input(input), expected !== "rejected", `${label}: ${ajv.errorsText(family.input.errors)}`);
  return native(family, input, expected, label);
}
function at(value, path) { return path.reduce((record, key) => record[key], value); }
function paths(value, predicate, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [...(predicate(value) ? [path] : []), ...Object.entries(value).flatMap(([key, child]) => paths(child, predicate, [...path, key]))];
}
const objects = value => paths(value, value => !Array.isArray(value));
const arrays = value => paths(value, Array.isArray);

test("pre-schema boundary carriers preserve actual native observations", () => {
  for (const family of families) {
    assert.equal(family.rows.length, 6);
    for (const row of family.rows) {
      const result = pair(family, row.input, row.output?.state || "rejected", `${family.command}/${row.case}`);
      if (row.output) assert.deepEqual(result, row.output);
      else assert.equal(result.stderr, row.stderr);
    }
  }
});

test("every input member is closed, required, nonnull and precisely typed", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of objects(baseline)) {
      const unknown = structuredClone(baseline);
      at(unknown, path).unexpected = true;
      pair(family, unknown, "rejected", `${family.command}/${path}/unknown`);
      for (const [key, value] of Object.entries(at(baseline, path))) {
        for (const mode of ["missing", "null", "wrong-type", ...(typeof value === "string" ? ["empty"] : [])]) {
          const input = structuredClone(baseline), record = at(input, path);
          if (mode === "missing") delete record[key];
          if (mode === "null") record[key] = null;
          if (mode === "wrong-type") record[key] = typeof value === "string" ? 0 : "wrong-type";
          if (mode === "empty") record[key] = "";
          pair(family, input, "rejected", `${family.command}/${path}/${key}/${mode}`);
        }
      }
    }
  }
});

test("array cardinality and duplicate guards match each native owner", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of arrays(baseline)) {
      const empty = structuredClone(baseline);
      at(empty, path).length = 0;
      pair(family, empty, family.emptyArrays.includes(path.at(-1)) ? undefined : "rejected", `${family.command}/${path}/empty`);
      if (at(baseline, path).length) {
        const duplicate = structuredClone(baseline);
        at(duplicate, path).push(structuredClone(at(duplicate, path)[0]));
        pair(family, duplicate, "rejected", `${family.command}/${path}/duplicate`);
      }
    }
    const duplicateID = structuredClone(baseline), row = structuredClone(duplicateID[family.list][0]);
    row.nonClaims = ["Different metadata still cannot duplicate an identity."];
    if (family.command === "rendered-artifact-freshness") row.artifactPath = "docs/different.md";
    duplicateID[family.list].push(row);
    assert.equal(family.input(duplicateID), true, "identity-key uniqueness is native, not uniqueItems");
    native(family, duplicateID, "rejected", `${family.command}/same-id-different-row`);
  }
});

test("native normalization preserves distinct text, path and glob policies", () => {
  for (const family of families) {
    const input = structuredClone(family.rows[0].input);
    input.nonClaims = ["  Caller context is advisory.  "];
    assert.equal(family.input(input), true);
    native(family, input, family.command === "rendered-artifact-freshness" ? "passed" : "rejected", `${family.command}/text-normalization`);
    const unsorted = structuredClone(family.rows[0].input);
    unsorted.nonClaims = ["Second context.", "First context."];
    assert.equal(family.input(unsorted), true);
    native(family, unsorted, "rejected", `${family.command}/text-order`);
  }
  const custom = structuredClone(families[0].rows[0].input);
  custom.rules[0].affectedPathGlobs = [" docs/** "];
  pair(families[0], custom, "passed", "trimmed-glob");
  const fresh = structuredClone(families[2].rows[0].input);
  fresh.nonClaims = [" Rendered artifact freshness reports do not read rendered artifacts or source files. "];
  assert.equal(families[2].input(fresh), true);
  native(families[2], fresh, "rejected", "normalized-builtin-collision");
});

test("array elements have independent scalar, object and tuple-position controls", () => {
  for (const family of families) {
    const baseline = family.rows[0].input;
    for (const path of arrays(baseline)) {
      const recordItems = path.length === 1 && path[0] === family.list;
      for (const value of [null, 0, true, [], "", ...(recordItems ? [] : [{}])]) {
        const input = structuredClone(baseline);
        at(input, path).push(value);
        pair(family, input, "rejected", `${family.command}/${path}/item/${JSON.stringify(value)}`);
      }
    }
    for (const row of family.rows.filter(row => row.output)) for (const path of arrays(row.output)) {
      const tuple = path.length === 1 && ["diagnostics", "ruleResults"].includes(path[0]);
      const textItems = path[0] === "nonClaims" || (path[0] === "diagnostics" && path.at(-1) === "value" && row.output.diagnostics[path[1]].key === "failures");
      for (const value of [null, 0, true, [], "", ...(textItems ? [{}] : [])]) {
        // Append to homogeneous arrays so builtin-presence guards stay satisfied.
        // Fixed tuples require replacement at each existing position instead.
        for (const index of tuple ? at(row.output, path).map((_, index) => index) : [at(row.output, path).length]) {
          const output = structuredClone(row.output);
          at(output, path)[index] = value;
          assert.equal(family.output(output), false, `${family.command}/${path}/${index}/item/${JSON.stringify(value)}`);
        }
      }
    }
  }
});

test("boolean false and nonempty optional arrays remain native-valid domains", () => {
  const custom = families[0];
  for (const flag of ["secretRedaction", "stableFindingIds", "stableOrdering"]) {
    const input = structuredClone(custom.rows[0].input);
    input.rules[0].deterministicOutput[flag] = false;
    pair(custom, input, "failed", `admitted-false/${flag}`);
  }
  const document = families[1], input = structuredClone(document.rows[0].input);
  input.documents[0].sourceRefs = ["docs/context.json"];
  pair(document, input, "passed", "nonempty-document-sourceRefs");
  const duplicate = structuredClone(input);
  duplicate.documents[0].sourceRefs.push("docs/context.json");
  pair(document, duplicate, "rejected", "duplicate-document-sourceRefs");
  const wrongItem = structuredClone(input);
  wrongItem.documents[0].sourceRefs = [true];
  pair(document, wrongItem, "rejected", "mistyped-document-sourceRefs");
});

test("schema constants, integer domains and upper bounds are observable independently", () => {
  for (const family of families) {
    for (const version of [0, 2, 1.5]) {
      const input = structuredClone(family.rows[0].input);
      input.schemaVersion = version;
      pair(family, input, "rejected", `${family.command}/schema-version/${version}`);
    }
    const baseline = family.rows[0].output;
    for (const [field, value] of Object.entries(baseline.summary)) for (const invalid of [value + 0.5, 1e20]) {
      const output = structuredClone(baseline);
      output.summary[field] = invalid;
      assert.equal(family.output(output), false, `${family.command}/${field}/integer-domain/${invalid}`);
    }
  }
  for (const invalid of [1.5, 1e20]) {
    const input = structuredClone(families[0].rows[0].input);
    input.rules[0].useLimit.maxAffectedPathGlobs = invalid;
    pair(families[0], input, "rejected", `positive-integer-domain/${invalid}`);
  }
});

test("identifier sites preserve their independent ASCII and 256-byte domain", () => {
  const inputPaths = {
    "custom-rule-boundary": [["boundaryId"], ["rules", 0, "ruleId"], ["rules", 0, "namespace"], ["rules", 0, "inputArtifactKinds", 0]],
    "document-lifecycle-boundary": [["boundaryId"], ["documents", 0, "documentId"]],
    "rendered-artifact-freshness": [["freshnessSetId"], ["artifacts", 0, "artifactId"], ["artifacts", 0, "generationScopeId"], ["artifacts", 0, "rendererId"]],
  };
  for (const family of families) {
    for (const path of inputPaths[family.command]) {
      for (const value of ["a", "a".repeat(256), "a".repeat(257), "invalid id", "7invalid"]) {
        const input = structuredClone(family.rows[0].input);
        at(input, path.slice(0, -1))[path.at(-1)] = value;
        pair(family, input, value === "a" || value.length === 256 ? undefined : "rejected", `${family.command}/${path}/identifier/${value.length}`);
      }
    }
    const outputPaths = [["reportId"], ...(family.command === "rendered-artifact-freshness" ? ["artifactId", "generationScopeId", "rendererId"].map(key => ["diagnostics", 0, "value", 0, key]) : [])];
    for (const path of outputPaths) for (const value of ["a", "a".repeat(256), "a".repeat(257), "invalid id", "7invalid"]) {
      const output = structuredClone(family.rows[0].output);
      at(output, path.slice(0, -1))[path.at(-1)] = value;
      assert.equal(family.output(output), value === "a" || value.length === 256, `${family.command}/${path}/output-identifier/${value.length}`);
    }
  }
});

test("independent finite vocabularies preserve admitted semantic failure states", () => {
  for (const family of families) for (const [field, values] of Object.entries(family.enums)) {
    const path = field.split("."), key = path.pop();
    for (const value of values) {
      const input = structuredClone(family.rows[0].input);
      at(input[family.list][0], path)[key] = value;
      pair(family, input, undefined, `${family.command}/${field}/${value}`);
    }
    for (const value of ["unsupported", ` ${values[0]} `, values[0].toUpperCase()]) {
      const input = structuredClone(family.rows[0].input);
      at(input[family.list][0], path)[key] = value;
      pair(family, input, "rejected", `${family.command}/${field}/invalid-enum`);
    }
  }
});

test("digest grammar and canonical numeric framing have independent controls", () => {
  const fresh = families[2];
  for (const field of ["currentArtifactDigest", "currentGenerationScopeDigest", "currentRendererDigest", "currentSourceDigest", "recordedArtifactDigest", "recordedGenerationScopeDigest", "recordedRendererDigest", "recordedSourceDigest"]) {
    for (const invalid of ["a".repeat(64), "sha256:" + "A".repeat(64), "sha256:" + "a".repeat(63), "sha256:" + "a".repeat(65), "sha256:" + "a".repeat(64) + "\n"]) {
      const input = structuredClone(fresh.rows[0].input);
      input.artifacts[0][field] = invalid;
      pair(fresh, input, "rejected", `${field}/invalid-digest`);
    }
  }
  for (const family of families) for (const token of ["0", "2", "1.0", "1e0", '"1"']) {
    const wire = JSON.stringify(family.rows[0].input).replace('"schemaVersion":1', `"schemaVersion":${token}`);
    native(family, wire, "rejected", `${family.command}/version-token/${token}`);
  }
  const custom = families[0];
  for (const token of ["1", "9223372036854775807", "0", "-1", "1.0", "1e0", "9223372036854775808", '"2"']) {
    const wire = JSON.stringify(custom.rows[0].input).replace('"maxAffectedPathGlobs":2', `"maxAffectedPathGlobs":${token}`);
    native(custom, wire, token === "1" || token === "9223372036854775807" ? "passed" : "rejected", `native-int/${token}`);
  }
  for (const value of [0, -1]) {
    const input = structuredClone(custom.rows[0].input);
    input.rules[0].useLimit.maxAffectedPathGlobs = value;
    pair(custom, input, "rejected", `integer-lower-bound/${value}`);
  }
});

test("every output member, diagnostic position and rule position is closed", () => {
  for (const family of families) for (const row of family.rows.filter(row => row.output)) {
    assert.equal(family.output(row.output), true, "negative output controls require a valid precursor");
    for (const path of objects(row.output)) {
      const extra = structuredClone(row.output);
      at(extra, path).unexpected = true;
      assert.equal(family.output(extra), false, `${family.command}/${row.case}/${path}/extra`);
      for (const key of Object.keys(at(row.output, path))) for (const mode of ["missing", "null", "wrong-type", ...(typeof at(row.output, path)[key] === "string" ? ["empty"] : [])]) {
        const output = structuredClone(row.output), record = at(output, path);
        if (mode === "missing") delete record[key];
        if (mode === "null") record[key] = null;
        if (mode === "wrong-type") record[key] = typeof record[key] === "string" ? 42 : "wrong-type";
        if (mode === "empty") record[key] = "";
        assert.equal(family.output(output), false, `${family.command}/${row.case}/${path}/${key}/${mode}`);
      }
    }
    for (const field of ["diagnostics", "ruleResults"]) {
      const reversed = structuredClone(row.output);
      reversed[field].reverse();
      if (reversed[field].length > 1) assert.equal(family.output(reversed), false, `${family.command}/${field}/reversed`);
      const extra = structuredClone(row.output);
      extra[field].push(structuredClone(extra[field][0]));
      assert.equal(family.output(extra), false, `${family.command}/${field}/extra-position`);
    }
    const boundary = structuredClone(row.output);
    boundary.ruleResults[1 - family.variableRule].status = "failed";
    assert.equal(family.output(boundary), false, `${family.command}/fixed-boundary-status`);
    for (const field of Object.keys(row.output.summary)) {
      const negative = structuredClone(row.output);
      negative.summary[field] = -1;
      assert.equal(family.output(negative), false, `${family.command}/${field}/negative`);
    }
    const zero = structuredClone(row.output);
    const count = {"custom-rule-boundary": "customRuleCount", "document-lifecycle-boundary": "documentCount", "rendered-artifact-freshness": "artifactCount"}[family.command];
    zero.summary[count] = 0;
    assert.equal(family.output(zero), false, `${family.command}/nonempty-count`);
    for (const claim of row.output.nonClaims.filter(value => /^(?:Custom-rule|Document lifecycle|Rendered artifact)/.test(value))) {
      const missing = structuredClone(row.output);
      missing.nonClaims = missing.nonClaims.filter(value => value !== claim);
      while (missing.nonClaims.length < row.output.nonClaims.length) missing.nonClaims.push(`Neutral replacement claim ${missing.nonClaims.length}.`);
      assert.equal(family.output(missing), false, `${family.command}/missing-builtin-claim`);
    }
  }
});

test("native-only privacy and path constraints do not leak rejected caller text", () => {
  const secret = "Authorization: Bearer fixture-not-a-credential";
  for (const family of families) {
    const input = structuredClone(family.rows[0].input);
    input.nonClaims = [secret];
    assert.equal(family.input(input), true, "schema does not implement the shared secret classifier");
    const rejected = native(family, input, "rejected", `${family.command}/secret-shaped-text`);
    assert.equal(rejected.stderr.includes(secret), false);
    const unsafe = structuredClone(family.rows[0].input);
    const field = family.command === "custom-rule-boundary" ? "outputSchemaRef" : family.command === "document-lifecycle-boundary" ? "path" : "artifactPath";
    unsafe[family.list][0][field] = "../escape.json";
    assert.equal(family.input(unsafe), true, "path normalization stays native");
    native(family, unsafe, "rejected", `${family.command}/unsafe-path`);
  }
});

test("more than 999 real failures preserve the minimum-width diagnostic grammar", () => {
  const family = families[2], input = structuredClone(family.rows[0].input);
  input.artifacts = Array.from({length: 200}, (_, index) => ({...structuredClone(input.artifacts[0]),
    artifactId: `fixture.view.item${String(index).padStart(4, "0")}`, artifactPath: `docs/view/item${index}.md`,
    authority: "canonical_source", currentRendererVersion: "renderer-v2",
    currentArtifactDigest: "sha256:" + "b".repeat(64), currentGenerationScopeDigest: "sha256:" + "b".repeat(64),
    currentRendererDigest: "sha256:" + "b".repeat(64), currentSourceDigest: "sha256:" + "b".repeat(64),
  }));
  const output = pair(family, input, "failed", "large-failure-array");
  assert.equal(output.summary.failureCount, 1200);
  assert.equal(output.ruleResults[0].diagnostics[999].key, "failure.1000");
  const malformed = structuredClone(output);
  malformed.ruleResults[0].diagnostics[999].key = "failure.10";
  assert.equal(family.output(malformed), false);
});
