import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const contract = JSON.parse(fs.readFileSync(new URL("../proofkit/cli-contract.v2.json", import.meta.url), "utf8"));
const observations = JSON.parse(fs.readFileSync(new URL("../internal/app/testdata/spec-tree-native-observations.json", import.meta.url), "utf8"));
const validators = {};
for (const [kind, id] of [
  ["report", "proofkit.requirement-spec-tree.output.v1.json-schema"],
  ["view", "proofkit.requirement-spec-tree-view.output.v2.json-schema"],
]) {
  const definition = contract.contractDefinitions.find(row => row.definitionId === id);
  assert(definition, `missing owner structure ${id}`);
  validators[kind] = new Ajv2020({strict: false, validateFormats: false}).compile(definition.fieldTree.variants[0].schema);
}
const baseline = kind => observations.find(row => row.kind === kind && row.case === "valid").output;

function mutateValue(original, pointer, value, remove = false) {
  if (pointer === "") return structuredClone(value);
  const candidate = structuredClone(original);
  const parts = pointer.split("/").slice(1);
  const key = parts.pop();
  const parent = parts.reduce((object, part) => object[part], candidate);
  if (remove) delete parent[key]; else parent[key] = value;
  return candidate;
}
const mutated = (kind, pointer, value, remove = false) => mutateValue(baseline(kind), pointer, value, remove);

test("spec tree schemas accept independent pre-structure native output observations", () => {
  assert.equal(observations.length, 8);
  assert.equal(observations.filter(row => row.output !== undefined).length, 5);
  for (const row of observations) {
    if (row.output === undefined) continue;
    assert.equal(validators[row.kind](row.output), true, `${row.kind}/${row.case}: ${JSON.stringify(validators[row.kind].errors)}`);
  }
});

test("every observed output field retains independent required, type, null and closed-object guards", () => {
  for (const row of observations.filter(row => row.output !== undefined)) {
    function inspect(value, pointer) {
      const check = candidate => assert.equal(validators[row.kind](candidate), false, `${row.kind}/${row.case}${pointer}`);
      const field = pointer.split("/").at(-1);
      if (pointer !== "") {
        check(mutateValue(row.output, pointer, null));
        const wrong = Array.isArray(value) ? {} : typeof value === "object" ? [] : typeof value === "string" ? 0 : "wrong type";
        check(mutateValue(row.output, pointer, wrong));
        if (typeof value === "string" && value !== "" && !pointer.endsWith("/parentNodeId")) {
          check(mutateValue(row.output, pointer, ""));
        }
        if (typeof value === "string") {
          if (/(?:Id|Ids\/\d+)$/.test(pointer)) {
            check(mutateValue(row.output, pointer, "bad id"));
            check(mutateValue(row.output, pointer, "a".repeat(257)));
          }
          if (["reportKind", "viewKind", "authority", "callerAnnotationAuthority", "key", "nodeKind", "overlayKind", "refKind", "sourceRole", "sourceRefKind", "digestAlgorithm", "status", "state"].includes(field) || /^\/nonClaims\/\d+$/.test(pointer) || /^\/diagnostics\/0\/value\/\d+$/.test(pointer)) {
            check(mutateValue(row.output, pointer, "foreign"));
          }
          if (["currentSourceDigest", "recordedSourceDigest", "refDigest"].includes(field)) {
            check(mutateValue(row.output, pointer, "sha256:bad"));
          }
        }
        if (field === "schemaVersion") check(mutateValue(row.output, pointer, 999));
        if (field === "staleDigest") check(mutateValue(row.output, pointer, true));
        if (field === "depth") {
          check(mutateValue(row.output, pointer, 0));
          check(mutateValue(row.output, pointer, 1.5));
          check(mutateValue(row.output, pointer, 513));
        }
        if (field === "displayOrder") {
          check(mutateValue(row.output, pointer, 0));
          check(mutateValue(row.output, pointer, 1.5));
        }
      }
      if (Array.isArray(value)) {
        value.forEach((child, i) => inspect(child, `${pointer}/${i}`));
      } else if (value !== null && typeof value === "object") {
        check(mutateValue(row.output, pointer, {...value, unknown: true}));
        for (const [name, child] of Object.entries(value)) {
          const childPointer = `${pointer}/${name}`;
          check(mutateValue(row.output, childPointer, null, true));
          inspect(child, childPointer);
        }
      }
    }
    inspect(row.output, "");
  }
});

test("spec tree summary bounds and scalar types cannot be weakened unnoticed", () => {
  const bounds = {
    report: {nodeCount: [1, 4096], edgeCount: [0, 8192], overlayCount: [0, 4096], maxDepth: [0, 512], sourceRefCount: [1, null], visitedNodeCount: [0, 8193], failureCount: [0, null], staleSourceRefCount: [0, null], callerAnnotationCount: [0, null]},
    view: {nodeCount: [1, 4096], edgeCount: [0, 8192], overlayCount: [0, 4096], maxDepth: [1, 512], sourceRefCount: [1, null], staleSourceRefCount: [0, 0], callerAnnotationCount: [0, null]},
  };
  for (const [kind, counters] of Object.entries(bounds)) {
    for (const [name, [min, max]] of Object.entries(counters)) {
      const pointer = `${kind === "report" ? "/summary" : ""}/${name}`;
      for (const value of [null, "1", true, 0.5, min - 1, ...(max === null ? [] : [max + 1])]) {
        assert.equal(validators[kind](mutated(kind, pointer, value)), false, `${kind}${pointer}: ${JSON.stringify(value)}`);
      }
      assert.equal(validators[kind](mutated(kind, pointer, null, true)), false, `${kind}${pointer}: absent`);
    }
  }
});

test("spec tree nested required, null, enum, cardinality and tuple guards are independently observable", () => {
  const cases = [
    ["report", "/reportKind", "foreign"], ["report", "/schemaVersion", 2],
    ["report", "/diagnostics/4/value/0/nodeKind", "foreign"],
    ["report", "/diagnostics/4/value/0/sourceRefIds", []],
    ["report", "/diagnostics/4/value/0/sourceRefIds", null],
    ["report", "/diagnostics/4/value/0/displayOrder", 0],
    ["report", "/diagnostics/4/value/0/displayOrder", "1"],
    ["report", "/diagnostics/0/key", "wrong"],
    ["report", "/ruleResults/0/status", "skipped"],
    ["report", "/ruleResults/3/diagnostics", [{key: "failures", value: []}]],
    ["report", "/nonClaims/0", "foreign"],
    ["view", "/authority", "proof"], ["view", "/callerAnnotationAuthority", "trusted"],
    ["view", "/nodes", []], ["view", "/nodes/0/parentNodeId", null],
    ["view", "/nodes/0/depth", 0], ["view", "/nodes/0/depth", 513],
    ["view", "/nodes/0/displayOrder", 0], ["view", "/nodes/0/nodeKind", "foreign"],
    ["view", "/nodes/0/sourceRefs", []],
    ["view", "/nodes/2/sourceRefs/0/staleDigest", true],
    ["view", "/nodes/2/sourceRefs/0/digestAlgorithm", "md5"],
    ["view", "/nodes/2/sourceRefs/0/sourceRole", "foreign"],
    ["view", "/nodes/2/sourceRefs/0/currentSourceDigest", "sha256:bad"],
    ["view", "/nodes/2/sourceRefs/0/sourceId", "foreign"],
  ];
  for (const [kind, pointer, value] of cases) {
    assert.equal(validators[kind](mutated(kind, pointer, value)), false, `${kind}${pointer}`);
  }
  for (const [kind, pointer] of [
    ["report", "/diagnostics/4/value/0/label"], ["report", "/ruleResults/0/diagnostics/0/value"],
    ["view", "/nodes/0/parentNodeId"], ["view", "/nodes/2/sourceRefs/0/staleDigest"],
    ["view", "/nodes/2/sourceRefs/0/currentSourceDigest"],
  ]) {
    assert.equal(validators[kind](mutated(kind, pointer, null, true)), false, `${kind}${pointer}: absent`);
  }
  for (const kind of ["report", "view"]) {
    assert.equal(validators[kind]({...structuredClone(baseline(kind)), unknown: true}), false);
  }
});

test("spec tree structure preserves intentional empty root parent and semantic non-claims", () => {
  assert.equal(baseline("view").nodes[0].parentNodeId, "");
  assert.equal(validators.view(mutated("view", "/nodes/0/parentNodeId", "")), true);
  assert.equal(validators.report(observations.find(row => row.kind === "report" && row.case === "failed").output), true);
  const failed = observations.find(row => row.kind === "report" && row.case === "failed").output;
  assert.equal(validators.report(mutateValue(failed, "/ruleResults/0/diagnostics/0/value/0", "foreign")), true);
  // Referential truth is not schema validity: native validation remains owner.
  assert.equal(validators.view(mutated("view", "/nodes/1/parentNodeId", "missing")), true);
});

test("spec tree fixed native tuples reject empty, shortened and extended arrays", () => {
  for (const [kind, pointer, length] of [
    ["report", "/diagnostics", 6], ["report", "/ruleResults", 4],
    ["report", "/diagnostics/0/value", 8],
    ["report", "/ruleResults/0/diagnostics", 1], ["report", "/ruleResults/1/diagnostics", 1],
    ["report", "/ruleResults/2/diagnostics", 1], ["report", "/nonClaims", 8],
    ["view", "/nonClaims", 13],
  ]) {
    const value = pointer.split("/").slice(1).reduce((object, part) => object[part], baseline(kind));
    assert.equal(value.length, length);
    for (const replacement of [[], value.slice(0, -1), [...value, value.at(-1)]]) {
      assert.equal(validators[kind](mutated(kind, pointer, replacement)), false, `${kind}${pointer}: tuple length`);
    }
  }
});

test("spec tree bounded arrays retain native minimum and maximum cardinalities", () => {
  for (const [kind, pointer, min, max] of [
    ["report", "/diagnostics/4/value", 1, 4096], ["report", "/diagnostics/2/value", 0, 8192],
    ["report", "/diagnostics/5/value", 0, 4096], ["view", "/nodes", 1, 4096],
    ["view", "/nodes/1/overlays", 0, 4096],
  ]) {
    const values = pointer.split("/").slice(1).reduce((object, part) => object[part], baseline(kind));
    assert(values.length > 0, `${kind}${pointer}: native representative`);
    if (min > 0) assert.equal(validators[kind](mutated(kind, pointer, [])), false, `${kind}${pointer}: minimum`);
    assert.equal(validators[kind](mutated(kind, pointer, Array(max + 1).fill(values[0]))), false, `${kind}${pointer}: maximum`);
  }
});

test("spec tree schemas accept native failed reports visiting undeclared child IDs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proofkit-spec-tree-native-"));
  const binary = path.join(dir, "agentic-proofkit");
  const env = {...process.env};
  for (const key of ["OPENAI_API_KEY", "OPENROUTER_API_KEY", "GH_TOKEN", "GITHUB_TOKEN", "NODE_AUTH_TOKEN", "NPM_TOKEN"]) delete env[key];
  try {
    // Private witness commands execute from the repository root.
    const build = spawnSync("go", ["build", "-buildvcs=false", "-o", binary, "./cmd/agentic-proofkit"], {env, encoding: "utf8", timeout: 60000, maxBuffer: 2 << 20});
    assert.equal(build.error, undefined);
    assert.equal(build.signal, null);
    assert.equal(build.status, 0, build.stderr);
    const original = observations.find(row => row.kind === "report" && row.case === "valid").input;
    for (const count of [0, 4096, 8192]) {
      const input = structuredClone(original);
      input.nodes = input.nodes.filter(node => node.nodeId === input.rootNodeId);
      input.overlays = [];
      input.edges = Array.from({length: count}, (_, i) => ({parentNodeId: input.rootNodeId, childNodeId: `missing${String(i).padStart(5, "0")}`}));
      const run = spawnSync(binary, ["requirement-spec-tree", "--input", "-"], {env, input: JSON.stringify(input), encoding: "utf8", timeout: 60000, maxBuffer: 32 << 20});
      assert.equal(run.error, undefined);
      assert.equal(run.signal, null);
      assert.equal(run.status, count === 0 ? 0 : 1);
      assert.equal(run.stderr, "");
      const output = JSON.parse(run.stdout);
      assert.equal(output.state, count === 0 ? "passed" : "failed");
      assert.equal(output.summary.nodeCount, 1);
      assert.equal(output.summary.edgeCount, count);
      assert.equal(output.summary.visitedNodeCount, count + 1);
      assert.equal(validators.report(output), true, JSON.stringify(validators.report.errors));
    }
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});
