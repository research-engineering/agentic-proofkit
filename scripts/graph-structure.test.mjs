import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const contract = JSON.parse(fs.readFileSync(new URL("../proofkit/cli-contract.v2.json", import.meta.url), "utf8"));
const observations = JSON.parse(fs.readFileSync(new URL("../internal/app/testdata/graph-native-observations.json", import.meta.url), "utf8"));
const definition = contract.contractDefinitions.find(row => row.definitionId === "proofkit.requirement-traceability-graph.output.v1.json-schema");
assert(definition, "missing native graph output structure");
const validate = new Ajv2020({strict: false, validateFormats: false}).compile(definition.fieldTree.variants[0].schema);
const baseline = observations.find(row => row.case === "all-levels-verified").output;

function mutate(original, pointer, value, remove = false) {
  const result = structuredClone(original);
  const parts = pointer.split("/").slice(1);
  const key = parts.pop();
  const parent = parts.reduce((record, name) => record[name], result);
  if (remove) delete parent[key]; else parent[key] = value;
  return result;
}
function reject(original, pointer, value, remove = false) {
  const kind = remove ? "absent" : Array.isArray(value) ? `array(${value.length})` : typeof value;
  assert.equal(validate(mutate(original, pointer, value, remove)), false, `${pointer}: ${kind}`);
}
const nodeFields = {
  specification_coverage: ["evidencePlane", "kind", "label", "nodeId", "sourceId"],
  proof_coverage: ["evidencePlane", "kind", "label", "nodeId", "sourceId", "requirementId", "scenarioId", "witnessId", "witnessKind", "witnessPath"],
  native_execution_coverage: ["evidencePlane", "kind", "label", "nodeId", "sourceId", "authorityClass", "currentnessState", "producerId", "state"],
  code_traceability: ["evidencePlane", "kind", "label", "nodeId", "sourceId", "currentnessState", "sourceDigest"],
};
const rootFields = ["edgeCount", "edges", "graphId", "graphKind", "nodeCount", "nodes", "nonClaims", "schemaVersion", "snapshotId"];

test("graph structure accepts the complete independent predecessor carrier corpus", () => {
  assert.deepEqual(observations.map(row => row.case), ["spec-proof", "empty-topology", "all-levels-verified", "all-levels-unverified", "failed-evidence", "skipped-evidence", "unavailable-evidence", "int64-range"]);
  for (const row of observations) assert.equal(validate(row.output), true, `${row.case}: ${JSON.stringify(validate.errors)}`);
  assert.deepEqual([...new Set(baseline.nodes.map(node => node.evidencePlane))].sort(), Object.keys(nodeFields).sort());
  assert.deepEqual(baseline.nodes.filter(node => node.evidencePlane === "code_traceability").map(node => node.kind).sort(), ["file", "module", "package", "repository", "source_range", "symbol"]);
  // These JS projections are not an oracle for exact integer token identity.
});

test("graph root fields have independent required, scalar and closed-object guards", () => {
  assert.deepEqual(Object.keys(baseline).sort(), rootFields.slice().sort());
  for (const key of rootFields) {
    reject(baseline, `/${key}`, null, true);
    reject(baseline, `/${key}`, null);
    reject(baseline, `/${key}`, typeof baseline[key] === "string" ? 1 : "wrong");
  }
  assert.equal(validate({...structuredClone(baseline), unknown: true}), false);
  for (const [pointer, value] of [["/graphKind", "foreign"], ["/schemaVersion", 2], ["/snapshotId", "sha256:bad"], ["/graphId", "bad id"], ["/graphId", "x".repeat(257)], ["/graphId", ""]]) reject(baseline, pointer, value);
});

test("graph node branches independently preserve required and optional field inventories", () => {
  for (const row of observations) {
    row.output.nodes.forEach((node, index) => {
      const fields = [...nodeFields[node.evidencePlane]];
      if (node.evidencePlane === "code_traceability" && node.kind !== "repository") fields.push("parentNodeId");
      if (node.kind === "source_range") fields.push("byteStart", "byteEnd", "coordinateUnit", "rangeVerification");
      const allowed = [...fields, ...(node.evidencePlane === "code_traceability" ? ["symbolId"] : [])];
      assert(Object.keys(node).every(key => allowed.includes(key)));
      for (const field of fields) reject(row.output, `/nodes/${index}/${field}`, null, true);
      for (const [key, value] of Object.entries(node)) {
        const pointer = `/nodes/${index}/${key}`;
        reject(row.output, pointer, null);
        reject(row.output, pointer, typeof value === "string" ? 1 : "wrong");
        if (typeof value === "string") reject(row.output, pointer, "");
        if (["evidencePlane", "kind", "authorityClass", "currentnessState", "state", "coordinateUnit", "rangeVerification"].includes(key)) reject(row.output, pointer, "foreign");
      }
      reject(row.output, `/nodes/${index}`, {...node, unknown: true});
      if (node.evidencePlane === "code_traceability") {
        reject(row.output, `/nodes/${index}/sourceDigest`, "sha256:bad");
        assert.equal(validate(mutate(row.output, `/nodes/${index}/symbolId`, "symbol.optional")), true);
        assert.equal(validate(mutate(row.output, `/nodes/${index}/symbolId`, null, true)), true);
        if (node.kind === "repository") reject(row.output, `/nodes/${index}/parentNodeId`, "code:foreign");
        if (node.kind !== "source_range") {
          for (const [key, value] of [["byteStart", 0], ["byteEnd", 1], ["coordinateUnit", "utf8_byte"], ["rangeVerification", "verified"]]) reject(row.output, `/nodes/${index}/${key}`, value);
        } else {
          for (const [key, values] of [["byteStart", [-1, 0.5]], ["byteEnd", [0, 1.5]]]) {
            for (const value of values) reject(row.output, `/nodes/${index}/${key}`, value);
          }
        }
      }
    });
  }
});

test("graph edge variants preserve independent fields, planes and endpoint-carrier types", () => {
  const edges = [...baseline.edges, {...baseline.edges.find(edge => edge.evidencePlane === "specification_coverage"), edgeKind: "contains"}];
  const observed = new Set();
  for (const edge of edges) {
    observed.add(`${edge.evidencePlane}:${edge.edgeKind}`);
    const output = {...structuredClone(baseline), edges: [edge], edgeCount: 1};
    assert.equal(validate(output), true);
    const fields = ["edgeId", "edgeKind", "evidencePlane", "fromNodeId", "toNodeId"];
    if (edge.evidencePlane === "code_traceability" && edge.edgeKind === "traced_to") fields.push("authorityClass", "currentnessState", "evidenceRefs");
    if (edge.evidencePlane === "native_execution_coverage") fields.push("codeNodeId");
    assert.deepEqual(Object.keys(edge).sort(), fields.slice().sort());
    for (const key of fields) {
      reject(output, `/edges/0/${key}`, null, true);
      reject(output, `/edges/0/${key}`, null);
      reject(output, `/edges/0/${key}`, typeof edge[key] === "string" ? 1 : "wrong");
      if (typeof edge[key] === "string") reject(output, `/edges/0/${key}`, "");
      if (["edgeKind", "evidencePlane", "authorityClass", "currentnessState"].includes(key)) reject(output, `/edges/0/${key}`, "foreign");
    }
    reject(output, "/edges/0", {...edge, unknown: true});
    if (edge.evidenceRefs) {
      reject(output, "/edges/0/evidenceRefs", []);
      reject(output, "/edges/0/evidenceRefs/0", null);
      reject(output, "/edges/0/evidenceRefs/0", 1);
      reject(output, "/edges/0/evidenceRefs/0", "");
    }
  }
  assert.deepEqual([...observed].sort(), ["code_traceability:contains", "code_traceability:traced_to", "native_execution_coverage:observed_by", "proof_coverage:proved_by_candidate", "specification_coverage:contains", "specification_coverage:declares"]);
});

test("graph bounds and denial tuple reject isolated structural violations", () => {
  for (const [field, max] of [["nodeCount", 20000], ["edgeCount", 80000]]) {
    for (const value of [-1, 0.5, max+1]) reject(baseline, `/${field}`, value);
    for (const value of [0, max]) assert.equal(validate(mutate(baseline, `/${field}`, value)), true);
  }
  for (const [field, max] of [["nodes", 20000], ["edges", 80000]]) {
    const representative = baseline[field][0];
    assert.equal(validate(mutate(baseline, `/${field}`, [])), true);
    assert.equal(validate(mutate(baseline, `/${field}`, Array(max).fill(representative))), true);
    reject(baseline, `/${field}`, Array(max+1).fill(representative));
  }
  assert.equal(baseline.nonClaims.length, 2);
  for (const values of [[], baseline.nonClaims.slice(1), [...baseline.nonClaims, baseline.nonClaims[0]], baseline.nonClaims.toReversed()]) reject(baseline, "/nonClaims", values);
  reject(baseline, "/nonClaims/0", "foreign");
  reject(baseline, "/nonClaims/1", "foreign");
});

test("graph structure does not claim native semantic or freshness authority", () => {
  assert.equal(validate(mutate(baseline, "/edges/0/toNodeId", "code:missing")), true);
  const index = baseline.nodes.findIndex(node => node.kind === "source_range");
  assert(index >= 0);
  assert.equal(validate(mutate(baseline, `/nodes/${index}/parentNodeId`, "code:missing")), true);
  assert.equal(validate(mutate(baseline, `/nodes/${index}/byteEnd`, 1)), true);
  assert.equal(validate(mutate(baseline, `/nodes/${index}/sourceDigest`, `sha256:${"0".repeat(64)}`)), true);
});
