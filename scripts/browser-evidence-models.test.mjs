import assert from "node:assert/strict";
import test from "node:test";
import {summarizeDiffPage} from "../internal/command/requirementbrowser/assets/workspace-diff.js";
import {GRAPH_PAGE, GRAPH_PLANES, graphPagePositions, visibleGraphPage} from "../internal/command/requirementbrowser/assets/workspace-graph.js";
import {resolveHandoffRequirement} from "../internal/command/requirementbrowser/assets/workspace-handoff.js";

test("diff page classes partition changes while risk and lifecycle remain independent facets", () => {
  const changes = [
    {entityId: "REQ-A", entityKind: "requirement", changeClass: "scalar_changed", jsonPointer: "/requirements/REQ-A/riskClass"},
    {entityId: "REQ-A", entityKind: "requirement", changeClass: "scalar_changed", jsonPointer: "/requirements/REQ-A/invariant"},
    {entityId: "REQ-B", entityKind: "requirement", changeClass: "entity_added", after: {riskClass: "high"}},
    {entityId: "REQ-C", entityKind: "requirement", changeClass: "entity_removed", before: {riskClass: "high"}},
    {entityId: "REQ-C", entityKind: "requirement", changeClass: "lifecycle_transition"},
    {entityId: "REQ-D", entityKind: "requirement", changeClass: "set_changed", jsonPointer: "/requirements/REQ-D/riskClass"},
    {entityId: "REQ-A", entityKind: "source", changeClass: "scalar_changed", jsonPointer: "/requirements/REQ-A/riskClass"},
    {entityId: "REQ-A", entityKind: "requirement", changeClass: "scalar_changed", jsonPointer: "/requirements/REQ-X/riskClass"},
  ];
  const summary = summarizeDiffPage(changes);
  assert.deepEqual(summary, {changeCount: 8, entityCount: 4, riskChanges: 1, lifecycleChanges: 1, byClass: [["entity_added", 1], ["entity_removed", 1], ["lifecycle_transition", 1], ["scalar_changed", 4], ["set_changed", 1]]});
  assert.equal(summary.byClass.reduce((count, [, value]) => count + value, 0), changes.length);
  assert.deepEqual(summarizeDiffPage([]), {changeCount: 0, entityCount: 0, riskChanges: 0, lifecycleChanges: 0, byClass: []});
  assert.equal(summarizeDiffPage([{entityId: "A/~", entityKind: "requirement", changeClass: "scalar_changed", jsonPointer: "/requirements/A~1~0/riskClass"}]).riskChanges, 1);
});

const spec = "specification_coverage", code = "code_traceability", proof = "proof_coverage", native = "native_execution_coverage";
const graph = {
  nodes: [
    {nodeId: "a", evidencePlane: spec}, {nodeId: "b", evidencePlane: code},
    {nodeId: "c", evidencePlane: proof}, {nodeId: "d", evidencePlane: code},
    {nodeId: "e", evidencePlane: native}, {nodeId: "isolated", evidencePlane: spec},
  ],
  edges: [
    {edgeId: "ab1", fromNodeId: "a", toNodeId: "b", evidencePlane: code},
    {edgeId: "ab2", fromNodeId: "b", toNodeId: "a", evidencePlane: code},
    {edgeId: "ac", fromNodeId: "a", toNodeId: "c", evidencePlane: proof},
    {edgeId: "bc", fromNodeId: "b", toNodeId: "c", evidencePlane: code},
    {edgeId: "bd", fromNodeId: "b", toNodeId: "d", evidencePlane: code},
    {edgeId: "ae", fromNodeId: "a", toNodeId: "e", evidencePlane: native},
  ],
};
const allPlanes = new Set(GRAPH_PLANES.map(plane => plane.id));
const identities = page => ({nodes: page.nodes.map(node => node.nodeId), edges: page.edges.map(edge => edge.edgeId), selectedId: page.selectedId, neighborhood: page.neighborhood});

test("graph visibility closes endpoints and preserves induced directed parallel relations", () => {
  const original = JSON.stringify(graph);
  // Opaque helper graphs are broader than current Go-built edge/plane pairs.
  // These defensive operand tests do not prove source-built reachability.
  assert.deepEqual(identities(visibleGraphPage(graph, new Set([spec, code]), null, false)), {nodes: ["a", "b", "d", "isolated"], edges: ["ab1", "ab2", "bd"], selectedId: null, neighborhood: false});
  assert.deepEqual(identities(visibleGraphPage(graph, new Set([code]), null, false)), {nodes: ["b", "d"], edges: ["bd"], selectedId: null, neighborhood: false});
  assert.deepEqual(identities(visibleGraphPage(graph, allPlanes, "a", true)), {nodes: ["a", "b", "c", "e"], edges: ["ab1", "ab2", "ac", "bc", "ae"], selectedId: "a", neighborhood: true});
  assert.deepEqual(identities(visibleGraphPage(graph, new Set([spec, code]), "a", true)), {nodes: ["a", "b"], edges: ["ab1", "ab2"], selectedId: "a", neighborhood: true});
  assert.deepEqual(identities(visibleGraphPage(graph, new Set([spec]), "b", true)), {nodes: ["a", "isolated"], edges: [], selectedId: null, neighborhood: false});
  assert.deepEqual(identities(visibleGraphPage(graph, allPlanes, "isolated", true)), {nodes: ["isolated"], edges: [], selectedId: "isolated", neighborhood: true});
  assert.deepEqual(identities(visibleGraphPage(graph, new Set(), "a", true)), {nodes: [], edges: [], selectedId: null, neighborhood: false});
  assert.equal(JSON.stringify(graph), original);
  assert.equal(visibleGraphPage(graph, allPlanes, null, true).neighborhood, false);
});

test("maximum graph page layout is stable, bounded and non-overlapping", () => {
  assert.deepEqual(GRAPH_PAGE, {maxRecords: 64, maxEdges: 128});
  const nodes = Array.from({length: 192}, (_, index) => ({nodeId: `node.${String(index).padStart(3, "0")}`, evidencePlane: GRAPH_PLANES[index % 4].id}));
  const layout = graphPagePositions(nodes);
  assert.deepEqual(graphPagePositions([...nodes].reverse()), layout);
  assert.equal(layout.positions.size, 192);
  for (const [id, position] of layout.positions) {
    assert(position.x >= 0 && position.x + 240 <= layout.width);
    assert(position.y >= 0 && position.y + 96 <= layout.height);
    for (const [otherId, other] of layout.positions) if (id !== otherId) assert(position.x + 240 <= other.x || other.x + 240 <= position.x || position.y + 96 <= other.y || other.y + 96 <= position.y);
  }
  assert.equal(graphPagePositions([]).height, 180);
});

test("handoff detail resolution uses requirement identity rather than unsliced source offsets", () => {
  const requirement = {requirementId: "REQ-B", invariant: "Selected requirement."};
  const source = {requirements: [requirement]};
  const packet = {context: {projections: {requirementSources: [source]}}};
  assert.deepEqual(resolveHandoffRequirement(packet, "REQ-B"), {state: "found", requirement});
  assert.deepEqual(resolveHandoffRequirement(packet, "REQ-A"), {state: "unavailable", requirement: null});
  packet.context.projections.requirementSources.push({requirements: [{...requirement}]});
  assert.deepEqual(resolveHandoffRequirement(packet, "REQ-B"), {state: "ambiguous", requirement: null});
});
