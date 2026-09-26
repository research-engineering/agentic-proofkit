import assert from "node:assert/strict";
import test from "node:test";
import {summarizeDiffPage} from "../internal/command/requirementbrowser/assets/workspace-diff.js";
import {GEOMETRY, GRAPH_PAGE, GRAPH_PLANES, graphPagePositions, visibleGraphPage} from "../internal/command/requirementbrowser/assets/workspace-graph.js";
import {assertGraphGeometry, graphNodeIntersections, segmentIntersectsRectangle} from "../tests/browser/graph-geometry-oracle.mjs";
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

function graphObservation(graph) {
  const layout = graphPagePositions(graph.nodes, graph.edges);
  return {width: layout.width, height: layout.height, columns: layout.columns,
    nodes: graph.nodes.map(n => ({id: n.nodeId, ...layout.positions.get(n.nodeId), width: GEOMETRY.cardWidth, height: GEOMETRY.cardHeight})),
    routes: [...layout.routes].map(([id, points]) => ({id, points})),
  };
}

function assertLayout(graph) {
  const before = structuredClone(graph);
  const observed = graphObservation(graph);
  assertGraphGeometry(graph, observed);
  assert.deepEqual(graphPagePositions(graph.nodes, graph.edges), graphPagePositions([...graph.nodes].reverse(), [...graph.edges].reverse()));
  assert.deepEqual(graph, before);
  return observed;
}

test("graph segment oracle analytically distinguishes crossings, contact and misses", () => {
  const rectangle = {x: 10, y: 10, width: 10, height: 10};
  for (const [a, b] of [[[0, 15], [30, 15]], [[15, 0], [15, 30]], [[0, 0], [30, 30]], [[0, 10], [30, 10]], [[15, 15], [15, 15]]]) assert(segmentIntersectsRectangle(a, b, rectangle));
  for (const [a, b] of [[[0, 0], [9, 9]], [[0, 9], [30, 9]], [[0, 0], [0, 0]]]) assert(!segmentIntersectsRectangle(a, b, rectangle));
  assert(segmentIntersectsRectangle([0, 9.5], [30, 9.5], rectangle, 0.75));
});

test("graph routes preserve four-plane endpoints, slots and bounds across permutations and filters", () => {
  assert(Object.isFrozen(GEOMETRY));
  assert.deepEqual(GRAPH_PLANES.map(p => p.id), [spec, proof, code, native]);
  const nodes = Array.from({length: 12}, (_, i) => ({nodeId: `n${String(i).padStart(2, "0")}`, evidencePlane: GRAPH_PLANES[i % 4].id}));
  // Reverse and arbitrary helper relations exercise geometry, not public admission.
  for (const a of nodes) for (const b of nodes) if (a !== b) assertLayout({nodes, edges: [{edgeId: "edge", fromNodeId: a.nodeId, toNodeId: b.nodeId}]});
  for (let mask = 0; mask < 16; mask++) {
    const visible = visibleGraphPage(graph, new Set(GRAPH_PLANES.filter((_, i) => mask & (1 << i)).map(p => p.id)), "a", false);
    assertLayout(visible);
    assertLayout(visibleGraphPage(graph, new Set(GRAPH_PLANES.filter((_, i) => mask & (1 << i)).map(p => p.id)), "a", true));
  }
  const empty = assertLayout({nodes: [], edges: []});
  assert.deepEqual([empty.width, empty.height, empty.columns], [1040, 180, [12, 272, 532, 792]]);
});

test("graph endpoint-role slots reach the page ceilings without requiring planar edges", () => {
  for (const [a, b] of [[spec, proof], [proof, spec], [spec, native], [native, spec]]) {
    const nodes = [{nodeId: "a", evidencePlane: a}, {nodeId: "b", evidencePlane: b}];
    const edges = Array.from({length: 128}, (_, i) => ({edgeId: `edge.${i}`, fromNodeId: "a", toNodeId: "b"}));
    assert.equal(assertLayout({nodes, edges}).width, 2576);
  }
  for (const distribution of ["one", "four"]) {
    const nodes = Array.from({length: 192}, (_, i) => ({nodeId: `n${String(i).padStart(3, "0")}`, evidencePlane: GRAPH_PLANES[distribution === "one" ? 3 : i % 4].id}));
    const edges = Array.from({length: 128}, (_, i) => ({edgeId: `edge.${i}`, fromNodeId: nodes[0].nodeId, toNodeId: nodes[i + 1].nodeId}));
    const observed = assertLayout({nodes, edges});
    if (distribution === "one") assert.equal(observed.height, 22332);
  }
  const nodes = Array.from({length: 6}, (_, i) => ({nodeId: `n${i}`, evidencePlane: i < 3 ? spec : proof}));
  const edges = nodes.slice(0, 3).flatMap(a => nodes.slice(3).map(b => ({edgeId: `${a.nodeId}.${b.nodeId}`, fromNodeId: a.nodeId, toNodeId: b.nodeId})));
  assertLayout({nodes, edges}); // K3,3: edge crossings are allowed; node crossings are not.
});

test("graph geometry oracle rejects independent causal mutants", () => {
  const fixture = {nodes: [
    {nodeId: "spec:a", evidencePlane: spec}, {nodeId: "spec:b", evidencePlane: spec}, {nodeId: "spec:z", evidencePlane: spec},
    {nodeId: "proof", evidencePlane: proof}, {nodeId: "code", evidencePlane: code}, {nodeId: "native", evidencePlane: native},
  ], edges: [
    {edgeId: "contains", fromNodeId: "spec:z", toNodeId: "spec:a"},
    {edgeId: "adjacent", fromNodeId: "spec:a", toNodeId: "proof"},
    {edgeId: "cross", fromNodeId: "spec:a", toNodeId: "native"},
    {edgeId: "parallel", fromNodeId: "spec:a", toNodeId: "native"},
  ]};
  const good = assertLayout(fixture);
  const route = (value, id) => value.routes.find(e => e.id === id);
  const mutants = {
    nodeCrossing(value) { route(value, "contains").points[1][0] = route(value, "contains").points[2][0] = 132; },
    unsafeCrossRow(value) { route(value, "cross").points[2][1] = route(value, "cross").points[3][1] = 96; },
    collapsedAdjacentSlots(value) { const e = route(value, "adjacent"); e.points[3][0] = e.points[4][0] = e.points[1][0]; },
    wrongFacingPort(value) { route(value, "cross").points.at(-1)[0] += 240; },
    wrongArrowDirection(value) { route(value, "contains").points.reverse(); },
    coincidentParallel(value) { route(value, "parallel").points = structuredClone(route(value, "cross").points); },
    swappedIdentity(value) { [route(value, "cross").id, route(value, "contains").id] = ["contains", "cross"]; },
    droppedRelation(value) { value.routes.pop(); },
    staleHeading(value) { value.columns[1] -= 6; },
    cardSizeDrift(value) { value.nodes[0].width++; },
    clippedCanvas(value) { value.width = 1040; },
  };
  for (const [name, mutate] of Object.entries(mutants)) {
    const value = structuredClone(good); mutate(value);
    assert.throws(() => assertGraphGeometry(fixture, value), name);
  }
  const legacy = structuredClone(good);
  route(legacy, "contains").points = [[132, 280], [132, 144]];
  assert(graphNodeIntersections(fixture, legacy).some(hit => hit.edgeId === "contains" && hit.nodeId === "spec:b"));
});

test("graph geometry rejects unavailable and coincident local endpoints without a public-input claim", () => {
  const nodes = [{nodeId: "a", evidencePlane: spec}];
  assert.throws(() => graphPagePositions(nodes, [{edgeId: "e", fromNodeId: "a", toNodeId: "missing"}]), /unavailable/);
  assert.throws(() => graphPagePositions(nodes, [{edgeId: "e", fromNodeId: "a", toNodeId: "a"}]), /Coincident/);
});

test("graph DOM precision allowance neither relaxes pure geometry nor hides visible drift", () => {
  const graph = {nodes: [{nodeId: "a", evidencePlane: spec}, {nodeId: "b", evidencePlane: spec}], edges: [{edgeId: "e", fromNodeId: "a", toNodeId: "b"}]};
  const observed = assertLayout(graph);
  for (const node of observed.nodes) node.placement = {left: node.x, top: node.y};
  observed.nodes[0].y += 1 / 16384;
  assert.throws(() => assertGraphGeometry(graph, observed), /source port/);
  assertGraphGeometry(graph, observed, true);
  const wrongEndpoint = structuredClone(observed);
  wrongEndpoint.routes[0].points[0][1] += 1 / 16384;
  assert.throws(() => assertGraphGeometry(graph, wrongEndpoint, true), /exact DOM source port/);
  observed.nodes[0].y += 0.01;
  assert.throws(() => assertGraphGeometry(graph, observed, true), /DOM top placement/);
  observed.nodes[0].width = 241;
  assert.throws(() => assertGraphGeometry(graph, observed, true), /DOM card width/);
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
