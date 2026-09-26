import assert from "node:assert/strict";

// Test-only observation contract, independent of the production router/constants.
const planes = ["specification_coverage", "proof_coverage", "code_traceability", "native_execution_coverage"];

export function segmentIntersectsRectangle(a, b, r, inflate = 0) {
  let low = 0, high = 1;
  for (const [axis, min, max] of [[0, r.x - inflate, r.x + r.width + inflate], [1, r.y - inflate, r.y + r.height + inflate]]) {
    const delta = b[axis] - a[axis];
    if (delta === 0) {
      if (a[axis] < min || a[axis] > max) return false;
    } else {
      const first = (min - a[axis]) / delta, last = (max - a[axis]) / delta;
      low = Math.max(low, Math.min(first, last));
      high = Math.min(high, Math.max(first, last));
      if (low > high) return false;
    }
  }
  return true;
}

export function graphNodeIntersections(graph, observed, inflate = 0.75) {
  const edges = new Map(graph.edges.map(edge => [edge.edgeId, edge]));
  const hits = [];
  for (const route of observed.routes) {
    const edge = edges.get(route.id);
    assert(edge, "unexpected rendered edge");
    for (const node of observed.nodes) {
      if (node.id === edge.fromNodeId || node.id === edge.toNodeId) continue;
      for (let i = 1; i < route.points.length; i++) {
        if (segmentIntersectsRectangle(route.points[i - 1], route.points[i], node, inflate)) hits.push({edgeId: route.id, nodeId: node.id, segment: i - 1});
      }
    }
  }
  return hits;
}

export function assertGraphGeometry(graph, observed, domMeasurement = false) {
  // getBoundingClientRect subtraction can lose low bits after Firefox scrolls.
  // Only DOM comparisons allow <1/1024 CSS px; pure geometry stays exact.
  const epsilon = domMeasurement ? 1 / 1024 : 0;
  const equalCoordinate = (actual, expected, message) => assert(Number.isFinite(actual) && Number.isFinite(expected) && Math.abs(actual - expected) <= epsilon, message);
  const equalPoint = (actual, expected, message) => { assert.equal(actual.length, 2); for (let i = 0; i < 2; i++) equalCoordinate(actual[i], expected[i], message); };
  assert.deepEqual(observed.nodes.map(n => n.id).sort(), graph.nodes.map(n => n.nodeId).sort(), "node identity");
  assert.deepEqual(observed.routes.map(e => e.id).sort(), graph.edges.map(e => e.edgeId).sort(), "edge identity");
  assert.deepEqual(graphNodeIntersections(graph, observed, 6 + 2 * epsilon), [], "unrelated node clearance");
  assert(observed.width <= 2576 && observed.height <= 22332, "canvas ceiling");
  assert.equal(observed.columns.length, 4);
  for (const x of observed.columns) assert(Number.isFinite(x) && x >= 0 && x + 240 <= observed.width, "heading bounds");
  const rects = new Map(observed.nodes.map(n => [n.id, n]));
  const columns = new Map(graph.nodes.map(n => [n.nodeId, planes.indexOf(n.evidencePlane)]));
  const edges = new Map(graph.edges.map(e => [e.edgeId, e]));
  for (const n of observed.nodes) {
    equalCoordinate(n.width, 240, "DOM card width"); equalCoordinate(n.height, 96, "DOM card height");
    equalCoordinate(n.x, observed.columns[columns.get(n.id)], "heading alignment");
    if (domMeasurement) {
      equalCoordinate(n.x, n.placement.left, "DOM left placement");
      equalCoordinate(n.y, n.placement.top, "DOM top placement");
    }
    assert(Number.isFinite(n.y) && n.y >= 48 && n.y + n.height <= observed.height, "card bounds");
    for (const other of observed.nodes) if (other.id !== n.id) assert(n.x + n.width <= other.x || other.x + other.width <= n.x || n.y + n.height <= other.y || other.y + other.height <= n.y, "card separation");
  }
  const verticals = new Set();
  let demand = 0;
  for (const route of observed.routes) {
    const edge = edges.get(route.id), from = rects.get(edge.fromNodeId), to = rects.get(edge.toNodeId);
    const direction = Math.sign(columns.get(to.id) - columns.get(from.id));
    const source = [direction < 0 ? from.x : from.x + from.width, from.y + from.height / 2];
    const target = [direction > 0 ? to.x : to.x + to.width, to.y + to.height / 2];
    if (domMeasurement) {
      assert.deepEqual(route.points[0], [from.placement.left + (direction < 0 ? 0 : 240), from.placement.top + 48], "exact DOM source port");
      assert.deepEqual(route.points.at(-1), [to.placement.left + (direction > 0 ? 0 : 240), to.placement.top + 48], "exact DOM target port");
    }
    equalPoint(route.points[0], source, "source port");
    equalPoint(route.points.at(-1), target, "target port");
    assert.equal(route.points.length, direction === 0 ? 4 : 6, "bounded segment count");
    equalCoordinate(route.points[1][1], source[1], "source stub"); equalCoordinate(route.points.at(-2)[1], target[1], "target stub");
    assert.equal(Math.sign(route.points[1][0] - source[0]), direction < 0 ? -1 : 1, "outward source");
    assert.equal(Math.sign(target[0] - route.points.at(-2)[0]), direction > 0 ? 1 : -1, "arrow direction");
    for (const start of direction === 0 ? [1] : [1, 3]) {
      const [a, b] = [route.points[start], route.points[start + 1]];
      assert.equal(a[0], b[0], "vertical slot"); assert.notEqual(a[1], b[1], "nonzero slot span");
      assert(!verticals.has(a[0]), "distinct endpoint-role slots"); verticals.add(a[0]); demand++;
    }
    for (const p of route.points) assert(p.every(Number.isFinite) && p[0] >= 0 && p[0] <= observed.width && p[1] >= 48 && p[1] <= observed.height, "finite route bounds");
    for (let i = 1; i < route.points.length; i++) assert(route.points[i - 1][0] === route.points[i][0] || route.points[i - 1][1] === route.points[i][1], "orthogonal segment");
    const marker = {x: direction > 0 ? to.x - 6 : to.x + to.width, y: target[1] - 3, width: 6, height: 6};
    assert(marker.x >= 0 && marker.x + marker.width <= observed.width && marker.y >= 48 && marker.y + marker.height <= observed.height, "marker bounds");
    for (const n of observed.nodes) if (n.id !== to.id) assert(marker.x + marker.width < n.x || marker.x > n.x + n.width || marker.y + marker.height < n.y || marker.y > n.y + n.height, "marker clearance");
  }
  assert.equal(demand, graph.edges.reduce((sum, e) => sum + (columns.get(e.fromNodeId) === columns.get(e.toNodeId) ? 1 : 2), 0));
  assert(demand <= 256, "slot ceiling");
  assert.equal(observed.width, 1040 + 6 * demand, "slot width budget");
  const sorted = [...verticals].sort((a, b) => a - b);
  for (let i = 1; i < sorted.length; i++) assert(sorted[i] - sorted[i - 1] >= 6, "slot spacing");
}

export async function readGraphGeometry(page) {
  return page.locator(".graph-canvas").evaluate(canvas => {
    const bounds = canvas.getBoundingClientRect(), svg = canvas.querySelector(":scope > svg");
    const svgBounds = svg.getBoundingClientRect();
    // HTML authored color and SVG system ink need not have equal computed
    // values in forced colors. Resolve the required token independently.
    const probe = document.createElement("span");
    probe.style.color = matchMedia("(forced-colors: active)").matches ? "CanvasText" : "var(--text)";
    canvas.append(probe);
    const expectedInk = getComputedStyle(probe).color;
    probe.remove();
    return {
      width: bounds.width, height: bounds.height, svgWidth: svgBounds.width, svgHeight: svgBounds.height,
      viewBox: svg.getAttribute("viewBox"),
      columns: [...canvas.querySelectorAll(".graph-plane-heading")].map(h => h.getBoundingClientRect().x - bounds.x),
      nodes: [...canvas.querySelectorAll(".graph-node")].map(n => {const r = n.getBoundingClientRect(); return {id: n.dataset.graphSelect, x: r.x - bounds.x, y: r.y - bounds.y, width: r.width, height: r.height, placement: {left: parseFloat(n.style.left), top: parseFloat(n.style.top)}};}),
      routes: [...svg.querySelectorAll("[data-edge-id]")].map(e => ({id: e.dataset.edgeId, points: e.tagName === "line" ? [[e.x1.baseVal.value, e.y1.baseVal.value], [e.x2.baseVal.value, e.y2.baseVal.value]] : [...e.points].map(p => [p.x, p.y]), marker: e.getAttribute("marker-end")})),
      paint: [...svg.querySelectorAll("[data-edge-id]")].map(e => {const s = getComputedStyle(e); return {fill: s.fill, stroke: s.stroke, width: parseFloat(s.strokeWidth), join: s.strokeLinejoin};}),
      marker: Object.fromEntries(["viewBox", "markerUnits", "markerWidth", "markerHeight", "refX", "refY", "orient"].map(key => [key, svg.querySelector("marker").getAttribute(key)])),
      markerPath: svg.querySelector("marker path").getAttribute("d"), markerFill: getComputedStyle(svg.querySelector("marker path")).fill,
      expectedInk,
    };
  });
}

export function assertGraphPaint(observed) {
  assert.equal(observed.svgWidth, observed.width); assert.equal(observed.svgHeight, observed.height);
  assert.equal(observed.viewBox, `0 0 ${observed.width} ${observed.height}`);
  assert.deepEqual(observed.marker, {viewBox: "0 0 10 10", markerUnits: "userSpaceOnUse", markerWidth: "6", markerHeight: "6", refX: "10", refY: "5", orient: "auto-start-reverse"});
  assert.equal(observed.markerPath, "M 0 0 L 10 5 L 0 10 z");
  assert.equal(observed.markerFill, observed.expectedInk);
  for (const p of observed.paint) assert.deepEqual(p, {fill: "none", stroke: observed.expectedInk, width: 1.5, join: "round"});
  for (const e of observed.routes) assert.equal(e.marker, "url(#graph-arrow)");
}
