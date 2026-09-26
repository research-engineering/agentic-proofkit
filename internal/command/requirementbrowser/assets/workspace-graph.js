// @ts-check

import {icon} from "./workspace-icons.js";
import {workspaceScalarText} from "./workspace-json.js";

export const GRAPH_PAGE = Object.freeze({maxRecords: 64, maxEdges: 128});
export const GRAPH_PLANES = Object.freeze([
  {id: "specification_coverage", label: "Specifications"},
  {id: "proof_coverage", label: "Proof declarations"},
  {id: "code_traceability", label: "Code"},
  {id: "native_execution_coverage", label: "Native execution"},
]);

export const GEOMETRY = Object.freeze({
  cardWidth: 240, cardHeight: 96, columnGap: 20, rowGap: 20,
  leftPadding: 12, rightPadding: 8, headingBand: 48, bottomPadding: 32,
  minimumHeight: 180, slotPitch: 6, strokeWidth: 1.5, markerSize: 6, markerViewBox: 10,
});

/** @typedef {{gap: number, rank: number}} GraphSlot */
/** @typedef {[number, number]} GraphPoint */

/** @param {{nodes: any[], edges: any[]}} graph @param {Set<string>} planes @param {string | null} selectedId @param {boolean} neighborhood */
export function visibleGraphPage(graph, planes, selectedId, neighborhood) {
  let nodes = graph.nodes.filter(node => planes.has(node.evidencePlane));
  const admittedIDs = new Set(nodes.map(node => node.nodeId));
  let edges = graph.edges.filter(edge => planes.has(edge.evidencePlane) && admittedIDs.has(edge.fromNodeId) && admittedIDs.has(edge.toNodeId));
  if (!admittedIDs.has(selectedId)) { selectedId = null; neighborhood = false; }
  if (neighborhood && selectedId !== null) {
    const neighbors = new Set([selectedId]);
    for (const edge of edges) {
      if (edge.fromNodeId === selectedId) neighbors.add(edge.toNodeId);
      if (edge.toNodeId === selectedId) neighbors.add(edge.fromNodeId);
    }
    nodes = nodes.filter(node => neighbors.has(node.nodeId));
    edges = edges.filter(edge => neighbors.has(edge.fromNodeId) && neighbors.has(edge.toNodeId));
  }
  return {nodes, edges, selectedId, neighborhood};
}

/** @param {any[]} nodes @param {any[]} [edges] */
export function graphPagePositions(nodes, edges = []) {
  const g = GEOMETRY;
  const rows = GRAPH_PLANES.map(() => 0);
  const slotCounts = GRAPH_PLANES.map(() => 0);
  /** @type {Map<string, number>} */
  const nodeColumns = new Map();
  /** @type {Map<string, {x: number, y: number}>} */
  const positions = new Map();
  /** @type {Map<string, {source: GraphSlot, target: GraphSlot}>} */
  const slots = new Map();
  /** @type {Map<string, GraphPoint[]>} */
  const routes = new Map();
  const ordered = [...nodes].sort((a, b) => a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0);
  for (const node of ordered) {
    const column = GRAPH_PLANES.findIndex(plane => plane.id === node.evidencePlane);
    if (column < 0) throw new Error("Unknown admitted evidence plane");
    nodeColumns.set(node.nodeId, column);
  }
  /** @param {number} gap */
  const reserve = gap => ({gap, rank: slotCounts[gap]++});
  const orderedEdges = [...edges].sort((a, b) => a.edgeId < b.edgeId ? -1 : a.edgeId > b.edgeId ? 1 : 0);
  for (const edge of orderedEdges) {
    const from = nodeColumns.get(edge.fromNodeId), to = nodeColumns.get(edge.toNodeId);
    if (from === undefined || to === undefined) throw new Error("Visible edge endpoint is unavailable");
    if (edge.fromNodeId === edge.toNodeId) throw new Error("Coincident graph endpoints are unsupported");
    // Endpoint roles get distinct slots even in a shared adjacent-column gap.
    // Lower-column endpoints reserve first, independently of edge direction.
    if (from === to) {
      const slot = reserve(from);
      slots.set(edge.edgeId, {source: slot, target: slot});
    } else if (from < to) {
      slots.set(edge.edgeId, {source: reserve(from), target: reserve(to - 1)});
    } else {
      const target = reserve(to), source = reserve(from - 1);
      slots.set(edge.edgeId, {source, target});
    }
  }
  /** @type {number[]} */
  const columns = [g.leftPadding];
  for (let column = 1; column < GRAPH_PLANES.length; column++) columns.push(columns[column - 1] + g.cardWidth + g.columnGap + g.slotPitch * slotCounts[column - 1]);
  for (const node of ordered) {
    const column = nodeColumns.get(node.nodeId);
    if (column === undefined) throw new Error("Node column is unavailable");
    positions.set(node.nodeId, {x: columns[column], y: g.headingBand + rows[column]++ * (g.cardHeight + g.rowGap)});
  }
  /** @param {GraphSlot} slot */
  const lane = slot => columns[slot.gap] + g.cardWidth + g.columnGap / 2 + g.slotPitch * slot.rank;
  for (const edge of orderedEdges) {
    const from = positions.get(edge.fromNodeId), to = positions.get(edge.toNodeId), pair = slots.get(edge.edgeId);
    if (!from || !to || !pair) throw new Error("Visible edge endpoint is unavailable");
    /** @type {GraphPoint} */
    const source = [from.x + (from.x > to.x ? 0 : g.cardWidth), from.y + g.cardHeight / 2];
    /** @type {GraphPoint} */
    const target = [to.x + (from.x < to.x ? 0 : g.cardWidth), to.y + g.cardHeight / 2];
    const sourceLane = lane(pair.source), targetLane = lane(pair.target);
    const corridor = from.y + g.cardHeight + g.rowGap / 2;
    routes.set(edge.edgeId, from.x === to.x
      ? [source, [sourceLane, source[1]], [sourceLane, target[1]], target]
      : [source, [sourceLane, source[1]], [sourceLane, corridor], [targetLane, corridor], [targetLane, target[1]], target]);
  }
  const width = g.leftPadding + GRAPH_PLANES.length * g.cardWidth + (GRAPH_PLANES.length - 1) * g.columnGap + g.rightPadding + g.slotPitch * slotCounts.reduce((sum, count) => sum + count, 0);
  const height = Math.max(g.minimumHeight, g.headingBand + Math.max(...rows) * (g.cardHeight + g.rowGap) - g.rowGap + g.bottomPadding);
  return {positions, columns, routes, width, height};
}

/** @param {HTMLElement} container @param {any} graph @param {{follow: (offset: number, id: string) => void, reconcile: () => void, initialId?: string | null}} options */
export function renderGraphPage(container, graph, options) {
  let planes = new Set(GRAPH_PLANES.map(plane => plane.id));
  let selectedId = options.initialId ?? null;
  let neighborhood = false;
  const primaryIDs = new Set(graph.primaryNodeIds);
  const controls = document.createElement("fieldset");
  controls.className = "graph-filters";
  const legend = document.createElement("legend");
  legend.textContent = "Evidence planes";
  controls.append(legend);
  /** @type {Map<string, HTMLInputElement>} */
  const checkboxes = new Map();
  for (const plane of GRAPH_PLANES) {
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = true;
    checkboxes.set(plane.id, checkbox);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) planes.add(plane.id); else planes.delete(plane.id);
      update(checkbox);
    });
    label.append(checkbox, document.createTextNode(plane.label));
    controls.append(label);
  }
  const neighborhoodLabel = document.createElement("label");
  const neighborhoodInput = document.createElement("input");
  neighborhoodInput.type = "checkbox";
  neighborhoodInput.addEventListener("change", () => { neighborhood = neighborhoodInput.checked; update(neighborhoodInput); });
  neighborhoodLabel.append(neighborhoodInput, document.createTextNode("Selected node and neighbors"));
  controls.append(neighborhoodLabel);
  const counts = document.createElement("p");
  counts.className = "page-summary";
  counts.dataset.graphCounts = "";
  const announcement = document.createElement("p");
  announcement.setAttribute("role", "status");
  announcement.setAttribute("aria-live", "polite");
  const viewport = document.createElement("div");
  viewport.className = "graph-viewport";
  viewport.setAttribute("role", "region");
  viewport.setAttribute("aria-label", "Traceability graph viewport");
  viewport.tabIndex = 0;
  const inspector = document.createElement("section");
  inspector.className = "graph-inspector";
  inspector.setAttribute("aria-label", "Selected graph node");
  const records = document.createElement("details");
  records.className = "graph-records";
  records.open = true;
  const recordLabel = document.createElement("summary");
  recordLabel.textContent = "Node and relation records";
  records.append(recordLabel);
  const recordBody = document.createElement("div");
  records.append(recordBody);
  container.append(controls, counts, announcement, viewport, inspector, records);
  /** @type {any[]} */
  let renderedNodes = [];
  /** @type {any[]} */
  let renderedEdges = [];
  /** @type {Map<string, HTMLButtonElement>} */
  const nodeButtons = new Map();
  /** @type {Map<string, HTMLButtonElement>} */
  const recordButtons = new Map();
  let topologyRendered = false;

  /** @param {string} id @param {boolean} [reveal] */
  function select(id, reveal = false) {
    if (reveal) {
      planes = new Set(GRAPH_PLANES.map(plane => plane.id));
      for (const checkbox of checkboxes.values()) checkbox.checked = true;
      neighborhood = false;
    }
    selectedId = id;
    update(undefined, id);
  }

  /** @param {HTMLElement} [fallback] @param {string} [focusTarget] */
  function update(fallback, focusTarget) {
    const start = performance.now();
    const focused = document.activeElement;
    const focusedNode = focusTarget ?? (focused instanceof HTMLElement ? focused.dataset.graphSelect : undefined);
    const recordFocused = focused !== null && (recordBody.contains(focused) || inspector.contains(focused));
    const oldSelection = selectedId;
    const visible = visibleGraphPage(graph, planes, selectedId, neighborhood);
    selectedId = visible.selectedId;
    neighborhood = visible.neighborhood;
    neighborhoodInput.checked = neighborhood;
    neighborhoodInput.disabled = selectedId === null;
    if (oldSelection !== null && selectedId === null) announcement.textContent = "Selection cleared by evidence-plane filters.";
    else announcement.textContent = selectedId === null ? "No node selected." : `Selected ${selectedId}.`;
    counts.textContent = `Available: ${graph.availableNodeCount} nodes, ${graph.availableEdgeCount} relations. Returned page: ${graph.primaryNodeCount} primary and ${graph.boundaryNodeCount} boundary nodes, ${graph.selectedEdgeCount} relations. Visible in this returned page: ${visible.nodes.length} nodes, ${visible.edges.length} relations.`;
    // Selection does not change immutable page records or their layout.
    if (!topologyRendered || !sameRecords(renderedNodes, visible.nodes) || !sameRecords(renderedEdges, visible.edges)) {
      renderTopology(visible);
      renderedNodes = visible.nodes;
      renderedEdges = visible.edges;
      topologyRendered = true;
    }
    for (const [id, button] of nodeButtons) button.setAttribute("aria-pressed", String(selectedId === id));
    for (const [id, button] of recordButtons) button.setAttribute("aria-pressed", String(selectedId === id));
    inspector.replaceChildren();
    const selected = visible.nodes.find(node => node.nodeId === selectedId);
    if (selected) {
      const title = document.createElement("h3");
      title.className = "caller-text";
      title.textContent = selected.label;
      const kind = document.createElement("p");
      kind.textContent = primaryIDs.has(selected.nodeId) ? "Primary node" : "Endpoint boundary node";
      inspector.append(title, kind, fields(selected));
      appendReferences(inspector, "node", selected.nodeId, visible);
      for (const [direction, key] of [["Incoming", "toNodeId"], ["Outgoing", "fromNodeId"]]) {
        const heading = document.createElement("h4");
        heading.textContent = `${direction} relations in this page`;
        const list = document.createElement("ul");
        for (const edge of graph.edges.filter((/** @type {any} */ edge) => edge[key] === selected.nodeId)) {
          const item = document.createElement("li");
          item.append(edgeRecord(edge, visible));
          list.append(item);
        }
        if (!list.children.length) { const item = document.createElement("li"); item.textContent = "None returned"; list.append(item); }
        inspector.append(heading, list);
      }
    } else {
      const empty = document.createElement("p"); empty.textContent = "No node selected."; inspector.append(empty);
    }
    options.reconcile();
    if (focusedNode) {
      const replacement = nodeButtons.get(focusedNode);
      const recordButton = recordButtons.get(focusedNode);
      if (recordButton && (recordFocused || window.getComputedStyle(viewport).display === "none")) { records.open = true; recordButton.focus(); }
      else if (replacement) replacement.focus();
      else if (fallback?.isConnected) fallback.focus();
      else recordBody.querySelector("button")?.focus();
    }
    viewport.dataset.commitMilliseconds = String(performance.now() - start);
  }

  /** @param {any[]} previous @param {any[]} current */
  function sameRecords(previous, current) {
    return previous.length === current.length && previous.every((record, index) => record === current[index]);
  }

  /** @param {ReturnType<typeof visibleGraphPage>} visible */
  function renderTopology(visible) {
    nodeButtons.clear();
    recordButtons.clear();
    const {positions, columns, routes, width, height} = graphPagePositions(visible.nodes, visible.edges);
    const canvas = document.createElement("div");
    canvas.className = "graph-canvas";
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    canvas.style.setProperty("--graph-card-width", `${GEOMETRY.cardWidth}px`);
    canvas.style.setProperty("--graph-card-height", `${GEOMETRY.cardHeight}px`);
    canvas.style.setProperty("--graph-edge-stroke", `${GEOMETRY.strokeWidth}px`);
    for (let column = 0; column < GRAPH_PLANES.length; column++) {
      const heading = document.createElement("p");
      heading.className = "graph-plane-heading";
      heading.textContent = GRAPH_PLANES[column].label;
      heading.style.left = `${columns[column]}px`;
      canvas.append(heading);
    }
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("width", String(width));
    svg.setAttribute("height", String(height));
    svg.dataset.nodeIds = visible.nodes.map(node => node.nodeId).join(" ");
    svg.dataset.edgeIds = visible.edges.map(edge => edge.edgeId).join(" ");
    const defs = document.createElementNS(svg.namespaceURI, "defs");
    const marker = document.createElementNS(svg.namespaceURI, "marker");
    const unit = GEOMETRY.markerViewBox;
    for (const [key, value] of Object.entries({id: "graph-arrow", viewBox: `0 0 ${unit} ${unit}`, refX: unit, refY: unit / 2, markerWidth: GEOMETRY.markerSize, markerHeight: GEOMETRY.markerSize, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse"})) marker.setAttribute(key, String(value));
    const arrow = document.createElementNS(svg.namespaceURI, "path");
    arrow.setAttribute("d", `M 0 0 L ${unit} ${unit / 2} L 0 ${unit} z`);
    marker.append(arrow); defs.append(marker); svg.append(defs);
    for (const edge of visible.edges) {
      const points = routes.get(edge.edgeId);
      if (!points) throw new Error("Visible edge route is unavailable");
      const polyline = document.createElementNS(svg.namespaceURI, "polyline");
      for (const [key, value] of Object.entries({class: "graph-edge", "data-edge-id": edge.edgeId, points: points.map(point => point.join(",")).join(" "), "marker-end": "url(#graph-arrow)"})) polyline.setAttribute(key, value);
      svg.append(polyline);
    }
    canvas.append(svg);
    for (const node of visible.nodes) {
      const position = positions.get(node.nodeId);
      if (!position) throw new Error("Node position is unavailable");
      const button = nodeButton(node);
      button.classList.add("graph-node");
      button.style.left = `${position.x}px`;
      button.style.top = `${position.y}px`;
      button.dataset.plane = node.evidencePlane;
      button.dataset.boundary = String(!primaryIDs.has(node.nodeId));
      nodeButtons.set(node.nodeId, button);
      canvas.append(button);
    }
    viewport.replaceChildren(canvas);
    recordBody.replaceChildren();
    const nodes = document.createElement("ul");
    nodes.setAttribute("aria-label", "Admitted traceability nodes");
    for (const node of visible.nodes) {
      const item = document.createElement("li");
      item.dataset.identity = node.nodeId;
      const button = nodeButton(node);
      recordButtons.set(node.nodeId, button);
      item.append(button);
      nodes.append(item);
    }
    const edges = document.createElement("ul");
    edges.setAttribute("aria-label", "Admitted traceability edges");
    for (const edge of visible.edges) {
      const item = document.createElement("li");
      item.dataset.identity = edge.edgeId;
      item.append(edgeRecord(edge, visible));
      edges.append(item);
    }
    recordBody.append(nodes, edges);
  }

  /** @param {any} node */
  function nodeButton(node) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.graphSelect = node.nodeId;
    button.title = `${node.label}: ${node.nodeId}`;
    const label = document.createElement("span"); label.className = "graph-node-label caller-text"; label.textContent = node.label;
    const identity = document.createElement("span"); identity.className = "graph-node-identity caller-text"; identity.textContent = node.nodeId;
    button.append(label, identity);
    button.addEventListener("click", () => select(node.nodeId));
    return button;
  }

  /** @param {any} record */
  function fields(record) {
    const list = document.createElement("dl");
    list.className = "graph-record-fields";
    for (const [key, value] of Object.entries(record)) {
      const term = document.createElement("dt"); term.textContent = key;
      const detail = document.createElement("dd"); detail.className = "caller-text";
      detail.textContent = Array.isArray(value) ? value.map(workspaceScalarText).join(", ") : workspaceScalarText(value);
      list.append(term, detail);
    }
    return list;
  }

  /** @param {any} edge @param {ReturnType<typeof visibleGraphPage>} visible */
  function edgeRecord(edge, visible) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.className = "caller-text";
    summary.textContent = `${edge.edgeKind}: ${edge.fromNodeId} -> ${edge.toNodeId}`;
    details.append(summary);
    details.addEventListener("toggle", () => {
      if (!details.open || details.querySelector("dl")) return;
      details.append(fields(edge));
      appendReferences(details, "edge", edge.edgeId, visible);
      options.reconcile();
    });
    return details;
  }

  /** @param {HTMLElement} parent @param {string} kind @param {string} id @param {ReturnType<typeof visibleGraphPage>} visible */
  function appendReferences(parent, kind, id, visible) {
    const visibleIDs = new Set(visible.nodes.map(node => node.nodeId));
    for (const ref of graph.references.filter((/** @type {any} */ ref) => ref.recordKind === kind && ref.recordId === id)) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "graph-reference";
      const outside = ref.disposition === "outside_page";
      const hidden = !outside && !visibleIDs.has(ref.targetNodeId);
      const label = document.createElement("bdi");
      label.textContent = `${ref.field}: ${ref.targetNodeId} (${outside ? "outside page" : hidden ? "hidden by filters" : "included"})`;
      button.append(icon("arrow-right"), label);
      if (outside) button.dataset.protectedRequest = "";
      button.addEventListener("click", () => {
        if (button.disabled) return;
        if (outside) options.follow(ref.targetOffset, ref.targetNodeId);
        else select(ref.targetNodeId, hidden);
      });
      parent.append(button);
    }
  }

  update();
}
