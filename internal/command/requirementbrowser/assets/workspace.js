// @ts-check

import {emptySelectionState, transitionSelection} from "./selection-authority.js";

export {};

/** @typedef {import("./selection-authority.js").SelectionTarget} SelectionTarget */

const capabilityElement = document.querySelector('meta[name="proofkit-browser-capability"]');
if (!(capabilityElement instanceof HTMLMetaElement)) throw new Error("Missing browser capability");
const capability = capabilityElement.content;
capabilityElement.remove();

const headers = {"Content-Type": "application/json", "X-Proofkit-Browser-Capability": capability};
const contentElement = document.querySelector("#workspace-content");
if (!(contentElement instanceof HTMLElement)) throw new Error("Missing workspace content region");
const content = /** @type {HTMLElement} */ (contentElement);

const manifest = await fetchJSON("/api/v1/manifest", {headers: {"X-Proofkit-Browser-Capability": capability}});
const authorityElement = document.querySelector("#workspace-authority");
if (!(authorityElement instanceof HTMLElement)) throw new Error("Missing workspace authority boundary");
const authorityText = authorityElement.querySelector("[data-authority]");
const authorityNonClaims = authorityElement.querySelector("[data-non-claims]");
if (!(authorityText instanceof HTMLElement) || !(authorityNonClaims instanceof HTMLUListElement)) throw new Error("Missing workspace authority fields");
authorityText.textContent = `Authority: ${manifest.authority}. Snapshot: ${manifest.snapshotId}. Baseline: ${manifest.baselineVerification}.`;
appendTextItems(authorityNonClaims, manifest.nonClaims ?? []);
let activeRequestId = "";
let requestSequence = 0;
/** @type {AbortController | null} */
let activeViewController = null;
let selectionState = emptySelectionState();

/** @param {string} prefix */
function nextRequestId(prefix) {
  requestSequence += 1;
  activeRequestId = `${prefix}.${requestSequence.toString(36)}`;
  return activeRequestId;
}

/** @param {string} path @param {RequestInit} init @returns {Promise<any>} */
async function fetchJSON(path, init) {
  const response = await fetch(path, init);
  if (!response.ok) throw new Error(`Workspace request failed: ${response.status}`);
  return response.json();
}

/** @param {string} path @param {any} body @param {AbortSignal} [signal] @returns {Promise<any>} */
async function post(path, body, signal) {
  return fetchJSON(path, {method: "POST", headers, body: JSON.stringify(body), signal});
}

/** @param {string} title @param {string} requestPrefix */
function beginView(title, requestPrefix) {
  activeViewController?.abort();
  activeViewController = new AbortController();
  const requestId = nextRequestId(requestPrefix);
  clearSelection();
  content.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent = title;
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  status.dataset.state = "loading";
  status.textContent = "Loading admitted data...";
  content.append(heading, status);
  return {requestId, signal: activeViewController.signal, status};
}

/** @param {HTMLElement} status @param {unknown} error */
function failView(status, error) {
  status.dataset.state = "failed";
  status.textContent = error instanceof Error ? error.message : "Workspace request failed.";
}

/** @param {number} [offset] */
async function renderSpecifications(offset = 0) {
  const {requestId, signal, status} = beginView("Specifications", "browser.specifications");
  try {
    const response = await post("/api/v1/requirements", {
      requestId,
      snapshotId: manifest.snapshotId,
      query: {maxRecords: 256, offset},
    }, signal);
    if (signal.aborted || requestId !== activeRequestId || response.requestId !== requestId || response.snapshotId !== manifest.snapshotId) return;
    status.remove();
    const tree = document.createElement("div");
    tree.setAttribute("role", "tree");
    tree.setAttribute("aria-label", "Specification requirements");
    const requirements = response.projection?.requirements ?? [];
    let itemIndex = 0;
    for (const requirement of requirements) {
        const article = document.createElement("article");
        article.setAttribute("role", "treeitem");
        article.tabIndex = itemIndex === 0 ? 0 : -1;
        article.dataset.requirementId = requirement.requirementId;
        const title = document.createElement("h3");
        title.textContent = requirement.requirementId;
        const boundary = document.createElement("section");
        boundary.className = "requirement-boundary";
        boundary.setAttribute("aria-label", `Boundary for ${requirement.requirementId}`);
        const ownership = document.createElement("p");
        ownership.textContent = `Owner: ${requirement.ownerId}. Claim level: ${requirement.claimLevel}.`;
        const nonClaims = document.createElement("ul");
        appendTextItems(nonClaims, [...(requirement.sourceNonClaims ?? []), ...(requirement.nonClaims ?? [])]);
        boundary.append(ownership, nonClaims);
        const invariant = document.createElement("p");
        const anchorId = requirement.anchor.anchorId;
        invariant.dataset.anchorId = anchorId;
        invariant.textContent = requirement.invariant;
        const choose = document.createElement("button");
        choose.type = "button";
        choose.dataset.selectAnchor = anchorId;
        choose.setAttribute("aria-pressed", "false");
        choose.textContent = "Select invariant";
        choose.addEventListener("click", () => {
          for (const control of content.querySelectorAll("[data-select-anchor]")) control.setAttribute("aria-pressed", "false");
          choose.setAttribute("aria-pressed", "true");
          selectionState = transitionSelection(selectionState, {kind: "button", targets: [{anchorId, exactQuote: requirement.invariant, startCodePoint: 0, endCodePoint: [...requirement.invariant].length}]});
          announceSelection();
        });
        article.append(title, boundary, invariant, choose);
        tree.append(article);
        itemIndex += 1;
    }
    if (itemIndex === 0) {
      status.dataset.state = "no-match";
      status.textContent = "No requirements matched the admitted query.";
      content.append(status);
      return;
    }
    tree.addEventListener("keydown", moveTreeFocus);
    content.append(tree);
    appendPagingControls("specifications", offset, response.projection.selectedRequirementCount ?? 0, response.projection.availableRequirementCount ?? 0);
  } catch (error) {
    if (signal.aborted) return;
    failView(status, error);
  }
}

/** @param {KeyboardEvent} event */
function moveTreeFocus(event) {
  if (!["ArrowDown", "ArrowUp"].includes(event.key)) return;
  const items = /** @type {HTMLElement[]} */ ([...content.querySelectorAll('[role="treeitem"]')]);
  const active = document.activeElement;
  if (!(active instanceof HTMLElement)) return;
  const current = items.indexOf(active);
  if (current < 0) return;
  event.preventDefault();
  const direction = event.key === "ArrowDown" ? 1 : -1;
  const next = Math.max(0, Math.min(items.length - 1, current + direction));
  const nextItem = items[next];
  if (!nextItem) return;
  for (const item of items) item.tabIndex = item === nextItem ? 0 : -1;
  nextItem.focus();
}

/** @param {number} [offset] */
async function renderDiff(offset = 0) {
  const {requestId, signal, status} = beginView("Semantic diff", "browser.diff");
  if (!manifest.diffAvailable) {
    status.dataset.state = "unavailable";
    status.textContent = "No admitted semantic diff was supplied.";
    return;
  }
  try {
    const response = await post("/api/v1/diff", {requestId, snapshotId: manifest.snapshotId, query: {maxRecords: 512, offset}}, signal);
    if (signal.aborted || requestId !== activeRequestId || response.requestId !== requestId || response.snapshotId !== manifest.snapshotId) return;
    status.remove();
    appendProjectionBoundary(response.projection.authority, response.projection.nonClaims ?? [], [
      `Base snapshot: ${response.projection.baseSnapshotId} (${response.projection.baseBaselineVerification}).`,
      `Current snapshot: ${response.projection.currentSnapshotId} (${response.projection.currentBaselineVerification}).`,
    ]);
    for (const change of response.projection.changes ?? []) {
      const article = document.createElement("article");
      article.dataset.changeId = change.changeId;
      const title = document.createElement("h3");
      title.textContent = `${change.changeClass}: ${change.entityId}`;
      const pointer = document.createElement("p");
      pointer.textContent = change.jsonPointer;
      const sourceDigests = document.createElement("p");
      sourceDigests.textContent = `Source digests: ${change.baseSourceDigest ?? "not-recorded"} -> ${change.currentSourceDigest ?? "not-recorded"}`;
      const values = document.createElement("pre");
      values.textContent = `${JSON.stringify(change.before, null, 2)}\n->\n${JSON.stringify(change.after, null, 2)}`;
      article.append(title, pointer, sourceDigests, values);
      content.append(article);
    }
    appendPagingControls("diff", offset, response.projection.selectedChangeCount ?? 0, response.projection.availableChangeCount ?? 0);
  } catch (error) {
    if (signal.aborted) return;
    failView(status, error);
  }
}

/** @param {number} [offset] */
async function renderGraph(offset = 0, edgeOffset = 0) {
  const {requestId, signal, status} = beginView("Traceability graph", "browser.graph");
  if (!manifest.graphAvailable) {
    status.dataset.state = "unavailable";
    status.textContent = "No admitted traceability graph was supplied.";
    return;
  }
  try {
    const response = await post("/api/v1/graph", {requestId, snapshotId: manifest.snapshotId, query: {edgeOffset, maxEdges: 2048, maxRecords: 256, offset}}, signal);
    if (signal.aborted || requestId !== activeRequestId || response.requestId !== requestId || response.snapshotId !== manifest.snapshotId) return;
    status.remove();
    const graph = response.projection;
    appendProjectionBoundary(graph.authority, graph.nonClaims ?? [], [`Source snapshot: ${graph.sourceSnapshotId}.`]);
    const nodes = /** @type {any[]} */ (graph.nodes ?? []);
    const edges = /** @type {any[]} */ (graph.edges ?? []);
    const positions = new Map(nodes.map((node, index) => [node.nodeId, {x: 28 + (index % 2) * 390, y: 28 + Math.floor(index / 2) * 76}]));
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Non-authoritative layout of admitted traceability nodes and edges");
    svg.setAttribute("viewBox", `0 0 800 ${Math.max(180, Math.ceil(nodes.length / 2) * 76 + 40)}`);
    svg.dataset.nodeIds = nodes.map((node) => node.nodeId).join(" ");
    svg.dataset.edgeIds = edges.map((edge) => edge.edgeId).join(" ");
    for (const edge of edges) {
      const from = positions.get(edge.fromNodeId);
      const to = positions.get(edge.toNodeId);
      if (!from || !to) throw new Error("Graph edge endpoint is not present in admitted nodes");
      const line = document.createElementNS(svg.namespaceURI, "line");
      line.setAttribute("data-edge-id", edge.edgeId);
      line.setAttribute("x1", String(from.x + 180));
      line.setAttribute("y1", String(from.y + 24));
      line.setAttribute("x2", String(to.x + 180));
      line.setAttribute("y2", String(to.y + 24));
      svg.append(line);
    }
    for (const node of nodes) {
      const position = positions.get(node.nodeId);
      if (!position) throw new Error("Graph node position is unavailable");
      const group = document.createElementNS(svg.namespaceURI, "g");
      group.setAttribute("data-node-id", node.nodeId);
      const box = document.createElementNS(svg.namespaceURI, "rect");
      box.setAttribute("x", String(position.x));
      box.setAttribute("y", String(position.y));
      box.setAttribute("width", "350");
      box.setAttribute("height", "48");
      box.setAttribute("rx", "4");
      const label = document.createElementNS(svg.namespaceURI, "text");
      label.setAttribute("x", String(position.x + 10));
      label.setAttribute("y", String(position.y + 29));
      const fullLabel = `${node.evidencePlane}: ${node.label}`;
      label.textContent = [...fullLabel].length > 48 ? `${[...fullLabel].slice(0, 47).join("")}...` : fullLabel;
      const accessibleLabel = document.createElementNS(svg.namespaceURI, "title");
      accessibleLabel.textContent = fullLabel;
      group.append(accessibleLabel, box, label);
      svg.append(group);
    }
    const viewport = document.createElement("div");
    viewport.className = "graph-viewport";
    viewport.append(svg);
    content.append(viewport, graphTable(
      "Admitted traceability nodes",
      ["Node", "Kind", "Evidence plane", "Source", "Authority", "Currentness", "Verification", "State", "Producer"],
      nodes.map((node) => [node.nodeId, node.kind, node.evidencePlane, node.sourceId, node.authorityClass, node.currentnessState, node.rangeVerification, node.state, node.producerId]),
      "node",
    ));
    content.append(graphTable(
      "Admitted traceability edges",
      ["Edge", "Kind", "From", "To", "Authority", "Currentness", "Evidence"],
      edges.map((edge) => [edge.edgeId, edge.edgeKind, edge.fromNodeId, edge.toNodeId, edge.authorityClass, edge.currentnessState, displayList(edge.evidenceRefs)]),
      "edge",
    ));
    appendPagingControls("graph", offset, graph.primaryNodeCount ?? 0, graph.availableNodeCount ?? 0);
    appendGraphEdgeControls(offset, edgeOffset, graph.selectedEdgeCount ?? 0, graph.availableIncidentEdgeCount ?? 0);
  } catch (error) {
    if (signal.aborted) return;
    failView(status, error);
  }
}

/** @param {"specifications" | "diff" | "graph"} view @param {number} offset @param {number} selectedCount @param {number} availableCount */
function appendPagingControls(view, offset, selectedCount, availableCount) {
  const summary = document.createElement("p");
  const first = selectedCount === 0 ? 0 : offset + 1;
  summary.textContent = `Showing ${first}-${offset + selectedCount} of ${availableCount} ${view} records.`;
  content.append(summary);
  if (offset === 0 && selectedCount >= availableCount) return;
  const controls = document.createElement("nav");
  controls.setAttribute("aria-label", `${view} pages`);
  const pageSize = view === "diff" ? 512 : 256;
  if (offset > 0) {
    const previous = document.createElement("button");
    previous.type = "button";
    previous.textContent = `Previous ${view} page`;
    previous.addEventListener("click", () => void (view === "diff" ? renderDiff(Math.max(0, offset - pageSize)) : view === "graph" ? renderGraph(Math.max(0, offset - pageSize)) : renderSpecifications(Math.max(0, offset - pageSize))));
    controls.append(previous);
  }
  if (offset + selectedCount < availableCount) {
    const next = document.createElement("button");
    next.type = "button";
    next.textContent = `Next ${view} page`;
    next.addEventListener("click", () => void (view === "diff" ? renderDiff(offset + selectedCount) : view === "graph" ? renderGraph(offset + selectedCount) : renderSpecifications(offset + selectedCount)));
    controls.append(next);
  }
  content.append(controls);
}

/** @param {number} nodeOffset @param {number} edgeOffset @param {number} selectedCount @param {number} availableCount */
function appendGraphEdgeControls(nodeOffset, edgeOffset, selectedCount, availableCount) {
  const summary = document.createElement("p");
  const first = selectedCount === 0 ? 0 : edgeOffset + 1;
  summary.textContent = `Showing ${first}-${edgeOffset + selectedCount} of ${availableCount} incident graph relations.`;
  content.append(summary);
  if (edgeOffset === 0 && selectedCount >= availableCount) return;
  const controls = document.createElement("nav");
  controls.setAttribute("aria-label", "graph relation pages");
  if (edgeOffset > 0) {
    const previous = document.createElement("button");
    previous.type = "button";
    previous.textContent = "Previous graph relation page";
    previous.addEventListener("click", () => void renderGraph(nodeOffset, Math.max(0, edgeOffset - 2048)));
    controls.append(previous);
  }
  if (edgeOffset + selectedCount < availableCount) {
    const next = document.createElement("button");
    next.type = "button";
    next.textContent = "Next graph relation page";
    next.addEventListener("click", () => void renderGraph(nodeOffset, edgeOffset + selectedCount));
    controls.append(next);
  }
  content.append(controls);
}

/** @param {string} captionText @param {string[]} headings @param {string[][]} rows @param {string} identityKind */
function graphTable(captionText, headings, rows, identityKind) {
  const table = document.createElement("table");
  table.dataset.identityKind = identityKind;
  const caption = document.createElement("caption");
  caption.textContent = captionText;
  const head = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const label of headings) {
    const cell = document.createElement("th");
    cell.textContent = label;
    headRow.append(cell);
  }
  head.append(headRow);
  const body = document.createElement("tbody");
  for (const values of rows) {
    const row = document.createElement("tr");
    row.dataset.identity = values[0] ?? "";
    for (const value of values) {
      const cell = document.createElement("td");
      cell.textContent = value ?? "";
      row.append(cell);
    }
    body.append(row);
  }
  table.append(caption, head, body);
  return table;
}

/** @param {unknown} value */
function displayList(value) {
  return Array.isArray(value) ? value.join(", ") : value;
}

/** @param {HTMLUListElement} list @param {unknown[]} values */
function appendTextItems(list, values) {
  for (const value of values) {
    const item = document.createElement("li");
    item.textContent = String(value);
    list.append(item);
  }
}

/** @param {unknown} authority @param {unknown[]} nonClaims @param {string[]} details */
function appendProjectionBoundary(authority, nonClaims, details) {
  const section = document.createElement("section");
  section.className = "projection-boundary";
  section.setAttribute("aria-label", "Projection boundary");
  const heading = document.createElement("h3");
  heading.textContent = "Projection boundary";
  const authorityText = document.createElement("p");
  authorityText.textContent = `Authority: ${String(authority)}.`;
  section.append(heading, authorityText);
  for (const detail of details) {
    const paragraph = document.createElement("p");
    paragraph.textContent = detail;
    section.append(paragraph);
  }
  const list = document.createElement("ul");
  appendTextItems(list, nonClaims);
  section.append(list);
  content.append(section);
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => {
  if (!(button instanceof HTMLButtonElement)) return;
  if (button.dataset.view === "specifications") void renderSpecifications();
  if (button.dataset.view === "diff") void renderDiff();
  if (button.dataset.view === "graph") void renderGraph();
}));

document.addEventListener("selectionchange", () => {
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed || selection.rangeCount !== 1) {
    const nextState = transitionSelection(selectionState, {kind: "collapse"});
    if (nextState !== selectionState) {
      selectionState = nextState;
      resetPressedSelectionControls();
      announceSelection();
    }
    return;
  }
  const range = selection.getRangeAt(0);
  /** @type {SelectionTarget[]} */
  const targets = [];
  for (const element of content.querySelectorAll("[data-anchor-id]")) {
    if (!(element instanceof HTMLElement) || !range.intersectsNode(element) || !element.firstChild) continue;
    const local = document.createRange();
    local.selectNodeContents(element);
    if (element.contains(range.startContainer)) local.setStart(range.startContainer, range.startOffset);
    if (element.contains(range.endContainer)) local.setEnd(range.endContainer, range.endOffset);
    const exactQuote = local.toString();
    if (!exactQuote) continue;
    const prefix = document.createRange();
    prefix.selectNodeContents(element);
    prefix.setEnd(local.startContainer, local.startOffset);
    const startCodePoint = [...prefix.toString()].length;
    const anchorId = element.dataset.anchorId;
    if (!anchorId) continue;
    targets.push({anchorId, exactQuote, startCodePoint, endCodePoint: startCodePoint + [...exactQuote].length});
  }
  selectionState = transitionSelection(selectionState, {kind: "text", targets});
  resetPressedSelectionControls();
  announceSelection();
});

const questionInputElement = document.querySelector("#annotation-question");
const statusElement = document.querySelector("#handoff-status");
const packetElement = document.querySelector("#handoff-packet");
const submitElement = document.querySelector("#submit-question");
if (!(questionInputElement instanceof HTMLTextAreaElement) || !(statusElement instanceof HTMLElement) || !(packetElement instanceof HTMLElement) || !(submitElement instanceof HTMLButtonElement)) throw new Error("Missing handoff controls");
const questionInput = /** @type {HTMLTextAreaElement} */ (questionInputElement);
const status = /** @type {HTMLElement} */ (statusElement);
const packetView = /** @type {HTMLElement} */ (packetElement);
const submit = /** @type {HTMLButtonElement} */ (submitElement);

function announceSelection() {
  status.textContent = selectionState.targets.length === 0 ? "No source-bound text selected." : `${selectionState.targets.length} source-bound target(s) selected.`;
}

function resetPressedSelectionControls() {
  for (const control of content.querySelectorAll("[data-select-anchor]")) control.setAttribute("aria-pressed", "false");
}

function clearSelection() {
  selectionState = transitionSelection(selectionState, {kind: "clear"});
  resetPressedSelectionControls();
  const selection = window.getSelection();
  if (selection && !selection.isCollapsed) selection.removeAllRanges();
  status.textContent = "No source-bound text selected.";
}
submit.addEventListener("click", async () => {
  if (submit.disabled) return;
  const question = questionInput.value.trim();
  if (selectionState.targets.length === 0 || !question) {
    status.textContent = "Select invariant text and enter a question.";
    return;
  }
  submit.disabled = true;
  status.textContent = "Creating handoff packet...";
  try {
    const packet = await post("/api/v1/handoff", {annotations: selectionState.targets.map((target) => ({...target, question}))});
    packetView.textContent = JSON.stringify(packet, null, 2);
    status.textContent = "Handoff packet created.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Handoff was rejected.";
  } finally {
    submit.disabled = false;
  }
});

void renderSpecifications();
