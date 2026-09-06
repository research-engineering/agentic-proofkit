// @ts-check

import {emptySelectionState, transitionSelection} from "./selection-authority.js";
import {decorateIcons, icon} from "./workspace-icons.js";
import {initializePanels} from "./workspace-panels.js";
import {initializeNavigation} from "./workspace-navigation.js";
import {fetchWorkspaceJSON, fetchWorkspaceResponse, workspaceFailure} from "./workspace-requests.js";
import {renderCoveragePage} from "./workspace-coverage.js";
import {renderDiffPage} from "./workspace-diff.js";
import {GRAPH_PAGE, renderGraphPage} from "./workspace-graph.js";
import {initializeHandoffPreview} from "./workspace-handoff.js";

export {};

/** @typedef {import("./selection-authority.js").SelectionTarget} SelectionTarget */
/** @typedef {"specifications" | "coverage" | "diff" | "graph"} WorkspaceView */

const capabilityElement = document.querySelector('meta[name="proofkit-browser-capability"]');
if (!(capabilityElement instanceof HTMLMetaElement)) throw new Error("Missing browser capability");
const capability = capabilityElement.content;
capabilityElement.remove();

const headers = {"Content-Type": "application/json", "X-Proofkit-Browser-Capability": capability};
const contentElement = document.querySelector("#workspace-content");
if (!(contentElement instanceof HTMLElement)) throw new Error("Missing workspace content region");
const content = /** @type {HTMLElement} */ (contentElement);
const recovery = document.createElement("div");
recovery.id = "workspace-recovery";
content.before(recovery);

const authorityElement = document.querySelector("#workspace-authority");
if (!(authorityElement instanceof HTMLElement)) throw new Error("Missing workspace authority boundary");
const authorityText = authorityElement.querySelector("[data-authority]");
const authorityNonClaims = authorityElement.querySelector("[data-non-claims]");
if (!(authorityText instanceof HTMLElement) || !(authorityNonClaims instanceof HTMLUListElement)) throw new Error("Missing workspace authority fields");
const authorityTextView = /** @type {HTMLElement} */ (authorityText);
const authorityNonClaimsView = /** @type {HTMLUListElement} */ (authorityNonClaims);
/** @type {any} */
let manifest = null;
let activeRequestId = "";
let requestSequence = 0;
/** @type {AbortController | null} */
let activeViewController = null;
let selectionState = emptySelectionState();
let requestsLocked = false;
let handoffPending = false;
/** @type {"specifications" | "coverage"} */
let lookupView = "specifications";
/** @type {import("./workspace-navigation.js").LookupFilters} */
let activeFilters = Object.freeze({});

/** @param {string} prefix */
function nextRequestId(prefix) {
  requestSequence += 1;
  return `${prefix}.${requestSequence.toString(36)}`;
}

/** @param {string} state */
function setWorkspaceState(state) {
  document.body.dataset.state = state;
}

/** @param {WorkspaceView} activeView */
function setActiveView(activeView) {
  for (const control of document.querySelectorAll("[data-view]")) {
    if (!(control instanceof HTMLButtonElement)) continue;
    if (control.dataset.view === activeView) {
      control.setAttribute("aria-current", "page");
    } else {
      control.removeAttribute("aria-current");
    }
  }
}

function handoffUnavailable() {
  return manifest === null || requestsLocked || handoffPending;
}

function reconcileRequestControls() {
  for (const control of document.querySelectorAll("[data-protected-request]")) {
    if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement || control instanceof HTMLSelectElement) {
      control.disabled = control === submit || control.hasAttribute("data-evidence-question") ? handoffUnavailable() : requestsLocked;
    }
  }
}

/** @param {WorkspaceView} state */
function completeContentView(state) {
  reconcileRequestControls();
  content.setAttribute("aria-busy", "false");
  setWorkspaceState(state);
}

async function initializeWorkspace() {
  if (requestsLocked) return;
  activeViewController?.abort();
  activeViewController = new AbortController();
  const signal = activeViewController.signal;
  const requestId = nextRequestId("browser.bootstrap");
  activeRequestId = requestId;
  setWorkspaceState("bootstrap-loading");
  const heading = document.createElement("h2");
  heading.textContent = "Loading workspace";
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  status.textContent = "Loading admitted manifest...";
  content.replaceChildren(heading, status);
  content.setAttribute("aria-busy", "true");
  try {
    const response = await fetchWorkspaceJSON("/api/v1/manifest", {headers: {"X-Proofkit-Browser-Capability": capability}, signal});
    if (signal.aborted || requestId !== activeRequestId) return;
    manifest = response;
    authorityTextView.textContent = `Authority: ${manifest.authority}. Snapshot: ${manifest.snapshotId}. Expected-digest coverage: ${manifest.expectedDigestCoverage}.`;
    appendTextItems(authorityNonClaimsView, manifest.nonClaims ?? []);
    reconcileRequestControls();
    navigation.start(manifest);
    await renderSpecifications();
  } catch (error) {
    if (signal.aborted || requestId !== activeRequestId) return;
    activeViewController?.abort();
    content.replaceChildren();
    content.setAttribute("aria-busy", "false");
    const heading = document.createElement("h2");
    heading.textContent = "Workspace unavailable";
    content.append(heading);
    showFailure(error, content, () => void initializeWorkspace());
    setWorkspaceState("bootstrap-failed");
  }
}

/** @param {string} path @param {any} body @param {AbortSignal} [signal] @returns {Promise<any>} */
async function post(path, body, signal) {
  return fetchWorkspaceJSON(path, {method: "POST", headers, body: JSON.stringify(body), signal});
}

/** @param {string} title @param {string} requestPrefix @param {WorkspaceView} view @param {boolean} [focusContent] */
function beginView(title, requestPrefix, view, focusContent = false) {
  const restoreFocus = focusContent || document.activeElement !== null && content.contains(document.activeElement);
  activeViewController?.abort();
  activeViewController = new AbortController();
  const requestId = nextRequestId(requestPrefix);
  activeRequestId = requestId;
  clearSelection();
  handoffPreview.clear();
  setActiveView(view);
  setWorkspaceState(`${view}-loading`);
  content.replaceChildren();
  content.setAttribute("aria-busy", "true");
  const heading = document.createElement("h2");
  heading.textContent = title;
  heading.tabIndex = -1;
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  status.dataset.state = "loading";
  status.textContent = "Loading admitted data...";
  content.append(heading, status);
  if (restoreFocus) heading.focus();
  const focusAfterCommit = () => {
    if (restoreFocus && heading.isConnected && activeRequestId === requestId && (document.activeElement === document.body || document.activeElement === heading)) heading.focus();
  };
  return {requestId, signal: activeViewController.signal, status, focusAfterCommit};
}

/** @param {ReturnType<typeof workspaceFailure>} failure */
function applyFailureLock(failure) {
  if (!failure.lock) return;
  requestsLocked = true;
  reconcileRequestControls();
  navigation.cancel();
  if (failure.action === "reload" && !recovery.hasChildNodes()) {
    const action = document.createElement("button");
    action.type = "button";
    action.title = failure.message;
    action.append(icon("refresh-cw"), document.createTextNode("Reload workspace"));
    action.addEventListener("click", () => window.location.reload());
    recovery.append(action);
  }
}

/** @param {unknown} error @param {HTMLElement} container @param {() => void} retry @param {boolean} [optional] */
function showFailure(error, container, retry, optional = false) {
  const failure = workspaceFailure(error, optional);
  applyFailureLock(failure);
  const message = document.createElement("p");
  message.setAttribute("role", "alert");
  message.dataset.state = failure.kind;
  message.textContent = failure.message;
  container.append(message);
  if (failure.action === "none" || failure.lock) return;
  const action = document.createElement("button");
  action.type = "button";
  action.dataset.protectedRequest = "";
  action.disabled = requestsLocked;
  action.append(icon("refresh-cw"), document.createTextNode("Retry"));
  action.addEventListener("click", () => {
    if (!action.isConnected) return;
    if (!requestsLocked) retry();
  });
  container.append(action);
}

/** @param {HTMLElement} status @param {unknown} error @param {() => void} retry @param {boolean} [optional] */
function failView(status, error, retry, optional = false) {
  content.setAttribute("aria-busy", "false");
  setWorkspaceState("view-failed");
  status.remove();
  const failedRequestId = activeRequestId;
  showFailure(error, content, () => { if (activeRequestId === failedRequestId) retry(); }, optional);
}

/** @param {any} response @param {string} requestId @param {AbortSignal} signal */
function admitCurrentViewResponse(response, requestId, signal) {
  if (signal.aborted || requestId !== activeRequestId) return false;
  if (response?.requestId !== requestId || response?.snapshotId !== manifest.snapshotId) {
    throw new Error("Workspace view response identity mismatch");
  }
  return true;
}

/** @param {number} [offset] @param {import("./workspace-navigation.js").LookupFilters} [filters] @param {number[]} [history] */
async function renderSpecifications(offset = 0, filters = activeFilters, history = []) {
  if (requestsLocked) return;
  lookupView = "specifications";
  activeFilters = filters;
  const query = Object.freeze({...filters, maxRecords: 64, offset});
  const {requestId, signal, status} = beginView("Specifications", "browser.specifications", "specifications");
  try {
    const response = await post("/api/v1/requirements", {
      requestId,
      snapshotId: manifest.snapshotId,
      query,
    }, signal);
    if (!admitCurrentViewResponse(response, requestId, signal)) return;
    status.remove();
    const list = document.createElement("ul");
    list.setAttribute("aria-label", "Specification requirements");
    const requirements = response.projection?.requirements ?? [];
    let itemIndex = 0;
    for (const requirement of requirements) {
        const item = document.createElement("li");
        const article = document.createElement("article");
        article.dataset.requirementId = requirement.requirementId;
        const title = document.createElement("h3");
        title.textContent = requirement.requirementId;
        const boundary = document.createElement("details");
        boundary.className = "requirement-boundary";
        boundary.setAttribute("aria-label", `Boundary for ${requirement.requirementId}`);
        const ownership = document.createElement("summary");
        ownership.textContent = `Owner: ${requirement.ownerId}. Claim level: ${requirement.claimLevel}.`;
        boundary.append(ownership);
        boundary.addEventListener("toggle", () => {
          if (!boundary.open || boundary.querySelector("ul")) return;
          const nonClaims = document.createElement("ul");
          appendTextItems(nonClaims, [...(requirement.sourceNonClaims ?? []), ...(requirement.nonClaims ?? [])]);
          boundary.append(nonClaims);
        });
        const invariant = document.createElement("p");
        const anchorId = requirement.anchor.anchorId;
        invariant.dataset.anchorId = anchorId;
        invariant.textContent = requirement.invariant;
        const choose = document.createElement("button");
        choose.type = "button";
        choose.dataset.selectAnchor = anchorId;
        choose.setAttribute("aria-pressed", "false");
        choose.append(icon("check"), document.createTextNode("Select invariant"));
        choose.addEventListener("click", () => {
          for (const control of content.querySelectorAll("[data-select-anchor]")) control.setAttribute("aria-pressed", "false");
          choose.setAttribute("aria-pressed", "true");
          selectionState = transitionSelection(selectionState, {kind: "button", targets: [{anchorId, exactQuote: requirement.invariant, startCodePoint: 0, endCodePoint: [...requirement.invariant].length}]});
          announceSelection();
        });
        article.append(title, invariant, boundary, choose);
        item.append(article);
        list.append(item);
        itemIndex += 1;
    }
    if (itemIndex === 0) {
      status.dataset.state = "no-match";
      status.textContent = "No requirements matched the admitted query.";
      content.append(status);
      completeContentView("specifications");
      return;
    }
    content.append(list);
    appendRequirementPaging("specifications", offset, response.projection.selectedRequirementCount ?? 0, response.projection.matchingRequirementCount ?? 0, filters, history);
    completeContentView("specifications");
  } catch (error) {
    if (signal.aborted || requestId !== activeRequestId) return;
    failView(status, error, () => void renderSpecifications(offset, filters, history));
  }
}

/** @param {number} [offset] @param {import("./workspace-navigation.js").LookupFilters} [filters] @param {number[]} [history] */
async function renderCoverage(offset = 0, filters = activeFilters, history = []) {
  if (requestsLocked) return;
  lookupView = "coverage";
  activeFilters = filters;
  const query = Object.freeze({...filters, maxRecords: 64, offset});
  const {requestId, signal, status} = beginView("Coverage", "browser.coverage", "coverage");
  if (!manifest.coverageAvailable) {
    content.setAttribute("aria-busy", "false");
    setWorkspaceState("coverage-unavailable");
    status.dataset.state = "unavailable";
    status.textContent = "No admitted coverage report was supplied.";
    return;
  }
  try {
    const response = await post("/api/v1/coverage", {requestId, snapshotId: manifest.snapshotId, query}, signal);
    if (!admitCurrentViewResponse(response, requestId, signal)) return;
    status.remove();
    const projection = response.projection;
    appendProjectionBoundary(projection.coverageAuthority, projection.nonClaims, [`Coverage input: ${projection.sourceViewInputId}.`], true);
    renderCoveragePage(content, projection, (requirement, opener) => {
      if (handoffUnavailable()) return;
      selectionState = transitionSelection(selectionState, {kind: "button", targets: [{anchorId: requirement.anchor.anchorId, exactQuote: requirement.invariant, startCodePoint: 0, endCodePoint: [...requirement.invariant].length}]});
      announceSelection();
      if (questionInput.value === "") questionInput.value = `What evidence supports ${requirement.requirementId}?`;
      panels.showInspector(opener);
    });
    appendRequirementPaging("coverage", offset, projection.selectedRequirementCount, projection.matchingRequirementCount, filters, history);
    completeContentView("coverage");
  } catch (error) {
    if (signal.aborted || requestId !== activeRequestId) return;
    failView(status, error, () => void renderCoverage(offset, filters, history), true);
  }
}

/** @param {number} [offset] */
async function renderDiff(offset = 0) {
  if (requestsLocked) return;
  const {requestId, signal, status} = beginView("Semantic diff", "browser.diff", "diff");
  if (!manifest.diffAvailable) {
    content.setAttribute("aria-busy", "false");
    setWorkspaceState("diff-unavailable");
    status.dataset.state = "unavailable";
    status.textContent = "No admitted semantic diff was supplied.";
    return;
  }
  try {
    const response = await post("/api/v1/diff", {requestId, snapshotId: manifest.snapshotId, query: {maxRecords: 512, offset}}, signal);
    if (!admitCurrentViewResponse(response, requestId, signal)) return;
    status.remove();
    appendProjectionBoundary(response.projection.authority, response.projection.nonClaims ?? [], [
      `Base snapshot: ${response.projection.baseSnapshotId} (expected-digest coverage: ${response.projection.baseExpectedDigestCoverage}).`,
      `Current snapshot: ${response.projection.currentSnapshotId} (expected-digest coverage: ${response.projection.currentExpectedDigestCoverage}).`,
    ]);
    renderDiffPage(content, response.projection.changes ?? []);
    appendPagingControls("diff", offset, response.projection.selectedChangeCount ?? 0, response.projection.availableChangeCount ?? 0);
    completeContentView("diff");
  } catch (error) {
    if (signal.aborted || requestId !== activeRequestId) return;
    failView(status, error, () => void renderDiff(offset), true);
  }
}

/** @param {number} [offset] @param {number} [edgeOffset] @param {string | null} [initialId] */
async function renderGraph(offset = 0, edgeOffset = 0, initialId = null) {
  if (requestsLocked) return;
  const {requestId, signal, status, focusAfterCommit} = beginView("Traceability graph", "browser.graph", "graph", initialId !== null);
  if (!manifest.graphAvailable) {
    content.setAttribute("aria-busy", "false");
    setWorkspaceState("graph-unavailable");
    status.dataset.state = "unavailable";
    status.textContent = "No admitted traceability graph was supplied.";
    return;
  }
  try {
    const response = await post("/api/v1/graph", {requestId, snapshotId: manifest.snapshotId, query: {...GRAPH_PAGE, edgeOffset, offset}}, signal);
    if (!admitCurrentViewResponse(response, requestId, signal)) return;
    status.remove();
    const graph = response.projection;
    appendProjectionBoundary(graph.authority, graph.nonClaims ?? [], [`Source snapshot: ${graph.sourceSnapshotId}.`]);
    if (initialId !== null && !graph.nodes.some((/** @type {any} */ node) => node.nodeId === initialId)) throw new Error("Referenced node is unavailable in its canonical page");
    renderGraphPage(content, graph, {
      follow: (targetOffset, targetId) => void renderGraph(targetOffset, 0, targetId),
      reconcile: reconcileRequestControls,
      initialId,
    });
    appendPagingControls("graph", offset, graph.primaryNodeCount ?? 0, graph.availableNodeCount ?? 0);
    appendGraphEdgeControls(offset, edgeOffset, graph.selectedEdgeCount ?? 0, graph.availableIncidentEdgeCount ?? 0);
    completeContentView("graph");
    focusAfterCommit();
  } catch (error) {
    if (signal.aborted || requestId !== activeRequestId) return;
    failView(status, error, () => void renderGraph(offset, edgeOffset, initialId), true);
  }
}

/** @param {"specifications" | "coverage"} view @param {number} offset @param {number} selected @param {number} matching @param {import("./workspace-navigation.js").LookupFilters} filters @param {number[]} history */
function appendRequirementPaging(view, offset, selected, matching, filters, history) {
  const render = view === "coverage" ? renderCoverage : renderSpecifications;
  const summary = document.createElement("p");
  summary.className = "page-summary";
  summary.textContent = `Showing ${selected === 0 ? 0 : offset + 1}-${offset + selected} of ${matching} ${view} records.`;
  content.append(summary);
  const controls = document.createElement("nav");
  controls.setAttribute("aria-label", `${view} pages`);
  /** @param {string} label @param {string} symbol @param {() => void} action */
  function add(label, symbol, action) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.protectedRequest = "";
    button.append(icon(symbol), document.createTextNode(label));
    button.addEventListener("click", action);
    controls.append(button);
  }
  if (history.length > 0) add(`Previous ${view} page`, "arrow-left", () => void render(history.at(-1) ?? 0, filters, history.slice(0, -1)));
  if (offset + selected < matching) add(`Next ${view} page`, "arrow-right", () => void render(offset + selected, filters, [...history, offset]));
  content.append(controls);
}

/** @param {"diff" | "graph"} view @param {number} offset @param {number} selectedCount @param {number} availableCount */
function appendPagingControls(view, offset, selectedCount, availableCount) {
  const summary = document.createElement("p");
  const first = selectedCount === 0 ? 0 : offset + 1;
  summary.textContent = `Showing ${first}-${offset + selectedCount} of ${availableCount} ${view} records.`;
  content.append(summary);
  if (offset === 0 && selectedCount >= availableCount) return;
  const controls = document.createElement("nav");
  controls.setAttribute("aria-label", `${view} pages`);
  const pageSize = view === "diff" ? 512 : GRAPH_PAGE.maxRecords;
  if (offset > 0) {
    const previous = document.createElement("button");
    previous.type = "button";
    previous.dataset.protectedRequest = "";
    previous.textContent = `Previous ${view} page`;
    previous.addEventListener("click", () => void (view === "diff" ? renderDiff(Math.max(0, offset - pageSize)) : renderGraph(Math.max(0, offset - pageSize))));
    controls.append(previous);
  }
  if (offset + selectedCount < availableCount) {
    const next = document.createElement("button");
    next.type = "button";
    next.dataset.protectedRequest = "";
    next.textContent = `Next ${view} page`;
    next.addEventListener("click", () => void (view === "diff" ? renderDiff(offset + selectedCount) : renderGraph(offset + selectedCount)));
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
    previous.dataset.protectedRequest = "";
    previous.textContent = "Previous graph relation page";
    previous.addEventListener("click", () => void renderGraph(nodeOffset, Math.max(0, edgeOffset - GRAPH_PAGE.maxEdges)));
    controls.append(previous);
  }
  if (edgeOffset + selectedCount < availableCount) {
    const next = document.createElement("button");
    next.type = "button";
    next.dataset.protectedRequest = "";
    next.textContent = "Next graph relation page";
    next.addEventListener("click", () => void renderGraph(nodeOffset, edgeOffset + selectedCount));
    controls.append(next);
  }
  content.append(controls);
}

/** @param {HTMLUListElement} list @param {unknown[]} values */
function appendTextItems(list, values) {
  for (const value of values) {
    const item = document.createElement("li");
    item.textContent = String(value);
    list.append(item);
  }
}

/** @param {unknown} authority @param {unknown[]} nonClaims @param {string[]} details @param {boolean} [collapsed] */
function appendProjectionBoundary(authority, nonClaims, details, collapsed = false) {
  const section = document.createElement(collapsed ? "details" : "section");
  section.className = "projection-boundary";
  section.setAttribute("aria-label", "Projection boundary");
  const heading = document.createElement(collapsed ? "summary" : "h3");
  heading.textContent = collapsed ? `Derived coverage: ${String(authority)}` : "Projection boundary";
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
  if (button.dataset.view === "coverage") void renderCoverage();
  if (button.dataset.view === "diff") void renderDiff();
  if (button.dataset.view === "graph") void renderGraph();
}));

const questionInputElement = document.querySelector("#annotation-question");
const statusElement = document.querySelector("#handoff-status");
const packetElement = document.querySelector("#handoff-packet");
const previewElement = document.querySelector("#handoff-preview");
const submitElement = document.querySelector("#submit-question");
const selectedContextElement = document.querySelector("#selected-context");
const clearSelectionElement = document.querySelector("#clear-selection");
if (!(questionInputElement instanceof HTMLTextAreaElement) || !(statusElement instanceof HTMLElement) || !(packetElement instanceof HTMLElement) || !(previewElement instanceof HTMLElement) || !(submitElement instanceof HTMLButtonElement) || !(selectedContextElement instanceof HTMLUListElement) || !(clearSelectionElement instanceof HTMLButtonElement)) throw new Error("Missing handoff controls");
const questionInput = /** @type {HTMLTextAreaElement} */ (questionInputElement);
const status = /** @type {HTMLElement} */ (statusElement);
const packetView = /** @type {HTMLElement} */ (packetElement);
const handoffPreview = initializeHandoffPreview(previewElement, packetView, status);
const submit = /** @type {HTMLButtonElement} */ (submitElement);
const selectedContext = /** @type {HTMLUListElement} */ (selectedContextElement);
const clearSelectionButton = /** @type {HTMLButtonElement} */ (clearSelectionElement);

document.addEventListener("selectionchange", () => {
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed || selection.rangeCount !== 1) {
    const focusedHandoffControl = document.activeElement === questionInput || document.activeElement === submit || document.activeElement === clearSelectionButton;
    const nextState = transitionSelection(selectionState, {kind: focusedHandoffControl ? "commit" : "collapse"});
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

function announceSelection() {
  selectedContext.replaceChildren();
  appendTextItems(selectedContext, selectionState.targets.map((target) => target.exactQuote));
  clearSelectionButton.disabled = selectionState.targets.length === 0;
  status.textContent = selectionState.targets.length === 0 ? "No source-bound text selected." : `${selectionState.targets.length} source-bound target(s) selected.`;
}

function resetPressedSelectionControls() {
  for (const control of content.querySelectorAll("[data-select-anchor]")) control.setAttribute("aria-pressed", "false");
}

function clearSelection() {
  selectionState = transitionSelection(selectionState, {kind: "clear"});
  resetPressedSelectionControls();
  const selection = window.getSelection();
  selection?.removeAllRanges();
  announceSelection();
}

function commitSelection() {
  const nextState = transitionSelection(selectionState, {kind: "commit"});
  if (nextState !== selectionState) {
    selectionState = nextState;
    announceSelection();
  }
}

for (const control of [questionInput, submit]) {
  control.addEventListener("pointerdown", commitSelection);
  control.addEventListener("focus", commitSelection);
}
clearSelectionButton.addEventListener("click", clearSelection);
submit.addEventListener("click", async () => {
  if (submit.disabled || handoffUnavailable()) return;
  const question = questionInput.value.trim();
  if (selectionState.targets.length === 0 || !question) {
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.textContent = "Select invariant text and enter a question.";
    return;
  }
  const submissionViewRequestId = activeRequestId;
  handoffPending = true;
  reconcileRequestControls();
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  status.textContent = "Creating handoff packet...";
  try {
    const response = await fetchWorkspaceResponse("/api/v1/handoff", {method: "POST", headers, body: JSON.stringify({annotations: selectionState.targets.map((target) => ({...target, question}))})});
    if (submissionViewRequestId !== activeRequestId) return;
    handoffPreview.show(response.text, response.value);
    status.textContent = "Handoff packet created.";
    setWorkspaceState("handoff-result");
  } catch (error) {
    const failure = workspaceFailure(error);
    applyFailureLock(failure);
    if (submissionViewRequestId !== activeRequestId) return;
    handoffPreview.clear();
    status.setAttribute("role", "alert");
    status.setAttribute("aria-live", "assertive");
    status.textContent = failure.lock ? failure.message : "The handoff packet could not be created.";
    setWorkspaceState("handoff-failed");
  } finally {
    handoffPending = false;
    reconcileRequestControls();
  }
});

decorateIcons(document);
const panels = initializePanels(commitSelection);
const navigation = initializeNavigation({
  post,
  nextRequestId,
  select(filters) { void (lookupView === "coverage" ? renderCoverage(0, filters) : renderSpecifications(0, filters)); panels.closeNavigation(); },
  fail: showFailure,
  locked: () => requestsLocked,
});
announceSelection();
void initializeWorkspace();
