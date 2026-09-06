// @ts-check

import {icon} from "./workspace-icons.js";

/** @typedef {{nodeId: string, label: string, nodeKind: string, childCount: number}} NavigationNode */
/** @typedef {{parentNodeId?: string, offset: number, maxRecords: number}} NavigationQuery */
/** @typedef {{query: NavigationQuery, history: number[], rows: NavigationNode[], available: number, reduced: boolean, ready: boolean, controller: AbortController, requestId: string, error?: unknown}} Branch */
/** @typedef {{searchText?: string, nodeId?: string, ownerId?: string, lifecycleState?: string}} LookupFilters */

/**
 * @param {{post: (path: string, body: any, signal?: AbortSignal) => Promise<any>, nextRequestId: (prefix: string) => string, select: (filters: LookupFilters) => void, fail: (error: unknown, container: HTMLElement, retry: () => void) => void, locked: () => boolean}} actions
 */
export function initializeNavigation(actions) {
  const form = document.querySelector("#workspace-search");
  const search = document.querySelector("#requirement-search");
  const owner = document.querySelector("#requirement-owner");
  const lifecycle = document.querySelector("#requirement-lifecycle");
  const tree = document.querySelector("#spec-navigation");
  const scope = document.querySelector("#selected-scope");
  if (!(form instanceof HTMLFormElement) || !(search instanceof HTMLInputElement) || !(owner instanceof HTMLSelectElement) || !(lifecycle instanceof HTMLSelectElement) || !(tree instanceof HTMLElement) || !(scope instanceof HTMLElement)) throw new Error("Missing navigation controls");
  const controls = {form, search, owner, lifecycle, tree, scope};
  /** @type {Branch[]} */
  let branches = [];
  /** @type {NavigationNode[]} */
  let selectedPath = [];
  let snapshotId = "";
  const maxVisibleRows = 256;

  function submit() {
    if (actions.locked() || !snapshotId) return;
    /** @type {LookupFilters} */
    const filters = {};
    if (controls.search.value) filters.searchText = controls.search.value;
    if (controls.owner.value) filters.ownerId = controls.owner.value;
    if (controls.lifecycle.value) filters.lifecycleState = controls.lifecycle.value;
    const selected = selectedPath.at(-1);
    if (selected) filters.nodeId = selected.nodeId;
    actions.select(Object.freeze(filters));
  }

  controls.form.addEventListener("submit", event => { event.preventDefault(); submit(); });
  controls.owner.addEventListener("change", submit);
  controls.lifecycle.addEventListener("change", submit);
  document.querySelector("#reset-filters")?.addEventListener("click", () => {
    controls.form.reset();
    selectedPath = [];
    render();
    submit();
  });
  document.querySelector("#all-requirements")?.addEventListener("click", () => {
    selectedPath = [];
    render();
    submit();
  });

  /** @param {number} depth */
  function discardFrom(depth) {
    for (const branch of branches.slice(depth)) branch.controller.abort();
    branches = branches.slice(0, depth);
  }

  /** @param {number} depth @param {NavigationNode} node */
  function pathTo(depth, node) {
    const path = branches.slice(0, depth).map((branch, index) => branch.rows.find(row => row.nodeId === branches[index + 1]?.query.parentNodeId));
    if (path.some(row => !row)) throw new Error("Navigation path is incomplete");
    return [.../** @type {NavigationNode[]} */ (path), node];
  }

  function capacity() {
    if (controls.tree.querySelector("[data-navigation-capacity]")) return;
    const status = document.createElement("p");
    status.dataset.navigationCapacity = "";
    status.setAttribute("role", "status");
    status.textContent = "The navigation path reached its display limit. Collapse a branch to continue.";
    controls.tree.append(status);
  }

  /** @param {number} depth @param {string | undefined} parentNodeId @param {number} offset @param {number[]} history @param {NavigationQuery} [retryQuery] */
  async function load(depth, parentNodeId, offset, history, retryQuery) {
    if (actions.locked()) return;
    if (depth >= maxVisibleRows) { capacity(); return; }
    const focusInTree = controls.tree.contains(document.activeElement);
    discardFrom(depth);
    // Old sibling pages can be recovered explicitly; keep the expanded path.
    for (let index = 0; index < branches.length; index += 1) {
      if (branches.reduce((count, branch) => count + branch.rows.length, 0) + 64 <= maxVisibleRows) break;
      const branch = branches[index];
      const expandedId = branches[index + 1]?.query.parentNodeId ?? parentNodeId;
      const expanded = branch.rows.find(row => row.nodeId === expandedId);
      if (expanded && branch.rows.length > 1) { branch.rows = [expanded]; branch.reduced = true; }
    }
    const remaining = maxVisibleRows - branches.reduce((count, branch) => count + branch.rows.length, 0);
    if (remaining < 1) { render(); capacity(); return; }
    const query = retryQuery ?? Object.freeze({...parentNodeId ? {parentNodeId} : {}, offset, maxRecords: Math.min(64, remaining)});
    const branch = {query, history, rows: /** @type {NavigationNode[]} */ ([]), available: 0, reduced: false, ready: false, controller: new AbortController(), requestId: actions.nextRequestId("browser.navigation")};
    branches.push(branch);
    render();
    if (focusInTree && parentNodeId) restoreNodeFocus(parentNodeId, "disclosure");
    try {
      const response = await actions.post("/api/v1/navigation", {requestId: branch.requestId, snapshotId, query}, branch.controller.signal);
      if (branch.controller.signal.aborted || branches[depth] !== branch) return;
      if (response?.requestId !== branch.requestId || response?.snapshotId !== snapshotId) throw new Error("Navigation response identity mismatch");
      if ((response.projection.parent?.nodeId ?? undefined) !== query.parentNodeId) throw new Error("Navigation parent identity mismatch");
      branch.rows = response.projection.nodes;
      branch.available = response.projection.availableNodeCount;
      branch.ready = true;
      render();
    } catch (error) {
      if (branch.controller.signal.aborted || branches[depth] !== branch) return;
      /** @type {Branch} */ (branch).error = error;
      render();
    }
  }

  /** @param {string} label @param {string} symbol @param {() => void} action */
  function button(label, symbol, action) {
    const control = document.createElement("button");
    control.type = "button";
    control.dataset.protectedRequest = "";
    control.disabled = actions.locked();
    control.title = label;
    control.setAttribute("aria-label", label);
    control.append(icon(symbol));
    control.addEventListener("click", action);
    return control;
  }

  /** @param {number} depth @returns {HTMLElement} */
  function branchView(depth) {
    const branch = branches[depth];
    const section = document.createElement("div");
    section.id = `navigation-branch-${depth}`;
    section.dataset.navigationBranch = String(depth);
    if (Object.hasOwn(branch, "error")) {
      actions.fail(branch.error, section, () => {
        if (branches[depth] === branch && !branch.controller.signal.aborted) void load(depth, branch.query.parentNodeId, branch.query.offset, branch.history, branch.query);
      });
      return section;
    }
    const list = document.createElement("ul");
    list.className = "navigation-nodes";
    section.append(list);
    for (const node of branch.rows) {
      const item = document.createElement("li");
      item.dataset.navigationNode = node.nodeId;
      const row = document.createElement("div");
      row.className = "navigation-row";
      const expanded = branches[depth + 1]?.query.parentNodeId === node.nodeId;
      if (node.childCount > 0) {
        const disclosure = button(`${expanded ? "Collapse" : "Expand"} ${node.label}`, expanded ? "chevron-down" : "chevron-right", () => {
          if (expanded) { discardFrom(depth + 1); render(); }
          else void load(depth + 1, node.nodeId, 0, []);
        });
        disclosure.className = "icon-button";
        disclosure.dataset.navigationAction = "disclosure";
        disclosure.setAttribute("aria-expanded", String(expanded));
        if (expanded) disclosure.setAttribute("aria-controls", `navigation-branch-${depth + 1}`);
        row.append(disclosure);
      }
      const choose = button(node.label, "file-text", () => { selectedPath = pathTo(depth, node); render(); submit(); });
      choose.className = "navigation-label";
      choose.dataset.navigationAction = "select";
      choose.append(document.createTextNode(node.label));
      if (selectedPath.at(-1)?.nodeId === node.nodeId) choose.setAttribute("aria-current", "true");
      row.append(choose);
      item.append(row);
      if (expanded) item.append(branchView(depth + 1));
      list.append(item);
    }
    if (branch.rows.length === 0 && branch.available === 0) {
      const status = document.createElement("p");
      status.setAttribute("role", "status");
      status.textContent = branch.ready ? "No child specifications." : "Loading navigation...";
      section.append(status);
    }
    const paging = document.createElement("div");
    paging.className = "navigation-paging";
    if (branch.reduced) {
      const siblings = button("Show sibling page", "arrow-left", () => void load(depth, branch.query.parentNodeId, branch.query.offset, branch.history));
      siblings.append(document.createTextNode("Show siblings"));
      paging.append(siblings);
    } else {
      if (branch.history.length > 0) paging.append(button("Previous navigation page", "arrow-left", () => void load(depth, branch.query.parentNodeId, branch.history.at(-1) ?? 0, branch.history.slice(0, -1))));
      if (branch.query.offset + branch.rows.length < branch.available) paging.append(button("Next navigation page", "arrow-right", () => void load(depth, branch.query.parentNodeId, branch.query.offset + branch.rows.length, [...branch.history, branch.query.offset])));
    }
    section.append(paging);
    return section;
  }

  /** @param {string} nodeId @param {string} action */
  function restoreNodeFocus(nodeId, action) {
    if (action !== "disclosure" && action !== "select") return;
    const control = controls.tree.querySelector(`[data-navigation-node="${CSS.escape(nodeId)}"] > .navigation-row > [data-navigation-action="${action}"]`);
    if (control instanceof HTMLButtonElement && !control.disabled) control.focus({preventScroll: true});
  }

  function render() {
    const active = document.activeElement;
    const focusedNode = active instanceof HTMLElement && controls.tree.contains(active) ? active.closest("[data-navigation-node]") : null;
    const nodeId = focusedNode instanceof HTMLElement ? focusedNode.dataset.navigationNode : undefined;
    const action = active instanceof HTMLElement ? active.dataset.navigationAction : undefined;
    controls.scope.replaceChildren();
    if (selectedPath.length > 0) {
      const label = document.createElement("p");
      label.textContent = selectedPath.map(node => node.label).join(" / ");
      controls.scope.append(label);
    }
    controls.tree.replaceChildren();
    if (branches.length > 0) {
      const view = branchView(0);
      for (const control of view.querySelectorAll("[data-protected-request]")) {
        if (control instanceof HTMLButtonElement) control.disabled = actions.locked();
      }
      controls.tree.append(view);
    }
    if (nodeId && action) restoreNodeFocus(nodeId, action);
  }

  return {
    /** @param {any} manifest */
    start(manifest) {
      snapshotId = manifest.snapshotId;
      for (const [select, values] of [[controls.owner, manifest.lookupFacets.ownerIds], [controls.lifecycle, manifest.lookupFacets.lifecycleStates]]) {
        for (const value of values) {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = value;
          select.append(option);
        }
      }
      void load(0, undefined, 0, []);
    },
    cancel() { for (const branch of branches) branch.controller.abort(); },
  };
}
