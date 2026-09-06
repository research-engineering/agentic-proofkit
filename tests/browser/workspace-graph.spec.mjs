import {expect} from "@playwright/test";
import {capacityTest, test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";
import {analyzeAxe, assertAxeTestComplete, initializeAxe} from "./axe-harness.mjs";

async function openGraph(page, url) {
  await openWorkspace(page, url);
  const response = page.waitForResponse(response => response.url().endsWith("/api/v1/graph"));
  await page.getByRole("button", {name: "Traceability", exact: true}).click();
  const graph = (await (await response).json()).projection;
  await expect(page.locator("body")).toHaveAttribute("data-state", "graph");
  return graph;
}

async function identities(page, kind) {
  return page.getByRole("list", {name: `Admitted traceability ${kind}`}).locator(":scope > li").evaluateAll(items => items.map(item => item.dataset.identity));
}

test("graph filters retain evidence scope, directed neighborhood and a keyboard record equivalent", async ({baseURL, page}) => {
  await page.setViewportSize({width: 1920, height: 1080});
  await initializeAxe(page);
  const graph = await openGraph(page, baseURL);
  const requirementID = "requirement:REQ-CONSUMER-001";
  const button = page.locator(`.graph-records button[data-graph-select="${requirementID}"]`);
  await button.focus();
  await page.keyboard.press("Enter");
  await expect(button).toBeFocused();
  await page.getByRole("checkbox", {name: "Selected node and neighbors", exact: true}).check();
  const retained = new Set([requirementID]);
  for (const edge of graph.edges) {
    if (edge.fromNodeId === requirementID) retained.add(edge.toNodeId);
    if (edge.toNodeId === requirementID) retained.add(edge.fromNodeId);
  }
  expect(await identities(page, "nodes")).toEqual(graph.nodes.filter(node => retained.has(node.nodeId)).map(node => node.nodeId));
  expect(await identities(page, "edges")).toEqual(graph.edges.filter(edge => retained.has(edge.fromNodeId) && retained.has(edge.toNodeId)).map(edge => edge.edgeId));
  const specifications = page.getByRole("checkbox", {name: "Specifications", exact: true});
  await specifications.focus();
  await page.keyboard.press("Space");
  await expect(specifications).toBeFocused();
  await expect(page.getByRole("checkbox", {name: "Selected node and neighbors", exact: true})).not.toBeChecked();
  await expect(page.getByRole("checkbox", {name: "Selected node and neighbors", exact: true})).toBeDisabled();
  await expect(page.getByRole("region", {name: "Selected graph node"})).toHaveText("No node selected.");
  const visible = new Set(graph.nodes.filter(node => node.evidencePlane !== "specification_coverage").map(node => node.nodeId));
  expect(await identities(page, "edges")).toEqual(graph.edges.filter(edge => edge.evidencePlane !== "specification_coverage" && visible.has(edge.fromNodeId) && visible.has(edge.toNodeId)).map(edge => edge.edgeId));
  await expect(page.locator("[data-graph-counts]")).toContainText(`Available: ${graph.availableNodeCount} nodes, ${graph.availableEdgeCount} relations.`);
  for (const name of ["Proof declarations", "Code", "Native execution"]) await page.getByRole("checkbox", {name, exact: true}).uncheck();
  expect(await identities(page, "nodes")).toEqual([]);
  expect(await identities(page, "edges")).toEqual([]);
  await expect(page.locator("[data-graph-counts]")).toContainText("Visible in this returned page: 0 nodes, 0 relations.");
  expect((await analyzeAxe(page)).violations).toEqual([]);
  assertAxeTestComplete(page);
});

test("an outside-page parent follows its canonical offset without synthesizing a relation", async ({baseURL, page}) => {
  await page.setViewportSize({width: 1920, height: 1080});
  const requests = [];
  await page.route("**/api/v1/graph", async route => {
    const body = route.request().postDataJSON();
    requests.push(body);
    const query = requests.length === 1 ? {offset: 1, edgeOffset: 80000, maxRecords: 1, maxEdges: 1} : body.query;
    await route.fulfill({response: await route.fetch({postData: {...body, query}})});
  });
  const graph = await openGraph(page, baseURL);
  expect(graph.nodes.map(node => node.nodeId)).toEqual(["code:code.retry"]);
  expect(graph.edges).toEqual([]);
  await page.locator('.graph-records button[data-graph-select="code:code.retry"]').click();
  const parent = page.getByRole("button", {name: "parentNodeId: code:code.repository (outside page)", exact: true});
  await expect(parent).toBeVisible();
  expect(requests).toHaveLength(1);
  await parent.click();
  await expect(page.getByRole("region", {name: "Selected graph node"})).toContainText("code:code.repository");
  expect(requests).toHaveLength(2);
  expect(requests[1].query).toEqual({offset: 0, edgeOffset: 0, maxRecords: 64, maxEdges: 128});
  await expect(page.getByRole("heading", {name: "Traceability graph", exact: true})).toBeFocused();
});

test("included structural targets hidden by filters are revealed locally without a fetch", async ({baseURL, page}) => {
  await page.setViewportSize({width: 1920, height: 1080});
  let requests = 0;
  page.on("request", request => { if (request.url().endsWith("/api/v1/graph")) requests++; });
  const graph = await openGraph(page, baseURL);
  const execution = graph.nodes.find(node => node.evidencePlane === "native_execution_coverage");
  await page.locator(`.graph-records button[data-graph-select="${execution.nodeId}"]`).click();
  await page.getByRole("checkbox", {name: "Code", exact: true}).uncheck();
  const details = page.locator(".graph-inspector li details").first();
  await details.locator("summary").click();
  const link = details.getByRole("button", {name: "codeNodeId: code:code.retry (hidden by filters)", exact: true});
  await link.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("region", {name: "Selected graph node"})).toContainText("code:code.retry");
  await expect(page.getByRole("checkbox", {name: "Code", exact: true})).toBeChecked();
  await expect(page.locator('.graph-records button[data-graph-select="code:code.retry"]')).toBeFocused();
  expect(requests).toBe(1);
});

capacityTest("maximum admitted graph page remains bounded, inspectable and below the commit budget", async ({graphCapacityURL, page}, testInfo) => {
  await page.setViewportSize({width: 1920, height: 1080});
  const samples = [];
  await page.route("**/api/v1/graph", async route => {
    const body = route.request().postDataJSON();
    await route.fulfill({response: await route.fetch({postData: {...body, query: {offset: 130, edgeOffset: 64, maxRecords: 64, maxEdges: 128}}})});
  });
  const graph = await openGraph(page, graphCapacityURL);
  expect(graph.primaryNodeCount).toBe(64);
  expect(graph.boundaryNodeCount).toBe(128);
  expect(graph.nodes).toHaveLength(192);
  expect(graph.edges).toHaveLength(128);
  const buttons = page.locator(".graph-canvas > button");
  await expect(buttons).toHaveCount(192);
  expect(await identities(page, "nodes")).toEqual(graph.nodes.map(node => node.nodeId));
  expect(await identities(page, "edges")).toEqual(graph.edges.map(edge => edge.edgeId));
  const viewport = page.getByRole("region", {name: "Traceability graph viewport"});
  samples.push(Number(await viewport.getAttribute("data-commit-milliseconds")));
  for (const index of [0, 63, 128, 191]) {
    await page.locator(`.graph-records button[data-graph-select="${graph.nodes[index].nodeId}"]`).click();
    await expect(page.locator(".graph-inspector > dl dt")).toHaveText(Object.keys(graph.nodes[index]));
    samples.push(Number(await viewport.getAttribute("data-commit-milliseconds")));
  }
  expect(samples.every(value => Number.isFinite(value) && value > 0 && value <= 100)).toBe(true);
  await testInfo.attach("graph-page-commit-distribution.json", {body: JSON.stringify({nodes: 192, edges: 128, milliseconds: samples}), contentType: "application/json"});
});

capacityTest("Go-built unverified coordinates retain exact HTTP and DOM values or fail closed", async ({graphNumericURL, page}) => {
  await openWorkspace(page, graphNumericURL);
  const response = page.waitForResponse(response => response.url().endsWith("/api/v1/graph"));
  await page.getByRole("button", {name: "Traceability", exact: true}).click();
  const body = await (await response).text();
  const wire = JSON.parse(body, (key, value, context) => key === "byteStart" || key === "byteEnd" ? context.source : value);
  const range = wire.projection.nodes.find(node => node.nodeId === "code:code.retry");
  expect([range.byteStart, range.byteEnd]).toEqual(["9007199254740992", "9007199254740993"]);
  await page.locator('.graph-records button[data-graph-select="code:code.retry"]').click();
  const inspector = page.getByRole("region", {name: "Selected graph node"});
  await expect(inspector.locator('dt:has-text("byteStart") + dd')).toHaveText("9007199254740992");
  await expect(inspector.locator('dt:has-text("byteEnd") + dd')).toHaveText("9007199254740993");
  await expect(inspector.locator('dt:has-text("rangeVerification") + dd')).toHaveText("unverified");
  await expect(inspector.locator('dt:has-text("currentnessState") + dd')).toHaveText("unverified");

  await page.evaluate(() => Reflect.set(JSON, "rawJSON", undefined));
  await page.getByRole("button", {name: "Specifications", exact: true}).click();
  await expect(page.locator("body")).toHaveAttribute("data-state", "specifications");
  await page.getByRole("button", {name: "Traceability", exact: true}).click();
  await expect(page.getByText("The admitted workspace is unavailable.", {exact: true})).toBeVisible();
  await expect(page.locator(".graph-inspector")).toHaveCount(0);
});

test("native numeric observation preserves fractional tokens, strings and control values", async ({baseURL, page}) => {
  const body = '{"start":9007199254740992,"end":9007199254740993,"safe":9007199254740991,"zero":0,"string":"9007199254740993","nested":[1.0000000000000001,1e-400,-0,1e400,-9007199254740993,0.123456789012345678901],"unbranded":{"rawJSON":"17"}}';
  await page.route("**/numeric-observation-fixture", route => route.fulfill({status: 200, contentType: "application/json", body}));
  await openWorkspace(page, baseURL);
  const observed = await page.evaluate(async () => {
    const {fetchWorkspaceResponse} = await import("/assets/workspace-requests.js");
    const {workspaceScalarText} = await import("/assets/workspace-json.js");
    const {text, value} = await fetchWorkspaceResponse("/numeric-observation-fixture", {});
    return {
      text, serialized: JSON.stringify(value), start: workspaceScalarText(value.start), end: workspaceScalarText(value.end),
      safe: value.safe, zero: value.zero, stringType: typeof value.string, string: value.string,
      unbranded: workspaceScalarText(value.unbranded), frozen: Object.isFrozen(value.end),
    };
  });
  expect(observed).toEqual({
    text: body, serialized: body, start: "9007199254740992", end: "9007199254740993",
    safe: 9007199254740991, zero: 0, stringType: "string", string: "9007199254740993",
    unbranded: "[object Object]", frozen: true,
  });
});
