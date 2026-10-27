import {expect} from "@playwright/test";
import {modes, openWorkspaceView, test} from "../harness/matrix-harness.mjs";
import {oracleControls} from "../harness/controls.mjs";
import {contentOracle} from "../harness/oracles.mjs";

// The oracle controls on the workspace Specifications tab, light, 1440.
const mode = modes.find((candidate) => candidate.id === "1440");
test.use({viewport: mode.viewport, deviceScaleFactor: mode.deviceScaleFactor});

const controls = oracleControls({
  open: (page, servers) => openWorkspaceView(page, servers, "workspace-specifications", "light", mode),
  container: "#workspace-content",
  // The workspace CSP admits only same-origin images, so a data: image is refused.
  blockedLoad: {source: "data:image/gif;base64,R0lGODlhAQABAAAAACw=", matches: (uri) => uri === "data"},
});
for (const [title, body] of controls) test(title, body);

test("lost graph content requires its narrow breakpoint and exact alternate record", async ({page, matrixServers}) => {
  const {records, expectedRecords} = await openWorkspaceView(page, matrixServers, "workspace-traceability", "light", mode);
  const graph = page.getByRole("region", {name: "Traceability graph viewport", includeHidden: true});
  await contentOracle(page, records, expectedRecords);
  const node = page.locator(".graph-node").first();
  for (const field of ["label", "identity"]) {
    const text = node.locator(`.graph-node-${field}`);
    await text.evaluate(element => {element.style.height = "1px"; element.style.overflow = "hidden"; element.style.flex = "none";});
    await contentOracle(page, records, expectedRecords);
    await text.evaluate(element => {for (const property of ["height", "overflow", "flex"]) element.style.removeProperty(property);});
    await contentOracle(page, records, expectedRecords);
  }
  const addUnrepresentedText = className => node.evaluate((element, className) => {
    const extra = document.createElement("span");
    extra.id = "graph-unrepresented-control";
    extra.className = className;
    extra.textContent = "Unrepresented graph text.";
    Object.assign(extra.style, {display: "block", flex: "none", height: "1px", lineHeight: "16px", overflow: "hidden"});
    element.append(extra);
  }, className);
  for (const className of ["", "graph-node-label", "graph-node-identity"]) {
    await addUnrepresentedText(className);
    await expect(contentOracle(page, records, expectedRecords)).rejects.toThrow(/content: record text is lost[\s\S]*Unrepresented graph text/);
    await page.locator("#graph-unrepresented-control").evaluate(element => element.remove());
    await contentOracle(page, records, expectedRecords);
  }
  await graph.evaluate(element => {element.style.display = "none";});
  await expect(contentOracle(page, records, expectedRecords)).rejects.toThrow("content: record text is lost");
  await graph.evaluate(element => {element.style.removeProperty("display");});
  await contentOracle(page, records, expectedRecords);
  await page.setViewportSize({width: 768, height: 900});
  await expect(page.locator("body")).toHaveAttribute("data-navigation-open", "false");
  await expect(page.locator("body")).toHaveAttribute("data-inspector-open", "false");
  await expect(graph).toBeHidden();
  await contentOracle(page, records, expectedRecords);
  const alternate = page.locator(".graph-records [data-graph-select]").first();
  for (const className of ["", "graph-node-label", "graph-node-identity"]) {
    await addUnrepresentedText(className);
    await expect(contentOracle(page, records, expectedRecords)).rejects.toThrow(/content: record text is lost[\s\S]*Unrepresented graph text/);
    await page.locator("#graph-unrepresented-control").evaluate(element => element.remove());
    await contentOracle(page, records, expectedRecords);
  }
  const original = await alternate.evaluate(element => ({id: element.dataset.graphSelect,
    label: element.querySelector(".graph-node-label").textContent, identity: element.querySelector(".graph-node-identity").textContent}));
  for (const field of ["node-id", "label", "identity", "label-whitespace"]) {
    await alternate.evaluate((element, field) => {
      if (field === "node-id") element.dataset.graphSelect = "missing:alternate";
      else element.querySelector(`.graph-node-${field === "label-whitespace" ? "label" : field}`).textContent += field === "label-whitespace" ? " " : " altered";
    }, field);
    await expect(contentOracle(page, records, expectedRecords)).rejects.toThrow("content: record text is lost");
    await alternate.evaluate((element, original) => {
      element.dataset.graphSelect = original.id;
      element.querySelector(".graph-node-label").textContent = original.label;
      element.querySelector(".graph-node-identity").textContent = original.identity;
    }, original);
    await contentOracle(page, records, expectedRecords);
  }
  await page.setViewportSize({width: 769, height: 900});
  await expect(graph).toBeVisible();
  await graph.evaluate(element => {element.style.display = "none";});
  await expect(contentOracle(page, records, expectedRecords)).rejects.toThrow("content: record text is lost");
  await graph.evaluate(element => {element.style.removeProperty("display");});
  await contentOracle(page, records, expectedRecords);
});
