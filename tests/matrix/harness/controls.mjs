import {expect} from "@playwright/test";

import {
  axeOracle, axeRuleNodes, axeTargetSelector, computedContrast, contentOracle, controlContrastOracle, judgeSecurityEvents, keyboardOracle, reflowOracle,
} from "./oracles.mjs";

// Negative controls: each one breaks one oracle's premise in a real rendered
// view, or hands the oracle's judgement a reclassified real result, and
// requires the oracle to refuse it with its own message. They run in every
// engine on one view of each family.

// mark attaches a test-owned identity to a node the control injects.
const controlId = "proofkit-matrix-control";

// withIncompleteTargetSize adds an incomplete target-size result for a real
// node of the page to the real axe result.
function withIncompleteTargetSize(result) {
  const node = axeRuleNodes(result, "passes", "target-size")[0];
  if (node === undefined) throw new Error("the control view has no passing target-size node");
  return {...result, incomplete: [...result.incomplete, {id: "target-size", nodes: [node]}]};
}

// reclassifyAsIncomplete moves the color-contrast violation of the injected
// node into the incomplete results, as axe reports a node whose background
// it cannot determine, so the computed-contrast oracle must decide it.
function reclassifyAsIncomplete(result) {
  const selector = `#${controlId}`;
  const isControl = (node) => axeTargetSelector(node) === selector;
  const violations = axeRuleNodes(result, "violations", "color-contrast").filter(isControl);
  if (violations.length !== 1) throw new Error("the injected low-contrast text must be one color-contrast violation");
  return {
    ...result,
    violations: result.violations.map((entry) => entry.id === "color-contrast" ? {...entry, nodes: entry.nodes.filter((node) => !isControl(node))} : entry)
      .filter((entry) => entry.nodes.length > 0),
    incomplete: [...result.incomplete, {id: "color-contrast", nodes: violations}],
  };
}

// oracleControls returns each control's title and body; the spec file calls
// test() for each, so the report names the spec file as each test's file.
export function oracleControls({open, container, blockedLoad}) {
  const controls = [];
  const test = (title, body) => controls.push([title, body]);
  test("axe refuses an injected violation", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate((selector) => document.querySelector(selector).append(document.createElement("button")), container);
    await expect(axeOracle(page)).rejects.toThrow(/axe: axe reported violations[\s\S]*button-name/);
  });

  test("axe refuses a view in which target-size applies to no node", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate(() => {
      for (const element of document.querySelectorAll("a[href], button, input, select, textarea, summary, [tabindex]")) element.remove();
    });
    await expect(axeOracle(page)).rejects.toThrow("axe: target-size applies to no node");
  });

  test("axe refuses an incomplete target-size result", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await expect(axeOracle(page, withIncompleteTargetSize)).rejects.toThrow("axe: target-size has incomplete results");
  });

  test("axe refuses an incomplete color-contrast node that fails the computed-contrast oracle", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate(({selector, id}) => {
      const text = document.createElement("p");
      text.id = id;
      text.textContent = "Low-contrast control text";
      text.style.color = "rgb(200, 200, 200)";
      document.querySelector(selector).prepend(text);
    }, {selector: container, id: controlId});
    await expect(axeOracle(page, reclassifyAsIncomplete)).rejects.toThrow("axe: an incomplete color-contrast node fails the computed-contrast oracle");
  });

  test("contrast refuses a placeholder below 4.5:1", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate(({selector, id}) => {
      const field = document.createElement("input");
      field.id = id;
      field.type = "search";
      field.placeholder = "Low-contrast control placeholder";
      field.setAttribute("aria-label", "Control field");
      document.querySelector(selector).prepend(field);
      // A rule of the page's own last stylesheet paints the placeholder; the
      // CSSOM is not subject to the page's CSP.
      const sheet = [...document.styleSheets].at(-1);
      sheet.insertRule(`#${id}::placeholder{color:rgb(200, 200, 200);opacity:1}`, sheet.cssRules.length);
    }, {selector: container, id: controlId});
    await expect(controlContrastOracle(page)).rejects.toThrow("contrast: a placeholder has less than 4.5:1 contrast with its field");
  });

  test("contrast refuses a checkbox without a 3:1 boundary", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate(({selector, id}) => {
      const checkbox = document.createElement("input");
      checkbox.id = id;
      checkbox.type = "checkbox";
      checkbox.setAttribute("aria-label", "Control checkbox");
      checkbox.style.setProperty("outline", "none", "important");
      document.querySelector(selector).prepend(checkbox);
    }, {selector: container, id: controlId});
    await expect(controlContrastOracle(page)).rejects.toThrow("contrast: a checkbox has no boundary of the border width with 3:1 contrast");
  });

  test("reflow refuses a horizontally scrolling document", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate(() => {
      const wide = document.createElement("div");
      wide.style.width = "4000px";
      wide.style.height = "1px";
      document.body.append(wide);
    });
    await expect(reflowOracle(page)).rejects.toThrow("reflow: the document scrolls horizontally");
  });

  test("reflow refuses an unlabelled scrolling region", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate((selector) => {
      const region = document.createElement("div");
      region.style.overflowX = "auto";
      region.style.width = "100px";
      const table = document.createElement("table");
      const cell = table.insertRow().insertCell();
      cell.textContent = "wide";
      cell.style.minWidth = "400px";
      region.append(table);
      document.querySelector(selector).prepend(region);
    }, container);
    await expect(reflowOracle(page)).rejects.toThrow("reflow: content overflows an element that is not a labelled focusable graph or table region");
  });

  test("lost content refuses clipped record text", async ({page, matrixServers}) => {
    const {records, expectedRecords} = await open(page, matrixServers);
    await page.evaluate((selector) => {
      const record = document.querySelector(selector);
      record.style.overflow = "hidden";
      record.style.maxHeight = "1rem";
    }, records);
    await expect(contentOracle(page, records, expectedRecords)).rejects.toThrow("content: record text is lost");
  });

  test("lost content refuses hidden record text", async ({page, matrixServers}) => {
    const {records, expectedRecords} = await open(page, matrixServers);
    await contentOracle(page, records, expectedRecords);
    for (const mode of ["display", "hidden", "visibility", "opacity", "transparent"]) {
      await page.evaluate(({selector, mode, id}) => {
        const text = document.createElement("p");
        text.id = id;
        text.textContent = "Required record control text";
        if (mode === "display") text.style.display = "none";
        if (mode === "hidden") text.hidden = true;
        if (mode === "visibility") text.style.visibility = "hidden";
        if (mode === "opacity") text.style.opacity = "0";
        if (mode === "transparent") text.style.color = "transparent";
        document.querySelector(selector).append(text);
      }, {selector: records, mode, id: controlId});
      await expect(contentOracle(page, records, expectedRecords), mode).rejects.toThrow("content: record text is lost");
      await page.locator(`#${controlId}`).evaluate((element) => element.remove());
      await contentOracle(page, records, expectedRecords);
    }
  });

  test("contrast refuses undecidable group opacity", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate(({selector, id}) => {
      const group = document.createElement("div");
      group.id = id;
      group.style.opacity = "0.5";
      group.style.backgroundColor = "black";
      const text = document.createElement("p");
      text.textContent = "White text in a translucent black group";
      text.style.color = "white";
      group.append(text);
      document.querySelector(selector).prepend(group);
    }, {selector: container, id: controlId});
    const observation = await computedContrast(page, [`#${controlId} p`]);
    expect(observation).toHaveLength(1);
    expect(observation[0]).toMatchObject({decided: false, reason: "group opacity on DIV"});
    await page.locator(`#${controlId}`).evaluate((element) => { element.style.opacity = "1"; });
    const restored = await computedContrast(page, [`#${controlId} p`]);
    expect(restored[0]).toMatchObject({decided: true, required: 4.5});
    expect(restored[0].ratio).toBeGreaterThanOrEqual(4.5);
  });

  test("keyboard refuses an interactive element that Tab cannot reach", async ({page, matrixServers}, testInfo) => {
    await open(page, matrixServers);
    await page.evaluate(() => {
      const control = globalThis.proofkitMatrix.tabStops().find((element) => element.matches("button, select, input"));
      control.tabIndex = -1;
    });
    await expect(keyboardOracle(page, testInfo.project.name)).rejects.toThrow("keyboard: Tab does not reach every enabled interactive element in DOM order");
  });

  test("keyboard refuses an invisible focus indicator", async ({page, matrixServers}, testInfo) => {
    await open(page, matrixServers);
    await page.evaluate(() => {
      for (const element of globalThis.proofkitMatrix.tabStops()) element.style.setProperty("outline", "none", "important");
    });
    await expect(keyboardOracle(page, testInfo.project.name)).rejects.toThrow("keyboard: a focused element has no visible focus indicator");
  });

  test("keyboard refuses a clipped focus indicator", async ({page, matrixServers}, testInfo) => {
    await open(page, matrixServers);
    await keyboardOracle(page, testInfo.project.name);
    await page.evaluate((selector) => {
      const clip = document.createElement("div");
      clip.style.width = "100px";
      clip.style.height = "40px";
      clip.style.overflow = "hidden";
      const button = document.createElement("button");
      button.textContent = "Clipped ring";
      button.style.width = "100px";
      button.style.height = "40px";
      clip.append(button);
      document.querySelector(selector).prepend(clip);
    }, container);
    await expect(keyboardOracle(page, testInfo.project.name)).rejects.toThrow("keyboard: a focused element has no visible focus indicator");
    await page.locator("button", {hasText: "Clipped ring"}).evaluate((button) => button.parentElement.remove());
    await keyboardOracle(page, testInfo.project.name);
  });

  test("security refuses a page-initiated load that the CSP blocks", async ({page, matrixServers, security}) => {
    await open(page, matrixServers);
    await page.evaluate(({selector, source}) => {
      const image = document.createElement("img");
      image.alt = "";
      image.src = source;
      document.querySelector(selector).append(image);
    }, {selector: container, source: blockedLoad.source});
    await expect.poll(() => security.observation().violations.length, {message: "the blocked load must raise a securitypolicyviolation event"}).toBeGreaterThan(0);
    expect(security.observation().violations.map((violation) => violation.effectiveDirective)).toContain("img-src");
    expect(security.observation().violations.some((violation) => blockedLoad.matches(violation.blockedURI)), JSON.stringify(security.observation().violations)).toBe(true);
    expect(() => judgeSecurityEvents(security.observation())).toThrow("security: the page raised a console error, a page error or a securitypolicyviolation event");
  });

  test("security refuses a console error", async ({page, matrixServers, security}) => {
    await open(page, matrixServers);
    await page.evaluate(() => console.error("matrix control console error"));
    await expect.poll(() => security.observation().consoleErrors.length).toBeGreaterThan(0);
    expect(() => judgeSecurityEvents(security.observation())).toThrow("security: the page raised a console error, a page error or a securitypolicyviolation event");
  });

  test("security refuses a document whose CSP differs from the exact policy", async ({page, matrixServers}) => {
    await page.route("**/*", async (route) => {
      if (!route.request().isNavigationRequest()) return route.continue();
      const response = await route.fetch();
      const headers = {...response.headers(), "content-security-policy": `${response.headers()["content-security-policy"]}; img-src *`};
      await route.fulfill({response, headers});
    });
    await expect(open(page, matrixServers)).rejects.toThrow("security: the document security headers differ from the exact expected headers");
  });
  return controls;
}
