import {expect} from "@playwright/test";

import {
  axeOracle, axeRuleNodes, axeTargetSelector, computedContrast, contentOracle, controlContrastOracle, judgeSecurityEvents, keyboardOracle, reflowOracle, settleSecurityEvents,
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

  test("contrast refuses opaque child paint and preserves transparent text wrappers", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    await page.evaluate(({selector, id}) => {
      const text = document.createElement("p");
      text.id = id;
      text.textContent = "First line contrast\nSecond line contrast";
      Object.assign(text.style, {position: "relative", whiteSpace: "pre-line"});
      document.querySelector(selector).prepend(text);
    }, {selector: container, id: controlId});
    const selector = `#${controlId}`;
    await axeOracle(page);
    await expect(computedContrast(page, [selector])).resolves.toMatchObject([{decided: true}]);
    for (const pointerEvents of ["auto", "none"]) {
      for (const extent of ["full", "partial", "later-line"]) {
        await page.locator(selector).evaluate((element, {pointerEvents, extent}) => {
          const range = document.createRange();
          range.selectNodeContents(element);
          const lines = [...range.getClientRects()].filter(rect => rect.width > 0 && rect.height > 0);
          if (lines.length !== 2) throw new Error("the contrast control must have two actual text lines");
          const line = lines[extent === "later-line" ? 1 : 0];
          const box = element.getBoundingClientRect();
          const offset = extent === "partial" ? line.width / 2 : 0;
          const cover = document.createElement("span");
          Object.assign(cover.style, {position: "absolute", left: `${line.left - box.left + offset}px`, top: `${line.top - box.top}px`,
            width: `${line.width - offset}px`, height: `${line.height}px`, zIndex: "1", background: "rgb(255, 255, 255)", pointerEvents});
          element.append(cover);
        }, {pointerEvents, extent});
        const context = `${extent}, pointer-events:${pointerEvents}`;
        await expect(computedContrast(page, [selector]), context).resolves.toMatchObject([{decided: false}]);
        await expect(axeOracle(page), context).rejects.toThrow("axe: the computed-contrast oracle cannot decide an incomplete color-contrast node");
        if (extent === "full" && pointerEvents === "none") {
          await page.locator(`${selector} span`).evaluate(element => {
            const box = element.getBoundingClientRect();
            Object.assign(element.style, {position: "fixed", left: `${box.left}px`, top: `${box.top}px`});
            element.parentElement.after(element);
          });
          await expect(computedContrast(page, [selector])).resolves.toMatchObject([{decided: false}]);
          await page.locator(`${selector} + span`).evaluate(element => element.remove());
        } else {
          await page.locator(`${selector} span`).evaluate(element => element.remove());
        }
        await expect(computedContrast(page, [selector]), context).resolves.toMatchObject([{decided: true}]);
        await axeOracle(page);
      }
    }
    await page.locator(selector).evaluate(element => {
      const wrapper = document.createElement("span");
      wrapper.textContent = element.textContent;
      element.replaceChildren(wrapper);
    });
    await expect(computedContrast(page, [selector])).resolves.toMatchObject([{decided: true}]);
    await axeOracle(page);
    await page.locator(selector).evaluate(element => element.remove());
    await axeOracle(page);
  });

  test("contrast checks every text owner's threshold in either DOM order", async ({page, matrixServers}) => {
    await open(page, matrixServers);
    const selector = `#${controlId}`;
    for (const reverse of [false, true]) {
      await page.evaluate(({container, id, reverse}) => {
        const text = document.createElement("p");
        text.id = id;
        text.style.backgroundColor = "rgb(255, 255, 255)";
        const large = document.createElement("span");
        large.textContent = "Passing large text. ";
        Object.assign(large.style, {fontSize: "24px", fontWeight: "400", color: "rgb(140, 140, 140)"});
        const normal = document.createElement("span");
        normal.textContent = "Failing normal text.";
        Object.assign(normal.style, {fontSize: "16px", fontWeight: "400", color: "rgb(120, 120, 120)"});
        text.append(...(reverse ? [normal, large] : [large, normal]));
        document.querySelector(container).prepend(text);
      }, {container, id: controlId, reverse});
      const [failed] = await computedContrast(page, [selector]);
      expect(failed).toMatchObject({decided: true, fontSize: 16, large: false, required: 4.5});
      expect(failed.ratio).toBeLessThan(4.5);
      await page.locator(selector).evaluate(element => {
        const normal = [...element.children].find(child => child.textContent === "Failing normal text.");
        normal.style.color = "rgb(100, 100, 100)";
      });
      const [restored] = await computedContrast(page, [selector]);
      expect(restored).toMatchObject({decided: true, fontSize: 24, large: true, required: 3});
      expect(restored.ratio).toBeGreaterThanOrEqual(3);
      expect(restored.ratio).toBeLessThan(4.5);
      await page.locator(selector).evaluate(element => element.remove());
    }
    await axeOracle(page);
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
    await page.evaluate(({selector, id}) => {
      const region = document.createElement("div");
      region.id = id;
      region.style.overflowX = "auto";
      region.style.width = "100px";
      const table = document.createElement("table");
      const cell = table.insertRow().insertCell();
      cell.textContent = "wide";
      cell.style.minWidth = "400px";
      region.append(table);
      document.querySelector(selector).prepend(region);
    }, {selector: container, id: controlId});
    await expect(reflowOracle(page)).rejects.toThrow("reflow: content overflows an element that is not a labelled focusable graph or table region");
    const region = page.locator(`#${controlId}`);
    const restore = () => region.evaluate(element => {
      element.setAttribute("role", "region");
      element.setAttribute("aria-label", "Scrollable data");
      element.removeAttribute("aria-labelledby");
      element.tabIndex = 0;
      element.style.overflowX = "auto";
      const table = document.createElement("table");
      const cell = table.insertRow().insertCell();
      cell.textContent = "wide";
      cell.style.minWidth = "400px";
      element.replaceChildren(table);
    });
    await restore();
    await reflowOracle(page);
    for (const field of ["role", "name", "tabIndex", "overflowX", "content"]) {
      await region.evaluate((element, field) => {
        if (field === "role") element.removeAttribute("role");
        if (field === "name") element.removeAttribute("aria-label");
        if (field === "tabIndex") element.tabIndex = -1;
        if (field === "overflowX") element.style.overflowX = "hidden";
        if (field === "content") {
          const content = document.createElement("div");
          content.style.width = "400px";
          content.textContent = "wide";
          element.replaceChildren(content);
        }
      }, field);
      await expect(reflowOracle(page)).rejects.toThrow("reflow: content overflows an element that is not a labelled focusable graph or table region");
      await restore();
      await reflowOracle(page);
    }
    await region.evaluate(element => {
      const label = document.createElement("span");
      label.id = "proofkit-scroll-label";
      label.textContent = "Scrollable data";
      element.before(label);
      element.removeAttribute("aria-label");
      element.setAttribute("aria-labelledby", label.id);
    });
    await reflowOracle(page);
    await page.locator("#proofkit-scroll-label").evaluate(element => element.textContent = " ");
    await expect(reflowOracle(page)).rejects.toThrow("reflow: content overflows an element that is not a labelled focusable graph or table region");
    await page.locator("#proofkit-scroll-label").evaluate(element => element.textContent = "Scrollable data");
    await reflowOracle(page);
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

  test("lost content follows native disclosure state", async ({page, matrixServers}) => {
    const {records, expectedRecords} = await open(page, matrixServers);
    await page.evaluate(({selector, id}) => {
      const details = document.createElement("details");
      details.id = id;
      const summary = document.createElement("summary");
      summary.textContent = "Disclosure control";
      const text = document.createElement("p");
      text.textContent = "Required expanded disclosure text";
      text.hidden = true;
      details.append(summary, text);
      document.querySelector(selector).append(details);
    }, {selector: records, id: controlId});
    await contentOracle(page, records, expectedRecords);
    await page.locator(`#${controlId}`).evaluate(element => {element.open = true;});
    await expect(contentOracle(page, records, expectedRecords)).rejects.toThrow("content: record text is lost");
    await page.locator(`#${controlId} p`).evaluate(element => {element.hidden = false;});
    await contentOracle(page, records, expectedRecords);
    await page.locator(`#${controlId}`).evaluate(element => element.remove());
    await contentOracle(page, records, expectedRecords);
  });

  test("lost content refuses full and partial painted overlays", async ({page, matrixServers}) => {
    const {records, expectedRecords} = await open(page, matrixServers);
    await contentOracle(page, records, expectedRecords);
    for (const mode of ["full-noninteractive", "partial", "partial-noninteractive"]) {
      await page.evaluate(({selector, mode, id}) => {
        const walker = document.createTreeWalker(document.querySelector(selector), NodeFilter.SHOW_TEXT);
        let line = null;
        while (walker.nextNode()) {
          if (walker.currentNode.textContent.trim() === "") continue;
          const range = document.createRange();
          range.selectNodeContents(walker.currentNode);
          line = [...range.getClientRects()].find(rect => rect.width > 20 && rect.height > 0);
          if (line) break;
        }
        if (line === null) throw new Error("the control requires a rendered record line");
        const overlay = document.createElement("div");
        overlay.id = id;
        overlay.style.position = "fixed";
        overlay.style.top = "0";
        overlay.style.bottom = "0";
        overlay.style.left = mode === "full-noninteractive" ? "0" : `${line.left + line.width / 2}px`;
        overlay.style.width = mode === "full-noninteractive" ? "100%" : `${line.width / 2}px`;
        overlay.style.backgroundColor = "black";
        overlay.style.zIndex = "999999";
        overlay.style.pointerEvents = mode.endsWith("noninteractive") ? "none" : "auto";
        document.body.append(overlay);
      }, {selector: records, mode, id: controlId});
      await expect(contentOracle(page, records, expectedRecords), mode).rejects.toThrow("content: record text is lost");
      await page.locator(`#${controlId}`).evaluate(element => element.remove());
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

  for (const [title, pointerEvents] of [["keyboard refuses an occluded focus indicator", "auto"], ["keyboard refuses potential non-hit-tested focus occlusion", "none"]]) {
    test(title, async ({page, matrixServers, security}, testInfo) => {
      await open(page, matrixServers);
      await keyboardOracle(page, testInfo.project.name);
      await page.evaluate(({id, pointerEvents}) => {
        const overlay = document.createElement("div");
        overlay.id = id;
        Object.assign(overlay.style, {position: "fixed", inset: "0", backgroundColor: "black", zIndex: "999999", pointerEvents});
        document.body.append(overlay);
      }, {id: controlId, pointerEvents});
      await expect(keyboardOracle(page, testInfo.project.name)).rejects.toThrow("keyboard: a focused element has no visible focus indicator");
      await page.locator(`#${controlId}`).evaluate(element => element.remove());
      await keyboardOracle(page, testInfo.project.name);
      await settleSecurityEvents(page);
      judgeSecurityEvents(security.observation());
    });
  }

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

  test("security refuses an uncaught page error", async ({page, matrixServers, security}) => {
    await open(page, matrixServers);
    await settleSecurityEvents(page);
    expect(security.observation()).toEqual({consoleErrors: [], pageErrors: [], violations: []});
    const [uncaught] = await Promise.all([
      page.waitForEvent("pageerror"),
      page.evaluate(() => { setTimeout(() => { throw new Error("matrix control uncaught error"); }, 0); }),
    ]);
    expect(uncaught.message).toContain("matrix control uncaught error");
    await settleSecurityEvents(page);
    const observation = security.observation();
    expect(observation.consoleErrors).toEqual([]);
    expect(observation.violations).toEqual([]);
    expect(observation.pageErrors).toEqual(["matrix control uncaught error"]);
    expect(() => judgeSecurityEvents(observation)).toThrow("security: the page raised a console error, a page error or a securitypolicyviolation event");
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
