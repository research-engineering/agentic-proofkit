import {readFile} from "node:fs/promises";
import {expect} from "@playwright/test";
import {staticViewTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

const heading = "Requirement Source View: browser.fixture.requirements";
const treeHeading = "Requirement Spec Tree View: browser.fixture.tree";

test("static exact Unicode and ASCII search preserves cards/table parity without normalization", async ({staticViewURL, page}) => {
  await openWorkspace(page, staticViewURL, heading, "static-view");
  const cases = [
    ["\u039f\u0394\u039f\u03a3", ["REQ-CONSUMER-001"]],
    ["\u03bf\u03b4\u03bf\u03c2", ["REQ-CONSUMER-001"]],
    ["\u0130stanbul", ["REQ-STATIC-1"]],
    ["i\u0307stanbul", ["REQ-STATIC-1"]],
    ["istanbul", []],
    ["  aScIi nEeDlE  ", ["REQ-STATIC-2"]],
    ["needle", ["REQ-STATIC-2"]],
    ["Caf\u00e9", ["REQ-STATIC-3"]],
    ["Cafe\u0301", ["REQ-STATIC-4"]],
    ["no-such-record", []],
    ["", ["REQ-CONSUMER-001", "REQ-STATIC-1", "REQ-STATIC-2", "REQ-STATIC-3", "REQ-STATIC-4"]],
  ];
  for (const [query, ids] of cases) {
    await page.getByRole("searchbox").fill(query);
    for (const mode of ["cards", "table"]) {
      await page.getByLabel("View", {exact: true}).selectOption(mode);
      await expect(page.locator(mode === "cards" ? "[data-proofkit-card]:visible .proofkit-id" : "[data-proofkit-table-row]:visible td:first-child")).toHaveText(ids);
      await expect(page.locator("#proofkit-visible-count")).toHaveText(String(ids.length));
    }
  }
  await page.getByRole("searchbox").fill("\u0130stanbul");
  await page.getByLabel("Owner", {exact: true}).selectOption("browser.fixture.owner");
  await expect(page.locator("#proofkit-visible-count")).toHaveText("0");
  await page.getByLabel("Owner", {exact: true}).selectOption("browser.fixture.other");
  await expect(page.locator("#proofkit-visible-count")).toHaveText("1");
});

test("static filtering preserves manual disclosures and explicit bulk control still works", async ({staticViewURL, page}) => {
  await openWorkspace(page, staticViewURL, heading, "static-view");
  const details = page.locator("details");
  const first = details.first();
  const second = details.nth(1);
  expect(await details.count()).toBeGreaterThan(1);
  await first.locator("summary").first().click();
  await expect(first).toHaveJSProperty("open", true);
  await expect(second).toHaveJSProperty("open", false);
  for (const query of ["\u039f\u0394\u039f\u03a3", "no-such-record", ""]) {
    await page.getByRole("searchbox").fill(query);
    await expect(first).toHaveJSProperty("open", true);
    await expect(second).toHaveJSProperty("open", false);
  }
  for (const mode of ["table", "cards"]) {
    await page.getByLabel("View", {exact: true}).selectOption(mode);
    await page.getByLabel("Show IDs", {exact: true}).uncheck();
    await expect(page.locator("html")).toHaveAttribute("data-show-ids", "false");
    await page.getByLabel("Owner", {exact: true}).selectOption("browser.fixture.other");
    await expect(first).toHaveJSProperty("open", true);
    await expect(second).toHaveJSProperty("open", false);
  }
  await page.getByLabel("Open details", {exact: true}).check();
  expect(await details.evaluateAll(nodes => nodes.every(node => node.open))).toBe(true);
  await first.locator("summary").first().click();
  await page.getByRole("searchbox").fill("ASCII");
  await page.getByLabel("Show IDs", {exact: true}).check();
  await expect(page.locator("html")).toHaveAttribute("data-show-ids", "true");
  await expect(first).toHaveJSProperty("open", false);
  await expect(second).toHaveJSProperty("open", true);
  await page.getByLabel("Open details", {exact: true}).uncheck();
  expect(await details.evaluateAll(nodes => nodes.every(node => !node.open))).toBe(true);
});

test("static hierarchy links resolve once and remain deterministic", async ({staticViewURL, page}) => {
  await openWorkspace(page, staticViewURL, heading, "static-view");
  const links = page.locator('.hierarchy a[href^="#"]');
  const hrefs = await links.evaluateAll(nodes => nodes.map(node => node.getAttribute("href")));
  expect(hrefs).toHaveLength(5);
  expect(new Set(hrefs).size).toBe(5);
  for (const href of hrefs) {
    await expect(page.locator(href)).toHaveCount(1);
    await page.locator(`.hierarchy a[href="${href}"]`).click();
    expect(new URL(page.url()).hash).toBe(href);
  }
  await openWorkspace(page, staticViewURL, heading, "static-view");
  expect(await links.evaluateAll(nodes => nodes.map(node => node.getAttribute("href")))).toEqual(hrefs);
});

for (const colorScheme of ["light", "dark"]) {
  test(`static control boundaries have computed contrast in ${colorScheme}`, async ({staticTreeURL, page}, testInfo) => {
    await openWorkspace(page, staticTreeURL, treeHeading, "static-view");
    await page.emulateMedia({colorScheme});
    const controls = page.locator('input[type="search"], select, button');
    expect(await controls.count()).toBeGreaterThanOrEqual(4);
    const inspect = () => controls.evaluateAll(nodes => {
      function luminance(color) {
        const channels = color.match(/[\d.]+/g).slice(0, 3).map(Number).map(value => {
          const channel = value / 255;
          return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
        });
        return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
      }
      function ratio(left, right) {
        const a = luminance(left), b = luminance(right);
        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      }
      return nodes.map(node => {
        const style = getComputedStyle(node);
        let parent = node.parentElement;
        while (getComputedStyle(parent).backgroundColor === "rgba(0, 0, 0, 0)") parent = parent.parentElement;
        const outside = getComputedStyle(parent).backgroundColor;
        return {tag: node.tagName, border: style.borderTopColor, inside: style.backgroundColor, outside,
          insideRatio: ratio(style.borderTopColor, style.backgroundColor), outsideRatio: ratio(style.borderTopColor, outside),
          textRatio: ratio(style.color, style.backgroundColor), borderWidth: parseFloat(style.borderTopWidth)};
      });
    });
    const normal = await inspect();
    for (const control of normal) {
      expect(control.borderWidth).toBeGreaterThan(0);
      expect(control.insideRatio, JSON.stringify(control)).toBeGreaterThanOrEqual(3);
      expect(control.outsideRatio, JSON.stringify(control)).toBeGreaterThanOrEqual(3);
      expect(control.textRatio, JSON.stringify(control)).toBeGreaterThanOrEqual(4.5);
    }
    await page.getByRole("button").first().hover();
    const hover = await inspect();
    for (const control of hover) {
      expect(control.insideRatio, JSON.stringify(control)).toBeGreaterThanOrEqual(3);
      expect(control.outsideRatio, JSON.stringify(control)).toBeGreaterThanOrEqual(3);
    }
    await page.getByRole("searchbox").focus();
    await expect(page.getByRole("searchbox")).toBeFocused();
    expect(await page.getByRole("searchbox").evaluate(node => {
      const style = getComputedStyle(node);
      return style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0;
    })).toBe(true);
    await testInfo.attach(`contrast-${colorScheme}`, {body: JSON.stringify({normal, hover}), contentType: "application/json"});
  });
}

test("static downloads preserve declared bytes including Unicode", async ({staticTreeURL, page}) => {
  await openWorkspace(page, staticTreeURL, treeHeading, "static-view");
  const buttons = page.locator("[data-proofkit-download]");
  await expect(buttons).toHaveCount(2);
  for (const button of await buttons.all()) {
    const expected = Buffer.from(await button.getAttribute("data-download-content"), "base64");
    const downloadEvent = page.waitForEvent("download");
    await button.click();
    const download = await downloadEvent;
    expect(download.suggestedFilename()).toBe(await button.getAttribute("data-download-file"));
    expect(await readFile(await download.path())).toEqual(expected);
    expect(expected.toString("utf8")).toContain("\u039f\u0394\u039f\u03a3 \u0130stanbul &lt;input&gt;");
  }
});

test("static search keys are lowercased only once per rendered record", async ({staticViewURL, page}) => {
  await page.addInitScript(() => {
    const lower = String.prototype.toLowerCase;
    window.staticLowerCalls = [];
    String.prototype.toLowerCase = function () {
      window.staticLowerCalls.push(String(this));
      return lower.call(this);
    };
  });
  await openWorkspace(page, staticViewURL, heading, "static-view");
  for (const query of ["ASCII", "\u0130stanbul", ""]) {
    await page.getByRole("searchbox").fill(query);
    await page.getByLabel("View", {exact: true}).selectOption("table");
    await page.getByLabel("View", {exact: true}).selectOption("cards");
  }
  const counts = await page.evaluate(() => {
    const originals = [...document.querySelectorAll("[data-search]")].map(node => node.getAttribute("data-search"));
    return [...new Set(originals)].map(text => ({
      records: originals.filter(value => value === text).length,
      lowerCalls: window.staticLowerCalls.filter(value => value === text).length,
    }));
  });
  expect(counts).toHaveLength(5);
  for (const count of counts) expect(count.lowerCalls).toBe(count.records);
});

test("static consumers retain unique hierarchy targets and interactive records", async ({staticTreeURL, staticProofURL, staticCoverageURL, page}) => {
  const consumers = [
    [staticTreeURL, treeHeading],
    [staticProofURL, "Requirement Proof View: proofkit.browser.coverage.binding"],
    [staticCoverageURL, "Requirement Coverage View: proofkit.browser.coverage.view"],
  ];
  for (const [url, title] of consumers) {
    await openWorkspace(page, url, title, "static-view");
    const hrefs = await page.locator('.hierarchy a[href^="#"]').evaluateAll(nodes => nodes.map(node => node.getAttribute("href")));
    expect(hrefs.length, title).toBeGreaterThan(0);
    for (const href of hrefs) await expect(page.locator(href)).toHaveCount(1);
    const ids = await page.locator("[id]").evaluateAll(nodes => nodes.map(node => node.id));
    expect(new Set(ids).size, title).toBe(ids.length);
    const cards = page.locator("[data-proofkit-card]");
    expect(await cards.count(), title).toBeGreaterThan(0);
    const detail = cards.locator("details").first();
    if (await detail.count()) {
      await detail.locator("summary").first().click();
      await expect(detail).toHaveJSProperty("open", true);
    }
    for (const mode of ["table", "cards"]) {
      await page.getByLabel("View", {exact: true}).selectOption(mode);
      await page.getByRole("searchbox").fill("no-such-record");
      await expect(page.locator("#proofkit-visible-count")).toHaveText("0");
      await page.getByRole("searchbox").fill("");
      await expect(page.locator("#proofkit-visible-count")).toHaveText(String(await cards.count()));
      if (await detail.count()) await expect(detail).toHaveJSProperty("open", true);
    }
  }
});
