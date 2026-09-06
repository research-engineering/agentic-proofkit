import {expect} from "@playwright/test";
import {coverageTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";
import {analyzeAxe, assertAxeTestComplete, initializeAxe} from "./axe-harness.mjs";

const viewports = [
  {width: 320, height: 640, view: "coverage", colorScheme: "light"},
  {width: 390, height: 844, view: "graph", colorScheme: "dark"},
  {width: 844, height: 390, view: "coverage", colorScheme: "light"},
  {width: 768, height: 1024, view: "graph", colorScheme: "light"},
  {width: 1280, height: 800, view: "coverage", colorScheme: "dark"},
  {width: 1920, height: 1080, view: "graph", colorScheme: "light"},
  {width: 640, height: 400, view: "coverage", colorScheme: "light"},
];

for (const viewport of viewports) {
  test(`evidence ${viewport.view} reflows at ${viewport.width}x${viewport.height} ${viewport.colorScheme}`, async ({compactURL, page}, testInfo) => {
    await page.setViewportSize({width: viewport.width, height: viewport.height});
    await page.emulateMedia({colorScheme: viewport.colorScheme, reducedMotion: "reduce"});
    await initializeAxe(page);
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await openWorkspace(page, compactURL);
    await page.getByRole("button", {name: viewport.view === "coverage" ? "Coverage" : "Traceability", exact: true}).click();
    await expect(page.locator("body")).toHaveAttribute("data-state", viewport.view);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    if (viewport.view === "coverage") {
      const ask = page.locator(".coverage-record").first().getByRole("button", {name: "Ask about evidence", exact: true});
      await ask.focus();
      await page.keyboard.press("Enter");
      const question = page.getByRole("textbox", {name: "Question", exact: true});
      await expect(question).toBeFocused();
      await question.fill("Keep \u{1F680} e\u0301 and \u05d0\u05d1 unchanged.");
      await page.getByRole("button", {name: "Create handoff packet", exact: true}).click();
      await expect(page.locator("#handoff-status")).toHaveText("Handoff packet created.");
      await expect(page.getByRole("button", {name: "Copy JSON", exact: true})).toBeVisible();
      await expect(page.getByRole("button", {name: "Download JSON", exact: true})).toBeVisible();
      await expect(question).toHaveValue("Keep \u{1F680} e\u0301 and \u05d0\u05d1 unchanged.");
      const bounds = await page.locator("#workspace-inspector").evaluate(element => ({width: element.clientWidth, scroll: element.scrollWidth}));
      expect(bounds.scroll).toBeLessThanOrEqual(bounds.width + 1);
      if (viewport.width <= 1024) {
        await page.getByRole("button", {name: "Close inspector", exact: true}).click();
        await expect(ask).toBeFocused();
      }
    } else {
      const records = page.getByRole("list", {name: "Admitted traceability nodes"});
      const first = records.getByRole("button").first();
      await first.focus();
      await page.keyboard.press("Enter");
      await expect(first).toBeFocused();
      await expect(page.locator(".graph-inspector > dl")).toBeVisible();
      await expect(page.getByRole("region", {name: "Traceability graph viewport"})).toBeVisible({visible: viewport.width > 768});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    }
    expect((await analyzeAxe(page)).violations).toEqual([]);
    assertAxeTestComplete(page);
    expect(errors).toEqual([]);
    await page.evaluate(() => window.scrollTo(0, 0));
    await testInfo.attach("evidence-viewport.png", {body: await page.screenshot(), contentType: "image/png"});
  });
}
