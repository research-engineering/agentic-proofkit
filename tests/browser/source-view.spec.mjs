import {expect} from "@playwright/test";
import {sourceViewTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

const requirementId = "REQ-CONSUMER-001";
const sourceHeading = "Requirement Source View: browser.fixture.requirements";

test("source view renders declared scenarios and provenance without granting execution authority", async ({sourceViewURL, page}) => {
  await openWorkspace(page, sourceViewURL, sourceHeading, "static-view");
  const summary = page.locator(".summary");
  for (const [section, record] of [["Vocabulary", "TERM-BROWSER"], ["Declared Scenarios", "SCN-BROWSER"], ["Declared Derivations", "DRV-BROWSER"]]) {
    await summary.locator("summary").filter({hasText: new RegExp(`^${section}$`)}).click();
    await summary.locator("summary").filter({hasText: new RegExp(`^${record}$`)}).click();
  }
  await expect(summary).toContainText("The <input> text remains inert.");
  await expect(summary).toContainText("1. Open the source.");
  await expect(summary).toContainText("2. Read the invariant.");
  await expect(summary).toContainText("A declaration is shown as an execution result.");
  await expect(summary).toContainText("docs/decision.md");
  await expect(summary).toContainText("owner_decision");
  await expect(summary.locator("input")).toHaveCount(0);
  const group = page.getByRole("link", {name: /RGRP-BROWSER/});
  const href = await group.getAttribute("href");
  expect(href).toMatch(/^#/);
  await expect(page.locator(href)).toBeVisible();
  await expect(page.locator("[data-proofkit-card] .proofkit-id")).toHaveText([requirementId]);
});

test("source search preserves the record set and count across cards and table", async ({sourceViewURL, page}) => {
  await openWorkspace(page, sourceViewURL, sourceHeading, "static-view");
  for (const [query, ids] of [["does not approve", [requirementId]], [requirementId, [requirementId]], ["no-such-record", []]]) {
    await page.getByRole("searchbox").fill(query);
    for (const mode of ["cards", "table", "cards"]) {
      await page.getByLabel("View", {exact: true}).selectOption(mode);
      for (const [kind, active] of [["card", mode === "cards"], ["table", mode === "table"]]) {
        const section = page.locator(`[data-proofkit-${kind}-section]`);
        await expect(section).toHaveJSProperty("hidden", !active);
        if (!active) await expect(section).toBeHidden();
        else if (ids.length > 0) await expect(section).toBeVisible();
      }
      const rows = page.locator(mode === "cards" ? "[data-proofkit-card]:visible .proofkit-id" : "[data-proofkit-table-row]:visible td:first-child");
      await expect(rows).toHaveText(ids);
      await expect(page.locator("#proofkit-visible-count")).toHaveText(String(ids.length));
    }
  }
});

test("source navigation rejects an incorrect view identity", async ({sourceViewURL, page}) => {
  await expect(openWorkspace(page, sourceViewURL, "Requirement Source View: missing.source", "static-view")).rejects.toThrow();
  await expect(page.getByRole("heading", {name: sourceHeading, exact: true})).toBeVisible();
});

for (const width of [390, 1280]) {
  test(`source select labels stay grouped at ${width}px`, async ({sourceViewURL, page}) => {
    await page.setViewportSize({width, height: 900});
    await openWorkspace(page, sourceViewURL, sourceHeading, "static-view");
    await expect(page.getByRole("searchbox", {name: "Search", exact: true})).toBeVisible();
    for (const id of ["proofkit-view-mode", "proofkit-filter-owner", "proofkit-filter-claim-level", "proofkit-filter-risk-class", "proofkit-filter-lifecycle"]) {
      const label = page.locator(`label[for="${id}"]`);
      const control = page.locator(`#${id}`);
      await expect(label).toBeVisible();
      await expect(control).toBeVisible();
      const labelBox = await label.boundingBox();
      const controlBox = await control.boundingBox();
      expect(labelBox).not.toBeNull();
      expect(controlBox).not.toBeNull();
      expect(Math.abs(labelBox.x - controlBox.x)).toBeLessThanOrEqual(1);
      expect(labelBox.y + labelBox.height).toBeLessThanOrEqual(controlBox.y);
    }
  });

  test(`source paths remain readable without overflow at ${width}px`, async ({sourceViewURL, page}) => {
    await page.setViewportSize({width, height: 900});
    await openWorkspace(page, sourceViewURL, sourceHeading, "static-view");
    const sourcePath = page.locator(".summary dt").filter({hasText: /^Requirements source$/}).locator("xpath=following-sibling::dd[1]").locator("code");
    await expect(sourcePath).toHaveText(`docs/specs/${"source".repeat(20)}/requirements.v2.json`);
    const layout = await page.evaluate(() => ({width: innerWidth, scrollWidth: document.documentElement.scrollWidth}));
    expect(layout.scrollWidth).toBeLessThanOrEqual(layout.width);
    const paths = await page.locator(".summary code").evaluateAll(elements => elements.map(element => ({
      right: element.getBoundingClientRect().right,
      parentRight: element.closest("dd").getBoundingClientRect().right,
    })));
    for (const path of paths) expect(path.right).toBeLessThanOrEqual(path.parentRight + 1);
  });
}
