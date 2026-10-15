import {expect} from "@playwright/test";
import {analyzeAxe, assertAxeTestComplete, initializeAxe} from "./axe-harness.mjs";
import {sourceViewTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

const requirementId = "REQ-CONSUMER-001";
const sharedRequirementId = "REQ-CONSUMER-002";
const sourceHeading = "Requirement Source View: browser.fixture.requirements";

test("source view nests scenarios under their requirement and renders provenance without granting execution authority", async ({sourceViewURL, page}) => {
  await openWorkspace(page, sourceViewURL, sourceHeading, "static-view");
  const summary = page.locator(".summary");
  for (const [section, record] of [["Vocabulary", "TERM-BROWSER"], ["Declared Derivations", "DRV-BROWSER"]]) {
    await summary.locator("summary").filter({hasText: new RegExp(`^${section}$`)}).click();
    await summary.locator("summary").filter({hasText: new RegExp(`^${record}$`)}).click();
  }
  await expect(summary.locator("summary").filter({hasText: /^Declared Scenarios$/})).toHaveCount(0);
  const card = page.locator("[data-proofkit-card]").filter({has: page.locator(".proofkit-id", {hasText: requirementId})});
  await expect(card.getByRole("heading", {name: "Scenarios", exact: true})).toBeVisible();
  const scenarioLink = card.getByRole("link", {name: "SCN-BROWSER", exact: true});
  const scenarioHref = await scenarioLink.getAttribute("href");
  expect(scenarioHref).toMatch(/^#proofkit-/);
  await expect(page.locator(scenarioHref)).toHaveCount(1);
  await scenarioLink.click();
  expect(new URL(page.url()).hash).toBe(scenarioHref);
  await expect(card.locator(scenarioHref)).toBeInViewport();
  await card.locator("summary").filter({hasText: /^SCN-BROWSER$/}).click();
  await expect(summary).toContainText("The <input> text remains inert.");
  await expect(card).toContainText("1. Open the source.");
  await expect(card).toContainText("2. Read the invariant.");
  await expect(card).toContainText("A declaration is shown as an execution result.");
  await expect(card.locator("input")).toHaveCount(0);
  await expect(summary).toContainText("docs/decision.md");
  await expect(summary).toContainText("owner_decision");
  await expect(summary.locator("input")).toHaveCount(0);
  await page.getByRole("searchbox").fill("SCN-BROWSER");
  await expect(page.locator("[data-proofkit-card]:visible .proofkit-id")).toHaveText([requirementId]);
  await page.getByRole("searchbox").fill("");
  const group = page.getByRole("link", {name: /RGRP-BROWSER/});
  const href = await group.getAttribute("href");
  expect(href).toMatch(/^#/);
  await expect(page.locator(href)).toBeVisible();
  await expect(page.locator("[data-proofkit-card] .proofkit-id")).toHaveText([requirementId]);
});

test("a scenario linked to two requirements renders once under Shared Scenarios and both cards link to it", async ({sharedSourceViewURL, page}) => {
  await openWorkspace(page, sharedSourceViewURL, sourceHeading, "static-view");
  const shared = page.locator(".summary dt").filter({hasText: /^Shared Scenarios$/}).locator("xpath=following-sibling::dd[1]");
  const record = shared.locator("details").filter({has: page.locator("summary", {hasText: /^SCN-SHARED$/})});
  await expect(record).toHaveCount(1);
  const target = `#${await record.getAttribute("id")}`;
  expect(target).toMatch(/^#proofkit-/);
  await expect(page.locator(target)).toHaveCount(1);
  await expect(page.locator("li").filter({hasText: /^The shared record is shown once\.$/})).toHaveCount(1);
  for (const id of [requirementId, sharedRequirementId]) {
    const card = page.locator("[data-proofkit-card]").filter({has: page.locator(".proofkit-id", {hasText: id})});
    await expect(card.locator(target)).toHaveCount(0);
    await expect(card).not.toContainText("The shared record is shown once.");
    const link = card.getByRole("link", {name: "SCN-SHARED", exact: true});
    await expect(link).toHaveAttribute("href", target);
    await link.click();
    expect(new URL(page.url()).hash).toBe(target);
    await expect(record).toBeInViewport();
  }
  await record.locator("summary").click();
  await expect(record).toContainText("1. Follow the shared scenario link.");
  for (const id of [requirementId, sharedRequirementId]) await expect(record).toContainText(id);
  for (const [query, ids] of [["SCN-SHARED", [requirementId, sharedRequirementId]], ["SCN-BROWSER", [requirementId]]]) {
    await page.getByRole("searchbox").fill(query);
    await expect(page.locator("[data-proofkit-card]:visible .proofkit-id")).toHaveText(ids);
  }
});

test("source view with a shared scenario has no automated accessibility violations at 390px", async ({sharedSourceViewURL, page}) => {
  await initializeAxe(page);
  try {
    await page.setViewportSize({width: 390, height: 900});
    await openWorkspace(page, sharedSourceViewURL, sourceHeading, "static-view");
    const record = page.locator(".summary dt").filter({hasText: /^Shared Scenarios$/}).locator("xpath=following-sibling::dd[1]").locator("details");
    await record.locator("summary").click();
    await expect(record).toContainText("1. Follow the shared scenario link.");
    const layout = await page.evaluate(() => ({width: innerWidth, scrollWidth: document.documentElement.scrollWidth}));
    expect(layout.scrollWidth).toBeLessThanOrEqual(layout.width);
    const accessibility = await analyzeAxe(page);
    expect(accessibility.violations).toEqual([]);
  } finally { assertAxeTestComplete(page); }
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

for (const width of [390, 1280]) {
  test(`source view with nested scenarios has no automated accessibility violations at ${width}px`, async ({sourceViewURL, page}) => {
    await initializeAxe(page);
    try {
      await page.setViewportSize({width, height: 900});
      await openWorkspace(page, sourceViewURL, sourceHeading, "static-view");
      const card = page.locator("[data-proofkit-card]").first();
      await card.locator("summary").filter({hasText: /^SCN-BROWSER$/}).click();
      await expect(card).toContainText("1. Open the source.");
      const layout = await page.evaluate(() => ({width: innerWidth, scrollWidth: document.documentElement.scrollWidth}));
      expect(layout.scrollWidth).toBeLessThanOrEqual(layout.width);
      const accessibility = await analyzeAxe(page);
      expect(accessibility.violations).toEqual([]);
    } finally { assertAxeTestComplete(page); }
  });
}
