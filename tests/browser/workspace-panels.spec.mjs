import {expect} from "@playwright/test";
import {analyzeAxe, assertAxeTestComplete, initializeAxe} from "./axe-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";
import {lookupTest} from "./workspace-test-harness.mjs";

const test = lookupTest.extend({
  axePage: async ({page}, use) => {
    await initializeAxe(page);
    try { await use(page); }
    finally { assertAxeTestComplete(page); }
  },
});

for (const panel of ["navigation", "inspector"]) {
  lookupTest(`desktop-to-mobile focus returns to the corresponding ${panel} opener`, async ({lookupURL, page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await openWorkspace(page, lookupURL);
    await expect(page.locator("#workspace-content [data-requirement-id]").first()).toBeVisible();
    await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
    await page.getByRole("textbox", {name: "Question", exact: true}).fill("Preserve the selected source and draft.");
    const selected = await page.locator("#selected-context li").allTextContents();
    await page.locator(panel === "navigation" ? "#requirement-search" : "#annotation-question").focus();
    await page.setViewportSize({width: 390, height: 844});
    await expect(page.locator(`#workspace-${panel}`)).not.toBeVisible();
    await expect(page.locator(`#open-${panel}`)).toBeFocused();
    await expect(page.locator("dialog:modal")).toHaveCount(0);
    await expect(page.locator("body")).toHaveAttribute("data-modal-open", "false");
    expect(await page.locator("#selected-context li").allTextContents()).toEqual(selected);
    await expect(page.locator("#annotation-question")).toHaveValue("Preserve the selected source and draft.");
  });
}

lookupTest("desktop layout does not acquire focus without user activation", async ({lookupURL, page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await openWorkspace(page, lookupURL);
  await expect(page.locator("[data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-A");
  await expect(page.locator("body")).toBeFocused();
  await page.getByRole("searchbox").focus();
  await page.setViewportSize({width: 1920, height: 1080});
  await expect(page.getByRole("searchbox")).toBeFocused();
  await page.getByRole("button", {name: "Close navigation", exact: true}).click();
  await expect(page.getByRole("button", {name: "Toggle specification navigation", exact: true})).toBeFocused();
  await page.getByRole("button", {name: "Toggle specification navigation", exact: true}).click();
  await expect(page.getByRole("searchbox")).toBeFocused();
});

test("mobile inspector commits source selection, contains focus, and preserves the draft through resize", async ({lookupURL, axePage: page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await openWorkspace(page, lookupURL);
  await expect(page.locator("[data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-A");
  const first = await page.locator("[data-anchor-id]").first().boundingBox();
  expect(first).not.toBeNull();
  expect(first.y).toBeGreaterThan(0);
  expect(first.y + first.height).toBeLessThan(844);
  await expect(page.locator("#workspace-navigation")).not.toBeVisible();
  await expect(page.locator("#workspace-inspector")).not.toBeVisible();
  await page.getByRole("button", {name: "Toggle specification navigation", exact: true}).click();
  await expect(page.getByRole("searchbox")).toBeFocused();
  await page.getByRole("searchbox").fill("REQ-B-129");
  await page.getByRole("button", {name: "Search requirements", exact: true}).click();
  await expect(page.locator("#workspace-navigation")).not.toBeVisible();
  const invariant = page.locator('[data-requirement-id="REQ-B-129"] [data-anchor-id]');
  await expect(invariant).toHaveText("State \u{1f9ed} e\u0301 keeps source identity.");
  await invariant.evaluate(element => {
    const range = document.createRange();
    range.setStart(element.firstChild, 6);
    range.setEnd(element.firstChild, 8);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  });
  await expect(page.locator("#selected-context li")).toHaveText("\u{1f9ed}");
  const opener = page.getByRole("button", {name: "Toggle question inspector", exact: true});
  await opener.click();
  const inspector = page.getByRole("dialog", {name: "Ask about selection", exact: true});
  await expect(inspector).toBeVisible();
  const question = page.getByRole("textbox", {name: "Question", exact: true});
  await expect(question).toBeFocused();
  await question.fill("Keep the source-bound coordinates.");
  await expect(page.locator("#selected-context li")).toHaveText("\u{1f9ed}");
  const focusStates = [];
  for (let index = 0; index < 10; index += 1) {
    await page.keyboard.press("Tab");
    focusStates.push(await inspector.evaluate(element => ({documentFocused: document.hasFocus(), inside: element.contains(document.activeElement), body: document.activeElement === document.body})));
  }
  // W3C H102 permits native modal focus in the dialog or browser chrome.
  expect(focusStates.filter(state => state.documentFocused).length).toBeGreaterThanOrEqual(3);
  for (const state of focusStates) expect(state.documentFocused ? state.inside : state.body).toBe(true);
  await question.focus();
  const accessibility = await analyzeAxe(page);
  expect(accessibility.violations).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(inspector).not.toBeVisible();
  await expect(opener).toBeFocused();
  await opener.click();
  await expect(question).toHaveValue("Keep the source-bound coordinates.");
  await page.getByRole("button", {name: "Create handoff packet", exact: true}).click();
  await expect(page.locator("#handoff-status")).toHaveText("Handoff packet created.");
  const packet = JSON.parse(await page.locator("#handoff-packet").textContent());
  expect(packet.annotations[0]).toMatchObject({exactQuote: "\u{1f9ed}", startCodePoint: 6, endCodePoint: 7});
  await page.setViewportSize({width: 1440, height: 900});
  await expect(page.locator("#workspace-navigation")).toBeVisible();
  await expect(inspector).toBeVisible();
  expect(await page.locator("dialog:modal").count()).toBe(0);
  await expect(question).toHaveValue("Keep the source-bound coordinates.");
  await page.setViewportSize({width: 390, height: 844});
  await expect(page.locator("dialog:modal")).toHaveCount(0);
  await expect(page.locator("#workspace-navigation")).not.toBeVisible();
  await expect(inspector).not.toBeVisible();
  await page.getByRole("button", {name: "Diff", exact: true}).click();
  await expect(page.locator("body")).toHaveAttribute("data-state", "diff-unavailable");
  await expect(page.locator("#selected-context li")).toHaveCount(0);
  await opener.click();
  await expect(question).toHaveValue("Keep the source-bound coordinates.");
  await expect(page.locator("#handoff-packet")).toBeEmpty();
});

test("mobile navigation and inspector never retain simultaneous modal authority", async ({lookupURL, axePage: page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await openWorkspace(page, lookupURL);
  await page.getByRole("button", {name: "Toggle specification navigation", exact: true}).click();
  await expect(page.locator("dialog:modal")).toHaveAttribute("id", "workspace-navigation");
  // Exercise the transition owner even when an outside opener is natively inert.
  await page.locator("#open-inspector").evaluate(button => button.click());
  await expect(page.locator("dialog:modal")).toHaveAttribute("id", "workspace-inspector");
  await expect(page.locator("#workspace-navigation")).not.toBeVisible();
  await expect(page.locator("#annotation-question")).toBeFocused();
  await page.locator("#open-navigation").evaluate(button => button.click());
  await expect(page.locator("dialog:modal")).toHaveAttribute("id", "workspace-navigation");
  await expect(page.locator("#workspace-inspector")).not.toBeVisible();
  await expect(page.getByRole("searchbox")).toBeFocused();
  const accessibility = await analyzeAxe(page);
  expect(accessibility.violations).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(page.locator("dialog:modal")).toHaveCount(0);
  await expect(page.locator("#open-navigation")).toBeFocused();
});
