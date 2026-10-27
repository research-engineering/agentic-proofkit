import {expect} from "@playwright/test";

import {judgeSecurityEvents, settleSecurityEvents} from "./oracles.mjs";

// Oracle 5: Unicode selection in the Specifications tab. Selecting the one
// astral code point of an invariant projects code-point coordinates into the
// handoff packet, the oracle of the runtime harness, here in every matrix
// mode. In the narrow modes the inspector is a modal dialog that the reader
// opens after selecting; opening it commits the selection.
const needle = "\u{1F680}";

export async function unicodeSelectionOracle(page, mode, security) {
  const invariant = page.locator("[data-anchor-id]").filter({hasText: `retry ${needle}`}).first();
  await expect(invariant).toBeVisible();
  const invariantText = await invariant.textContent();
  if (invariantText === null) throw new Error("Unicode fixture text is unavailable");
  const domStart = invariantText.indexOf(needle);
  if (domStart < 0) throw new Error("Unicode fixture is unavailable");
  const domEnd = domStart + needle.length;
  const expectedStart = Array.from(invariantText.slice(0, domStart)).length;
  const expectedEnd = Array.from(invariantText.slice(0, domEnd)).length;
  expect(domEnd - domStart).toBe(2);
  expect(expectedEnd - expectedStart).toBe(1);
  await invariant.evaluate((element, bounds) => {
    const text = element.firstChild;
    const selection = window.getSelection();
    if (!(text instanceof Text) || text.textContent !== bounds.expectedText || !selection) throw new Error("Exact Unicode selection fixture is unavailable");
    const range = document.createRange();
    range.setStart(text, bounds.start);
    range.setEnd(text, bounds.end);
    selection.removeAllRanges();
    selection.addRange(range);
  }, {end: domEnd, expectedText: invariantText, start: domStart});
  const status = page.locator("#handoff-status");
  await expect(status).toContainText("1 source-bound target");
  await expect(page.locator("#selected-context li")).toHaveText([needle]);
  if (mode.narrow) {
    await page.locator("#open-inspector").click();
    await expect(page.locator("#workspace-inspector:modal")).toHaveCount(1);
  }
  const inspector = page.locator("#workspace-inspector");
  await expect(inspector).toBeVisible();
  await inspector.getByRole("textbox", {name: "Question"}).fill("Does the Unicode coordinate remain source-bound?");
  await expect(inspector.getByLabel("Selected source text").getByRole("listitem")).toHaveText([needle]);
  await inspector.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(status).toContainText("Handoff packet created");
  const packet = JSON.parse(await page.locator("#handoff-packet").textContent());
  expect(packet.annotations).toHaveLength(1);
  expect(packet.annotations[0].exactQuote).toBe(needle);
  expect(packet.annotations[0].startCodePoint).toBe(expectedStart);
  expect(packet.annotations[0].endCodePoint).toBe(expectedEnd);
  await settleSecurityEvents(page);
  judgeSecurityEvents(security.observation());
}
