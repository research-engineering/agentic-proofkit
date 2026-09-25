import {expect} from "@playwright/test";
import {lookupTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

test("a new selection resets a handoff error to polite routine status", async ({lookupURL, page}) => {
  await page.route("**/api/v1/handoff", route => route.fulfill({status: 400, body: "private failure detail"}));
  await openWorkspace(page, lookupURL);
  await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
  const draft = "Keep this question after a failed handoff.";
  await page.getByRole("textbox", {name: "Question", exact: true}).fill(draft);
  await page.getByRole("button", {name: "Create handoff packet", exact: true}).click();
  const status = page.locator("#handoff-status");
  await expect(status).toHaveAttribute("role", "alert");
  await expect(status).toHaveAttribute("aria-live", "assertive");
  await expect(status).toHaveText("The handoff packet could not be created.");
  await page.getByRole("button", {name: "Select invariant", exact: true}).nth(1).click();
  await expect(status).toHaveText("1 source-bound target(s) selected.");
  await expect(status).toHaveAttribute("role", "status");
  await expect(status).toHaveAttribute("aria-live", "polite");
  await expect(page.getByRole("textbox", {name: "Question", exact: true})).toHaveValue(draft);
  await page.getByRole("button", {name: "Clear selection", exact: true}).click();
  await expect(status).toHaveText("No source-bound text selected.");
  await expect(status).toHaveAttribute("role", "status");
  await expect(status).toHaveAttribute("aria-live", "polite");
});

for (const statusCode of [409, 410]) {
  test(`handoff ${statusCode} retains its exact locked recovery and question draft`, async ({lookupURL, page}) => {
    let calls = 0;
    await page.route("**/api/v1/handoff", route => {
      calls++;
      return route.fulfill({status: statusCode, body: "private terminal detail"});
    });
    await openWorkspace(page, lookupURL);
    await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
    const question = page.getByRole("textbox", {name: "Question", exact: true});
    await question.fill("Keep my terminal question.");
    await page.getByRole("button", {name: "Create handoff packet", exact: true}).click();
    const status = page.locator("#handoff-status");
    await expect(status).toHaveAttribute("role", "alert");
    await expect(status).toHaveText(statusCode === 409 ? "The workspace snapshot has changed." : "This one-shot session has already ended. No further handoff can be created.");
    await expect(page.locator("body")).not.toContainText("private terminal detail");
    await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
    await expect(page.getByRole("button", {name: "Reload workspace", exact: true})).toHaveCount(statusCode === 409 ? 1 : 0);
    expect(await page.locator("[data-protected-request]").evaluateAll(elements => elements.every(element => element.disabled))).toBe(true);
    await page.locator("[data-protected-request]").evaluateAll(elements => elements.forEach(element => element.click()));
    expect(calls).toBe(1);
    await expect(question).toHaveValue("Keep my terminal question.");
    await question.fill("The locked draft remains editable.");
    await expect(question).toHaveValue("The locked draft remains editable.");
  });
}

for (const [name, unit] of [["ASCII", "a"], ["CJK", "\u754c"], ["astral", "\u{1f9ed}"], ["combining", "e\u0301"]]) {
  test(`${name} question UTF-8 limit rejects overflow before fetch and retains exact draft`, async ({lookupURL, page}) => {
    await page.addInitScript(() => {
      const nativeFetch = window.fetch;
      window.handoffFetchCount = 0;
      window.fetch = (...args) => {
        if (args[0] === "/api/v1/handoff") window.handoffFetchCount++;
        return nativeFetch(...args);
      };
    });
    const sent = [];
    page.on("request", request => {
      if (new URL(request.url()).pathname === "/api/v1/handoff") sent.push(request.postDataJSON());
    });
    await openWorkspace(page, lookupURL);
    await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
    const question = page.getByRole("textbox", {name: "Question", exact: true});
    const limit = Number(await question.getAttribute("data-max-question-bytes"));
    expect(limit).toBe(4096);
    expect(await question.getAttribute("maxlength")).toBeNull();
    const unitBytes = Buffer.byteLength(unit, "utf8");
    const exact = unit.repeat(Math.floor(limit / unitBytes)) + "a".repeat(limit % unitBytes);
    expect(Buffer.byteLength(exact, "utf8")).toBe(limit);
    await question.fill(exact);
    await question.press("End");
    await page.keyboard.insertText("b");
    const overflow = `${exact}b`;
    await expect(question).toHaveValue(overflow);
    await page.getByRole("button", {name: "Create handoff packet", exact: true}).click();
    const status = page.locator("#handoff-status");
    await expect(status).toHaveText(`Question exceeds the ${limit}-byte UTF-8 limit (${limit + 1} bytes). Shorten it before submitting.`);
    await expect(status).toHaveAttribute("role", "alert");
    await expect(status).toHaveAttribute("aria-live", "assertive");
    expect(await page.evaluate(() => window.handoffFetchCount)).toBe(0);
    expect(sent).toHaveLength(0);
    await expect(question).toHaveValue(overflow);
    await expect(page.locator("#selected-context li")).toHaveCount(1);
    const draft = ` \n${exact}\n `;
    await question.fill(draft);
    await page.getByRole("button", {name: "Create handoff packet", exact: true}).click();
    await expect(status).toHaveText("Handoff packet created.");
    await expect(status).toHaveAttribute("role", "status");
    await expect(status).toHaveAttribute("aria-live", "polite");
    expect(await page.evaluate(() => window.handoffFetchCount)).toBe(1);
    expect(sent).toHaveLength(1);
    expect(sent[0].annotations[0].question).toBe(exact);
    const packet = JSON.parse(await page.locator("#handoff-packet").textContent());
    expect(packet.annotations[0].question).toBe(exact);
    await expect(question).toHaveValue(draft);
  });
}
