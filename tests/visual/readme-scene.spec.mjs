import {expect} from "@playwright/test";

import {assertEmulation, assertMatchesReference, captureTwice, navigate, readmeViewport, test} from "./visual-harness.mjs";

const question = "Which negative case should reject a request without an idempotency key?";

// The README scene: the committed example.dispatch project served through the
// project view path, its first invariant selected and a question typed into
// the inspector, in a 1440x960 light window. Only the Chromium project runs it.
test("readme-scene light 1440x960", async ({page, browserName, visualServers}, testInfo) => {
  expect(browserName).toBe("chromium");
  await page.setViewportSize(readmeViewport);
  await navigate(page, await visualServers.url("--readme-project"), "workspace", "example.dispatch", "light");
  await expect(page.locator("body")).toHaveAttribute("data-state", "specifications");
  await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
  await page.getByRole("button", {name: "Select invariant"}).first().click();
  const questionInput = page.locator("#annotation-question");
  await questionInput.fill(question);
  await expect(questionInput).toHaveValue(question);
  await page.mouse.move(readmeViewport.width - 1, readmeViewport.height - 1);
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
  });
  await assertEmulation(page, "light");
  const captures = await captureTwice(page, {fullPage: false});
  assertMatchesReference(testInfo, "chromium/readme-scene.light.1440", captures);
});
