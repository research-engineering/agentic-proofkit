import {expect} from "@playwright/test";
import {lookupTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

for (const late of [{route: "navigation", status: 403}, {route: "navigation", status: 200}, {route: "requirements", status: 403}]) {
  test(`superseded non-cooperative ${late.route} ${late.status} cannot change current content or request authority`, async ({lookupURL, page}) => {
    await page.addInitScript(({path}) => {
      const nativeFetch = globalThis.fetch.bind(globalThis);
      const probe = globalThis.__lateWorkspaceResponses = {bodyStarted: 0, bodyConsumed: 0, completed: 0, releaseBody: undefined};
      const bodyReleased = new Promise(resolve => { probe.releaseBody = resolve; });
      // These owners finish policy work synchronously in the response Promise reactions:
      // workspace-requests.js -> workspace.js post/renderSpecifications or navigation load.
      // A next-task marker follows that entire chain, not just headers or a body chunk.
      const afterResponseReactions = () => setTimeout(() => { probe.completed += 1; }, 0);
      globalThis.fetch = async (input, init = {}) => {
        const url = new URL(typeof input === "string" ? input : input.url, location.href);
        if (url.pathname !== path) return nativeFetch(input, init);
        const query = typeof init.body === "string" ? JSON.parse(init.body).query : null;
        const delayed = query?.searchText === "Root" || query?.parentNodeId === "spec.root";
        const response = await nativeFetch(input, {...init, signal: undefined});
        if (delayed) {
          if (response.ok) {
            const readBody = response.text.bind(response);
            response.text = async () => {
              probe.bodyStarted += 1;
              await bodyReleased;
              const body = await readBody();
              probe.bodyConsumed += 1;
              afterResponseReactions();
              return body;
            };
          } else {
            // fetchWorkspaceResponse rejects HTTP errors without reading the body.
            afterResponseReactions();
          }
        }
        return response;
      };
    }, {path: `/api/v1/${late.route}`});
    let release;
    const barrier = new Promise(resolve => { release = resolve; });
    let markStarted;
    const started = new Promise(resolve => { markStarted = resolve; });
    await page.route(`**/api/v1/${late.route}`, async route => {
      const query = route.request().postDataJSON().query;
      if (query.searchText !== "Root" && query.parentNodeId !== "spec.root") return route.continue();
      const response = late.status === 200 ? await route.fetch() : null;
      markStarted();
      await barrier;
      return response ? route.fulfill({response}) : route.fulfill({status: late.status, body: "private obsolete detail"});
    });
    try {
      await openWorkspace(page, lookupURL);
      await expect(page.locator("#workspace-content [data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-A");
      if (late.route === "navigation") {
        await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
        await started;
        await page.getByRole("button", {name: "Collapse Workspace root", exact: true}).click();
      } else {
        await page.getByRole("searchbox").fill("Root");
        await page.getByRole("button", {name: "Search requirements", exact: true}).click();
        await started;
      }
      await page.getByRole("searchbox").fill("REQ-B-129");
      await page.getByRole("button", {name: "Search requirements", exact: true}).click();
      await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveAttribute("data-requirement-id", "REQ-B-129");
      await page.getByRole("button", {name: "Select invariant", exact: true}).click();
      release();
      if (late.status === 200) {
        await expect.poll(() => page.evaluate(() => globalThis.__lateWorkspaceResponses.bodyStarted)).toBe(1);
        expect(await page.evaluate(() => ({
          bodyConsumed: globalThis.__lateWorkspaceResponses.bodyConsumed,
          completed: globalThis.__lateWorkspaceResponses.completed,
        }))).toEqual({bodyConsumed: 0, completed: 0});
        await page.evaluate(() => globalThis.__lateWorkspaceResponses.releaseBody());
      }
      await expect.poll(() => page.evaluate(() => globalThis.__lateWorkspaceResponses.completed)).toBe(1);
      expect(await page.evaluate(() => ({
        bodyStarted: globalThis.__lateWorkspaceResponses.bodyStarted,
        bodyConsumed: globalThis.__lateWorkspaceResponses.bodyConsumed,
      }))).toEqual({bodyStarted: late.status === 200 ? 1 : 0, bodyConsumed: late.status === 200 ? 1 : 0});
      await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveAttribute("data-requirement-id", "REQ-B-129");
      await expect(page.locator("#selected-context li")).toHaveText("State \u{1f9ed} e\u0301 keeps source identity.");
      await expect(page.getByRole("searchbox")).toBeEnabled();
      await expect(page.getByRole("alert")).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Expand Workspace root", exact: true})).toBeVisible();
      await expect(page.getByRole("button", {name: "Child contracts", exact: true})).toHaveCount(0);
    } finally {
      release();
      if (!page.isClosed()) await page.evaluate(() => globalThis.__lateWorkspaceResponses?.releaseBody());
    }
  });
}
