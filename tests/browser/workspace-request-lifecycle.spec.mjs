import {expect} from "@playwright/test";
import {lookupTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

for (const late of [{route: "navigation", status: 403}, {route: "navigation", status: 200}, {route: "requirements", status: 403}]) {
  test(`superseded non-cooperative ${late.route} ${late.status} cannot change current content or request authority`, async ({lookupURL, page}) => {
    await page.addInitScript(({path}) => {
      const nativeFetch = globalThis.fetch.bind(globalThis);
      globalThis.__lateWorkspaceResponses = 0;
      globalThis.fetch = async (input, init = {}) => {
        const url = new URL(typeof input === "string" ? input : input.url, location.href);
        if (url.pathname !== path) return nativeFetch(input, init);
        const query = typeof init.body === "string" ? JSON.parse(init.body).query : null;
        const delayed = query?.searchText === "Root" || query?.parentNodeId === "spec.root";
        const response = await nativeFetch(input, {...init, signal: undefined});
        if (delayed) globalThis.__lateWorkspaceResponses += 1;
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
      await expect.poll(() => page.evaluate(() => globalThis.__lateWorkspaceResponses)).toBe(1);
      await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveAttribute("data-requirement-id", "REQ-B-129");
      await expect(page.locator("#selected-context li")).toHaveText("State \u{1f9ed} e\u0301 keeps source identity.");
      await expect(page.getByRole("searchbox")).toBeEnabled();
      await expect(page.getByRole("alert")).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Expand Workspace root", exact: true})).toBeVisible();
      await expect(page.getByRole("button", {name: "Child contracts", exact: true})).toHaveCount(0);
    } finally { release(); }
  });
}
