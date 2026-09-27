import {expect} from "@playwright/test";
import {lookupTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

for (const late of [{route: "navigation", status: 403}, {route: "navigation", status: 200}, {route: "requirements", status: 403}]) {
  test(`superseded non-cooperative ${late.route} ${late.status} cannot change current content or request authority`, async ({lookupURL, page}) => {
    await observeNonCooperativeResponse(page, `/api/v1/${late.route}`);
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

for (const status of [200, 409]) {
  test(`retained navigation ignores non-cooperative ${status} after an independent authority lock`, async ({lookupURL, page}) => {
    await observeNonCooperativeResponse(page, "/api/v1/navigation");
    const headers = Promise.withResolvers();
    const started = Promise.withResolvers();
    await page.route("**/api/v1/navigation", async route => {
      const body = route.request().postDataJSON();
      if (body.query.parentNodeId !== "spec.root") return route.continue();
      const response = await route.fetch(status === 200 ? {} : {
        postData: {...body, snapshotId: `sha256:${"0".repeat(64)}`},
      });
      expect(response.status()).toBe(status);
      if (status === 200) {
        expect((await response.json()).projection.nodes.map(node => node.nodeId)).toContain("spec.child");
      }
      started.resolve();
      await headers.promise;
      return route.fulfill({response});
    });
    let lockingRequests = 0;
    await page.route("**/api/v1/requirements", async route => {
      if (route.request().postDataJSON().query.searchText !== "REQ-B-129") return route.continue();
      lockingRequests += 1;
      const requestHeaders = await route.request().allHeaders();
      delete requestHeaders["x-proofkit-browser-capability"];
      const response = await route.fetch({headers: requestHeaders});
      expect(response.status()).toBe(403);
      return route.fulfill({response});
    });
    let retainedBranch;
    try {
      await openWorkspace(page, lookupURL);
      await expect(page.locator("#workspace-content [data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-A");
      const authority = await page.locator("#workspace-authority").textContent();
      await page.getByRole("textbox", {name: "Question", exact: true}).fill("Keep the draft after cancellation.");
      await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
      await started.promise;
      retainedBranch = await page.locator("#navigation-branch-1").elementHandle();
      expect(retainedBranch).not.toBeNull();
      expect(await page.evaluate(() => globalThis.__lateWorkspaceResponses.signal.aborted)).toBe(false);
      if (status === 200) {
        headers.resolve();
        await expect.poll(() => page.evaluate(() => globalThis.__lateWorkspaceResponses.bodyStarted)).toBe(1);
      }
      expect(await page.evaluate(() => ({
        bodyConsumed: globalThis.__lateWorkspaceResponses.bodyConsumed,
        completed: globalThis.__lateWorkspaceResponses.completed,
      }))).toEqual({bodyConsumed: 0, completed: 0});

      // A current view fails while the pending navigation branch is retained:
      // applyFailureLock -> navigation.cancel aborts, but never discards it.
      await page.getByRole("searchbox").fill("REQ-B-129");
      await page.getByRole("button", {name: "Search requirements", exact: true}).click();
      const denied = page.locator("#workspace-content [role=alert]");
      await expect(denied).toHaveText("Access to this workspace was denied.");
      await expect(denied).toHaveAttribute("data-state", "denied");
      expect(lockingRequests).toBe(1);
      expect(await page.evaluate(() => globalThis.__lateWorkspaceResponses.signal.aborted)).toBe(true);
      expect(await retainedBranch.evaluate(branch => branch === document.querySelector("#navigation-branch-1"))).toBe(true);
      const protectedCalls = await page.evaluate(() => globalThis.__lateWorkspaceResponses.protectedCalls);

      headers.resolve();
      await page.evaluate(() => globalThis.__lateWorkspaceResponses.releaseBody());
      await expect.poll(() => page.evaluate(() => globalThis.__lateWorkspaceResponses.completed)).toBe(1);
      expect(await page.evaluate(() => ({
        bodyStarted: globalThis.__lateWorkspaceResponses.bodyStarted,
        bodyConsumed: globalThis.__lateWorkspaceResponses.bodyConsumed,
        aborted: globalThis.__lateWorkspaceResponses.signal.aborted,
      }))).toEqual({bodyStarted: status === 200 ? 1 : 0, bodyConsumed: status === 200 ? 1 : 0, aborted: true});
      await expect(page.getByRole("button", {name: "Child contracts", exact: true})).toHaveCount(0);
      await expect(page.locator("#spec-navigation [role=alert]")).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Reload workspace", exact: true})).toHaveCount(0);
      expect(await retainedBranch.evaluate(branch => branch === document.querySelector("#navigation-branch-1"))).toBe(true);
      await expect(page.locator("#navigation-branch-1 [role=status]")).toHaveText("Loading navigation...");
      await expect(page.getByRole("button", {name: "Collapse Workspace root", exact: true})).toBeDisabled();
      await expect(page.getByRole("alert")).toHaveText("Access to this workspace was denied.");
      await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveCount(0);
      await expect(page.locator("body")).toHaveAttribute("data-state", "view-failed");
      expect(await page.locator("#workspace-authority").textContent()).toBe(authority);
      const controls = page.locator("[data-protected-request]");
      expect(await controls.count()).toBeGreaterThan(8);
      expect(await controls.evaluateAll(elements => elements.every(element => element.disabled))).toBe(true);
      await controls.evaluateAll(elements => { for (const element of elements) element.click(); });
      await page.locator("#workspace-search").dispatchEvent("submit");
      expect(await page.evaluate(() => globalThis.__lateWorkspaceResponses.protectedCalls)).toBe(protectedCalls);
      await expect(page.getByRole("textbox", {name: "Question", exact: true})).toHaveValue("Keep the draft after cancellation.");
    } finally {
      headers.resolve();
      if (!page.isClosed()) await page.evaluate(() => globalThis.__lateWorkspaceResponses?.releaseBody());
      await retainedBranch?.dispose();
    }
  });
}

async function observeNonCooperativeResponse(page, path) {
  await page.addInitScript(({path}) => {
    const nativeFetch = globalThis.fetch.bind(globalThis);
    const probe = globalThis.__lateWorkspaceResponses = {bodyStarted: 0, bodyConsumed: 0, completed: 0, protectedCalls: 0, releaseBody: undefined, signal: undefined};
    const bodyReleased = new Promise(resolve => { probe.releaseBody = resolve; });
    // These owners finish policy work synchronously in the response Promise reactions:
    // workspace-requests.js -> workspace.js post/renderSpecifications or navigation load.
    // A next-task marker follows that entire chain, not just headers or a body chunk.
    const afterResponseReactions = () => setTimeout(() => { probe.completed += 1; }, 0);
    globalThis.fetch = async (input, init = {}) => {
      const url = new URL(typeof input === "string" ? input : input.url, location.href);
      if (url.pathname.startsWith("/api/")) probe.protectedCalls += 1;
      if (url.pathname !== path) return nativeFetch(input, init);
      const query = typeof init.body === "string" ? JSON.parse(init.body).query : null;
      const delayed = query?.searchText === "Root" || query?.parentNodeId === "spec.root";
      if (!delayed) return nativeFetch(input, init);
      probe.signal = init.signal;
      const response = await nativeFetch(input, {...init, signal: undefined});
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
      return response;
    };
  }, {path});
}
