import {expect} from "@playwright/test";
import {lookupTest as test} from "./workspace-test-harness.mjs";
import {admittedWorkspaceURL, navigateWorkspace, openWorkspace} from "./workspace-navigation-harness.mjs";

const states = [
  {status: 400, message: "The query could not be accepted. Check its fields and submit again.", kind: "correction", action: null},
  {status: 403, message: "Access to this workspace was denied.", kind: "denied", action: null},
  {status: 409, message: "The workspace snapshot has changed.", kind: "stale", action: "Reload workspace"},
  {status: 404, message: "The admitted workspace is unavailable.", kind: "unavailable", action: null},
];

for (const operation of ["requirements", "navigation"]) {
  for (const failure of states) {
    test(`${operation} ${failure.status} has its exact recovery authority`, async ({lookupURL, page}) => {
      let fail = false;
      const attempts = [];
      const protectedCalls = [];
      page.on("request", request => { if (new URL(request.url()).pathname.startsWith("/api/")) protectedCalls.push(request.url()); });
      await page.route(`**/api/v1/${operation}`, route => {
        if (!fail) return route.continue();
        attempts.push(route.request().postDataJSON());
        return route.fulfill({status: failure.status, body: "private recovery detail"});
      });
      await openWorkspace(page, lookupURL);
      await expect(page.locator("#workspace-content [data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-A");
      await expect(page.getByRole("button", {name: "Expand Workspace root", exact: true})).toBeVisible();
      await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
      await page.getByRole("textbox", {name: "Question", exact: true}).fill("Keep the draft after failure.");
      fail = true;
      if (operation === "requirements") {
        await page.getByRole("searchbox").fill("Root");
        await page.getByRole("button", {name: "Search requirements", exact: true}).click();
      } else {
        await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
      }
      const container = page.locator(operation === "requirements" ? "#workspace-content" : "#spec-navigation");
      await expect(container.getByRole("alert")).toHaveText(failure.message);
      await expect(container.getByRole("alert")).toHaveAttribute("data-state", failure.kind);
      await expect(page.locator("body")).not.toContainText("private recovery detail");
      await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Reload workspace", exact: true})).toHaveCount(failure.action ? 1 : 0);
      expect(attempts).toHaveLength(1);
      await expect(page.locator("#selected-context li")).toHaveCount(operation === "requirements" ? 0 : 1);
      await expect(page.getByRole("textbox", {name: "Question", exact: true})).toHaveValue("Keep the draft after failure.");

      if (failure.status === 403 || failure.status === 409) {
        const count = protectedCalls.length;
        const controls = page.locator("[data-protected-request]");
        expect(await controls.count()).toBeGreaterThan(8);
        expect(await controls.evaluateAll(elements => elements.every(element => element.disabled))).toBe(true);
        await controls.evaluateAll(elements => { for (const element of elements) element.click(); });
        await page.getByRole("textbox", {name: "Question", exact: true}).fill("Local draft remains editable.");
        expect(protectedCalls).toHaveLength(count);
      }
      if (failure.status === 400) {
        fail = false;
        const recovery = page.waitForRequest(request => new URL(request.url()).pathname === `/api/v1/${operation}`);
        if (operation === "requirements") {
          await page.getByRole("searchbox").fill("REQ-B-129");
          await page.getByRole("button", {name: "Search requirements", exact: true}).click();
          await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveAttribute("data-requirement-id", "REQ-B-129");
        } else {
          await page.getByRole("button", {name: "Collapse Workspace root", exact: true}).click();
          await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
          await expect(page.getByRole("button", {name: "Child contracts", exact: true})).toBeVisible();
        }
        expect((await recovery).postDataJSON().requestId).not.toBe(attempts[0].requestId);
      }
      if (failure.status === 409) {
        fail = false;
        let navigations = 0;
        page.on("request", request => { if (request.isNavigationRequest() && request.frame() === page.mainFrame()) navigations += 1; });
        await navigateWorkspace(page, admittedWorkspaceURL(lookupURL), async token => {
          await page.getByRole("button", {name: "Reload workspace", exact: true}).evaluate(button => button.click());
          return token;
        }, "Explicit workspace reload failed");
        await expect(page.locator("#workspace-content [data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-A");
        expect(navigations).toBe(1);
      }
      if (failure.status === 404) {
        await expect(container.locator('[data-state="no-match"]')).toHaveCount(0);
        await expect(page.getByRole("searchbox")).toBeEnabled();
      }
    });
  }
}

test("manifest Retry preserves GET and does not invent query or snapshot input", async ({lookupURL, page}) => {
  const attempts = [];
  await page.route("**/api/v1/manifest", route => {
    const request = route.request();
    attempts.push({method: request.method(), path: new URL(request.url()).pathname, body: request.postData()});
    return attempts.length === 1 ? route.fulfill({status: 503, body: "private bootstrap detail"}) : route.continue();
  });
  await openWorkspace(page, lookupURL);
  await expect(page.getByRole("button", {name: "Retry", exact: true})).toBeVisible();
  expect(attempts).toEqual([{method: "GET", path: "/api/v1/manifest", body: null}]);
  await page.getByRole("button", {name: "Retry", exact: true}).click();
  await expect(page.locator("#workspace-content [data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-A");
  expect(attempts).toEqual(Array(2).fill({method: "GET", path: "/api/v1/manifest", body: null}));
  await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
});

for (const optional of [{route: "diff", button: "Diff"}, {route: "graph", button: "Traceability"}]) {
  test(`${optional.route} 404 is unavailable rather than a successful empty result`, async ({baseURL, page}) => {
    let count = 0;
    await page.route(`**/api/v1/${optional.route}`, route => {
      count += 1;
      return route.fulfill({status: 404, body: "private optional detail"});
    });
    await openWorkspace(page, baseURL);
    await page.getByRole("button", {name: optional.button, exact: true}).click();
    await expect(page.locator("#workspace-content [role=alert]")).toHaveText("This workspace view is unavailable.");
    await expect(page.locator("#workspace-content [role=alert]")).toHaveAttribute("data-state", "optional-unavailable");
    expect(count).toBe(1);
    await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
    await expect(page.getByRole("button", {name: "Specifications", exact: true})).toBeEnabled();
  });
}

test("an explicit new lookup invalidates a detached Retry action", async ({lookupURL, page}) => {
  const searches = [];
  await page.route("**/api/v1/requirements", route => {
    const body = route.request().postDataJSON();
    searches.push(body.query.searchText ?? "");
    return body.query.searchText === "old request" ? route.fulfill({status: 503, body: "{}"}) : route.continue();
  });
  await openWorkspace(page, lookupURL);
  await page.getByRole("searchbox").fill("old request");
  await page.getByRole("button", {name: "Search requirements", exact: true}).click();
  const retry = page.getByRole("button", {name: "Retry", exact: true});
  await expect(retry).toBeVisible();
  const staleAction = await retry.elementHandle();
  await page.getByRole("searchbox").fill("REQ-B-129");
  await page.getByRole("button", {name: "Search requirements", exact: true}).click();
  await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveAttribute("data-requirement-id", "REQ-B-129");
  await staleAction.evaluate(button => button.click());
  await expect(page.locator("body")).toHaveAttribute("data-state", "specifications");
  expect(searches).toEqual(["", "old request", "REQ-B-129"]);
});
