import {expect} from "@playwright/test";
import {capacityTest, lookupTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

async function expectRows(page, ids) {
  await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveCount(ids.length);
  await expect.poll(() => page.locator("#workspace-content [data-requirement-id]").evaluateAll(rows => rows.map(row => row.dataset.requirementId))).toEqual(ids);
}

function ids(first, last) {
  return Array.from({length: last - first + 1}, (_, index) => `REQ-B-${String(first + index).padStart(3, "0")}`);
}

async function selectChild(page) {
  await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
  await page.getByRole("button", {name: "Child contracts", exact: true}).click();
}

capacityTest("maximum-node workspace keeps lazy navigation and full-cohort search bounded", async ({capacityURL, page}) => {
  await openWorkspace(page, capacityURL);
  await expectRows(page, ["REQ-A", ...ids(0, 62)]);
  await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li')).toHaveCount(64);
  await expect(page.locator("[data-navigation-node]")).toHaveCount(65);
  await page.getByRole("button", {name: "Next navigation page", exact: true}).click();
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li').first()).toHaveAttribute("data-navigation-node", "spec.sibling.063");
  await expect(page.locator("[data-navigation-node]")).toHaveCount(65);
  await page.getByRole("searchbox").fill("REQ-B-129");
  await page.getByRole("button", {name: "Search requirements", exact: true}).click();
  await expectRows(page, ["REQ-B-129"]);
  await expect(page.locator('[data-requirement-id="REQ-B-129"] [data-anchor-id]')).toHaveText("State \u{1f9ed} e\u0301 keeps source identity.");
});

test("native lookup searches the full cohort, intersects scope, and preserves original handoff anchors", async ({lookupURL, page}) => {
  const requests = [];
  page.on("request", request => {
    if (new URL(request.url()).pathname === "/api/v1/requirements") requests.push(request.postDataJSON());
  });
  await openWorkspace(page, lookupURL);
  await expectRows(page, ["REQ-A", ...ids(0, 62)]);
  await page.getByRole("button", {name: "Next specifications page", exact: true}).click();
  await expectRows(page, ids(63, 126));
  await page.getByRole("button", {name: "Next specifications page", exact: true}).click();
  await expectRows(page, [...ids(127, 129), "REQ-C"]);
  await page.getByRole("button", {name: "Previous specifications page", exact: true}).click();
  await expectRows(page, ids(63, 126));

  await selectChild(page);
  await page.getByLabel("Owner", {exact: true}).selectOption("owner.b");
  await page.getByLabel("Lifecycle", {exact: true}).selectOption("active");
  await expectRows(page, ids(2, 65));
  await page.getByRole("searchbox").fill(" STATE \u{1f9ed} e\u0301 ");
  await page.getByRole("button", {name: "Search requirements", exact: true}).click();
  await expectRows(page, ["REQ-B-129"]);
  expect(requests.at(-1).query).toEqual({nodeId: "spec.child", ownerId: "owner.b", lifecycleState: "active", searchText: " STATE \u{1f9ed} e\u0301 ", offset: 0, maxRecords: 64});
  await expect(page.locator(".page-summary")).toHaveText("Showing 1-1 of 1 specifications records.");
  await page.getByRole("button", {name: "Select invariant", exact: true}).click();
  await page.getByRole("textbox", {name: "Question", exact: true}).fill("Does the original source identity survive lookup?");
  await page.getByRole("button", {name: "Create handoff packet", exact: true}).click();
  await expect(page.locator("#handoff-status")).toHaveText("Handoff packet created.");
  const packet = JSON.parse(await page.locator("#handoff-packet").textContent());
  expect(packet.annotations[0]).toMatchObject({anchor: {anchorId: "requirement:REQ-B-129:invariant", requirementId: "REQ-B-129", jsonPointer: "/projections/requirementSources/1/requirements/129/invariant"}, exactQuote: "State \u{1f9ed} e\u0301 keeps source identity."});

  await page.getByRole("searchbox").fill("\u00e9");
  await page.getByRole("button", {name: "Search requirements", exact: true}).click();
  await expectRows(page, []);
  await expect(page.locator("#workspace-content [role=status]")).toHaveAttribute("data-state", "no-match");
  await expect(page.locator("#selected-context li")).toHaveCount(0);
  await expect(page.getByRole("textbox", {name: "Question", exact: true})).toHaveValue("Does the original source identity survive lookup?");
});

test("navigation pages retain parent scope and overview-only nodes select no requirements", async ({lookupURL, page}) => {
  await openWorkspace(page, lookupURL);
  await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li')).toHaveCount(64);
  await page.getByRole("button", {name: "Next navigation page", exact: true}).click();
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li').first()).toHaveAttribute("data-navigation-node", "spec.sibling.063");
  await page.getByRole("button", {name: "Next navigation page", exact: true}).click();
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li')).toHaveCount(3);
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li').first()).toHaveAttribute("data-navigation-node", "spec.sibling.127");
  await page.getByRole("button", {name: "Sibling 129", exact: true}).click();
  await expectRows(page, []);
  await expect(page.locator("#selected-scope")).toHaveText("Workspace root / Sibling 129");
  await page.getByRole("button", {name: "Previous navigation page", exact: true}).click();
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li').first()).toHaveAttribute("data-navigation-node", "spec.sibling.063");
  await expect(page.locator("#selected-scope")).toHaveText("Workspace root / Sibling 129");
});

for (const failure of [429, 500, 503, "network", "body"]) {
  test(`lookup Retry preserves every non-default operand after ${failure}`, async ({lookupURL, page}) => {
    const attempts = [];
    if (failure === "body") {
      await page.addInitScript(() => {
        const nativeFetch = globalThis.fetch.bind(globalThis);
        let failed = false;
        globalThis.fetch = async (input, init) => {
          const response = await nativeFetch(input, init);
          const query = typeof init?.body === "string" ? JSON.parse(init.body)?.query : null;
          if (!failed && query?.offset === 64 && query?.searchText === "Capability") {
            failed = true;
            await response.arrayBuffer();
            return new Response(new ReadableStream({
              start(controller) { controller.error(new TypeError("private body transport failure")); },
            }), {status: 200, headers: {"Content-Type": "application/json"}});
          }
          return response;
        };
      });
    }
    await page.route("**/api/v1/requirements", async route => {
      const request = route.request();
      const body = request.postDataJSON();
      if (body.query.offset !== 64 || body.query.searchText !== "Capability") return route.continue();
      attempts.push({method: request.method(), path: new URL(request.url()).pathname, body});
      if (attempts.length === 1) {
        if (failure === "network") return route.abort("failed");
        if (failure === "body") return route.continue();
        return route.fulfill({status: failure, body: "private failure detail"});
      }
      return route.continue();
    });
    await openWorkspace(page, lookupURL);
    await selectChild(page);
    await page.getByLabel("Owner", {exact: true}).selectOption("owner.b");
    await page.getByLabel("Lifecycle", {exact: true}).selectOption("active");
    await page.getByRole("searchbox").fill("Capability");
    await page.getByRole("button", {name: "Search requirements", exact: true}).click();
    await expectRows(page, ids(2, 65));
    await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
    await page.getByRole("textbox", {name: "Question", exact: true}).fill("Keep this draft.");
    await page.getByRole("button", {name: "Next specifications page", exact: true}).click();
    await expect(page.getByRole("button", {name: "Retry", exact: true})).toBeVisible();
    expect(attempts).toHaveLength(1);
    await expect(page.locator("#selected-context li")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("private failure detail");
    await expect(page.locator("body")).not.toContainText("private body transport failure");
    await page.getByRole("searchbox").fill("unsent different search");
    await page.getByRole("button", {name: "Retry", exact: true}).click();
    await expectRows(page, ids(66, 128));
    expect(attempts).toHaveLength(2);
    const expectedQuery = {searchText: "Capability", nodeId: "spec.child", ownerId: "owner.b", lifecycleState: "active", maxRecords: 64, offset: 64};
    for (const attempt of attempts) {
      expect(attempt.method).toBe("POST");
      expect(attempt.path).toBe("/api/v1/requirements");
      expect(attempt.body).toEqual({query: expectedQuery, requestId: expect.stringMatching(/^browser\.specifications\./), snapshotId: expect.stringMatching(/^sha256:[0-9a-f]{64}$/)});
    }
    expect(attempts[1].body.snapshotId).toBe(attempts[0].body.snapshotId);
    expect(attempts[1].body.requestId).not.toBe(attempts[0].body.requestId);
    await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
    await expect(page.getByRole("textbox", {name: "Question", exact: true})).toHaveValue("Keep this draft.");
  });
}

test("navigation Retry preserves its parent and page without invalidating content selection", async ({lookupURL, page}) => {
  const attempts = [];
  await page.route("**/api/v1/navigation", route => {
    const request = route.request();
    const body = request.postDataJSON();
    if (body.query.offset !== 64) return route.continue();
    attempts.push({method: request.method(), path: new URL(request.url()).pathname, body});
    return attempts.length === 1 ? route.fulfill({status: 503, body: "private navigation detail"}) : route.continue();
  });
  await openWorkspace(page, lookupURL);
  await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
  await page.getByRole("button", {name: "Expand Workspace root", exact: true}).click();
  await page.getByRole("button", {name: "Next navigation page", exact: true}).click();
  await expect(page.getByRole("button", {name: "Retry", exact: true})).toBeVisible();
  expect(attempts).toHaveLength(1);
  await expect(page.locator("#selected-context li")).toHaveText("Root scope remains independent.");
  await page.getByRole("button", {name: "Retry", exact: true}).click();
  await expect(page.locator('[data-navigation-branch="1"] > .navigation-nodes > li').first()).toHaveAttribute("data-navigation-node", "spec.sibling.063");
  expect(attempts).toHaveLength(2);
  for (const attempt of attempts) {
    expect(attempt.method).toBe("POST");
    expect(attempt.path).toBe("/api/v1/navigation");
    expect(attempt.body).toEqual({query: {parentNodeId: "spec.root", offset: 64, maxRecords: 64}, requestId: expect.stringMatching(/^browser\.navigation\./), snapshotId: expect.stringMatching(/^sha256:[0-9a-f]{64}$/)});
  }
  expect(attempts[1].body.snapshotId).toBe(attempts[0].body.snapshotId);
  expect(attempts[1].body.requestId).not.toBe(attempts[0].body.requestId);
  await expect(page.locator("#selected-context li")).toHaveText("Root scope remains independent.");
});

test("variable-size admitted pages return to exact visited offsets", async ({lookupURL, page}) => {
  const offsets = [];
  await page.route("**/api/v1/requirements", async route => {
    const body = route.request().postDataJSON();
    offsets.push(body.query.offset);
    const response = await route.fetch({postData: {...body, query: {...body.query, maxRecords: body.query.offset === 0 ? 2 : 1}}});
    return route.fulfill({response});
  });
  await openWorkspace(page, lookupURL);
  const rows = page.locator("#workspace-content [data-requirement-id]");
  await expect(rows).toHaveCount(2);
  expect(await rows.evaluateAll(elements => elements.map(element => element.dataset.requirementId))).toEqual(["REQ-A", "REQ-B-000"]);
  for (const id of ["REQ-B-001", "REQ-B-002"]) {
    await page.getByRole("button", {name: "Next specifications page", exact: true}).click();
    await expect(rows).toHaveAttribute("data-requirement-id", id);
  }
  await page.getByRole("button", {name: "Previous specifications page", exact: true}).click();
  await expect(rows).toHaveAttribute("data-requirement-id", "REQ-B-001");
  await page.getByRole("button", {name: "Previous specifications page", exact: true}).click();
  await expect(rows).toHaveCount(2);
  expect(await rows.evaluateAll(elements => elements.map(element => element.dataset.requirementId))).toEqual(["REQ-A", "REQ-B-000"]);
  expect(offsets).toEqual([0, 2, 3, 2, 0]);
});

test("deep navigation retains the selected path within 256 rows and preserves disclosure focus", async ({lookupURL, page}) => {
  await openWorkspace(page, lookupURL);
  for (const label of ["Workspace root", "Child contracts", "Nested contracts", "Depth 1", "Depth 2", "Depth 3", "Depth 4", "Depth 5"]) {
    const disclosure = page.getByRole("button", {name: `Expand ${label}`, exact: true});
    await disclosure.focus();
    await disclosure.press("Enter");
    await expect(page.getByRole("button", {name: `Collapse ${label}`, exact: true})).toBeFocused();
    await expect.poll(() => page.locator("#spec-navigation [data-navigation-node]").count()).toBeLessThanOrEqual(256);
  }
  const deepestSelection = page.getByRole("button", {name: "Depth 6", exact: true});
  await deepestSelection.focus();
  await deepestSelection.press("Enter");
  await expect(page.locator("#selected-scope")).toHaveText("Workspace root / Child contracts / Nested contracts / Depth 1 / Depth 2 / Depth 3 / Depth 4 / Depth 5 / Depth 6");
  await expect(page.getByRole("button", {name: "Depth 6", exact: true})).toBeFocused();
  await page.locator('[data-navigation-branch="1"] > .navigation-paging').getByRole("button", {name: "Show sibling page", exact: true}).click();
  await expect(page.getByRole("button", {name: "Sibling 062", exact: true})).toBeVisible();
  await expect(page.locator("#selected-scope")).toContainText("Depth 6");
  expect(await page.locator("#spec-navigation [data-navigation-node]").count()).toBeLessThanOrEqual(256);
});
