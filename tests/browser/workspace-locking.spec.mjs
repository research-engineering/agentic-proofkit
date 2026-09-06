import {expect} from "@playwright/test";
import {lookupTest, pagingTest, test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

for (const status of [403, 409]) {
  lookupTest(`requirements content commit preserves navigation ${status} lock`, async ({lookupURL, page}) => {
    await assertLockedContentCommit(page, lookupURL, "requirements", status);
  });
  for (const view of ["diff", "graph"]) {
    pagingTest(`${view} content commit preserves navigation ${status} lock`, async ({pagingURL, page}) => {
      await assertLockedContentCommit(page, pagingURL, view, status);
    });
  }
}

for (const outcome of [200, 400]) {
  test(`pending handoff survives content refresh and releases after ${outcome}`, async ({baseURL, page}) => {
    const handoff = await holdFirstHandoff(page, outcome);
    try {
      await startPendingHandoff(page, baseURL, handoff.started);
      await page.getByRole("button", {name: "Specifications", exact: true}).click();
      await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
      await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
      const question = page.getByRole("textbox", {name: "Question", exact: true});
      await question.fill("Second intentional question.");
      const submit = page.getByRole("button", {name: "Create handoff packet", exact: true});
      await expect(submit).toBeDisabled();
      await submit.dispatchEvent("click");
      expect(await handoff.count()).toBe(1);

      handoff.release();
      const packet = page.locator("#handoff-packet");
      if (outcome === 200) {
        await expect(page.locator("#handoff-status")).toHaveText("Handoff packet created.");
        expect(JSON.parse(await packet.textContent()).annotations.map(item => item.question)).toEqual(["First pending question."]);
      } else {
        await expect(page.locator("#handoff-status")).toHaveText("The handoff packet could not be created.");
        await expect(packet).toBeEmpty();
      }
      await expect(question).toHaveValue("Second intentional question.");
      await expect(submit).toBeEnabled();
      await submit.click();
      await expect(packet).toContainText("Second intentional question.");
      expect(JSON.parse(await packet.textContent()).annotations.map(item => item.question)).toEqual(["Second intentional question."]);
      expect(await handoff.count()).toBe(2);
    } finally { handoff.release(); }
  });
}

for (const status of [403, 409]) {
  for (const first of ["handoff", "lock"]) {
    test(`pending handoff preserves ${status} authority when ${first} finishes first`, async ({baseURL, page}) => {
      const handoff = await holdFirstHandoff(page, 200);
      const lock = Promise.withResolvers();
      const lockStarted = Promise.withResolvers();
      try {
        await startPendingHandoff(page, baseURL, handoff.started);
        await page.route("**/api/v1/requirements", async route => {
          lockStarted.resolve();
          await lock.promise;
          return route.fulfill({status, body: "private refresh detail"});
        });
        await page.getByRole("button", {name: "Specifications", exact: true}).click();
        await lockStarted.promise;
        const expectLock = async () => {
          const message = status === 403 ? "Access to this workspace was denied." : "The workspace snapshot has changed.";
          await expect(page.locator("#workspace-content [role=alert]")).toHaveText(message);
        };
        const expectHandoff = () => expect(page.locator("#handoff-status")).toHaveText("Handoff packet created.");
        if (first === "handoff") {
          handoff.release();
          await expectHandoff();
          lock.resolve();
          await expectLock();
        } else {
          lock.resolve();
          await expectLock();
          handoff.release();
          await expectHandoff();
        }
        const submit = page.getByRole("button", {name: "Create handoff packet", exact: true});
        await expect(submit).toBeDisabled();
        await submit.dispatchEvent("click");
        expect(await handoff.count()).toBe(1);
        await expect(page.getByRole("textbox", {name: "Question", exact: true})).toHaveValue("First pending question.");
        await expect(page.getByRole("button", {name: "Reload workspace", exact: true})).toHaveCount(status === 409 ? 1 : 0);
        await expect(page.locator("body")).not.toContainText("private refresh detail");
      } finally {
        lock.resolve();
        handoff.release();
      }
    });
  }
}

async function holdFirstHandoff(page, outcome) {
  const barrier = Promise.withResolvers();
  const started = Promise.withResolvers();
  await page.addInitScript(() => {
    const nativeFetch = globalThis.fetch.bind(globalThis);
    globalThis.__handoffFetchCount = 0;
    globalThis.fetch = (input, init) => {
      const url = new URL(typeof input === "string" ? input : input.url, location.href);
      if (url.pathname === "/api/v1/handoff") globalThis.__handoffFetchCount += 1;
      return nativeFetch(input, init);
    };
  });
  let count = 0;
  await page.route("**/api/v1/handoff", async route => {
    count += 1;
    if (count !== 1) return route.continue();
    const response = outcome === 200 ? await route.fetch() :
      await route.fetch({postData: {...route.request().postDataJSON(), annotations: []}});
    expect(response.status()).toBe(outcome);
    started.resolve();
    await barrier.promise;
    return route.fulfill({response});
  });
  return {release: barrier.resolve, started: started.promise, count: () => page.evaluate(() => globalThis.__handoffFetchCount)};
}

async function startPendingHandoff(page, url, started) {
  await page.setViewportSize({width: 1920, height: 1080});
  await openWorkspace(page, url);
  const select = page.getByRole("button", {name: "Select invariant", exact: true}).first();
  await expect(select).toBeVisible();
  await select.click();
  await page.getByRole("textbox", {name: "Question", exact: true}).fill("First pending question.");
  const submit = page.getByRole("button", {name: "Create handoff packet", exact: true});
  await submit.click();
  await started;
  await expect(submit).toBeDisabled();
}

async function assertLockedContentCommit(page, url, view, status) {
  let releaseNavigation;
  const navigationBarrier = new Promise(resolve => { releaseNavigation = resolve; });
  let releaseContent;
  const contentBarrier = new Promise(resolve => { releaseContent = resolve; });
  let contentStarted;
  const started = new Promise(resolve => { contentStarted = resolve; });
  await page.addInitScript(() => {
    const nativeFetch = globalThis.fetch.bind(globalThis);
    globalThis.__protectedFetchCount = 0;
    globalThis.fetch = (input, init) => {
      const url = new URL(typeof input === "string" ? input : input.url, location.href);
      if (url.pathname.startsWith("/api/")) globalThis.__protectedFetchCount += 1;
      return nativeFetch(input, init);
    };
  });
  await page.route("**/api/v1/navigation", async route => {
    await navigationBarrier;
    return route.fulfill({status, body: "private navigation detail"});
  });
  await page.route(`**/api/v1/${view}`, async route => {
    const body = route.request().postDataJSON();
    const query = view === "requirements" ? body.query : {
      ...body.query, maxRecords: 1, ...view === "graph" ? {maxEdges: 1} : {},
    };
    const response = await route.fetch({postData: {...body, query}});
    const delayed = view === "requirements" ? query.offset === 64 :
      query.offset === 1 && (view !== "graph" || query.edgeOffset === 1);
    if (delayed) {
      contentStarted();
      await contentBarrier;
    }
    return route.fulfill({response});
  });
  try {
    await openWorkspace(page, url);
    await expect(page.locator("#workspace-content [data-requirement-id]").first()).toBeVisible();
    await page.getByRole("textbox", {name: "Question", exact: true}).fill("Keep this local question.");
    if (view !== "requirements") {
      await page.getByRole("button", {name: view === "diff" ? "Diff" : "Traceability", exact: true}).click();
    }
    await page.getByRole("button", {name: `Next ${view === "requirements" ? "specifications" : view} page`, exact: true}).click();
    if (view === "graph") await page.getByRole("button", {name: "Next graph relation page", exact: true}).click();
    await started;
    releaseNavigation();
    const message = status === 403 ? "Access to this workspace was denied." : "The workspace snapshot has changed.";
    await expect(page.locator("#spec-navigation [role=alert]")).toHaveText(message);
    releaseContent();
    await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
    await expect(page.getByRole("button", {name: `Previous ${view === "requirements" ? "specifications" : view} page`, exact: true})).toBeVisible();
    if (view === "requirements") {
      await expect(page.locator("#workspace-content [data-requirement-id]")).toHaveCount(64);
      await expect(page.locator("#workspace-content [data-requirement-id]").first()).toHaveAttribute("data-requirement-id", "REQ-B-063");
    } else if (view === "diff") {
      await expect(page.locator("#workspace-content article > p").first()).toHaveText("/requirements/REQ-CONSUMER-001/riskClass");
    } else {
      await expect(page.getByRole("button", {name: "Previous graph relation page", exact: true})).toBeVisible();
      await expect(page.locator('table[data-identity-kind="edge"] tbody tr')).toHaveCount(1);
    }
    const controls = page.locator("[data-protected-request]");
    expect(await controls.evaluateAll(elements => elements.filter(element => !element.disabled).map(element => element.textContent))).toEqual([]);
    const before = await page.evaluate(() => globalThis.__protectedFetchCount);
    await controls.evaluateAll(elements => { for (const element of elements) element.click(); });
    expect(await page.evaluate(() => globalThis.__protectedFetchCount)).toBe(before);
    await expect(page.getByRole("textbox", {name: "Question", exact: true})).toHaveValue("Keep this local question.");
    await page.getByRole("textbox", {name: "Question", exact: true}).fill("Local draft still editable.");
    await expect(page.getByRole("button", {name: "Reload workspace", exact: true})).toHaveCount(status === 409 ? 1 : 0);
    await expect(page.locator("body")).not.toContainText("private navigation detail");
  } finally {
    releaseNavigation();
    releaseContent();
  }
}
