import AxeBuilder from "@axe-core/playwright";
import {expect, test} from "@playwright/test";

test.beforeEach(async ({browser, browserName, channel, connectOptions, launchOptions}, testInfo) => {
  testInfo.annotations.push({type: "proofkit.browser-engine", description: browserName});
  testInfo.annotations.push({type: "proofkit.browser-version", description: browser.version()});
  expect(browserName).toBe(testInfo.project.name);
  expect(channel).toBeUndefined();
  expect(connectOptions).toBeUndefined();
  expect(launchOptions.channel).toBeUndefined();
  expect(launchOptions.executablePath).toBeUndefined();
});

test("workspace renders admitted views and creates a keyboard-authorized handoff", async ({page}) => {
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });

  await page.goto("/");
  await expect(page.getByRole("heading", {name: "browser.fixture.workspace"})).toBeVisible();
  await expect(page.locator('meta[name="proofkit-browser-capability"]')).toHaveCount(0);
  const workspaceAuthority = page.getByLabel("Authority boundary");
  await expect(workspaceAuthority).toContainText("presentation_adapter");
  await expect(workspaceAuthority).toContainText("Baseline: unverified");
  await expect(workspaceAuthority).toContainText("do not prove receipt freshness");

  const requirementBoundary = page.getByLabel("Boundary for REQ-CONSUMER-001");
  await expect(requirementBoundary).toContainText("Owner: browser.fixture.owner");
  await expect(requirementBoundary).toContainText("Claim level: blocking");
  await expect(requirementBoundary).toContainText("Fixture requirements do not approve merge");
  await expect(requirementBoundary).toContainText("This requirement does not approve merge");

  const selectInvariant = page.getByRole("button", {name: "Select invariant"});
  await selectInvariant.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("1 source-bound target");
  await page.getByRole("textbox", {name: "Question"}).fill("Does retry preserve the same contract?");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Handoff packet created");
  await expect(page.getByLabel("Handoff packet")).toContainText('"state": "submitted"');
  await expect(page.getByLabel("Handoff packet")).toContainText("retry \u{1F680}");

  await page.getByRole("button", {name: "Diff"}).click();
  await expect(page.getByRole("heading", {name: /scalar_changed/})).toBeVisible();
  await expect(page.getByText(/Source digests: sha256:/)).toBeVisible();
  const diffBoundary = page.locator(".projection-boundary");
  await expect(diffBoundary).toContainText("lookup_fragment_only");
  await expect(diffBoundary).toContainText(/Base snapshot: sha256:.*\(unverified\)/);
  await expect(diffBoundary).toContainText(/Current snapshot: sha256:.*\(unverified\)/);
  await expect(diffBoundary).toContainText("does not own requirement meaning");

  await page.getByRole("button", {name: "Traceability"}).click();
  const graph = page.getByRole("img", {name: /traceability nodes and edges/});
  await expect(graph).toBeVisible();
  const nodeIDs = (await graph.getAttribute("data-node-ids")).split(" ").filter(Boolean);
  const edgeIDs = (await graph.getAttribute("data-edge-ids")).split(" ").filter(Boolean);
  const tableNodeIDs = await page.locator('table[data-identity-kind="node"] tbody tr').evaluateAll((rows) => rows.map((row) => row.dataset.identity));
  const tableEdgeIDs = await page.locator('table[data-identity-kind="edge"] tbody tr').evaluateAll((rows) => rows.map((row) => row.dataset.identity));
  expect(tableNodeIDs).toEqual(nodeIDs);
  expect(tableEdgeIDs).toEqual(edgeIDs);
  const repositoryRow = page.locator('table[data-identity-kind="node"] tbody tr[data-identity="code:code.repository"]');
  await expect(repositoryRow).toContainText("stale");
  const rangeRow = page.locator('table[data-identity-kind="node"] tbody tr[data-identity="code:code.retry"]');
  await expect(rangeRow).toContainText("source_range");
  await expect(rangeRow).toContainText("verified");
  const candidateRow = page.locator('table[data-identity-kind="node"] tbody tr').filter({hasText: "browser.fixture.candidate-runner"});
  await expect(candidateRow).toContainText("caller_reported");
  await expect(candidateRow).toContainText("unverified");
  await expect(candidateRow).toContainText("failed");
  const executionRow = page.locator('table[data-identity-kind="node"] tbody tr').filter({hasText: "browser.fixture.runner"});
  await expect(executionRow).toContainText("receipt_admitted");
  await expect(executionRow).toContainText("current");
  await expect(executionRow).toContainText("passed");
  const traceEdgeRow = page.locator('table[data-identity-kind="edge"] tbody tr').filter({hasText: "browser.fixture.trace"});
  await expect(traceEdgeRow).toContainText("owner_admitted");
  await expect(traceEdgeRow).toContainText("current");
  await expect(page.locator(".projection-boundary")).toContainText("does not infer code topology");
  await expect(graph.locator("title").filter({hasText: /deliberately long traceability label/})).toHaveCount(1);
  const graphBox = await graph.boundingBox();
  expect(graphBox?.width).toBeGreaterThan(100);
  expect(graphBox?.height).toBeGreaterThan(100);
  expect(consoleErrors).toEqual([]);
  const firstEdge = graph.locator("line").first();
  await expect(firstEdge).toHaveCount(1);
  expect(await firstEdge.evaluate((line) => getComputedStyle(line).stroke)).not.toBe("none");
  expect((await graph.screenshot({animations: "allow", caret: "initial"})).byteLength).toBeGreaterThan(1000);
  const accessibility = await new AxeBuilder({page}).analyze();
  expect(accessibility.violations).toEqual([]);
});

test("collapsed text selection cannot retain hidden handoff authority", async ({page}) => {
  await page.goto("/");
  const invariant = page.locator("[data-anchor-id]").first();
  const selectionButton = page.locator("[data-select-anchor]").first();
  await expect(invariant).toBeVisible();
  await selectionButton.click();
  await expect(selectionButton).toHaveAttribute("aria-pressed", "true");
  await setSelection(page, invariant, 0, 0);
  await expect(selectionButton).toHaveAttribute("aria-pressed", "true");
  await setSelection(page, invariant, 0, 3);
  await expect(page.getByRole("status")).toContainText("1 source-bound target");
  await expect(selectionButton).toHaveAttribute("aria-pressed", "false");
  await page.evaluate(() => window.getSelection()?.collapseToStart());
  await expect(page.getByRole("status")).toContainText("No source-bound text selected");
  await expect(selectionButton).toHaveAttribute("aria-pressed", "false");
  await page.getByRole("textbox", {name: "Question"}).fill("Can a hidden selection be submitted?");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Select invariant text");
  await expect(page.getByLabel("Handoff packet")).toBeEmpty();
});

test("text selection projects Unicode code-point coordinates", async ({page}) => {
  await page.goto("/");
  const invariant = page.locator("[data-anchor-id]").filter({hasText: "retry \u{1F680}"}).first();
  await expect(invariant).toBeVisible();
  const offsets = await invariant.evaluate((element) => {
    const text = element.firstChild?.textContent ?? "";
    const domStart = text.indexOf("\u{1F680}");
    if (domStart < 0) throw new Error("Unicode fixture is unavailable");
    return {
      codePointStart: Array.from(text.slice(0, domStart)).length,
      domEnd: domStart + "\u{1F680}".length,
      domStart,
    };
  });
  await setSelection(page, invariant, offsets.domStart, offsets.domEnd);
  await expect(page.getByRole("status")).toContainText("1 source-bound target");
  await expect(page.getByLabel("Selected source text").getByRole("listitem")).toHaveText("\u{1F680}");
  await page.getByRole("textbox", {name: "Question"}).fill("Does the Unicode coordinate remain source-bound?");
  await expect(page.getByLabel("Selected source text").getByRole("listitem")).toHaveText("\u{1F680}");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Handoff packet created");

  const packet = JSON.parse(await page.getByLabel("Handoff packet").textContent());
  const annotation = packet.annotations[0];
  expect(annotation.exactQuote).toBe("\u{1F680}");
  expect(annotation.startCodePoint).toBe(offsets.codePointStart);
  expect(annotation.endCodePoint).toBe(offsets.codePointStart + 1);
  await page.getByRole("button", {name: "Clear selection"}).click();
  await expect(page.getByLabel("Selected source text").getByRole("listitem")).toHaveCount(0);
  await expect(page.getByRole("status")).toContainText("No source-bound text selected");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Select invariant text");
});

/** @param {import("@playwright/test").Page} page @param {import("@playwright/test").Locator} locator @param {number} start @param {number} end */
async function setSelection(page, locator, start, end) {
  const anchorID = await locator.getAttribute("data-anchor-id");
  if (!anchorID) throw new Error("Invariant anchor identity is unavailable");
  await page.waitForFunction((expectedID) => [...document.querySelectorAll("[data-anchor-id]")].some((element) => element.getAttribute("data-anchor-id") === expectedID), anchorID);
  await page.evaluate((bounds) => {
    const element = [...document.querySelectorAll("[data-anchor-id]")].find((candidate) => candidate.getAttribute("data-anchor-id") === bounds.anchorID);
    if (!element) throw new Error("Invariant anchor is unavailable");
    const text = element.firstChild;
    const selection = window.getSelection();
    if (!text || !selection) throw new Error("Text selection is unavailable");
    const limit = text.textContent?.length ?? 0;
    const range = document.createRange();
    range.setStart(text, Math.min(bounds.start, limit));
    range.setEnd(text, Math.min(bounds.end, limit));
    selection.removeAllRanges();
    selection.addRange(range);
    document.dispatchEvent(new Event("selectionchange"));
  }, {anchorID, end, start});
}

test("a view transition cooperatively aborts the superseded request", async ({page}) => {
  await disableOptionalViews(page);
  await page.addInitScript(() => {
    const nativeFetch = globalThis.fetch.bind(globalThis);
    globalThis.__proofkitAbortProbe = {aborted: false, started: false};
    globalThis.fetch = (input, init = {}) => {
      const path = new URL(typeof input === "string" ? input : input.url, location.href).pathname;
      if (path === "/api/v1/requirements") {
        globalThis.__proofkitAbortProbe.started = true;
        init.signal?.addEventListener("abort", () => { globalThis.__proofkitAbortProbe.aborted = true; }, {once: true});
      }
      return nativeFetch(input, init);
    };
  });
  let releaseRequest;
  const requestReleased = new Promise((resolve) => { releaseRequest = resolve; });
  await page.route("**/api/v1/requirements", async (route) => {
    await requestReleased;
    try {
      await route.continue();
    } catch {
      // The asserted abort may close the intercepted request first.
    }
  });

  await page.goto("/");
  await page.waitForFunction(() => globalThis.__proofkitAbortProbe?.started === true);
  await page.getByRole("button", {name: "Diff"}).click();
  await page.waitForFunction(() => globalThis.__proofkitAbortProbe?.aborted === true);
  releaseRequest();
  await expect(page.locator("#workspace-content [role=status]")).toHaveAttribute("data-state", "unavailable");
});

for (const unavailableView of [
  {button: "Diff", heading: "Semantic diff"},
  {button: "Traceability", heading: "Traceability graph"},
]) {
  test(`request generation rejects a non-cooperative late response after opening ${unavailableView.button}`, async ({page}) => {
    await disableOptionalViews(page);
    await page.addInitScript(() => {
      const nativeFetch = globalThis.fetch.bind(globalThis);
      globalThis.AbortController = class {
        signal = {aborted: false, addEventListener() {}};
        abort() {}
      };
      globalThis.__proofkitLateResponse = {consumed: false, release: undefined, started: false};
      globalThis.fetch = async (input, init = {}) => {
        const path = new URL(typeof input === "string" ? input : input.url, location.href).pathname;
        if (path !== "/api/v1/requirements") return nativeFetch(input, init);
        globalThis.__proofkitLateResponse.started = true;
        const {signal: _ignored, ...nonCooperativeInit} = init;
        const response = await nativeFetch(input, nonCooperativeInit);
        await new Promise((resolve) => { globalThis.__proofkitLateResponse.release = resolve; });
        return {
          ok: response.ok,
          status: response.status,
          async json() {
            const value = await response.json();
            setTimeout(() => { globalThis.__proofkitLateResponse.consumed = true; }, 0);
            return value;
          },
        };
      };
    });

    await page.goto("/");
    await page.waitForFunction(() => globalThis.__proofkitLateResponse?.started === true);
    await page.getByRole("button", {name: unavailableView.button}).click();
    await expect(page.getByRole("heading", {name: unavailableView.heading})).toBeVisible();
    await expect(page.locator("#workspace-content [role=status]")).toHaveAttribute("data-state", "unavailable");
    await page.evaluate(() => globalThis.__proofkitLateResponse.release());
    await page.waitForFunction(() => globalThis.__proofkitLateResponse?.consumed === true);
    await expect(page.getByRole("heading", {name: unavailableView.heading})).toBeVisible();
    await expect(page.locator('[role="tree"]')).toHaveCount(0);
  });
}

async function disableOptionalViews(page) {
  await page.route("**/api/v1/manifest", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    await route.fulfill({response, json: {...body, diffAvailable: false, graphAvailable: false}});
  });
}
