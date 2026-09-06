import {expect} from "@playwright/test";
import {test} from "./workspace-test-harness.mjs";

import {analyzeAxe, assertAxeTestComplete, initializeAxe} from "./axe-harness.mjs";

import {admittedWorkspaceURL, isWorkspaceNavigationResponse, navigateWorkspace, openWorkspace, reloadWorkspace} from "./workspace-navigation-harness.mjs";

async function expectIdentityOrder(rows, expected) {
  await expect(rows).toHaveCount(expected.length);
  for (let index = 0; index < expected.length; index += 1) {
    await expect(rows.nth(index)).toHaveAttribute("data-identity", expected[index]);
  }
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

async function executeAssertionPlan(plan, sink) {
  for (const entry of plan) await sink(entry);
}

async function expectCSS(locator, properties) {
  const plan = Object.freeze(Object.entries(properties).map(([property, value]) =>
    Object.freeze({property, value})));
  const completed = [];
  await executeAssertionPlan(plan, async ({property, value}) => {
    await expect(locator).toHaveCSS(property, value);
    completed.push({property, value});
  });
  expect(completed).toEqual(plan);
}

function assertAssertionPlanFalsifiers() {
  const first = Object.freeze({property: "opacity", value: "1"});
  const second = Object.freeze({property: "filter", value: "none"});
  const plan = Object.freeze([first, second]);
  for (const mutant of [
    [first],
    [first, second, first],
    [second, first],
    [first, second, Object.freeze({property: "mask-image", value: "none"})],
  ]) expect(mutant).not.toEqual(plan);
}


const axeTest = test.extend({
  axePage: async ({page}, use) => {
    await initializeAxe(page);
    try {
      await use(page);
    } finally {
      assertAxeTestComplete(page);
    }
  },
});

const workspaceStateMatrix = [
  {
    name: "bootstrap loading",
    state: "bootstrap-loading",
    heading: "Loading workspace",
    setup: async (page, baseURL) => {
      let releaseManifest;
      const barrier = new Promise((resolve) => { releaseManifest = resolve; });
      await page.route("**/api/v1/manifest", async (route) => {
        await barrier;
        try {
          await route.continue();
        } catch {
          // Releasing the barrier during page teardown may close the request.
        }
      });
      await openWorkspace(page, baseURL);
      return () => releaseManifest();
    },
    packetState: "empty",
  },
  {
    name: "bootstrap failed",
    state: "bootstrap-failed",
    heading: "Workspace unavailable",
    setup: async (page, baseURL) => {
      await page.route("**/api/v1/manifest", (route) => route.fulfill({status: 503, contentType: "application/json", body: '{"error":"secret-internal-detail"}'}));
      await openWorkspace(page, baseURL);
      await expect(page.getByRole("alert")).toContainText("The workspace could not be reached. Try this request again.");
      await expect(page.getByRole("alert")).not.toContainText("secret-internal-detail");
    },
    packetState: "empty",
  },
  {
    name: "specifications loading",
    state: "specifications-loading",
    heading: "Specifications",
    setup: async (page, baseURL) => {
      const release = await holdRoute(page, "**/api/v1/requirements");
      await openWorkspace(page, baseURL);
      await expect(page.locator("body")).toHaveAttribute("data-state", "specifications-loading");
      return release;
    },
    packetState: "empty",
  },
  {
    name: "specifications",
    state: "specifications",
    heading: "Specifications",
    setup: async (page, baseURL) => {
      await openWorkspace(page, baseURL);
    },
    packetState: "empty",
  },
  {
    name: "specifications no match",
    state: "specifications",
    contentState: "no-match",
    heading: "Specifications",
    setup: async (page, baseURL) => {
      await page.route("**/api/v1/requirements", async (route) => {
        const response = await route.fetch();
        const body = await response.json();
        await route.fulfill({
          response,
          json: {
            ...body,
            projection: {
              ...body.projection,
              availableRequirementCount: 0,
              omittedRequirementCount: 0,
              requirements: [],
              selectedRequirementCount: 0,
            },
          },
        });
      });
      await openWorkspace(page, baseURL);
      await expect(page.locator("#workspace-content [role=status]")).toHaveText("No requirements matched the admitted query.");
    },
    packetState: "empty",
  },
  {
    name: "diff loading",
    state: "diff-loading",
    heading: "Semantic diff",
    setup: async (page, baseURL) => {
      const release = await holdRoute(page, "**/api/v1/diff");
      await openWorkspace(page, baseURL);
      await page.getByRole("button", {name: "Diff"}).click();
      await expect(page.locator("body")).toHaveAttribute("data-state", "diff-loading");
      return release;
    },
    packetState: "empty",
  },
  {
    name: "diff",
    state: "diff",
    heading: "Semantic diff",
    setup: async (page, baseURL) => {
      await openWorkspace(page, baseURL);
      await page.getByRole("button", {name: "Diff"}).click();
    },
    packetState: "empty",
  },
  {
    name: "graph loading",
    state: "graph-loading",
    heading: "Traceability graph",
    setup: async (page, baseURL) => {
      const release = await holdRoute(page, "**/api/v1/graph");
      await openWorkspace(page, baseURL);
      await page.getByRole("button", {name: "Traceability"}).click();
      await expect(page.locator("body")).toHaveAttribute("data-state", "graph-loading");
      return release;
    },
    packetState: "empty",
  },
  {
    name: "graph",
    state: "graph",
    heading: "Traceability graph",
    setup: async (page, baseURL) => {
      await openWorkspace(page, baseURL);
      await page.getByRole("button", {name: "Traceability"}).click();
    },
    packetState: "empty",
  },
  {
    name: "diff unavailable",
    state: "diff-unavailable",
    heading: "Semantic diff",
    setup: async (page, baseURL) => {
      await disableOptionalViews(page);
      await openWorkspace(page, baseURL);
      await page.getByRole("button", {name: "Diff"}).click();
    },
    packetState: "empty",
  },
  {
    name: "graph unavailable",
    state: "graph-unavailable",
    heading: "Traceability graph",
    setup: async (page, baseURL) => {
      await disableOptionalViews(page);
      await openWorkspace(page, baseURL);
      await page.getByRole("button", {name: "Traceability"}).click();
    },
    packetState: "empty",
  },
  {
    name: "view request failed",
    state: "view-failed",
    heading: "Specifications",
    setup: async (page, baseURL) => {
      await page.route("**/api/v1/requirements", (route) => route.fulfill({status: 500, contentType: "application/json", body: '{"error":"secret-view-detail"}'}));
      await openWorkspace(page, baseURL);
      await expect(page.getByRole("alert")).toContainText("The workspace could not be reached. Try this request again.");
      await expect(page.getByRole("alert")).not.toContainText("secret-view-detail");
    },
    packetState: "empty",
  },
  {
    name: "handoff result",
    state: "handoff-result",
    heading: "Handoff packet",
    setup: async (page, baseURL) => {
      await openWorkspace(page, baseURL);
      await createHandoff(page);
    },
    packetState: "result",
  },
  {
    name: "handoff failed",
    state: "handoff-failed",
    heading: "Handoff packet",
    setup: async (page, baseURL) => {
      await page.route("**/api/v1/handoff", (route) => route.fulfill({status: 500, contentType: "application/json", body: '{"error":"secret-handoff-detail"}'}));
      await openWorkspace(page, baseURL);
      await createHandoff(page);
      await expect(page.getByRole("alert")).toContainText("The handoff packet could not be created.");
      await expect(page.getByRole("alert")).not.toContainText("secret-handoff-detail");
    },
    packetState: "failed",
  },
];

for (const row of workspaceStateMatrix) {
  axeTest(`workspace state matrix: ${row.name}`, async ({axePage: page, baseURL}) => {
    const release = await row.setup(page, baseURL);
    try {
      await assertAxe(page, row);
      await assertReflow(page, row);
      await assertRenderedContrast(page, row);
      const packetRegion = page.getByRole("region", {name: "Handoff packet"});
      await expect(packetRegion).toBeVisible();
      if (row.packetState === "result") {
        expect(JSON.parse(await packetRegion.locator("pre").textContent()).state).toBe("submitted");
      } else {
        await expect(packetRegion.locator("pre")).toBeEmpty();
      }
      await assertHandoffPacketTabOrder(page, packetRegion);
    } finally {
      release?.();
    }
  });
}

test("workspace open rejects an unsuccessful main-resource response", async ({baseURL, page}) => {
  await page.route((url) => url.pathname === "/", async (route) => {
    const response = await route.fetch();
    await route.fulfill({response, status: 503});
  });
  await expect(openWorkspace(page, baseURL)).rejects.toThrow(
    "Workspace navigation did not return a successful response",
  );
});

test("workspace reload rejects an unsuccessful main-resource response", async ({baseURL, page}) => {
  await openWorkspace(page, baseURL);
  await page.route((url) => url.pathname === "/", async (route) => {
    const response = await route.fetch();
    await route.fulfill({response, status: 503});
  });
  await expect(reloadWorkspace(page, baseURL)).rejects.toThrow(
    "Workspace reload did not return a successful response",
  );
});

test("workspace open rejects accessible-name drift in the server-owned heading", async ({baseURL, page}) => {
  const heading = "<h1>browser.fixture.workspace</h1>";
  let mutantDelivered = false;
  await page.route((url) => url.pathname === "/", async (route) => {
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    const body = await response.text();
    expect(body).toContain(heading);
    const mutatedBody = body.replace(heading, "<h1>browser.fixture.workspace drift</h1>");
    expect(mutatedBody).not.toBe(body);
    await route.fulfill({
      response,
      body: mutatedBody,
    });
    mutantDelivered = true;
  });
  await expect(openWorkspace(page, baseURL)).rejects.toThrow();
  expect(mutantDelivered).toBe(true);
});

test("workspace navigation admits the exact base and ignores response decoys", async ({baseURL, page}) => {
  const configuredURL = new URL(baseURL);
  const localAuthorityError = "Workspace base URL is outside the admitted local origin";
  expect(admittedWorkspaceURL(baseURL)).toBe(configuredURL.href);
  expect(() => admittedWorkspaceURL(undefined)).toThrow("Workspace base URL is unavailable");
  for (const rejectedURL of [
    `https://127.0.0.1:${configuredURL.port}/`,
    `http://localhost:${configuredURL.port}/`,
    "http://127.0.0.1/",
    `http://user@127.0.0.1:${configuredURL.port}/`,
    `http://:secret@127.0.0.1:${configuredURL.port}/`,
    `http://127.0.0.1:${configuredURL.port}/workspace`,
    `http://127.0.0.1:${configuredURL.port}/?query=1`,
    `http://127.0.0.1:${configuredURL.port}/#fragment`,
  ]) {
    expect(() => admittedWorkspaceURL(rejectedURL)).toThrow(localAuthorityError);
  }
  await openWorkspace(page, baseURL);
  const workspaceURL = admittedWorkspaceURL(baseURL);
  const mainFrame = page.mainFrame();
  const childFrame = {};
  const candidate = (url, navigation, frame) => ({
    url: () => url,
    request: () => ({
      isNavigationRequest: () => navigation,
      frame: () => frame,
    }),
  });
  expect([
    isWorkspaceNavigationResponse(candidate(workspaceURL, true, mainFrame), workspaceURL, mainFrame),
    isWorkspaceNavigationResponse(candidate(workspaceURL, false, mainFrame), workspaceURL, mainFrame),
    isWorkspaceNavigationResponse(candidate(workspaceURL, true, childFrame), workspaceURL, mainFrame),
    isWorkspaceNavigationResponse(candidate(`${workspaceURL}foreign`, true, mainFrame), workspaceURL, mainFrame),
  ]).toEqual([true, false, false, false]);
  let decoyDelivered = false;
  await page.route((url) => url.href === workspaceURL, async (route) => {
    const response = await route.fetch();
    if (route.request().isNavigationRequest()) {
      await route.fulfill({response});
      return;
    }
    await route.fulfill({response, status: 503});
    decoyDelivered = true;
  });
  await navigateWorkspace(
    page,
    workspaceURL,
    (token) => page.evaluate(({target, value}) => {
      window.setTimeout(async () => {
        await window.fetch(target);
        window.location.reload();
      }, 0);
      return value;
    }, {target: workspaceURL, value: token}),
    "Workspace reload did not return a successful response",
  );
  expect(decoyDelivered).toBe(true);

  const cleanupFrame = {};
  let cleanupAbortObserved = false;
  let cleanupConsumptionObserved = false;
  const cleanupEvents = [];
  const cleanupPage = {
    mainFrame: () => cleanupFrame,
    waitForResponse: (_predicate, {signal}) => {
      cleanupEvents.push("waiter-armed");
      let fallback;
      const pending = new Promise((resolve, reject) => {
        fallback = setTimeout(() => resolve({ok: () => false}), 25);
        signal.addEventListener("abort", () => {
          clearTimeout(fallback);
          cleanupAbortObserved = true;
          cleanupEvents.push("waiter-aborted");
          reject(new Error("Workspace navigation waiter aborted"));
        }, {once: true});
      });
      const consume = pending.catch.bind(pending);
      pending.catch = (...args) => {
        cleanupConsumptionObserved = true;
        cleanupEvents.push("waiter-consumed");
        return consume(...args);
      };
      return pending;
    },
  };
  await expect(navigateWorkspace(
    cleanupPage,
    workspaceURL,
    async () => {
      cleanupEvents.push("trigger-called");
      return "proofkit.workspace-navigation.wrong";
    },
    "Workspace navigation fallback response was admitted",
  )).rejects.toThrow("Workspace navigation trigger token is invalid");
  expect(cleanupAbortObserved).toBe(true);
  expect(cleanupConsumptionObserved).toBe(true);
  expect(cleanupEvents).toEqual([
    "waiter-armed",
    "trigger-called",
    "waiter-aborted",
    "waiter-consumed",
  ]);
});

axeTest("combined axe negative control proves default and target-size sensitivity", async ({axePage: page}) => {
  await page.goto("about:blank");
  await page.setContent(`
    <main>
      <button id="undersized" aria-label="Small target" style="box-sizing:border-box;width:10px;height:10px;min-width:0;min-height:0;padding:0"></button><button id="unnamed" style="box-sizing:border-box;width:44px;height:44px;min-width:0;min-height:0;padding:0"></button>
    </main>
  `);
  const result = await analyzeAxe(page);
  const expectedTargetSize = {
    incomplete: [],
    passes: [["#unnamed"]],
    violations: [["#undersized"]],
  };
  const expectedButtonName = {
    incomplete: [],
    passes: [["#undersized"]],
    violations: [["#unnamed"]],
  };
  expect(axeRuleProjection(result, "target-size")).toEqual(expectedTargetSize);
  expect(axeRuleProjection(result, "button-name")).toEqual(expectedButtonName);
  for (const mutant of [
    [withAxeOutcome(result, "violations", "target-size", "#unnamed"), "target-size", expectedTargetSize],
    [withAxeOutcome(result, "incomplete", "target-size", "#unnamed"), "target-size", expectedTargetSize],
    [withAxeOutcome(result, "violations", "button-name", "#undersized"), "button-name", expectedButtonName],
    [withAxeOutcome(result, "incomplete", "button-name", "#undersized"), "button-name", expectedButtonName],
  ]) {
    expect(axeRuleProjection(mutant[0], mutant[1])).not.toEqual(mutant[2]);
  }
});

test("focus contrast negative control rejects an invisible focus indicator", async ({baseURL, page}) => {
  await openWorkspace(page, baseURL);
  await page.locator("#submit-question, [data-view]:not([disabled])").evaluateAll((controls) => {
    for (const control of controls) control.style.setProperty("outline", "none", "important");
  });
  await expect(assertRenderedContrast(page, workspaceStateMatrix.find((row) => row.name === "specifications"))).rejects.toThrow(/visible positive-width outline/);
});

for (const mismatch of [
  {field: "requestId", value: "browser.specifications.foreign"},
  {field: "snapshotId", value: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
]) {
  test(`a malformed current view response with mismatched ${mismatch.field} fails closed`, async ({baseURL, page}) => {
    await page.route("**/api/v1/requirements", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      await route.fulfill({response, json: {...body, [mismatch.field]: mismatch.value}});
    });
    await openWorkspace(page, baseURL);
    await expect(page.locator("body")).toHaveAttribute("data-state", "view-failed");
    await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
    await expect(page.getByRole("alert")).toHaveText("The admitted workspace is unavailable.");
    await expect(page.getByRole("alert")).not.toContainText(mismatch.value);
  });
}

test("handoff packet output never creates a zero-value keyboard stop", async ({baseURL, page}) => {
  let handoffFails = false;
  await page.route("**/api/v1/handoff", (route) => route.fulfill(handoffFails ? {
    status: 500,
    contentType: "application/json",
    body: "{}",
  } : {
    status: 200,
    contentType: "application/json",
    body: '{"state":"submitted"}',
  }));
  const packet = page.locator("#handoff-packet");
  const expectNotFocusable = async () => {
    await expect(packet).not.toHaveAttribute("tabindex", /.+/);
    expect(await packet.evaluate((element) => {
      element.focus();
      return element === document.activeElement;
    })).toBe(false);
  };

  await openWorkspace(page, baseURL);
  await expect(packet).toBeEmpty();
  await expectNotFocusable();

  await page.getByRole("button", {name: "Select invariant"}).first().click();
  await page.getByRole("textbox", {name: "Question"}).fill("Is the handoff output still readable?");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.locator("body")).toHaveAttribute("data-state", "handoff-result");
  await expect(packet).toHaveText('{"state":"submitted"}');
  await expectNotFocusable();

  handoffFails = true;
  await reloadWorkspace(page, baseURL);
  await page.getByRole("button", {name: "Select invariant"}).first().click();
  await page.getByRole("textbox", {name: "Question"}).fill("Does failure add a keyboard stop?");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.locator("body")).toHaveAttribute("data-state", "handoff-failed");
  await expect(packet).toBeEmpty();
  await expectNotFocusable();
});

test("workspace renders admitted views and creates a keyboard-authorized handoff", async ({baseURL, browserName, page}) => {
  test.setTimeout(60_000);
  assertAssertionPlanFalsifiers();
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });

  await openWorkspace(page, baseURL);
  await expect(page.getByRole("heading", {name: "browser.fixture.workspace"})).toBeVisible();
  await expect(page.locator('meta[name="proofkit-browser-capability"]')).toHaveCount(0);
  const workspaceAuthority = page.getByLabel("Authority boundary");
  await expect(workspaceAuthority).toContainText("presentation_adapter");
  await expect(workspaceAuthority).toContainText("Expected-digest coverage: none");
  await expect(workspaceAuthority).toContainText("do not prove receipt freshness");

  const requirementBoundary = page.getByLabel("Boundary for REQ-CONSUMER-001");
  await requirementBoundary.locator("summary").click();
  await expect(requirementBoundary).toContainText("Owner: browser.fixture.owner");
  await expect(requirementBoundary).toContainText("Claim level: blocking");
  await expect(requirementBoundary).toContainText("Fixture requirements do not approve merge");
  await expect(requirementBoundary).toContainText("This requirement does not approve merge");

  const selectInvariant = page.getByRole("button", {name: "Select invariant"});
  const specificationsView = page.getByRole("button", {name: "Specifications"});
  const diffView = page.getByRole("button", {name: "Diff"});
  const coverageView = page.getByRole("button", {name: "Coverage", exact: true});
  await expect(specificationsView).toHaveAttribute("aria-current", "page");
  await specificationsView.focus();
  await page.keyboard.press("Tab");
  if (browserName === "webkit") {
    const authoritySummary = page.locator("#workspace-authority > summary");
    if (await authoritySummary.evaluate((element) => element === document.activeElement)) {
      // Playwright WebKit follows the macOS preference that Tab visits
      // selected native control kinds; Option-Tab includes all controls.
      await expect(authoritySummary).toBeFocused();
      await specificationsView.focus();
      await page.keyboard.press("Alt+Tab");
      await expect(coverageView).toBeFocused();
      await page.keyboard.press("Alt+Shift+Tab");
      await expect(specificationsView).toBeFocused();
    } else {
      await expect(coverageView).toBeFocused();
      await page.keyboard.press("Shift+Tab");
      await expect(specificationsView).toBeFocused();
    }
  } else {
    await expect(coverageView).toBeFocused();
    await page.keyboard.press("Shift+Tab");
    await expect(specificationsView).toBeFocused();
  }
  await selectInvariant.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("1 source-bound target");
  await page.getByRole("button", {name: "Clear selection"}).click();
  await expect(page.getByRole("status")).toContainText("No source-bound text selected");
  await selectInvariant.focus();
  await page.keyboard.press("Space");
  await expect(page.getByRole("status")).toContainText("1 source-bound target");
  await page.getByRole("textbox", {name: "Question"}).fill("Does retry preserve the same contract?");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Handoff packet created");
  const packetRegion = page.getByRole("region", {name: "Handoff packet"});
  await expect(packetRegion).toContainText('"state":"submitted"');
  await expect(packetRegion).toContainText("retry \u{1F680}");

  await page.getByRole("button", {name: "Diff"}).click();
  await expect(diffView).toHaveAttribute("aria-current", "page");
  await expect(specificationsView).not.toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("heading", {name: /scalar_changed/})).toBeVisible();
  await page.getByText("Before and after", {exact: true}).click();
  await expect(page.getByText(/Source digests: sha256:/)).toBeVisible();
  const diffBoundary = page.locator(".projection-boundary");
  await expect(diffBoundary).toContainText("lookup_fragment_only");
  await expect(diffBoundary).toContainText(/Base snapshot: sha256:.*\(expected-digest coverage: none\)/);
  await expect(diffBoundary).toContainText(/Current snapshot: sha256:.*\(expected-digest coverage: none\)/);
  await expect(diffBoundary).toContainText("does not own requirement meaning");

  const graphURL = new URL("/api/v1/graph", page.url()).href;
  const graphRequests = [];
  const graphResponses = [];
  const graphInterceptions = [];
  const graphCallbacks = new Set();
  const graphCallbackErrors = [];
  let graphAttemptState = "armed";
  const sentinel = "c116-intercepted-node";
  const isGraphRequest = (request) => request.method() === "POST" && request.url() === graphURL;
  const requestHandler = (request) => {
    if (isGraphRequest(request)) graphRequests.push(request);
  };
  const responseHandler = (response) => {
    if (!isGraphRequest(response.request())) return;
    const callback = response.json()
      .then((body) => graphResponses.push({body, response}))
      .catch((error) => graphCallbackErrors.push(error));
    graphCallbacks.add(callback);
  };
  const routeHandler = async (route) => {
    const callback = (async () => {
      try {
        expect(graphAttemptState).toBe("armed");
        graphAttemptState = "intercepted";
        expect(route.request().url()).toBe(graphURL);
        const upstream = await route.fetch({timeout: 5000, maxRedirects: 0, maxRetries: 0});
        expect(upstream.ok()).toBe(true);
        expect(upstream.url()).toBe(graphURL);
        const body = await upstream.json();
        expect(JSON.stringify(body)).not.toContain(sentinel);
        expect(body.projection.nodes.length).toBeGreaterThan(0);
        body.projection.nodes[0] = {
          ...body.projection.nodes[0],
          label: `${sentinel} ${body.projection.nodes[0].label}`,
        };
        graphInterceptions.push(body);
        await route.fulfill({response: upstream, json: body});
        graphAttemptState = "admitted";
      } catch (error) {
        try {
          await route.abort("failed");
        } catch {
          // The route may already have reached a terminal state.
        }
        throw error;
      }
    })();
    graphCallbacks.add(callback);
    await callback;
  };
  page.on("request", requestHandler);
  page.on("response", responseHandler);
  await page.route(graphURL, routeHandler);
  try {
    await page.getByRole("button", {name: "Traceability"}).click();
    await expect(page.locator("body")).toHaveAttribute("data-state", "graph");
    await expect.poll(() => graphRequests.length).toBe(1);
    await expect.poll(() => graphInterceptions.length).toBe(1);
    await expect.poll(() => graphResponses.length).toBe(1);
    expect(graphResponses[0].response.request()).toBe(graphRequests[0]);
    expect(graphResponses[0].body).toEqual(graphInterceptions[0]);
    const projection = deepFreeze(structuredClone(graphResponses[0].body.projection));
    expect(Object.isFrozen(projection.nodes)).toBe(true);
    const nodes = projection.nodes;
    const edges = projection.edges;
    const nodeIDs = nodes.map((node) => node.nodeId);
    const edgeIDs = edges.map((edge) => edge.edgeId);
    expect(edges.some((edge, index) => edges.slice(index + 1).some(other => edge.edgeId !== other.edgeId && edge.fromNodeId === other.fromNodeId && edge.toNodeId === other.toNodeId)), "source fixture preserves owner-distinct parallel relations").toBe(true);
    const graph = page.locator(".graph-canvas > svg");
    const graphViewport = page.getByRole("region", {name: "Traceability graph viewport"});
    await expect(graphViewport).toBeVisible();
    await expect(graph).toHaveAttribute("aria-hidden", "true");
    await expect(graph).toHaveAttribute("data-node-ids", nodeIDs.join(" "));
    await expect(graph).toHaveAttribute("data-edge-ids", edgeIDs.join(" "));
    const buttons = page.locator(".graph-canvas > button[data-graph-select]");
    await expect(buttons).toHaveCount(nodes.length);
    const primaryIDs = new Set(projection.primaryNodeIds);
    const nativeFields = page.locator(".graph-inspector > dl");
    for (let index = 0; index < nodes.length; index++) {
      const node = nodes[index];
      const button = buttons.nth(index);
      await expect(button).toHaveAttribute("data-graph-select", node.nodeId);
      await expect(button).toHaveAttribute("data-plane", node.evidencePlane);
      await expect(button).toHaveAttribute("data-boundary", String(!primaryIDs.has(node.nodeId)));
      await expect(button.locator(".graph-node-label")).toHaveText(node.label);
      await expect(button.locator(".graph-node-identity")).toHaveText(node.nodeId);
      await expect(button).toHaveAttribute("title", `${node.label}: ${node.nodeId}`);
      await button.focus();
      await page.keyboard.press("Enter");
      await expect(page.locator(`.graph-canvas > button[data-graph-select="${node.nodeId}"]`)).toBeFocused();
      await expect(nativeFields.locator("dt")).toHaveText(Object.keys(node));
      await expect(nativeFields.locator("dd")).toHaveText(Object.values(node).map(value => Array.isArray(value) ? value.join(", ") : String(value)));
      await expectCSS(nativeFields, {visibility: "visible", opacity: "1", filter: "none", "clip-path": "none", "content-visibility": "visible"});
    }
    const nodeRecords = page.getByRole("list", {name: "Admitted traceability nodes"}).locator(":scope > li");
    const edgeRecords = page.getByRole("list", {name: "Admitted traceability edges"}).locator(":scope > li");
    await expectIdentityOrder(nodeRecords, nodeIDs);
    await expectIdentityOrder(edgeRecords, edgeIDs);
    const nativeGraph = await graph.evaluate(svg => ({
      boxes: Array.from(svg.parentElement.querySelectorAll(":scope > button[data-graph-select]"), element => {
        const rect = element.getBoundingClientRect();
        return {id: element.dataset.graphSelect, x: rect.left, y: rect.top, width: rect.width, height: rect.height};
      }),
      lines: Array.from(svg.querySelectorAll("line"), line => {
        const matrix = line.getScreenCTM();
        if (!matrix) throw new Error("Native line coordinate system is unavailable");
        const start = new DOMPoint(line.x1.baseVal.value, line.y1.baseVal.value).matrixTransform(matrix);
        const end = new DOMPoint(line.x2.baseVal.value, line.y2.baseVal.value).matrixTransform(matrix);
        return {id: line.dataset.edgeId, raw: ["x1", "y1", "x2", "y2"].map(name => Number(line.getAttribute(name))), points: [start.x, start.y, end.x, end.y]};
      }),
    }));
    expect(nativeGraph.lines.map(line => line.id), "complete native line identities").toEqual(edgeIDs);
    const boxes = nativeGraph.boxes;
    const boxesByID = new Map(boxes.map(box => [box.id, box]));
    expect([...boxesByID.keys()]).toEqual(nodeIDs);
    for (const box of boxes) {
      expect([box.x, box.y, box.width, box.height].every(Number.isFinite)).toBe(true);
      expect(box.width).toBeGreaterThan(0);
      expect(box.height).toBeGreaterThan(0);
    }
    for (let index = 0; index < edges.length; index++) {
      const edge = edges[index];
      const details = edgeRecords.nth(index).locator("details");
      await details.locator("summary").click();
      await expect(details.locator("dt")).toHaveText(Object.keys(edge));
      await expect(details.locator("dd")).toHaveText(Object.values(edge).map(value => Array.isArray(value) ? value.join(", ") : String(value)));
      const line = graph.locator("line").nth(index);
      await expect(line).toHaveAttribute("data-edge-id", edge.edgeId);
      await expect(line).toHaveAttribute("marker-end", "url(#graph-arrow)");
      const geometry = nativeGraph.lines[index].points;
      expect(nativeGraph.lines[index].raw.every(Number.isFinite)).toBe(true);
      expect(geometry.every(Number.isFinite)).toBe(true);
      expect(geometry[0] !== geometry[2] || geometry[1] !== geometry[3]).toBe(true);
      for (const [role, id, x, y] of [["source", edge.fromNodeId, geometry[0], geometry[1]], ["target", edge.toNodeId, geometry[2], geometry[3]]]) {
        const box = boxesByID.get(id);
        expect(box, `${role} endpoint node`).toBeDefined();
        const tolerance = 0.5;
        const inside = x >= box.x - tolerance && x <= box.x + box.width + tolerance && y >= box.y - tolerance && y <= box.y + box.height + tolerance;
        const perimeter = Math.min(Math.abs(x - box.x), Math.abs(x - box.x - box.width), Math.abs(y - box.y), Math.abs(y - box.y - box.height)) <= tolerance;
        expect(inside && perimeter, `${role} endpoint of ${edge.edgeId} touches ${id}`).toBe(true);
      }
      await expectCSS(line, {visibility: "visible", opacity: "1", stroke: "rgb(32, 37, 34)", "stroke-width": "1.5px", filter: "none", "clip-path": "none"});
    }
    for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j];
      expect(a.x + a.width <= b.x || b.x + b.width <= a.x || a.y + a.height <= b.y || b.y + b.height <= a.y).toBe(true);
    }
    await expect(buttons.first()).toContainText(sentinel);
    await expect(page.locator("animate, animateColor, animateMotion, animateTransform")).toHaveCount(0);
  } finally {
    const stateBeforeCleanup = graphAttemptState;
    graphAttemptState = "closing";
    page.off("request", requestHandler);
    page.off("response", responseHandler);
    let detachError;
    try {
      await page.unroute(graphURL, routeHandler);
    } catch (error) {
      detachError = error;
    }
    const callbackResults = await Promise.allSettled([...graphCallbacks]);
    graphAttemptState = "detached";
    expect(stateBeforeCleanup).toBe("admitted");
    expect(detachError).toBeUndefined();
    expect(callbackResults.every((result) => result.status === "fulfilled")).toBe(true);
    expect(graphCallbackErrors).toEqual([]);
    expect(graphRequests).toHaveLength(1);
    expect(graphInterceptions).toHaveLength(1);
    expect(graphResponses).toHaveLength(1);
    expect(graphAttemptState).toBe("detached");
  }
  const inspector = page.getByRole("region", {name: "Selected graph node"});
  const selectNode = async id => { await page.locator(`.graph-records button[data-graph-select="${id}"]`).click(); };
  await selectNode("code:code.repository");
  await expect(inspector).toContainText("stale");
  await selectNode("code:code.retry");
  await expect(inspector).toContainText("source_range");
  await expect(inspector).toContainText("verified");
  const nodes = graphResponses[0].body.projection.nodes;
  await selectNode(nodes.find(node => node.producerId === "browser.fixture.candidate-runner").nodeId);
  await expect(inspector).toContainText("caller_reported");
  await expect(inspector).toContainText("unverified");
  await expect(inspector).toContainText("failed");
  await selectNode(nodes.find(node => node.producerId === "browser.fixture.runner").nodeId);
  await expect(inspector).toContainText("receipt_admitted");
  await expect(inspector).toContainText("current");
  await expect(inspector).toContainText("passed");
  const traceEdge = graphResponses[0].body.projection.edges.find(edge => edge.evidenceRefs?.includes("browser.fixture.trace"));
  expect(traceEdge).toBeDefined();
  const traceEdgeRow = page.getByRole("list", {name: "Admitted traceability edges"}).locator(`:scope > li[data-identity="${traceEdge.edgeId}"]`);
  if (!(await traceEdgeRow.locator("details").evaluate(element => element.open))) await traceEdgeRow.locator("summary").click();
  await expect(traceEdgeRow).toContainText("owner_admitted");
  await expect(traceEdgeRow).toContainText("current");
  await expect(page.locator(".projection-boundary")).toContainText("does not infer code topology");
  await expect(page.locator(".graph-canvas > button").filter({hasText: /deliberately long traceability label/})).toHaveCount(1);
  expect(consoleErrors).toEqual([]);
});

test("collapsed text selection cannot retain hidden handoff authority", async ({baseURL, page}) => {
  await openWorkspace(page, baseURL);
  const invariant = page.locator("[data-anchor-id]").first();
  const selectionButton = page.locator("[data-select-anchor]").first();
  await expect(invariant).toBeVisible();
  await selectionButton.click();
  await expect(selectionButton).toHaveAttribute("aria-pressed", "true");
  await invariant.click();
  await expect(selectionButton).toHaveAttribute("aria-pressed", "true");
  await invariant.selectText();
  await expect(page.getByRole("status")).toContainText("1 source-bound target");
  await expect(selectionButton).toHaveAttribute("aria-pressed", "false");
  await invariant.click();
  await expect(page.getByRole("status")).toContainText("No source-bound text selected");
  await expect(selectionButton).toHaveAttribute("aria-pressed", "false");
  await page.getByRole("textbox", {name: "Question"}).fill("Can a hidden selection be submitted?");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Select invariant text");
  await expect(page.getByRole("region", {name: "Handoff packet"}).locator("pre")).toBeEmpty();
});

test("text selection projects Unicode code-point coordinates", async ({baseURL, page}) => {
  await openWorkspace(page, baseURL);
  const invariant = page.locator("[data-anchor-id]").filter({hasText: "retry \u{1F680}"}).first();
  await expect(invariant).toBeVisible();
  const invariantText = await invariant.textContent();
  if (invariantText === null) throw new Error("Unicode fixture text is unavailable");
  const domStart = invariantText.indexOf("\u{1F680}");
  if (domStart < 0) throw new Error("Unicode fixture is unavailable");
  const domEnd = domStart + "\u{1F680}".length;
  const expectedStartCodePoint = Array.from(invariantText.slice(0, domStart)).length;
  const expectedEndCodePoint = Array.from(invariantText.slice(0, domEnd)).length;
  expect(domEnd - domStart).toBe(2);
  expect(expectedStartCodePoint).toBeGreaterThan(0);
  expect(expectedEndCodePoint - expectedStartCodePoint).toBe(1);
  await invariant.evaluate((element, bounds) => {
    const text = element.firstChild;
    const selection = window.getSelection();
    if (!(text instanceof Text) || text.textContent !== bounds.expectedText || !selection) {
      throw new Error("Exact Unicode selection fixture is unavailable");
    }
    if (!Number.isInteger(bounds.start) || !Number.isInteger(bounds.end) ||
        bounds.start < 0 || bounds.end > text.length || bounds.start >= bounds.end) {
      throw new Error("Exact Unicode selection bounds are invalid");
    }
    const range = document.createRange();
    range.setStart(text, bounds.start);
    range.setEnd(text, bounds.end);
    selection.removeAllRanges();
    selection.addRange(range);
  }, {end: domEnd, expectedText: invariantText, start: domStart});
  await expect(page.getByRole("status")).toContainText("1 source-bound target");
  await expect(page.getByLabel("Selected source text").getByRole("listitem")).toHaveText("\u{1F680}");
  await page.getByRole("textbox", {name: "Question"}).fill("Does the Unicode coordinate remain source-bound?");
  await expect(page.getByLabel("Selected source text").getByRole("listitem")).toHaveText("\u{1F680}");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Handoff packet created");

  const packet = JSON.parse(await page.getByRole("region", {name: "Handoff packet"}).locator("pre").textContent());
  const annotation = packet.annotations[0];
  expect(annotation.exactQuote).toBe("\u{1F680}");
  expect(annotation.startCodePoint).toBe(expectedStartCodePoint);
  expect(annotation.endCodePoint).toBe(expectedEndCodePoint);
  await page.getByRole("button", {name: "Clear selection"}).click();
  await expect(page.getByLabel("Selected source text").getByRole("listitem")).toHaveCount(0);
  await expect(page.getByRole("status")).toContainText("No source-bound text selected");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  await expect(page.getByRole("status")).toContainText("Select invariant text");
});

test("a view transition cooperatively aborts the superseded request", async ({baseURL, page}) => {
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

  await openWorkspace(page, baseURL);
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
  test(`request generation rejects a non-cooperative late response after opening ${unavailableView.button}`, async ({baseURL, page}) => {
    await disableOptionalViews(page);
    await page.addInitScript(() => {
      const nativeFetch = globalThis.fetch.bind(globalThis);
      const NativeAbortController = globalThis.AbortController;
      globalThis.AbortController = class extends NativeAbortController {
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
        for (const method of ["text", "json"]) {
          const readBody = response[method].bind(response);
          response[method] = async () => {
            const value = await readBody();
            setTimeout(() => { globalThis.__proofkitLateResponse.consumed = true; }, 0);
            return value;
          };
        }
        return response;
      };
    });

    await openWorkspace(page, baseURL);
    await page.waitForFunction(() => typeof globalThis.__proofkitLateResponse?.release === "function");
    await page.getByRole("button", {name: unavailableView.button}).click();
    await expect(page.getByRole("heading", {name: unavailableView.heading})).toBeVisible();
    await expect(page.locator("#workspace-content [role=status]")).toHaveAttribute("data-state", "unavailable");
    await page.evaluate(() => globalThis.__proofkitLateResponse.release());
    await page.waitForFunction(() => globalThis.__proofkitLateResponse?.consumed === true);
    await expect(page.getByRole("heading", {name: unavailableView.heading})).toBeVisible();
    await expect(page.getByRole("list", {name: "Specification requirements"})).toHaveCount(0);
  });
}

for (const handoffOutcome of [
  {name: "successful", expectedStatus: "Handoff packet created."},
  {name: "failed", expectedStatus: "The handoff packet could not be created."},
]) {
  test(`a late ${handoffOutcome.name} handoff cannot replace a newer view state`, async ({baseURL, page}) => {
    let releaseHandoff;
    let markHandoffStarted;
    const handoffReleased = new Promise((resolve) => { releaseHandoff = resolve; });
    const handoffStarted = new Promise((resolve) => { markHandoffStarted = resolve; });
    await page.route("**/api/v1/handoff", async (route) => {
      const response = handoffOutcome.name === "successful"
        ? await route.fetch({timeout: 5000, maxRedirects: 0, maxRetries: 0})
        : null;
      markHandoffStarted();
      await handoffReleased;
      if (response) {
        await route.fulfill({response});
      } else {
        await route.fulfill({status: 503, contentType: "application/json", body: "{}"});
      }
    });

    await openWorkspace(page, baseURL);
    await page.getByRole("button", {name: "Select invariant"}).first().click();
    await page.getByRole("textbox", {name: "Question"}).fill("Does a newer view retain its state?");
    await page.getByRole("button", {name: "Create handoff packet"}).click();
    await handoffStarted;
    await page.getByRole("button", {name: "Diff"}).click();
    await expect(page.locator("body")).toHaveAttribute("data-state", "diff");
    await expect(page.getByRole("button", {name: "Diff"})).toHaveAttribute("aria-current", "page");

    await expect(page.getByRole("button", {name: "Create handoff packet"})).toBeDisabled();
    releaseHandoff();
    await expect(page.getByRole("button", {name: "Create handoff packet"})).toBeEnabled();
    await expect(page.getByText(handoffOutcome.expectedStatus, {exact: true})).toHaveCount(0);
    await expect(page.locator("#handoff-packet")).toBeEmpty();
    await expect(page.locator("#handoff-preview")).toBeEmpty();
    await expect(page.getByRole("textbox", {name: "Question"})).toHaveValue("Does a newer view retain its state?");
    await expect(page.locator("body")).toHaveAttribute("data-state", "diff");
    await expect(page.getByRole("button", {name: "Diff"})).toHaveAttribute("aria-current", "page");
  });
}

async function createHandoff(page) {
  await page.getByRole("button", {name: "Select invariant"}).first().click();
  await page.getByRole("textbox", {name: "Question"}).fill("Does the admitted contract remain source-bound?");
  await page.getByRole("button", {name: "Create handoff packet"}).click();
}

async function holdRoute(page, pattern) {
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  await page.route(pattern, async (route) => {
    await barrier;
    try {
      await route.continue();
    } catch {
      // Releasing the barrier during page teardown may close the request.
    }
  });
  return () => release();
}

async function assertHandoffPacketTabOrder(page, packetRegion) {
  const packet = packetRegion.locator("pre");
  expect(await packet.getAttribute("tabindex")).toBeNull();
  expect(await packet.evaluate((element) => element.tabIndex)).toBe(-1);
  const submit = page.getByRole("button", {name: "Create handoff packet"});
  const focusOwner = await submit.isDisabled() ? page.getByRole("textbox", {name: "Question"}) : submit;
  await focusOwner.focus();
  await page.keyboard.press("Tab");
  await expect(packet).not.toBeFocused();
  await focusOwner.focus();
  await page.keyboard.press("Shift+Tab");
  await expect(packet).not.toBeFocused();
}

async function assertWorkspaceState(page, row) {
  await expect(page.locator("body")).toHaveAttribute("data-state", row.state);
  await expect(page.getByRole("heading", {name: row.heading, exact: true})).toBeVisible();
  if (row.contentState) {
    await expect(page.locator("#workspace-content [role=status]")).toHaveAttribute("data-state", row.contentState);
  }
}

async function assertAxe(page, row) {
  await assertWorkspaceState(page, row);
  const result = await analyzeAxe(page);
  const applicable = [...result.passes, ...result.violations, ...result.incomplete].filter((entry) => entry.id === "target-size");
  expect(result.violations).toEqual([]);
  expect(applicable.length).toBeGreaterThan(0);
  expect(result.incomplete.filter((entry) => entry.id === "target-size")).toEqual([]);
}

function axeRuleProjection(result, ruleId) {
  return {
    incomplete: result.incomplete.filter((entry) => entry.id === ruleId).flatMap((entry) => entry.nodes.map((node) => node.target)),
    passes: result.passes.filter((entry) => entry.id === ruleId).flatMap((entry) => entry.nodes.map((node) => node.target)),
    violations: result.violations.filter((entry) => entry.id === ruleId).flatMap((entry) => entry.nodes.map((node) => node.target)),
  };
}

function withAxeOutcome(result, outcome, ruleId, target) {
  return {
    ...result,
    [outcome]: [...result[outcome], {id: ruleId, nodes: [{target: [target]}]}],
  };
}

async function assertReflow(page, row) {
  const previousViewport = page.viewportSize();
  await page.setViewportSize({width: 320, height: 800});
  if (row.heading === "Handoff packet") await page.getByRole("button", {name: "Toggle question inspector"}).click();
  await assertWorkspaceState(page, row);
  const result = await page.evaluate(() => {
    const documentOverflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
    const internal = [...document.querySelectorAll("*")]
      .filter((element) => element.clientWidth > 0 && element.scrollWidth - element.clientWidth > 1)
      .map((element) => ({
        clientWidth: element.clientWidth,
        className: element.className,
        id: element.id,
        label: element.getAttribute("aria-label"),
        role: element.getAttribute("role"),
        scrollWidth: element.scrollWidth,
        tagName: element.tagName,
      }));
    const viewTitles = [...document.querySelectorAll(".view-controls button")].map(button => {
      const lines = new Set();
      const walker = document.createTreeWalker(button, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        if (!walker.currentNode.textContent.trim()) continue;
        const range = document.createRange();
        range.selectNodeContents(walker.currentNode);
        for (const rect of range.getClientRects()) {
          if (rect.width > 0 && rect.height > 0) lines.add(rect.top);
        }
      }
      return {title: button.textContent.trim(), lines: lines.size};
    });
    return {documentOverflow, internal, viewTitles};
  });
  expect(result.documentOverflow).toBeLessThanOrEqual(1);
  expect(result.viewTitles).toEqual([
    {title: "Specifications", lines: 1}, {title: "Coverage", lines: 1}, {title: "Diff", lines: 1}, {title: "Traceability", lines: 1},
  ]);
  const unlabelledOverflow = result.internal.filter((viewport) =>
    !["graph-viewport", "table-viewport"].includes(viewport.className) ||
    viewport.role !== "region" ||
    !viewport.label);
  expect(unlabelledOverflow).toEqual([]);
  await page.setViewportSize(previousViewport);
  await expect(page.locator("#workspace-inspector")).toBeVisible();
  await expect(page.locator("#workspace-navigation")).toBeVisible();
}

async function assertRenderedContrast(page, row) {
  for (const colorScheme of ["light", "dark"]) {
    await page.emulateMedia({colorScheme});
    await assertWorkspaceState(page, row);
    const samples = await page.evaluate(() => {
      const parse = (value) => {
        if (value === "transparent") return [0, 0, 0, 0];
        const match = value.match(/^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:\s*[,/]\s*([\d.]+))?\s*\)$/);
        if (!match) throw new Error(`Unsupported rendered color: ${value}`);
        return [Number(match[1]), Number(match[2]), Number(match[3]), match[4] === undefined ? 1 : Number(match[4])];
      };
      const composite = (foreground, background) => {
        const alpha = foreground[3] + background[3] * (1 - foreground[3]);
        if (alpha === 0) return [0, 0, 0, 0];
        return [
          (foreground[0] * foreground[3] + background[0] * background[3] * (1 - foreground[3])) / alpha,
          (foreground[1] * foreground[3] + background[1] * background[3] * (1 - foreground[3])) / alpha,
          (foreground[2] * foreground[3] + background[2] * background[3] * (1 - foreground[3])) / alpha,
          alpha,
        ];
      };
      const background = (element) => {
        if (!(element instanceof Element)) return [255, 255, 255, 1];
        const parent = background(element.parentElement);
        const color = parse(getComputedStyle(element).backgroundColor);
        color[3] *= Number(getComputedStyle(element).opacity);
        return composite(color, parent);
      };
      const luminance = (color) => {
        const channels = color.slice(0, 3).map((value) => {
          const normalized = value / 255;
          return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
        });
        return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
      };
      const ratio = (left, right) => {
        const first = luminance(left);
        const second = luminance(right);
        return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
      };
      const controls = [document.querySelector("#annotation-question"), document.querySelector("#submit-question:not([disabled])"), document.querySelector("[data-view]:not([disabled])")]
        .filter((element, index, values) => element instanceof HTMLElement && values.indexOf(element) === index);
      const values = [];
      for (const control of controls) {
        const style = getComputedStyle(control);
        const parentBackground = background(control.parentElement);
        const controlBackground = background(control);
        const opacity = Number(style.opacity);
        const text = parse(style.color);
        text[3] *= opacity;
        const border = parse(style.borderTopColor);
        border[3] *= opacity;
        control.blur();
        control.focus({focusVisible: true});
        const focused = getComputedStyle(control);
        const outlineStyle = focused.outlineStyle;
        const outlineWidth = Number.parseFloat(focused.outlineWidth);
        if (["hidden", "none"].includes(outlineStyle) || !Number.isFinite(outlineWidth) || outlineWidth <= 0) {
          throw new Error("Rendered focus indicator must use a visible positive-width outline");
        }
        const outline = parse(focused.outlineColor);
        outline[3] *= Number(focused.opacity);
        values.push({
          border: ratio(composite(border, parentBackground), parentBackground),
          focus: ratio(composite(outline, parentBackground), parentBackground),
          text: ratio(composite(text, controlBackground), controlBackground),
        });
      }
      const heading = document.querySelector("h1");
      if (!(heading instanceof HTMLElement)) throw new Error("Workspace heading is unavailable");
      const headingBackground = background(heading);
      const headingColor = parse(getComputedStyle(heading).color);
      values.push({border: null, focus: null, text: ratio(composite(headingColor, headingBackground), headingBackground)});
      return values;
    });
    expect(samples.length).toBeGreaterThan(1);
    for (const sample of samples) {
      expect(sample.text).toBeGreaterThanOrEqual(4.5);
      if (sample.border !== null) expect(sample.border).toBeGreaterThanOrEqual(3);
      if (sample.focus !== null) expect(sample.focus).toBeGreaterThanOrEqual(3);
    }
  }
}

async function disableOptionalViews(page) {
  await page.route("**/api/v1/manifest", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    await route.fulfill({response, json: {...body, diffAvailable: false, graphAvailable: false}});
  });
}
