import {expect} from "@playwright/test";
import {coverageTest, test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";
import {analyzeAxe, assertAxeTestComplete, initializeAxe} from "./axe-harness.mjs";

async function openCoverage(page, url) {
  await openWorkspace(page, url);
  await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
  const response = page.waitForResponse(response => response.url().endsWith("/api/v1/coverage") && response.request().method() === "POST");
  await page.getByRole("button", {name: "Coverage", exact: true}).click();
  const packet = await (await response).json();
  await expect(page.locator("body")).toHaveAttribute("data-state", "coverage");
  return packet.projection;
}

for (const mode of ["compact", "structured"]) {
  coverageTest(`coverage ${mode} preserves reported and unreported evidence without a verdict upgrade`, async ({compactURL, structuredURL, page}) => {
    await page.setViewportSize({width: 1920, height: 1080});
    await initializeAxe(page);
    const projection = await openCoverage(page, mode === "compact" ? compactURL : structuredURL);
    expect(projection.proofMode).toBe(mode);
    const boundary = page.locator("details.projection-boundary");
    await expect(boundary).not.toHaveAttribute("open");
    await boundary.locator("summary").click();
    await expect(boundary.locator("li")).toHaveText(projection.nonClaims);
    await boundary.locator("summary").click();
    await expect(page.locator("[data-coverage-summary]")).toHaveText(`1 reported; 1 not reported in 2 matching requirements. Mode: ${mode}.`);
    const rows = page.locator(".coverage-record");
    await expect(rows).toHaveCount(2);
    for (const requirement of projection.requirements) {
      const row = rows.filter({has: page.getByRole("heading", {name: requirement.requirementId, exact: true})});
      const state = row.locator(".coverage-state");
      await expect(row.locator("[data-anchor-id]")).toHaveText(requirement.invariant);
      await expect(row.locator("[data-anchor-id]")).toHaveAttribute("data-anchor-id", requirement.anchor.anchorId);
      if (requirement.coverage === null) {
        await expect(state.locator("dt")).toHaveText(["Coverage"]);
        await expect(state.locator("dd")).toHaveText(["Not reported"]);
      } else {
        const evidence = requirement.coverage;
        await expect(state.locator("dd")).toHaveText([evidence.coverageState, evidence.evidenceClass, evidence.claimLevel, evidence.lifecycleState, String(evidence.scenarioCount), String(evidence.tests.length), String((mode === "compact" ? evidence.declaredWitnessRoutes : evidence.witnessRefs).length)]);
        await row.locator(".coverage-details > summary").click();
        await expect(row.locator(".coverage-details")).toContainText("Route-only evidence remains insufficient.");
        expect(await row.locator(".coverage-details pre").allTextContents()).toEqual([evidence.scenarios, evidence.tests, mode === "compact" ? evidence.declaredWitnessRoutes : evidence.witnessRefs].map(value => JSON.stringify(value, null, 2)));
        await expect(row.locator(".coverage-details")).toContainText(requirement.sourceNonClaims[0]);
      }
    }
    expect((await analyzeAxe(page)).violations).toEqual([]);
    assertAxeTestComplete(page);
  });

  coverageTest(`coverage ${mode} question action uses an explicit anchor without overwriting a draft`, async ({compactURL, structuredURL, page}) => {
    await page.setViewportSize({width: 1920, height: 1080});
    const projection = await openCoverage(page, mode === "compact" ? compactURL : structuredURL);
    const requirement = projection.requirements.find(row => row.coverage !== null);
    const row = page.locator(`.coverage-record[data-requirement-id="${requirement.requirementId}"]`);
    const ask = row.getByRole("button", {name: "Ask about evidence", exact: true});
    const question = page.getByRole("textbox", {name: "Question", exact: true});
    let submissions = 0;
    page.on("request", request => { if (request.url().endsWith("/api/v1/handoff")) submissions++; });
    await ask.focus();
    await page.keyboard.press("Enter");
    await expect(question).toBeFocused();
    await expect(question).toHaveValue(`What evidence supports ${requirement.requirementId}?`);
    for (const draft of [" ", "Keep my question \u{1F680}."]) {
      await question.fill(draft);
      await ask.click();
      await expect(question).toBeFocused();
      await expect(question).toHaveValue(draft);
      await expect(page.locator("#workspace-inspector")).toBeVisible();
    }
    expect(submissions).toBe(0);
    const response = page.waitForResponse(response => response.url().endsWith("/api/v1/handoff"));
    await page.getByRole("button", {name: "Create handoff packet"}).click();
    const raw = await (await response).text();
    await expect(page.locator("#handoff-packet")).toHaveText(raw, {useInnerText: false});
    const packet = JSON.parse(raw);
    expect(packet.annotations.map(annotation => ({id: annotation.anchor.requirementId, quote: annotation.exactQuote, question: annotation.question}))).toEqual([{id: requirement.requirementId, quote: requirement.invariant, question: "Keep my question \u{1F680}."}]);
    await page.locator("#handoff-preview article details > summary").click();
    await expect(page.locator('[data-handoff-detail="found"]')).toHaveText(requirement.invariant);
    expect(submissions).toBe(1);
    await page.getByRole("searchbox").fill("REQ-CONSUMER-001");
    await page.getByRole("button", {name: "Search requirements", exact: true}).click();
    await expect(page.locator("body")).toHaveAttribute("data-state", "coverage");
    await expect(page.locator(".coverage-record")).toHaveAttribute("data-requirement-id", "REQ-CONSUMER-001");
    await expect(page.locator("[data-coverage-summary]")).toHaveText(`0 reported; 1 not reported in 1 matching requirements. Mode: ${mode}.`);
    await expect(page.locator("#handoff-preview")).toBeEmpty();
  });
}

coverageTest("an admitted empty coverage report differs from an absent report", async ({emptyCoverageURL, baseURL, page}) => {
  const projection = await openCoverage(page, emptyCoverageURL);
  expect(projection.proofMode).toBe("compact");
  await expect(page.locator("[data-coverage-summary]")).toHaveText("0 reported; 1 not reported in 1 matching requirements. Mode: compact.");
  await expect(page.locator(".coverage-state dd")).toHaveText(["Not reported"]);
  await openWorkspace(page, baseURL);
  await page.getByRole("button", {name: "Coverage", exact: true}).click();
  await expect(page.locator("body")).toHaveAttribute("data-state", "coverage-unavailable");
  await expect(page.locator("#workspace-content")).toContainText("No admitted coverage report was supplied.");
  await expect(page.locator("[data-coverage-summary]")).toHaveCount(0);
});

coverageTest("a newly committed coverage view preserves independent handoff exclusion", async ({compactURL, page}) => {
  await page.setViewportSize({width: 1920, height: 1080});
  const barrier = Promise.withResolvers();
  const started = Promise.withResolvers();
  let posts = 0;
  await page.route("**/api/v1/handoff", async route => {
    posts++;
    const response = await route.fetch();
    started.resolve();
    await barrier.promise;
    await route.fulfill({response});
  });
  try {
    await openWorkspace(page, compactURL);
    await page.getByRole("button", {name: "Select invariant", exact: true}).first().click();
    const question = page.getByRole("textbox", {name: "Question", exact: true});
    await question.fill("Keep pending question.");
    const submit = page.getByRole("button", {name: "Create handoff packet", exact: true});
    await submit.click();
    await started.promise;
    await page.getByRole("button", {name: "Coverage", exact: true}).click();
    await expect(page.locator("body")).toHaveAttribute("data-state", "coverage");
    const actions = page.locator("[data-evidence-question]");
    await expect(actions).toHaveCount(2);
    expect(await actions.evaluateAll(items => items.every(item => item.disabled))).toBe(true);
    await actions.first().dispatchEvent("click");
    await expect(page.locator("#selected-context li")).toHaveCount(0);
    await expect(question).toHaveValue("Keep pending question.");
    expect(posts).toBe(1);
    barrier.resolve();
    await expect(submit).toBeEnabled();
    await expect(actions.first()).toBeEnabled();
    await expect(page.locator("#handoff-packet")).toBeEmpty();
  } finally { barrier.resolve(); }
});

test("handoff preview, clipboard and real download preserve the exact response carrier", async ({baseURL, page}) => {
  await page.setViewportSize({width: 1920, height: 1080});
  await page.addInitScript(() => {
    globalThis.__copiedPackets = [];
    Object.defineProperty(navigator, "clipboard", {value: {writeText: async text => { globalThis.__copiedPackets.push(text); }}});
    globalThis.__createdURLs = [];
    globalThis.__revokedURLs = [];
    const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = blob => { const url = create(blob); globalThis.__createdURLs.push(url); return url; };
    URL.revokeObjectURL = url => { globalThis.__revokedURLs.push(url); return revoke(url); };
  });
  await openWorkspace(page, baseURL);
  await page.getByRole("button", {name: "Select invariant", exact: true}).click();
  await page.getByRole("textbox", {name: "Question", exact: true}).fill("Keep quote \u{1F680} and context separate.");
  const response = page.waitForResponse(response => response.url().endsWith("/api/v1/handoff"));
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  const raw = await (await response).text();
  await expect(page.locator("#handoff-status")).toHaveText("Handoff packet created.");
  expect(await page.locator("#handoff-packet").textContent()).toBe(raw);
  expect(raw.endsWith("\n")).toBe(true);
  expect(raw.split("\n")).toHaveLength(2);
  await page.getByRole("button", {name: "Copy JSON", exact: true}).click();
  await expect(page.locator("#handoff-status")).toHaveText("Exact handoff JSON copied.");
  expect(await page.evaluate(() => globalThis.__copiedPackets)).toEqual([raw]);
  const downloadable = page.waitForEvent("download");
  await page.getByRole("button", {name: "Download JSON", exact: true}).click();
  const download = await downloadable;
  expect(download.suggestedFilename()).toBe("proofkit-question.json");
  const chunks = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk);
  expect(Buffer.concat(chunks).equals(Buffer.from(raw))).toBe(true);
  await expect.poll(() => page.evaluate(() => globalThis.__revokedURLs.length)).toBe(1);
  expect(await page.evaluate(() => globalThis.__revokedURLs)).toEqual(await page.evaluate(() => globalThis.__createdURLs));
  await page.getByRole("button", {name: "Diff", exact: true}).click();
  await expect(page.locator("#handoff-preview")).toBeEmpty();
  await expect(page.locator("#handoff-packet")).toBeEmpty();
});

test("unavailable export effects preserve a selectable exact JSON fallback", async ({baseURL, page}) => {
  await page.setViewportSize({width: 1920, height: 1080});
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {value: {writeText: async () => { throw new Error("private clipboard detail"); }}});
    URL.createObjectURL = () => { throw new Error("private download detail"); };
  });
  await openWorkspace(page, baseURL);
  await page.getByRole("button", {name: "Select invariant", exact: true}).click();
  const question = page.getByRole("textbox", {name: "Question", exact: true});
  await question.fill("Keep my draft and exact packet.");
  const response = page.waitForResponse(response => response.url().endsWith("/api/v1/handoff"));
  await page.getByRole("button", {name: "Create handoff packet"}).click();
  const raw = await (await response).text();
  const disclosure = page.locator("#handoff-output details").filter({has: page.locator("#handoff-packet")});
  for (const effect of ["Copy", "Download"]) {
    if (await disclosure.getAttribute("open") !== null) await disclosure.locator("summary").click();
    await page.getByRole("button", {name: `${effect} JSON`, exact: true}).click();
    await expect(disclosure).toHaveAttribute("open");
    expect(await page.locator("#handoff-packet").textContent()).toBe(raw);
    await expect(page.locator("#handoff-status")).toHaveText(`${effect === "Copy" ? "Clipboard" : effect} unavailable. Exact JSON remains available below.`);
  }
  await expect(question).toHaveValue("Keep my draft and exact packet.");
  await expect(page.locator("body")).not.toContainText("private clipboard detail");
  await expect(page.locator("body")).not.toContainText("private download detail");
});

for (const outcome of ["resolved", "rejected"]) for (const newer of ["view", "packet"]) {
  test(`a late ${outcome} clipboard effect cannot label a newer ${newer}`, async ({baseURL, page}) => {
    await page.setViewportSize({width: 1920, height: 1080});
    await page.addInitScript(() => {
      globalThis.__clipboardCalls = [];
      Object.defineProperty(navigator, "clipboard", {value: {writeText: text => {
        let resolve, reject;
        const promise = new Promise((accept, deny) => { resolve = accept; reject = deny; });
        globalThis.__clipboardCalls.push({text, resolve, reject, settled: promise.catch(() => {})});
        return promise;
      }}});
    });
    await openWorkspace(page, baseURL);
    await page.getByRole("button", {name: "Select invariant"}).click();
    const question = page.getByRole("textbox", {name: "Question", exact: true});
    await question.fill("Do not erase this draft.");
    const firstResponse = page.waitForResponse(response => response.url().endsWith("/api/v1/handoff"));
    await page.getByRole("button", {name: "Create handoff packet"}).click();
    const firstRaw = await (await firstResponse).text();
    await page.getByRole("button", {name: "Copy JSON", exact: true}).click();
    await expect(page.getByRole("button", {name: "Copy JSON", exact: true})).toBeDisabled();
    expect(await page.evaluate(() => globalThis.__clipboardCalls.map(call => call.text))).toEqual([firstRaw]);
    let secondRaw;
    if (newer === "view") {
      await page.getByRole("button", {name: "Diff", exact: true}).click();
      await expect(page.locator("body")).toHaveAttribute("data-state", "diff");
    } else {
      await question.fill("Preserve packet B and its draft.");
      const secondResponse = page.waitForResponse(response => response.url().endsWith("/api/v1/handoff"));
      await page.getByRole("button", {name: "Create handoff packet"}).click();
      secondRaw = await (await secondResponse).text();
      expect(secondRaw).not.toBe(firstRaw);
      await expect(page.locator("#handoff-status")).toHaveText("Handoff packet created.");
      expect(await page.locator("#handoff-packet").textContent()).toBe(secondRaw);
      await page.getByRole("button", {name: "Copy JSON", exact: true}).click();
      await expect(page.getByRole("button", {name: "Copy JSON", exact: true})).toBeDisabled();
      expect(await page.evaluate(() => globalThis.__clipboardCalls.map(call => call.text))).toEqual([firstRaw, secondRaw]);
    }
    await page.evaluate(async outcome => {
      const call = globalThis.__clipboardCalls[0];
      if (outcome === "resolved") call.resolve(); else call.reject(new Error("private clipboard failure"));
      await call.settled;
    }, outcome);
    if (newer === "view") {
      await expect(page.locator("#handoff-status")).toHaveText("No source-bound text selected.");
      await expect(page.locator("#handoff-preview")).toBeEmpty();
      await expect(question).toHaveValue("Do not erase this draft.");
    } else {
      await expect(page.locator("#handoff-status"), "packet B status ignores old Copy settlement").toHaveText("Handoff packet created.");
      expect(await page.locator("#handoff-packet").textContent()).toBe(secondRaw);
      await expect(question).toHaveValue("Preserve packet B and its draft.");
      await expect(page.getByRole("button", {name: "Copy JSON", exact: true})).toBeDisabled();
      await expect(page.getByRole("button", {name: "Download JSON", exact: true})).toBeEnabled();
      await page.evaluate(async () => { const call = globalThis.__clipboardCalls[1]; call.resolve(); await call.settled; });
      await expect(page.locator("#handoff-status")).toHaveText("Exact handoff JSON copied.");
      expect(await page.locator("#handoff-packet").textContent(), "settled packet B carrier").toBe(secondRaw);
      await expect(question).toHaveValue("Preserve packet B and its draft.");
      await expect(page.getByRole("button", {name: "Download JSON", exact: true})).toBeEnabled();
      await expect(page.getByRole("button", {name: "Copy JSON", exact: true})).toBeEnabled();
    }
    await expect(page.locator("body")).not.toContainText("private clipboard failure");
  });
}
