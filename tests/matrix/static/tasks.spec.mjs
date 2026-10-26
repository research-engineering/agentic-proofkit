import {expect} from "@playwright/test";

import {judgeSecurityNow, modes, navigate, staticRenderings, test} from "../harness/matrix-harness.mjs";

// Reader tasks in the static renderings, in every engine, through the
// controls a reader uses: search, disclosure, in-page links and filters.
const mode = modes.find((candidate) => candidate.id === "1440");
test.use({viewport: mode.viewport, deviceScaleFactor: mode.deviceScaleFactor});

async function open(page, servers, rendering, selector = staticRenderings[rendering].selector, heading = staticRenderings[rendering].heading) {
  await navigate(page, await servers.url(selector), "static", heading, "light");
}

test("a reader finds a requirement by searching the static source view", async ({page, matrixServers, security}) => {
  await open(page, matrixServers, "static-source");
  await page.getByRole("searchbox", {name: "Search"}).fill("needle");
  await expect(page.locator("#proofkit-visible-count")).toHaveText("1");
  const card = page.locator("[data-proofkit-card]:visible");
  await expect(card.locator(".proofkit-id")).toHaveText(["REQ-STATIC-2"]);
  await expect(card.locator(".proofkit-title")).toHaveText(["ASCII Needle"]);
  await expect(card).toBeVisible();
  await judgeSecurityNow(page, security);
});

test("a reader opens a requirement's scenario in the static source view", async ({page, matrixServers, security}) => {
  await open(page, matrixServers, "static-source");
  const card = page.locator("[data-proofkit-card]").filter({has: page.locator(".proofkit-id", {hasText: "REQ-CONSUMER-001"})});
  await card.getByRole("link", {name: "SCN-BROWSER", exact: true}).click();
  const scenario = card.locator("details").filter({has: page.locator(":scope > summary", {hasText: "SCN-BROWSER"})});
  expect(new URL(page.url()).hash).toBe(`#${await scenario.getAttribute("id")}`);
  await expect(scenario.locator(":scope > summary")).toBeInViewport();
  await expect(scenario).toHaveJSProperty("open", false);
  await scenario.locator(":scope > summary").press("Enter");
  await expect(scenario).toHaveJSProperty("open", true);
  await expect(scenario.getByText("1. Open the source.", {exact: true})).toBeVisible();
  await expect(scenario.getByText("The original requirement ID remains visible.", {exact: true})).toBeVisible();
  await judgeSecurityNow(page, security);
});

test("a reader follows a proof hierarchy link to the binding's witness in the static proof view", async ({page, matrixServers, security}) => {
  for (const initialMode of ["cards", "table"]) {
    await open(page, matrixServers, "static-proof-structured");
    await page.getByLabel("View", {exact: true}).selectOption(initialMode);
    const query = initialMode === "table" ? "no-matching-hierarchy-record" : "REQ-BROWSER";
    await page.getByRole("searchbox", {name: "Search"}).fill(query);
    await expect(page.locator("#proofkit-visible-count")).toHaveText(initialMode === "table" ? "0" : "1");
    await page.getByRole("navigation", {name: "Specification hierarchy"}).getByRole("link", {name: "browser.coverage", exact: true}).click();
    await expect(page.getByLabel("View", {exact: true})).toHaveValue("cards");
    await expect(page.getByRole("searchbox", {name: "Search"})).toHaveValue(initialMode === "table" ? "" : query);
    const group = page.locator("[data-proofkit-card-group]").filter({has: page.getByRole("heading", {name: "Owner: browser.coverage 1"})});
    expect(new URL(page.url()).hash).toBe(`#${await group.getAttribute("id")}`);
    await expect(group.getByRole("heading", {name: "Owner: browser.coverage 1"})).toBeInViewport();
    const card = group.locator("[data-proofkit-card]");
    await expect(card.locator(".proofkit-id")).toHaveText("REQ-BROWSER-COVERAGE-001");
    await card.locator("summary", {hasText: "Scenarios and test witnesses"}).click();
    const binding = card.locator(".scenario-block").filter({has: page.getByRole("heading", {name: "proofkit.browser.coverage.scenario"})});
    await expect(binding.locator("dt", {hasText: "Witness id"}).locator("+ dd")).toHaveText("proofkit.browser.coverage.witness");
    await expect(binding.locator("dt", {hasText: "Witness path"}).locator("+ dd")).toHaveText("internal/browser_coverage_test.go");
    await expect(binding).toBeVisible();
    await judgeSecurityNow(page, security);
  }
});

test("a reader sees the coverage gap of a static coverage view with an uncovered requirement", async ({page, matrixServers, security}) => {
  await open(page, matrixServers, "static-coverage", "--static-coverage-gap");
  const summary = page.getByRole("region", {name: "View summary"});
  await expect(summary.locator("dt", {hasText: "Coverage report state"}).locator("+ dd")).toHaveText("failed");
  await expect(summary.locator("dt", {hasText: "Failures"}).locator("+ dd")).toHaveText("1");
  await page.getByLabel("Coverage", {exact: true}).selectOption("missing_proof_binding_route");
  await expect(page.locator("#proofkit-visible-count")).toHaveText("1");
  const card = page.locator("[data-proofkit-card]:visible");
  await expect(card.locator(".proofkit-id")).toHaveText(["REQ-BROWSER-COVERAGE-002"]);
  await expect(card.locator("dt", {hasText: "Tests"}).locator("+ dd")).toHaveText("none");
  await card.locator("summary", {hasText: "Test evidence, scenarios, failures, and non-claims"}).click();
  await expect(card.getByText("missing_proof_binding_route:REQ-BROWSER-COVERAGE-002", {exact: true})).toBeVisible();
  await judgeSecurityNow(page, security);
});
