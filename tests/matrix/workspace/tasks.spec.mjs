import {expect} from "@playwright/test";

import {judgeSecurityNow, modes, navigate, workspaceHeading, workspaceSelector, test} from "../harness/matrix-harness.mjs";

// Reader tasks in the workspace, in every engine, through the controls a
// reader uses: the requirement search, the view tabs, the Traceability
// records and inspector, and disclosures.
const mode = modes.find((candidate) => candidate.id === "1440");
test.use({viewport: mode.viewport, deviceScaleFactor: mode.deviceScaleFactor});

async function open(page, servers, selector = workspaceSelector) {
  await navigate(page, await servers.url(selector), "workspace", workspaceHeading, "light");
  await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
}

async function openTab(page, name, state) {
  await page.getByRole("navigation", {name: "Workspace views"}).getByRole("button", {name, exact: true}).click();
  await expect(page.locator("body")).toHaveAttribute("data-state", state);
  await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
}

test("a reader finds a requirement by searching the workspace", async ({page, matrixServers, security}) => {
  await open(page, matrixServers);
  await expect(page.locator("#workspace-content article")).toHaveCount(2);
  await page.getByRole("searchbox", {name: "Search requirements"}).fill("retry");
  await page.getByRole("button", {name: "Search requirements", exact: true}).click();
  const article = page.locator("#workspace-content article");
  await expect(article).toHaveCount(1);
  await expect(article.getByRole("heading", {name: "REQ-CONSUMER-001", exact: true})).toBeVisible();
  await expect(article.locator("[data-anchor-id]")).toHaveText("The system preserves semantic identity for retry \u{1F680}.");
  await judgeSecurityNow(page, security);
});

test("a reader follows a Traceability record to its relation in the workspace", async ({page, matrixServers, security}) => {
  await open(page, matrixServers);
  await openTab(page, "Traceability", "graph");
  const record = page.locator('.graph-records button[data-graph-select="code:code.retry"]');
  await record.focus();
  await page.keyboard.press("Enter");
  await expect(record).toHaveAttribute("aria-pressed", "true");
  const inspector = page.getByRole("region", {name: "Selected graph node"});
  await expect(inspector.getByRole("heading", {name: "Retry", exact: true})).toBeVisible();
  const incoming = inspector.locator("h4", {hasText: "Incoming relations in this page"}).locator("+ ul > li")
    .filter({has: page.locator("summary", {hasText: "contains: code:code.repository -> code:code.retry"})});
  await expect(incoming).toHaveCount(1);
  const relation = incoming.locator("details");
  await relation.locator("summary").click();
  await expect(relation).toHaveJSProperty("open", true);
  await expect(relation.locator("dt", {hasText: "fromNodeId"}).locator("+ dd")).toHaveText("code:code.repository");
  await judgeSecurityNow(page, security);
});

test("a reader sees that an admitted empty coverage report covers no requirement", async ({page, matrixServers, security}) => {
  await open(page, matrixServers, "--coverage-empty");
  await openTab(page, "Coverage", "coverage");
  await expect(page.locator("[data-coverage-summary]")).toHaveText("0 reported; 1 not reported in 1 matching requirements. Mode: compact.");
  const row = page.locator(".coverage-record");
  await expect(row).toHaveCount(1);
  await expect(row.locator(".coverage-state dt")).toHaveText(["Coverage"]);
  await expect(row.locator(".coverage-state dd")).toHaveText(["Not reported"]);
  await expect(row).toBeVisible();
  await judgeSecurityNow(page, security);
});

test("a reader reads a requirement change in the workspace diff", async ({page, matrixServers, security}) => {
  await open(page, matrixServers);
  await openTab(page, "Diff", "diff");
  const change = page.locator("#workspace-content article");
  await expect(change).toHaveCount(1);
  // The heading names the changed requirement and carries its change class as a badge.
  const heading = change.getByRole("heading", {name: /^requirement REQ-CONSUMER-001\s*scalar_changed$/});
  await expect(heading).toBeVisible();
  await expect(heading.locator(".status-badge")).toHaveText("scalar_changed");
  await expect(change.getByText("/requirements/REQ-CONSUMER-001/invariant", {exact: true})).toBeVisible();
  await change.locator("summary", {hasText: "Before and after"}).click();
  await expect(change.locator("pre")).toContainText("retry");
  await expect(change.locator("pre")).toBeVisible();
  await judgeSecurityNow(page, security);
});
