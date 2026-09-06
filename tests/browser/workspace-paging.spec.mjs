import {expect} from "@playwright/test";
import {pagingTest as test} from "./workspace-test-harness.mjs";
import {openWorkspace} from "./workspace-navigation-harness.mjs";

for (const view of ["diff", "graph"]) {
  test(`${view} Retry preserves every non-default page operand through native admission`, async ({pagingURL, page}) => {
    const failedAttempts = [];
    await page.route(`**/api/v1/${view}`, async route => {
      const request = route.request();
      const body = request.postDataJSON();
      const target = body.query.offset === 1 && (view === "diff" || body.query.edgeOffset === 1);
      if (target) {
        failedAttempts.push({method: request.method(), path: new URL(request.url()).pathname, body});
        if (failedAttempts.length === 1) return route.fulfill({status: 503, body: "private page detail"});
      }
      // A smaller admitted server window exercises client pagination without
      // inventing graph edges, diff changes, identities, or response counts.
      const query = {...body.query, maxRecords: 1, ...view === "graph" ? {maxEdges: 1} : {}};
      const response = await route.fetch({postData: {...body, query}});
      return route.fulfill({response});
    });
    await openWorkspace(page, pagingURL);
    await expect(page.getByRole("button", {name: "Select invariant", exact: true})).toBeVisible();
    await page.getByRole("button", {name: view === "diff" ? "Diff" : "Traceability", exact: true}).click();
    await page.getByRole("button", {name: `Next ${view} page`, exact: true}).click();
    if (view === "graph") await page.getByRole("button", {name: "Next graph relation page", exact: true}).click();
    await expect(page.getByRole("button", {name: "Retry", exact: true})).toBeVisible();
    expect(failedAttempts).toHaveLength(1);
    await page.getByRole("searchbox").fill("Unsubmitted text must not change this operation.");
    await page.getByRole("button", {name: "Retry", exact: true}).click();
    await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
    await expect(page.getByRole("button", {name: "Retry", exact: true})).toHaveCount(0);
    expect(failedAttempts).toHaveLength(2);
    for (const attempt of failedAttempts) {
      expect(attempt).toEqual({
        method: "POST", path: `/api/v1/${view}`,
        body: {
          requestId: expect.stringMatching(new RegExp(`^browser\\.${view}\\.`)),
          snapshotId: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
          query: view === "diff" ? {offset: 1, maxRecords: 512} : {offset: 1, edgeOffset: 1, maxRecords: 64, maxEdges: 128},
        },
      });
    }
    expect(failedAttempts[1].body.snapshotId).toBe(failedAttempts[0].body.snapshotId);
    expect(failedAttempts[1].body.requestId).not.toBe(failedAttempts[0].body.requestId);
    if (view === "diff") {
      await expect(page.locator("[data-diff-summary]")).toHaveText("Changes: 1; requirements: 1; risk changes: 1; lifecycle changes: 0.");
      await expect(page.getByRole("list", {name: "Change classes on this page"})).toHaveText("scalar_changed: 1");
      await expect(page.locator("#workspace-content article > p").first()).toHaveText("/requirements/REQ-CONSUMER-001/riskClass");
      await page.getByText("Before and after", {exact: true}).click();
      await expect(page.locator("#workspace-content article pre")).toHaveText('"high"\n->\n"medium"');
    } else {
      const nodes = page.getByRole("list", {name: "Admitted traceability nodes"}).locator(":scope > li");
      await expect(nodes).toHaveCount(2);
      expect(await nodes.evaluateAll(rows => rows.map(row => row.dataset.identity))).toEqual(["code:code.repository", "code:code.retry"]);
      const edges = page.getByRole("list", {name: "Admitted traceability edges"}).locator(":scope > li");
      await expect(edges).toHaveCount(1);
      await expect(edges.locator("summary")).toHaveText("contains: code:code.repository -> code:code.retry");
    }
  });
}
