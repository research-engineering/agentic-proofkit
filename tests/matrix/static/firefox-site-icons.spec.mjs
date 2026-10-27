import {expect} from "@playwright/test";

import {expectedCSP, firefoxPreferences, modes, openStaticView, staticRenderings, test} from "../harness/matrix-harness.mjs";
import {SecurityMonitor, judgeDocumentHeaders, judgeSecurityEvents, matrixInitScript} from "../harness/oracles.mjs";

// The Firefox site-icon control. Without browser.chrome.site_icons=false,
// pinned Firefox requests /favicon.ico for a static view on its own, the
// static CSP refuses it, and the security oracle sees the refusal; with the
// preference, which only the matrix and visual projects set, Firefox makes no
// such request in the same view, while a page-initiated /favicon.ico load is
// still refused and seen (the security control of this family).
const mode = modes.find((candidate) => candidate.id === "1440");
const isFavicon = (violation) => violation.effectiveDirective === "img-src" && new URL(violation.blockedURI).pathname === "/favicon.ico";

test("Firefox's own favicon request is refused and seen without the site-icon preference and absent with it", async ({playwright, page, matrixServers, security}) => {
  const url = await matrixServers.url(staticRenderings["static-source"].selector);
  const {"browser.chrome.site_icons": siteIcons, ...withoutSiteIcons} = firefoxPreferences;
  expect(siteIcons).toBe(false);
  const browser = await playwright.firefox.launch({firefoxUserPrefs: withoutSiteIcons});
  let elapsed;
  try {
    const context = await browser.newContext({viewport: mode.viewport});
    const probe = await context.newPage();
    const monitor = await SecurityMonitor.attach(probe);
    await probe.addInitScript({content: matrixInitScript});
    const started = Date.now();
    const response = await probe.goto(url, {waitUntil: "load"});
    judgeDocumentHeaders(response.headers(), expectedCSP.static);
    await expect.poll(() => monitor.observation().violations.filter(isFavicon).length, {
      message: "without the preference Firefox must request /favicon.ico and the static CSP must refuse it",
      timeout: 15_000,
    }).toBeGreaterThan(0);
    elapsed = Date.now() - started;
    expect(() => judgeSecurityEvents(monitor.observation())).toThrow("security: the page raised a console error, a page error or a securitypolicyviolation event");
    await context.close();
  } finally {
    await browser.close();
  }
  // The project browser carries the preference: the same view, observed for
  // twice as long as the refusal took to arrive without it, raises nothing.
  await openStaticView(page, matrixServers, "static-source-cards", "light", mode);
  await page.waitForTimeout(Math.max(2 * elapsed, 1_000));
  judgeSecurityEvents(security.observation());
});
