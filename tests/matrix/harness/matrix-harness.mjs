import {spawn} from "node:child_process";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {expect, test as base} from "@playwright/test";

import {startBrowserServer, withNavigationRequestBarrier} from "../../../scripts/browser-proof-execution.mjs";
import {
  SecurityMonitor, axeOracle, contentOracle, controlContrastOracle, judgeDocumentHeaders, judgeSecurityEvents, keyboardOracle,
  matrixInitScript, reflowOracle, settleSecurityEvents,
} from "./oracles.mjs";

// The accessibility matrix harness. A cell is one view in one engine, color
// scheme and mode; every cell runs every oracle. The two families, static
// renderings and workspace tabs, each run as their own witness command and
// write their own record; both read this harness.

const fontConfig = readFileSync(new URL("../../visual/fonts.conf", import.meta.url));
const staticScriptDigest = createHash("sha256").update(readFileSync(new URL("../../../internal/kernel/browserdoc/browser.js", import.meta.url))).digest("base64");
export const expectedCSP = Object.freeze({
  static: `default-src 'none'; script-src 'sha256-${staticScriptDigest}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  workspace: "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
});
// Beyond the runtime harness projects, the matrix Firefox project adds only
// the preference that stops Firefox's own /favicon.ico request, which the
// static CSP refuses; the site-icon control proves what it removes and keeps.
export const firefoxPreferences = Object.freeze({"browser.chrome.site_icons": false, "fission.webContentIsolationStrategy": 1});

export const schemes = Object.freeze(["light", "dark"]);
// Five modes: 320 and 1440 CSS px, each also at a 200% root font size set
// through the CSSOM, and full-page zoom emulated as a 720 CSS px viewport
// with device scale factor 2, a 1440x900 window at 200%.
export const modes = Object.freeze([
  {id: "320", viewport: {width: 320, height: 900}, deviceScaleFactor: 1, rootFontSize: null, narrow: true},
  {id: "1440", viewport: {width: 1440, height: 900}, deviceScaleFactor: 1, rootFontSize: null, narrow: false},
  {id: "320-root-200", viewport: {width: 320, height: 900}, deviceScaleFactor: 1, rootFontSize: "200%", narrow: true},
  {id: "1440-root-200", viewport: {width: 1440, height: 900}, deviceScaleFactor: 1, rootFontSize: "200%", narrow: false},
  {id: "720-dsf-2", viewport: {width: 720, height: 450}, deviceScaleFactor: 2, rootFontSize: null, narrow: true},
].map((mode) => Object.freeze(mode)));
export const narrowModes = Object.freeze(modes.filter((mode) => mode.narrow));

// Five static renderings, each in Cards and Table modes. Each record
// selector names the records of the mode; the expected count is the fixture's.
export const staticRenderings = Object.freeze({
  "static-source": {selector: "--static-source", heading: "Requirement Source View: browser.fixture.requirements", records: 5},
  "static-spec-tree": {selector: "--static-tree", heading: "Requirement Spec Tree View: browser.fixture.tree", records: 1},
  "static-proof-structured": {selector: "--static-proof", heading: "Requirement Proof View: proofkit.browser.coverage.binding", records: 1},
  "static-proof-compact": {selector: "--static-proof-compact", heading: "Compact Requirement Proof View: proofkit.browser.coverage.compact", records: 1},
  "static-coverage": {selector: "--static-coverage", heading: "Requirement Coverage View: proofkit.browser.coverage.view", records: 1},
});
export const staticViews = Object.freeze(Object.keys(staticRenderings).flatMap((name) => [`${name}-cards`, `${name}-table`]));

// Four workspace tabs over the workspace fixture that carries coverage. The
// fixture holds two requirements, two coverage rows, one diff change, and
// seven graph nodes and seven relations, which the Traceability record list
// holds and whose nodes the canvas shows again.
export const workspaceSelector = "--coverage-structured";
export const workspaceHeading = "browser.fixture.workspace";
export const workspaceTabs = Object.freeze({
  "workspace-specifications": {view: "specifications", state: "specifications", records: "#workspace-content article", expectedRecords: 2},
  "workspace-coverage": {view: "coverage", state: "coverage", records: ".coverage-record", expectedRecords: 2},
  "workspace-diff": {view: "diff", state: "diff", records: "#workspace-content article", expectedRecords: 1},
  "workspace-traceability": {view: "graph", state: "graph", records: ".graph-records [data-identity], .graph-node", expectedRecords: 21},
});
export const workspaceViews = Object.freeze(Object.keys(workspaceTabs));
// Two dialog states, only in the narrow modes, where the panels are modal.
export const workspaceDialogs = Object.freeze({
  "workspace-navigation-dialog": {
    opener: "#open-navigation", panel: "#workspace-navigation",
    // Native select options have no document line boxes. Their labels, the
    // navigation records and every other text-bearing panel section do.
    records: "#workspace-navigation > .panel-heading, #workspace-search > label, #reset-filters, #selected-scope, #workspace-navigation > h3, #all-requirements, #spec-navigation",
    expectedRecords: 9,
  },
  "workspace-inspector-dialog": {opener: "#open-inspector", panel: "#workspace-inspector", records: "#workspace-inspector", expectedRecords: 1},
});

export function cellTitle(view, scheme) {
  return `${view} ${scheme}`;
}

export const test = base.extend({
  engineEvidence: [async ({browser, browserName, channel, connectOptions, launchOptions}, use, testInfo) => {
    testInfo.annotations.push({type: "proofkit.browser-engine", description: browserName});
    testInfo.annotations.push({type: "proofkit.browser-version", description: browser.version()});
    expect(browserName).toBe(testInfo.project.name);
    expect(channel).toBeUndefined();
    expect(connectOptions).toBeUndefined();
    expect(launchOptions.channel).toBeUndefined();
    expect(launchOptions.executablePath).toBeUndefined();
    expect(launchOptions.firefoxUserPrefs).toEqual(browserName === "firefox" ? firefoxPreferences : undefined);
    expect(launchOptions.args).toBeUndefined();
    expect(testInfo.retry, "matrix cells run with zero retries").toBe(0);
    // Every browser reads the run directory's copy of tests/visual/fonts.conf,
    // the recorded font mapping, which the writer set before any launch.
    const fontConfigCopy = resolve(testInfo.project.outputDir, "..", "fonts.conf");
    expect(launchOptions.env, "browsers must inherit the environment that names the font configuration copy").toBeUndefined();
    expect(process.env.FONTCONFIG_FILE, "FONTCONFIG_FILE must name the run directory's font configuration copy").toBe(fontConfigCopy);
    expect(readFileSync(fontConfigCopy).equals(fontConfig), "the run directory's font configuration must equal tests/visual/fonts.conf").toBe(true);
    await use();
  }, {auto: true}],
  matrixServers: [async ({}, use, workerInfo) => {
    // The proof runner publishes this snapshot-built binary before workers start.
    const binary = resolve(workerInfo.project.outputDir, "..", "server");
    const servers = new Map();
    try {
      await use({
        async url(selector) {
          if (!servers.has(selector)) {
            servers.set(selector, startBrowserServer(binary, {spawnProcess: (path, args, options) => spawn(path, [selector, ...args], options)}));
          }
          return (await servers.get(selector)).url;
        },
      });
    } finally {
      const failures = [];
      for (const server of servers.values()) {
        try { await (await server).stop(); } catch (error) { failures.push(error); }
      }
      if (failures.length > 0) throw new AggregateError(failures, "matrix fixture servers did not stop");
    }
  }, {scope: "worker"}],
  // Every page carries the security monitor and the init script before its
  // first navigation.
  security: [async ({page}, use) => {
    const monitor = await SecurityMonitor.attach(page);
    await page.addInitScript({content: matrixInitScript});
    await use(monitor);
  }, {auto: true}],
});

// navigate opens a fixture document, checks its exact security headers and
// then applies the color scheme in the document under test: pinned Firefox
// drops color-scheme emulation at a navigation into or out of a document
// served with Cross-Origin-Opener-Policy: same-origin, so emulation follows
// the last navigation and matchMedia proves it.
export async function navigate(page, url, profile, heading, scheme) {
  const response = await withNavigationRequestBarrier(page, () => page.goto(url, {waitUntil: "load"}));
  if (response === null || response.status() !== 200) throw new Error("matrix view navigation did not return 200");
  judgeDocumentHeaders(response.headers(), expectedCSP[profile]);
  await emulateSchemeInEffect(page, scheme);
  await expect(page.getByRole("heading", {name: heading, exact: true})).toBeVisible();
}

export async function emulateSchemeInEffect(page, scheme) {
  await page.emulateMedia({colorScheme: scheme});
  const observed = await page.evaluate((colorScheme) => ({protocol: location.protocol, matches: matchMedia(`(prefers-color-scheme: ${colorScheme})`).matches}), scheme);
  expect(observed, `color scheme ${scheme} must be in effect in the document under test`).toEqual({protocol: "http:", matches: true});
}

async function applyRootFontSize(page, mode) {
  if (mode.rootFontSize === null) return;
  // The CSSOM sets the root size; an injected style element would violate
  // the workspace CSP.
  await page.evaluate((size) => { document.documentElement.style.fontSize = size; }, mode.rootFontSize);
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).fontSize)).toBe("32px");
}

export async function settle(page) {
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
  });
}

// openStaticView renders one static view; the mode is chosen without moving
// focus, so the Tab walk starts at the document start.
export async function openStaticView(page, servers, view, scheme, mode) {
  const match = view.match(/^(.*)-(cards|table)$/);
  const rendering = match === null ? undefined : staticRenderings[match[1]];
  if (rendering === undefined) throw new Error(`unknown static view ${view}`);
  await navigate(page, await servers.url(rendering.selector), "static", rendering.heading, scheme);
  await applyRootFontSize(page, mode);
  if (match[2] === "table") {
    await page.locator("#proofkit-view-mode").evaluate((select) => {
      select.value = "table";
      select.dispatchEvent(new Event("change", {bubbles: true}));
    });
  }
  await expect(page.locator("#proofkit-view-mode")).toHaveValue(match[2]);
  await expect(page.locator(match[2] === "table" ? "[data-proofkit-table-section]" : "[data-proofkit-card-section]")).toBeVisible();
  await settle(page);
  return {records: match[2] === "table" ? "[data-proofkit-table-row]" : "[data-proofkit-card]", expectedRecords: rendering.records};
}

// openWorkspaceView renders one workspace tab; a programmatic click selects
// it without leaving focus or hover behind.
export async function openWorkspaceView(page, servers, view, scheme, mode, selector = workspaceSelector) {
  const tab = workspaceTabs[view];
  if (tab === undefined) throw new Error(`unknown workspace view ${view}`);
  await navigate(page, await servers.url(selector), "workspace", workspaceHeading, scheme);
  await applyRootFontSize(page, mode);
  await expect(page.locator("body")).toHaveAttribute("data-state", "specifications");
  await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
  if (tab.view !== "specifications") {
    await page.locator(`[data-view="${tab.view}"]`).evaluate((button) => button.click());
    await expect(page.locator("body")).toHaveAttribute("data-state", tab.state);
    await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
  }
  await settle(page);
  return {records: tab.records, expectedRecords: tab.expectedRecords};
}

// openWorkspaceDialog opens a panel from its toolbar button by keyboard; the
// modal dialog then holds focus, and Escape must return it to the opener.
export async function openWorkspaceDialog(page, dialog) {
  const {opener, panel, records, expectedRecords} = workspaceDialogs[dialog];
  await page.locator(opener).focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(`${panel}:modal`)).toHaveCount(1);
  await settle(page);
  return {records, expectedRecords};
}

export async function closeDialogByEscape(page, dialog) {
  const {opener, panel} = workspaceDialogs[dialog];
  await page.keyboard.press("Escape");
  await expect(page.locator(`${panel}`)).not.toHaveJSProperty("open", true);
  await expect(page.locator("dialog:modal")).toHaveCount(0);
  await expect(page.locator(opener), "Escape must return focus to the dialog's opener").toBeFocused();
}

export async function judgeSecurityNow(page, security) {
  await settleSecurityEvents(page);
  judgeSecurityEvents(security.observation());
}

// runOracles runs oracles 1 to 4 and 6 on the current state of a cell.
export async function runOracles(page, security, {records, expectedRecords}, testInfo) {
  const browserName = testInfo.project.name;
  const axe = await axeOracle(page);
  const controlContrast = await controlContrastOracle(page);
  const reflow = await reflowOracle(page);
  const content = await contentOracle(page, records, expectedRecords);
  const keyboard = await keyboardOracle(page, browserName);
  await settleSecurityEvents(page);
  judgeSecurityEvents(security.observation());
  await testInfo.attach("matrix-cell", {
    body: JSON.stringify({axe, controlContrast, overflowing: reflow.overflowing.length, content, keyboard}),
    contentType: "application/json",
  });
}
