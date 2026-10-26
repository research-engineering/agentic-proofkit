import {spawn} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import {dirname, resolve, sep} from "node:path";
import {fileURLToPath} from "node:url";
import {expect, test as base} from "@playwright/test";

import {startBrowserServer, withNavigationRequestBarrier} from "../../scripts/browser-proof-execution.mjs";
import {canonicalRGBADigest, decodePNG} from "./exact-png.mjs";

// The visual reference harness. It captures each view twice, requires both
// captures to be byte-equal, decodes the capture and compares its canonical
// RGBA digest and dimensions with the admitted inventory entry. References are
// digests only; every capture is written below the run directory, never into
// the test directory.

export const clipHeight = 2400;
export const viewportHeight = 900;
export const readmeViewport = Object.freeze({width: 1440, height: 960});

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const testDirectory = resolve(repositoryRoot, "tests/visual");
const environment = JSON.parse(readFileSync(new URL("./environment.json", import.meta.url), "utf8"));
const fontConfig = readFileSync(new URL("./fonts.conf", import.meta.url));
const inventory = JSON.parse(readFileSync(new URL("./references.json", import.meta.url), "utf8"));
const staticScriptDigest = createHash("sha256").update(readFileSync(new URL("../../internal/kernel/browserdoc/browser.js", import.meta.url))).digest("base64");
const expectedCSP = Object.freeze({
  static: `default-src 'none'; script-src 'sha256-${staticScriptDigest}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  workspace: "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
});
const firefoxPreferences = Object.freeze({"browser.chrome.site_icons": false, "fission.webContentIsolationStrategy": 1});
// Chromium re-rasters only invalidated tile regions by default; which regions
// an asynchronous state change invalidates varies between launches and
// changed rounded-corner pixels by one unit. Full tile raster is deterministic.
const chromiumArguments = Object.freeze(["--disable-partial-raster"]);

// Five static renderings, each shown in Cards and Table modes.
const staticRenderings = Object.freeze({
  "static-source": {selector: "--static-source", heading: "Requirement Source View: browser.fixture.requirements"},
  "static-spec-tree": {selector: "--static-tree", heading: "Requirement Spec Tree View: browser.fixture.tree"},
  "static-proof-structured": {selector: "--static-proof", heading: "Requirement Proof View: proofkit.browser.coverage.binding"},
  "static-proof-compact": {selector: "--static-proof-compact", heading: "Compact Requirement Proof View: proofkit.browser.coverage.compact"},
  "static-coverage": {selector: "--static-coverage", heading: "Requirement Coverage View: proofkit.browser.coverage.view"},
});
// Four workspace tabs over the workspace fixture that carries coverage.
const workspaceTabs = Object.freeze({
  "workspace-specifications": {view: "specifications", state: "specifications"},
  "workspace-coverage": {view: "coverage", state: "coverage"},
  "workspace-diff": {view: "diff", state: "diff"},
  "workspace-traceability": {view: "graph", state: "graph"},
});
const workspaceSelector = "--coverage-structured";
const workspaceHeading = "browser.fixture.workspace";

export const viewNames = Object.freeze([
  ...Object.keys(staticRenderings).flatMap((name) => [`${name}-cards`, `${name}-table`]),
  ...Object.keys(workspaceTabs),
]);
export const schemes = Object.freeze(["light", "dark"]);
export const widths = Object.freeze([320, 1440]);

export function referenceId(engine, view, scheme, width) {
  return `${engine}/${view}.${scheme}.${width}`;
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
    expect(launchOptions.args).toEqual(browserName === "chromium" ? chromiumArguments : undefined);
    // The probe compared engine revisions before launch; the launched
    // version must also equal the recorded reference environment.
    expect(browser.version()).toBe(environment.browserVersions[browserName]);
    // Every browser reads the font configuration from the run directory's
    // copy, whose bytes the probe hashed, and that copy must equal the
    // content-bound fonts.conf of this test snapshot. Browsers inherit this
    // worker's environment only while no project sets launchOptions.env.
    const fontConfigCopy = resolve(testInfo.project.outputDir, "..", "fonts.conf");
    expect(launchOptions.env, "browsers must inherit the environment that names the font configuration copy").toBeUndefined();
    expect(process.env.FONTCONFIG_FILE, "FONTCONFIG_FILE must name the run directory's font configuration copy").toBe(fontConfigCopy);
    expect(readFileSync(fontConfigCopy).equals(fontConfig), "the run directory's font configuration must equal tests/visual/fonts.conf").toBe(true);
    await use();
  }, {auto: true}],
  visualServers: [async ({}, use, workerInfo) => {
    // Every worker consumes the binary published before Playwright started.
    const binary = resolve(workerInfo.project.outputDir, "..", "server");
    const servers = new Map();
    try {
      await use({
        async url(selector) {
          if (!servers.has(selector)) {
            servers.set(selector, await startBrowserServer(binary, {
              spawnProcess: (path, args, options) => spawn(path, [selector, ...args], options),
            }));
          }
          return servers.get(selector).url;
        },
      });
    } finally {
      const failures = [];
      for (const server of servers.values()) {
        try { await server.stop(); } catch (error) { failures.push(error); }
      }
      if (failures.length > 0) throw new AggregateError(failures, "visual fixture servers did not stop");
    }
  }, {scope: "worker"}],
});

// navigate loads the view with the color scheme and reduced motion in effect.
// Firefox drops color-scheme emulation at a navigation into or out of a
// document served with Cross-Origin-Opener-Policy: same-origin, unless both
// documents have the same origin and send that header: the first navigation
// from about:blank, a navigation to another fixture server (each has its own
// port) and history traversal across such a boundary. Emulation applied after
// the last such navigation holds across reload and across navigation between
// documents of the same fixture. The emulation is therefore applied after the
// first navigation, the document is reloaded under it so that scripts reading
// the scheme at load see it, and it is applied again after the reload, the
// last navigation of every captured view; assertEmulation checks it before
// each capture. Both navigations run behind the shared navigation request
// barrier.
export async function navigate(page, url, profile, heading, scheme) {
  await emulate(page, scheme);
  const first = await withNavigationRequestBarrier(page, () => page.goto(url, {waitUntil: "load"}));
  if (first === null || first.status() !== 200) throw new Error("visual view navigation did not return 200");
  await emulate(page, scheme);
  const response = await withNavigationRequestBarrier(page, () => page.reload({waitUntil: "load"}));
  if (response === null || response.status() !== 200) throw new Error("visual view reload did not return 200");
  await emulate(page, scheme);
  expect(response.headers()["content-security-policy"]).toBe(expectedCSP[profile]);
  expect(response.headers()["x-content-type-options"]).toBe("nosniff");
  await expect(page.getByRole("heading", {name: heading, exact: true})).toBeVisible();
  await assertEmulation(page, scheme);
}

async function emulate(page, scheme) {
  await page.emulateMedia({colorScheme: scheme, reducedMotion: "reduce"});
}

// assertEmulation requires the requested color scheme and reduced motion to
// be in effect in the document about to be captured.
export async function assertEmulation(page, scheme) {
  expect(await page.evaluate((colorScheme) => [
    matchMedia(`(prefers-color-scheme: ${colorScheme})`).matches,
    matchMedia("(prefers-reduced-motion: reduce)").matches,
  ], scheme), `color scheme ${scheme} and reduced motion must be in effect in the captured document`).toEqual([true, true]);
}

async function settle(page) {
  await page.evaluate(async () => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    await document.fonts.ready;
    await new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
  });
}

// openView renders one inventory view at the given scheme and width.
export async function openView(page, visualServers, view, scheme, width) {
  await page.setViewportSize({width, height: viewportHeight});
  const tab = workspaceTabs[view];
  if (tab !== undefined) {
    await navigate(page, await visualServers.url(workspaceSelector), "workspace", workspaceHeading, scheme);
    await expect(page.locator("body")).toHaveAttribute("data-state", "specifications");
    if (tab.view !== "specifications") {
      // A programmatic click selects the tab without leaving hover or focus.
      await page.locator(`[data-view="${tab.view}"]`).evaluate((button) => button.click());
      await expect(page.locator("body")).toHaveAttribute("data-state", tab.state);
    }
    await expect(page.locator("#workspace-content")).toHaveAttribute("aria-busy", "false");
    await settle(page);
    await assertEmulation(page, scheme);
    return;
  }
  const match = view.match(/^(.*)-(cards|table)$/);
  const rendering = match === null ? undefined : staticRenderings[match[1]];
  if (rendering === undefined) throw new Error(`unknown visual view ${view}`);
  await navigate(page, await visualServers.url(rendering.selector), "static", rendering.heading, scheme);
  if (match[2] === "table") await page.locator("#proofkit-view-mode").selectOption("table");
  await expect(page.locator("#proofkit-view-mode")).toHaveValue(match[2]);
  await settle(page);
  await assertEmulation(page, scheme);
}

// fitViewportToDocument makes the window exactly as tall as the document, cut
// at clipHeight, so a plain viewport capture is the full page cut at 2400 CSS
// pixels. Capturing beyond the viewport would re-run layout at another
// viewport height during the capture, which changed page heights between two
// otherwise identical Chromium captures.
async function fitViewportToDocument(page) {
  const {width} = page.viewportSize();
  let height = page.viewportSize().height;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const documentHeight = await page.evaluate(() => Math.max(
      document.documentElement.scrollHeight, document.body.scrollHeight,
      document.documentElement.offsetHeight, document.body.offsetHeight,
    ));
    const target = Math.min(clipHeight, documentHeight);
    if (target === height) return;
    height = target;
    await page.setViewportSize({width, height});
    await settle(page);
  }
  throw new Error("document height did not converge while fitting the window to the page");
}

// captureTwice takes two captures with identical options; the gate admits a
// capture only when both are byte-equal. A full-page capture is the whole
// document cut at clipHeight CSS pixels.
export async function captureTwice(page, {fullPage}) {
  if (fullPage) await fitViewportToDocument(page);
  const options = {animations: "disabled", caret: "hide", scale: "css", fullPage: false};
  const first = await page.screenshot(options);
  const second = await page.screenshot(options);
  return {first, second};
}

// The run directory is the parent of the Playwright output directory. Stable
// captures go to <run>/captures/<id>.png, unstable pairs to <run>/unstable,
// and mutated control captures to <run>/controls. No path resolves into the
// test directory.
function runFile(testInfo, area, relativePath) {
  const runDirectory = resolve(testInfo.project.outputDir, "..");
  const root = resolve(runDirectory, area);
  const target = resolve(root, relativePath);
  if (!target.startsWith(root + sep) || target === testDirectory || target.startsWith(testDirectory + sep)) {
    throw new Error("visual capture path escaped its run directory area");
  }
  return target;
}

function writeRunFile(testInfo, area, relativePath, bytes) {
  const target = runFile(testInfo, area, relativePath);
  mkdirSync(dirname(target), {recursive: true});
  writeFileSync(target, bytes, {flag: "wx"});
}

function admittedEntry(id) {
  return Array.isArray(inventory.references) ? inventory.references.find((entry) => entry.id === id) : undefined;
}

function describe(digest) {
  return `${digest.rgbaSHA256} (${digest.width}x${digest.height})`;
}

// stableDigest requires the two captures to be byte-equal and returns the
// canonical digest and dimensions of the decoded capture.
function stableDigest(testInfo, id, {first, second}) {
  if (!first.equals(second)) {
    writeRunFile(testInfo, "unstable", `${id}.first.png`, first);
    writeRunFile(testInfo, "unstable", `${id}.second.png`, second);
    throw new Error(`${id}: two captures of the same state differ; the view is not stable`);
  }
  const image = decodePNG(first);
  return {height: image.height, rgbaSHA256: canonicalRGBADigest(image), width: image.width};
}

// assertMatchesReference keeps the capture for the gallery and admission,
// then requires equal dimensions and an equal canonical digest.
export function assertMatchesReference(testInfo, id, captures) {
  const actual = stableDigest(testInfo, id, captures);
  writeRunFile(testInfo, "captures", `${id}.png`, captures.first);
  const admitted = admittedEntry(id);
  if (admitted === undefined) {
    throw new Error(`${id}: has no admitted reference; captured ${describe(actual)}`);
  }
  if (admitted.width !== actual.width || admitted.height !== actual.height || admitted.rgbaSHA256 !== actual.rgbaSHA256) {
    throw new Error(`${id}: captured ${describe(actual)} differs from the admitted ${describe(admitted)}`);
  }
}

// controlDigest returns the digest of a mutated capture and the admitted
// entry of the unmutated view; a control passes only when they differ.
export function controlDigest(testInfo, id, controlName, captures) {
  const actual = stableDigest(testInfo, `controls/${id}.${controlName}`, captures);
  writeRunFile(testInfo, "controls", `${id}.${controlName}.png`, captures.first);
  const admitted = admittedEntry(id);
  if (admitted === undefined) throw new Error(`${id}: has no admitted reference for the ${controlName} control`);
  return {actual, admitted};
}
