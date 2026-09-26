import {spawn, execFileSync} from "node:child_process";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {expect, test as base} from "@playwright/test";
import {startBrowserServer} from "../../scripts/browser-proof-execution.mjs";

export const test = base.extend({
  engineEvidence: [async ({browser, browserName, channel, connectOptions, launchOptions}, use, testInfo) => {
    testInfo.annotations.push({type: "proofkit.browser-engine", description: browserName});
    testInfo.annotations.push({type: "proofkit.browser-version", description: browser.version()});
    expect(browserName).toBe(testInfo.project.name);
    expect(channel).toBeUndefined();
    expect(connectOptions).toBeUndefined();
    expect(launchOptions.channel).toBeUndefined();
    expect(launchOptions.executablePath).toBeUndefined();
    await use();
  }, {auto: true}],
});

export const lookupTest = test.extend({
  lookupURL: [async ({}, use) => { await withFixture("--lookup", use); }, {scope: "worker"}],
});

export const sourceViewTest = test.extend({
  sourceViewURL: [async ({}, use) => { await withFixture("--source", use); }, {scope: "worker"}],
});

export const staticViewTest = test.extend({
  staticViewURL: [async ({}, use) => { await withFixture("--static-source", use); }, {scope: "worker"}],
  staticTreeURL: [async ({}, use) => { await withFixture("--static-tree", use); }, {scope: "worker"}],
  staticProofURL: [async ({}, use) => { await withFixture("--static-proof", use); }, {scope: "worker"}],
  staticCoverageURL: [async ({}, use) => { await withFixture("--static-coverage", use); }, {scope: "worker"}],
});

export const pagingTest = test.extend({
  pagingURL: [async ({}, use) => { await withFixture("--paging", use); }, {scope: "worker"}],
});

export const capacityTest = test.extend({
  capacityURL: [async ({}, use) => { await withFixture("--capacity", use); }, {scope: "worker"}],
  graphCapacityURL: [async ({}, use) => { await withFixture("--graph-capacity", use); }, {scope: "worker"}],
  graphNumericURL: [async ({}, use) => { await withFixture("--graph-numeric", use); }, {scope: "worker"}],
});

export const graphLayoutTest = test.extend({
  graphLayoutURL: [async ({}, use) => { await withFixture("--graph-layout", use); }, {scope: "worker"}],
  graphMixedLayoutURL: [async ({}, use) => { await withFixture("--graph-layout-mixed", use); }, {scope: "worker"}],
});

export const coverageTest = test.extend({
  compactURL: [async ({}, use) => { await withFixture("--coverage-compact", use); }, {scope: "worker"}],
  structuredURL: [async ({}, use) => { await withFixture("--coverage-structured", use); }, {scope: "worker"}],
  emptyCoverageURL: [async ({}, use) => { await withFixture("--coverage-empty", use); }, {scope: "worker"}],
});

async function withFixture(selector, use) {
  const directory = mkdtempSync(join(tmpdir(), "proofkit-browser-fixture-"));
  try {
    const binary = join(directory, "server");
    execFileSync("go", ["build", "-o", binary, "./internal/tools/browsertestserver"], {stdio: "pipe"});
    const server = await startBrowserServer(binary, {
      spawnProcess: (path, args, options) => spawn(path, [selector, ...args], options),
    });
    try { await use(server.url); }
    finally { await server.stop(); }
  } finally { rmSync(directory, {recursive: true, force: true}); }
}
