import assert from "node:assert/strict";
import {existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, relative, resolve} from "node:path";
import test from "node:test";

import {createScanner, LanguageVariant, SyntaxKind} from "typescript/unstable/ast";

import {executeBrowserProof} from "./browser-proof-execution.mjs";
import {assertInputSnapshotUnchanged, browserProofInputManifestPath, loadBrowserProofInputResolution, materializeInputSnapshot, snapshotInputAssets} from "./browser-proof-inputs.mjs";

test("owner resolution closes manifest, Go dependencies, and role-owned paths", () => {
  const resolution = loadBrowserProofInputResolution();
  assert.deepEqual(resolution.inputPaths, [...resolution.inputPaths].sort());
  assert(resolution.inputPaths.includes(browserProofInputManifestPath));
  assert(resolution.inputPaths.includes(resolution.writerPath));
  assert(resolution.inputPaths.some((path) => path.startsWith("internal/command/requirementcontext/")));
  assert.equal(resolution.serverTarget, "./internal/tools/browsertestserver");
});

test("every local JavaScript import is content-bound by the owner resolution", () => {
  const {inputPaths} = loadBrowserProofInputResolution();
  const admitted = new Set(inputPaths);
  for (const path of inputPaths.filter((candidate) => candidate.endsWith(".mjs") || candidate.endsWith(".js"))) {
    for (const specifier of localModuleSpecifiers(path)) {
      const importedPath = resolveLocalModule(path, specifier);
      assert(admitted.has(importedPath), `${path} imports omitted browser proof input ${importedPath}`);
    }
  }
});

test("input snapshot rejects source mutation during browser proof execution", () => {
  const root = mkdtempSync(join(tmpdir(), "proofkit-browser-inputs-"));
  try {
    const input = join(root, "input.txt");
    writeFileSync(input, "before");
    const before = snapshotInputAssets([input]);
    writeFileSync(input, "after");
    const after = snapshotInputAssets([input]);
    assert.throws(() => assertInputSnapshotUnchanged(before, after), /changed during execution/);
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("materialized execution snapshot is isolated from mutate-restore source changes", () => {
  const root = mkdtempSync(join(tmpdir(), "proofkit-browser-materialized-"));
  try {
    const sourceRoot = join(root, "source");
    const executionRoot = join(root, "execution");
    const input = join(sourceRoot, "input.txt");
    mkdirSync(sourceRoot, {recursive: true});
    writeFileSync(input, "before");
    const assets = materializeInputSnapshot(["input.txt"], sourceRoot, executionRoot);
    writeFileSync(input, "transient-executed");
    assert.equal(readFileSync(join(executionRoot, "input.txt"), "utf8"), "before");
    writeFileSync(input, "before");
    assertInputSnapshotUnchanged(assets, snapshotInputAssets(["input.txt"], executionRoot));
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("materialized execution snapshot rejects escaping destination paths", () => {
  const root = mkdtempSync(join(tmpdir(), "proofkit-browser-materialized-path-"));
  try {
    assert.throws(() => materializeInputSnapshot([join(root, "input.txt")], root, join(root, "execution")), /repository-relative/);
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("browser proof composition binds materialization, build, and Playwright to one source root", async () => {
  const root = mkdtempSync(join(tmpdir(), "proofkit-browser-process-boundary-"));
  try {
    const runDirectory = join(root, "run");
    const calls = [];
    const result = await executeBrowserProof({
      environment: {PATH: "/test/bin"},
      execFile: (...args) => {
        if (args[1]?.includes("--admit-playwright-report")) {
          calls.push({kind: "admit-report", args});
          return JSON.stringify(passingProjectExecutions());
        }
        calls.push({kind: "build", args});
        return undefined;
      },
      inputPaths: ["package.json"],
      nodeExecutable: "/test/node",
      resolution: {serverTarget: "./internal/tools/browsertestserver"},
      runDirectory,
      spawnProcess: (...args) => {
        calls.push({kind: "test", args});
        writeFileSync(args[2].env.PROOFKIT_BROWSER_TEST_REPORT_PATH, JSON.stringify(passingPlaywrightReport()));
        return {status: 0};
      },
      startServer: async (serverBinary) => {
        calls.push({kind: "server", serverBinary});
        return {url: "http://127.0.0.1:41001/", stop: async () => { calls.push({kind: "stop"}); }};
      },
      testCommand: ["node_modules/@playwright/test/cli.js", "test"],
    });
    const sourceDirectory = resolve(runDirectory, "source");
    assert.equal(result.sourceDirectory, sourceDirectory);
    assert.equal(result.testResult.status, 0);
    assert.deepEqual(result.projects.map((project) => project.name), ["chromium", "firefox", "webkit"]);
    assert.equal(calls.length, 5);
    assert.equal(calls[0].args[2].cwd, sourceDirectory);
    assert.equal(calls[1].serverBinary, resolve(runDirectory, "server"));
    assert.equal(calls[2].args[2].cwd, sourceDirectory);
    assert.equal(calls[2].args[2].env.PROOFKIT_BROWSER_TEST_OUTPUT_DIR, resolve(runDirectory, "test-results"));
    assert.equal(calls[2].args[2].env.PROOFKIT_BROWSER_TEST_REPORT_PATH, resolve(runDirectory, "playwright-report.json"));
    assert.equal(calls[3].kind, "admit-report");
    assert.equal(calls[3].args[2].cwd, sourceDirectory);
    assert.equal(calls[4].kind, "stop");
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

function passingPlaywrightReport() {
  return {
    config: {},
    errors: [],
    stats: {duration: 1, expected: 3, flaky: 0, skipped: 0, startTime: "2026-07-13T00:00:00Z", unexpected: 0},
    suites: [{
      title: "workspace.spec.mjs",
      specs: [{
        file: "tests/browser/workspace.spec.mjs",
        ok: true,
        title: "runs",
        tests: ["chromium", "firefox", "webkit"].map((projectName) => ({expectedStatus: "passed", projectName, results: [{errors: [], retry: 0, status: "passed"}], status: "expected"})),
      }],
    }],
  };
}

function passingProjectExecutions() {
  const testIds = ["tests/browser/workspace.spec.mjs::workspace.spec.mjs > runs"];
  return ["chromium", "firefox", "webkit"].map((name) => ({executedTestCount: 1, name, passedTestCount: 1, testIds}));
}

function localModuleSpecifiers(path) {
  const scanner = createScanner(true, LanguageVariant.Standard, readFileSync(path, "utf8"));
  const tokens = [];
  for (let kind = scanner.scan(); kind !== SyntaxKind.EndOfFile; kind = scanner.scan()) {
    tokens.push({kind, value: scanner.getTokenValue()});
  }
  const result = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.kind === SyntaxKind.ImportKeyword) {
      const next = tokens[index + 1];
      if (next?.kind === SyntaxKind.DotToken) continue;
      if (next?.kind === SyntaxKind.OpenParenToken) {
        const specifier = tokens[index + 2];
        if (!isStaticModuleToken(specifier)) throw new Error(`${path} contains a non-static dynamic import`);
        result.push(specifier.value);
        continue;
      }
      if (isStaticModuleToken(next)) {
        result.push(next.value);
        continue;
      }
      const from = tokens.slice(index + 1).findIndex((candidate) => candidate.kind === SyntaxKind.FromKeyword || candidate.kind === SyntaxKind.SemicolonToken);
      const absoluteFrom = from < 0 ? -1 : index + 1 + from;
      if (absoluteFrom >= 0 && tokens[absoluteFrom].kind === SyntaxKind.FromKeyword && isStaticModuleToken(tokens[absoluteFrom + 1])) result.push(tokens[absoluteFrom + 1].value);
    }
    if (token.kind === SyntaxKind.ExportKeyword && [SyntaxKind.AsteriskToken, SyntaxKind.OpenBraceToken].includes(tokens[index + 1]?.kind)) {
      const from = tokens.slice(index + 1).findIndex((candidate) => candidate.kind === SyntaxKind.FromKeyword || candidate.kind === SyntaxKind.SemicolonToken);
      const absoluteFrom = from < 0 ? -1 : index + 1 + from;
      if (absoluteFrom >= 0 && tokens[absoluteFrom].kind === SyntaxKind.FromKeyword && isStaticModuleToken(tokens[absoluteFrom + 1])) result.push(tokens[absoluteFrom + 1].value);
    }
  }
  return result.filter((specifier) => specifier.startsWith("."));
}

function isStaticModuleToken(token) {
  return token && [SyntaxKind.StringLiteral, SyntaxKind.NoSubstitutionTemplateLiteral].includes(token.kind);
}

function resolveLocalModule(importer, specifier) {
  const base = resolve(dirname(importer), specifier);
  const candidates = [base, `${base}.mjs`, `${base}.js`, join(base, "index.mjs"), join(base, "index.js")];
  const match = candidates.find((candidate) => existsSync(candidate));
  if (!match) throw new Error(`${importer} imports missing local module ${specifier}`);
  return relative(process.cwd(), match).replaceAll("\\", "/");
}
