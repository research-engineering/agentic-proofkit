import assert from "node:assert/strict";
import {existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, relative, resolve} from "node:path";
import test from "node:test";

import {createScanner, LanguageVariant, SyntaxKind} from "typescript/unstable/ast";

import {analyzeAxe, assertAxeTestComplete, axeConfigureOptions, axeDistributionSource, axeDistributionVersion, axeRunOptions, initializeAxe} from "../tests/browser/axe-harness.mjs";
import {executeBrowserProof} from "./browser-proof-execution.mjs";
import {assertInputSnapshotUnchanged, browserProofInputManifestPath, loadBrowserProofInputResolution, materializeInputSnapshot, snapshotInputAssets} from "./browser-proof-inputs.mjs";

test("browser accessibility harness closes direct audit topology", async () => {
  const values = {
    PROOFKIT_BROWSER_TEST_OUTPUT_DIR: resolve(tmpdir(), "proofkit-browser-config-output"),
    PROOFKIT_BROWSER_TEST_REPORT_PATH: resolve(tmpdir(), "proofkit-browser-config-report.json"),
    PROOFKIT_BROWSER_TEST_URL: "http://127.0.0.1:41001/",
  };
  const previous = Object.fromEntries(Object.keys(values).map((name) => [name, process.env[name]]));
  Object.assign(process.env, values);
  try {
    const {default: config} = await import("../playwright.config.mjs");
    assert.equal(config.retries, 0);
    assert.equal(config.timeout, 30_000);
    assert.equal(config.use.screenshot, "only-on-failure");
    assert.deepEqual(config.use.trace, {
      mode: "retain-on-failure",
      screenshots: false,
      snapshots: true,
      sources: true,
    });
    assert.equal(axeDistributionVersion, "4.13.0");
    assert(axeDistributionSource.length > 0);
    const exactConfigureOptions = {
      allowedOrigins: ["<same_origin>"],
      branding: {application: "playwright"},
    };
    const exactRunOptions = {
      rules: {"target-size": {enabled: true}},
    };
    assert.deepEqual(axeConfigureOptions, exactConfigureOptions);
    assert.deepEqual(axeRunOptions, exactRunOptions);
    assert(Object.isFrozen(axeConfigureOptions));
    assert(Object.isFrozen(axeConfigureOptions.allowedOrigins));
    assert(Object.isFrozen(axeConfigureOptions.branding));
    assert(Object.isFrozen(axeRunOptions));
    assert(Object.isFrozen(axeRunOptions.rules));
    assert(Object.isFrozen(axeRunOptions.rules["target-size"]));

    const assertClosedConfigureOptions = (actual) => {
      assert.deepEqual(actual, exactConfigureOptions);
    };
    for (const mutant of [
      {branding: {application: "playwright"}},
      {allowedOrigins: ["<same_origin>"]},
      {allowedOrigins: ["https://example.invalid"], branding: {application: "playwright"}},
      {allowedOrigins: ["<same_origin>"], branding: {}},
      {allowedOrigins: ["<same_origin>"], branding: {application: "other"}},
      {allowedOrigins: ["<same_origin>"], branding: {application: "playwright"}, surplus: true},
      {allowedOrigins: ["<same_origin>"], branding: {application: "playwright", surplus: true}},
    ]) {
      assert.throws(() => assertClosedConfigureOptions(mutant));
    }
    const assertClosedRunOptions = (actual) => {
      assert.deepEqual(actual, exactRunOptions);
    };
    for (const mutant of [
      {},
      {rules: {}},
      {rules: {"target-size": {}}},
      {rules: {"target-size": {enabled: false}}},
      {rules: {"target-size": {enabled: true, surplus: true}}},
      {rules: {"target-size": {enabled: true}}, surplus: true},
      {rules: {"target-size": {enabled: true}}, runOnly: ["target-size", "button-name"]},
      {rules: {"button-name": {enabled: true}, "target-size": {enabled: true}}},
    ]) {
      assert.throws(() => assertClosedRunOptions(mutant));
    }

    const initScripts = [];
    const initContext = {
      addInitScript: async (value) => {
        initScripts.push(value);
      },
    };
    const initPageA = {context: () => initContext};
    const initPageB = {context: () => initContext};
    await initializeAxe(initPageA);
    await assert.rejects(initializeAxe(initPageB), /already initialized/);
    const otherInitScripts = [];
    await initializeAxe({
      context: () => ({
        addInitScript: async (value) => {
          otherInitScripts.push(value);
        },
      }),
    });
    const exactInitScripts = [{content: axeDistributionSource}];
    assert.deepEqual(initScripts, exactInitScripts);
    assert.deepEqual(otherInitScripts, exactInitScripts);
    for (const mutant of [
      [],
      [{content: "wrong"}],
      [...exactInitScripts, ...exactInitScripts],
      [{content: axeDistributionSource, surplus: true}],
    ]) {
      assert.throws(() => assert.deepEqual(mutant, exactInitScripts));
    }

    let releaseRegistration;
    let registrationStarted;
    const registrationBarrier = new Promise((resolve) => {
      releaseRegistration = resolve;
    });
    const registrationEntered = new Promise((resolve) => {
      registrationStarted = resolve;
    });
    const concurrentInitScripts = [];
    const concurrentContext = {
      addInitScript: async (value) => {
        concurrentInitScripts.push(value);
        registrationStarted();
        await registrationBarrier;
      },
    };
    const firstInit = initializeAxe({context: () => concurrentContext});
    await registrationEntered;
    const secondInit = initializeAxe({context: () => concurrentContext});
    await Promise.resolve();
    const registrationsBeforeRelease = concurrentInitScripts.length;
    releaseRegistration();
    const initOutcomes = await Promise.allSettled([firstInit, secondInit]);
    assert.equal(registrationsBeforeRelease, 1);
    assert.equal(initOutcomes[0].status, "fulfilled");
    assert.equal(initOutcomes[1].status, "rejected");
    assert.match(initOutcomes[1].reason.message, /already initialized/);
    assert.deepEqual(concurrentInitScripts, exactInitScripts);

    let rollbackAttempts = 0;
    const rollbackContext = {
      addInitScript: async () => {
        rollbackAttempts += 1;
        if (rollbackAttempts === 1) throw new Error("registration failed");
      },
    };
    const rollbackPage = {context: () => rollbackContext};
    await assert.rejects(initializeAxe(rollbackPage), /registration failed/);
    await initializeAxe(rollbackPage);
    await assert.rejects(initializeAxe(rollbackPage), /already initialized/);
    assert.equal(rollbackAttempts, 2);

    const mainFrame = {};
    const documentSentinel = {};
    const exactTestEngine = {
      name: "axe-core",
      version: axeDistributionVersion,
    };
    const createHarnessPage = ({
      beforeEvaluate,
      configure = "callable",
      frames = [mainFrame],
      run = "callable",
      testEngine = exactTestEngine,
      version = axeDistributionVersion,
    } = {}) => {
      const calls = {
        configure: [],
        context: 0,
        evaluate: [],
        events: [],
        run: [],
      };
      const runtime = {};
      if (version !== "absent") {
        Object.defineProperty(runtime, "version", {
          get: () => {
            calls.events.push({type: "version", value: version});
            return version;
          },
        });
      }
      if (configure === "callable") {
        runtime.configure = (options) => {
          calls.configure.push(options);
          calls.events.push({options, type: "configure"});
        };
      } else if (configure !== "absent") {
        runtime.configure = configure;
      }
      if (run === "callable") {
        runtime.run = async (document, options) => {
          calls.run.push({document, options});
          calls.events.push({document, options, type: "run"});
          return {
            incomplete: [],
            passes: [],
            testEngine,
            violations: [],
          };
        };
      } else if (run !== "absent") {
        runtime.run = run;
      }
      const page = {
        context: () => {
          calls.context += 1;
          throw new Error("analysis must not access a context or temporary page");
        },
        evaluate: async (callback, args) => {
          calls.evaluate.push({args});
          await beforeEvaluate?.();
          const previousAxe = globalThis.axe;
          const previousDocument = globalThis.document;
          globalThis.axe = runtime;
          globalThis.document = documentSentinel;
          try {
            return await callback(args);
          } finally {
            if (previousAxe === undefined) delete globalThis.axe;
            else globalThis.axe = previousAxe;
            if (previousDocument === undefined) delete globalThis.document;
            else globalThis.document = previousDocument;
          }
        },
        frames: () => frames,
        mainFrame: () => mainFrame,
      };
      return {calls, page};
    };

    const admitted = createHarnessPage();
    const result = await analyzeAxe(admitted.page);
    assert.deepEqual(result.testEngine, exactTestEngine);
    assert.deepEqual(admitted.calls.configure, [exactConfigureOptions]);
    assert.deepEqual(admitted.calls.run, [{
      document: documentSentinel,
      options: exactRunOptions,
    }]);
    assert.deepEqual(admitted.calls.evaluate, [{
      args: {
        configureOptions: exactConfigureOptions,
        expectedVersion: axeDistributionVersion,
        runOptions: exactRunOptions,
      },
    }]);
    assert.deepEqual(admitted.calls.events, [
      {type: "version", value: axeDistributionVersion},
      {options: exactConfigureOptions, type: "configure"},
      {document: documentSentinel, options: exactRunOptions, type: "run"},
    ]);
    assert.equal(admitted.calls.context, 0);
    await assert.rejects(analyzeAxe(admitted.page), /already analyzed/);
    assert.equal(admitted.calls.evaluate.length, 1);

    let releasePendingRegistration;
    let pendingRegistrationStarted;
    const pendingRegistrationBarrier = new Promise((resolve) => {
      releasePendingRegistration = resolve;
    });
    const pendingRegistrationEntered = new Promise((resolve) => {
      pendingRegistrationStarted = resolve;
    });
    const pending = createHarnessPage();
    const pendingContext = {
      addInitScript: async () => {
        pendingRegistrationStarted();
        await pendingRegistrationBarrier;
      },
    };
    pending.page.context = () => pendingContext;
    const pendingInitialization = initializeAxe(pending.page);
    await pendingRegistrationEntered;
    await analyzeAxe(pending.page);
    assert.throws(() => assertAxeTestComplete(pending.page), /did not initialize and analyze exactly once/);
    releasePendingRegistration();
    await pendingInitialization;
    assert.doesNotThrow(() => assertAxeTestComplete(pending.page));

    let releaseEvaluation;
    let evaluationStarted;
    const evaluationBarrier = new Promise((resolve) => {
      releaseEvaluation = resolve;
    });
    const evaluationEntered = new Promise((resolve) => {
      evaluationStarted = resolve;
    });
    const concurrent = createHarnessPage({
      beforeEvaluate: async () => {
        evaluationStarted();
        await evaluationBarrier;
      },
    });
    const concurrentAuditContext = {addInitScript: async () => {}};
    concurrent.page.context = () => concurrentAuditContext;
    await initializeAxe(concurrent.page);
    const firstAudit = analyzeAxe(concurrent.page);
    await evaluationEntered;
    const secondAudit = analyzeAxe(concurrent.page);
    await Promise.resolve();
    const evaluationsBeforeRelease = concurrent.calls.evaluate.length;
    assert.throws(() => assertAxeTestComplete(concurrent.page), /did not initialize and analyze exactly once/);
    releaseEvaluation();
    const auditOutcomes = await Promise.allSettled([firstAudit, secondAudit]);
    assert.equal(evaluationsBeforeRelease, 1);
    assert.equal(auditOutcomes[0].status, "fulfilled");
    assert.equal(auditOutcomes[1].status, "rejected");
    assert.match(auditOutcomes[1].reason.message, /already analyzed/);
    assert.equal(concurrent.calls.evaluate.length, 1);
    assert.doesNotThrow(() => assertAxeTestComplete(concurrent.page));

    const incompleteContext = {addInitScript: async () => {}};
    const incomplete = createHarnessPage();
    incomplete.page.context = () => incompleteContext;
    await initializeAxe(incomplete.page);
    assert.throws(() => assertAxeTestComplete(incomplete.page), /did not initialize and analyze exactly once/);
    await analyzeAxe(incomplete.page);
    assert.doesNotThrow(() => assertAxeTestComplete(incomplete.page));
    const auditOnlyContext = {addInitScript: async () => {}};
    const auditOnly = createHarnessPage();
    auditOnly.page.context = () => auditOnlyContext;
    await analyzeAxe(auditOnly.page);
    assert.throws(() => assertAxeTestComplete(auditOnly.page), /did not initialize and analyze exactly once/);
    for (const options of [
      {frames: []},
      {version: "4.12.0"},
      {testEngine: {name: "other", version: axeDistributionVersion}},
    ]) {
      const failed = createHarnessPage(options);
      const failedContext = {addInitScript: async () => {}};
      failed.page.context = () => failedContext;
      await initializeAxe(failed.page);
      await assert.rejects(analyzeAxe(failed.page));
      const evaluationsAfterFailure = failed.calls.evaluate.length;
      await assert.rejects(analyzeAxe(failed.page), /already analyzed/);
      assert.equal(failed.calls.evaluate.length, evaluationsAfterFailure);
      assert.throws(() => assertAxeTestComplete(failed.page), /did not initialize and analyze exactly once/);
    }

    for (const frames of [[], [{}], [mainFrame, {}]]) {
      const rejected = createHarnessPage({frames});
      await assert.rejects(analyzeAxe(rejected.page), /exactly the main frame/);
      assert.equal(rejected.calls.evaluate.length, 0);
    }
    for (const version of ["absent", "4.12.0"]) {
      const rejected = createHarnessPage({version});
      await assert.rejects(analyzeAxe(rejected.page), /was not initialized/);
      assert.equal(rejected.calls.configure.length, 0);
      assert.equal(rejected.calls.run.length, 0);
    }
    for (const [field, value] of [
      ["configure", "absent"],
      ["configure", null],
      ["run", "absent"],
      ["run", null],
    ]) {
      const rejected = createHarnessPage({[field]: value});
      await assert.rejects(analyzeAxe(rejected.page), /is incomplete/);
      assert.equal(rejected.calls.configure.length, 0);
      assert.equal(rejected.calls.run.length, 0);
    }
    for (const testEngine of [
      null,
      {version: axeDistributionVersion},
      {name: "other", version: axeDistributionVersion},
      {name: "axe-core"},
      {name: "axe-core", version: "4.12.0"},
    ]) {
      const rejected = createHarnessPage({testEngine});
      await assert.rejects(analyzeAxe(rejected.page), /unexpected test engine/);
      assert.equal(rejected.calls.evaluate.length, 1);
      assert.equal(rejected.calls.run.length, 1);
    }
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("owner resolution closes manifest, Go dependencies, and role-owned paths", () => {
  const resolution = loadBrowserProofInputResolution();
  assert.deepEqual(resolution.inputPaths, [...resolution.inputPaths].sort());
  assert(resolution.inputPaths.includes(browserProofInputManifestPath));
  assert(resolution.inputPaths.includes(resolution.writerPath));
  assert(resolution.inputPaths.some((path) => path.startsWith("internal/command/requirementcontext/")));
  assert.equal(resolution.serverTarget, "./internal/tools/browsertestserver");
});

test("workspace navigation excludes provider-falsified lifecycle waits", () => {
  const source = readFileSync("tests/browser/workspace.spec.mjs", "utf8");
  const lifecycleMethods = [...source.matchAll(
    /\bpage\.(goBack|goForward|goto|reload|waitForLoadState|waitForNavigation|waitForURL)\s*\(/g,
  )].map((match) => match[1]);
  assert.deepEqual(lifecycleMethods, ["goto"]);
  assert.equal(source.match(/\bpage\.goto\("about:blank"\);/g)?.length, 1);
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
