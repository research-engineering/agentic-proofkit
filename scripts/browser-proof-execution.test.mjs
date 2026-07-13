import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {PassThrough} from "node:stream";
import test from "node:test";

import {executeBrowserProof, runBrowserProofTests, startBrowserServer} from "./browser-proof-execution.mjs";

test("browser proof test execution rejects ambient remote-connect authority", () => {
  let observed;
  const result = runBrowserProofTests({
    environment: {
      KEEP_ME: "yes",
      PW_TEST_CONNECT_EXPOSE_NETWORK: "*",
      PW_TEST_CONNECT_FUTURE_OPTION: "unexpected",
      PW_TEST_CONNECT_HEADERS: "{}",
      PW_TEST_CONNECT_WS_ENDPOINT: "ws://remote.invalid/",
    },
    nodeExecutable: "node",
    runDirectory: "artifacts/run",
    serverURL: "http://127.0.0.1:41001/",
    sourceDirectory: "source",
    spawnProcess: (_executable, _argv, options) => {
      observed = options.env;
      return {status: 0};
    },
    testCommand: ["playwright", "test"],
  });
  assert.equal(result.status, 0);
  assert.equal(observed.KEEP_ME, "yes");
  assert.equal(observed.PROOFKIT_BROWSER_TEST_URL, "http://127.0.0.1:41001/");
  assert.equal(Object.keys(observed).some((name) => name.startsWith("PW_TEST_CONNECT_")), false);
});

test("browser proof server readiness timeout terminates the child", async () => {
  const child = new FakeChild((signal) => {
    if (signal === "SIGTERM") child.exit(signal);
  });
  await assert.rejects(
    startBrowserServer("server", {spawnProcess: () => child, readinessTimeoutMs: 10, stopTimeoutMs: 50}),
    /readiness timed out/,
  );
  assert.deepEqual(child.signals, ["SIGTERM"]);
  assert.equal(child.listenerCount("exit"), 0);
});

test("browser proof server cleanup escalates from SIGTERM to SIGKILL", async () => {
  const child = new FakeChild((signal) => {
    if (signal === "SIGKILL") child.exit(signal);
  });
  queueMicrotask(() => child.stdout.write("Proofkit requirement browser: http://127.0.0.1:41001/\n"));
  const server = await startBrowserServer("server", {spawnProcess: () => child, readinessTimeoutMs: 50, stopTimeoutMs: 10});
  assert.equal(server.url, "http://127.0.0.1:41001/");
  await server.stop();
  await server.stop();
  assert.deepEqual(child.signals, ["SIGTERM", "SIGKILL"]);
  assert.equal(child.listenerCount("exit"), 0);
});

test("browser proof server observes a child that exited before readiness listeners", async () => {
  const child = new FakeChild(() => {});
  child.exitCode = 23;
  await assert.rejects(
    startBrowserServer("server", {spawnProcess: () => child, readinessTimeoutMs: 50, stopTimeoutMs: 50}),
    /exited before readiness with code 23/,
  );
  assert.deepEqual(child.signals, []);
  assert.equal(child.listenerCount("exit"), 0);
});

test("browser proof server rejects a terminal exit after readiness but before requested shutdown", async () => {
  const child = new FakeChild(() => {});
  queueMicrotask(() => child.stdout.write("Proofkit requirement browser: http://127.0.0.1:41001/\n"));
  const server = await startBrowserServer("server", {spawnProcess: () => child, readinessTimeoutMs: 50, stopTimeoutMs: 50});
  child.exitWithCode(1);
  await Promise.resolve();
  await assert.rejects(server.stop(), /before requested shutdown/);
  assert.deepEqual(child.signals, []);
  assert.equal(child.listenerCount("error"), 0);
});

test("browser proof server captures a process error after readiness", async () => {
  const child = new FakeChild(() => {});
  queueMicrotask(() => child.stdout.write("Proofkit requirement browser: http://127.0.0.1:41001/\n"));
  const server = await startBrowserServer("server", {spawnProcess: () => child, readinessTimeoutMs: 50, stopTimeoutMs: 50});
  child.emit("error", new Error("post-readiness failure"));
  await assert.rejects(server.stop(), /process error before requested shutdown/);
  assert.deepEqual(child.signals, []);
  assert.equal(child.listenerCount("error"), 0);
});

test("browser proof preserves execution and cleanup failures", async () => {
  const root = mkdtempSync(join(tmpdir(), "proofkit-browser-dual-failure-"));
  try {
    await assert.rejects(
      executeBrowserProof({
        environment: {},
        execFile: () => {},
        inputPaths: ["package.json"],
        nodeExecutable: "node",
        resolution: {serverTarget: "./internal/tools/browsertestserver"},
        runDirectory: join(root, "run"),
        spawnProcess: () => ({status: 1}),
        startServer: async () => ({
          stop: async () => { throw new Error("cleanup failed"); },
          url: "http://127.0.0.1:41001/",
        }),
        testCommand: ["playwright", "test"],
      }),
      (error) => error instanceof AggregateError &&
        error.errors.some((item) => /browser test command failed/.test(item.message)) &&
        error.errors.some((item) => /cleanup failed/.test(item.message)),
    );
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

class FakeChild extends EventEmitter {
  constructor(onKill) {
    super();
    this.exitCode = null;
    this.signalCode = null;
    this.stderr = new PassThrough();
    this.stdout = new PassThrough();
    this.signals = [];
    this.onKill = onKill;
  }

  kill(signal) {
    this.signals.push(signal);
    this.onKill(signal);
    return true;
  }

  exit(signal) {
    if (this.exitCode !== null || this.signalCode !== null) return;
    this.signalCode = signal;
    queueMicrotask(() => this.emit("exit", null, signal));
  }

  exitWithCode(code) {
    if (this.exitCode !== null || this.signalCode !== null) return;
    this.exitCode = code;
    queueMicrotask(() => this.emit("exit", code, null));
  }
}
