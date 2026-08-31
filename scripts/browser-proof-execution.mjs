import {spawn} from "node:child_process";
import {symlinkSync} from "node:fs";
import {join, resolve} from "node:path";

import {assertInputSnapshotUnchanged, materializeInputSnapshot, snapshotInputAssets} from "./browser-proof-inputs.mjs";
import {createUTF8StrictStreamDecoder, decodeUTF8Strict} from "./stable-json.mjs";

export async function executeBrowserProof({environment, execFile, inputPaths, nodeExecutable, resolution, runDirectory, spawnProcess, startServer = startBrowserServer, testCommand}) {
  const sourceDirectory = resolve(runDirectory, "source");
  const assets = materializeInputSnapshot(inputPaths, ".", sourceDirectory);
  symlinkSync(resolve("node_modules"), join(sourceDirectory, "node_modules"), process.platform === "win32" ? "junction" : "dir");
  const serverBinary = buildBrowserProofServer({execFile, runDirectory, serverTarget: resolution.serverTarget, sourceDirectory});
  const server = await startServer(serverBinary);
  let projects;
  let testResult;
  let executionError;
  try {
    testResult = runBrowserProofTests({environment, nodeExecutable, runDirectory, serverURL: server.url, sourceDirectory, spawnProcess, testCommand});
    if (testResult.error) throw testResult.error;
    if (testResult.status !== 0) throw new Error(`browser test command failed; diagnostics retained in ${runDirectory}`);
    projects = admitBrowserProofReport({execFile, reportPath: resolve(runDirectory, "playwright-report.json"), sourceDirectory});
  } catch (error) {
    executionError = error;
  }
  try {
    await server.stop();
  } catch (cleanupError) {
    if (executionError) {
      throw new AggregateError([executionError, cleanupError], "browser proof execution and server cleanup both failed");
    }
    throw cleanupError;
  }
  if (executionError) throw executionError;
  assertInputSnapshotUnchanged(assets, snapshotInputAssets(inputPaths, sourceDirectory));
  return {assets, projects, sourceDirectory, testResult};
}

export function buildBrowserProofServer({execFile, runDirectory, serverTarget, sourceDirectory}) {
  const serverBinary = resolve(runDirectory, "server");
  execFile("go", ["build", "-o", serverBinary, serverTarget], {cwd: sourceDirectory, stdio: "inherit"});
  return serverBinary;
}

export function runBrowserProofTests({environment, nodeExecutable, runDirectory, serverURL, sourceDirectory, spawnProcess, testCommand}) {
  const admittedEnvironment = Object.fromEntries(
    Object.entries(environment).filter(([name]) => !name.startsWith("PW_TEST_CONNECT_")),
  );
  return spawnProcess(nodeExecutable, testCommand, {
    cwd: sourceDirectory,
    env: {
      ...admittedEnvironment,
      PROOFKIT_BROWSER_TEST_REPORT_PATH: resolve(runDirectory, "playwright-report.json"),
      PROOFKIT_BROWSER_TEST_OUTPUT_DIR: resolve(runDirectory, "test-results"),
      PROOFKIT_BROWSER_TEST_URL: serverURL,
    },
    stdio: "inherit",
  });
}

function admitBrowserProofReport({execFile, reportPath, sourceDirectory}) {
  const output = execFile(
    "go",
    ["run", "./internal/tools/browserproofverify", "--admit-playwright-report", reportPath],
    {cwd: sourceDirectory, maxBuffer: 8 << 20},
  );
  const encoded = typeof output === "string" ? output : decodeUTF8Strict(output, "browser proof report admission output");
  const projects = JSON.parse(encoded);
  if (!Array.isArray(projects)) throw new Error("browser proof report admission returned an invalid projection");
  return projects;
}

export async function startBrowserServer(binary, options = {}) {
  const spawnProcess = options.spawnProcess ?? spawn;
  const readinessTimeoutMs = options.readinessTimeoutMs ?? 30_000;
  const stopTimeoutMs = options.stopTimeoutMs ?? 10_000;
  const child = spawnProcess(binary, [], {stdio: ["ignore", "pipe", "pipe"]});
	const stdoutDecoder = boundedUTF8Stream("browser test server stdout");
	const collectStdout = (chunk) => { stdoutDecoder.write(chunk); };
	const drainStderr = () => {};
  child.stdout.on("data", collectStdout);
	child.stderr.on("data", drainStderr);
  const lifecycle = observeChildProcess(child);
  let ready = false;
  let stopPromise;
  const stop = () => {
    const terminalBeforeStop = lifecycle.current();
	stopPromise ??= stopChildProcess(child, lifecycle, stopTimeoutMs, ready && terminalBeforeStop !== null).then(() => {
		stdoutDecoder.finish();
		if (stdoutDecoder.error() !== null) throw stdoutDecoder.error();
	}).finally(() => {
      child.stdout.off("data", collectStdout);
		child.stderr.off("data", drainStderr);
      lifecycle.dispose();
    });
    return stopPromise;
  };
  try {
	const url = await waitForBrowserServerReady(child, lifecycle, stdoutDecoder.value, stdoutDecoder.error, stdoutDecoder.finish, readinessTimeoutMs);
    ready = true;
    return {url, stop};
  } catch (error) {
    try {
      await stop();
    } catch (cleanupError) {
		if (cleanupError === error) throw error;
      throw new AggregateError([error, cleanupError], "browser test server failed before readiness and cleanup did not complete");
    }
    throw error;
  }
}

function waitForBrowserServerReady(child, lifecycle, stdout, decodeError, finishDecode, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      child.stdout.off("data", inspect);
      callback(value);
    };
    const inspect = () => {
		const error = decodeError();
		if (error !== null) {
			finish(reject, error);
			return;
		}
      const match = stdout().match(/Proofkit requirement browser: (http:\/\/127\.0\.0\.1:\d+\/)\n/);
      if (match) finish(resolve, match[1]);
    };
	const timeout = setTimeout(() => finish(reject, new Error("browser test server readiness timed out")), timeoutMs);
	child.stdout.on("data", inspect);
	lifecycle.promise.then((outcome) => {
		finishDecode();
		const error = decodeError();
		finish(reject, error ?? terminalOutcomeError(outcome, "before readiness"));
	});
    inspect();
  });
}

function observeChildProcess(child) {
  let current = null;
  let resolveTerminal;
  const promise = new Promise((resolve) => { resolveTerminal = resolve; });
  const record = (outcome) => {
    if (current !== null) return;
    current = outcome;
    resolveTerminal(outcome);
  };
  const onExit = (code, signal) => record({code, kind: "exit", signal});
  const onError = () => record({kind: "error"});
  child.once("exit", onExit);
  child.on("error", onError);
  if (child.exitCode !== null || child.signalCode !== null) onExit(child.exitCode, child.signalCode);
  return {
    current: () => current,
    dispose: () => {
      child.off("exit", onExit);
      child.off("error", onError);
    },
    promise,
  };
}

async function stopChildProcess(child, lifecycle, timeoutMs, rejectExistingTerminal) {
  const existing = lifecycle.current();
  if (existing !== null) {
    if (rejectExistingTerminal) throw terminalOutcomeError(existing, "before requested shutdown");
    return;
  }
  child.kill("SIGTERM");
  let outcome = await waitForTerminalOutcome(lifecycle, timeoutMs);
  if (outcome !== null) {
    admitRequestedShutdown(outcome);
    return;
  }
  child.kill("SIGKILL");
  outcome = await waitForTerminalOutcome(lifecycle, timeoutMs);
  if (outcome === null) throw new Error("browser test server did not stop after SIGKILL");
  admitRequestedShutdown(outcome);
}

function waitForTerminalOutcome(lifecycle, timeoutMs) {
  const existing = lifecycle.current();
  if (existing !== null) return Promise.resolve(existing);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(outcome);
    };
    const timeout = setTimeout(() => finish(null), timeoutMs);
    lifecycle.promise.then(finish);
  });
}

function admitRequestedShutdown(outcome) {
  if (outcome.kind === "error") throw terminalOutcomeError(outcome, "during requested shutdown");
  if (outcome.code === 0 || outcome.signal === "SIGTERM" || outcome.signal === "SIGKILL") return;
  throw terminalOutcomeError(outcome, "during requested shutdown");
}

function terminalOutcomeError(outcome, phase) {
  if (outcome.kind === "error") return new Error(`browser test server process error ${phase}`);
	return new Error(`browser test server exited ${phase} with code ${outcome.code} and signal ${outcome.signal}`);
}

function boundedUTF8Stream(label) {
	const decoder = createUTF8StrictStreamDecoder(label);
	let decodeError = null;
	let output = "";
	let finished = false;
	const append = (text) => {
		const next = output + text;
		output = next.length <= 65_536 ? next : next.slice(-65_536);
	};
	return {
		error: () => decodeError,
		finish() {
			if (finished || decodeError !== null) return;
			finished = true;
			try {
				append(decoder.finish());
			} catch (error) {
				decodeError = error;
			}
		},
		value: () => output,
		write(chunk) {
			if (finished || decodeError !== null) return;
			try {
				append(decoder.write(chunk));
			} catch (error) {
				decodeError = error;
			}
		},
	};
}
