import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {after, before} from "node:test";
import {assertCLITransport} from "./cli-process.mjs";

// 8 MiB exceeds every pipe buffer, so a child that exits without reading stdin
// deterministically leaves spawnSync with an unwritten payload and EPIPE.
const payload = "x".repeat(8 << 20);
const root = new URL("../", import.meta.url);
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-cli-process-"));
  binary = join(directory, "proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 180000, maxBuffer: 2 << 20, env: {...process.env, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });
const invoke = (file, args, input, timeout = 20000, maxBuffer = 2 << 20) => spawnSync(file, args, {input, encoding: "utf8", timeout, maxBuffer});
const fakeChild = (source, input = payload, maxBuffer) => invoke(process.execPath, ["-e", source], input, 20000, maxBuffer);
const rejected = (result, label) => assert.throws(() => assertCLITransport(result, label), {code: "ERR_ASSERTION"}, label);

test("a CLI flag refusal that exits before reading stdin is accepted as a closed pipe", () => {
  const args = ["change", "plan", "--input", "-", "--agent-envelope", "--format", "text"];
  const refusal = invoke(binary, args, payload);
  assert.equal(refusal.error?.code, "EPIPE", "the oversized payload must outlast the refusing child");
  assert.equal(assertCLITransport(refusal, "early refusal"), refusal);
  assert.equal(refusal.status, 1); assert.equal(refusal.stdout, ""); assert.notEqual(refusal.stderr, "");
  const small = assertCLITransport(invoke(binary, args, "{}"), "small refusal");
  assert.equal(small.status, 1); assert.equal(small.stderr, refusal.stderr);
});

test("EPIPE from a child that exits 0 without reading its required input is rejected", () => {
  const result = fakeChild("process.exit(0)");
  assert.equal(result.error?.code, "EPIPE"); assert.equal(result.status, 0); assert.equal(result.signal, null);
  rejected(result, "unread input with status 0");
});

test("a child killed by a signal is rejected with or without EPIPE", () => {
  const result = fakeChild("process.kill(process.pid, 'SIGKILL')");
  assert.equal(result.error?.code, "EPIPE"); assert.equal(result.status, null); assert.equal(result.signal, "SIGKILL");
  rejected(result, "signal with EPIPE");
  const withoutInput = fakeChild("process.kill(process.pid, 'SIGKILL')", "");
  assert.equal(withoutInput.error, undefined); assert.equal(withoutInput.signal, "SIGKILL");
  rejected(withoutInput, "signal without EPIPE");
});

test("spawn errors other than EPIPE and timeouts are rejected", () => {
  const absent = invoke(join(directory, "absent"), [], payload);
  assert.equal(absent.error?.code, "ENOENT"); assert.equal(absent.signal, null);
  rejected(absent, "spawn failure");
  // The child traps the maxBuffer kill and exits non-zero, so only the error code separates it from an early refusal.
  const overflow = fakeChild("process.on('SIGTERM', () => process.exit(3)); process.stdout.write('x'.repeat(1 << 20)); setInterval(() => {}, 1000)", "", 1024);
  assert.equal(overflow.error?.code, "ENOBUFS"); assert.ok(Number.isInteger(overflow.status) && overflow.status !== 0); assert.equal(overflow.signal, null);
  rejected(overflow, "output overflow");
  const timeout = invoke(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], "", 200);
  assert.equal(timeout.error?.code, "ETIMEDOUT");
  rejected(timeout, "timeout");
});
