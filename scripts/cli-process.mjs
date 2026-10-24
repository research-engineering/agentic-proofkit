// Transport for oracles that run the Proofkit CLI, or another child process,
// synchronously.
//
// spawnWithInputFile(file, args, options) is spawnSync(file, args, options),
// except that options.input reaches the child as a standard input opened on
// a temporary regular file instead of through a pipe. For the `input` option,
// Node's spawnSync gives the child one end of a Unix-domain socket pair: it
// writes the input, calls shutdown(SHUT_WR) on its end and keeps that end open
// until the child exits or the timeout kills it. On macOS, a child blocked in
// read(2) on the socket is sometimes not woken by the shutdown although the
// socket already holds end of file, so the call ends only at its timeout. The
// same syscall sequence stalls without Node; a pipe, a close or a regular file
// does not. A regular file ends at its size, so the child always reads end of
// file.
//
// args must be an array. spawnSync(file, options) would take the options from
// the args position and drop the third argument, so the two-argument form
// would feed the input through the socket again; it is refused.
//
// The input is written to a file of mode 0600 in a fresh directory of mode
// 0700 and opened read-only. The directory is removed as soon as the file is
// open, before the child starts: the open descriptor keeps the file, so while
// the child runs no input remains on disk, and a signal that ends this process
// then leaves none behind. A throw while the file is written or opened removes
// the directory too. The removal uses path calls only; if it fails, the input
// descriptor is closed and the call throws.
//
// The result is spawnSync's result (status, signal, error, stdout, stderr,
// output, pid) plus stdinUnreadBytes: the input bytes past the file offset
// that the child shares with this process, read when the child has exited.
// read(2) and lseek(2) on the inherited descriptor move that offset; pread(2),
// mmap(2) and, on Linux, reopening /dev/stdin do not. A child that reads its
// input only those ways reports unread bytes although it read them, and a
// child that seeks past bytes it did not read reports them as read. No current
// caller depends on those readings: its children are Proofkit CLI builds and
// the Node probes of cli-process.test.mjs, which read their standard input
// with read(2) or not at all. An empty or absent input is an empty file. With
// stdio ["ignore", "pipe", "pipe"] the child's standard input is the null
// device, no input is allowed and stdinUnreadBytes is absent.
//
// assertCLITransport checks the transport of a result. A CLI that refuses its
// flags exits before it reads stdin. Through a pipe (an asynchronous spawn
// that writes stdin), the parent can then report EPIPE for the input it could
// not write; through spawnWithInputFile, stdinUnreadBytes is not zero. As in
// internal/tools/workflowsmoke/process_streams.go, either is an ordinary early
// exit and not a transport failure only when the child exited normally with a
// non-zero status and no signal. Any other spawn error, a timeout, a signal,
// and EPIPE or a non-zero stdinUnreadBytes with status 0 (a success that did
// not consume its input) fail. Callers keep their own status, stdout and
// stderr checks.
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {closeSync, mkdtempSync, openSync, readSync, rmdirSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";

const passedOptions = new Set(["cwd", "encoding", "env", "killSignal", "maxBuffer", "timeout"]);
const ignoredStdin = ["ignore", "pipe", "pipe"];

export function spawnWithInputFile(file, args, options = {}) {
  if (!Array.isArray(args)) {
    throw new TypeError("spawnWithInputFile: args must be an array; spawnWithInputFile(file, options) is refused");
  }
  const {input, stdio, ...passed} = options;
  for (const key of Object.keys(passed)) {
    if (!passedOptions.has(key)) throw new TypeError(`spawnWithInputFile: unsupported option ${key}`);
  }
  if (stdio !== undefined) {
    if (!Array.isArray(stdio) || stdio.length !== ignoredStdin.length || stdio.some((value, index) => value !== ignoredStdin[index])) {
      throw new TypeError('spawnWithInputFile: stdio must be absent or ["ignore", "pipe", "pipe"]');
    }
    if (input !== undefined) throw new TypeError("spawnWithInputFile: input with an ignored standard input");
    return spawnSync(file, args, {...passed, stdio});
  }
  const bytes = inputBytes(input, passed.encoding);
  const directory = mkdtempSync(join(tmpdir(), "proofkit-cli-stdin-"));
  const path = join(directory, "stdin");
  let descriptor;
  try {
    writeFileSync(path, bytes, {flag: "wx", mode: 0o600});
    descriptor = openSync(path, "r");
  } finally {
    // Path calls only: the removal needs no descriptor of its own. If it
    // fails, the input descriptor is closed before the throw.
    try {
      rmSync(path, {force: true});
      rmdirSync(directory);
    } catch (error) {
      if (descriptor !== undefined) closeSync(descriptor);
      throw error;
    }
  }
  try {
    // Only the caller's options pass: an explicit undefined maxBuffer would lift spawnSync's default bound.
    const result = spawnSync(file, args, {...passed, stdio: [descriptor, "pipe", "pipe"]});
    result.stdinUnreadBytes = unreadBytes(descriptor);
    return result;
  } finally {
    closeSync(descriptor);
  }
}

// As spawnSync does, a falsy input is no input and a string is encoded with
// options.encoding.
function inputBytes(input, encoding) {
  if (!input) return Buffer.alloc(0);
  if (typeof input === "string") return Buffer.from(input, encoding);
  if (ArrayBuffer.isView(input)) return input;
  throw new TypeError("spawnWithInputFile: input must be a string, Buffer, TypedArray or DataView");
}

// The child inherited this open file description, so its read(2) calls
// advanced the shared offset; reading from that offset counts the bytes past
// it.
function unreadBytes(descriptor) {
  const buffer = Buffer.allocUnsafe(1 << 16);
  let total = 0;
  for (let count; (count = readSync(descriptor, buffer, 0, buffer.length, null)) > 0;) total += count;
  return total;
}

export function assertCLITransport(result, label = "CLI") {
  const observed = `${label}: transport error ${result.error}, status ${result.status}, signal ${result.signal}, unread input bytes ${result.stdinUnreadBytes}`;
  const refusal = Number.isInteger(result.status) && result.status !== 0;
  assert.equal(result.signal, null, observed);
  if (result.error !== undefined) {
    assert.equal(result.error.code, "EPIPE", observed);
    assert.ok(refusal, observed);
  }
  if (result.stdinUnreadBytes !== undefined && result.stdinUnreadBytes !== 0) assert.ok(refusal, observed);
  return result;
}
