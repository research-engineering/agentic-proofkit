import assert from "node:assert/strict";
import {execFileSync, spawn} from "node:child_process";
import fs, {mkdtempSync, readFileSync, readdirSync, rmSync, statSync} from "node:fs";
import {syncBuiltinESMExports} from "node:module";
import {tmpdir} from "node:os";
import {dirname, join, sep} from "node:path";
import test, {after, before} from "node:test";
import {fileURLToPath} from "node:url";
import {assertCLITransport, spawnWithInputFile} from "./cli-process.mjs";

// 8 MiB exceeds every pipe buffer, so a child that exits without reading stdin
// deterministically leaves a pipe writer with an unwritten payload and EPIPE.
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
const invoke = (file, args, input, timeout = 20000, maxBuffer = 2 << 20) => spawnWithInputFile(file, args, {input, encoding: "utf8", timeout, maxBuffer});
const fakeChild = (source, input = payload, maxBuffer) => invoke(process.execPath, ["-e", source], input, 20000, maxBuffer);
const rejected = (result, label) => assert.throws(() => assertCLITransport(result, label), {code: "ERR_ASSERTION"}, label);
// The asynchronous pipe transport of scripts/schema-completeness.test.mjs: the
// parent writes stdin through a pipe and reports EPIPE when the child is gone.
const pipeChild = (file, args, input) => new Promise(resolve => {
  const child = spawn(file, args);
  let failure, stdinError;
  child.on("error", error => { failure ??= error; });
  child.stdin.on("error", error => { stdinError ??= error; });
  child.stdout.resume(); child.stderr.resume();
  child.on("close", (status, signal) => resolve({status, signal, error: failure ?? stdinError}));
  child.stdin.end(input);
});

test("a CLI flag refusal that exits before reading stdin is accepted with its input unread", async () => {
  const args = ["change", "plan", "--input", "-", "--agent-envelope", "--format", "text"];
  const refusal = invoke(binary, args, payload);
  assert.equal(refusal.error, undefined); assert.equal(refusal.stdinUnreadBytes, payload.length, "the refusal must read none of its input");
  assert.equal(assertCLITransport(refusal, "early refusal"), refusal);
  assert.equal(refusal.status, 1); assert.equal(refusal.stdout, ""); assert.notEqual(refusal.stderr, "");
  const small = assertCLITransport(invoke(binary, args, "{}"), "small refusal");
  assert.equal(small.status, 1); assert.equal(small.stderr, refusal.stderr); assert.equal(small.stdinUnreadBytes, 2);
  const piped = await pipeChild(binary, args, payload);
  assert.equal(piped.error?.code, "EPIPE", "the oversized payload must outlast the refusing child");
  assert.equal(assertCLITransport(piped, "early refusal through a pipe"), piped); assert.equal(piped.status, 1);
});

test("unread input or EPIPE from a child that exits 0 is rejected", async () => {
  const result = fakeChild("process.exit(0)");
  assert.equal(result.error, undefined); assert.equal(result.status, 0); assert.equal(result.stdinUnreadBytes, payload.length);
  rejected(result, "unread input with status 0");
  const partial = fakeChild("require('node:fs').readSync(0, Buffer.alloc(1024)); process.exit(0)");
  assert.equal(partial.status, 0); assert.equal(partial.stdinUnreadBytes, payload.length - 1024);
  rejected(partial, "partly read input with status 0");
  const piped = await pipeChild(process.execPath, ["-e", "process.exit(0)"], payload);
  assert.equal(piped.error?.code, "EPIPE"); assert.equal(piped.status, 0); assert.equal(piped.signal, null);
  rejected(piped, "EPIPE with status 0");
});

test("a child killed by a signal is rejected with or without unread input", async () => {
  const result = fakeChild("process.kill(process.pid, 'SIGKILL')");
  assert.equal(result.status, null); assert.equal(result.signal, "SIGKILL"); assert.equal(result.stdinUnreadBytes, payload.length);
  rejected(result, "signal with unread input");
  const withoutInput = fakeChild("process.kill(process.pid, 'SIGKILL')", "");
  assert.equal(withoutInput.error, undefined); assert.equal(withoutInput.signal, "SIGKILL"); assert.equal(withoutInput.stdinUnreadBytes, 0);
  rejected(withoutInput, "signal without input");
  const piped = await pipeChild(process.execPath, ["-e", "process.kill(process.pid, 'SIGKILL')"], payload);
  assert.equal(piped.error?.code, "EPIPE"); assert.equal(piped.signal, "SIGKILL");
  rejected(piped, "signal with EPIPE");
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

// The child reports the kind of its standard input and the bytes it read.
const stdinProbe = "const fs = require('node:fs'); const stat = fs.fstatSync(0); const bytes = fs.readFileSync(0);"
  + " process.stdout.write(JSON.stringify({file: stat.isFile(), socket: stat.isSocket(), fifo: stat.isFIFO(), device: stat.isCharacterDevice(), hex: bytes.toString('hex')}))";

test("input reaches the child as a regular file that it reads to the end", () => {
  const cases = [
    ["string", "caf\u00e9 \u{1F600}\n", Buffer.from("caf\u00e9 \u{1F600}\n", "utf8")],
    ["Buffer", Buffer.from([0, 255, 10, 13]), Buffer.from([0, 255, 10, 13])],
    ["Uint8Array", new Uint8Array([1, 2, 3]), Buffer.from([1, 2, 3])],
    ["empty string", "", Buffer.alloc(0)],
    ["absent", undefined, Buffer.alloc(0)],
  ];
  for (const [label, input, expected] of cases) {
    const result = assertCLITransport(invoke(process.execPath, ["-e", stdinProbe], input), label);
    assert.equal(result.status, 0, `${label}: ${result.stderr}`); assert.equal(result.stdinUnreadBytes, 0, label);
    assert.deepEqual(JSON.parse(result.stdout), {file: true, socket: false, fifo: false, device: false, hex: expected.toString("hex")}, label);
  }
  const latin1 = spawnWithInputFile(process.execPath, ["-e", stdinProbe], {input: "\u00e9", encoding: "latin1"});
  assert.equal(JSON.parse(latin1.stdout).hex, "e9", "a string input is encoded with options.encoding, as spawnSync does");
  const ignored = spawnWithInputFile(process.execPath, ["-e", stdinProbe], {stdio: ["ignore", "pipe", "pipe"], encoding: "utf8"});
  assert.equal(ignored.status, 0, ignored.stderr); assert.equal(ignored.stdinUnreadBytes, undefined);
  assert.deepEqual(JSON.parse(ignored.stdout), {file: false, socket: false, fifo: false, device: true, hex: ""});
});

test("the helper keeps spawnSync's options and refuses what it cannot keep", () => {
  // Without maxBuffer the child still has spawnSync's default bound.
  const bounded = spawnWithInputFile(process.execPath, ["-e", "process.stdout.write('x'.repeat(2 << 20))"], {input: "{}", encoding: "utf8"});
  assert.equal(bounded.error?.code, "ENOBUFS");
  const options = spawnWithInputFile(process.execPath, ["-e", "process.stdout.write(process.cwd() + ' ' + process.env.PROOFKIT_PROBE)"],
    {cwd: directory, env: {...process.env, PROOFKIT_PROBE: "kept"}, encoding: "utf8", timeout: 20000, killSignal: "SIGKILL", maxBuffer: 1 << 20});
  assert.equal(options.status, 0, options.stderr); assert.match(options.stdout, / kept$/);
  assert.throws(() => spawnWithInputFile(process.execPath, [], {shell: true}), /unsupported option shell/);
  assert.throws(() => spawnWithInputFile(process.execPath, [], {stdio: "pipe"}), /stdio must be absent/);
  assert.throws(() => spawnWithInputFile(process.execPath, [], {stdio: ["pipe", "pipe", "pipe"]}), /stdio must be absent/);
  assert.throws(() => spawnWithInputFile(process.execPath, [], {stdio: ["ignore", "pipe", "pipe"], input: "{}"}), /ignored standard input/);
  assert.throws(() => spawnWithInputFile(process.execPath, [], {input: 7}), /input must be/);
  // spawnSync(file, options) would take {input} as its options and drop the third argument.
  assert.throws(() => spawnWithInputFile(process.execPath, {input: "{}"}), /args must be an array/, "the two-argument form");
  assert.throws(() => spawnWithInputFile(process.execPath, undefined, {input: "{}"}), /args must be an array/);
  assert.throws(() => spawnWithInputFile(process.execPath, "-e", {input: "{}"}), /args must be an array/);
});

// The helper's temporary root is a fresh TMPDIR, so the test sees every entry
// the helper leaves there. A wrapper of fs.openSync records the modes of the
// input file and of its directory at the read-only open (writeFileSync's own
// open for writing passes through), and can make that open fail; the child
// reports what it sees while it runs. Wrappers of fs.writeFileSync, fs.rmSync
// and fs.rmdirSync can make the write fail after it created the file, or the
// first removal call fail; the open descriptors of this process are the
// entries of /dev/fd.
test("the input file leaves the disk before the child runs, and no file remains after a call or a throw", () => {
  const root = mkdtempSync(join(tmpdir(), "proofkit-cli-process-tmp-"));
  const savedTMPDIR = process.env.TMPDIR, opened = [];
  const original = {openSync: fs.openSync, writeFileSync: fs.writeFileSync, rmSync: fs.rmSync, rmdirSync: fs.rmdirSync};
  const inRoot = path => typeof path === "string" && path.startsWith(root + sep);
  const simulated = (message, code) => Object.assign(new Error(message), {code});
  let failOpen = false, failWrite = false, failRemoval = false;
  fs.openSync = (path, ...rest) => {
    if (inRoot(path) && rest[0] === "r") {
      opened.push({directory: statSync(dirname(path)).mode & 0o777, file: statSync(path).mode & 0o777});
      if (failOpen) throw simulated("simulated open failure", "EMFILE");
    }
    return original.openSync(path, ...rest);
  };
  fs.writeFileSync = (path, data, ...rest) => {
    if (!inRoot(path) || !failWrite) return original.writeFileSync(path, data, ...rest);
    original.writeFileSync(path, "", ...rest);
    throw simulated("simulated write failure", "ENOSPC");
  };
  const removal = name => (path, ...rest) => {
    if (inRoot(path) && failRemoval) { failRemoval = false; throw simulated(`simulated ${name} failure`, "EBUSY"); }
    return original[name](path, ...rest);
  };
  fs.rmSync = removal("rmSync"); fs.rmdirSync = removal("rmdirSync");
  syncBuiltinESMExports();
  process.env.TMPDIR = root;
  try {
    const probe = "const fs = require('node:fs'); const stat = fs.fstatSync(0);"
      + " process.stdout.write(JSON.stringify({mode: stat.mode & 0o777, links: stat.nlink, entries: fs.readdirSync(process.env.TMPDIR), bytes: fs.readFileSync(0).length}))";
    const result = assertCLITransport(spawnWithInputFile(process.execPath, ["-e", probe], {input: '{"a":1}', encoding: "utf8", timeout: 20000}), "residue probe");
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {mode: 0o600, links: 0, entries: [], bytes: 7}, "the child must read an unlinked 0600 file, with no input left on disk");
    assert.deepEqual(opened, [{directory: 0o700, file: 0o600}], "the directory is 0700 and the file 0600 up to the open");
    assert.deepEqual(readdirSync(root), [], "no file may remain after a call");
    assert.throws(() => spawnWithInputFile(process.execPath, ["-e", ""], {input: "{}", timeout: -1}), {code: "ERR_OUT_OF_RANGE"});
    assert.deepEqual(readdirSync(root), [], "no file may remain after spawnSync throws");
    failOpen = true;
    assert.throws(() => spawnWithInputFile(process.execPath, ["-e", ""], {input: "{}"}), {code: "EMFILE"});
    assert.deepEqual(readdirSync(root), [], "no file may remain after the open throws");
    assert.equal(opened.length, 3);
    failOpen = false; failWrite = true;
    assert.throws(() => spawnWithInputFile(process.execPath, ["-e", ""], {input: "{}"}), {code: "ENOSPC"});
    assert.deepEqual(readdirSync(root), [], "no file may remain after the write throws");
    failWrite = false; failRemoval = true;
    const descriptors = readdirSync("/dev/fd").length;
    assert.throws(() => spawnWithInputFile(process.execPath, ["-e", ""], {input: "{}"}), {code: "EBUSY"});
    assert.equal(readdirSync("/dev/fd").length, descriptors, "a failed removal must close the input descriptor");
  } finally {
    Object.assign(fs, original);
    syncBuiltinESMExports();
    if (savedTMPDIR === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = savedTMPDIR;
    rmSync(root, {recursive: true, force: true});
  }
});

// Source check: a lexical scan of the .js, .cjs, .mjs, .ts, .cts and .mts files
// under scripts/ and tests/ (node_modules excluded) that refuses an `input`
// member in the arguments of a direct spawnSync, execFileSync or execSync
// call; spawnWithInputFile carries input instead. It skips comments, strings,
// template text and regular expressions, finds each name of the three
// functions followed by "(", also as a member (x.spawnSync(...)), and reports
// every `input` member of an object literal anywhere in that call's
// arguments: a plain or quoted key, a string-literal computed key
// (["input"]), a shorthand, or a method with a plain or quoted name. It does
// not see options assembled outside the call, a synchronous spawn function
// under another name, calls through .call, .apply, Reflect.apply or an
// optional call ?.(), a bracketed callee (cp["spawnSync"](...)), a call with
// type arguments (spawnSync<T>(...)), getter, setter, async or generator
// members, methods with a computed key (["input"]() {...}), computed keys
// other than string literals, or escaped key names. Its lexer chooses between
// a division and a regular expression from the previous token alone, so it
// misreads some code: for example a / after ++, --, a template literal, an
// object literal, a property named like a keyword that a regular expression
// can follow (x.in / y) or a name with a non-ASCII letter, a regular
// expression after ) or export default (export default /'/), and a hashbang
// line with an unbalanced quote. A misreading can hide the code after it.
const synchronousSpawns = new Set(["spawnSync", "execFileSync", "execSync"]);
const regexAfter = new Set(["await", "case", "delete", "do", "else", "in", "instanceof", "new", "of", "return", "throw", "typeof", "void", "yield"]);

function tokenize(source) {
  const tokens = [], frames = [];
  let index = 0, line = 1;
  const push = (type, value) => tokens.push({type, value, line});
  const take = end => { line += source.slice(index, end).split("\n").length - 1; const text = source.slice(index, end); index = end; return text; };
  const quoted = quote => {
    let end = index + 1;
    while (end < source.length && source[end] !== quote) end += source[end] === "\\" ? 2 : 1;
    return take(end + 1).slice(1, -1);
  };
  const templateText = () => {
    let end = index;
    while (end < source.length && source[end] !== "`" && !(source[end] === "$" && source[end + 1] === "{")) end += source[end] === "\\" ? 2 : 1;
    take(end);
    if (source[index] === "`") { take(index + 1); return; }
    take(index + 2); frames.push(0);
  };
  const regexAllowed = () => {
    const previous = tokens.at(-1);
    if (previous === undefined) return true;
    if (previous.type === "name") return regexAfter.has(previous.value);
    return previous.type === "punct" && previous.value !== ")" && previous.value !== "]";
  };
  while (index < source.length) {
    const char = source[index], next = source[index + 1];
    if (/\s/.test(char)) { take(index + 1); continue; }
    if (char === "/" && next === "/") { const end = source.indexOf("\n", index); take(end < 0 ? source.length : end); continue; }
    if (char === "/" && next === "*") { const end = source.indexOf("*/", index + 2); take(end < 0 ? source.length : end + 2); continue; }
    if (char === "'" || char === "\"") { push("string", quoted(char)); continue; }
    if (char === "`") { take(index + 1); templateText(); continue; }
    if (char === "}" && frames.length > 0 && frames.at(-1) === 0) { frames.pop(); take(index + 1); templateText(); continue; }
    if (char === "/" && regexAllowed()) {
      let end = index + 1, inClass = false;
      while (end < source.length && (inClass || source[end] !== "/")) {
        if (source[end] === "\\") end++;
        else if (source[end] === "[") inClass = true;
        else if (source[end] === "]") inClass = false;
        end++;
      }
      end++;
      while (/[a-z]/i.test(source[end] ?? "")) end++;
      push("regex", take(end));
      continue;
    }
    const name = /^[A-Za-z_$][\w$]*/.exec(source.slice(index, index + 256));
    if (name) { push("name", take(index + name[0].length)); continue; }
    const number = /^[0-9][\w.]*/.exec(source.slice(index, index + 64));
    if (number) { push("number", take(index + number[0].length)); continue; }
    const punct = source.startsWith("...", index) ? "..." : char;
    if (frames.length > 0 && punct === "{") frames[frames.length - 1]++;
    if (frames.length > 0 && punct === "}") frames[frames.length - 1]--;
    push("punct", take(index + punct.length));
  }
  return tokens;
}

function inputPipeViolations(source) {
  const tokens = tokenize(source), violations = [];
  const opens = {"(": ")", "[": "]", "{": "}"};
  for (let start = 0; start < tokens.length - 1; start++) {
    const callee = tokens[start];
    if (callee.type !== "name" || !synchronousSpawns.has(callee.value) || tokens[start + 1].value !== "(") continue;
    if (tokens[start - 1]?.value === "function") continue;
    const stack = [];
    for (let at = start + 1; at < tokens.length; at++) {
      const token = tokens[at];
      if (token.type === "punct" && Object.hasOwn(opens, token.value)) { stack.push(token.value); continue; }
      if (token.type === "punct" && Object.values(opens).includes(token.value)) {
        stack.pop();
        if (stack.length === 0) break;
        continue;
      }
      if (token.value !== "input" || (token.type !== "name" && token.type !== "string")) continue;
      const before = tokens[at - 1].value, after = tokens[at + 1]?.value;
      const member = stack.at(-1) === "{" && (before === "{" || before === ",") && [":", ",", "}", "("].includes(after);
      const computed = token.type === "string" && before === "[" && after === "]" && tokens[at + 2]?.value === ":";
      if (member || computed) violations.push(`line ${token.line}: ${callee.value} passes input`);
    }
  }
  return violations;
}

test("the source check finds the input option in synchronous spawn calls", () => {
  const found = [
    "spawnSync(binary, args, {input: text, encoding: 'utf8'});",
    "spawnSync(binary, args, {\n  encoding: 'utf8',\n  input,\n});",
    "child_process.spawnSync(binary, args, {'input': text});",
    "execFileSync(binary, args, {\"input\": text});",
    "execFileSync(binary, {input: text});",
    "execSync(`cat ${file}`, {[\"input\"]: text});",
    "spawnSync(file, args, {...(argvOnly ? {stdio: ['ignore', 'pipe', 'pipe']} : {input}), timeout: 1});",
    "const re = /\\)/; spawnSync(file, [`${x}`, re.source], {env: {...process.env}, input: x});",
    "spawnSync(binary, args, {input() { return text; }});",
  ];
  for (const source of found) assert.equal(inputPipeViolations(source).length, 1, source);
  const clean = [
    "spawnSync(binary, ['--input', '-'], {encoding: 'utf8'});",
    "spawnWithInputFile(binary, args, {input: text});",
    "spawnSync(binary, args, {env: {...process.env, X: input}});",
    "spawnSync(make(a, input), args, {timeout: input ? 1 : 2});",
    "// spawnSync(binary, args, {input: text});\nspawnSync(binary, args);",
    "const text = 'spawnSync(binary, args, {input: text})'; const t = `spawnSync(b, a, {input: ${'x'}})`;",
    "const help = {input: 1}; spawnSync(binary, args, {stdio: 'ignore'});",
    "function spawnSync(file, args, {input} = {}) {}",
  ];
  for (const source of clean) assert.deepEqual(inputPipeViolations(source), [], source);
});

test("no direct synchronous spawn call under scripts or tests passes an input member", () => {
  const rootPath = fileURLToPath(root), violations = [];
  let scanned = 0;
  for (const top of ["scripts", "tests"]) {
    for (const entry of readdirSync(join(rootPath, top), {recursive: true, withFileTypes: true})) {
      if (!entry.isFile() || !/\.[cm]?[jt]s$/.test(entry.name)) continue;
      const path = join(entry.parentPath, entry.name);
      if (path.split(/[\\/]/).includes("node_modules")) continue;
      const source = readFileSync(path, "utf8");
      scanned += tokenize(source).filter(token => token.type === "name" && synchronousSpawns.has(token.value)).length;
      for (const violation of inputPipeViolations(source)) violations.push(`${path.slice(rootPath.length)} ${violation}`);
    }
  }
  assert.ok(scanned > 0, "the scan must see the synchronous spawn calls of the build steps");
  assert.deepEqual(violations, [], "use spawnWithInputFile from scripts/cli-process.mjs for stdin input");
});
