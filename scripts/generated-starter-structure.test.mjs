import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_STARTER_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const baseline = JSON.parse(readFileSync(new URL("internal/app/testdata/generated-starter-native-observations.json", root), "utf8"));
assert.equal(baseline.head, "95b2c5ecb09a86210af20c4e38e6311f9ab5cbaa");
assert.equal(baseline.observations.length, 52);
const names = ["stack-preset", "json-report-cli-adapter-source"];
const ajv = new Ajv2020({strict: false, validateFormats: false});
const validators = new Map(names.map(name => {
  const definition = contract.contractDefinitions.find(x => x.definitionId === `proofkit.${name}.output.v1.json-schema`);
  assert.ok(definition, `${name}/output owner`);
  const command = contract.commands.find(x => x.command === name);
  assert.equal(command.input, "none"); assert.equal(command.inputContract, undefined);
  return [name, ajv.compile(definition.fieldTree.variants[0].schema)];
}));
const presets = {
  agentic_runtime_repo: {files: 3, languages: ["typescript"], environments: 3, witnesses: 4,
    commands: ["stack-preset --preset agentic_runtime_repo", "requirement-bindings --input docs/contracts/requirement-proof-bindings.v1.json", "proof-slice --input docs/contracts/requirement-proof-bindings.v1.json"]},
  generated_docs_contract_repo: {files: 3, languages: ["markdown", "typescript"], environments: 2, witnesses: 3,
    commands: ["stack-preset --preset generated_docs_contract_repo", "evidence-graph --input docs/contracts/requirement-proof-bindings.v1.json"]},
  python_service: {files: 3, languages: ["python"], environments: 2, witnesses: 3,
    commands: ["stack-preset --preset python_service", "witness-scheduler-plan --input proofkit/witness-plan.json"]},
  python_typescript_service: {files: 5, languages: ["python", "typescript"], environments: 3, witnesses: 4,
    commands: ["stack-preset --preset python_typescript_service", "selective-gate-plan --input proofkit/selective-gate-plan.json"]},
  typescript_monorepo: {files: 3, languages: ["typescript"], environments: 2, witnesses: 4,
    commands: ["stack-preset --preset typescript_monorepo", "selective-gate-plan --input proofkit/selective-gate-plan.json"]},
  typescript_workspace: {files: 3, languages: ["typescript"], environments: 2, witnesses: 4,
    commands: ["stack-preset --preset typescript_workspace", "gradual-adoption-bootstrap --input proofkit/bootstrap.json"]},
};
const symbols = ["ProofkitCommandRunOptions", "ProofkitJsonCommandResult", "ProofkitJsonRecord", "ProofkitJsonReportCliFlag",
  "ProofkitJsonReportCliOptions", "ProofkitJsonReportCliParseConfig", "ProofkitJsonReportOutputOptions", "ProofkitJsonValue",
  "ProofkitProcessResult", "ProofkitReportInputReadOptions", "ProofkitReportRecord", "ProofkitTextCommandResult",
  "formatProofkitCliError", "isProofkitJsonRecord", "parseProofkitJsonReportCli", "parseProofkitJsonStrict",
  "proofkitStableJsonString", "proofkitStableJsonValue", "readProofkitJsonReportInput", "readProofkitTextReportInput",
  "runProofkitJsonCommand", "runProofkitJsonReportCliMain", "runProofkitNoInputJsonCommand", "runProofkitTextCommand", "writeProofkitJsonReportOutput"];
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-starter-")); binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120000, env: {...process.env, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
// Declared, single-purpose deltas from the frozen predecessor streams. The
// corpus stays untouched; each delta names its rows and exact byte change.
const helpRows = Object.freeze(["stack-preset--help", "stack-preset-h", "json-report-cli-adapter-source--help", "json-report-cli-adapter-source-h"]);
// The adapter source gives the CLI its input as a regular file, and a call
// without input the null device, instead of spawnSync's input socket, which on
// macOS can leave the child blocked forever. The bundle rows carry the source
// change, its digest and its line count; the texts below are adapter source,
// compared in their JSON string encoding.
const adapterBundleRows = Object.freeze(["adapter-default", "adapter-explicit-json", "adapter-compact"]);
const adapterImportsPredecessor = `import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
`;
const adapterImportsCurrent = `import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readSync, realpathSync, renameSync, rmdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
`;
const adapterTransportPredecessor = `  const childResult = spawnSync(options.binaryPath, childArgs, {
    cwd: options.cwd,
    env: options.env,
    input: options.inputMode === "none" ? undefined : proofkitStableJsonString(input),
    maxBuffer: options.maxBuffer ?? defaultMaxBuffer,
  });
  if (childResult.error !== undefined) {
    throw new Error(formatProofkitCliError(childResult.error));
  }
  const child: ProofkitProcessResult = {
    status: childResult.status,
    stdout: decodeProofkitUTF8(childResult.stdout, "Proofkit stdout"),
    stderr: decodeProofkitUTF8(childResult.stderr, "Proofkit stderr"),
  };
  return {child, outputFile: prepared.outputFile};
}
`;
const adapterTransportCurrent = `  const executionOptions = Object.freeze({...options, cwd: prepared.cwd});
  const inputText = options.inputMode === "none" ? null : proofkitStableJsonString(input);
  const childResult = spawnProofkitChild(executionOptions, childArgs, inputText);
  if (childResult.error !== undefined) {
    throw new Error(formatProofkitCliError(childResult.error));
  }
  const child: ProofkitProcessResult = {
    status: childResult.status,
    stdout: decodeProofkitUTF8(childResult.stdout, "Proofkit stdout"),
    stderr: decodeProofkitUTF8(childResult.stderr, "Proofkit stderr"),
  };
  return {child, outputFile: prepared.outputFile};
}

// Capture before output admission or input serialization can run caller code.
// Node includes enumerable inherited env entries and omits undefined values.
// Its NODE_V8_COVERAGE fallback must also be captured, including absence, so
// spawn cannot substitute a later ambient value. Only owned records are frozen.
function snapshotProofkitRunOptions(caller: ProofkitCommandRunOptions, inputModeOverride?: "none"): ProofkitCommandRunOptions {
  try {
    let parentCwd: string | undefined;
    let parentCwdError: unknown;
    try { parentCwd = process.cwd(); } catch (error) { parentCwdError = error; }
    const {binaryPath, cwd, env, inputMode, jsonLayout, maxBuffer} = caller;
    let executionCwd = cwd;
    if (cwd.length !== 0 && !isAbsolute(cwd)) {
      if (parentCwd === undefined) throw parentCwdError;
      executionCwd = parentCwd + (parentCwd.endsWith(sep) ? "" : sep) + cwd;
    }
    const sourceEnv = env ?? process.env;
    const environment = Object.create(null) as Record<string, string | undefined>;
    for (const key in sourceEnv) environment[key] = sourceEnv[key];
    if (env == null || !Object.hasOwn(env, "NODE_V8_COVERAGE")) {
      const coverage = process.env.NODE_V8_COVERAGE;
      if (coverage) environment.NODE_V8_COVERAGE = coverage;
    }
    return Object.freeze({binaryPath, cwd: executionCwd, env: Object.freeze(environment), inputMode: inputModeOverride ?? inputMode, jsonLayout, maxBuffer});
  } catch (error) {
    throw new Error(formatProofkitCliError(error));
  }
}

// The child never reads its standard input from spawnSync's input option. On
// Unix-like systems that option writes into a socket pair, shuts down writing and
// keeps its end open until the child exits, and on macOS a child blocked reading
// such a socket is sometimes not woken by the shutdown and then waits forever.
// Input goes through a regular file, which ends at its size; a call without input
// gives the child the null device.
function spawnProofkitChild(options: ProofkitCommandRunOptions, childArgs: readonly string[], inputText: string | null) {
  try {
    return inputText === null ?
      spawnProofkitWithStdin(options, childArgs, "ignore") :
      spawnProofkitWithInputFile(options, childArgs, inputText);
  } catch (error) {
    throw new Error(formatProofkitCliError(error));
  }
}

// The input is written to a file created exclusively with mode 0600 in a fresh
// mode 0700 directory under the temporary directory of this process, and the
// child gets that file opened read-only. Except on Windows, the file and its
// directory are removed as soon as the file is open, before the child starts:
// the open descriptor alone keeps the input, so none remains on disk while the
// child runs, and a signal that ends this process then leaves none behind. When
// the call returns or throws, the descriptor is closed and the file and directory
// are removed if they have not been removed yet: on Windows, where an open file
// can keep its name until it is closed, after a throw before the early removal,
// and after a failed early removal. The removal uses path calls only, so it needs
// no descriptor of its own, and a failed removal fails the call.
function spawnProofkitWithInputFile(options: ProofkitCommandRunOptions, childArgs: readonly string[], inputText: string) {
  const directory = mkdtempSync(join(tmpdir(), "proofkit-cli-stdin-"));
  const inputPath = join(directory, "stdin");
  let inputFd: number | null = null;
  let removed = false;
  try {
    const writeFd = openSync(inputPath, "wx", 0o600);
    try {
      writeFileSync(writeFd, inputText, {encoding: "utf8"});
    } finally {
      closeSync(writeFd);
    }
    inputFd = openSync(inputPath, "r");
    if (process.platform !== "win32") {
      removeProofkitInputFile(inputPath, directory);
      removed = true;
    }
    return spawnProofkitWithStdin(options, childArgs, inputFd);
  } finally {
    try {
      if (inputFd !== null) closeSync(inputFd);
    } finally {
      if (!removed) removeProofkitInputFile(inputPath, directory);
    }
  }
}

function removeProofkitInputFile(inputPath: string, directory: string): void {
  rmSync(inputPath, {force: true});
  rmdirSync(directory);
}

function spawnProofkitWithStdin(options: ProofkitCommandRunOptions, childArgs: readonly string[], stdin: "ignore" | number) {
  const environment = options.env === undefined ? undefined : Object.assign(Object.create(null), options.env);
  if (environment !== undefined && !Object.hasOwn(environment, "NODE_V8_COVERAGE")) Object.defineProperty(environment, "NODE_V8_COVERAGE", {value: undefined});
  return spawnSync(options.binaryPath, childArgs, {
    cwd: options.cwd,
    env: environment,
    maxBuffer: options.maxBuffer ?? defaultMaxBuffer,
    stdio: [stdin, "pipe", "pipe"],
  });
}
`;
const jsonText = text => JSON.stringify(text).slice(1, -1);
const adapterStdinReason = "The adapter uses regular-file stdin and one owned execution context, including the admitted physical output root and isolated Node environment.";
const adapterStdinDelta = (suffix, rows, predecessor, current) => Object.freeze({
  id: `ADAPTER-STDIN-FILE-${suffix}`, reason: adapterStdinReason, rows: Object.freeze(rows), predecessor, current, occurrences: 1,
});
const declaredStreamDeltas = Object.freeze([Object.freeze({
  id: "PILOT-D10",
  reason: "Usage lines name the --format values a command admits instead of <mode>.",
  rows: Object.freeze(["json-report-cli-adapter-source--help", "json-report-cli-adapter-source-h"]),
  predecessor: "[--format <mode>]", current: "[--format <json>]", occurrences: 2,
}), Object.freeze({
  id: "HELP-CONTRACT-SCHEMAS",
  reason: "The help contract stanza names the structural JSON Schemas the CLI contract publishes instead of root JSON shapes.",
  rows: helpRows,
  predecessor: "CLI command routing, root JSON shapes,", current: "CLI command routing, structural JSON Schemas,", occurrences: 1,
}),
adapterStdinDelta("IMPORTS", adapterBundleRows, jsonText(adapterImportsPredecessor), jsonText(adapterImportsCurrent)),
adapterStdinDelta("TEXT-OPTIONS", adapterBundleRows,
  jsonText(`  if (options.jsonLayout !== undefined) {
    throw new Error("Proofkit jsonLayout is valid only for JSON command output");
  }
  const {child, outputFile} = runProofkitCommand(commandRoute, input, args, options);`),
  jsonText("  const {child, outputFile} = runProofkitCommand(commandRoute, input, args, options, \"text\");")),
adapterStdinDelta("EXECUTION-OPTIONS", adapterBundleRows,
  jsonText("function runProofkitCommand(commandRoute: string, input: unknown, args: readonly string[], options: ProofkitCommandRunOptions) {"),
  jsonText(`function runProofkitCommand(commandRoute: string, input: unknown, args: readonly string[], callerOptions: ProofkitCommandRunOptions, mode: "json" | "text" | "json-no-input" = "json") {
  const options = snapshotProofkitRunOptions(callerOptions, mode === "json-no-input" ? "none" : undefined);
  if (mode === "text" && options.jsonLayout !== undefined) {
    throw new Error("Proofkit jsonLayout is valid only for JSON command output");
  }`)),
adapterStdinDelta("JSON-RESULT-OWNER", adapterBundleRows,
  jsonText(`  const {child, outputFile} = runProofkitCommand(commandRoute, input, args, options);
  if (child.status !== 0 && child.stdout.trim().length === 0) {`),
  jsonText(`  return readProofkitJsonCommandResult<T>(commandRoute, runProofkitCommand(commandRoute, input, args, options));
}

function readProofkitJsonCommandResult<T>(commandRoute: string, {child, outputFile}: ReturnType<typeof runProofkitCommand>): ProofkitJsonCommandResult<T> {
  if (child.status !== 0 && child.stdout.trim().length === 0) {`)),
adapterStdinDelta("NO-INPUT-OWNER", adapterBundleRows,
  jsonText("  return runProofkitJsonCommand<T>(commandRoute, null, args, {...options, inputMode: \"none\"});"),
  jsonText("  return readProofkitJsonCommandResult<T>(commandRoute, runProofkitCommand(commandRoute, null, args, options, \"json-no-input\"));")),
adapterStdinDelta("TRANSPORT", adapterBundleRows, jsonText(adapterTransportPredecessor), jsonText(adapterTransportCurrent)),
adapterStdinDelta("PREPARED-TYPE", adapterBundleRows,
  jsonText("  let prepared: {readonly args: readonly string[]; readonly outputFile: string | null};"),
  jsonText("  let prepared: {readonly args: readonly string[]; readonly outputFile: string | null; readonly cwd: string};")),
adapterStdinDelta("OUTPUT-CONTEXT-TYPE", adapterBundleRows,
  jsonText("function prepareOutputArgs(cwd: string, args: readonly string[]): {readonly args: readonly string[]; readonly outputFile: string | null} {"),
  jsonText("function prepareOutputArgs(cwd: string, args: readonly string[]): {readonly args: readonly string[]; readonly outputFile: string | null; readonly cwd: string} {")),
adapterStdinDelta("NO-OUTPUT-CONTEXT", adapterBundleRows,
  jsonText("    return {args, outputFile: null};"), jsonText("    return {args, outputFile: null, cwd};")),
adapterStdinDelta("ADMITTED-OUTPUT-CONTEXT", adapterBundleRows,
  jsonText("  return {args: canonicalArgs, outputFile: target.filePath};"),
  jsonText("  return {args: canonicalArgs, outputFile: target.filePath, cwd: target.cwd};")),
adapterStdinDelta("OUTPUT-TARGET-TYPE", adapterBundleRows,
  jsonText("function admitWritableOutputTarget(cwd: string, outputPath: string): {readonly argument: string; readonly filePath: string} {"),
  jsonText("function admitWritableOutputTarget(cwd: string, outputPath: string): {readonly argument: string; readonly filePath: string; readonly cwd: string} {")),
adapterStdinDelta("PHYSICAL-OUTPUT-ROOT", adapterBundleRows,
  jsonText("\tconst root = realpathSync(cwd);"), jsonText("\tconst root = realpathSync.native(cwd);")),
adapterStdinDelta("OUTPUT-ROOT-BINDING", adapterBundleRows,
  jsonText("  return {argument: relative(root, filePath), filePath};"),
  jsonText("  return {argument: relative(root, filePath), filePath, cwd: root};")),
adapterStdinDelta("SHA256", adapterBundleRows,
  "sha256:e9089d40688aa25c2565633825244c55bcadab85b65c74242ef871cedc2c6533",
  "sha256:434d4b3a03096288ae895711ba0626e7e705fdc7724cfcba3e7306d8ce5ec06b"),
adapterStdinDelta("LINE-COUNT", ["adapter-default", "adapter-explicit-json"], "\"lineCount\": 1124", "\"lineCount\": 1224"),
adapterStdinDelta("LINE-COUNT-COMPACT", ["adapter-compact"], "\"lineCount\":1124", "\"lineCount\":1224"),
]);
const count = (text, needle) => text.split(needle).length - 1;
// Returns the predecessor stdout implied by the declared deltas of a row, or null
// when the current bytes do not carry exactly each delta in exactly its occurrences.
function predecessorStdout(rowName, stdout) {
  let predecessor = stdout;
  for (const delta of declaredStreamDeltas.filter(item => item.rows.includes(rowName))) {
    if (count(predecessor, delta.current) !== delta.occurrences || count(predecessor, delta.predecessor) !== 0) return null;
    predecessor = predecessor.split(delta.current).join(delta.predecessor);
  }
  return predecessor;
}
const conservesPredecessor = (row, stdout) => {
  const predecessor = predecessorStdout(row.name, stdout);
  return predecessor !== null && hash(predecessor) === row.stdoutSHA256;
};
function invoke(row) {
  const result = spawnSync(binary, row.argv, {stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 10000, maxBuffer: 2 << 20,
    env: {...process.env, AGENTIC_PROOFKIT_LAUNCHER_PROFILE: row.launcherProfile || "path", AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: row.pythonExecutable || ""}});
  assert.equal(result.error, undefined); assert.equal(result.signal, null); return result;
}
function bundleSemantics(value) {
  assert.equal(value.artifactKind, "proofkit.json-report-cli-adapter-source");
  assert.equal(value.generatorId, "proofkit.json-report-cli-adapter-source.typescript.v2");
  assert.equal(value.sourceFileName, "proofkit-json-report-cli-adapter.ts");
  assert.equal(value.language, "typescript"); assert.equal(value.format, "json");
  assert.equal(value.sourceSha256, `sha256:${hash(value.source)}`);
  assert.deepEqual(value.exportedSymbols, symbols);
  assert.deepEqual(value.summary, {exportedSymbolCount: 25,
    lineCount: value.source.split("\n").length - Number(value.source.endsWith("\n")),
    publicContract: "CLI/JSON plus generated source; no package-root SDK contract"});
}
function presetSemantics(value, row) {
  const id = row.argv[row.argv.indexOf("--preset") + 1], expected = presets[id];
  assert.ok(expected); assert.equal(value.reportKind, "proofkit.stack-preset");
  assert.equal(value.reportId, `proofkit.stack-preset.${id}`); assert.equal(value.state, "passed");
  assert.deepEqual(value.summary, {expectedFileCount: expected.files, presetId: id, primaryLanguages: expected.languages,
    starterEnvironmentClassCount: expected.environments, starterWitnessKindCount: expected.witnesses});
  assert.deepEqual(value.diagnostics[0], {key: "pathPolicy", value: {consumerOverrideRequired: true, defaultFilesAreSuggestions: true,
    nonClaims: ["Stack presets do not override consuming repository documentation policy.", "Stack presets do not prove that suggested paths are complete for a consuming repository."],
    policyClass: "starter_suggestion"}});
  const detail = value.diagnostics[1]; assert.equal(detail.key, "preset");
  assert.equal(detail.value.expectedFiles.length, expected.files);
  let prefix = "agentic-proofkit";
  if (row.launcherProfile === "npm_offline") prefix = "npm exec --offline -- agentic-proofkit";
  if (row.launcherProfile === "python_module") prefix = row.pythonExecutable === "/opt/Proof Kit's/python"
    ? "'/opt/Proof Kit'\"'\"'s/python' -m agentic_proofkit" : "/opt/python/bin/python -m agentic_proofkit";
  assert.deepEqual(detail.value.suggestedCommands, expected.commands.map(command => `${prefix} ${command}`));
  assert.deepEqual(value.ruleResults, [{diagnostics: [], message: "stack preset is deterministic and non-authoritative",
    ruleId: "proofkit.stack-preset.accepted", status: "passed"}]);
  assert.deepEqual(value.nonClaims, ["Stack presets do not read repository state.", "Stack presets do not execute native witnesses.",
    "Stack presets do not own consuming repository policy.", "Stack presets do not prove requirement coverage or rollout readiness."]);
}

test("starter outputs preserve predecessor streams, launcher domains and independent meanings", () => {
  for (const row of baseline.observations) {
    const result = invoke(row);
    assert.equal(result.status, row.exitCode, row.name);
    assert.ok(conservesPredecessor(row, result.stdout), `${row.name}/stdout`);
    assert.equal(hash(result.stderr), row.stderrSHA256, `${row.name}/stderr`);
    if (row.exitCode !== 0 || row.argv.some(x => x === "-h" || x === "--help")) continue;
    const command = row.argv.find(x => names.includes(x)), value = JSON.parse(result.stdout);
    assert.equal(validators.get(command)(value), true, `${row.name}/schema`);
    if (command === "stack-preset") presetSemantics(value, row); else bundleSemantics(value);
  }
});

const at = (value, path) => path.reduce((current, key) => current[key], value);
function paths(value, path = [], result = []) {
  result.push({path, value});
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) paths(child, [...path, Array.isArray(value) ? Number(key) : key], result);
  }
  return result;
}
function replace(value, path, replacement) {
  const copy = structuredClone(value), parent = at(copy, path.slice(0, -1));
  parent[path.at(-1)] = replacement; return copy;
}
test("starter nested fields and ordered tuples reject missing unknown null type and domain drift", () => {
  const cases = baseline.observations.filter(x => x.name === "adapter-default" || /^preset-(?!.*-compact$)/.test(x.name) && x.exitCode === 0);
  assert.equal(cases.length, 7);
  for (const row of cases) {
    const command = row.argv[0], valid = validators.get(command), result = invoke(row);
    assert.equal(result.status, 0); const value = JSON.parse(result.stdout);
    for (const item of paths(value)) {
      const {path, value: original} = item;
      if (original && !Array.isArray(original) && typeof original === "object") {
        const unknown = structuredClone(value); at(unknown, path).foreign = true;
        assert.equal(valid(unknown), false, `${row.name}/${path}/unknown`);
        for (const key of Object.keys(original)) {
          const missing = structuredClone(value); delete at(missing, path)[key];
          assert.equal(valid(missing), false, `${row.name}/${path}/${key}/missing`);
        }
      }
      if (path.length) {
        assert.equal(valid(replace(value, path, null)), false, `${row.name}/${path}/null`);
        assert.equal(valid(replace(value, path, typeof original === "string" ? 0 : "wrong-type")), false, `${row.name}/${path}/type`);
      }
      if (Array.isArray(original)) {
        if (original.length) assert.equal(valid(replace(value, path, original.slice(0, -1))), false, `${row.name}/${path}/short`);
        assert.equal(valid(replace(value, path, [...original, original[0] ?? null])), false, `${row.name}/${path}/long`);
        if (original.length > 1 && path.at(-1) !== "suggestedCommands") {
          assert.equal(valid(replace(value, path, [...original].reverse())), false, `${row.name}/${path}/order`);
        }
      }
      if (typeof original === "string") {
        assert.equal(valid(replace(value, path, "")), false, `${row.name}/${path}/empty`);
        const dynamic = path[0] === "source" || path.includes("suggestedCommands");
        assert.equal(valid(replace(value, path, dynamic ? " \t\n" : "foreign-value")), false, `${row.name}/${path}/domain`);
      }
      if (typeof original === "boolean") assert.equal(valid(replace(value, path, !original)), false, `${row.name}/${path}/boolean`);
      if (typeof original === "number") {
        assert.equal(valid(replace(value, path, -1)), false, `${row.name}/${path}/negative`);
        assert.equal(valid(replace(value, path, 1.5)), false, `${row.name}/${path}/fraction`);
        if (path.at(-1) !== "lineCount") assert.equal(valid(replace(value, path, original + 1)), false, `${row.name}/${path}/literal`);
      }
    }
  }
});

test("starter schema does not launder native-only hash line-count and rendered-command relations", () => {
  const adapter = JSON.parse(invoke(baseline.observations.find(x => x.name === "adapter-default")).stdout);
  for (const [path, wrong] of [[["sourceSha256"], `sha256:${"0".repeat(64)}`], [["summary", "lineCount"], adapter.summary.lineCount + 1]]) {
    const changed = replace(adapter, path, wrong);
    assert.equal(validators.get("json-report-cli-adapter-source")(changed), true);
    assert.throws(() => bundleSemantics(changed), assert.AssertionError);
  }
  for (const hashValue of ["0".repeat(64), `sha256:${"A".repeat(64)}`, `sha256:${"0".repeat(63)}`, `sha256:${"0".repeat(65)}`, `sha256:${"0".repeat(64)}\n`]) {
    assert.equal(validators.get("json-report-cli-adapter-source")(replace(adapter, ["sourceSha256"], hashValue)), false, "adapter/hash-domain");
  }
  assert.equal(validators.get("json-report-cli-adapter-source")(replace(adapter, ["summary", "lineCount"], 0)), false, "adapter/lineCount/zero");
  const row = baseline.observations.find(x => x.name === "preset-python_service");
  const preset = JSON.parse(invoke(row).stdout), wrong = replace(preset, ["diagnostics", 1, "value", "suggestedCommands", 0], "different executable");
  assert.equal(validators.get("stack-preset")(wrong), true);
  assert.throws(() => presetSemantics(wrong, row), assert.AssertionError);
});

test("the PILOT-D10 usage delta is exact and limited to its rows", () => {
  const delta = declaredStreamDeltas.find(item => item.id === "PILOT-D10");
  assert.equal(declaredStreamDeltas.length, 18);
  const rows = baseline.observations.filter(row => delta.rows.includes(row.name));
  assert.deepEqual(rows.map(row => row.name), [...delta.rows]);
  const current = invoke(rows[0]).stdout;
  assert.ok(conservesPredecessor(rows[0], current), "current stdout must carry exactly the declared delta");
  const once = current.replace(delta.current, delta.predecessor);
  const otherByte = current.replace("Usage:", "Usage: ");
  for (const [name, mutated] of [["delta once", once], ["other byte", otherByte]]) {
    assert.notEqual(mutated, current, name);
    assert.equal(conservesPredecessor(rows[0], mutated), false, name);
  }
  const unlisted = baseline.observations.find(row => row.name === "stack-preset--help");
  const unlistedCurrent = invoke(unlisted).stdout;
  assert.ok(conservesPredecessor(unlisted, unlistedCurrent), "rows outside the delta carry no usage delta");
  assert.equal(conservesPredecessor(unlisted, unlistedCurrent + delta.current), false, "delta applied to an unlisted row");
});

test("the ADAPTER-STDIN-FILE deltas are exact and limited to the adapter bundle rows", () => {
  const deltas = declaredStreamDeltas.filter(item => item.id.startsWith("ADAPTER-STDIN-FILE-"));
  assert.equal(deltas.length, 16);
  const rows = baseline.observations.filter(row => adapterBundleRows.includes(row.name));
  assert.deepEqual(rows.map(row => row.name), [...adapterBundleRows]);
  for (const row of rows) {
    const current = invoke(row).stdout, source = JSON.parse(current).source;
    assert.ok(conservesPredecessor(row, current), `${row.name}/declared adapter deltas`);
    assert.equal(source.includes(adapterTransportCurrent), true, `${row.name}/file transport`);
    assert.equal(source.includes("input: options.inputMode"), false, `${row.name}/no spawnSync input option`);
    const applied = deltas.filter(item => item.rows.includes(row.name));
    assert.equal(applied.length, 15, row.name);
    for (const delta of applied) {
      const reverted = current.replace(delta.current, delta.predecessor);
      assert.notEqual(reverted, current, `${row.name}/${delta.id}`);
      assert.equal(conservesPredecessor(row, reverted), false, `${row.name}/${delta.id}/reverted`);
    }
    const otherByte = current.replace("Proofkit binaryPath is required", "Proofkit binaryPath is  required");
    assert.notEqual(otherByte, current);
    assert.equal(conservesPredecessor(row, otherByte), false, `${row.name}/other byte`);
  }
  for (const name of ["json-report-cli-adapter-source--help", "adapter-missing", "preset-python_service"]) {
    const row = baseline.observations.find(item => item.name === name), current = invoke(row).stdout;
    assert.ok(conservesPredecessor(row, current), `${name}/no adapter delta`);
    for (const delta of deltas) assert.equal(conservesPredecessor(row, current + delta.current), false, `${name}/${delta.id} applied to an unlisted row`);
  }
});

test("the HELP-CONTRACT-SCHEMAS help delta is exact and limited to help rows", () => {
  const delta = declaredStreamDeltas.find(item => item.id === "HELP-CONTRACT-SCHEMAS");
  const rows = baseline.observations.filter(row => delta.rows.includes(row.name));
  assert.deepEqual(rows.map(row => row.name), [...helpRows]);
  for (const row of rows) {
    const current = invoke(row).stdout;
    assert.equal(count(current, delta.current), 1, row.name); assert.equal(count(current, delta.predecessor), 0, row.name);
    assert.ok(conservesPredecessor(row, current), `${row.name}/declared help delta`);
    const reverted = current.replace(delta.current, delta.predecessor), otherByte = current.replace("Public contract:", "Public contract: ");
    for (const [name, mutated] of [["reverted", reverted], ["other byte", otherByte]]) {
      assert.notEqual(mutated, current, name);
      assert.equal(conservesPredecessor(row, mutated), false, `${row.name}/${name}`);
    }
  }
  const report = baseline.observations.find(row => !delta.rows.includes(row.name) && row.exitCode === 0);
  const reportCurrent = invoke(report).stdout;
  assert.equal(count(reportCurrent, delta.current), 0);
  assert.ok(conservesPredecessor(report, reportCurrent), "non-help rows stay byte-exact");
});
