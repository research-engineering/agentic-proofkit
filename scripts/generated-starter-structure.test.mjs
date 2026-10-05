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
    assert.equal(hash(result.stdout), row.stdoutSHA256, `${row.name}/stdout`);
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
