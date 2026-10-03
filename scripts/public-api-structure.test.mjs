import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_PUBLIC_API_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const corpus = JSON.parse(readFileSync(new URL("internal/app/testdata/public-api-native-observations.json", root), "utf8"));
assert.equal(corpus.sourceCommit, "7567e6e7cfb60966f39577d50ea1fc87ee6479de");
assert.equal(corpus.observations.length, 15);
const command = "typescript-public-api-surfaces";
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const validate = Object.fromEntries(["input", "output"].map(direction => {
  const id = `proofkit.${command}.${direction}.v1.json-schema`;
  const definition = contract.contractDefinitions.find(row => row.definitionId === id);
  assert.ok(definition, id);
  return [direction, ajv.compile({oneOf: definition.fieldTree.variants.map(row => row.schema)})];
}));
const seed = () => structuredClone(corpus.observations[0].input);
const at = (object, path) => path.reduce((value, key) => value[key], object);
const badType = value => typeof value === "string" ? false : Array.isArray(value) ? {} : "wrong";
let directory, binary, fixtureRoot;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-publicapi-structure-"));
  binary = join(directory, "proofkit");
  fixtureRoot = join(directory, "fixture");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120_000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

function native(input, {files = corpus.observations[0].files, carrier = "stdin"} = {}) {
  rmSync(fixtureRoot, {recursive: true, force: true});
  for (const [name, content] of Object.entries(files)) {
    const target = join(fixtureRoot, name);
    mkdirSync(dirname(target), {recursive: true});
    writeFileSync(target, content);
  }
  let argv = [command, "--repo-root", fixtureRoot, "--input", "-"];
  let bytes = typeof input === "string" ? input : JSON.stringify(input);
  if (carrier === "pointer") {
    writeFileSync(join(directory, "input.json"), JSON.stringify({payload: input}));
    argv = [command, "--repo-root", fixtureRoot, "--input", join(directory, "input.json"), "--input-pointer", "/payload"];
    bytes = "";
  }
  if (carrier === "compact") argv = ["--json-layout", "compact", ...argv];
  const result = spawnSync(binary, argv, {input: bytes, encoding: "utf8", timeout: 10_000, maxBuffer: 4 << 20});
  assert.equal(result.error, undefined, "native transport error");
  assert.equal(result.signal, null, "native transport signal");
  assert.ok(result.status === 0 || result.status === 1);
  if (result.stdout) {
    assert.equal(result.stderr, "");
    result.output = JSON.parse(result.stdout);
    assert.equal(validate.output(result.output), true, ajv.errorsText(validate.output.errors));
    assert.equal(result.status, result.output.failures.length === 0 ? 0 : 1);
  } else {
    assert.equal(result.status, 1);
    assert.notEqual(result.stderr, "");
  }
  return result;
}

function rejected(input, label, structural = true) {
  assert.equal(validate.input(input), !structural, `${label}/schema`);
  assert.equal(native(input).stdout, "", `${label}/native admission`);
}

test("public API preserves all exact predecessor process observations", () => {
  for (const row of corpus.observations) {
    const result = native(row.input, {files: row.files});
    assert.equal(result.status, row.exitCode, `${row.name}/exit`);
    assert.equal(result.stdout, row.stdout, `${row.name}/stdout`);
    assert.equal(result.stderr, row.stderr, `${row.name}/stderr`);
  }
});

test("closed manifest records preserve required optional nullable and scalar domains", () => {
  for (const [path, required] of [
    [[], ["entries", "machineContract", "schemaVersion"]],
    [["entries", 0], ["exportConditions", "exportKey", "packageManifestPath", "packageName", "runtimeExports", "typeExports"]],
    [["entries", 0, "exportConditions", 0], ["condition", "path", "sourcePath"]],
  ]) {
    const unknown = seed();
    at(unknown, path).unexpected = true;
    rejected(unknown, `${path}/unknown`);
    for (const key of required) for (const mode of ["missing", "null", "wrong-type"]) {
      const input = seed(), target = at(input, path);
      if (mode === "missing") delete target[key];
      else target[key] = mode === "null" ? null : badType(target[key]);
      rejected(input, `${path}/${key}/${mode}`);
    }
    for (const [key, value] of Object.entries(at(seed(), path))) {
      if (typeof value !== "string") continue;
      const input = seed();
      at(input, path)[key] = "";
      rejected(input, `${path}/${key}/empty`);
    }
  }
  for (const value of [false, {}, "wrong", 1]) {
    const input = seed();
    input.entries[0].deniedExportKeys = value;
    rejected(input, "deniedExportKeys/wrong-type");
  }
  for (const name of ["denied-absent", "denied-null", "denied-empty"]) {
    const row = corpus.observations.find(row => row.name === name);
    assert.equal(validate.input(row.input), true, name);
    assert.deepEqual(native(row.input).output.failures, ["@example/alpha package.json export keys drift: missing=[] extra=[./internal]"]);
  }
  for (const [key, wrong] of [["schemaVersion", 2], ["machineContract", "different"]]) rejected({...seed(), [key]: wrong}, key);
});

test("array items bounds and independent uniqueness clauses are enforced", () => {
  for (const path of [["entries"], ["entries", 0, "exportConditions"], ["entries", 0, "runtimeExports"], ["entries", 0, "typeExports"], ["entries", 0, "deniedExportKeys"]]) {
    for (const wrong of [null, false, 1, []]) {
      const input = seed();
      at(input, path.slice(0, -1))[path.at(-1)] = [wrong];
      rejected(input, `${path}/item`);
    }
  }
  for (const field of ["runtimeExports", "typeExports", "deniedExportKeys", "exportConditions"]) {
    const input = seed(), items = input.entries[0][field];
    items.push(structuredClone(items[0]));
    rejected(input, `${field}/duplicate`);
  }
  const noConditions = seed();
  noConditions.entries[0].exportConditions = [];
  rejected(noConditions, "conditions/nonempty");
  for (const field of ["runtimeExports", "typeExports"]) {
    const input = seed();
    input.entries[0][field] = [];
    assert.equal(validate.input(input), true);
    assert.equal(native(input).status, 1, `${field}/valid-empty-report-mismatch`);
  }
  const empty = {...seed(), entries: []};
  assert.equal(validate.input(empty), true);
  assert.equal(native(empty).output.entryCount, 0);
  const boundary = seed();
  boundary.entries = Array.from({length: 1024}, () => structuredClone(boundary.entries[0]));
  assert.equal(validate.input(boundary), true);
  const report = native(boundary).output;
  assert.equal(report.entryCount, 1024);
  assert.equal(report.failures.length, 1023);
  boundary.entries.push(structuredClone(boundary.entries[0]));
  rejected(boundary, "entries/maximum");
});

test("native-only ordering normalization paths privacy and numeric spelling remain explicit", () => {
  const cases = [
    ["order", input => {input.entries[0].runtimeExports = ["z", "a"];}],
    ["normalized-duplicate", input => {input.entries[0].runtimeExports = ["VALUE", " VALUE "];}],
    ["condition-name", input => {input.entries[0].exportConditions.push({...input.entries[0].exportConditions[0], path: "./other.js"});}],
    ["parent-path", input => {input.entries[0].packageManifestPath = "../package.json";}],
    ["wrong-manifest", input => {input.entries[0].packageManifestPath = "modules/alpha/other.json";}],
    ["tsx", input => {input.entries[0].exportConditions[0].sourcePath = "modules/alpha/lib/api.tsx";}],
    ["trim-empty", input => {input.entries[0].packageName = "  ";}],
  ];
  for (const [label, mutate] of cases) {const input = seed(); mutate(input); rejected(input, label, false);}
  const secret = `Authorization: Bearer ${"x".repeat(24)}`, input = seed();
  input.entries[0].packageName = secret;
  assert.equal(validate.input(input), true);
  const result = native(input);
  assert.equal(result.stdout, "");
  assert.equal((result.stdout + result.stderr).includes(secret), false);
  assert.equal(native(JSON.stringify(seed()).replace('"schemaVersion":1', '"schemaVersion":1.0')).stdout, "");
});

test("output shape rejects missing fields altered literals invalid counts and extra claims", () => {
  const output = native(seed()).output;
  assert.deepEqual(Object.keys(output).sort(), ["entryCount", "failures", "inputAuthority", "nonClaims"]);
  for (const key of ["entryCount", "failures", "inputAuthority", "nonClaims"]) {
    const missing = structuredClone(output); delete missing[key];
    assert.equal(validate.output(missing), false, `${key}/required`);
    assert.equal(validate.output({...output, [key]: null}), false, `${key}/nonnull`);
    assert.equal(validate.output({...output, [key]: badType(output[key])}), false, `${key}/type`);
  }
  assert.equal(validate.output({...output, extra: true}), false);
  assert.equal(validate.output({...output, inputAuthority: "caller_assertion"}), false, "inputAuthority/literal");
  for (const count of [-1, 0.5, 1025]) assert.equal(validate.output({...output, entryCount: count}), false, `entryCount/${count}`);
  for (const item of [null, false, 1, ""]) assert.equal(validate.output({...output, failures: [item]}), false);
  assert.equal(output.nonClaims.length, 5);
  for (let index = 0; index < 5; index += 1) {
    const changed = structuredClone(output); changed.nonClaims[index] += " changed";
    assert.equal(validate.output(changed), false, `nonClaims/${index}`);
  }
  assert.equal(validate.output({...output, nonClaims: output.nonClaims.slice(0, 4)}), false);
  assert.equal(validate.output({...output, nonClaims: [...output.nonClaims, "extra"]}), false);
});

test("public carriers preserve reports and documented direct-generator refusal", () => {
  const expected = native(seed()).output;
  assert.deepEqual(native(seed(), {carrier: "pointer"}).output, expected);
  assert.deepEqual(native(seed(), {carrier: "compact"}).output, expected);
  const grammar = contract.commands.find(row => row.command === command).inputContract.sourceGrammar;
  assert.ok(grammar.rejectedLexicalForms.includes("direct exported generator function declarations (export function* and export async function*)"));
  for (const [source, code] of [["export function run() { return 1; }", 0], ["export async function run() { return 1; }", 0],
    ["export function* run() { yield 1; }", 1], ["export async function* run() { yield 1; }", 1],
    ["export const run = function* () { yield 1; };", 0]]) {
    const input = seed(); input.entries[0].runtimeExports = ["run"]; input.entries[0].typeExports = [];
    const result = native(input, {files: {...corpus.observations[0].files, "modules/alpha/lib/api.mts": source}});
    assert.equal(result.status, code, source);
    if (code === 1) {assert.equal(result.stdout, ""); assert.match(result.stderr, /unsupported public export statement/);}
  }
});
