import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_WORKSPACE_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const corpus = JSON.parse(readFileSync(new URL("internal/app/testdata/workspace-native-observations.json", root), "utf8"));
assert.equal(corpus.sourceCommit, "0b16f188d208198338f8d54fc178218f425006ed");
assert.equal(corpus.observations.length, 64);
const names = ["workspace-manifest-facts", "workspace-changed-package-plan", "workspace-shard-partition"];
const [manifest, changed, shard] = names;
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const families = Object.fromEntries(names.map(command => [command, Object.fromEntries(["input", "output"].map(direction => {
  const id = `proofkit.${command}.${direction}.v1.json-schema`;
  const definition = contract.contractDefinitions.find(row => row.definitionId === id);
  assert.ok(definition, id);
  return [direction, ajv.compile({oneOf: definition.fieldTree.variants.map(row => row.schema)})];
}))]));
const seed = command => structuredClone(corpus.observations.find(row => row.command === command && row.name === "positive").input);
const hash = text => createHash("sha256").update(text).digest("hex");
const at = (value, path) => path.reduce((current, key) => current[key], value);
const wrongType = value => typeof value === "string" ? 0 : typeof value === "number" || typeof value === "boolean" ? "wrong" : Array.isArray(value) ? {} : false;
function objects(value, path = []) {
  if (!value || typeof value !== "object") return [];
  return [...(Array.isArray(value) ? [] : [path]), ...Object.entries(value).flatMap(([key, child]) => objects(child, [...path, key]))];
}
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-workspace-"));
  binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120_000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
function native(command, input, extra = [], carrier = "stdin") {
  let argv = [command, "--input", "-", ...extra], bytes = typeof input === "string" ? input : JSON.stringify(input);
  if (carrier === "pointer") {
    writeFileSync(join(directory, "input.json"), JSON.stringify({payload: input}));
    argv = [command, "--input", join(directory, "input.json"), "--input-pointer", "/payload", ...extra];
    bytes = "";
  }
  if (carrier === "compact") argv = ["--json-layout", "compact", ...argv];
  const result = spawnSync(binary, argv, {input: bytes, encoding: "utf8", timeout: 10_000, maxBuffer: 4 << 20});
  assert.equal(result.error, undefined, `${command}/transport-error`);
  assert.equal(result.signal, null, `${command}/transport-signal`);
  assert.ok(result.status === 0 || result.status === 1, `${command}/exit`);
  result.output = undefined;
  if (result.stdout) {
    assert.equal(result.stderr, "", `${command}/stderr`);
    result.output = JSON.parse(result.stdout);
    assert.equal(families[command].output(result.output), true, `${command}/output: ${ajv.errorsText(families[command].output.errors)}`);
  } else {
    assert.equal(result.status, 1, `${command}/input-error-exit`);
    assert.notEqual(result.stderr, "", `${command}/input-error-stderr`);
  }
  return result;
}
function rejected(command, input, label, schemaRejects = true) {
  assert.equal(families[command].input(input), !schemaRejects, `${label}/schema`);
  assert.equal(native(command, input).stdout, "", `${label}/native`);
}

test("all predecessor observations preserve exact exit stderr and stdout bytes", () => {
  for (const row of corpus.observations) {
    const label = `${row.command}/${row.name}`;
    assert.equal(families[row.command].input(row.input), row.schemaValid, `${label}/input`);
    const result = native(row.command, row.input, row.extra);
    assert.equal(result.status, row.exitCode, `${label}/exit`);
    assert.equal(result.stderr, row.stderr, `${label}/stderr`);
    assert.equal(hash(result.stdout), row.stdoutSHA256, `${label}/stdout`);
  }
});

test("closed input records preserve exact required nullable and type partitions", () => {
  for (const command of names) {
    const input = seed(command);
    const paths = command === manifest ? [[], ["root"], ["packages", 0], ["packages", 1]]
      : objects(input);
    for (const path of paths) {
      const unknown = structuredClone(input);
      at(unknown, path).unexpected = true;
      rejected(command, unknown, `${command}/${path}/unknown`);
      for (const [key, value] of Object.entries(at(input, path))) {
        const optional = command === changed && path.length === 0 && ["includeReverseDependents", "packagesRoot"].includes(key)
          || command === manifest && ["packageDir", "dirName"].includes(key) && (key === "packageDir" || path[0] === "root");
        for (const mode of ["wrong-type", ...(!optional ? ["missing", "null"] : [])]) {
          const bad = structuredClone(input), target = at(bad, path);
          if (mode === "missing") delete target[key];
          else target[key] = mode === "null" ? null : wrongType(value);
          rejected(command, bad, `${command}/${path}/${key}/${mode}`);
        }
      }
    }
  }
});

test("dynamic manifest maps remain typed without claiming input-dependent key admission", () => {
  for (const path of [["root", "manifest"], ["packages", 0, "manifest"]]) {
    for (const [name, mutate] of [
      ["missing-name", object => {delete object.name;}],
      ["null-name", object => {object.name = null;}],
      ["empty-name", object => {object.name = "";}],
      ["wrong-script-map", object => {object.scripts = [];}],
      ["wrong-script-value", object => {object.scripts = {test: false};}],
      ["empty-script-key", object => {object.scripts = {"": "node --test"};}],
      ["empty-script-value", object => {object.scripts = {test: ""};}],
      ["wrong-dependency-map", object => {object.dependencies = [];}],
      ["wrong-dependency-value", object => {object.dependencies = {beta: false};}],
    ]) {
      const input = seed(manifest);
      mutate(at(input, path));
      rejected(manifest, input, `${path}/${name}`);
    }
    const unknown = seed(manifest);
    at(unknown, path).unselected = {x: "1"};
    rejected(manifest, unknown, `${path}/native-key-relation`, false);
  }
});

test("array elements and optional defaults are independently constrained", () => {
  for (const command of names) {
    const input = seed(command);
    for (const path of objects(input)) for (const [key, value] of Object.entries(at(input, path))) {
      if (!Array.isArray(value)) continue;
      for (const badItem of [null, false, 1]) {
        const copy = structuredClone(input);
        at(copy, path)[key] = [badItem];
        rejected(command, copy, `${command}/${path}/${key}/bad-element`);
      }
    }
  }
  const base = seed(changed), expected = native(changed, base).stdout;
  for (const [key, value] of [["includeReverseDependents", true], ["packagesRoot", "packages"]]) {
    assert.equal(native(changed, {...base, [key]: value}).stdout, expected, `${key}/default`);
    for (const invalid of [null, [], {}, 1]) rejected(changed, {...base, [key]: invalid}, `${key}/invalid`);
  }
  assert.deepEqual(native(changed, {...base, includeReverseDependents: false}).output.rootPackageNames, ["alpha"]);
  for (const path of [["root"], ["packages", 0]]) {
    const input = seed(manifest), original = native(manifest, input).stdout;
    for (const mode of ["missing", "null"]) {
      const copy = structuredClone(input);
      if (mode === "missing") delete at(copy, path).packageDir;
      else at(copy, path).packageDir = null;
      assert.equal(families[manifest].input(copy), true);
      assert.equal(native(manifest, copy).stdout, original, `${path}/packageDir/${mode}`);
    }
  }
  for (const key of ["scripts", "dependencies", "devDependencies"]) {
    const input = seed(manifest);
    delete input.root.manifest[key];
    const absent = native(manifest, input).stdout;
    input.root.manifest[key] = null;
    assert.equal(families[manifest].input(input), true);
    assert.equal(native(manifest, input).stdout, absent, `${key}/null-is-absent`);
  }
});

test("empty strings are rejected where the native contract requires nonempty text", () => {
  for (const [command, paths] of [
    [manifest, [["root", "manifest", "name"], ["root", "manifestPath"], ["nonClaims", 0]]],
    [changed, [["changedPaths", 0], ["packages", 0, "name"], ["packages", 1, "workspaceDependencies", 0], ["escalationRules", 0, "pattern"]]],
    [shard, [["roots", 0, "name"], ["packages", 1, "workspaceDependencies", 0]]],
  ]) for (const path of paths) {
    const input = seed(command);
    at(input, path.slice(0, -1))[path.at(-1)] = "";
    rejected(command, input, `${command}/${path}/empty`);
  }
  const output = native(manifest, seed(manifest)).output;
  const altered = structuredClone(output);
  altered.packageUniverse.workspaceDependencyEdges[0].fromKind = "ambient";
  assert.equal(families[manifest].output(altered), false, "unknown edge kind");
  for (const label of ["0-of-2", "1-of-0", "01-of-2", "1-2"]) {
    const partition = native(shard, seed(shard)).output;
    partition.shards[0].shardLabel = label;
    assert.equal(families[shard].output(partition), false, label);
  }
});

test("output records require all fields and reject extra fields and wrong element types", () => {
  for (const command of names) {
    const output = native(command, seed(command)).output;
    for (const path of objects(output)) {
      const bad = structuredClone(output);
      at(bad, path).unexpected = true;
      assert.equal(families[command].output(bad), false, `${command}/${path}/unknown`);
      for (const [key, value] of Object.entries(at(output, path))) {
        for (const mode of ["missing", "null", "wrong-type"]) {
          const copy = structuredClone(output), target = at(copy, path);
          if (mode === "missing") delete target[key];
          else target[key] = mode === "null" ? null : wrongType(value);
          assert.equal(families[command].output(copy), false, `${command}/${path}/${key}/${mode}`);
        }
        if (Array.isArray(value)) {
          const copy = structuredClone(output);
          at(copy, path)[key] = [false];
          assert.equal(families[command].output(copy), false, `${command}/${path}/${key}/element`);
        }
      }
    }
  }
});

test("versions fixed report vocabulary and finite identifier neighbors are enforced", () => {
  for (const command of names) {
    const input = seed(command), output = native(command, input).output;
    for (const version of [0, 2, 1.5]) {
      rejected(command, {...input, schemaVersion: version}, `${command}/version-${version}`);
      assert.equal(families[command].output({...output, schemaVersion: version}), false);
    }
  }
  const output = native(manifest, seed(manifest)).output;
  for (const key of ["state", "reportKind"]) {
    assert.equal(families[manifest].output({...output, [key]: "wrong"}), false, key);
  }
  for (const [command, path, key] of [[manifest, [], "projectionId"], [manifest, ["packages", 0], "dirName"], [changed, ["packages", 0], "dirName"], [changed, ["escalationRules", 0], "reason"]]) {
    for (const length of [256, 257]) {
      const input = seed(command);
      at(input, path)[key] = "x".repeat(length);
      assert.equal(families[command].input(input), length === 256, `${command}/${key}/schema-${length}`);
      assert.equal(native(command, input).stdout !== "", length === 256, `${command}/${key}/native-${length}`);
    }
    for (const value of ["1bad", " bad ", "bad/segment", "", "\u00e9"]) {
      const input = seed(command); at(input, path)[key] = value;
      rejected(command, input, `${command}/${key}/grammar`);
    }
  }
});

test("numeric minima and cardinalities distinguish valid zero values from invalid neighbors", () => {
  const output = native(manifest, seed(manifest)).output;
  for (const key of Object.keys(output.summary)) {
    const minimum = key === "dependencyFieldCount" ? 1 : 0;
    for (const value of [minimum - 1, minimum, minimum + 1, minimum + 0.5]) {
      const copy = structuredClone(output); copy.summary[key] = value;
      assert.equal(families[manifest].output(copy), Number.isInteger(value) && value >= minimum, `${key}/${value}`);
    }
  }
  for (const path of [[], ["shards", 0], ["packageShards", "include", 0]]) {
    const output = native(shard, seed(shard)).output;
    for (const [key, number] of Object.entries(at(output, path)).filter(([, v]) => typeof v === "number")) {
      if (key === "schemaVersion") continue;
      const minimum = ["shardTotal", "shard_total"].includes(key) ? 1 : 0;
      for (const value of [minimum - 1, minimum, minimum + 1, minimum + 0.5]) {
        const copy = structuredClone(output); at(copy, path)[key] = value;
        assert.equal(families[shard].output(copy), Number.isInteger(value) && value >= minimum, `${path}/${key}/${number}/${value}`);
      }
    }
  }
  for (const field of ["dependencyFields", "nonClaims"]) rejected(manifest, {...seed(manifest), [field]: []}, field);
  const partition = native(shard, seed(shard)).output;
  assert.equal(families[shard].output({...partition, shards: []}), false);
  assert.equal(families[shard].output({...partition, packageShards: {include: []}}), false);
  for (const claims of [output.nonClaims.slice(0, 3), [...output.nonClaims].reverse()]) {
    assert.equal(families[manifest].output({...output, nonClaims: claims}), false, "builtin-denials");
  }
});

test("real manifest to changed-package to shard chain preserves independent expectations", () => {
  const facts = native(manifest, seed(manifest)).output;
  assert.deepEqual(facts.summary, {dependencyFieldCount: 2, packageCount: 2, packageDependencyRefCount: 3, packageScriptCount: 1, rootDependencyRefCount: 1, rootScriptCount: 1, workspaceDependencyEdgeCount: 2});
  assert.deepEqual(facts.changedPackagePlanPackages, [{dirName: "alpha", name: "alpha", workspaceDependencies: ["beta"]}, {dirName: "beta", name: "beta", workspaceDependencies: []}]);
  const changedInput = {...seed(changed), packages: facts.changedPackagePlanPackages, changedPaths: ["packages/beta/source.ts"]};
  assert.equal(families[changed].input(changedInput), true);
  const plan = native(changed, changedInput).output;
  assert.deepEqual(plan.directRootPackageNames, ["beta"]);
  assert.deepEqual(plan.rootPackageNames, ["alpha", "beta"]);
  const shardInput = {schemaVersion: 1, packages: facts.shardPartitionPackages, roots: plan.roots.map(({name, workspaceDependencies}) => ({name, workspaceDependencies})), shardTotal: 2};
  assert.equal(families[shard].input(shardInput), true);
  const partition = native(shard, shardInput).output;
  assert.deepEqual(partition.failures, []);
  assert.deepEqual(partition.shards, [
    {dependencyClosurePackageNames: ["beta", "alpha"], executionPackageNames: ["alpha"], rootPackageNames: ["alpha"], shardIndex: 0, shardLabel: "1-of-2", shardTotal: 2},
    {dependencyClosurePackageNames: ["beta"], executionPackageNames: ["beta"], rootPackageNames: ["beta"], shardIndex: 1, shardLabel: "2-of-2", shardTotal: 2},
  ]);
  assert.deepEqual(partition.packageShards, {include: [{shard_index: 0, shard_label: "1-of-2", shard_total: 2}, {shard_index: 1, shard_label: "2-of-2", shard_total: 2}]});
});

test("canonical JSON spelling privacy help and input transports remain public CLI boundaries", () => {
  for (const command of names) {
    const input = seed(command), serialized = JSON.stringify(input), normal = native(command, input);
    for (const token of ["1.0", "1e0", "-0"]) {
      assert.equal(native(command, serialized.replace('"schemaVersion":1', `"schemaVersion":${token}`)).stdout, "");
    }
    assert.equal(native(command, serialized.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')).stdout, "");
    assert.equal(native(command, input, [], "pointer").stdout, normal.stdout);
    assert.deepEqual(native(command, input, [], "compact").output, normal.output);
    const help = spawnSync(binary, [command, "--help"], {encoding: "utf8", timeout: 5000});
    assert.equal(help.error, undefined); assert.equal(help.signal, null); assert.equal(help.status, 0);
    assert.ok(help.stdout.includes("schemaVersion"), `${command}/root-help`);
    const secret = "api" + "_key=" + "synthetic-workspace-canary";
    if (command === manifest) input.root.manifest.name = secret;
    else input.packages[0].name = secret;
    const result = native(command, input);
    assert.equal(result.stdout, "");
    assert.equal((result.stdout + result.stderr).includes(secret), false);
  }
});
