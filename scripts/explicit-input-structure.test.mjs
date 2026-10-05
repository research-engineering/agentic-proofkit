import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_EXPLICIT_INPUT_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const baseline = JSON.parse(readFileSync(new URL("internal/app/testdata/explicit-input-native-observations.json", root), "utf8"));
assert.equal(baseline.head, "56192c94afaa1538cf6408f9624935df6b536cbd");
assert.equal(baseline.observations.length, 32);
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const families = new Map(["changed-path-set", "secret-scan"].map(command => [command, Object.fromEntries(["input", "output"].map(direction => {
  const owner = contract.contractDefinitions.find(x => x.definitionId === `proofkit.${command}.${direction}.v1.json-schema`);
  assert.ok(owner, `${command}/${direction}`);
  return [direction, owner.fieldTree.variants.map(variant => ajv.compile(variant.schema))];
}))]));
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-explicit-input-"));
  binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });
const hash = value => createHash("sha256").update(value).digest("hex");
const seed = (command, name = "plain") => structuredClone(baseline.observations.find(x => x.command === command && x.name === name).input);
const at = (value, path) => path.reduce((x, key) => x[key], value);
function containers(value, path = []) {
  if (!value || typeof value !== "object") return [];
  return [path, ...Object.entries(value).flatMap(([key, child]) => containers(child, [...path, key]))];
}
function invoke(command, input, args = []) {
  const r = spawnSync(binary, [command, "--input", "-", ...args], {input: typeof input === "string" ? input : JSON.stringify(input), encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
  assert.equal(r.error, undefined, command); assert.equal(r.signal, null, command);
  return r;
}
function outputValidator(command, value, args = []) {
  if (command !== "changed-path-set" || !args.includes("--agent-envelope")) return families.get(command).output[0];
  return families.get(command).output[value.envelopeId === "proofkit.agent-envelope.invalid-input" ? 2 : 1];
}
function reject(command, input, label, structural = true) {
  if (structural) assert.equal(families.get(command).input[0](input), false, label);
  const r = invoke(command, input);
  assert.equal(r.status, 1, label); assert.equal(r.stdout, "", label); assert.notEqual(r.stderr, "", label);
}

test("exact predecessor observations survive structural publication", () => {
  for (const row of baseline.observations) {
    const r = invoke(row.command, row.input, row.args);
    assert.equal(r.status, row.exitCode, row.name);
    assert.equal(hash(r.stdout), row.stdoutSha256, `${row.name}/stdout`);
    assert.equal(hash(r.stderr), row.stderrSha256, `${row.name}/stderr`);
    if (r.stdout) {
      const value = JSON.parse(r.stdout), validate = outputValidator(row.command, value, row.args);
      assert.equal(validate(value), true, `${row.name}: ${ajv.errorsText(validate.errors)}`);
    }
  }
});

test("input objects are closed with independent required and nullable boundaries", () => {
  for (const command of families.keys()) {
    const input = seed(command, command === "secret-scan" ? "suppressed-finding" : "plain");
    const optional = new Set(command === "secret-scan" ? ["suppressions"] : []);
    for (const path of containers(input).filter(p => !Array.isArray(at(input, p)))) {
      const unknown = structuredClone(input); at(unknown, path).foreignField = true;
      reject(command, unknown, `${command}/${path}/unknown`);
      for (const [key, value] of Object.entries(at(input, path))) {
        for (const mode of ["missing", "null", "type"]) {
          if (path.length === 0 && optional.has(key) && mode !== "type") continue;
          const bad = structuredClone(input), record = at(bad, path);
          if (mode === "missing") delete record[key];
          if (mode === "null") record[key] = null;
          if (mode === "type") record[key] = typeof value === "string" ? 0 : "wrong-type";
          reject(command, bad, `${command}/${path}/${key}/${mode}`);
        }
      }
    }
  }
});

test("input collection elements retain their authored scalar and object domains", () => {
  for (const command of families.keys()) {
    const input = seed(command, command === "secret-scan" ? "suppressed-finding" : "plain");
    for (const path of containers(input).filter(p => Array.isArray(at(input, p)))) {
      const records = ["sources", "files", "suppressions"].includes(path.at(-1));
      for (const value of [null, 0, true, [], ...(records ? [""] : [{}])]) {
        const bad = structuredClone(input); at(bad, path).push(value);
        reject(command, bad, `${command}/${path}/item`);
      }
    }
  }
});

test("empty and optional forms remain admitted at their actual owner phase", () => {
  for (const command of families.keys()) {
    for (const name of command === "changed-path-set" ? ["empty-sources", "empty-paths", "duplicate-paths", "duplicate-text", "invalid-path", "empty-path"] : ["empty-files", "missing-file", "empty-content", "null-suppressions", "empty-suppressions", "unused-suppression"]) {
      const input = seed(command, name), validate = families.get(command).input[0];
      assert.equal(validate(input), true, `${command}/${name}: ${ajv.errorsText(validate.errors)}`);
      const r = invoke(command, input); assert.equal(r.stderr, "", name); assert.notEqual(r.stdout, "", name);
    }
  }
  const unsorted = seed("secret-scan"); unsorted.nonClaims = ["Zulu context.", "Alpha context."];
  assert.equal(families.get("secret-scan").input[0](unsorted), true);
  const r = invoke("secret-scan", unsorted); assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout).nonClaims.filter(x => x.endsWith(" context.")), ["Alpha context.", "Zulu context."]);
});

test("state-content dependency, IDs and native integer boundaries have sensitive witnesses", () => {
  for (const name of ["missing-has-content", "present-without-content", "null-content", "zero-line", "fractional-line"]) reject("secret-scan", seed("secret-scan", name), name);
  for (const command of families.keys()) {
    for (const id of ["", "a".repeat(257), "space value"]) {
      const input = seed(command); input.reportId = id; reject(command, input, `${command}/id`);
    }
    const maximal = seed(command); maximal.reportId = "a".repeat(256);
    assert.equal(families.get(command).input[0](maximal), true);
    const result = invoke(command, maximal); assert.equal(result.status, 0);
    assert.equal(families.get(command).output[0](JSON.parse(result.stdout)), true, `${command}/maximum output ID`);
  }
  for (const [path, field] of [[[], "schemaVersion"], [["files", "0"], "state"], [["suppressions", "0"], "findingClass"]]) {
    const bad = seed("secret-scan", "suppressed-finding"); at(bad, path)[field] = field === "schemaVersion" ? 2 : "foreign";
    reject("secret-scan", bad, `${path}/${field}/domain`);
  }
  const raw = JSON.stringify(seed("secret-scan", "unused-suppression")).replace('"line":2', '"line":2.0');
  reject("secret-scan", raw, "native integer lexeme", false);
});

test("raw duplicate keys and native-only predicates do not become schema proof", () => {
  for (const command of families.keys()) {
    const raw = JSON.stringify(seed(command)).replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1');
    reject(command, raw, `${command}/raw duplicate`, false);
  }
  for (const name of ["malformed-content", "unsorted-file", "duplicate-file", "duplicate-suppression"]) reject("secret-scan", seed("secret-scan", name), name, false);
  reject("changed-path-set", seed("changed-path-set", "duplicate-source-id"), "source identity", false);
});

test("every populated output record rejects missing, foreign, null and wrong-type members", () => {
  for (const row of baseline.observations.filter(x => x.expected !== "rejected")) {
    const value = JSON.parse(invoke(row.command, row.input, row.args).stdout), validate = outputValidator(row.command, value, row.args);
    for (const path of containers(value).filter(p => !Array.isArray(at(value, p)))) {
      const unknown = structuredClone(value); at(unknown, path).foreignField = true;
      assert.equal(validate(unknown), false, `${row.name}/${path}/unknown`);
      for (const [key, original] of Object.entries(at(value, path))) {
        for (const mode of ["missing", "null", "type"]) {
          if (mode === "null" && original === null) continue;
          if (mode === "missing" && path.join(".") === "bounds" && key === "truncated") continue;
          const bad = structuredClone(value), record = at(bad, path);
          if (mode === "missing") delete record[key];
          if (mode === "null") record[key] = null;
          if (mode === "type") record[key] = typeof original === "string" ? 0 : "wrong-type";
          assert.equal(validate(bad), false, `${row.name}/${path}/${key}/${mode}`);
        }
      }
    }
    for (const path of containers(value).filter(p => Array.isArray(at(value, p)))) {
      for (const item of [null, 0, true]) {
        const bad = structuredClone(value); at(bad, path).push(item);
        assert.equal(validate(bad), false, `${row.name}/${path}/item`);
      }
    }
  }
});

test("report fixed identities, classifications and nonnegative counts are not inert", () => {
  for (const row of baseline.observations.filter(x => !x.args.length && x.expected !== "rejected")) {
    const value = JSON.parse(invoke(row.command, row.input).stdout), validate = families.get(row.command).output[0];
    for (const path of containers(value).filter(p => !Array.isArray(at(value, p)))) {
      for (const [key, original] of Object.entries(at(value, path))) {
        if (["reportId", "sourceId", "suppressionId"].includes(key)) {
          for (const id of ["", "a".repeat(257), "white space"]) {
            const bad = structuredClone(value); at(bad, path)[key] = id;
            assert.equal(validate(bad), false, `${row.name}/${path}/${key}/limit`);
          }
        }
        const mutations = typeof original === "number" ? [-1, 0.5] : ["state", "status", "reportKind", "ruleId", "message", "findingClass"].includes(key) ? ["foreign-value"] : [];
        for (const mutation of mutations) {
          const bad = structuredClone(value); at(bad, path)[key] = mutation;
          assert.equal(validate(bad), false, `${row.name}/${path}/${key}/domain`);
        }
      }
    }
  }
});

test("invalid-input repair envelope and input-pointer route use the correct producer", () => {
  const bad = seed("changed-path-set"); bad.nonClaims = null;
  const r = invoke("changed-path-set", bad, ["--agent-envelope"]);
  assert.equal(r.status, 1); assert.equal(r.stderr, "");
  const envelope = JSON.parse(r.stdout);
  assert.equal(envelope.envelopeId, "proofkit.agent-envelope.invalid-input");
  assert.equal(families.get("changed-path-set").output[2](envelope), true);
  assert.equal(families.get("changed-path-set").output[1](envelope), false);
  for (const command of families.keys()) {
    const value = seed(command), direct = invoke(command, value);
    const wrapped = invoke(command, {selected: value}, ["--input-pointer", "/selected"]);
    assert.deepEqual([wrapped.status, wrapped.stdout, wrapped.stderr], [direct.status, direct.stdout, direct.stderr]);
  }
});

test("builtin nonclaims, envelope constants and native numeric spelling remain explicit", () => {
  for (const command of families.keys()) {
    const value = JSON.parse(invoke(command, seed(command)).stdout), validate = families.get(command).output[0];
    for (let i = 0; i < value.nonClaims.length; i++) {
      const missingBuiltin = structuredClone(value); missingBuiltin.nonClaims[i] = "Different caller statement.";
      assert.equal(validate(missingBuiltin), false, `${command}/builtin/${i}`);
    }
    const wrongVersion = seed(command); wrongVersion.schemaVersion = 2;
    reject(command, wrongVersion, `${command}/version`);
    const sensitive = seed(command); sensitive.nonClaims = [["api_", "key=", "synthetic-fixture-value"].join("")];
    const rejected = invoke(command, sensitive);
    assert.equal(rejected.status, 1); assert.equal(rejected.stdout, "");
    assert.equal(rejected.stderr.includes("synthetic-fixture-value"), false);
  }
  const envelope = JSON.parse(invoke("changed-path-set", seed("changed-path-set"), ["--agent-envelope"]).stdout);
  const validate = families.get("changed-path-set").output[1];
  for (const [path, key, value] of [[["bounds"], "maxTokenBudget", 2201], [["costContract"], "maxTokenBudget", 2201], [["costContract"], "omittedEdgesCounted", false], [["bounds"], "truncated", false]]) {
    const bad = structuredClone(envelope); at(bad, path)[key] = value;
    assert.equal(validate(bad), false, `${path}/${key}/fixed`);
  }
  const raw = JSON.stringify(seed("secret-scan", "unused-suppression"));
  const maximum = invoke("secret-scan", raw.replace('"line":2', '"line":9223372036854775807'));
  assert.equal(maximum.status, 1); assert.equal(maximum.stderr, "");
  assert.ok(maximum.stdout.includes("9223372036854775807"));
  reject("secret-scan", raw.replace('"line":2', '"line":9223372036854775808'), "native int64 overflow", false);
});
