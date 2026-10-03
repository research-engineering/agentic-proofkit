import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {bindingInput, witnessInput, projectedWitnessInput, schedulerInput, resolverInput} from "./proof-routing-fixtures.mjs";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_ROUTING_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const ajv = new Ajv2020({strict: false, validateFormats: false});
const names = ["requirement-bindings", "evidence-graph", "proof-slice", "requirement-proof-resolver", "witness-plan", "witness-scheduler-plan"];
const validators = new Map();
for (const command of names) for (const direction of ["input", "output"]) {
  const reference = contract.commands.find(row => row.command === command)[`${direction}Contract`].rootDefinitionRef;
  const definition = contract.contractDefinitions.find(row => row.definitionId === reference);
  assert.equal(definition.fieldTree.kind, "structural_json_schema", `${command}/${direction}`);
  validators.set(`${command}/${direction}`, ajv.compile({oneOf: definition.fieldTree.variants.map(row => row.schema)}));
}
let directory, binary, executionSubjects;
const fileDigest = path => createHash("sha256").update(readFileSync(path)).digest("hex");
function binaryIdentity(path) {
  const metadata = execFileSync("go", ["version", "-m", path], {encoding: "utf8", timeout: 10000, maxBuffer: 1 << 20});
  const revision = /^\s*build\tvcs\.revision=([0-9a-f]{40})$/m.exec(metadata)?.[1];
  const modified = /^\s*build\tvcs\.modified=(true|false)$/m.exec(metadata)?.[1];
  assert.ok(revision && modified);
  return {sha256: fileDigest(path), revision, modified: modified === "true"};
}
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-routing-"));
  binary = join(directory, "proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"],
    {cwd: root, timeout: 120000, maxBuffer: 2 << 20, env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"}});
  if (process.env.PROOFKIT_ROUTING_BASELINE) {
    executionSubjects = {kind: "proofkit.routing-comparison-subjects", baseline: binaryIdentity(process.env.PROOFKIT_ROUTING_BASELINE),
      candidate: binaryIdentity(binary), testSourceSHA256: fileDigest(new URL(import.meta.url))};
    console.log(JSON.stringify(executionSubjects));
  }
});
after(() => {
  try {
    if (executionSubjects) {
      assert.equal(fileDigest(binary), executionSubjects.candidate.sha256);
      assert.equal(fileDigest(process.env.PROOFKIT_ROUTING_BASELINE), executionSubjects.baseline.sha256);
    }
  } finally { if (directory) rmSync(directory, {recursive: true, force: true}); }
});
function validates(command, direction, input, expected = true, label = "") {
  const check = validators.get(`${command}/${direction}`);
  assert.equal(check(input), expected, `${command}/${direction}/${label}: ${ajv.errorsText(check.errors)}`);
}
function native(command, input, {exit = 0, report = true, carrier = "stdin", extra = []} = {}) {
  if (command === "requirement-proof-resolver" && extra.length === 0) extra = ["--local-environment-class", "local-go"];
  let args = [command, "--input", "-", ...extra], bytes = typeof input === "string" ? input : JSON.stringify(input);
  if (carrier === "pointer") {
    const path = join(directory, "input.json");
    writeFileSync(path, JSON.stringify({payload: input}));
    args = [command, "--input", path, "--input-pointer", "/payload", ...extra];
    bytes = "";
  } else if (carrier === "compact") args.unshift("--json-layout", "compact");
  const invoke = executable => spawnSync(executable, args, {input: bytes, encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
  const result = invoke(binary);
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, exit, `${command}: ${result.stderr}`);
  if (process.env.PROOFKIT_ROUTING_BASELINE) {
    const prior = invoke(process.env.PROOFKIT_ROUTING_BASELINE);
    assert.equal(prior.error, undefined);
    assert.deepEqual([result.status, result.signal, result.stdout, result.stderr], [prior.status, prior.signal, prior.stdout, prior.stderr], "native predecessor observation changed");
  }
  if (!report) {
    assert.equal(result.stdout, "");
    assert.notEqual(result.stderr, "");
    return;
  }
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  validates(command, "output", output);
  return output;
}
const at = (value, path) => path.reduce((node, key) => node[key], value);
const wrongType = value => value === null || typeof value === "string" ? false : typeof value === "boolean" || typeof value === "number" ? "bad" : Array.isArray(value) ? {} : [];
function objects(value, path = []) {
  if (!value || typeof value !== "object") return [];
  return [...(Array.isArray(value) ? [] : [path]), ...Object.entries(value).flatMap(([key, child]) => objects(child, [...path, key]))];
}
function seed(command) {
  if (command === "witness-plan") return witnessInput();
  if (command === "witness-scheduler-plan") return schedulerInput();
  if (command === "requirement-proof-resolver") return resolverInput();
  return bindingInput();
}

function* outputCases() {
  for (const command of names) yield [command, native(command, seed(command))];
  const binding = bindingInput(); binding.bindings[0].requirementId = "REQ-MISSING";
  yield ["requirement-bindings", native("requirement-bindings", binding, {exit: 1})];
  const scheduler = schedulerInput(); scheduler.policies[0].commandId = "test.other";
  yield ["witness-scheduler-plan", native("witness-scheduler-plan", scheduler, {exit: 1})];
  const witness = witnessInput();
  witness.commands[0].environment = {inherit: "allowlist", allowlist: ["HOME"], classes: ["local-go"]};
  witness.commands[0].exitCodePolicy = {kind: "listed", successCodes: [0, 255]};
  yield ["witness-plan", native("witness-plan", witness)];
}

function* witnessInputs() {
  for (const command of ["witness-plan", "witness-scheduler-plan"]) {
    yield [command, seed(command)];
    const input = seed(command);
    input.commands[0].environment = {inherit: "allowlist", allowlist: ["HOME"], classes: ["local-go"]};
    input.commands[0].exitCodePolicy = {kind: "listed", successCodes: [0, 255]};
    if (command === "witness-scheduler-plan") {
      input.policies[0].retryPolicy = {kind: "bounded", maxAttempts: 2};
      input.policies[0].cancellationPolicy = {kind: "not_supported", graceMs: null};
    }
    yield [command, input];
  }
  yield ["witness-plan", projectedWitnessInput()];
  const projected = projectedWitnessInput();
  const binding = projected.requirementProofBinding;
  delete binding.witnessCommands[0].environmentClass;
  binding.witnessCommands[0].environmentClasses = ["local-go"];
  binding.bindings[0].witnessSelectors = null;
  binding.selection = {changedPaths: [], ownerIds: [], requirementIds: []};
  yield ["witness-plan", projected];
}

test("six whole-CLI routes preserve stdin pointer compact and distinct owner outputs", () => {
  for (const command of names) {
    const input = seed(command);
    validates(command, "input", input);
    const output = native(command, input, {extra: command === "requirement-proof-resolver" ? ["--local-environment-class", "local-go"] : []});
    for (const carrier of ["pointer", "compact"]) assert.deepEqual(native(command, input, {carrier,
      extra: command === "requirement-proof-resolver" ? ["--local-environment-class", "local-go"] : []}), output);
    if (command === "requirement-bindings") assert.deepEqual(output.summary, {bindingCount: 1, commandCount: 1, omittedRequirementCount: 0, requirementCount: 1, selectedRequirementCount: 1});
    if (command === "evidence-graph") assert.equal(output.requirements[0].scenarios[0].witnessSelectors[0].selector, "TestOne");
    if (command === "proof-slice") assert.deepEqual(output.selectedCommandIds, ["test.one"]);
    if (command === "witness-plan") assert.deepEqual(output.parallelGroups, [{commandIds: ["test.one"], parallelGroup: "local"}]);
    if (command === "witness-scheduler-plan") assert.equal(output.state, "passed");
    if (command === "requirement-proof-resolver") {
      assert.equal(output.bindings[0].preconditioned, false);
      assert.deepEqual(output.conformanceProofContract.bindings[0].witnessRefs.map(x => x.role), ["falsification", "positive"]);
      assert.equal(output.commands.length, 3);
      assert.deepEqual(output.commands.find(x => x.verifyCommandRef === "go test ./tests").witnessRouteIds, []);
      assert.equal(output.witnessRoutes.length, 2);
    }
  }
});

test("witness input variants retain absence null defaults and empty-plan behavior", () => {
  const direct = witnessInput(), expected = native("witness-plan", direct);
  assert.deepEqual(native("witness-plan", {...direct, schemaVersion: 1}), expected);
  const projected = projectedWitnessInput();
  validates("witness-plan", "input", projected);
  const fromBinding = native("witness-plan", projected);
  assert.deepEqual(fromBinding.commands.map(x => x.id), ["test.one"]);
  assert.deepEqual(fromBinding.commands[0].argv, ["go", "test", "./tests", "-run", "TestOne"]);
  const extra = {...projected, nonClaims: ["Root metadata must not be discarded."]};
  validates("witness-plan", "input", extra, false, "projected root nonClaims");
  native("witness-plan", extra, {exit: 1, report: false});
  for (const groups of [undefined, ["first", "second"]]) {
    const emptyBinding = bindingInput(); emptyBinding.requirements = []; emptyBinding.bindings = []; emptyBinding.witnessCommands = [];
    const input = {schemaVersion: 1, projection: "requirement-bindings", requirementProofBinding: emptyBinding,
      vocabulary: {artifactKinds: [], credentialClasses: [], environmentClasses: []}};
    if (groups) input.vocabulary.parallelGroups = groups;
    validates("witness-plan", "input", input);
    assert.deepEqual(native("witness-plan", input), {commands: [], parallelGroups: []});
  }
  const ambiguous = structuredClone(projected); ambiguous.vocabulary.parallelGroups = ["first", "second"];
  validates("witness-plan", "input", ambiguous);
  native("witness-plan", ambiguous, {exit: 1, report: false});
  for (const value of [null, 2, "1"]) {
    const bad = {...direct, schemaVersion: value};
    validates("witness-plan", "input", bad, false);
    native("witness-plan", bad, {exit: 1, report: false});
  }
  for (const input of [{commands: [], vocabulary: {artifactKinds: [], credentialClasses: [], environmentClasses: []}},
    {commands: [], vocabulary: {artifactKinds: [], credentialClasses: [], environmentClasses: [], maxTimeoutMs: null, parallelGroups: null, environmentClassPolicies: null, nonCacheableCredentialClasses: null}}]) {
    validates("witness-plan", "input", input);
    assert.deepEqual(native("witness-plan", input), {commands: [], parallelGroups: []});
  }
  for (const key of ["maxTimeoutMs", "nonCacheableCredentialClasses"]) for (const mode of ["missing", "null"]) {
    const input = witnessInput();
    if (mode === "missing") delete input.vocabulary[key]; else input.vocabulary[key] = null;
    validates("witness-plan", "input", input);
    assert.deepEqual(native("witness-plan", input), expected);
  }
  for (const value of [null, "unknown"]) {
    const input = {...projected, projection: value};
    validates("witness-plan", "input", input, false);
    native("witness-plan", input, {exit: 1, report: false});
  }
});

test("scheduler variants distinguish failed linkage from invalid metadata", () => {
  const command = "witness-scheduler-plan";
  for (const cancellation of [{kind: "not_supported"}, {kind: "not_supported", graceMs: null}, {kind: "cooperative", graceMs: 2}]) {
    const input = schedulerInput(); input.policies[0].cancellationPolicy = cancellation;
    validates(command, "input", input); assert.equal(native(command, input).state, "passed");
  }
  for (const attempts of [2, 10]) {
    const input = schedulerInput(); input.policies[0].retryPolicy = {kind: "bounded", maxAttempts: attempts};
    validates(command, "input", input); native(command, input);
  }
  const below = schedulerInput(); below.policies[0].retryPolicy = {kind: "bounded", maxAttempts: 1};
  validates(command, "input", below, false, "bounded retry lower boundary");
  native(command, below, {exit: 1, report: false});
  const empty = schedulerInput(); empty.policies = [];
  validates(command, "input", empty, false);
  native(command, empty, {exit: 1, report: false});
  const unlinked = schedulerInput(); unlinked.policies[0].commandId = "test.other";
  validates(command, "input", unlinked);
  const failed = native(command, unlinked, {exit: 1});
  assert.equal(failed.state, "failed"); assert.equal(failed.summary.policyCount, 1);
  assert.deepEqual(failed.diagnostics[0].value[0].sideEffectClasses, []);
  assert.match(failed.ruleResults[1].diagnostics[0].value, /missing scheduler policy/);
  for (const [key, value] of [["retryPolicy", {kind: "none", maxAttempts: 2}], ["retryPolicy", {kind: "bounded", maxAttempts: 11}],
    ["cancellationPolicy", {kind: "cooperative", graceMs: null}], ["cancellationPolicy", {kind: "not_supported", graceMs: 1}]]) {
    const input = schedulerInput(); input.policies[0][key] = value;
    validates(command, "input", input, false); native(command, input, {exit: 1, report: false});
  }
});

test("binding projections retain empty domains selectors and failed-report separation", () => {
  for (const command of ["requirement-bindings", "evidence-graph", "proof-slice"]) {
    const input = bindingInput(); input.requirements = []; input.bindings = []; input.witnessCommands = [];
    const output = native(command, input);
    if (command === "requirement-bindings") assert.equal(output.summary.requirementCount, 0);
    else assert.deepEqual(output[command === "evidence-graph" ? "requirements" : "selectedRequirements"], []);
    const failed = bindingInput(); failed.bindings[0].requirementId = "REQ-MISSING";
    const result = native(command, failed, {exit: 1, report: command === "requirement-bindings"});
    if (result) assert.equal(result.ruleResults[0].status, "failed");
  }
  const nonmatch = bindingInput(); nonmatch.selection = {ownerIds: ["owner.other"]};
  assert.equal(native("proof-slice", nonmatch).selectedRequirementCount, 0);
  for (const mode of ["missing", "null"]) {
    const input = bindingInput();
    if (mode === "missing") delete input.bindings[0].witnessSelectors; else input.bindings[0].witnessSelectors = null;
    const output = native("evidence-graph", input);
    assert.equal(Object.hasOwn(output.requirements[0].scenarios[0], "witnessSelectors"), false);
  }
  const unbound = bindingInput(); unbound.bindings = []; unbound.witnessCommands = [];
  unbound.requirements[0].claimLevel = "advisory"; unbound.requirements[0].proofState = "not_bound";
  assert.deepEqual(native("evidence-graph", unbound).requirements[0].scenarios, []);
});

test("resolver supports empty contracts surface-only environments and caller policy", () => {
  const input = resolverInput(); input.bindings = [];
  const output = native("requirement-proof-resolver", input);
  assert.deepEqual(output.bindings, []); assert.deepEqual(output.witnessRoutes, []);
  assert.deepEqual(output.environmentClasses, [{bindingRecordIds: [], environmentClass: "local-go", surfaceIds: ["surface.one"], witnessRouteIds: []}]);
  input.surfaces = [];
  assert.deepEqual(native("requirement-proof-resolver", input).environmentClasses, []);
  assert.equal(native("requirement-proof-resolver", resolverInput(), {extra: ["--empty-local-environment-policy"]}).bindings[0].preconditioned, true);
});

test("failed binding reports retain mandatory nonempty failure rules", () => {
  const input = bindingInput(); input.bindings[0].requirementId = "REQ-MISSING";
  const output = native("requirement-bindings", input, {exit: 1});
  assert.equal(output.state, "failed"); assert.ok(output.ruleResults.length > 0);
  output.ruleResults = [];
  validates("requirement-bindings", "output", output, false, "failed report must retain failure rules");
});

test("binding rule statuses stay fixed in both passed and failed report branches", () => {
  for (const failed of [false, true]) {
    const input = bindingInput();
    if (failed) input.bindings[0].requirementId = "REQ-MISSING";
    const output = native("requirement-bindings", input, {exit: failed ? 1 : 0});
    const status = failed ? "failed" : "passed";
    assert.equal(output.state, status); assert.ok(output.ruleResults.length > 0);
    for (const [index, rule] of output.ruleResults.entries()) {
      assert.equal(rule.status, status);
      const bad = structuredClone(output); bad.ruleResults[index].status = failed ? "passed" : "failed";
      validates("requirement-bindings", "output", bad, false, "opposite rule status in binding report");
    }
  }
});

test("scheduler boundary rule remains passed independently of the safety verdict", () => {
  for (const failed of [false, true]) {
    const input = schedulerInput();
    if (failed) input.policies[0].commandId = "test.other";
    const output = native("witness-scheduler-plan", input, {exit: failed ? 1 : 0});
    assert.equal(output.ruleResults[0].ruleId, "proofkit.witness-scheduler-plan.boundary");
    assert.equal(output.ruleResults[0].status, "passed");
    output.ruleResults[0].status = "failed";
    validates("witness-scheduler-plan", "output", output, false, "fixed scheduler boundary status");
  }
});

test("zero exit codes retain decimal integer tokens including raw negative zero", () => {
  for (const command of ["witness-plan", "witness-scheduler-plan"]) {
    const input = seed(command), expected = native(command, input);
    const definitionId = contract.commands.find(row => row.command === command).inputContract.rootDefinitionRef;
    const schema = contract.contractDefinitions.find(row => row.definitionId === definitionId).fieldTree.variants[0].schema;
    const policy = schema.properties.commands.items.properties.exitCodePolicy.oneOf.find(row => row.properties.kind.const === "zero");
    assert.equal(policy.properties.successCodes.prefixItems[0]["x-proofkit-number-encoding"], "decimal-integer-token-int64");
    for (const token of ["0", "-0", "0.0", "0e0"]) {
      const bytes = JSON.stringify(input).replace('"successCodes":[0]', `"successCodes":[${token}]`);
      assert.ok(bytes.includes(`"successCodes":[${token}]`));
      if (token === "0" || token === "-0") assert.deepEqual(native(command, bytes), expected);
      else native(command, bytes, {exit: 1, report: false});
    }
    if (command === "witness-plan") assert.deepEqual(expected.commands[0].exitCodePolicy.successCodes, [0]);
  }
});

test("environment allowlist names retain their grammar in alternative branches", () => {
  for (const command of ["witness-plan", "witness-scheduler-plan"]) {
    const input = seed(command);
    input.commands[0].environment = {inherit: "allowlist", allowlist: ["HOME"], classes: ["local-go"]};
    validates(command, "input", input);
    const output = native(command, input);
    for (const name of ["1HOME", "home", "HOME-KEY", "HOME KEY", ""]) {
      const bad = structuredClone(input); bad.commands[0].environment.allowlist = [name];
      validates(command, "input", bad, false, "invalid environment name");
      native(command, bad, {exit: 1, report: false});
      if (command === "witness-plan") {
        const badOutput = structuredClone(output); badOutput.commands[0].environment.allowlist = [name];
        validates(command, "output", badOutput, false, "invalid environment name");
      }
    }
    for (const name of ["_", "A", "HOME_1"]) {
      const good = structuredClone(input); good.commands[0].environment.allowlist = [name];
      validates(command, "input", good); native(command, good);
    }
  }
});

test("closed witness and scheduler records reject isolated missing null unknown and mistyped members", () => {
  for (const [command, input] of witnessInputs()) {
    validates(command, "input", input); native(command, input);
    for (const path of objects(input)) {
      const bad = structuredClone(input); at(bad, path).unexpected = true;
      validates(command, "input", bad, false, `${path}/unknown`); native(command, bad, {exit: 1, report: false});
      for (const [key, value] of Object.entries(at(input, path))) {
        const location = path.join("/");
        const nullableOptional = (location === "vocabulary" && ["maxTimeoutMs", "environmentClassPolicies", "parallelGroups", "nonCacheableCredentialClasses"].includes(key))
          || (path[0] === "requirementProofBinding" && key === "witnessSelectors")
          || (location === "requirementProofBinding" && key === "selection")
          || location === "requirementProofBinding/selection"
          || (key === "graceMs" && at(input, path).kind === "not_supported");
        for (const mode of nullableOptional ? ["wrong-type"] : ["missing", "null", "wrong-type"]) {
          const bad = structuredClone(input);
          if (mode === "missing") delete at(bad, path)[key];
          else at(bad, path)[key] = mode === "null" ? null : wrongType(value);
          validates(command, "input", bad, false, `${path}/${key}/${mode}`);
          native(command, bad, {exit: 1, report: false});
        }
      }
    }
  }
});

test("scheduler primitive domains reject their adjacent invalid boundaries", () => {
  for (const [path, value] of [
    [["commands"], []], [["nonClaims"], []], [["policies", 0, "nonClaims"], []],
    [["policies", 0, "sideEffectClass"], "unknown"], [["policies", 0, "retryPolicy", "kind"], "unknown"],
    [["policies", 0, "cancellationPolicy", "kind"], "unknown"], [["policies", 0, "cancellationPolicy", "graceMs"], 0],
    [["policies", 0, "timeoutPolicy", "kind"], "unknown"], [["policies", 0, "timeoutPolicy", "timeoutMs"], 0],
  ]) {
    const input = schedulerInput(); at(input, path.slice(0, -1))[path.at(-1)] = value;
    validates("witness-scheduler-plan", "input", input, false, `${path}/domain`);
    native("witness-scheduler-plan", input, {exit: 1, report: false});
  }
});

test("populated output members reject missing null unknown and mistyped values", () => {
  for (const [command, output] of outputCases()) {
    for (const path of objects(output)) {
      const bad = structuredClone(output); at(bad, path).unexpected = true;
      validates(command, "output", bad, false, `${path}/unknown`);
      for (const [key, value] of Object.entries(at(output, path))) {
        for (const mode of key === "witnessSelectors" ? ["null", "wrong-type"] : ["missing", "null", "wrong-type"]) {
          const bad = structuredClone(output);
          if (mode === "missing") delete at(bad, path)[key];
          else at(bad, path)[key] = mode === "null" ? null : wrongType(value);
          validates(command, "output", bad, false, `${path}/${key}/${mode}`);
        }
      }
    }
  }
});

test("output collection and positive-count minima have independent boundary cases", () => {
  const scenarios = key => ["commandIds", "environmentClasses", "witnessSelectors"].map(field => [[key, 0, "scenarios", 0, field], 1]);
  const cases = [
    ["requirement-bindings", [[["diagnostics"], 1], [["ruleResults"], 1]]],
    ["evidence-graph", scenarios("requirements")],
    ["proof-slice", scenarios("selectedRequirements")],
    ["witness-plan", [
      [["parallelGroups", 0, "commandIds"], 1], [["commands", 0, "argv"], 1],
      [["commands", 0, "environment", "classes"], 1], [["commands", 0, "exitCodePolicy", "successCodes"], 1],
    ]],
    ["witness-scheduler-plan", [
      [["diagnostics"], 2], [["ruleResults"], 2], [["diagnostics", 0, "value"], 1],
      [["diagnostics", 0, "value", 0, "commandIds"], 1],
    ]],
    ["requirement-proof-resolver", [
      [["commands", 0, "bindingRecordIds"], 1], [["environmentClasses", 0, "surfaceIds"], 1],
      [["conformanceProofContract", "bindings", 0, "witnessRefs"], 2],
    ]],
  ];
  for (const [command, boundaries] of cases) {
    const output = native(command, seed(command));
    for (const [path, minimum] of boundaries) {
      const values = at(output, path);
      assert.ok(Array.isArray(values) && values.length >= minimum, `${command}/${path}: valid boundary prerequisite`);
      const bad = structuredClone(output);
      at(bad, path.slice(0, -1))[path.at(-1)] = values.slice(0, minimum - 1);
      validates(command, "output", bad, false, `output cardinality below minimum: ${path}`);
    }
  }
  const listed = witnessInput();
  listed.commands[0].environment = {inherit: "allowlist", allowlist: ["HOME"], classes: ["local-go"]};
  listed.commands[0].exitCodePolicy = {kind: "listed", successCodes: [0, 255]};
  const output = native("witness-plan", listed);
  for (const path of [["commands", 0, "environment", "allowlist"], ["commands", 0, "exitCodePolicy", "successCodes"]]) {
    const bad = structuredClone(output); at(bad, path.slice(0, -1))[path.at(-1)] = [];
    validates("witness-plan", "output", bad, false, `output cardinality below minimum: ${path}`);
  }
  const scheduler = native("witness-scheduler-plan", schedulerInput());
  for (const field of ["commandCount", "policyCount", "executionGroupCount"]) {
    assert.ok(scheduler.summary[field] >= 1);
    const bad = structuredClone(scheduler); bad.summary[field] = 0;
    validates("witness-scheduler-plan", "output", bad, false, `positive count lower boundary: ${field}`);
  }
});

test("resolver fixed role positions reject the opposite valid role", () => {
  const command = "requirement-proof-resolver", output = native(command, resolverInput());
  for (const [index, role] of ["falsification", "positive"].entries()) {
    for (const path of [["bindings", 0, "testWitnesses", role, "role"],
      ["conformanceProofContract", "bindings", 0, "witnessRefs", index, "role"]]) {
      assert.equal(at(output, path), role);
      const bad = structuredClone(output);
      at(bad, path.slice(0, -1))[path.at(-1)] = role === "positive" ? "falsification" : "positive";
      validates(command, "output", bad, false, `opposite role in fixed position: ${path}`);
    }
  }
});

test("witness leaf domains and native-only safety predicates remain distinct", () => {
  for (const [path, value, structural] of [
    [["commands", 0, "networkPolicy"], "ambient", false],
    [["commands", 0, "cachePolicy"], "shared", false],
    [["commands", 0, "environment", "inherit"], "unknown", false],
    [["commands", 0, "exitCodePolicy", "kind"], "unknown", false],
    [["commands", 0, "id"], "UPPER", false],
    [["commands", 0, "timeoutMs"], 0, false],
    [["commands", 0, "argv"], [], false],
    [["commands", 0, "environment", "classes"], [], false],
    [["commands", 0, "environment", "classes"], ["other"], true],
    [["commands", 0, "environment", "allowlist"], ["HOME"], false],
    [["commands", 0, "exitCodePolicy", "successCodes"], [1], false],
    [["commands", 0, "argv"], ["sh", "-c", "true"], true],
    [["commands", 0, "cwd"], "../outside", true],
    [["vocabulary", "maxTimeoutMs"], 0, false],
    [["vocabulary", "environmentClassPolicies", 0, "networkPolicies"], ["ambient"], false],
  ]) {
    const input = witnessInput(); at(input, path.slice(0, -1))[path.at(-1)] = value;
    validates("witness-plan", "input", input, structural, `${path}`);
    native("witness-plan", input, {exit: 1, report: false});
  }
  const listed = witnessInput();
  listed.commands[0].exitCodePolicy = {kind: "listed", successCodes: [0, 255]};
  listed.commands[0].environment = {inherit: "allowlist", allowlist: ["HOME"], classes: ["local-go"]};
  validates("witness-plan", "input", listed); native("witness-plan", listed);
  for (const value of [-1, 256]) {
    const input = structuredClone(listed); input.commands[0].exitCodePolicy.successCodes = [value];
    validates("witness-plan", "input", input, false); native("witness-plan", input, {exit: 1, report: false});
  }
  for (const value of [[0, 0], [255, 0]]) {
    const input = structuredClone(listed); input.commands[0].exitCodePolicy.successCodes = value;
    validates("witness-plan", "input", input); native("witness-plan", input, {exit: 1, report: false});
  }
  const raw = JSON.stringify({...witnessInput(), schemaVersion: 1}).replace('"schemaVersion":1', '"schemaVersion":1.0');
  validates("witness-plan", "input", JSON.parse(raw));
  native("witness-plan", raw, {exit: 1, report: false});
  const duplicate = JSON.stringify(witnessInput()).replace('"commands":', '"commands":[],"commands":');
  native("witness-plan", duplicate, {exit: 1, report: false});
});

test("output literal roles counts hashes and selector omission have independent controls", () => {
  for (const [command, output] of outputCases()) {
    for (const path of objects(output)) for (const [key, value] of Object.entries(at(output, path))) {
      let replacement;
      if (["reportKind", "graphKind", "sliceKind", "projectionKind", "declarationKind", "state", "status", "role", "authority", "claimLevel", "proofState", "witnessKind", "ruleId", "key"].includes(key)) replacement = "unknown";
      else if (key === "message" || (key === "value" && typeof value === "string")) replacement = "";
      else if (key === "schemaVersion") replacement = value + 1;
      else if (key.endsWith("Count") || key === "resolutionOrderIndex") replacement = -1;
      else if (key === "bindingRecordId" || key === "witnessRouteId") replacement = "sha256:abc";
      else continue;
      const bad = structuredClone(output); at(bad, path)[key] = replacement;
      validates(command, "output", bad, false, `${path}/${key}/value-domain`);
    }
  }
  const output = native("evidence-graph", bindingInput());
  output.requirements[0].scenarios[0].witnessSelectors = [];
  validates("evidence-graph", "output", output, false, "present selector list is nonempty");
});
