import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {annotatedInventoryInput, directComposeInput, discoveryInput, inventoryInput, normalizedComposeInput, ownerInvariantRegistry, proofInventoryInput, sourceSetInput, twoSourceSetInput, wrappedInventory} from "./inventory-coverage-fixtures.mjs";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_INVENTORY_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const inventory = "test-evidence-inventory", composer = "requirement-coverage-input-compose", view = "requirement-coverage-view";
const validators = new Map();
for (const command of [inventory, composer, view]) for (const direction of ["input", "output"]) {
  const ref = contract.commands.find(row => row.command === command)[`${direction}Contract`].rootDefinitionRef;
  const definition = contract.contractDefinitions.find(row => row.definitionId === ref);
  assert.equal(definition.fieldTree.kind, "structural_json_schema");
  validators.set(`${command}/${direction}`, new Ajv2020({strict: false, validateFormats: false}).compile({oneOf: definition.fieldTree.variants.map(row => row.schema)}));
}
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-inventory-"));
  binary = join(directory, "proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120000, maxBuffer: 2 << 20, env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });

function validates(command, direction, value, expected = true, label = "") {
  const check = validators.get(`${command}/${direction}`);
  assert.equal(check(value), expected, `${command}/${direction}/${label}: ${JSON.stringify(check.errors)}`);
}

function native(command, input, {flags = [], exit = 0, report = true, carrier = "stdin", compare = true, absent = []} = {}) {
  let args = [command, "--input", "-", ...flags], bytes = JSON.stringify(input);
  if (carrier === "pointer") {
    const path = join(directory, "input.json");
    writeFileSync(path, JSON.stringify({payload: input}));
    args = [command, "--input", path, "--input-pointer", "/payload", ...flags]; bytes = "";
  } else if (carrier === "compact") args.unshift("--json-layout", "compact");
  const invoke = path => spawnSync(path, args, {input: bytes, encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
  const result = invoke(binary);
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  for (const value of absent) assert.equal((result.stdout + result.stderr).includes(value), false, "caller value disclosed");
  if (exit === null) assert.ok([0, 1].includes(result.status), result.stderr);
  else assert.equal(result.status, exit, result.stderr);
  if (process.env.PROOFKIT_INVENTORY_BASELINE && compare) {
    const prior = invoke(process.env.PROOFKIT_INVENTORY_BASELINE);
    assert.equal(prior.error, undefined);
    assert.deepEqual([result.status, result.signal, result.stdout, result.stderr], [prior.status, prior.signal, prior.stdout, prior.stderr], "undeclared native predecessor delta");
  }
  if (!report) { assert.equal(result.stdout, ""); assert.notEqual(result.stderr, ""); return; }
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  validates(command, "output", output);
  if (output.state) assert.equal(result.status, output.state === "passed" ? 0 : 1);
  return output;
}

function rejectionCheck(command, direction, baseline, flags = []) {
  return (mutate, label) => {
    const changed = structuredClone(baseline); mutate(changed);
    validates(command, direction, changed, false, label);
    if (direction === "input") native(command, changed, {flags, exit: 1, report: false});
  };
}

test("ordinary and fallback report egress stay separate from safe normalized data", () => {
  for (const testId of ["test.safe", "password"]) for (const severity of ["warning", "failure"]) {
    const input = annotatedInventoryInput(); input.entries[0].testId = testId;
    input.entries[0].qualityFindings[0].evidenceRefs = [testId];
    input.entries[0].qualityFindings[0].severity = severity;
    for (const normalized of [false, true]) {
      const flags = normalized ? ["--normalized-inventory"] : [];
      const unsafe = testId === "password" && (!normalized || severity === "failure");
      if (unsafe) {
        native(inventory, input, {flags, exit: 1, report: false, compare: false, absent: ["quality_finding:tautology:password:"]});
      } else {
        const output = native(inventory, input, {flags, exit: severity === "failure" ? 1 : 0});
        assert.equal(output.normalizedKind === "proofkit.test-evidence-inventory.normalized", normalized && severity === "warning");
      }
    }
  }
});

test("discovery input records and finite vocabularies have independent clause witnesses", () => {
  const input = discoveryInput(), flags = ["--projection", "discovery-draft"];
  for (const path of [[], ["repository"], ["runner"], ["discoveredTests", 0]]) at(input, path).nonClaims = [];
  native(inventory, input, {flags});
  const reject = rejectionCheck(inventory, "input", input, flags);
  const records = [
    [[], ["schemaVersion", "authority", "draftId", "repository", "runner", "discoveredTests"]],
    [["repository"], ["repositoryId"]],
    [["runner"], ["runnerId", "runnerKind", "commandRef", "environmentClass"]],
    [["discoveredTests", 0], ["testId", "ownerId", "selector", "sourcePath", "title", "candidateRequirementRefs", "ownerInvariantRefs", "oracleSignals", "selectorSignals"]],
  ];
  for (const [path, required] of records) {
    reject(value => {at(value, path).foreign = true;}, `${path} extra field`);
    for (const key of required) {
      reject(value => {delete at(value, path)[key];}, `${path}/${key} missing`);
      for (const value of [null, false]) reject(record => {at(record, path)[key] = value;}, `${path}/${key} invalid`);
    }
    for (const absent of [false, true]) {
      const value = structuredClone(input);
      if (absent) delete at(value, path).nonClaims; else at(value, path).nonClaims = null;
      validates(inventory, "input", value); native(inventory, value, {flags});
    }
    reject(value => {at(value, path).nonClaims = [false];}, `${path} nonClaims item`);
  }
  for (const [path, values, array] of [
    [["runner", "runnerKind"], ["generic", "go_test", "node_test", "playwright", "pytest", "vitest"], false],
    [["discoveredTests", 0, "oracleSignals"], ["assertion_present", "expected_exception", "no_assertion_observed", "snapshot_only", "status_or_exit_assertion", "unknown"], true],
    [["discoveredTests", 0, "selectorSignals"], ["first_or_last_selector", "nth_selector", "raw_css_selector", "role_selector", "structured_selector", "test_id_selector", "text_selector", "unknown", "xpath_selector"], true],
  ]) {
    const assign = (record, value) => {at(record, path.slice(0, -1))[path.at(-1)] = array ? [value] : value;};
    for (const value of values) {
      const positive = structuredClone(input); assign(positive, value);
      validates(inventory, "input", positive); native(inventory, positive, {flags});
    }
    for (const value of ["", "foreign", null, 1]) reject(record => assign(record, value), `${path} enum`);
  }
  reject(value => {value.discoveredTests = [];}, "discovery tests minimum");
  reject(value => {value.discoveredTests = [null];}, "discovery test item");
  reject(value => {value.schemaVersion = 2;}, "discovery version");
  reject(value => {value.authority = "foreign";}, "discovery authority");
});

test("discovery action types expose exactly the producer routing vocabulary", () => {
  const input = discoveryInput(), row = input.discoveredTests[0];
  row.candidateRequirementRefs = []; row.oracleSignals = []; row.selectorSignals = ["raw_css_selector"];
  const output = native(inventory, input, {flags: ["--projection", "discovery-draft"]});
  const actions = output.diagnostics.find(row => row.key === "agentActionPlan").value;
  assert.deepEqual(actions.map(row => row.type).sort(), ["candidate_only", "missing_declared_assertion_signal", "missing_declared_route_anchor", "selector_fragility"]);
  for (const value of ["", "foreign"]) {
    const changed = structuredClone(output); changed.diagnostics.find(row => row.key === "agentActionPlan").value[0].type = value;
    validates(inventory, "output", changed, false, "discovery action enum");
  }
});

test("coverage parent records preserve required fields nullable modes and universe domains", () => {
  const normalized = native(inventory, inventoryInput(), {flags: ["--normalized-inventory"]});
  for (const input of [directComposeInput(), normalizedComposeInput(normalized)]) {
    const compact = Object.hasOwn(input, "normalizedTestEvidenceInventory");
    input.ownerInvariantRegistry = ownerInvariantRegistry();
    input.options = {scope: "scope.one"}; input.localEnvironmentPolicy = {authority: "caller_provided", localEnvironmentClasses: ["local-go"]};
    input.coverageUniverse.commandRefs = ["test.one"];
    for (const [key, surfaceId, path] of [["codeSurfaces", "code.one", "src/one.go"], ["specSurfaces", "spec.one", "specs/requirements.v2.json"], ["testSurfaces", "test.surface", "tests/one.go"]]) {
      input.coverageUniverse[key] = [{surfaceId, ownerId: "owner.one", path}];
    }
    const output = native(composer, input); native(view, output, {exit: null});
    for (const [command, direction, baseline] of [[composer, "input", input], [composer, "output", output], [view, "input", output]]) {
      const reject = rejectionCheck(command, direction, baseline);
      const records = [
        [["coverageUniverse"], ["schemaVersion", "authority", "universeId", "completenessDeclaration", "ownerIds", "commandRefs", "codeSurfaces", "specSurfaces", "testSurfaces", "nonClaims"]],
        ...["codeSurfaces", "specSurfaces", "testSurfaces"].map(key => [["coverageUniverse", key, 0], ["surfaceId", "ownerId", "path"]]),
        [["localEnvironmentPolicy"], ["authority", "localEnvironmentClasses"]], [["options"], []],
      ];
      for (const [path, required] of records) {
        reject(value => {at(value, path).foreign = true;}, `${path} extra field`);
        for (const key of required) {
          reject(value => {delete at(value, path)[key];}, `${path}/${key} missing`);
          for (const value of [null, false]) reject(record => {at(record, path)[key] = value;}, `${path}/${key} invalid`);
        }
      }
      for (const key of ["ownerIds", "nonClaims"]) reject(value => {value.coverageUniverse[key] = [];}, `universe ${key} minimum`);
      for (const key of ["ownerIds", "nonClaims", "commandRefs", "codeSurfaces", "specSurfaces", "testSurfaces"]) {
        reject(value => {value.coverageUniverse[key] = [false];}, `universe ${key} item`);
      }
      for (const value of ["foreign", ""]) {
        reject(record => {record.coverageUniverse.completenessDeclaration = value;}, "universe completeness enum");
        reject(record => {record.coverageUniverse.authority = value;}, "universe authority");
        reject(record => {record.localEnvironmentPolicy.authority = value;}, "local policy authority");
      }
      reject(value => {value.coverageUniverse.schemaVersion = 2;}, "universe version");
      reject(value => {value.localEnvironmentPolicy.localEnvironmentClasses = [false];}, "local policy item");
      for (const value of [null, false]) reject(record => {record.options.scope = value;}, "options scope type");
      for (const completeness of ["full_repository", "selected_owner_surfaces", "selected_paths_advisory"]) {
        const positive = structuredClone(baseline); positive.coverageUniverse.completenessDeclaration = completeness;
        validates(command, direction, positive);
        if (direction === "input") native(command, positive, {exit: command === view ? null : 0});
      }
      const rootRequired = ["schemaVersion", "viewInputId", "coverageUniverse", "requirementSource", compact ? "compactProofContract" : "requirementProofBinding"];
      if (compact) rootRequired.push("localEnvironmentPolicy");
      if (command === composer && direction === "input") rootRequired.push("composerInputId", "selectedOwnerIds", compact ? "normalizedTestEvidenceInventory" : "testEvidenceInventory");
      if (direction === "output") {
        rootRequired.push("compactProofContract", "requirementProofBinding", "testEvidenceInventory", "options", "ownerInvariantRegistry", "localEnvironmentPolicy");
        if (compact) rootRequired.push("normalizedTestEvidenceInventory");
      }
      const nullable = new Set(["options", "ownerInvariantRegistry", ...(compact ? ["requirementProofBinding"] : ["compactProofContract", "localEnvironmentPolicy"])]);
      for (const key of new Set(rootRequired)) {
        const missing = structuredClone(baseline); delete missing[key];
        validates(command, direction, missing, false, `root required ${key}`);
        if (direction === "input") native(command, missing, {exit: 1, report: false});
        reject(value => {value[key] = false;}, `root type ${key}`);
        if (!nullable.has(key)) reject(value => {value[key] = null;}, `root nonnull ${key}`);
      }
      reject(value => {value.foreign = true;}, "parent root extra field");
      reject(value => {value.schemaVersion = 2;}, "parent root version");
      if (command === composer && direction === "input") reject(value => {value.selectedOwnerIds = [];}, "selected owner minimum");
      for (const key of ["options", "ownerInvariantRegistry", ...(!compact ? ["localEnvironmentPolicy"] : [])]) {
        const positive = structuredClone(baseline); positive[key] = null;
        validates(command, direction, positive);
        if (direction === "input") native(command, positive, {exit: command === view ? null : 0});
      }
    }
  }
});

test("inventory modes use real CLI branches and preserve stdin pointer and compact carriers", () => {
  for (const [input, flags] of [[inventoryInput(), []], [sourceSetInput(), []], [wrappedInventory(), []], [wrappedInventory(sourceSetInput()), []],
    [discoveryInput(), ["--projection", "discovery-draft"]], [proofInventoryInput(), ["--projection", "proof-binding-derived"]]]) {
    validates(inventory, "input", input);
    const output = native(inventory, input, {flags});
    assert.equal(output.reportKind, flags[1] === "discovery-draft" ? "proofkit.test-inventory-discovery-draft" : "proofkit.test-evidence-inventory");
    for (const carrier of ["pointer", "compact"]) assert.deepEqual(native(inventory, input, {flags, carrier}), output);
    if (flags[1] !== "discovery-draft") {
      const normalized = native(inventory, input, {flags: [...flags, "--normalized-inventory"]});
      assert.equal(normalized.normalizedKind, "proofkit.test-evidence-inventory.normalized");
      assert.equal(normalized.inventory.entries.length, 1);
      assert.equal(normalized.inventory.authority, "caller_owned_inventory");
      if (flags[1] === "proof-binding-derived") {
        assert.equal(normalized.projectionKind, "proofkit.proof-binding-test-inventory");
        assert.equal(normalized.projectionSummary.routeEntryMappings[0].testId, normalized.inventory.entries[0].testId);
      }
    }
  }
  native(inventory, discoveryInput(), {flags: ["--projection", "discovery-draft", "--normalized-inventory"], exit: 1, report: false});
});

test("discovery rejects unsafe composed identities and preserves safe maximum-length IDs", () => {
  const unsafe = ["eyJabc", "def"].join(".");
  for (const field of ["draftId", "testId"]) for (const id of ["ordinary.id", "a".repeat(256), unsafe]) {
    const input = discoveryInput();
    if (field === "draftId") input.draftId = id;
    else input.discoveredTests[0].testId = id;
    validates(inventory, "input", input);
    if (id === unsafe) {
      native(inventory, input, {flags: ["--projection", "discovery-draft"], exit: 1, report: false, compare: false, absent: [id]});
    } else {
      const output = native(inventory, input, {flags: ["--projection", "discovery-draft"]});
      const candidate = output.diagnostics.find(row => row.key === "candidateInventory").value;
      assert.equal(candidate.inventoryId, `${input.draftId}.candidate_inventory`);
      assert.equal(candidate.authority, "caller_owned_test_discovery_candidate_inventory");
      assert.equal(candidate.entries[0].testId, input.discoveredTests[0].testId);
    }
  }
});

test("source-set identity admission spans distinct fragments before reporting or normalization", () => {
  const duplicate = twoSourceSetInput({duplicateFalsifier: true});
  validates(inventory, "input", duplicate);
  for (const row of duplicate.sourceTexts) native(inventory, JSON.parse(row.text));
  for (const flags of [[], ["--normalized-inventory"]]) {
    native(inventory, duplicate, {flags, exit: 1, report: false, compare: false});
  }
  for (const options of [{}, {nullFalsifiers: true}]) {
    const input = twoSourceSetInput(options);
    const normalized = native(inventory, input, {flags: ["--normalized-inventory"]});
    assert.equal(normalized.inventory.entries.length, 2);
    assert.deepEqual(normalized.entrySources.map(row => row.testId), ["test.one", "test.two"]);
    const composed = native(composer, normalizedComposeInput(normalized));
    assert.deepEqual(composed.normalizedTestEvidenceInventory, normalized);
    native(view, composed, {exit: null});
  }
});

test("populated invariant registry preserves required structure across composer and view", () => {
  const input = directComposeInput(); input.ownerInvariantRegistry = ownerInvariantRegistry();
  input.testEvidenceInventory.entries[0].ownerInvariantRefs = ["invariant.one"];
  validates(composer, "input", input);
  const output = native(composer, input);
  assert.deepEqual(output.ownerInvariantRegistry, input.ownerInvariantRegistry);
  native(view, output, {exit: null});
  for (const [command, direction, baseline] of [[composer, "input", input], [composer, "output", output], [view, "input", output]]) {
    const check = (change, label) => {
      const modified = structuredClone(baseline); change(modified.ownerInvariantRegistry);
      validates(command, direction, modified, false, label);
      if (direction === "input") native(command, modified, {exit: 1, report: false});
    };
    for (const [level, keys] of [["registry", ["schemaVersion", "registryId", "nonClaims", "invariants"]],
      ["row", ["ownerInvariantId", "ownerId", "sourcePath", "summary", "nonClaims"]]]) {
      const record = registry => level === "row" ? registry.invariants[0] : registry;
      for (const key of keys) {
        check(registry => {delete record(registry)[key];}, `${level} missing ${key}`);
        for (const value of [null, false]) check(registry => {record(registry)[key] = value;}, `${level} invalid ${key}`);
      }
      check(registry => {record(registry).unknown = true;}, `${level} unknown field`);
    }
    check(registry => {registry.invariants = [null];}, "null invariant row");
    check(registry => {registry.nonClaims = [];}, "empty registry nonClaims");
    check(registry => {registry.schemaVersion = 2;}, "wrong registry version");
  }
});

test("proof-derived normalized mappings preserve their whole CLI chain and numeric bound", () => {
  for (const order of [0, Number.MAX_SAFE_INTEGER]) {
    const proof = proofInventoryInput(); proof.compactProofContract.bindings[0][8][3] = order;
    const normalized = native(inventory, proof, {flags: ["--projection", "proof-binding-derived", "--normalized-inventory"]});
    const input = normalizedComposeInput(normalized); input.compactProofContract = proof.compactProofContract;
    validates(composer, "input", input);
    const output = native(composer, input, {compare: false});
    assert.deepEqual(output.normalizedTestEvidenceInventory, normalized);
    assert.equal(normalized.projectionSummary.routeEntryMappings[0].resolutionOrderIndex, order);
    const coverage = native(view, output, {exit: 1, compare: false});
    assert.equal(coverage.requirementCoverage[0].coverageState, "proof_route_candidate_only");
    assert.equal(coverage.failures.some(value => value.includes("unknown_command_or_witness_ref:") && value.endsWith(normalized.inventory.entries[0].witnessRefs[0])), false);
    for (const [command, direction, baseline, envelope] of [
      [inventory, "output", normalized, value => value],
      [composer, "input", input, value => value.normalizedTestEvidenceInventory],
      [composer, "output", output, value => value.normalizedTestEvidenceInventory],
      [view, "input", output, value => value.normalizedTestEvidenceInventory],
    ]) {
      for (const invalid of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, "1"]) {
        const changed = structuredClone(baseline);
        envelope(changed).projectionSummary.routeEntryMappings[0].resolutionOrderIndex = invalid;
        validates(command, direction, changed, false, "mapping numeric bound");
        if (direction === "input") native(command, changed, {exit: 1, report: false});
      }
      const row = envelope(baseline).projectionSummary.routeEntryMappings[0];
      assert.deepEqual(Object.keys(row).sort(), ["bindingRecordId", "requirementId", "resolutionOrderIndex", "role", "scenarioId", "selector", "surfaceId", "testId", "witnessRouteId"]);
      for (const key of Object.keys(row)) {
        const changed = structuredClone(baseline); delete envelope(changed).projectionSummary.routeEntryMappings[0][key];
        validates(command, direction, changed, false, `missing mapping ${key}`);
        if (direction === "input") native(command, changed, {exit: 1, report: false});
      }
    }
  }
});

test("raw SHA whitespace normalizes but emitted source metadata remains canonical", () => {
  const expected = native(inventory, sourceSetInput(), {flags: ["--normalized-inventory"]});
  for (const padding of [" ", "\u0085\u2000"]) {
    const source = sourceSetInput(); source.sources[0][2] = padding + source.sources[0][2] + padding;
    for (const input of [source, wrappedInventory(source)]) {
      validates(inventory, "input", input);
      assert.deepEqual(native(inventory, input, {flags: ["--normalized-inventory"]}), expected);
    }
    const envelope = structuredClone(expected); envelope.sources[0][2] = padding + envelope.sources[0][2] + padding;
    validates(inventory, "output", envelope, false, "emitted digest is canonical");
    const input = normalizedComposeInput(envelope); validates(composer, "input", input);
    const output = native(composer, input);
    assert.deepEqual(output.normalizedTestEvidenceInventory, expected);
    const paddedOutput = structuredClone(output); paddedOutput.normalizedTestEvidenceInventory = envelope;
    validates(composer, "output", paddedOutput, false);
    validates(view, "input", paddedOutput);
    assert.deepEqual(native(view, paddedOutput, {exit: null}), native(view, output, {exit: null}));
  }
  for (const digest of ["", " ", "a".repeat(63), "A".repeat(64), ` ${"a".repeat(63)}z `]) {
    const input = sourceSetInput(); input.sources[0][2] = digest;
    validates(inventory, "input", input, false); native(inventory, input, {exit: 1, report: false});
    const envelope = structuredClone(expected); envelope.sources[0][2] = digest;
    const compose = normalizedComposeInput(envelope);
    validates(composer, "input", compose, false); native(composer, compose, {exit: 1, report: false});
  }
});

test("normalized projection markers are jointly absent null or populated", () => {
  const proof = proofInventoryInput();
  const normalized = native(inventory, proof, {flags: ["--projection", "proof-binding-derived", "--normalized-inventory"]});
  const ordinary = native(inventory, inventoryInput(), {flags: ["--normalized-inventory"]});
  for (const [original, mutate] of [
    [normalized, value => {delete value.projectionKind;}],
    [normalized, value => {delete value.projectionSummary;}],
    [normalized, value => {value.projectionKind = null;}],
    [normalized, value => {value.projectionSummary = null;}],
    [normalized, value => {value.projectionKind = "foreign";}],
    [normalized, value => {value.projectionSummary.schemaVersion = 1;}],
    [normalized, value => {value.projectionSummary.routeEntryMappings[0].role = "positive";}],
  ]) {
    const envelope = structuredClone(original); mutate(envelope);
    const input = normalizedComposeInput(envelope);
    validates(composer, "input", input, false); native(composer, input, {exit: 1, report: false});
  }
  for (const markers of [{}, {projectionKind: null}, {projectionSummary: null}, {projectionKind: null, projectionSummary: null}]) {
    const input = normalizedComposeInput({...ordinary, ...markers});
    validates(composer, "input", input);
    const output = native(composer, input);
    assert.equal(Object.hasOwn(output.normalizedTestEvidenceInventory, "projectionKind"), false);
    assert.equal(Object.hasOwn(output.normalizedTestEvidenceInventory, "projectionSummary"), false);
  }
});

test("rare inventory fields survive normalization composition and coverage", () => {
  const input = annotatedInventoryInput(), entry = input.entries[0];
  const normalized = native(inventory, input, {flags: ["--normalized-inventory"]});
  assert.deepEqual(normalized.inventory.entries[0], entry);
  const direct = directComposeInput(); direct.testEvidenceInventory = normalized.inventory;
  const output = native(composer, direct);
  assert.deepEqual(output.testEvidenceInventory.entries[0], entry);
  const coverage = native(view, output, {exit: null});
  const retained = coverage.requirementCoverage[0].tests.find(row => row.testId === entry.testId);
  for (const [key, value] of Object.entries(entry.falsifier)) assert.deepEqual(retained[key], value);
  for (const key of ["qualityFindings", "nonClaims"]) assert.deepEqual(retained[key], entry[key]);
  for (const scope of ["legacy.one", "legacy.two"]) {
    const scoped = structuredClone(output); scoped.options = {scope};
    validates(view, "input", scoped);
    assert.deepEqual(native(view, scoped, {exit: null}), coverage);
  }
});

test("unsafe derived identity is refused at the public normalized CLI boundary", () => {
  const input = inventoryInput(); input.inventoryId = ["eyJabc", "def"].join(".");
  native(inventory, input);
  native(inventory, input, {flags: ["--normalized-inventory"], exit: 1, report: false,
    compare: false, absent: [input.inventoryId, input.inventoryId + ".normalized"]});
});

function at(value, path) { return path.reduce((record, key) => record[key], value); }
function objectPaths(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [...(Array.isArray(value) ? [] : [path]),
    ...Object.entries(value).flatMap(([key, child]) => objectPaths(child, [...path, key]))];
}

test("new inventory output records have independent required key null type and count controls", () => {
  const failedInput = inventoryInput(); failedInput.entries[0].commandRefs = [];
  const draftInput = discoveryInput(); draftInput.discoveredTests[0].oracleSignals = [];
  const fixtures = [
    native(inventory, inventoryInput()),
    native(inventory, failedInput, {exit: 1}),
    native(inventory, draftInput, {flags: ["--projection", "discovery-draft"]}),
    native(inventory, sourceSetInput(), {flags: ["--normalized-inventory"]}),
    native(inventory, annotatedInventoryInput(), {flags: ["--normalized-inventory"]}),
    native(inventory, proofInventoryInput(), {flags: ["--projection", "proof-binding-derived", "--normalized-inventory"]}),
  ];
  for (const baseline of fixtures) {
    for (const path of objectPaths(baseline)) {
      const original = at(baseline, path);
      const unknown = structuredClone(baseline); at(unknown, path).undeclared = true;
      validates(inventory, "output", unknown, false, `${path}/unknown`);
      for (const [key, value] of Object.entries(original)) {
        // Only inventory-level identity annotations and declaration refs are optional.
        const optional = (original.authority === "caller_owned_inventory" && ["ownerId", "sourceId"].includes(key)) || key === "supersessionDeclarationRef";
        const missing = structuredClone(baseline); delete at(missing, path)[key];
        validates(inventory, "output", missing, optional, `${path}/${key}/presence`);
        const wrong = structuredClone(baseline); at(wrong, path)[key] = typeof value === "string" ? 0 : "wrong-type";
        validates(inventory, "output", wrong, false, `${path}/${key}/type`);
        const nullable = key === "falsifier" || key === "oracle";
        const nil = structuredClone(baseline); at(nil, path)[key] = null;
        validates(inventory, "output", nil, nullable, `${path}/${key}/null`);
        if (typeof value === "number") {
          const negative = structuredClone(baseline); at(negative, path)[key] = -1;
          validates(inventory, "output", negative, false, `${path}/${key}/nonnegative`);
          const fraction = structuredClone(baseline); at(fraction, path)[key] = 0.5;
          validates(inventory, "output", fraction, false, `${path}/${key}/integer`);
        }
      }
    }
    if (baseline.reportKind) {
      for (const field of ["diagnostics", "ruleResults"]) {
        for (const operation of ["remove", "append"]) {
          const changed = structuredClone(baseline);
          if (operation === "remove") changed[field].pop(); else changed[field].push(structuredClone(changed[field][0]));
          validates(inventory, "output", changed, false, `${field}/${operation}`);
        }
      }
    }
  }
});

test("failed normalized reports remain reports and discovery fallback remains advisory", () => {
  const input = inventoryInput(); input.entries[0].commandRefs = [];
  validates(inventory, "input", input);
  const failed = native(inventory, input, {flags: ["--normalized-inventory"], exit: 1});
  assert.equal(failed.reportKind, "proofkit.test-evidence-inventory");
  assert.equal(failed.state, "failed"); assert.equal(failed.normalizedKind, undefined);
  const draft = discoveryInput(); draft.discoveredTests[0].oracleSignals = [];
  const candidate = native(inventory, draft, {flags: ["--projection", "discovery-draft"]});
  const classifications = candidate.diagnostics.find(row => row.key === "warningClassifications").value;
  assert.ok(classifications.some(row => row.classificationId === "unclassified_test_inventory_gap"));
  assert.equal(candidate.state, "passed");
});

test("direct and normalized composition preserve source joins through coverage", () => {
  const normalized = native(inventory, sourceSetInput(), {flags: ["--normalized-inventory"]});
  for (const input of [directComposeInput(), normalizedComposeInput(normalized)]) {
    validates(composer, "input", input);
    const output = native(composer, input);
    assert.equal(output.viewInputId, "view.one");
    assert.equal(output.testEvidenceInventory.entries[0].testId, "test.one");
    for (const carrier of ["pointer", "compact"]) assert.deepEqual(native(composer, input, {carrier}), output);
    validates(view, "input", output);
    const coverage = native(view, output, {exit: null});
    assert.equal(coverage.viewKind, "proofkit.requirement-coverage-view");
    assert.equal(coverage.requirementCoverage[0].requirementId, "REQ-ONE");
    if (input.normalizedTestEvidenceInventory) {
      assert.deepEqual(output.normalizedTestEvidenceInventory.sources, normalized.sources);
      assert.deepEqual(output.normalizedTestEvidenceInventory.inventory, output.testEvidenceInventory);
    } else assert.equal(output.normalizedTestEvidenceInventory, undefined);
  }
});

test("presence-based composer and non-null coverage modes remain distinct", () => {
  const normalized = native(inventory, inventoryInput(), {flags: ["--normalized-inventory"]});
  const cases = [
    ["direct optional nulls", directComposeInput(), input => {input.options = null; input.ownerInvariantRegistry = null; input.localEnvironmentPolicy = null;}, true],
    ["wrapped direct", directComposeInput(), input => {input.testEvidenceInventory = wrappedInventory(input.testEvidenceInventory);}, true],
    ["null opposite binding", directComposeInput(), input => {input.compactProofContract = null;}, false],
    ["null opposite inventory", directComposeInput(), input => {input.normalizedTestEvidenceInventory = null;}, false],
    ["normalized null direct", normalizedComposeInput(normalized), input => {input.testEvidenceInventory = null;}, false],
    ["normalized null binding", normalizedComposeInput(normalized), input => {input.requirementProofBinding = null;}, false],
    ["normalized missing policy", normalizedComposeInput(normalized), input => {delete input.localEnvironmentPolicy;}, false],
    ["normalized null policy", normalizedComposeInput(normalized), input => {input.localEnvironmentPolicy = null;}, false],
    ["normalized wrapped inventory", normalizedComposeInput(normalized), input => {input.normalizedTestEvidenceInventory.inventory = wrappedInventory(input.normalizedTestEvidenceInventory.inventory);}, true],
    ["normalized null projection markers", normalizedComposeInput(normalized), input => {input.normalizedTestEvidenceInventory.projectionKind = null; input.normalizedTestEvidenceInventory.projectionSummary = null;}, true],
  ];
  for (const [label, original, mutate, valid] of cases) {
    const input = structuredClone(original); mutate(input);
    validates(composer, "input", input, valid, label);
    const output = native(composer, input, {exit: valid ? 0 : 1, report: valid});
    if (valid) { validates(view, "input", output); native(view, output, {exit: null}); }
  }
});

test("source header whitespace and nested field boundaries match native admission", () => {
  const spaced = sourceSetInput(); spaced.sourceColumns[0] = "\u0085 source_id\u2000";
  validates(inventory, "input", spaced); native(inventory, spaced);
  for (const [original, flags, mutate] of [
    [sourceSetInput(), [], input => {input.sourceColumns[0] = "foreign";}],
    [sourceSetInput(), [], input => {input.sources[0][2] = "not-a-digest";}],
    [sourceSetInput(), [], input => {input.sources[0].pop();}],
    [sourceSetInput(), [], input => {input.sourceTexts[0].unknown = true;}],
    [wrappedInventory(), [], input => {input.schemaVersion = 1;}],
    [wrappedInventory(), [], input => {input.inventory = wrappedInventory(input.inventory);}],
    [discoveryInput(), ["--projection", "discovery-draft"], input => {delete input.discoveredTests[0].title;}],
    [discoveryInput(), ["--projection", "discovery-draft"], input => {input.runner.runnerKind = "unsupported";}],
    [discoveryInput(), ["--projection", "discovery-draft"], input => {input.discoveredTests[0].oracleSignals = ["unsupported"];}],
    [inventoryInput(), [], input => {input.entries[0].oracle.expectedPublicOutcome = null;}],
  ]) {
    const input = structuredClone(original); mutate(input);
    validates(inventory, "input", input, false); native(inventory, input, {flags, exit: 1, report: false});
  }
});

test("normalized identifier extension is bounded and preserves the full command chain", () => {
  for (const length of [245, 246, 256]) {
    const input = inventoryInput(); input.inventoryId = "a".repeat(length);
    const normalized = native(inventory, input, {flags: ["--normalized-inventory"]});
    assert.equal(normalized.normalizedInventoryId, `${input.inventoryId}.normalized`);
    const compose = normalizedComposeInput(normalized);
    validates(composer, "input", compose);
    const output = native(composer, compose, {compare: length === 245});
    assert.equal(output.normalizedTestEvidenceInventory.normalizedInventoryId, normalized.normalizedInventoryId);
    validates(view, "input", output); native(view, output, {exit: null, compare: length === 245});
  }
  const normalized = native(inventory, inventoryInput(), {flags: ["--normalized-inventory"]});
  normalized.normalizedInventoryId = "a".repeat(257);
  const input = normalizedComposeInput(normalized);
  validates(composer, "input", input, false);
  native(composer, input, {exit: 1, report: false});
});
