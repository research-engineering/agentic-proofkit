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
    for (const invalid of [false, [false]]) reject(value => {at(value, path).nonClaims = invalid;}, `${path} nonClaims container/item`);
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
  for (const key of ["candidateRequirementRefs", "ownerInvariantRefs"]) reject(value => {value.discoveredTests[0][key] = [false];}, `discovery/${key} item`);
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
      if (command === composer && direction === "input") {
        reject(value => {value.selectedOwnerIds = [];}, "selected owner minimum");
        reject(value => {value.selectedOwnerIds = [false];}, "selected owner item");
      }
      for (const key of ["options", "ownerInvariantRegistry", ...(!compact ? ["localEnvironmentPolicy"] : [])]) {
        const positive = structuredClone(baseline); positive[key] = null;
        validates(command, direction, positive);
        if (direction === "input") native(command, positive, {exit: command === view ? null : 0});
      }
    }
  }
});

test("proof-derived input parents expose every required and optional clause", () => {
  const input = proofInventoryInput(), flags = ["--projection", "proof-binding-derived"];
  validates(inventory, "input", input); native(inventory, input, {flags});
  const reject = rejectionCheck(inventory, "input", input, flags);
  for (const [path, keys] of [[[], ["schemaVersion", "inventoryId", "commandRefPolicy", "requirementSource", "compactProofContract"]], [["commandRefPolicy"], ["prefix"]]]) {
    reject(value => {at(value, path).foreign = true;}, `proof/${path} extra field`);
    for (const key of keys) {
      reject(value => {delete at(value, path)[key];}, `proof/${path}/${key} missing`);
      for (const invalid of [null, false]) reject(value => {at(value, path)[key] = invalid;}, `proof/${path}/${key} invalid`);
    }
  }
  reject(value => {value.schemaVersion = 2;}, "proof version");
  for (const nonClaims of [null, [], ["Synthetic declaration."]]) {
    const value = {...input, nonClaims}; validates(inventory, "input", value); native(inventory, value, {flags});
  }
  for (const nonClaims of [false, [false]]) reject(value => {value.nonClaims = nonClaims;}, "proof nonClaims type");
});

test("direct inventory input clauses distinguish optional data from required records", () => {
  const input = annotatedInventoryInput();
  const verify = (value, valid, label) => {
    for (const wire of [value, wrappedInventory(value)]) {
      validates(inventory, "input", wire, valid, label);
      native(inventory, wire, {exit: valid ? null : 1, report: valid});
    }
  };
  const reject = (mutate, label) => {const value = structuredClone(input); mutate(value); verify(value, false, label);};
  const rowPath = ["entries", 0];
  const records = [
    [[], ["schemaVersion", "authority", "inventoryId", "entries", "nonClaims"]],
    [rowPath, ["testId", "ownerId", "sourcePath", "selector", "evidenceClass", "requirementRefs", "ownerInvariantRefs", "commandRefs", "witnessRefs", "nonClaims"]],
    [[...rowPath, "falsifier"], ["falsifierId", "negativeCaseId", "wrongImplementationClassId", "dominanceGroup", "supersedes"]],
    [[...rowPath, "oracle"], ["oracleId", "oracleKind", "assertionSummary", "expectedPublicOutcome"]],
    [[...rowPath, "qualityFindings", 0], ["findingId", "class", "severity", "ownerReviewState", "evidenceRefs", "nonClaims"]],
  ];
  for (const [path, keys] of records) {
    reject(value => {at(value, path).foreign = true;}, `direct/${path} extra field`);
    for (const key of keys) {
      reject(value => {delete at(value, path)[key];}, `direct/${path}/${key} missing`);
      for (const invalid of [null, false]) reject(value => {at(value, path)[key] = invalid;}, `direct/${path}/${key} invalid`);
    }
  }
  for (const path of [["ownerId"], ["sourceId"], [...rowPath, "falsifier"], [...rowPath, "oracle"], [...rowPath, "qualityFindings"], [...rowPath, "falsifier", "supersessionDeclarationRef"]]) {
    for (const absent of [false, true]) {
      const value = structuredClone(input), record = at(value, path.slice(0, -1));
      if (absent) delete record[path.at(-1)]; else record[path.at(-1)] = null;
      verify(value, true, `direct/${path} optional absence/null`);
    }
    reject(value => {at(value, path.slice(0, -1))[path.at(-1)] = false;}, `direct/${path} optional type`);
  }
  const arrays = [["entries"], ["nonClaims"], ...["requirementRefs", "ownerInvariantRefs", "commandRefs", "witnessRefs", "nonClaims", "qualityFindings"].map(key => [...rowPath, key]),
    [...rowPath, "falsifier", "supersedes"], [...rowPath, "qualityFindings", 0, "evidenceRefs"], [...rowPath, "qualityFindings", 0, "nonClaims"]];
  for (const path of arrays) {
    reject(value => {at(value, path.slice(0, -1))[path.at(-1)] = [false];}, `direct/${path} item`);
    const minimum = path.length === 1 && path[0] === "nonClaims" || path.includes("qualityFindings") && path.length > 3;
    const empty = structuredClone(input); at(empty, path.slice(0, -1))[path.at(-1)] = [];
    verify(empty, !minimum, `direct/${path} minimum`);
  }
  for (const [path, values] of [
    [[...rowPath, "evidenceClass"], ["benchmark", "declared_contract_admission_route", "declared_property_or_fuzz_route", "declared_semantic_falsifier_route", "governance_or_release", "helper_or_testkit", "proof_route_candidate", "routing_smoke_nonclaim"]],
    [[...rowPath, "qualityFindings", 0, "class"], ["duplicate_falsifier_candidate", "empty_oracle", "fixture_leak_risk", "flaky_time", "implementation_mirror", "import_cost_leak", "missing_edge", "mock_tests_mock", "over_broad_integration", "snapshot_without_oracle", "tautology", "unasserted_diagnostic", "wrong_boundary"]],
    [[...rowPath, "qualityFindings", 0, "severity"], ["failure", "warning"]],
    [[...rowPath, "qualityFindings", 0, "ownerReviewState"], ["candidate", "confirmed"]],
  ]) {
    for (const item of values) {
      const value = structuredClone(input); at(value, path.slice(0, -1))[path.at(-1)] = item;
      verify(value, true, `direct/${path} admitted enum`);
    }
    reject(value => {at(value, path.slice(0, -1))[path.at(-1)] = "foreign";}, `direct/${path} enum`);
  }
  reject(value => {value.schemaVersion = 2;}, "direct version");
  reject(value => {value.authority = "foreign";}, "direct authority");
});

test("normalized receiving records preserve independent parent field constraints", () => {
  for (const [seed, flags] of [[inventoryInput(), []], [sourceSetInput(), []], [proofInventoryInput(), ["--projection", "proof-binding-derived"]]]) {
    const envelope = native(inventory, seed, {flags: [...flags, "--normalized-inventory"]});
    assert.equal(envelope.sourceAuthority, seed.authority === "caller_owned_inventory_source_set" ? "caller_owned_inventory_source_set" : "caller_owned_inventory");
    validates(inventory, "output", {...envelope, sourceAuthority: "foreign"}, false, "normalized/sourceAuthority output enum");
    const input = normalizedComposeInput(envelope), output = native(composer, input, {compare: !envelope.projectionKind});
    const invalidOutput = structuredClone(output); invalidOutput.normalizedTestEvidenceInventory.sourceAuthority = "foreign";
    validates(composer, "output", invalidOutput, false, "normalized/sourceAuthority output enum");
    for (const [command, direction, baseline] of [[inventory, "output", envelope], [composer, "output", output], [composer, "input", input], [view, "input", output]]) {
      const reject = rejectionCheck(command, direction, baseline), rootPath = command === inventory ? [] : ["normalizedTestEvidenceInventory"];
      const normalized = value => at(value, rootPath);
      const records = [[rootPath, ["schemaVersion", "normalizedKind", "normalizedInventoryId", "sourceAuthority", "sourceCount", "sourceColumns", "sources", "entrySources", "inputPaths", "inventory", "nonClaims"]]];
      if (envelope.entrySources.length) records.push([[...rootPath, "entrySources", 0], ["path", "sourceId", "testId"]]);
      if (envelope.projectionSummary) {
        records.push([[...rootPath, "projectionSummary"], ["schemaVersion", "entryCount", "commandRefCount", "routeEntryMappings"]]);
        records.push([[...rootPath, "projectionSummary", "routeEntryMappings", 0], ["bindingRecordId", "requirementId", "resolutionOrderIndex", "role", "scenarioId", "selector", "surfaceId", "testId", "witnessRouteId"]]);
      }
      for (const [path, keys] of records) {
        reject(value => {at(value, path).foreign = true;}, `normalized/${path} extra field`);
        for (const key of keys) {
          reject(value => {delete at(value, path)[key];}, `normalized/${path}/${key} missing`);
          for (const invalid of [null, false]) reject(value => {at(value, path)[key] = invalid;}, `normalized/${path}/${key} invalid`);
        }
      }
      for (const key of ["sources", "entrySources", "inputPaths", "nonClaims"]) reject(value => {normalized(value)[key] = [null];}, `normalized/${key} item`);
      reject(value => {normalized(value).nonClaims = [];}, "normalized/nonClaims minimum");
      for (const [key, invalid] of [["schemaVersion", 2], ["normalizedKind", "foreign"], ["sourceAuthority", "foreign"], ["sourceCount", -1], ["sourceCount", 0.5]]) {
        reject(value => {normalized(value)[key] = invalid;}, `normalized/${key} domain`);
      }
      for (let index = 0; index < 5; index++) reject(value => {normalized(value).sourceColumns[index] = "foreign";}, `normalized/header/${index}`);
      for (const extra of [false, true]) reject(value => {
        const columns = normalized(value).sourceColumns;
        if (extra) columns.push("foreign"); else columns.pop();
      }, "normalized/header width");
      if (envelope.sources.length) {
        for (let index = 0; index < 5; index++) reject(value => {normalized(value).sources[0][index] = false;}, `normalized/source/${index}`);
        for (const extra of [false, true]) reject(value => {
          const row = normalized(value).sources[0];
          if (extra) row.push("foreign"); else row.pop();
        }, "normalized/source width");
        reject(value => {normalized(value).sources[0][3] = "foreign";}, "normalized/source role");
        reject(value => {normalized(value).sources[0][4] = [];}, "normalized/source nonClaims minimum");
      }
      if (envelope.projectionSummary) {
        for (const key of ["entryCount", "commandRefCount"]) for (const invalid of [-1, 0.5]) reject(value => {normalized(value).projectionSummary[key] = invalid;}, `normalized/summary/${key} count`);
        reject(value => {normalized(value).projectionSummary.routeEntryMappings = [null];}, "normalized/mapping item");
        reject(value => {normalized(value).projectionKind = "foreign";}, "normalized/projectionKind domain");
        reject(value => {normalized(value).projectionSummary.schemaVersion = 1;}, "normalized/summary version");
        reject(value => {normalized(value).projectionSummary.routeEntryMappings[0].role = "foreign";}, "normalized/mapping role");
      }
      for (const id of ["", "has space.normalized", "\u00e9.normalized", "a".repeat(257) + ".normalized", ...(command === inventory ? ["ordinary.id"] : [])]) {
        reject(value => {normalized(value).normalizedInventoryId = id;}, "normalized/identifier grammar and maximum");
      }
    }
  }
});

test("inventory report discriminators and discovery collection minima are structural", () => {
  for (const [seed, flags] of [[annotatedInventoryInput(), []], [discoveryInput(), ["--projection", "discovery-draft"]]]) {
    const output = native(inventory, seed, {flags}), reject = rejectionCheck(inventory, "output", output);
    for (const [key, value] of [["schemaVersion", 2], ["reportKind", "foreign"], ["state", "foreign"]]) reject(record => {record[key] = value;}, `report/${key} domain`);
    for (let index = 0; index < output.diagnostics.length; index++) reject(record => {record.diagnostics[index].key = "foreign";}, "diagnostic key identity");
    for (let index = 0; index < output.ruleResults.length; index++) {
      for (const key of ["ruleId", "status"]) reject(record => {record.ruleResults[index][key] = "foreign";}, `rule/${key} identity`);
      reject(record => {record.ruleResults[index].diagnostics = ["foreign"];}, "rule diagnostic cardinality");
      if (!flags.length) reject(record => {record.ruleResults[index].message = "foreign";}, "rule/message literal");
    }
    const diagnostic = (record, key) => record.diagnostics.find(row => row.key === key).value;
    if (flags.length) {
      for (const key of ["agentActionPlan", "warnings"]) reject(record => {record.diagnostics.find(row => row.key === key).value = [];}, `discovery/${key} minimum`);
      for (const key of ["entries", "nonClaims"]) reject(record => {diagnostic(record, "candidateInventory")[key] = [];}, `discovery/candidate/${key} minimum`);
      for (const key of ["authority", "candidateKind"]) reject(record => {diagnostic(record, "candidateInventory")[key] = "foreign";}, `discovery/candidate/${key} identity`);
      reject(record => {record.summary.runnerKind = "foreign";}, "discovery runner enum");
      reject(record => {diagnostic(record, "agentActionPlan")[0].severity = "foreign";}, "discovery severity");
    } else {
      for (const key of ["classificationId", "decisionOwner", "nonClaim", "severity"]) reject(record => {diagnostic(record, "agentActionPlan")[0][key] = "foreign";}, `report/action/${key} domain`);
      for (const evidenceRefs of [[], ["one", "two"]]) reject(record => {diagnostic(record, "agentActionPlan")[0].evidenceRefs = evidenceRefs;}, "report/action evidence cardinality");
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
    check(registry => {registry.nonClaims = [false];}, "registry nonClaims item");
    check(registry => {registry.invariants[0].nonClaims = [false];}, "invariant nonClaims item");
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
  const canonicalOutput = native(composer, normalizedComposeInput(expected));
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
  for (const digest of ["", " ", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64), ` ${"a".repeat(63)}z `]) {
    const input = sourceSetInput(); input.sources[0][2] = digest;
    validates(inventory, "input", input, false); native(inventory, input, {exit: 1, report: false});
    const envelope = structuredClone(expected); envelope.sources[0][2] = digest;
    validates(inventory, "output", envelope, false, "canonical digest grammar");
    const output = structuredClone(canonicalOutput); output.normalizedTestEvidenceInventory = envelope;
    validates(composer, "output", output, false, "canonical digest grammar");
    validates(view, "input", output, false, "receiving digest grammar");
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
function containerEntries(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [[path, value], ...Object.entries(value).flatMap(([key, child]) => containerEntries(child, [...path, key]))];
}

test("new inventory output records have independent required key null type and count controls", () => {
  const failedInput = inventoryInput(); failedInput.entries[0].commandRefs = [];
  const draftInput = discoveryInput(); draftInput.discoveredTests[0].oracleSignals = [];
  const fixtures = [
    native(inventory, inventoryInput()),
    native(inventory, annotatedInventoryInput()),
    native(inventory, failedInput, {exit: 1}),
    native(inventory, draftInput, {flags: ["--projection", "discovery-draft"]}),
    native(inventory, sourceSetInput(), {flags: ["--normalized-inventory"]}),
    native(inventory, annotatedInventoryInput(), {flags: ["--normalized-inventory"]}),
    native(inventory, proofInventoryInput(), {flags: ["--projection", "proof-binding-derived", "--normalized-inventory"]}),
  ];
  for (const baseline of fixtures) {
    for (const [path, original] of containerEntries(baseline)) {
      if (Array.isArray(original)) {
        const changed = structuredClone(baseline), array = at(changed, path);
        if (array.length) array[0] = false; else array.push(false);
        validates(inventory, "output", changed, false, `${path}/array item`);
        continue;
      }
      const unknown = structuredClone(baseline); at(unknown, path).undeclared = true;
      validates(inventory, "output", unknown, false, `${path}/unknown`);
      for (const key of ["authority", "normalizedKind", "projectionKind", "candidateKind", "evidenceClass", "classificationId", "class", "ownerReviewState"]) {
        if (Object.hasOwn(original, key)) {
          const changed = structuredClone(baseline); at(changed, path)[key] = "foreign";
          validates(inventory, "output", changed, false, `${path}/${key}/domain`);
        }
      }
      if (Object.hasOwn(original, "classificationId") || Object.hasOwn(original, "ownerReviewState")) {
        const changed = structuredClone(baseline); at(changed, path).severity = "foreign";
        validates(inventory, "output", changed, false, `${path}/severity/domain`);
      }
      if (Object.hasOwn(original, "schemaVersion")) {
        const changed = structuredClone(baseline); at(changed, path).schemaVersion++;
        validates(inventory, "output", changed, false, `${path}/schemaVersion/domain`);
      }
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

test("source-set records and wrappers have independent structural clause witnesses", () => {
  for (const wrapped of [false, true]) {
    const original = wrapped ? wrappedInventory(sourceSetInput()) : sourceSetInput();
    const source = value => wrapped ? value.inventory : value;
    const reject = rejectionCheck(inventory, "input", original);
    const label = wrapped ? "wrapped source-set" : "bare source-set";
    validates(inventory, "input", original); native(inventory, original);
    for (const key of ["schemaVersion", "authority", "inventoryId", "nonClaims", "sourceColumns", "sources", "sourceTexts"]) {
      reject(value => {delete source(value)[key];}, `${label}/${key} missing`);
      for (const invalid of [null, false]) reject(value => {source(value)[key] = invalid;}, `${label}/${key} invalid`);
    }
    reject(value => {source(value).foreign = true;}, `${label} extra field`);
    reject(value => {source(value).schemaVersion = 2;}, `${label} version`);
    reject(value => {source(value).authority = "foreign";}, `${label} authority`);
    for (const key of ["nonClaims", "sources", "sourceTexts"]) {
      reject(value => {source(value)[key] = [];}, `${label}/${key} minimum`);
      reject(value => {source(value)[key] = [null];}, `${label}/${key} item`);
    }
    for (const key of ["sourceColumns", "sources"]) for (const extra of [false, true]) {
      reject(value => {
        const tuple = key === "sources" ? source(value).sources[0] : source(value).sourceColumns;
        if (extra) tuple.push("foreign"); else tuple.pop();
      }, `${label}/${key} tuple width`);
    }
    for (let index = 0; index < 5; index++) {
      for (const invalid of [null, false, "foreign"]) {
        reject(value => {source(value).sourceColumns[index] = invalid;}, `${label}/header/${index}`);
      }
      for (const invalid of [null, false]) {
        reject(value => {source(value).sources[0][index] = invalid;}, `${label}/row/${index}`);
      }
    }
    for (const digest of ["a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64)]) {
      reject(value => {source(value).sources[0][2] = digest;}, `${label} digest grammar`);
    }
    reject(value => {source(value).sources[0][3] = "foreign";}, `${label} role enum`);
    reject(value => {source(value).sources[0][4] = [];}, `${label} row nonClaims minimum`);
    reject(value => {source(value).sources[0][4] = [false];}, `${label} row nonClaims item`);
    for (const key of ["path", "text"]) {
      reject(value => {delete source(value).sourceTexts[0][key];}, `${label}/text/${key} missing`);
      for (const invalid of [null, false]) reject(value => {source(value).sourceTexts[0][key] = invalid;}, `${label}/text/${key} invalid`);
    }
    reject(value => {source(value).sourceTexts[0].foreign = true;}, `${label} source text extra field`);
    const spaced = structuredClone(original);
    source(spaced).sourceColumns = source(spaced).sourceColumns.map(value => `\u0085 ${value}\u2000`);
    source(spaced).sources[0][2] = `\u0085 ${source(spaced).sources[0][2]}\u2000`;
    validates(inventory, "input", spaced); native(inventory, spaced);
    if (wrapped) {
      for (const key of ["schema", "inventory"]) {
        reject(value => {delete value[key];}, `wrapper/${key} missing`);
        for (const invalid of [null, false]) reject(value => {value[key] = invalid;}, `wrapper/${key} invalid`);
      }
      reject(value => {value.schema = "foreign";}, "wrapper identity");
      reject(value => {value.foreign = true;}, "wrapper extra field");
      reject(value => {value.inventory = wrappedInventory(value.inventory);}, "nested wrapper");
    }
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
