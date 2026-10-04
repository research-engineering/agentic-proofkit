import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {directComposeInput, discoveryInput, inventoryInput, normalizedComposeInput, proofInventoryInput, sourceSetInput, wrappedInventory} from "./inventory-coverage-fixtures.mjs";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(new URL("proofkit/cli-contract.v2.json", root), "utf8"));
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

function native(command, input, {flags = [], exit = 0, report = true, carrier = "stdin", compare = true} = {}) {
  let args = [command, "--input", "-", ...flags], bytes = JSON.stringify(input);
  if (carrier === "pointer") {
    const path = join(directory, "input.json");
    writeFileSync(path, JSON.stringify({payload: input}));
    args = [command, "--input", path, "--input-pointer", "/payload", ...flags]; bytes = "";
  } else if (carrier === "compact") args.unshift("--json-layout", "compact");
  const invoke = path => spawnSync(path, args, {input: bytes, encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
  const result = invoke(binary);
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
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
