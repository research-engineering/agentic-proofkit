import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {after, before} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const definitionId = "proofkit.compact-proof-contract.input.v2.json-schema";
const definition = contract.contractDefinitions.find(value => value.definitionId === definitionId);
assert.ok(definition, "compact structural definition is published");
const schema = definition.fieldTree.variants[0].schema;
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const validate = ajv.compile(schema);
const priorValidate = process.env.PROOFKIT_COMPACT_SCHEMA_BASELINE
  ? new Ajv2020({strict: false, validateFormats: false}).compile(JSON.parse(readFileSync(process.env.PROOFKIT_COMPACT_SCHEMA_BASELINE, "utf8")))
  : null;
// Historical wire bytes are independent of the current schema generator.
const observations = JSON.parse(readFileSync(new URL("internal/app/testdata/compact-v2-wire-observations.json", root), "utf8"));
const baseline = observations.observations.find(value => value.surface === "compact-contract" && value.direction === "input").document;
let directory;
let binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-compact-structure-"));
  binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120_000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });

function native(input, accepted, label) {
  const result = spawnSync(binary, ["requirement-proof-resolver", "--input", "-", "--local-environment-class", "local-go"], {
    input: typeof input === "string" ? input : JSON.stringify(input),
    encoding: "utf8", timeout: 10_000, maxBuffer: 2 << 20,
  });
  assert.equal(result.error, undefined, label);
  assert.equal(result.signal, null, label);
  assert.equal(result.status, accepted ? 0 : 1, `${label}: ${result.stderr}`);
  if (accepted) {
    assert.equal(result.stderr, "", label);
    assert.equal(JSON.parse(result.stdout).contractId, baseline.contract_id, label);
  } else {
    assert.equal(result.stdout, "", label);
    assert.notEqual(result.stderr, "", label);
    assert.match(result.stderr, /^compact requirement proof /, `${label}: wrong refusal boundary`);
  }
}

function pair(input, accepted, label) {
  assert.equal(validate(input), accepted, `${label}: ${ajv.errorsText(validate.errors)}`);
  if (priorValidate) assert.equal(priorValidate(input), accepted, `${label}: prior structural domain differs`);
  native(input, accepted, label);
}

function moveColumn(input, header, rows, name, position) {
  const from = input[header].indexOf(name);
  assert.notEqual(from, -1);
  input[header].splice(position, 0, input[header].splice(from, 1)[0]);
  for (const row of rows) row.splice(position, 0, row.splice(from, 1)[0]);
}

test("compact schema preserves every header/name position and rejects a wrong cell at that position", () => {
  for (const [header, table, names] of [
    ["surface_columns", "surfaces", ["surface_id", "required_environment_classes", "preconditioned_environment_classes"]],
    ["binding_columns", "bindings", ["requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"]],
  ]) {
    assert.deepEqual(baseline[header], names);
    for (const name of names) for (let position = 0; position < names.length; position++) {
      const input = structuredClone(baseline);
      moveColumn(input, header, input[table], name, position);
      const label = `${header}/${name}/${position}`;
      pair(input, true, label);
      const domainCase = structuredClone(input);
      if (["requirement_id", "surface_id", "invariant_role", "owned_invariant", "blocking_status", "declared_mutation_resistance_claim_id"].includes(name)) {
        domainCase[table][0][position] = "bad value";
        pair(domainCase, false, `${label}/non-null identifier domain`);
      } else if (["required_environment_classes", "preconditioned_environment_classes"].includes(name)) {
        domainCase[table][0][position] = ["a b"];
        pair(domainCase, false, `${label}/non-null identifier-list domain`);
      }
      input[table][0][position] = null;
      pair(input, false, `${label}/null`);
    }
  }
});

test("nested witness cell follows both independent header permutations", () => {
  const names = ["selector", "environment_classes", "verify_commands", "resolution_order_index"];
  assert.deepEqual(baseline.witness_columns, names);
  for (const witness of ["positive_witness", "falsification_witness"]) {
    for (let bindingPosition = 0; bindingPosition < 11; bindingPosition++) {
      for (const name of names) for (let witnessPosition = 0; witnessPosition < 4; witnessPosition++) {
        const input = structuredClone(baseline);
        moveColumn(input, "binding_columns", input.bindings, witness, bindingPosition);
        const rows = input.bindings.flatMap(row => [row[input.binding_columns.indexOf("positive_witness")], row[input.binding_columns.indexOf("falsification_witness")]]);
        moveColumn(input, "witness_columns", rows, name, witnessPosition);
        pair(input, true, `${witness}/${bindingPosition}/${name}/${witnessPosition}`);
        if (name === "environment_classes" || name === "resolution_order_index") {
          const domainCase = structuredClone(input);
          domainCase.bindings[0][bindingPosition][witnessPosition] = name === "environment_classes" ? ["a b"] : 0.5;
          pair(domainCase, false, `${witness}/${bindingPosition}/${name}/${witnessPosition}/non-null domain`);
        }
        input.bindings[0][bindingPosition][witnessPosition] = null;
        pair(input, false, `${witness}/${bindingPosition}/${name}/${witnessPosition}/null`);
      }
    }
  }
});

test("root, row width, column identity and normalization boundaries", () => {
  pair(structuredClone(baseline), true, "baseline");
  for (const field of Object.keys(baseline)) for (const mode of ["missing", "null"]) {
    const input = structuredClone(baseline);
    if (mode === "missing") delete input[field]; else input[field] = null;
    pair(input, false, `${field}/${mode}`);
  }
  const unknown = structuredClone(baseline);
  unknown.extra = true;
  pair(unknown, false, "unknown root member");
  for (const field of ["schema_version", "authority_state", "contract_kind", "normalization_profile"]) {
    const input = structuredClone(baseline);
    input[field] = field === "schema_version" ? 3 : "foreign";
    pair(input, false, `${field}/foreign literal`);
  }
  for (const header of ["surface_columns", "binding_columns", "witness_columns"]) {
    for (const mode of ["unknown", "duplicate", "short", "long"]) {
      const input = structuredClone(baseline);
      if (mode === "unknown") input[header][0] = "unknown_column";
      if (mode === "duplicate") input[header][0] = ` ${input[header][1]} `;
      if (mode === "short") input[header].pop();
      if (mode === "long") input[header].push("extra");
      pair(input, false, `${header}/${mode}`);
    }
  }
  for (const table of ["surfaces", "bindings", "positive_witness", "falsification_witness"]) for (const mode of ["short", "long"]) {
    const input = structuredClone(baseline);
    const row = input[table]?.[0] ?? input.bindings[0][input.binding_columns.indexOf(table)];
    if (mode === "short") row.pop(); else row.push("extra");
    pair(input, false, `${table}/${mode}`);
  }
  for (const pad of [" \t\r\n", "\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"]) {
    const input = structuredClone(baseline);
    for (const field of ["surface_columns", "binding_columns", "witness_columns"]) input[field] = input[field].map(name => pad + name + pad);
    for (const field of ["authority_state", "contract_kind", "normalization_profile", "contract_id"]) input[field] = pad + input[field] + pad;
    input.surfaces[0][1] = [pad + "local-go" + pad];
    pair(input, true, "trimmed columns, literals, text and array identifier");
  }
  for (const value of [-1, 0.5, 9007199254740992, "1"]) {
    const input = structuredClone(baseline);
    input.bindings[0][7][3] = value;
    pair(input, false, `order/${value}`);
  }
  for (const value of [" ", "a".repeat(257), " id ", "id\n"]) {
    const input = structuredClone(baseline);
    input.bindings[0][0] = value;
    pair(input, false, "invalid scalar identifier");
  }
  for (const value of [" ", "a".repeat(257), "a b", 1]) {
    const input = structuredClone(baseline);
    input.surfaces[0][1] = [value];
    pair(input, false, "invalid normalized identifier");
  }
  for (const list of ["non_claims", "environment", "commands"]) {
    const input = structuredClone(baseline);
    if (list === "non_claims") input.non_claims = ["claim", "claim"];
    if (list === "environment") input.surfaces[0][1] = ["local-go", "local-go"];
    if (list === "commands") input.bindings[0][9] = ["go test ./...", "go test ./..."];
    pair(input, false, `${list}/identical duplicate`);
  }
  for (const field of ["contract_id", "non_claims"]) {
    const input = structuredClone(baseline);
    input[field] = field === "contract_id" ? "\u0085 \t" : ["\u0085 \t"];
    pair(input, false, `${field}/empty after trimming`);
  }
  const empty = structuredClone(baseline);
  empty.surfaces = []; empty.bindings = []; empty.non_claims = [];
  pair(empty, true, "empty collections");
});

test("native-only lexical, normalized-duplicate and relational rules remain explicit", () => {
  const lexical = JSON.stringify(baseline).replace('"schema_version":2', '"schema_version":2.0');
  assert.equal(validate(JSON.parse(lexical)), true);
  native(lexical, false, "noncanonical integer lexeme");
  const duplicate = structuredClone(baseline);
  duplicate.non_claims = ["claim", " claim "];
  assert.equal(validate(duplicate), true);
  native(duplicate, false, "normalized duplicate");
  const missingSurface = structuredClone(baseline);
  missingSurface.surfaces = [];
  assert.equal(validate(missingSurface), true);
  native(missingSurface, false, "dangling surface");
});

test("one identified resource composes through multiple references, not duplicate inline IDs", () => {
  const composed = new Ajv2020({strict: false, validateFormats: false}).compile({
    $defs: {compact: schema}, type: "object", required: ["before", "after"],
    properties: {before: {$ref: schema.$id}, after: {$ref: schema.$id}},
  });
  assert.equal(composed({before: baseline, after: baseline}), true);
  assert.equal(composed({before: baseline, after: {}}), false);
  assert.throws(() => new Ajv2020({strict: false}).compile({properties: {before: schema, after: schema}}), /resolves to more than one schema/);
});
