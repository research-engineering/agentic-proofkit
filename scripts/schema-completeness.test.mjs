import assert from "node:assert/strict";
import {execFileSync, spawn} from "node:child_process";
import {createHash} from "node:crypto";
import {existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {isDeepStrictEqual} from "node:util";
import test, {after, before} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {expandSharedDefinitions, forEachSubschema, resolveLocalReference} from "./schema-definitions.mjs";

// SCHEMA-01 completeness oracle. The manifest is authored from the native
// admission and producer sources and is never regenerated from the contract.
// This oracle proves that the manifest is a bijection with the published
// directions, definitions and variants; recomputes the constraint classes
// each published schema expresses; checks every native-owned disposition and
// owner witness against the Go sources and the committed native residue
// rows; refuses class-targeted mutants of recorded native observations at
// every evaluated schema location; and replays the committed residue and
// uniqueItems agreement rows against the CLI. It imports neither the contract
// generator nor native code. Route reachability and mutation witnesses are
// proven by the internal/app/schemacompleteness Go tests. The native-owned
// records these checks verify are a lower bound, an input "absent" is
// relative to the class indicators, and the schemas never become semantic
// authority; the manifest nonClaims state the limits.
const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_SCHEMA_COMPLETENESS_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const manifestPath = "internal/app/testdata/schema-completeness-manifest.v1.json";
const observationsPath = "internal/app/testdata/schema-completeness-native-observations.json";
const residuePath = "internal/app/testdata/schema-completeness-native-residue.json";
const mutantCorpusPath = "internal/app/testdata/schema-completeness-mutant-corpus.json";
const manifest = JSON.parse(read(manifestPath));
const observations = JSON.parse(read(observationsPath));
const residue = JSON.parse(read(residuePath));
const mutantCorpus = JSON.parse(read(mutantCorpusPath));
const repoRootToken = "{repoRoot}";
// An argv token is the repoRoot directory itself or {repoRoot}/<name>.
const namesRepoRoot = (token) => token === repoRootToken || token.startsWith(`${repoRootToken}/`);

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const directionKey = (route, direction) => `${route}|${direction}`;
const expressedClasses = ["cardinality", "bound", "default", "duplicate", "enum", "unknownField", "crossField"];
const nativeOwnedClasses = [...expressedClasses, "referenceClosure", "numericCanonical", "secretTimestamp", "semantic"];
const semanticWitnessLiteral = /\bmust\b|invalid|cannot|failed|unsupported|reject|refus|requires|not admitted|mismatch/i;

// Independent restatement of the keywords that make a schema express each
// structural constraint class; crossField is decided by memberRelation.
const expressedKeywords = {
  cardinality: ["contains", "maxContains", "maxItems", "maxProperties", "minContains", "minItems", "minProperties"],
  bound: ["exclusiveMaximum", "exclusiveMinimum", "maxLength", "maximum", "minLength", "minimum", "multipleOf", "pattern"],
  default: ["default"],
  enum: ["const", "enum"],
};

const memberNames = (schema) => (isObject(schema)
  ? new Set([...Object.keys(schema.properties ?? {}), ...(schema.required ?? []), ...Object.keys(schema.dependentRequired ?? {})])
  : new Set());

// A node relates two or more members of one object: dependentRequired or
// dependentSchemas; if with then or else naming two or more members; oneOf/anyOf
// with two or more object alternatives that together name two or more
// members; or a not whose subschema names two or more members (an excluded
// combination). A single-location not (an excluded value set) relates none.
function memberRelation(node) {
  if (Object.hasOwn(node, "dependentRequired") || Object.hasOwn(node, "dependentSchemas")) return true;
  if (memberNames(node.not).size >= 2) return true;
  if (Object.hasOwn(node, "if") && (Object.hasOwn(node, "then") || Object.hasOwn(node, "else"))) {
    const names = new Set([...memberNames(node.if), ...memberNames(node.then), ...memberNames(node.else)]);
    if (names.size >= 2) return true;
  }
  for (const keyword of ["oneOf", "anyOf"]) {
    if (!Array.isArray(node[keyword])) continue;
    const alternatives = node[keyword].filter((member) => memberNames(member).size > 0);
    const names = new Set(alternatives.flatMap((member) => [...memberNames(member)]));
    if (alternatives.length >= 2 && names.size >= 2) return true;
  }
  return false;
}

function publishedDirections(source) {
  const definitions = new Map(source.contractDefinitions.map((definition) => [definition.definitionId, definition]));
  const rows = new Map();
  for (const command of source.commands) {
    const route = (command.route ?? [command.command]).join(" ");
    for (const direction of ["input", "output"]) {
      const record = command[`${direction}Contract`];
      if (!record) continue;
      const definition = definitions.get(record.rootDefinitionRef);
      assert.ok(definition, `${route} ${direction} binds a published definition`);
      rows.set(directionKey(route, direction), {route, direction, definition, command: command.command});
    }
  }
  return {rows, definitions};
}

// Returns every disagreement between the manifest enumeration and the contract.
function enumerationErrors(source, authored) {
  const errors = [];
  const {rows, definitions} = publishedDirections(source);
  const seen = new Set();
  for (const entry of authored.directions) {
    const key = directionKey(entry.route, entry.direction);
    if (seen.has(key)) errors.push(`duplicate manifest direction ${key}`);
    seen.add(key);
    const published = rows.get(key);
    if (!published) {
      errors.push(`manifest direction is not published: ${key}`);
      continue;
    }
    if (entry.definitionId !== published.definition.definitionId) {
      errors.push(`definition renamed for ${key}: manifest ${entry.definitionId}, contract ${published.definition.definitionId}`);
    }
    const variants = published.definition.fieldTree.variants.map((variant) => variant.variantId);
    if (JSON.stringify(entry.variantIds) !== JSON.stringify(variants)) {
      errors.push(`variants differ for ${key}: manifest ${entry.variantIds.join(",")}, contract ${variants.join(",")}`);
    }
  }
  for (const key of rows.keys()) if (!seen.has(key)) errors.push(`published direction is missing from the manifest: ${key}`);
  const authoredDefinitions = new Set(authored.directions.map((entry) => entry.definitionId));
  for (const id of definitions.keys()) if (!authoredDefinitions.has(id)) errors.push(`published definition is missing from the manifest: ${id}`);
  return errors;
}

function schemaFacts(schema) {
  const classes = new Set();
  let numeric = false, arrays = false, optional = false;
  const visit = (node) => {
    if (!isObject(node)) return;
    for (const [name, keywords] of Object.entries(expressedKeywords)) {
      if (keywords.some((keyword) => Object.hasOwn(node, keyword))) classes.add(name);
    }
    if (node.uniqueItems === true) classes.add("duplicate");
    if (node.additionalProperties === false || node.unevaluatedProperties === false) classes.add("unknownField");
    if (memberRelation(node)) classes.add("crossField");
    const types = [].concat(node.type ?? []);
    if (types.includes("integer") || types.includes("number") || Object.hasOwn(node, "x-proofkit-number-encoding")) numeric = true;
    if (types.includes("array") || Object.hasOwn(node, "items") || Object.hasOwn(node, "prefixItems")) arrays = true;
    if (isObject(node.properties) && Object.keys(node.properties).some((name) => !(node.required ?? []).includes(name))) optional = true;
    forEachSubschema(node, (child) => visit(child));
  };
  visit(expandSharedDefinitions(schema));
  return {classes, numeric, arrays, optional};
}

function definitionFacts(definition) {
  const classes = new Set();
  let numeric = false, arrays = false, optional = false;
  for (const variant of definition.fieldTree.variants) {
    const facts = schemaFacts(variant.schema);
    facts.classes.forEach((name) => classes.add(name));
    numeric ||= facts.numeric;
    arrays ||= facts.arrays;
    optional ||= facts.optional;
  }
  return {classes: [...classes].sort(), numeric, arrays, optional};
}

// Returns every disagreement between the declared and the published
// structural classes, and every native-owned disposition that contradicts the
// published schema.
function expressionErrors(source, authored) {
  const errors = [];
  const {rows} = publishedDirections(source);
  for (const entry of authored.directions) {
    const key = directionKey(entry.route, entry.direction);
    const published = rows.get(key);
    if (!published) continue;
    const facts = definitionFacts(published.definition);
    const declared = [...entry.schemaExpresses].sort();
    if (declared.some((name) => !expressedClasses.includes(name))) errors.push(`${key} declares an unknown expressed class`);
    if (JSON.stringify(declared) !== JSON.stringify(facts.classes)) {
      errors.push(`${key} schema expresses ${facts.classes.join(",") || "nothing"}, manifest declares ${declared.join(",") || "nothing"}`);
    }
    const owned = entry.nativeOwned;
    if ((owned.numericCanonical !== "absent") !== facts.numeric) errors.push(`${key} numericCanonical disposition contradicts the published numeric fields`);
    if (owned.semantic === "absent") errors.push(`${key} has no native semantic owner`);
    if (entry.direction === "output") {
      if ((owned.duplicate !== "absent") !== facts.arrays) errors.push(`${key} duplicate disposition contradicts the published arrays`);
      for (const name of nativeOwnedClasses) {
        if (owned[name] === "absent" && name !== "duplicate" && name !== "numericCanonical") errors.push(`${key} declares output ${name} absent although the producer owns it`);
      }
    } else if (owned.default === "absent" && facts.optional) {
      errors.push(`${key} declares default absent although the published input has optional members`);
    }
  }
  return errors;
}

// Top-level Go declarations are gofmt-formatted: a declaration starts at
// column zero and its body ends at the next column-zero closing brace. The
// body excludes the signature line, so a type or parameter name in the
// signature is not evidence.
function goFunctionBody(text, name) {
  const [receiver, method] = name.includes(".") ? name.split(".") : [null, name];
  const head = receiver === null
    ? new RegExp(`^func ${method}(?:\\[[^\\]]*\\])?\\(`, "m")
    : new RegExp(`^func \\([A-Za-z_][A-Za-z0-9_]* \\*?${receiver}(?:\\[[^\\]]*\\])?\\) ${method}\\(`, "m");
  const match = head.exec(text);
  if (!match) return null;
  const end = text.indexOf("\n}\n", match.index);
  if (end < 0) return null;
  const signatureEnd = text.indexOf("{\n", match.index);
  return signatureEnd < 0 || signatureEnd > end ? null : text.slice(signatureEnd + 2, end + 2);
}

// Decoded Go string literals ("..." and `...`) of a source fragment.
function goStringLiterals(text) {
  const literals = [];
  const pattern = /"((?:[^"\\\n]|\\.)*)"|`([^`]*)`/g;
  for (const match of text.matchAll(pattern)) {
    if (match[2] !== undefined) literals.push(match[2]);
    else {
      try {
        literals.push(JSON.parse(`"${match[1].replace(/\\x([0-9a-fA-F]{2})/g, "\\u00$1").replace(/\\'/g, "'")}"`));
      } catch {
        literals.push(match[1]);
      }
    }
  }
  return literals;
}

// The verb-free segments of the string literals of a function body; a
// literal "%s must be sorted and unique" yields "must be sorted and unique".
function literalSegments(body) {
  return goStringLiterals(body).flatMap((literal) => literal.split(/%[-+# 0-9.*]*[a-zA-Z%]/)).map((part) => part.trim()).filter((part) => part.length >= 10);
}

function splitLocation(location) {
  const [path, name, extra] = String(location).split("#");
  return extra === undefined && path && name ? {path, name} : null;
}
const directoryOf = (path) => path.slice(0, path.lastIndexOf("/"));

function classLiteral(authored, name) {
  if (name === "semantic") return semanticWitnessLiteral;
  const source = authored.classIndicators.classes[name].literal;
  return new RegExp(source.replace(/^\(\?i\)/, ""), source.startsWith("(?i)") ? "i" : "");
}

// Returns every owner record, witness and disposition that does not resolve.
function ownerErrors(authored, rowsOfResidue, readSource = (path) => (existsSync(new URL(path, root)) ? read(path) : null)) {
  const errors = [];
  const cache = new Map();
  const source = (path) => {
    if (!cache.has(path)) cache.set(path, readSource(path));
    return cache.get(path);
  };
  const used = new Map();
  for (const entry of authored.directions) {
    const key = directionKey(entry.route, entry.direction);
    const declared = Object.keys(entry.nativeOwned).sort();
    if (JSON.stringify(declared) !== JSON.stringify([...nativeOwnedClasses].sort())) {
      errors.push(`${key} must dispose of exactly the native-owned classes ${nativeOwnedClasses.join(",")}`);
    }
    for (const name of nativeOwnedClasses) {
      const disposition = entry.nativeOwned[name];
      if (disposition === "absent") continue;
      if (!Array.isArray(disposition) || disposition.length === 0) {
        errors.push(`${key} ${name} must be "absent" or a nonempty owner list`);
        continue;
      }
      if (new Set(disposition).size !== disposition.length) errors.push(`${key} ${name} repeats an owner`);
      for (const id of disposition) {
        if (!Object.hasOwn(authored.owners, id)) errors.push(`${key} ${name} names an undeclared owner ${id}`);
        if (!used.has(id)) used.set(id, new Set());
        used.get(id).add(name);
      }
      if (entry.direction === "output" && !disposition.some((id) => authored.owners[id]?.role === "producer")) {
        errors.push(`${key} ${name} names no producer`);
      }
    }
  }
  for (const [id, record] of Object.entries(authored.owners)) {
    if (!used.has(id)) errors.push(`owner ${id} is declared but never used`);
    const owner = splitLocation(record.owner);
    if (!owner || !owner.path.startsWith("internal/") || !owner.path.endsWith(".go") || owner.path.endsWith("_test.go")) {
      errors.push(`${id} owner must name a non-test Go source function: ${record.owner}`);
      continue;
    }
    if (!["enforcer", "producer"].includes(record.role)) errors.push(`${id} role must be enforcer or producer`);
    const ownerText = source(owner.path);
    const body = ownerText === null ? null : goFunctionBody(ownerText, owner.name);
    if (body === null) {
      errors.push(`${id} owner function does not exist: ${record.owner}`);
      continue;
    }
    const segments = literalSegments(body);
    for (const [name, witness] of Object.entries(record.witnesses ?? {})) {
      if (!used.get(id)?.has(name)) errors.push(`${id} witnesses ${name} for which no direction names it`);
      const keys = Object.keys(witness).sort().join(",");
      if (!["cli", "evidence,mutation,test", "evidence,test", "mutation,test"].includes(keys)) {
        errors.push(`${id} ${name} witness must be {test, evidence and/or mutation} or {cli}`);
        continue;
      }
      if (Object.hasOwn(witness, "evidence") || Object.hasOwn(witness, "cli")) {
        const evidence = witness.evidence ?? witness.cli;
        if (!segments.includes(evidence)) errors.push(`${id} ${name} evidence is not a complete refusal literal segment of the owner: ${evidence}`);
        if (!classLiteral(authored, name).test(evidence)) errors.push(`${id} ${name} evidence does not indicate the class: ${evidence}`);
      }
      if (Object.hasOwn(witness, "mutation")) {
        const {find, replace} = witness.mutation ?? {};
        if (typeof find !== "string" || find.length === 0 || typeof replace !== "string" || find === replace) errors.push(`${id} ${name} mutation must replace nonempty owner text`);
        else if (body.split(find).length !== 2) errors.push(`${id} ${name} mutation text must occur exactly once in the owner body`);
      }
      if (Object.hasOwn(witness, "cli")) {
        if (!rowsOfResidue.some((row) => row.owner === id && row.class === name && row.evidence === witness.cli)) errors.push(`${id} ${name} cli witness has no committed residue row`);
        continue;
      }
      const witnessLocation = splitLocation(witness.test);
      if (!witnessLocation || !witnessLocation.path.endsWith("_test.go") || !/^Test[A-Z0-9_]/.test(witnessLocation.name)) {
        errors.push(`${id} ${name} test must name a Go test function: ${witness.test}`);
        continue;
      }
      if (directoryOf(witnessLocation.path) !== directoryOf(owner.path)) errors.push(`${id} ${name} test must be in the owner package: ${witness.test}`);
      const testText = source(witnessLocation.path);
      const testBody = testText === null ? null : goFunctionBody(testText, witnessLocation.name);
      if (testBody === null || !testText.includes(`\nfunc ${witnessLocation.name}(t *testing.T) {\n`)) {
        errors.push(`${id} ${name} test does not exist: ${witness.test}`);
        continue;
      }
      if (Object.hasOwn(witness, "evidence") && !goStringLiterals(testBody).some((literal) => literal.includes(witness.evidence))) {
        errors.push(`${id} ${name} test does not assert its evidence: ${witness.evidence}`);
      }
    }
  }
  return errors;
}

// The manifest witnessSummary restates, per direction kind and class, how many
// dispositions are absent, witnessed or reachability-only.
function witnessSummary(authored) {
  const summary = {input: {}, output: {}};
  for (const direction of ["input", "output"]) {
    for (const name of nativeOwnedClasses) {
      const counts = {absent: 0, witnessed: 0, reachabilityOnly: 0};
      for (const entry of authored.directions.filter((item) => item.direction === direction)) {
        const disposition = entry.nativeOwned[name];
        if (disposition === "absent") counts.absent++;
        else if (disposition.some((id) => Object.hasOwn(authored.owners[id]?.witnesses ?? {}, name))) counts.witnessed++;
        else counts.reachabilityOnly++;
      }
      summary[direction][name] = counts;
    }
  }
  return summary;
}

test("manifest enumerates exactly every published direction, definition and variant", () => {
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.manifestId, "proofkit.schema-completeness-manifest.v1");
  assert.equal(manifest.contractId, contract.contractId);
  assert.deepEqual(enumerationErrors(contract, manifest), []);
  assert.equal(manifest.directions.length, publishedDirections(contract).rows.size);
});

test("enumeration parity refuses added, removed and renamed directions and variants", () => {
  const cases = {
    removed: (value) => { value.directions.pop(); },
    added: (value) => { value.directions.push({...structuredClone(value.directions[0]), route: "invented-command"}); },
    renamedRoute: (value) => { value.directions[1].route += "-renamed"; },
    renamedDefinition: (value) => { value.directions[2].definitionId = value.directions[2].definitionId.replace(".json-schema", ".v9.json-schema"); },
    renamedVariant: (value) => { value.directions[3].variantIds[0] += "-renamed"; },
    addedVariant: (value) => { value.directions[3].variantIds.push("99-invented"); },
    reorderedVariants: (value) => { value.directions.find((entry) => entry.variantIds.length > 1).variantIds.reverse(); },
    duplicated: (value) => { value.directions.push(structuredClone(value.directions[4])); },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const tampered = structuredClone(manifest);
    mutate(tampered);
    assert.notDeepEqual(enumerationErrors(contract, tampered), [], name);
  }
  const published = structuredClone(contract);
  published.contractDefinitions[0].fieldTree.variants.push({...structuredClone(published.contractDefinitions[0].fieldTree.variants[0]), variantId: "99-published-only"});
  assert.notDeepEqual(enumerationErrors(published, manifest), [], "variant added to the contract only");
  const removedCommand = structuredClone(contract);
  removedCommand.commands.pop();
  assert.notDeepEqual(enumerationErrors(removedCommand, manifest), [], "command removed from the contract only");
});

test("declared schema-expressed classes equal the classes the published schemas express", () => {
  assert.deepEqual(expressionErrors(contract, manifest), []);
  const tampered = structuredClone(manifest);
  tampered.directions[0].schemaExpresses = tampered.directions[0].schemaExpresses.filter((name) => name !== "unknownField");
  assert.notDeepEqual(expressionErrors(contract, tampered), [], "dropped expressed class");
  const relaxed = structuredClone(contract);
  const definition = relaxed.contractDefinitions.find((row) => row.definitionId === manifest.directions[0].definitionId);
  for (const variant of definition.fieldTree.variants) {
    const strip = (node) => {
      if (!isObject(node)) return;
      if (node.additionalProperties === false) delete node.additionalProperties;
      forEachSubschema(node, strip);
    };
    strip(variant.schema);
  }
  assert.notDeepEqual(expressionErrors(relaxed, manifest), [], "published closed-object policy removed");
  const numeric = structuredClone(manifest);
  numeric.directions.find((entry) => entry.nativeOwned.numericCanonical !== "absent").nativeOwned.numericCanonical = "absent";
  assert.notDeepEqual(expressionErrors(contract, numeric), [], "numeric fields without canonical-spelling owner");
  const outputAbsent = structuredClone(manifest);
  outputAbsent.directions.find((entry) => entry.route === "adopt plan" && entry.direction === "output").nativeOwned.duplicate = "absent";
  assert.notDeepEqual(expressionErrors(contract, outputAbsent), [], "adopt plan output declares duplicate absent");
  const defaultAbsent = structuredClone(manifest);
  defaultAbsent.directions.find((entry) => entry.direction === "input" && entry.nativeOwned.default !== "absent" && definitionFacts(publishedDirections(contract).rows.get(directionKey(entry.route, "input")).definition).optional).nativeOwned.default = "absent";
  assert.notDeepEqual(expressionErrors(contract, defaultAbsent), [], "default absent with optional input members");
});

test("crossField is expressed only by relations between members", () => {
  const notOnly = {type: "object", additionalProperties: false, properties: {values: {type: "array", items: {type: "string", not: {enum: ["reserved"]}}}}};
  assert.equal(schemaFacts(notOnly).classes.has("crossField"), false, "single-location not");
  const discriminated = {type: "object", oneOf: [{properties: {state: {const: "passed"}, count: {const: 0}}}, {properties: {state: {const: "failed"}, count: {minimum: 1}}}]};
  assert.equal(schemaFacts(discriminated).classes.has("crossField"), true, "oneOf over two members");
  const anyRequired = {type: "object", anyOf: [{required: ["a"]}, {required: ["b"]}]};
  assert.equal(schemaFacts(anyRequired).classes.has("crossField"), true, "anyOf requiring one of two members");
  const conditional = {type: "object", if: {properties: {status: {const: "blocked"}}, required: ["status"]}, then: {required: ["blocker"]}};
  assert.equal(schemaFacts(conditional).classes.has("crossField"), true, "if/then over two members");
  const nullable = {anyOf: [{type: "null"}, {type: "string"}]};
  assert.equal(schemaFacts(nullable).classes.has("crossField"), false, "nullable alternative");
  const excludedCombination = {type: "object", not: {properties: {presetId: {const: "docs"}, paths: {not: {required: ["specGlobs"]}}}, required: ["presetId", "paths"]}};
  assert.equal(schemaFacts(excludedCombination).classes.has("crossField"), true, "not over two members");
});

test("every native-owned disposition names existing owners with checkable witnesses", () => {
  assert.deepEqual(ownerErrors(manifest, residue.residue), []);
  assert.deepEqual(manifest.witnessSummary, witnessSummary(manifest));
  const firstWitnessed = Object.keys(manifest.owners).find((id) => Object.values(manifest.owners[id].witnesses ?? {}).some((witness) => witness.evidence));
  const firstClass = Object.keys(manifest.owners[firstWitnessed].witnesses).find((name) => manifest.owners[firstWitnessed].witnesses[name].evidence);
  const cases = {
    missingTest: (value) => { value.owners[firstWitnessed].witnesses[firstClass].test = value.owners[firstWitnessed].witnesses[firstClass].test.replace(/#.*/, "#TestDoesNotExistAnywhere"); },
    missingFunction: (value) => { value.owners[firstWitnessed].owner = value.owners[firstWitnessed].owner.replace(/#.*/, "#functionDoesNotExist"); },
    foreignPackageTest: (value) => { value.owners[firstWitnessed].witnesses[firstClass].test = "internal/app/authoring_input_guide_test.go#TestAuthoringInputGuideBootstrapCLI"; },
    partialEvidence: (value) => { const witness = value.owners[firstWitnessed].witnesses[firstClass]; witness.evidence = witness.evidence.slice(0, -2); },
    tokenEvidence: (value) => { value.owners[firstWitnessed].witnesses[firstClass].evidence = "JSONNumberEquals("; },
    wrongClassEvidence: (value) => {
      const id = Object.keys(value.owners).find((key) => value.owners[key].witnesses?.secretTimestamp?.evidence);
      value.owners[id].witnesses.crossField = value.owners[id].witnesses.secretTimestamp;
    },
    undeclaredOwner: (value) => { value.directions[0].nativeOwned.semantic = ["undeclared.owner"]; },
    omittedClass: (value) => { delete value.directions[0].nativeOwned.referenceClosure; },
    emptyOwners: (value) => { value.directions[0].nativeOwned.semantic = []; },
    outputWithoutProducer: (value) => {
      const entry = value.directions.find((item) => item.direction === "output");
      entry.nativeOwned.semantic = entry.nativeOwned.semantic.filter((id) => value.owners[id].role !== "producer");
      if (entry.nativeOwned.semantic.length === 0) entry.nativeOwned.semantic = ["admit.RuleID"];
    },
    ambiguousMutation: (value) => {
      const id = Object.keys(value.owners).find((key) => Object.values(value.owners[key].witnesses ?? {}).some((witness) => witness.mutation));
      const witness = Object.values(value.owners[id].witnesses).find((item) => item.mutation);
      witness.mutation.find = "\n";
    },
    cliWithoutRow: (value) => {
      const id = Object.keys(value.owners).find((key) => Object.values(value.owners[key].witnesses ?? {}).some((witness) => witness.cli));
      const name = Object.keys(value.owners[id].witnesses).find((key) => value.owners[id].witnesses[key].cli);
      value.owners[id].witnesses[name].cli = value.owners[id].witnesses[name].cli + " ";
    },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const tampered = structuredClone(manifest);
    mutate(tampered);
    assert.notDeepEqual(ownerErrors(tampered, residue.residue), [], name);
  }
  const summary = structuredClone(manifest);
  summary.witnessSummary.input.duplicate.witnessed++;
  assert.notDeepEqual(summary.witnessSummary, witnessSummary(summary), "summary drift");
});

// Class-targeted mutants of recorded native observations. An instance-guided
// walk visits every schema location the observation is evaluated against:
// object members, items, matching oneOf/anyOf alternatives, the taken if
// branch and dependent schemas. At each location every keyword of an
// expressed class yields one mutant of the instance that must be refused
// with that keyword at that instance path; a default yields a positive
// mutant (the member omitted) that must not be refused for absence.
const newAjv = (allErrors = true) => new Ajv2020({strict: false, allErrors, validateFormats: false});
const mutantMember = "x-schema-completeness-mutant";
const pointerOf = (path) => path.map((token) => `/${String(token).replaceAll("~", "~0").replaceAll("/", "~1")}`).join("");
const sameJSON = (left, right) => JSON.stringify(left) === JSON.stringify(right);

// A mutant is a list of edits to the observation. Edits are applied in
// place for one validation and undone afterwards, so a mutant of a large
// observation costs no copy of it.
const setAt = (_document, path, value) => ({edits: [{path, value}]});
const deleteAt = (_document, path) => ({edits: [{path, remove: true}]});
const combine = (changes) => ({edits: changes.flatMap((change) => change.edits)});

function validateEdited(check, base, change) {
  if (change.edits.length === 1 && change.edits[0].path.length === 0) return check(change.edits[0].value);
  const undo = [];
  for (const {path, value, remove} of change.edits) {
    const parent = path.slice(0, -1).reduce((node, key) => node[key], base);
    const key = path.at(-1);
    undo.push({parent, key, had: Object.hasOwn(parent, key), previous: parent[key], order: Array.isArray(parent) ? null : Object.keys(parent)});
    if (remove) delete parent[key];
    else parent[key] = value;
  }
  try {
    return check(base);
  } finally {
    for (const {parent, key, had, previous, order} of undo.reverse()) {
      if (!had) {
        delete parent[key];
        continue;
      }
      parent[key] = previous;
      if (order !== null && Object.keys(parent).join("\u0000") !== order.join("\u0000")) {
        const entries = order.map((name) => [name, parent[name]]);
        for (const name of Object.keys(parent)) delete parent[name];
        for (const [name, member] of entries) parent[name] = member;
      }
    }
  }
}
function outsideDomain(domain, value) {
  const candidates = typeof value === "string" ? [`${value}-${mutantMember}`, mutantMember]
    : typeof value === "number" ? [value + 1, value - 1, 987654321]
      : typeof value === "boolean" ? [!value] : value === null ? [mutantMember] : [mutantMember, 0];
  return candidates.find((candidate) => !domain.some((item) => sameJSON(item, candidate)));
}

class InstanceWalk {
  constructor(document) {
    this.document = document;
    this.compiled = new WeakMap();
    this.locations = [];
  }
  valid(node, resource, value) {
    if (typeof node === "boolean") return node;
    if (!this.compiled.has(node)) {
      const wrapper = {...node, $defs: {...(resource.$defs ?? {}), ...(node.$defs ?? {})}};
      delete wrapper.$id;
      this.compiled.set(node, newAjv(false).compile(wrapper));
    }
    return this.compiled.get(node)(value);
  }
  // A location below a matching anyOf/oneOf alternative, a taken if branch
  // or a dependent schema is conditional: another alternative or branch may
  // still admit a mutant of it, so only its refused mutants count.
  visit(node, value, path, resource = this.document, member = null, conditional = false) {
    if (!isObject(node)) return;
    if (Object.hasOwn(node, "$id")) resource = node;
    if (typeof node.$ref === "string") this.visit(resolveLocalReference(resource, node.$ref), value, path, resource, member, conditional);
    this.locations.push({node, value, path, resource, member, conditional});
    for (const child of node.allOf ?? []) this.visit(child, value, path, resource, member, conditional);
    for (const keyword of ["anyOf", "oneOf"]) {
      for (const child of node[keyword] ?? []) if (this.valid(child, resource, value)) this.visit(child, value, path, resource, member, true);
    }
    if (isObject(node.if) || typeof node.if === "boolean") {
      const branch = this.valid(node.if, resource, value) ? node.then : node.else;
      if (branch !== undefined) this.visit(branch, value, path, resource, member, true);
    }
    if (isObject(value)) {
      for (const [name, schema] of Object.entries(node.dependentSchemas ?? {})) if (Object.hasOwn(value, name)) this.visit(schema, value, path, resource, member, true);
      for (const [name, child] of Object.entries(value)) {
        let matched = false;
        const childMember = {name, required: node.required ?? []};
        if (isObject(node.properties) && Object.hasOwn(node.properties, name)) {
          matched = true;
          this.visit(node.properties[name], child, [...path, name], resource, childMember, conditional);
        }
        for (const [pattern, schema] of Object.entries(node.patternProperties ?? {})) {
          if (new RegExp(pattern, "u").test(name)) {
            matched = true;
            this.visit(schema, child, [...path, name], resource, childMember, conditional);
          }
        }
        if (!matched && isObject(node.additionalProperties)) this.visit(node.additionalProperties, child, [...path, name], resource, childMember, conditional);
      }
    }
    if (Array.isArray(value)) {
      const prefix = Array.isArray(node.prefixItems) ? node.prefixItems : [];
      value.forEach((item, index) => {
        if (index < prefix.length) this.visit(prefix[index], item, [...path, index], resource, null, conditional);
        else if (isObject(node.items)) this.visit(node.items, item, [...path, index], resource, null, conditional);
      });
    }
  }
}

// One mutant per class keyword at one evaluated location.
// A JSON value whose type the node's type keyword excludes.
function wrongType(types, value) {
  const admitted = [].concat(types);
  const typeOf = (candidate) => (candidate === null ? "null" : Array.isArray(candidate) ? "array" : Number.isInteger(candidate) ? "integer" : typeof candidate);
  return [null, true, 0.5, mutantMember, [], {[mutantMember]: true}].find((candidate) => {
    const type = typeOf(candidate);
    return !sameJSON(candidate, value) && !admitted.includes(type) && !(type === "integer" && admitted.includes("number")) && !(type === "number" && admitted.includes("number"));
  });
}

function locationMutants(location, base) {
  const {node, value, path} = location;
  const at = (replacement) => setAt(base, path, replacement);
  const rows = [];
  const add = (className, keyword, document, instancePath = path, parameter = JSON.stringify(node[keyword])) => rows.push({className, keyword, document, instancePath: pointerOf(instancePath), parameter});
  // Structure: every present required member is deleted (refused with
  // required at the object) and every typed location gets a value of an
  // excluded JSON type (refused with type at the location).
  if (isObject(value) && Array.isArray(node.required)) {
    for (const name of node.required) if (Object.hasOwn(value, name)) add("required", "required", deleteAt(base, [...path, name]), path, name);
  }
  if (Object.hasOwn(node, "type")) {
    const replacement = wrongType(node.type, value);
    if (replacement !== undefined) add("type", "type", at(replacement), path, `${JSON.stringify(node.type)}<-${JSON.stringify(replacement)}`);
  }
  if (Array.isArray(value)) {
    if (Number.isInteger(node.minItems) && node.minItems >= 1 && value.length >= node.minItems) add("cardinality", "minItems", at(value.slice(0, node.minItems - 1)));
    // Every maxItems bound is crossed, however large: the appended items
    // share the last observed item.
    if (Number.isInteger(node.maxItems) && value.length > 0) add("cardinality", "maxItems", at([...value, ...new Array(node.maxItems + 1 - value.length).fill(value.at(-1))]));
    if (Object.hasOwn(node, "contains") && isObject(node.contains) && Object.hasOwn(node.contains, "const")) add("cardinality", "contains", at(value.filter((item) => !sameJSON(item, node.contains.const))));
    if (node.uniqueItems === true && value.length > 0) add("duplicate", "uniqueItems", at([value[0], structuredClone(value[0]), ...value.slice(1)]));
  }
  if (isObject(value)) {
    if (Number.isInteger(node.maxProperties) && node.maxProperties <= 8192 && node.additionalProperties !== false) {
      const extra = Object.fromEntries(Array.from({length: node.maxProperties + 1}, (_, index) => [`${mutantMember}-${index}`, true]));
      add("cardinality", "maxProperties", at({...value, ...extra}));
    }
    if (node.additionalProperties === false) add("unknownField", "additionalProperties", at({...value, [mutantMember]: true}));
    if (node.unevaluatedProperties === false) add("unknownField", "unevaluatedProperties", at({...value, [mutantMember]: true}));
    for (const [name, dependents] of Object.entries(node.dependentRequired ?? {})) {
      const present = dependents.find((dependent) => Object.hasOwn(value, dependent));
      if (Object.hasOwn(value, name) && present !== undefined) add("crossField", "dependentRequired", deleteAt(base, [...path, present]));
    }
  }
  if (typeof value === "string") {
    const length = [...value].length;
    if (Number.isInteger(node.minLength) && node.minLength >= 1 && length >= node.minLength) add("bound", "minLength", at([...value].slice(0, node.minLength - 1).join("")));
    if (Number.isInteger(node.maxLength) && node.maxLength <= 1 << 20) add("bound", "maxLength", at(value + "a".repeat(node.maxLength + 1 - Math.min(length, node.maxLength))));
    if (typeof node.pattern === "string") {
      const pattern = new RegExp(node.pattern, "u");
      const outside = ["", " ", "\u0000", "!", `${value}\n`, `${value} ${mutantMember} !`].find((candidate) => !pattern.test(candidate));
      if (outside !== undefined) add("bound", "pattern", at(outside));
    }
  }
  if (typeof value === "number") {
    // Beyond 2^53 a JavaScript number cannot spell bound + 1; doubling the
    // magnitude still crosses the bound.
    const beyond = (bound, direction) => (Number.isSafeInteger(bound) ? bound + direction : bound * 2 + direction);
    if (typeof node.minimum === "number") add("bound", "minimum", at(beyond(node.minimum, -1)));
    if (typeof node.maximum === "number") add("bound", "maximum", at(beyond(node.maximum, 1)));
    if (typeof node.exclusiveMinimum === "number") add("bound", "exclusiveMinimum", at(node.exclusiveMinimum));
    if (typeof node.exclusiveMaximum === "number") add("bound", "exclusiveMaximum", at(node.exclusiveMaximum));
  }
  if (Object.hasOwn(node, "const")) {
    const outside = outsideDomain([node.const], value);
    if (outside !== undefined) add("enum", "const", at(outside));
  }
  if (Array.isArray(node.enum)) {
    const outside = outsideDomain(node.enum, value);
    if (outside !== undefined) add("enum", "enum", at(outside));
  }
  return rows;
}

// A change that makes an object satisfy the subschema of a multi-member not:
// each named member takes its const or first enum value, and a member whose
// subschema is not {required} loses those inner members.
function satisfyNot(inner, value, path, base) {
  const edits = [];
  for (const [name, schema] of Object.entries(inner.properties ?? {})) {
    if (!isObject(schema)) continue;
    if (Object.hasOwn(schema, "const")) edits.push(setAt(base, [...path, name], schema.const));
    else if (Array.isArray(schema.enum) && schema.enum.length > 0) edits.push(setAt(base, [...path, name], schema.enum[0]));
    else if (isObject(schema.not) && Array.isArray(schema.not.required) && isObject(value[name])) {
      for (const member of schema.not.required) if (Object.hasOwn(value[name], member)) edits.push(deleteAt(base, [...path, name, member]));
    }
  }
  return edits.length > 0 ? combine(edits) : null;
}

// Cross-member mutants: perturb each member a relation names (delete it,
// empty or flip it, or give it the value another alternative requires),
// delete every named member together, and make the object satisfy the
// subschema of a multi-member not. A mutant witnesses the relation only when
// the relation keyword itself refuses it at the relation's object.
const relationKeywords = new Set(["anyOf", "oneOf", "if", "dependentRequired", "dependentSchemas", "not"]);
function relationMutants(location, base) {
  const {node, value, path} = location;
  if (!isObject(value) || !memberRelation(node)) return [];
  const alternatives = [...(node.oneOf ?? []), ...(node.anyOf ?? []), ...[node.if, node.then, node.else].filter(isObject), ...(memberNames(node.not).size >= 2 ? [node.not] : [])];
  const names = new Set([...alternatives.flatMap((member) => [...memberNames(member)]), ...Object.keys(node.dependentRequired ?? {}), ...Object.values(node.dependentRequired ?? {}).flat(), ...Object.keys(node.dependentSchemas ?? {})]);
  const rows = [];
  const add = (operation, document) => rows.push({className: "crossField", keyword: "relation", document, instancePath: pointerOf(path), parameter: operation});
  const present = [...names].filter((name) => Object.hasOwn(value, name));
  for (const name of present) {
    const member = value[name];
    add(`delete ${name}`, deleteAt(base, [...path, name]));
    if (Array.isArray(member) && member.length > 0) add(`empty ${name}`, setAt(base, [...path, name], []));
    if (typeof member === "string") add(`blank ${name}`, setAt(base, [...path, name], member === "" ? mutantMember : ""));
    if (typeof member === "boolean") add(`flip ${name}`, setAt(base, [...path, name], !member));
    if (member === null) add(`fill ${name}`, setAt(base, [...path, name], mutantMember));
    for (const alternative of alternatives) {
      const target = alternative.properties?.[name];
      const replacement = isObject(target) ? (Object.hasOwn(target, "const") ? target.const : target.enum?.[0]) : undefined;
      if (replacement !== undefined && !sameJSON(replacement, member)) add(`swap ${name} ${JSON.stringify(replacement)}`, setAt(base, [...path, name], replacement));
    }
  }
  if (present.length >= 2) add(`delete ${present.join(",")}`, combine(present.map((name) => deleteAt(base, [...path, name]))));
  if (memberNames(node.not).size >= 2) {
    const satisfied = satisfyNot(node.not, value, path, base);
    if (satisfied !== null) add("satisfy not", satisfied);
  }
  return rows;
}

function defaultSatisfiesSchema(node, resource) {
  const schema = {...node, $defs: {...(resource.$defs ?? {}), ...(node.$defs ?? {})}};
  delete schema.$id;
  return newAjv().compile(schema)(node.default);
}

function resolvePointer(document, pointer) {
  if (pointer === "") return document;
  return pointer.slice(1).split("/").map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~")).reduce((value, token) => {
    assert.ok(value !== null && typeof value === "object" && Object.hasOwn(value, token), `pointer ${pointer} resolves`);
    return value[token];
  }, document);
}

// A corpus row must point at a row of the same command in another committed
// oracle corpus; the pointer's first segments select that row.
function corpusTarget(row) {
  const corpus = JSON.parse(read(row.corpus));
  const tokens = row.pointer.slice(1).split("/");
  const rowPointer = Array.isArray(corpus) ? `/${tokens[0]}` : `/${tokens[0]}/${tokens[1]}`;
  return {record: resolvePointer(corpus, rowPointer), value: resolvePointer(corpus, row.pointer)};
}

function observationValue(row) {
  if (!Object.hasOwn(row, "value")) {
    assert.match(row.corpus, /^internal\/app\/testdata\/[a-z0-9.-]+\.json$/);
    return corpusTarget(row).value;
  }
  const value = structuredClone(row.value);
  for (const [pointer, path] of Object.entries(row.embed ?? {})) {
    assert.match(pointer, /^\/[A-Za-z]+$/);
    assert.match(path, /^internal\/app\/testdata\/schema-completeness-embed-[a-z0-9.-]+\.json$/);
    value[pointer.slice(1)] = JSON.parse(read(path));
  }
  return value;
}

// A variant "when" condition is a prose list of flag requirements before
// its first ";" or "(": "--flag value" must appear, a lone "--flag" or
// "--flag naming <description>" must be present, and "without --flag" must
// be absent.
function argvSatisfies(argv, condition) {
  const tokens = condition.split(/[;(]/)[0].trim().split(/\s+/);
  let negated = false;
  for (let position = 0; position < tokens.length; position++) {
    const token = tokens[position];
    if (token === "without") {
      negated = true;
      continue;
    }
    if (!token.startsWith("--")) continue;
    const next = tokens[position + 1];
    const valued = next !== undefined && !next.startsWith("--") && !["and", "or", "without", "naming"].includes(next);
    const at = argv.indexOf(token);
    if (negated) {
      if (at >= 0) return false;
    } else if (at < 0 || (valued && argv[at + 1] !== next)) {
      return false;
    }
    if (valued && !negated) position++;
  }
  return true;
}

test("observation rows bind their command and the variant their argv selects", () => {
  const {rows} = publishedDirections(contract);
  for (const [index, row] of observations.observations.entries()) {
    const published = rows.get(directionKey(row.route, row.direction));
    assert.ok(published, `observation ${index} direction is published`);
    if (Object.hasOwn(row, "corpus")) {
      assert.equal(corpusTarget(row).record.command, published.command, `observation ${index} corpus row belongs to ${published.command}`);
    }
    if (Array.isArray(row.argv)) {
      const routeTokens = row.route.split(" ");
      const command = row.argv[0] === "--json-layout" ? row.argv.slice(2) : row.argv;
      assert.deepEqual(command.slice(0, routeTokens.length), routeTokens, `observation ${index} argv runs its route`);
      assert.deepEqual(row.argv.slice(row.argv.indexOf("--input"), row.argv.indexOf("--input") + 2), ["--input", "-"], `observation ${index} argv reads stdin`);
      assert.equal(Object.hasOwn(row, "repoRootFiles"), row.argv.some(namesRepoRoot), `observation ${index} binds repoRootFiles to the ${repoRootToken} argv token`);
      if (row.direction === "input") {
        const variant = published.definition.fieldTree.variants.find((item) => item.variantId === row.variantIds[0]);
        if ((variant.when ?? []).length > 0) {
          assert.ok(variant.when.some((condition) => argvSatisfies(row.argv, condition)), `observation ${index} argv selects ${row.variantIds[0]}`);
        }
      } else {
        assert.equal(Object.hasOwn(row, "inputObservation") !== Object.hasOwn(row, "refusedInput"), true, `output observation ${index} names exactly one input`);
        if (Object.hasOwn(row, "inputObservation")) assert.equal(observations.observations[row.inputObservation]?.route, row.route, `output observation ${index} input row runs the same route`);
      }
    } else {
      assert.equal(row.direction === "input" && index >= 207, false, `appended input observation ${index} carries argv`);
    }
  }
  const foreign = structuredClone(observations.observations.find((row) => Object.hasOwn(row, "corpus") && row.pointer.startsWith("/observations/")));
  const foreignRows = JSON.parse(read(foreign.corpus)).observations;
  const other = foreignRows.findIndex((record) => record.command !== corpusTarget(foreign).record.command);
  foreign.pointer = foreign.pointer.replace(/^\/observations\/\d+/, `/observations/${other}`);
  assert.notEqual(corpusTarget(foreign).record.command, publishedDirections(contract).rows.get(directionKey(foreign.route, foreign.direction)).command, "a pointer into another command's row is detected");
});

test("structural and multi-member not mutants are refused by their keyword", () => {
  const excludedCombination = {type: "object", not: {properties: {presetId: {const: "docs"}, paths: {not: {required: ["specGlobs"]}}}, required: ["presetId", "paths"]}};
  const preset = {presetId: "code", paths: {specGlobs: ["docs/**"]}};
  const satisfied = relationMutants({node: excludedCombination, value: preset, path: []}, preset).find((mutant) => mutant.parameter === "satisfy not");
  assert.ok(satisfied, "a multi-member not yields a mutant that satisfies its subschema");
  const excluded = newAjv().compile(excludedCombination);
  assert.equal(validateEdited(excluded, preset, satisfied.document), false);
  assert.ok(excluded.errors.some((error) => error.keyword === "not" && error.instancePath === ""), "refused by not at the object");
  assert.deepEqual(preset, {presetId: "code", paths: {specGlobs: ["docs/**"]}}, "edits are undone");
  const node = {type: "object", required: ["id", "count"], properties: {id: {type: "string"}, count: {type: "integer"}, note: {type: ["string", "null"]}}, additionalProperties: false};
  const instance = {id: "a", count: 1, note: null};
  const check = newAjv().compile(node);
  const required = locationMutants({node, value: instance, path: []}, instance).filter((mutant) => mutant.keyword === "required");
  assert.deepEqual(required.map((mutant) => mutant.parameter), ["id", "count"]);
  for (const mutant of required) {
    assert.equal(validateEdited(check, instance, mutant.document), false);
    assert.ok(check.errors.some((error) => error.keyword === "required" && error.params.missingProperty === mutant.parameter));
  }
  for (const [name, member] of Object.entries(node.properties)) {
    const [mutant] = locationMutants({node: member, value: instance[name], path: [name]}, instance).filter((row) => row.keyword === "type");
    assert.ok(mutant, `${name} has a wrong-type mutant`);
    assert.equal(validateEdited(check, instance, mutant.document), false);
    assert.ok(check.errors.some((error) => error.keyword === "type" && error.instancePath === `/${name}`), `${name} is refused with type`);
  }
  const bounded = {type: "array", maxItems: 20000};
  const [crossing] = locationMutants({node: bounded, value: [1], path: []}, [1]).filter((mutant) => mutant.keyword === "maxItems");
  assert.equal(crossing.document.edits[0].value.length, 20001, "maxItems above 8192 is crossed");
});

test("class-targeted mutants of recorded native observations are refused at every evaluated location", () => {
  assert.equal(observations.schemaVersion, 1);
  const {rows} = publishedDirections(contract);
  const byDirection = new Map();
  for (const row of observations.observations) {
    const key = directionKey(row.route, row.direction);
    if (!byDirection.has(key)) byDirection.set(key, []);
    byDirection.get(key).push(row);
  }
  const unconstrained = new Set(manifest.directions.filter((entry) => entry.mutantPolicy === "unconstrained-json-value").map((entry) => directionKey(entry.route, entry.direction)));
  const uncovered = [];
  const counts = {};
  const compiledVariants = new Map();
  const identities = new Map();
  const record = (key, className, identity) => {
    if (!identities.has(key)) identities.set(key, {});
    (identities.get(key)[className] ??= []).push(identity);
  };
  for (const entry of manifest.directions) {
    const key = directionKey(entry.route, entry.direction);
    const published = rows.get(key);
    if (unconstrained.has(key)) {
      assert.equal(byDirection.has(key), false, `${key} declares no structural mutant`);
      for (const variant of published.definition.fieldTree.variants) {
        const check = newAjv().compile(variant.schema);
        for (const value of [{}, [], "", 0, null, true, {[mutantMember]: [1]}]) assert.equal(check(value), true, `${key} accepts any JSON value`);
      }
      continue;
    }
    const bases = byDirection.get(key) ?? [];
    assert.ok(bases.length > 0, `${key} has a recorded native observation`);
    const exercised = new Set();
    for (const row of bases) {
      const base = observationValue(row);
      const observationIndex = observations.observations.indexOf(row);
      for (const variantId of row.variantIds) {
        const variant = published.definition.fieldTree.variants.find((candidate) => candidate.variantId === variantId);
        assert.ok(variant, `${key} observation names published variant ${variantId}`);
        if (!compiledVariants.has(variant)) {
          const expanded = expandSharedDefinitions(variant.schema);
          compiledVariants.set(variant, {check: newAjv().compile(variant.schema), expanded, walk: new InstanceWalk(expanded)});
        }
        const {check, expanded, walk} = compiledVariants.get(variant);
        assert.equal(check(base), true, `${key} ${variantId} accepts its native observation: ${JSON.stringify(check.errors?.slice(0, 3))}`);
        walk.locations = [];
        walk.visit(expanded, base, []);
        for (const location of walk.locations) {
          for (const mutant of [...locationMutants(location, base), ...relationMutants(location, base)]) {
            const refused = !validateEdited(check, base, mutant.document);
            const errors = check.errors ?? [];
            if (mutant.keyword === "relation") {
              if (!refused || !errors.some((error) => relationKeywords.has(error.keyword) && error.instancePath === mutant.instancePath)) continue;
            } else if (location.conditional) {
              if (!refused || !errors.some((error) => error.keyword === mutant.keyword && error.instancePath === mutant.instancePath)) continue;
            } else {
              assert.ok(refused, `${key} ${variantId} refuses ${mutant.className} mutant ${mutant.keyword} at ${mutant.instancePath}`);
              assert.ok(errors.some((error) => error.keyword === mutant.keyword && error.instancePath === mutant.instancePath), `${key} ${variantId} refuses ${mutant.keyword} at ${mutant.instancePath} with that keyword: ${JSON.stringify(errors.slice(0, 3))}`);
            }
            exercised.add(mutant.className);
            counts[mutant.className] = (counts[mutant.className] ?? 0) + 1;
            record(key, mutant.className, `${observationIndex}|${variantId}|${mutant.keyword}|${mutant.instancePath}|${mutant.parameter}`);
          }
          if (Object.hasOwn(location.node, "default") && location.member !== null) {
            assert.equal(location.member.required.includes(location.member.name), false, `${key} ${variantId} default at ${pointerOf(location.path)} is optional`);
            assert.equal(defaultSatisfiesSchema(location.node, location.resource), true, `${key} ${variantId} default at ${pointerOf(location.path)} satisfies its schema`);
            validateEdited(check, base, deleteAt(base, location.path));
            const parent = pointerOf(location.path.slice(0, -1));
            assert.equal((check.errors ?? []).some((error) => error.keyword === "required" && error.instancePath === parent && error.params.missingProperty === location.member.name), false, `${key} ${variantId} admits omitting defaulted ${pointerOf(location.path)}`);
            exercised.add("default");
            counts.default = (counts.default ?? 0) + 1;
            record(key, "default", `${observationIndex}|${variantId}|default|${pointerOf(location.path)}|${JSON.stringify(location.node.default)}`);
          }
          // A defaulted member the observation omits: the observation itself
          // shows omission is admitted; the default must be optional and valid.
          if (isObject(location.value) && isObject(location.node.properties)) {
            for (const [name, declared] of Object.entries(location.node.properties)) {
              const schema = isObject(declared) && typeof declared.$ref === "string" && !Object.hasOwn(declared, "default") ? resolveLocalReference(location.resource, declared.$ref) : declared;
              if (Object.hasOwn(location.value, name) || !isObject(schema) || !Object.hasOwn(schema, "default")) continue;
              assert.equal((location.node.required ?? []).includes(name), false, `${key} ${variantId} default ${pointerOf([...location.path, name])} is optional`);
              assert.equal(defaultSatisfiesSchema(schema, location.resource), true, `${key} ${variantId} default ${pointerOf([...location.path, name])} satisfies its schema`);
              exercised.add("default");
              counts.default = (counts.default ?? 0) + 1;
              record(key, "default", `${observationIndex}|${variantId}|default|${pointerOf([...location.path, name])}|${JSON.stringify(schema.default)}`);
            }
          }
        }
      }
    }
    for (const name of entry.schemaExpresses) if (!exercised.has(name)) uncovered.push(`${key} ${name}`);
    const observed = new Set(bases.flatMap((row) => row.variantIds));
    for (const variantId of entry.variantIds) if (!observed.has(variantId)) uncovered.push(`${key} variant ${variantId} has no recorded native observation`);
  }
  assert.deepEqual(uncovered, [], "every expressed class of every direction has a refused class-targeted mutant");
  for (const name of [...expressedClasses, "required", "type"]) assert.ok((counts[name] ?? 0) > 0, `${name} mutants exist`);
  // The committed corpus record pins, per direction and class, how many
  // refused mutants the observations produce and a digest of their
  // identities (observation, variant, keyword, instance path, keyword value).
  // Removing, adding or changing any observed constraint changes it.
  const recorded = {};
  for (const key of [...identities.keys()].sort()) {
    recorded[key] = {};
    for (const name of Object.keys(identities.get(key)).sort()) {
      const sorted = identities.get(key)[name].sort();
      recorded[key][name] = {mutants: sorted.length, sha256: createHash("sha256").update(sorted.join("\n")).digest("hex")};
    }
  }
  const drift = Object.keys({...recorded, ...mutantCorpus.directions}).sort().flatMap((key) => (sameJSON(recorded[key], mutantCorpus.directions[key]) ? [] : [`${key}: recorded ${JSON.stringify(mutantCorpus.directions[key])}, observed ${JSON.stringify(recorded[key])}`]));
  assert.deepEqual(drift, [], "the class-targeted mutant corpus equals its committed record");
});

// Native CLI replays. Committed rows bind each uniqueItems agreement and each
// native residue witness to a route by execution.
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-schema-completeness-"));
  binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 300_000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });

// An argv observation that names repoRootFiles runs with the repoRootToken
// replaced by a fresh directory holding exactly those files.
function observationArgv(row) {
  if (!Object.hasOwn(row, "repoRootFiles")) return row.argv;
  const repo = mkdtempSync(join(directory, "repo-root-"));
  for (const [name, text] of Object.entries(row.repoRootFiles)) writeFileSync(join(repo, name), text);
  return row.argv.map((token) => (namesRepoRoot(token) ? repo + token.slice(repoRootToken.length) : token));
}

function runNative(argv, value) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, argv, {cwd: directory});
    let stdout = "", stderr = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`${argv.join(" ")} timed out`)); }, 60_000);
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      let json = null;
      try { json = JSON.parse(stdout); } catch {}
      resolve({code, json, stderr});
    });
    child.stdin.end(JSON.stringify(value));
  });
}
const strings = (value, out = []) => {
  if (typeof value === "string") out.push(value);
  else if (value !== null && typeof value === "object") Object.values(value).forEach((child) => strings(child, out));
  return out;
};
async function inParallel(items, work, width = 4) {
  let next = 0;
  const results = new Array(items.length);
  await Promise.all(Array.from({length: width}, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await work(items[index]);
    }
  }));
  return results;
}

const tokensOf = (pointer) => pointer.slice(1).split("/").map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
function perturb(base, kind, pointer) {
  const path = tokensOf(pointer);
  const document = structuredClone(base);
  const parent = path.slice(0, -1).reduce((node, key) => node[key], document);
  const key = path.at(-1);
  const value = parent[key];
  switch (kind) {
    case "duplicate-item": value.splice(1, 0, structuredClone(value[0])); break;
    case "empty-array": parent[key] = []; break;
    case "unknown-member": value["x-schema-completeness-residue"] = true; break;
    case "omit-member": delete parent[key]; break;
    case "long-string": parent[key] = value + "x".repeat(320); break;
    case "other-token": parent[key] = value === "" ? "x-schema-completeness-residue" : `${value}-x-schema-completeness-residue`; break;
    case "large-number": parent[key] = value + 1000003; break;
    default: throw new Error(`unknown perturbation ${kind}`);
  }
  return document;
}

function argvObservation(index) {
  const row = observations.observations[index];
  assert.ok(row && row.direction === "input" && Array.isArray(row.argv), `residue observation ${index} is an argv input row`);
  assert.deepEqual(row.argv.slice(row.argv.indexOf("--input"), row.argv.indexOf("--input") + 2), ["--input", "-"]);
  const {rows} = publishedDirections(contract);
  const variant = rows.get(directionKey(row.route, "input")).definition.fieldTree.variants.find((item) => item.variantId === row.variantIds[0]);
  return {row, base: observationValue(row), check: newAjv().compile(variant.schema)};
}

// Every argv observation is replayed: an input row must be admitted by its
// route (JSON on stdout), and an output row must be exactly the stdout of its
// argv on its named input.
test("argv observations replay natively: inputs are admitted and outputs are reproduced exactly", async () => {
  const replayed = observations.observations.map((row, index) => ({row, index})).filter(({row}) => Array.isArray(row.argv));
  assert.ok(replayed.filter(({row}) => row.direction === "output").length > 0);
  const failures = await inParallel(replayed, async ({row, index}) => {
    const stdin = row.direction === "input" ? observationValue(row) : Object.hasOwn(row, "inputObservation") ? observationValue(observations.observations[row.inputObservation]) : row.refusedInput;
    const native = await runNative(observationArgv(row), stdin);
    if (native.json === null) return `observation ${index} ${row.argv.join(" ")}: native emitted no JSON: ${native.stderr.slice(0, 200)}`;
    if (row.direction === "output" && !isDeepStrictEqual(native.json, observationValue(row))) return `observation ${index} ${row.argv.join(" ")}: native output differs from the recorded output`;
    return null;
  });
  assert.deepEqual(failures.filter(Boolean), []);
});

test("every published uniqueItems that refuses an observed duplicate agrees with native refusal", async () => {
  // Enumerate every duplicate the published argv variants refuse with
  // uniqueItems at the probed array; each must be a committed agreement row.
  const expected = new Set();
  let probed = 0;
  for (const [index, row] of observations.observations.entries()) {
    if (row.direction !== "input" || !Array.isArray(row.argv)) continue;
    const {base, check} = argvObservation(index);
    const arrays = [];
    const collect = (value, path) => {
      if (Array.isArray(value) && value.length > 0) arrays.push(path);
      if (value !== null && typeof value === "object") for (const [key, child] of Object.entries(value)) collect(child, [...path, Array.isArray(value) ? Number(key) : key]);
    };
    collect(base, []);
    for (const path of arrays) {
      probed++;
      const list = path.reduce((node, key) => node[key], base);
      list.splice(1, 0, structuredClone(list[0]));
      const refused = !check(base) && check.errors.some((error) => error.keyword === "uniqueItems" && error.instancePath === pointerOf(path));
      list.splice(1, 1);
      if (refused) expected.add(`${index}${pointerOf(path)}`);
    }
  }
  const committed = new Set(residue.uniqueItemsAgreement.map((item) => `${item.observation}${item.pointer}`));
  assert.deepEqual([...committed].sort(), [...expected].sort(), "committed agreement rows are exactly the uniqueItems refusals");
  assert.ok(probed > residue.uniqueItemsAgreement.length);
  const verdicts = await inParallel(residue.uniqueItemsAgreement, async (item) => {
    const {row, base} = argvObservation(item.observation);
    assert.equal(row.route, item.route);
    const native = await runNative(observationArgv(row), perturb(base, "duplicate-item", item.pointer));
    return native.json === null ? null : `${item.route} ${item.pointer}: native admits a duplicate the published schema refuses`;
  });
  assert.deepEqual(verdicts.filter(Boolean), []);
});

test("committed native residue rows are schema-admitted, natively refused and owned by the named owner", async () => {
  const directions = new Map(manifest.directions.map((entry) => [directionKey(entry.route, entry.direction), entry]));
  const seen = new Set();
  const baselines = new Map();
  const baseline = (index, row, base) => {
    if (!baselines.has(index)) baselines.set(index, runNative(observationArgv(row), base));
    return baselines.get(index);
  };
  const failures = await inParallel(residue.residue, async (item) => {
    const {row, base, check} = argvObservation(item.observation);
    assert.equal(row.route, item.route);
    const key = `${item.observation}|${item.pointer}|${item.perturbation}|${item.class}|${item.owner}`;
    assert.equal(seen.has(key), false, `duplicate residue row ${key}`);
    seen.add(key);
    const entry = directions.get(directionKey(item.route, "input"));
    if (!Array.isArray(entry.nativeOwned[item.class]) || !entry.nativeOwned[item.class].includes(item.owner)) return `${item.route} ${item.class} does not name residue owner ${item.owner}`;
    const mutant = perturb(base, item.perturbation, item.pointer);
    if (!check(mutant)) return `${item.route} ${item.pointer} ${item.perturbation}: published schema refuses the residue perturbation`;
    const [reference, native] = [await baseline(item.observation, row, base), await runNative(observationArgv(row), mutant)];
    const known = new Set(strings(reference.json));
    const text = native.json === null ? native.stderr : native.code === reference.code ? null : strings(native.json).filter((value) => !known.has(value)).join("\n");
    if (text === null) return `${item.route} ${item.pointer} ${item.perturbation}: native admits the residue perturbation`;
    return text.includes(item.evidence) ? null : `${item.route} ${item.pointer} ${item.perturbation}: native diagnostic lacks ${item.evidence}`;
  });
  assert.deepEqual(failures.filter(Boolean), []);
  const classes = new Set(residue.residue.map((item) => item.class));
  for (const name of ["bound", "cardinality", "crossField", "default", "duplicate", "enum", "referenceClosure", "unknownField"]) assert.ok(classes.has(name), `residue witnesses ${name}`);
  const omissions = residue.residue.filter((item) => item.class === "default");
  assert.ok(omissions.length > 0 && omissions.every((item) => item.perturbation === "omit-member"), "default residue omits a member the published schema leaves optional");
});
