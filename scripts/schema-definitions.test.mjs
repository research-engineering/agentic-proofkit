import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {compileVariantUnion, expandSharedDefinitions, resolveLocalReference, SHARED_DEFINITION_PREFIX} from "./schema-definitions.mjs";
import {stableJSONStringify} from "./stable-json.mjs";

// This oracle does not trust the contract generator. It re-derives reference
// closure, acyclicity, content-addressed names, the exact inverse expansion and
// the byte savings from the published bytes alone.
const root = new URL("../", import.meta.url);
const bytes = readFileSync(process.env.PROOFKIT_SCHEMA_DEFINITIONS_CONTRACT || new URL("proofkit/cli-contract.v2.json", root));
const text = bytes.toString("utf8");
// Independently stated installed-carrier ceiling: 8 MiB of growth headroom.
const contractByteCeiling = 8 * 1024 * 1024;

// Numbers keep their exact source token, so canonical bytes match the
// published int64 bounds that a JavaScript number cannot represent.
class SourceNumber {
  constructor(source) { this.source = source; }
}
const lossless = JSON.parse(text, (_key, value, context) => typeof value === "number" ? new SourceNumber(context.source) : value);
const plain = JSON.parse(text);

const byScalar = (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right));
function canonical(value) {
  if (value instanceof SourceNumber) return value.source;
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort(byScalar).map((key) => `${stableJSONStringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  if (typeof value === "string" || typeof value === "boolean") return stableJSONStringify(value);
  throw new Error(`unexpected JSON value ${typeof value}`);
}
const byteLength = (value) => Buffer.byteLength(canonical(value));
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof SourceNumber);

// Draft 2020-12 subschema positions, restated independently of the helper.
// Each subschema is yielded with its JSON pointer relative to schema.
const single = ["additionalProperties", "contains", "contentSchema", "else", "if", "items", "not", "propertyNames", "then", "unevaluatedItems", "unevaluatedProperties"];
const lists = ["allOf", "anyOf", "oneOf", "prefixItems"];
const maps = ["$defs", "dependentSchemas", "patternProperties", "properties"];
const pointerToken = (token) => String(token).replaceAll("~", "~0").replaceAll("/", "~1");
function* subschemas(schema) {
  for (const keyword of Object.keys(schema)) {
    const value = schema[keyword];
    if (single.includes(keyword)) yield [`/${pointerToken(keyword)}`, value];
    if (lists.includes(keyword) && Array.isArray(value)) for (const [index, member] of value.entries()) yield [`/${keyword}/${index}`, member];
    if (maps.includes(keyword) && isObject(value)) for (const name of Object.keys(value)) yield [`/${pointerToken(keyword)}/${pointerToken(name)}`, value[name]];
  }
}

function directDefinition(resource, ref) {
  assert.equal(typeof ref, "string");
  const match = /^#\/\$defs\/([^/]+)$/.exec(decodeURIComponent(ref));
  assert.ok(match, `reference ${ref} names one direct local definition`);
  const name = match[1].replaceAll("~1", "/").replaceAll("~0", "~");
  assert.ok(isObject(resource.$defs) && Object.hasOwn(resource.$defs, name), `reference ${ref} resolves in its resource`);
  const target = resource.$defs[name];
  assert.ok(isObject(target) || typeof target === "boolean", `reference ${ref} targets a schema`);
  return target;
}

// Every reference resolves inside its own resource of the same variant
// document. Shared references never form a cycle, so expansion terminates;
// a cycle may only pass through a source-authored recursive definition (for
// example an arbitrary-JSON value schema), and exactly the same source
// definitions are recursive before and after sharing. A JSON-pointer
// $dynamicRef or $recursiveRef resolves like $ref (draft 2020-12 section
// 8.2.3.2) while Ajv ignores its pointer, so its closure is checked here too.
function assertClosedAndAcyclic(document, label) {
  const recursive = new Set();
  const visit = (schema, resource, sharedPath, sourcePath) => {
    if (!isObject(schema)) return;
    if (Object.hasOwn(schema, "$id") && schema !== document) resource = schema;
    for (const keyword of ["$dynamicRef", "$recursiveRef"]) {
      if (Object.hasOwn(schema, keyword)) directDefinition(resource, schema[keyword]);
    }
    if (Object.hasOwn(schema, "$ref")) {
      const target = directDefinition(resource, schema.$ref);
      const shared = resource === document && schema.$ref.startsWith(`#/$defs/${SHARED_DEFINITION_PREFIX}`);
      if (shared) {
        assert.ok(!sharedPath.has(target), `${label}: shared reference cycle through ${schema.$ref}`);
        visit(target, resource, new Set([...sharedPath, target]), sourcePath);
      } else if (sourcePath.has(target)) {
        recursive.add(sourcePath.get(target));
      } else {
        visit(target, resource, new Set(), new Map([...sourcePath, [target, schema.$ref]]));
      }
    }
    for (const [, child] of subschemas(schema)) visit(child, resource, sharedPath, sourcePath);
  };
  visit(document, document, new Set(), new Map());
  return recursive;
}

// The exact inverse of sharing, written independently of the helper.
function inlineShared(document) {
  const definitions = isObject(document.$defs) ? document.$defs : {};
  const inline = (value) => {
    if (!isObject(value)) return value;
    if (Object.hasOwn(value, "$id") && value !== document) return value;
    if (typeof value.$ref === "string" && value.$ref.startsWith(`#/$defs/${SHARED_DEFINITION_PREFIX}`)) {
      assert.deepEqual(Object.keys(value), ["$ref"], "shared reference is a pure alias");
      return inline(definitions[value.$ref.slice("#/$defs/".length)]);
    }
    const result = {};
    for (const [key, member] of Object.entries(value)) {
      if (single.includes(key)) result[key] = inline(member);
      else if (lists.includes(key) && Array.isArray(member)) result[key] = member.map(inline);
      else if (maps.includes(key) && isObject(member)) {
        result[key] = Object.fromEntries(Object.entries(member).map(([name, child]) => [name, inline(child)]));
      } else result[key] = member;
    }
    return result;
  };
  const expanded = inline(document);
  if (isObject(expanded.$defs)) {
    for (const name of Object.keys(expanded.$defs)) if (name.startsWith(SHARED_DEFINITION_PREFIX)) delete expanded.$defs[name];
    if (Object.keys(expanded.$defs).length === 0) delete expanded.$defs;
  }
  return expanded;
}

const variants = (contract) => contract.contractDefinitions.flatMap((definition, index) =>
  definition.fieldTree.variants.map((variant, variantIndex) => ({definition, index, variantIndex, label: `${definition.definitionId}/${variant.variantId}`, schema: variant.schema})));

test("published definitions keep their canonical digests under an independent encoder", () => {
  for (const definition of lossless.contractDefinitions) {
    const {canonicalDigest, ...record} = definition;
    assert.equal(`sha256:${sha256(canonical(record))}`, canonicalDigest, definition.definitionId);
  }
});

test("every reference resolves inside its own variant document and sharing introduces no cycle", () => {
  let references = 0, recursiveVariants = 0;
  for (const {label, schema} of variants(lossless)) {
    const recursive = assertClosedAndAcyclic(schema, label);
    assert.deepEqual([...recursive].sort(), [...assertClosedAndAcyclic(inlineShared(schema), label + "/expanded")].sort(), `${label}: recursion is inherited from the source`);
    for (const ref of recursive) assert.ok(!ref.startsWith(`#/$defs/${SHARED_DEFINITION_PREFIX}`), `${label}: ${ref} is a source definition`);
    if (recursive.size > 0) recursiveVariants += 1;
    references += (canonical(schema).match(/"\$ref":/g) ?? []).length;
  }
  assert.ok(references > 0);
  assert.ok(recursiveVariants > 0, "the arbitrary-JSON source recursion is exercised");
});

// Returns the bytes one variant saves; throws unless its shared definitions
// are root-only, content-addressed, used at least twice and strictly saving.
function assertSharedPublication(schema, label) {
  const names = Object.keys(isObject(schema.$defs) ? schema.$defs : {}).filter((name) => name.startsWith(SHARED_DEFINITION_PREFIX));
  const published = canonical(schema);
  const expandedText = canonical(inlineShared(schema));
  assert.ok(!expandedText.includes(`"#/$defs/${SHARED_DEFINITION_PREFIX}`), `${label}: expansion keeps no shared reference`);
  // A shared name anywhere but the root $defs would resolve in another scope.
  const nested = [];
  const scan = (value, atRoot) => {
    if (Array.isArray(value)) return value.forEach((member) => scan(member, false));
    if (!isObject(value)) return;
    for (const [key, member] of Object.entries(value)) {
      if (key === "$defs" && isObject(member) && !atRoot) nested.push(...Object.keys(member).filter((name) => name.startsWith(SHARED_DEFINITION_PREFIX)));
      scan(member, false);
    }
  };
  scan(schema, true);
  assert.deepEqual(nested, [], `${label}: shared definitions only at the document root`);
  if (names.length === 0) {
    assert.equal(expandedText, published, `${label}: unshared variant is unchanged`);
    return 0;
  }
  for (const name of names) {
    assert.match(name, /^shared-[0-9a-f]{16}$/, label);
    const content = canonical(inlineShared({$defs: schema.$defs, allOf: [schema.$defs[name]]}).allOf[0]);
    assert.equal(name, SHARED_DEFINITION_PREFIX + sha256(content).slice(0, 16), `${label}: ${name} is addressed by its expanded content`);
    const uses = published.split(`{"$ref":"#/$defs/${name}"}`).length - 1;
    assert.ok(uses >= 2, `${label}: ${name} is referenced ${uses} times`);
  }
  const delta = Buffer.byteLength(expandedText) - Buffer.byteLength(published);
  assert.ok(delta > 0, `${label}: sharing saves bytes (${delta})`);
  return delta;
}

test("shared definitions are root-only, content-addressed, referenced at least twice and save bytes", () => {
  let saved = 0, sharedVariants = 0;
  for (const {label, schema} of variants(lossless)) {
    const delta = assertSharedPublication(schema, label);
    saved += delta;
    if (delta > 0) sharedVariants += 1;
  }
  assert.ok(sharedVariants > 0 && saved > 0, `saved ${saved} bytes in ${sharedVariants} variants`);
  assert.ok(bytes.length < contractByteCeiling, `contract has ${bytes.length} bytes`);
});

// The predicates above must fail on tampered publications, or they prove nothing.
test("oracle predicates reject tampered shared publications", () => {
  const clone = (value) => value instanceof SourceNumber ? value : Array.isArray(value) ? value.map(clone)
    : isObject(value) ? Object.fromEntries(Object.entries(value).map(([key, member]) => [key, clone(member)])) : value;
  const {schema: source, label} = variants(lossless).find(({schema}) =>
    Object.keys(schema.$defs ?? {}).filter((name) => name.startsWith(SHARED_DEFINITION_PREFIX)).length >= 2);
  assertClosedAndAcyclic(source, label);
  assertSharedPublication(source, label);
  const sharedName = (schema) => Object.keys(schema.$defs).find((name) => name.startsWith(SHARED_DEFINITION_PREFIX));
  const firstReferenceAt = (schema, name) => {
    let found;
    const visit = (node, pointer) => {
      if (found || !isObject(node)) return;
      for (const [suffix, child] of subschemas(node)) {
        if (!found && isObject(child) && child.$ref === `#/$defs/${name}`) found = {node: child, pointer: pointer + suffix}; else visit(child, pointer + suffix);
      }
    };
    visit(schema, "");
    return found;
  };
  const firstReference = (schema, name) => firstReferenceAt(schema, name).node;
  const select = (document, pointer) => pointer.split("/").slice(1).map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((node, token) => (isObject(node) || Array.isArray(node)) && Object.hasOwn(node, token) ? node[token] : undefined, document);
  // Points a dynamic reference keyword at a subschema below a shared
  // occurrence: the location exists in the expanded source but not in the
  // publication, where the occurrence is a pure alias.
  const dynamicReferenceIntoSharedOccurrence = (keyword) => (schema) => {
    const name = Object.keys(schema.$defs).find((candidate) => candidate.startsWith(SHARED_DEFINITION_PREFIX)
      && [...subschemas(schema.$defs[candidate])].length > 0 && firstReferenceAt(schema, candidate));
    const [[suffix]] = subschemas(schema.$defs[name]);
    const target = firstReferenceAt(schema, name).pointer + suffix;
    assert.equal(select(schema, target), undefined, `${target} dangles in the publication`);
    assert.notEqual(select(inlineShared(schema), target), undefined, `${target} exists in the source`);
    schema[keyword] = `#${target}`;
  };
  for (const [mutation, tamper] of [
    ["dangling", (schema) => { firstReference(schema, sharedName(schema)).$ref = `#/$defs/${SHARED_DEFINITION_PREFIX}0000000000000000`; }],
    ["cycle", (schema) => { const name = sharedName(schema); schema.$defs[name].not = {$ref: `#/$defs/${name}`}; }],
    ["changed content", (schema) => { schema.$defs[sharedName(schema)].description = "tampered"; }],
    ["single use", (schema) => {
      const name = sharedName(schema), reference = firstReference(schema, name), uses = canonical(schema).split(`{"$ref":"#/$defs/${name}"}`).length - 1;
      delete reference.$ref;
      Object.assign(reference, clone(schema.$defs[name]));
      if (uses === 2) return;
      // Keep exactly one reference by inlining all but the last.
      for (let index = 2; index < uses; index += 1) {
        const next = firstReference(schema, name); delete next.$ref; Object.assign(next, clone(schema.$defs[name]));
      }
    }],
    ["nested shared definition", (schema) => {
      const name = sharedName(schema), target = schema.$defs[name];
      target.$defs = {[name]: clone(target)};
    }],
    ["$dynamicRef into a shared occurrence", dynamicReferenceIntoSharedOccurrence("$dynamicRef")],
    ["$recursiveRef into a shared occurrence", dynamicReferenceIntoSharedOccurrence("$recursiveRef")],
  ]) {
    const schema = clone(source);
    tamper(schema);
    assert.throws(() => { assertClosedAndAcyclic(schema, label); assertSharedPublication(schema, label); }, assert.AssertionError, mutation);
  }
});

test("the shared helper agrees with the independent expansion and resolver", () => {
  for (const {label, schema} of variants(plain)) {
    assert.deepEqual(expandSharedDefinitions(schema), inlineShared(schema), label);
    const walk = (node, resource) => {
      if (!isObject(node)) return;
      if (Object.hasOwn(node, "$id") && node !== schema) resource = node;
      if (Object.hasOwn(node, "$ref")) assert.equal(resolveLocalReference(resource, node.$ref), directDefinition(resource, node.$ref), label);
      for (const [, child] of subschemas(node)) walk(child, resource);
    };
    walk(schema, schema);
  }
});

test("Ajv compiles every published variant with its shared references", () => {
  for (const {label, schema} of variants(plain)) {
    assert.doesNotThrow(() => new Ajv2020({strict: false, validateFormats: false}).compile(schema), label);
  }
});

test("helper refuses invalid shared reference graphs and resolves only direct definitions", () => {
  for (const [label, schema] of [
    ["cycle", {$defs: {"shared-a": {items: {$ref: "#/$defs/shared-b"}}, "shared-b": {items: {$ref: "#/$defs/shared-a"}}}, items: {$ref: "#/$defs/shared-a"}}],
    ["missing", {items: {$ref: "#/$defs/shared-missing"}}],
    ["impure alias", {$defs: {"shared-a": {type: "string"}}, items: {$ref: "#/$defs/shared-a", maxLength: 3}}],
  ]) assert.throws(() => expandSharedDefinitions(schema), Error, label);
  const resource = {$defs: {item: {type: "string"}, "a/b": true, data: 3}};
  assert.deepEqual(resolveLocalReference(resource, "#/$defs/item"), {type: "string"});
  assert.equal(resolveLocalReference(resource, "#/$defs/a~1b"), true);
  assert.deepEqual(resolveLocalReference(resource, "#/$defs/it%65m"), {type: "string"});
  for (const ref of ["#/$defs/data", "#/$defs/missing", "#/$defs/a/b", "#/$defs/a~2b", "#/$defs/%zz", "#/properties/item", "#item", "item.json", 7]) {
    assert.throws(() => resolveLocalReference(resource, ref), Error, String(ref));
  }
  // Embedded resources keep their own definitions, including reserved-looking names.
  const embedded = {properties: {r: {$id: "urn:x", $defs: {"shared-a": {type: "string"}}, items: {$ref: "#/$defs/shared-a"}}}};
  assert.deepEqual(expandSharedDefinitions(embedded), embedded);
});

test("variant unions keep oneOf semantics while each variant resolves its own definitions", () => {
  const shared = {$defs: {"shared-0123456789abcdef": {type: "string", maxLength: 3}}, type: "object", properties: {a: {$ref: "#/$defs/shared-0123456789abcdef"}}, required: ["a"]};
  const other = {type: "object", properties: {b: {type: "integer"}}, required: ["b"]};
  const union = compileVariantUnion(() => new Ajv2020({strict: false}), [shared, other]);
  assert.equal(union({a: "abc"}), true);
  assert.equal(union({a: "abcd"}), false);
  assert.ok(union.errors.length > 0);
  assert.equal(union({a: "x", b: 1}), false, "matching two variants violates oneOf");
  assert.equal(union({b: 1}), true);
  assert.throws(() => new Ajv2020({strict: false}).compile({oneOf: [shared, other]}), "embedding a variant leaves its shared references dangling");
});
