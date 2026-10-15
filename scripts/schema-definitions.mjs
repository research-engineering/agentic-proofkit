// Local JSON Schema definition references for published CLI contract schemas.
//
// The contract generator publishes each variant schema with repeated subtrees
// shared through root $defs entries named SHARED_DEFINITION_PREFIX plus a
// content digest. Oracles validate with the published schema (Ajv resolves the
// references) and navigate the expansion returned by expandSharedDefinitions,
// which inlines exactly those shared entries again.

export const SHARED_DEFINITION_PREFIX = "shared-";

const SHARED_REFERENCE_PREFIX = `#/$defs/${SHARED_DEFINITION_PREFIX}`;

// Draft 2020-12 keywords whose values hold subschemas; every other keyword
// value (const, enum, required, default, annotations) is data.
const SINGLE_SUBSCHEMA = new Set([
  "additionalProperties", "contains", "contentSchema", "else", "if", "items", "not",
  "propertyNames", "then", "unevaluatedItems", "unevaluatedProperties",
]);
const SUBSCHEMA_LIST = new Set(["allOf", "anyOf", "oneOf", "prefixItems"]);
const SUBSCHEMA_MAP = new Set(["$defs", "dependentSchemas", "patternProperties", "properties"]);

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

// Calls visit(value, replace) for each subschema directly below schema.
export function forEachSubschema(schema, visit) {
  for (const keyword of Object.keys(schema).sort()) {
    const value = schema[keyword];
    if (SINGLE_SUBSCHEMA.has(keyword)) {
      visit(value, (next) => { schema[keyword] = next; }, keyword);
    } else if (SUBSCHEMA_LIST.has(keyword) && Array.isArray(value)) {
      value.forEach((member, index) => visit(member, (next) => { value[index] = next; }, keyword));
    } else if (SUBSCHEMA_MAP.has(keyword) && isObject(value)) {
      for (const name of Object.keys(value).sort()) visit(value[name], (next) => { value[name] = next; }, keyword);
    }
  }
}

// Resolves a URI fragment naming one direct $defs entry of resource, the
// nearest enclosing schema resource root. Throws when it does not resolve.
export function resolveLocalReference(resource, ref) {
  if (typeof ref !== "string" || !ref.startsWith("#")) throw new Error(`schema reference is not a local fragment: ${ref}`);
  let pointer;
  try {
    pointer = decodeURIComponent(ref.slice(1));
  } catch {
    throw new Error(`schema reference has an invalid percent encoding: ${ref}`);
  }
  if (!pointer.startsWith("/$defs/")) throw new Error(`schema reference must name one direct local definition: ${ref}`);
  const token = pointer.slice("/$defs/".length);
  if (token === "" || token.includes("/") || /~(?![01])/.test(token)) {
    throw new Error(`schema reference must name one direct local definition: ${ref}`);
  }
  const name = token.replaceAll("~1", "/").replaceAll("~0", "~");
  const definitions = resource.$defs;
  if (!isObject(definitions) || !Object.hasOwn(definitions, name)) throw new Error(`schema reference has no local definition: ${ref}`);
  const target = definitions[name];
  if (!isObject(target) && typeof target !== "boolean") throw new Error(`schema reference target is not a schema: ${ref}`);
  return target;
}

// Returns a copy of a published schema with every shared definition reference
// inlined and the shared definitions removed. Embedded resources ($id) and all
// other references are kept as published.
export function expandSharedDefinitions(schema) {
  const root = structuredClone(schema);
  const definitions = isObject(root.$defs) ? root.$defs : {};
  const shared = new Map();
  for (const name of Object.keys(definitions)) {
    if (name.startsWith(SHARED_DEFINITION_PREFIX)) {
      shared.set(name, definitions[name]);
      delete definitions[name];
    }
  }
  const expanded = new Map();
  const active = new Set();
  const expandDefinition = (name) => {
    if (expanded.has(name)) return expanded.get(name);
    if (active.has(name)) throw new Error(`shared schema definitions form a cycle at ${name}`);
    if (!shared.has(name)) throw new Error(`shared schema reference has no definition: ${name}`);
    active.add(name);
    let value = structuredClone(shared.get(name));
    expandSchema(value, (next) => { value = next; });
    active.delete(name);
    expanded.set(name, value);
    return value;
  };
  const expandSchema = (value, replace) => {
    if (!isObject(value) || Object.hasOwn(value, "$id")) return;
    if (typeof value.$ref === "string" && value.$ref.startsWith(SHARED_REFERENCE_PREFIX)) {
      if (Object.keys(value).length !== 1) throw new Error(`shared schema reference must be a pure alias: ${value.$ref}`);
      replace(structuredClone(expandDefinition(value.$ref.slice("#/$defs/".length))));
      return;
    }
    forEachSubschema(value, expandSchema);
  };
  forEachSubschema(root, expandSchema);
  if (shared.size !== 0 && Object.keys(definitions).length === 0) delete root.$defs;
  return root;
}

// Validates like {oneOf: schemas} while compiling each published variant as
// its own document: a variant's shared definitions resolve only at its root,
// so embedding it as a subschema of a new document would leave them dangling.
export function compileVariantUnion(createAjv, schemas) {
  const checks = schemas.map((schema) => createAjv().compile(schema));
  const union = (value) => {
    const matched = checks.filter((check) => check(value)).length;
    union.errors = matched === 1 ? null : matched === 0
      ? checks.flatMap((check) => check.errors ?? [])
      : [{instancePath: "", keyword: "oneOf", message: `must match exactly one schema in oneOf, matched ${matched}`}];
    return matched === 1;
  };
  union.errors = null;
  return union;
}
