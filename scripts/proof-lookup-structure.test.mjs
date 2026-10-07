import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {before, after} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const root = new URL('../', import.meta.url);
const source = 'requirement-proof-source-set', view = 'requirement-proof-view';
const baseline = JSON.parse(readFileSync(new URL('internal/app/testdata/proof-lookup-native-observations.json', root)));
assert.equal(baseline.head, 'a9f3964d1ca6b5526ee3cab6ba20d7e59f18acba');
assert.equal(baseline.tree, 'f7379a302945b684346604c21e68f26e8fe4f49b');
assert.equal(baseline.observations.length, 73);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_LOOKUP_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const validators = Object.fromEntries([source, view].map(command => [command, Object.fromEntries(['input', 'output'].map(direction => {
  const id = `proofkit.${command}.${direction}.v2.json-schema`;
  assert.equal(contract.commands.find(x => x.command === command)[direction + 'Contract'].rootDefinitionRef, id);
  return [direction, contract.contractDefinitions.find(x => x.definitionId === id).fieldTree.variants.map(row => {
    const ajv = new Ajv2020({strict: false, validateFormats: false});
    return {id: row.variantId, check: ajv.compile(row.schema)};
  })];
}))]));
function valid(command, direction, value) {
  const matches = validators[command][direction].filter(row => row.check(value));
  return matches.length === 1;
}
const hash = value => createHash('sha256').update(value).digest('hex');
const seed = name => JSON.parse(baseline.observations.find(row => row.name === name).input);
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-lookup-')); binary = join(directory, 'agentic-proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {cwd: root, timeout: 120000,
    env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'}});
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
function invoke(command, value, flags = []) {
  const result = spawnSync(binary, [command, '--input', '-', ...flags], {
    input: JSON.stringify(value), encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20});
  assert.equal(result.error, undefined); assert.equal(result.signal, null); return result;
}
function output(command, input, flags = []) {
  const result = invoke(command, input, flags);
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  const record = JSON.parse(result.stdout);
  assert.ok(valid(command, 'input', input)); assert.ok(valid(command, 'output', record));
  return record;
}

test('lookup contracts conserve73actual predecessor process and rendered streams', () => {
  for (const row of baseline.observations) {
    const result = spawnSync(binary, row.argv, {input: row.carrier === 'stdin' ? row.input : undefined,
      stdio: row.carrier === 'argv-only' ? ['ignore', 'pipe', 'pipe'] : undefined,
      encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20});
    assert.equal(result.error, undefined); assert.equal(result.signal, null);
    assert.equal(result.status, row.exitCode, row.name);
    assert.equal(hash(result.stdout), row.stdoutSHA256, row.name + '/stdout');
    assert.equal(hash(result.stderr), row.stderrSHA256, row.name + '/stderr');
    if (row.exitCode || row.format !== 'json') continue;
    const input = row.name === 'pointer' ? JSON.parse(row.input).payload : JSON.parse(row.input);
    assert.ok(valid(row.command, 'input', input), row.name + '/input');
    assert.ok(valid(row.command, 'output', JSON.parse(result.stdout)), row.name + '/output');
  }
});

test('source index selection preserves order and composes into resolver and view', () => {
  const input = seed('fragments');
  input.projection = {selectedSourceIds: input.sourceSet.sources.map(row => row[0]).reverse()};
  const canonical = output(source, input);
  assert.deepEqual(canonical.selectedSourceIds, input.sourceSet.sources.map(row => row[0]));
  assert.deepEqual(canonical.inputPaths, input.sourceSet.sources.map(row => row[1]).sort());
  assert.equal(canonical.sourceCount, 2); assert.equal(canonical.sourceSetCount, 2);
  assert.equal(canonical.contract.contract_id, input.canonicalEnvelope.contractId);
  input.projection.kind = 'resolver_input';
  const resolved = output(source, input);
  assert.equal(resolved.projectionKind, 'proofkit.requirement-proof-source-set.resolver_input');
  const routes = invoke('requirement-proof-resolver', resolved.resolverInput, ['--local-environment-class', 'local-go']);
  assert.equal(routes.status, 0, routes.stderr); const resolver = JSON.parse(routes.stdout);
  const lookup = output(view, resolved.resolverInput, ['--local-environment-class', 'local-go']);
  assert.equal(lookup.authority, 'lookup_only'); assert.equal(lookup.bindingCount, resolver.bindings.length);
  assert.equal(lookup.commandCount, resolver.commands.length); assert.equal(lookup.requirementCount, new Set(resolver.bindings.map(x => x.requirementId)).size);
  assert.equal(lookup.preconditionedBindingCount, resolver.bindings.filter(x => x.preconditioned).length);
  assert.deepEqual(lookup.bindings.map(x => x.declaredWitnessRoutes.map(r => r.role)), resolver.bindings.map(() => ['falsification', 'positive']));
  for (const binding of lookup.bindings) for (const route of binding.declaredWitnessRoutes) assert.equal(route.bindingRecordId, binding.bindingRecordId);
});

const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, replacement) {
  if (!path.length) return replacement;
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = replacement; return copy;
}
function walk(value, path = [], result = []) {
  result.push({path, value});
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) walk(child, [...path, Array.isArray(value) ? Number(key) : key], result);
  return result;
}
test('populated lookup variants close all object members and nonnull type boundaries', () => {
  let checked = 0;
  for (const [command, name, flags] of [[source, 'canonical', []], [source, 'canonical-resolver', []],
    [view, 'structured', []], [view, 'compact', ['--local-environment-class', 'local-go']]]) {
    const input = seed(name);
    if (command === source) input.projection = {kind: name.endsWith('resolver') ? 'resolver_input' : 'canonical_contract', selectedSourceIds: input.sourceSet.sources.map(row => row[0])};
    const record = output(command, input, flags);
    for (const [direction, specimen] of [['input', input], ['output', record]]) {
      for (const {path, value} of walk(specimen)) {
        const optional = command === source && direction === 'input' && (path.join('.') === 'projection' || path.join('.') === 'projection.kind' || path.join('.') === 'projection.selectedSourceIds')
          || command === view && direction === 'input' && name === 'structured' && (path[0] === 'selection' || path.at(-1) === 'witnessSelectors');
        if (value && !Array.isArray(value) && typeof value === 'object') {
          const unknown = structuredClone(specimen); at(unknown, path).foreign = true;
          assert.equal(valid(command, direction, unknown), false, `${name}/${direction}/${path}/unknown`);
          for (const key of Object.keys(value)) {
            const field = [...path, key], missing = structuredClone(specimen); delete at(missing, path)[key];
            const mayOmit = command === source && direction === 'input' && field[0] === 'projection'
              || command === view && direction === 'input' && name === 'structured' && (field[0] === 'selection' || key === 'witnessSelectors');
            assert.equal(valid(command, direction, missing), mayOmit, `${name}/${direction}/${field}/missing`);
          }
        }
        assert.equal(valid(command, direction, replace(specimen, path, null)), optional, `${name}/${direction}/${path}/null`);
        const wrong = typeof value === 'string' || value === null ? 0 : 'wrong-type';
        assert.equal(valid(command, direction, replace(specimen, path, wrong)), false, `${name}/${direction}/${path}/type`); checked++;
        if (typeof value === 'string' && (command === source || direction === 'output')) {
          assert.equal(valid(command, direction, replace(specimen, path, '')), false, `${name}/${direction}/${path}/empty`);
        }
      }
    }
  }
  assert.ok(checked > 350);
});

test('source index literals raw enums strict whitespace IDs and tuple arities are exact', () => {
  const input = seed('canonical');
  const populated = structuredClone(input);
  populated.projection = {kind: 'canonical_contract', selectedSourceIds: [input.sourceSet.sources[0][0]]};
  for (const {path, value} of walk(populated)) {
    if (typeof value !== 'string' || path[0] === 'sources' && path.at(-1) === 'text') continue;
    for (const padded of [' ' + value, value + '\n', '\u00a0' + value]) {
      assert.equal(valid(source, 'input', replace(populated, path, padded)), false, 'strict-input/' + path.join('.'));
    }
  }
  const paths = [['schemaVersion'], ['sourceSet', 'schema_version'], ['sourceSet', 'contract_kind'], ['sourceSet', 'contract_id'],
    ['sourceSet', 'authority_state'], ['sourceSet', 'normalization_profile'], ['canonicalEnvelope', 'schemaVersion'],
    ['canonicalEnvelope', 'contractKind'], ['canonicalEnvelope', 'authorityState'], ['canonicalEnvelope', 'normalizationProfile']];
  for (const path of paths) assert.equal(valid(source, 'input', replace(input, path, typeof at(input, path) === 'number' ? 3 : 'foreign')), false, path.join('.'));
  for (const path of [['sourceSet', 'source_columns'], ['canonicalEnvelope', 'surfaceColumns'], ['canonicalEnvelope', 'bindingColumns'], ['canonicalEnvelope', 'witnessColumns']]) {
    const columns = at(input, path);
    for (const invalid of [columns.slice(0, -1), [...columns, 'foreign'], columns.toReversed(), ...columns.map((_, index) => columns.map((x, i) => i === index ? 'foreign' : x))]) assert.equal(valid(source, 'input', replace(input, path, invalid)), false, path.join('.'));
  }
  for (const path of [['canonicalEnvelope', 'contractId'], ['sources', 0, 'path'], ['sourceSet', 'sources', 0, 1]]) {
    for (const value of ['', ' ', '\u00a0', ' padded', 'padded\n']) assert.equal(valid(source, 'input', replace(input, path, value)), false, path.join('.'));
    assert.equal(valid(source, 'input', replace(input, path, '\ufeff')), true, 'BOM is not Go TrimSpace whitespace');
  }
  const id = ['sourceSet', 'sources', 0, 0];
  for (const value of ['a'.repeat(256), 'source.example']) assert.ok(valid(source, 'input', replace(input, id, value)));
  for (const value of ['', 'a'.repeat(257), ' source.example', 'source/example']) assert.equal(valid(source, 'input', replace(input, id, value)), false);
  const selected = ['projection', 'selectedSourceIds', 0];
  for (const length of [256, 257]) {
    assert.equal(valid(source, 'input', replace(populated, selected, 'a'.repeat(length))), length === 256, 'selected-input/length-' + length);
  }
  const bounded = replace(populated, id, 'a'.repeat(256));
  bounded.projection.selectedSourceIds = ['a'.repeat(256)];
  assert.deepEqual(output(source, bounded).selectedSourceIds, bounded.projection.selectedSourceIds);
  assert.equal(invoke(source, replace(bounded, selected, 'a'.repeat(257))).status, 1);
  for (const value of ['', '0'.repeat(63), 'A'.repeat(64), 'sha256:' + '0'.repeat(64)]) assert.equal(valid(source, 'input', replace(input, ['sourceSet', 'sources', 0, 2], value)), false);
  for (const role of ['foreign', ' requirement_proof_route_declaration_contract ']) assert.equal(valid(source, 'input', replace(input, ['sourceSet', 'sources', 0, 3], role)), false);
  for (const row of [input.sourceSet.sources[0].slice(0, -1), [...input.sourceSet.sources[0], 'foreign']]) assert.equal(valid(source, 'input', replace(input, ['sourceSet', 'sources', 0], row)), false);
  for (const path of [['canonicalEnvelope', 'nonClaims'], ['sourceSet', 'non_claims'], ['sourceSet', 'sources'], ['sourceSet', 'sources', 0, 4]]) assert.equal(valid(source, 'input', replace(input, path, [])), false);
  assert.ok(valid(source, 'input', replace(input, ['sources'], [])), 'cross-reference absence is native, not structural');
  assert.ok(valid(source, 'input', replace(input, ['sources', 0, 'text'], ' ')), 'raw nonempty text is not trimmed');
  assert.equal(valid(source, 'input', replace(input, ['sources', 0, 'text'], '')), false);
  for (const projection of [null, {}, {kind: null, selectedSourceIds: null}, {kind: 'canonical_contract'}, {kind: 'resolver_input'}]) assert.ok(valid(source, 'input', replace(input, ['projection'], projection)));
  for (const projection of [{kind: ' resolver_input '}, {kind: 'foreign'}, {selectedSourceIds: []}, {selectedSourceIds: [' a']}]) assert.equal(valid(source, 'input', replace(input, ['projection'], projection)), false);
});

test('lookup output identities wire versions counts and ordered route roles are independent', () => {
  for (const [command, name, flags, version] of [[source, 'canonical', [], 2], [source, 'canonical-resolver', [], 2], [view, 'structured', [], 1], [view, 'compact', ['--local-environment-class', 'local-go'], 2]]) {
    const record = output(command, seed(name), flags);
    assert.equal(record.schemaVersion, version);
    for (const key of ['schemaVersion', command === source ? 'projectionKind' : 'viewKind', ...(command === view ? ['authority'] : [])]) {
      assert.equal(valid(command, 'output', replace(record, [key], typeof record[key] === 'number' ? 99 : 'foreign')), false, name + '/' + key);
    }
    for (const key of Object.keys(record).filter(x => x.endsWith('Count'))) {
      for (const value of [-1, 1.5, '0', ...(command === source ? [0] : [])]) assert.equal(valid(command, 'output', replace(record, [key], value)), false, name + '/' + key);
    }
    if (name !== 'compact') continue;
    const path = ['bindings', 0, 'declaredWitnessRoutes'], routes = at(record, path);
    for (const value of [[], routes.slice(0, -1), [...routes, routes[0]], routes.toReversed()]) assert.equal(valid(command, 'output', replace(record, path, value)), false);
    for (const index of [0, 1]) {
      assert.equal(valid(command, 'output', replace(record, [...path, index, 'role'], 'foreign')), false);
      for (const value of [-1, 0.5, 9007199254740992]) assert.equal(valid(command, 'output', replace(record, [...path, index, 'resolutionOrderIndex'], value)), false);
      for (const field of ['bindingRecordId', 'witnessRouteId']) assert.equal(valid(command, 'output', replace(record, [...path, index, field], 'sha256:' + 'A'.repeat(64))), false);
    }
    assert.equal(valid(command, 'output', replace(record, ['localEnvironmentPolicy', 'authority'], 'foreign')), false);
  }
});

test('view output scope and structured classifications retain their owned domains', () => {
  const record = output(view, seed('structured'));
  for (const value of ['foreign', ' slice ']) assert.equal(valid(view, 'output', replace(record, ['scope'], value)), false);
  for (const path of [['requirements', 0, 'claimLevel'], ['requirements', 0, 'proofState'], ['requirements', 0, 'scenarios', 0, 'witnessKind']]) {
    assert.equal(valid(view, 'output', replace(record, path, 'foreign')), false, path.join('.'));
  }
  const count = ['requirements', 0, 'scenarioCount'];
  for (const value of [-1, 1.5, '0']) assert.equal(valid(view, 'output', replace(record, count, value)), false);
  for (const [name, flags, minimum] of [['structured', [], 4], ['compact', ['--local-environment-class', 'local-go'], 6]]) {
    const specimen = output(view, seed(name), flags);
    for (const value of [[], specimen.nonClaims.slice(0, minimum - 1)]) assert.equal(valid(view, 'output', replace(specimen, ['nonClaims'], value)), false);
  }
});

test('empty declarations retain zero counts and explicit empty local policy', () => {
  const compact = seed('compact'); compact.surfaces = []; compact.bindings = []; compact.non_claims = [];
  const lookup = output(view, compact, ['--empty-local-environment-policy']);
  assert.deepEqual(lookup.bindings, []); assert.deepEqual(lookup.localEnvironmentPolicy, {authority: 'caller_provided', localEnvironmentClasses: []});
  for (const field of ['bindingCount', 'commandCount', 'preconditionedBindingCount', 'requirementCount']) assert.equal(lookup[field], 0);
  const structured = seed('structured'); structured.requirements = []; structured.bindings = []; structured.witnessCommands = []; structured.selection = null;
  const empty = output(view, structured); assert.deepEqual(empty.requirements, []);
  for (const field of ['commandCount', 'omittedRequirementCount', 'requirementCount']) assert.equal(empty[field], 0);
  assert.equal(empty.scope, 'slice'); assert.ok(empty.nonClaims.length >= 4);
});

test('unbound structured requirements retain zero scenarios and empty aggregates', () => {
  const input = seed('structured');
  input.bindings = []; input.witnessCommands = [];
  input.requirements[0].claimLevel = 'advisory'; input.requirements[0].proofState = 'not_bound';
  for (const scope of ['graph', 'slice']) {
    const record = output(view, input, ['--scope', scope]);
    assert.equal(record.scope, scope); assert.equal(record.requirementCount, 1); assert.equal(record.commandCount, 0);
    assert.equal(record.requirements.length, 1); assert.equal(record.requirements[0].requirementId, 'REQ-PROOFKIT-ONE');
    assert.equal(record.requirements[0].proofState, 'not_bound'); assert.equal(record.requirements[0].scenarioCount, 0);
    for (const field of ['scenarios', 'commandIds', 'environmentClasses', 'witnessPaths']) assert.deepEqual(record.requirements[0][field], [], field);
  }
});

test('source output array minima and canonical child headers have separating neighbors', () => {
  for (const name of ['canonical', 'canonical-resolver']) {
    const record = output(source, seed(name));
    for (const field of ['inputPaths', 'selectedSourceIds']) {
      assert.equal(record[field].length, 1);
      assert.ok(valid(source, 'output', replace(record, [field], [record[field][0]])), name + '/' + field + '/singleton');
      assert.equal(valid(source, 'output', replace(record, [field], [])), false, name + '/' + field + '/empty');
      assert.equal(valid(source, 'output', replace(record, [field, 0], ' padded ')), false, name + '/' + field + '/padding');
    }
    for (const value of ['foreign/id', 'a'.repeat(257)]) assert.equal(valid(source, 'output', replace(record, ['selectedSourceIds', 0], value)), false);
  }
  const input = seed('canonical'), payload = JSON.parse(input.sources[0].text);
  payload.surfaces = []; payload.bindings = [];
  input.sources[0].text = JSON.stringify(payload); input.sourceSet.sources[0][2] = hash(input.sources[0].text);
  const record = output(source, input); assert.deepEqual(record.contract.surfaces, []); assert.deepEqual(record.contract.bindings, []);
  for (const field of ['schema_version', 'contract_kind', 'authority_state', 'normalization_profile']) {
    assert.equal(valid(source, 'output', replace(record, ['contract', field], field === 'schema_version' ? 3 : 'foreign')), false, field);
  }
  for (const field of ['surface_columns', 'binding_columns', 'witness_columns']) {
    const columns = record.contract[field];
    for (const value of [columns.slice(0, -1), [...columns, 'foreign'], columns.toReversed(), ...columns.map((_, index) => columns.map((x, i) => i === index ? 'foreign' : x))]) {
      assert.equal(valid(source, 'output', replace(record, ['contract', field], value)), false, field);
    }
  }
  assert.equal(valid(source, 'output', replace(record, ['contract', 'non_claims'], [])), false);
  for (const [index, value] of record.contract.non_claims.entries()) {
    assert.ok(valid(source, 'output', replace(record, ['contract', 'non_claims', index], value)));
    for (const padded of [' ' + value, value + '\n', '\u00a0' + value]) {
      assert.equal(valid(source, 'output', replace(record, ['contract', 'non_claims', index], padded)), false, 'canonical-output/nonclaim-' + index + '/padding');
    }
  }
  for (const value of [' padded', 'padded\n']) assert.equal(valid(source, 'output', replace(record, ['contract', 'contract_id'], value)), false);
});
