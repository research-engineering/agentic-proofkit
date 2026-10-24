import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {get, request as httpRequest} from 'node:http';
import {tmpdir} from 'node:os';
import {delimiter, join} from 'node:path';
import test, {after, before} from 'node:test';
import {setTimeout as sleep} from 'node:timers/promises';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport, spawnWithInputFile} from './cli-process.mjs';
import {bindingInput, resolverInput} from './proof-routing-fixtures.mjs';
import {directComposeInput, inventoryInput, normalizedComposeInput, requirementSource} from './inventory-coverage-fixtures.mjs';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_BROWSER_CONTRACT || new URL('proofkit/cli-contract.v2.json', root), 'utf8'));

// Independently authored public identities, conditions and root inventories.
const coverageKeys = ['compactProofContract', 'coverageUniverse', 'localEnvironmentPolicy', 'normalizedTestEvidenceInventory', 'options',
  'ownerInvariantRegistry', 'requirementProofBinding', 'requirementSource', 'schemaVersion', 'testEvidenceInventory', 'viewInputId'];
const compactKeys = ['authority_state', 'binding_columns', 'bindings', 'contract_id', 'contract_kind', 'non_claims', 'normalization_profile',
  'schema_version', 'surface_columns', 'surfaces', 'witness_columns'];
const inputVariants = [
  {id: '01-coverage-compact', when: '--view coverage; compact proof', view: 'coverage', allowed: coverageKeys,
    required: ['compactProofContract', 'coverageUniverse', 'localEnvironmentPolicy', 'requirementSource', 'schemaVersion', 'viewInputId']},
  {id: '02-coverage-structured', when: '--view coverage; structured proof', view: 'coverage', allowed: coverageKeys,
    required: ['coverageUniverse', 'requirementProofBinding', 'requirementSource', 'schemaVersion', 'viewInputId']},
  {id: '03-proof-compact', when: '--view proof; compact proof', view: 'proof', allowed: compactKeys, required: compactKeys},
  {id: '04-proof-structured', when: '--view proof; structured proof', view: 'proof',
    allowed: ['bindingId', 'bindings', 'nonClaims', 'requirements', 'schemaVersion', 'selection', 'witnessCommands'],
    required: ['bindingId', 'bindings', 'nonClaims', 'requirements', 'schemaVersion', 'witnessCommands']},
  {id: '05-source', when: '--view source', view: 'source',
    allowed: ['derivations', 'groups', 'kind', 'nonClaimDefinitions', 'profiles', 'scenarios', 'schemaVersion', 'sourceId', 'sourceNonClaimRefs',
      'sourceNonClaims', 'specPackagePath', 'vocabulary'],
    required: ['groups', 'kind', 'schemaVersion', 'sourceId', 'sourceNonClaims', 'specPackagePath']},
  {id: '06-spec-tree', when: '--view spec-tree', view: 'spec-tree',
    allowed: ['callerAnnotations', 'edges', 'nodes', 'overlays', 'rootNodeId', 'schemaVersion', 'treeId'],
    required: ['callerAnnotations', 'edges', 'nodes', 'overlays', 'rootNodeId', 'schemaVersion', 'treeId']},
  {id: '07-workspace', when: '--view workspace', view: 'workspace', allowed: ['context', 'diffInput', 'graphInput', 'schemaVersion', 'workspaceId'],
    required: ['context', 'schemaVersion', 'workspaceId']},
];
const views = ['coverage', 'proof', 'source', 'spec-tree', 'workspace'];
const planKeys = ['authority', 'host', 'htmlByteLength', 'nonClaims', 'planKind', 'port', 'portSelection', 'renderedAuthority', 'renderedViewKind',
  'schemaVersion', 'url', 'view'];
const terminalKeys = ['handoffKind', 'nonClaims', 'schemaVersion', 'snapshotRefs', 'state'];
const submittedKeys = ['annotations', 'context', 'handoffKind', 'instructionAuthority', 'nonClaims', 'schemaVersion', 'snapshotRefs',
  'sourceTextAuthority', 'state'];
const annotationKeys = ['anchor', 'endCodePoint', 'exactQuote', 'prefix', 'question', 'startCodePoint', 'suffix', 'targetId'];
const anchorKeys = ['anchorId', 'coordinateSpace', 'jsonPointer', 'requirementId', 'sourceDigest', 'sourceId'];
const oneShot = '--open; --serve; --session-mode one-shot-question';
const directions = {
  input: {command: 'requirement-browser-server', direction: 'input', contractId: 'proofkit.requirement-browser-server.input.v4', version: 4,
    id: 'proofkit.requirement-browser-server.input.v4.json-schema', predecessor: 'proofkit.requirement-browser-server.input.v4.root-shape',
    variants: inputVariants.map(row => [row.id, row.when, row.allowed, row.required])},
  output: {command: 'requirement-browser-server', direction: 'output', contractId: 'proofkit.requirement-browser-server.output.v2', version: 2,
    id: 'proofkit.requirement-browser-server.output.v2.json-schema', predecessor: 'proofkit.requirement-browser-server.output.v2.root-shape',
    variants: [...views.map(view => ['01-plan-' + view, 'without --serve; --view ' + view, planKeys, planKeys]),
      ['02-one-shot-terminal', oneShot + '; --view workspace; state=cancelled|expired', terminalKeys, terminalKeys],
      ['03-one-shot-submitted', oneShot + '; --view workspace; state=submitted', submittedKeys, submittedKeys]]},
  view: {command: 'view', direction: 'output', contractId: 'proofkit.view.output.v2', version: 1,
    id: 'proofkit.view.output.v2.json-schema', predecessor: 'proofkit.view.output.v1.root-shape',
    variants: [['01-plan', 'without --serve', planKeys, planKeys],
      ['02-one-shot-terminal', oneShot + '; state=cancelled|expired', terminalKeys, terminalKeys],
      ['03-one-shot-submitted', oneShot + '; state=submitted', submittedKeys, submittedKeys]]},
};
const serverClaims = [
  'Requirement browser servers are local presentation adapters only.',
  'Explicit project preparation inspects repository state; serving the admitted immutable snapshot does not rescan it.',
  'Requirement browser servers do not execute native witnesses.',
  'Requirement browser servers do not prove receipt freshness, merge approval, or rollout readiness.',
  'Requirement browser servers do not persist browser annotations into source files.',
  'Requirement browser servers do not authenticate the surrounding browser profile or operating-system user.',
];
const rendered = {
  coverage: [['proofkit.requirement-coverage-view'], 'lookup_only'],
  proof: [['proofkit.compact-requirement-proof-view', 'proofkit.requirement-proof-view'], 'lookup_only'],
  source: [['proofkit.requirement-source-view'], 'presentation_only'],
  'spec-tree': [['proofkit.requirement-spec-tree-view'], 'presentation_only'],
  workspace: [['proofkit.requirement-workspace'], 'presentation_adapter'],
};

// Variants are independent schema documents selected by flags. Some reuse the
// same owner resource identity, so each compiles in its own validator.
const checks = Object.fromEntries(Object.entries(directions).map(([key, row]) => {
  const binding = contract.commands.find(command => command.command === row.command)[row.direction + 'Contract'];
  const definition = contract.contractDefinitions.find(item => item.definitionId === binding.rootDefinitionRef);
  assert.equal(definition?.fieldTree.kind, 'structural_json_schema', key);
  return [key, new Map(definition.fieldTree.variants.map(variant => [variant.variantId,
    new Ajv2020({strict: false, validateFormats: false}).compile(variant.schema)]))];
}));
function valid(key, variant, value, expected = true, label = '') {
  const check = checks[key].get(variant);
  assert.ok(check, `${key}/${variant} is not published`);
  assert.equal(check(value), expected, `${key}/${variant}/${label}: ${JSON.stringify(check.errors?.slice(0, 2))}`);
}
const selected = (key, value) => [...checks[key]].filter(([, check]) => check(value)).map(([id]) => id);
const clone = value => structuredClone(value);
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replaced(value, path, next) {
  const copy = clone(value);
  if (next === undefined) delete at(copy, path.slice(0, -1))[path.at(-1)];
  else at(copy, path.slice(0, -1))[path.at(-1)] = next;
  return copy;
}
function objectPaths(value, path = []) {
  if (!value || typeof value !== 'object') return [];
  const nested = Object.entries(value).flatMap(([key, child]) => objectPaths(child, [...path, Array.isArray(value) ? Number(key) : key]));
  return Array.isArray(value) ? nested : [path, ...nested];
}
function leafPaths(value, path = []) {
  if (value === null || typeof value !== 'object') return [path];
  return Object.entries(value).flatMap(([key, child]) => leafPaths(child, [...path, Array.isArray(value) ? Number(key) : key]));
}
const snapshotRefsOf = value => clone(value.snapshotRefs);
const flipped = value => typeof value === 'string' ? 7 : typeof value === 'number' ? String(value) : typeof value === 'boolean' ? 'true' : value === null ? false : null;

let directory, binary;
const fixtures = {};
function spawnCLI(args, input, options = {}) {
  return spawnWithInputFile(binary, args, {input: input === undefined ? '' : JSON.stringify(input),
    encoding: 'utf8', timeout: 30000, maxBuffer: 32 << 20, ...options});
}
function run(args, input, options = {}) {
  return assertCLITransport(spawnCLI(args, input, options), args.join(' '));
}
function json(args, input) {
  const result = run(args, input);
  assert.equal(result.status, 0, `${args.join(' ')}: ${result.stderr}`); assert.equal(result.stderr, '');
  return JSON.parse(result.stdout);
}
const browserArgs = (view, flags = []) => ['requirement-browser-server', '--input', '-', '--view', view, ...flags];
function refusedResult(result, label) {
  assert.equal(result.status, 1, `${label}: ${result.stdout}`); assert.equal(result.stdout, '', label); assert.notEqual(result.stderr, '', label);
}
function refused(args, input, label) {
  const result = assertCLITransport(spawnCLI(args, input), label);
  refusedResult(result, label);
  return result;
}
// A browser plan is admitted output only through the exactly selected variant.
function plan(view, input, flags = [], key = 'output') {
  const value = json(browserArgs(view, flags), input);
  assertPlan(key, key === 'view' ? '01-plan' : '01-plan-' + view, value, view);
  return value;
}
function assertPlan(key, variant, value, view) {
  assert.deepEqual(Object.keys(value).sort(), planKeys);
  assert.deepEqual(selected(key, value), [variant], `${variant} selection`);
  assert.equal(value.view, view); assert.deepEqual(value.nonClaims, serverClaims);
  assert(rendered[view][0].includes(value.renderedViewKind)); assert.equal(value.renderedAuthority, rendered[view][1]);
  assert.equal(value.authority, 'presentation_adapter_plan'); assert.equal(value.planKind, 'proofkit.requirement-browser-server-plan');
}

before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-browser-contract-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 180000, maxBuffer: 2 << 20, env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
  fixtures.source = requirementSource();
  fixtures.structuredProof = bindingInput();
  fixtures.compactProof = resolverInput();
  fixtures.structuredCoverage = json(['requirement-coverage-input-compose', '--input', '-'], directComposeInput());
  const normalized = json(['test-evidence-inventory', '--input', '-', '--normalized-inventory'], inventoryInput());
  fixtures.compactCoverage = json(['requirement-coverage-input-compose', '--input', '-'], normalizedComposeInput(normalized));
  fixtures.tree = {schemaVersion: 2, treeId: 'tree.one', rootNodeId: 'spec.root', callerAnnotations: [], edges: [], overlays: [],
    nodes: [{nodeId: 'spec.root', nodeKind: 'meta_spec', label: 'Root', displayOrder: 1, callerAnnotations: [],
      sourceRefs: [{sourceRefId: 'spec.root.requirements', sourceRefKind: 'source_id', sourceRole: 'requirements', sourceId: 'source.one'}]}]};
  const repository = join(directory, 'catalog');
  mkdirSync(join(repository, 'specs'), {recursive: true});
  writeFileSync(join(repository, 'specs/requirements.v2.json'), JSON.stringify(fixtures.source));
  writeFileSync(join(repository, 'specs/tree.json'), JSON.stringify(fixtures.tree));
  const catalog = id => ({schemaVersion: 2, catalogId: id, specTree: {path: 'specs/tree.json'},
    requirementSources: [{path: 'specs/requirements.v2.json', nodeId: 'spec.root'}]});
  fixtures.context = json(['requirement-context-compose', '--repo-root', repository, '--input', '-'], catalog('catalog.one'));
  fixtures.otherContext = json(['requirement-context-compose', '--repo-root', repository, '--input', '-'], catalog('catalog.two'));
  fixtures.workspace = {schemaVersion: 3, workspaceId: 'workspace.one', context: fixtures.context,
    diffInput: {schemaVersion: 3, diffId: 'diff.one', baseContext: fixtures.otherContext, currentContext: fixtures.context},
    graphInput: {schemaVersion: 3, graphId: 'graph.one', context: fixtures.context}};
  fixtures.inputs = {
    '01-coverage-compact': [fixtures.compactCoverage, []], '02-coverage-structured': [fixtures.structuredCoverage, []],
    '03-proof-compact': [fixtures.compactProof, ['--local-environment-class', 'local-go']], '04-proof-structured': [fixtures.structuredProof, []],
    '05-source': [fixtures.source, []], '06-spec-tree': [fixtures.tree, []], '07-workspace': [fixtures.workspace, []],
  };
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

test('published identities, predecessor conditions and root inventories are conserved', () => {
  for (const [key, row] of Object.entries(directions)) {
    const binding = contract.commands.find(command => command.command === row.command)[row.direction + 'Contract'];
    assert.equal(binding.contractId, row.contractId); assert.equal(binding.schemaVersion, row.version); assert.equal(binding.rootDefinitionRef, row.id);
    assert.ok(!contract.contractDefinitions.some(item => item.definitionId === row.predecessor), `${row.predecessor} remains`);
    assert.ok(!binding.compatibilitySummary.some(note => /root-shape/i.test(note)), `${key} retains a root-shape claim`);
    const definition = contract.contractDefinitions.find(item => item.definitionId === row.id);
    assert.deepEqual(definition.fieldTree.variants.map(variant => [variant.variantId, variant.when, variant.allowedFields, variant.requiredFields]),
      row.variants.map(([id, when, allowed, required]) => [id, [when], allowed, required]));
    for (const variant of definition.fieldTree.variants) {
      assert.equal(variant.schema.type, 'object'); assert.equal(variant.schema.additionalProperties, false);
    }
  }
  const input = contract.commands.find(command => command.command === 'requirement-browser-server').inputContract;
  assert.deepEqual(input.childDefinitionBindings.map(row => [row.pathSegments.join('/'), row.variantId ?? '*', row.definitionRef]), [
    ['requirementSource', '*', 'proofkit.requirement-source.input.v2.json-schema'],
    ['context/projections/requirementSources/*', '07-workspace', 'proofkit.requirement-source.input.v2.json-schema'],
    ['', '05-source', 'proofkit.requirement-source.input.v2.json-schema'],
    ['', '03-proof-compact', 'proofkit.compact-proof-contract.input.v2.json-schema'],
    ['compactProofContract', '01-coverage-compact', 'proofkit.compact-proof-contract.input.v2.json-schema'],
  ]);
  for (const command of ['requirement-browser-server', 'view']) {
    const output = contract.commands.find(row => row.command === command).outputContract;
    assert.deepEqual(output.handoffClauses.map(row => [row.appliesWhen, row.pathSegments.join('/')]), [['03-one-shot-submitted', 'annotations/*/anchor']]);
  }
});

test('every input variant is accepted by the CLI and selects exactly its plan variant', () => {
  for (const row of inputVariants) {
    const [input, flags] = fixtures.inputs[row.id];
    assert.deepEqual(Object.keys(input).sort().filter(key => !row.allowed.includes(key)), [], `${row.id} fixture keys`);
    assert.deepEqual(selected('input', input), [row.id], `${row.id} input selection`);
    const value = plan(row.view, input, flags);
    assert.equal(value.port, 0); assert.equal(value.portSelection, 'ephemeral'); assert.equal(value.url, null); assert.equal(value.host, '127.0.0.1');
    assert.ok(Number.isInteger(value.htmlByteLength) && value.htmlByteLength > 0);
    for (const other of views.filter(view => view !== row.view)) valid('output', '01-plan-' + other, value, false, `${row.id} as ${other}`);
    for (const variant of ['02-one-shot-terminal', '03-one-shot-submitted']) valid('output', variant, value, false, `${row.id} as ${variant}`);
  }
  const proof = {compact: plan('proof', fixtures.compactProof, ['--empty-local-environment-policy']), structured: plan('proof', fixtures.structuredProof, ['--scope', 'graph'])};
  assert.equal(proof.compact.renderedViewKind, 'proofkit.compact-requirement-proof-view');
  assert.equal(proof.structured.renderedViewKind, 'proofkit.requirement-proof-view');
  // Structured proof rendering ignores local-environment flags instead of refusing them.
  assert.deepEqual(plan('proof', fixtures.structuredProof, ['--local-environment-class', 'local-go']), plan('proof', fixtures.structuredProof));
  for (const [flags, port, url] of [[['--port', '8080'], 8080, 'http://127.0.0.1:8080/'], [['--port', '80'], 80, 'http://127.0.0.1/'],
    [['--host', '::1', '--port', '65535'], 65535, 'http://[::1]:65535/'], [['--host', '::1'], 0, null]]) {
    const value = plan('workspace', fixtures.workspace, flags);
    assert.equal(value.port, port); assert.equal(value.url, url); assert.equal(value.portSelection, port === 0 ? 'ephemeral' : 'fixed');
  }
  const pointer = join(directory, 'pointer.json');
  writeFileSync(pointer, JSON.stringify({payload: {nested: fixtures.source}}));
  assert.deepEqual(json(['requirement-browser-server', '--input', pointer, '--input-pointer', '/payload/nested', '--view', 'source']), plan('source', fixtures.source));
  const compact = run(['--json-layout', 'compact', ...browserArgs('source')], fixtures.source);
  assert.equal(compact.status, 0); assert.equal(compact.stdout, JSON.stringify(JSON.parse(compact.stdout)) + '\n');
  assert.deepEqual(JSON.parse(compact.stdout), plan('source', fixtures.source));
});

test('root input clauses are refused by both the selected variant and the CLI', () => {
  function both(row, value, label, flags = fixtures.inputs[row.id][1]) {
    valid('input', row.id, value, false, label);
    refused(browserArgs(row.view, flags), value, `${row.id}/${label}`);
  }
  for (const row of inputVariants) {
    const [input] = fixtures.inputs[row.id];
    for (const bad of [null, [], 'object', 0, true]) both(row, bad, 'root type ' + JSON.stringify(bad));
    both(row, {...clone(input), foreign: true}, 'unknown root member');
    for (const key of row.required) both(row, replaced(input, [key]), 'missing ' + key);
    for (const key of row.allowed.filter(key => key !== 'schemaVersion' && key !== 'schema_version' && input[key] !== null && input[key] !== undefined)) {
      both(row, replaced(input, [key], flipped(input[key]) ?? 7), 'wrong type ' + key);
    }
    const version = row.id === '03-proof-compact' ? 'schema_version' : 'schemaVersion';
    for (const bad of [input[version] + 1, String(input[version]), null]) both(row, replaced(input, [version], bad), 'version ' + JSON.stringify(bad));
    for (const other of inputVariants.filter(other => other.view !== row.view)) {
      valid('input', other.id, input, false, `${row.id} as ${other.id}`);
      refused(browserArgs(other.view, fixtures.inputs[other.id][1]), input, `${row.id} through --view ${other.view}`);
    }
  }
  const [compactCoverage, structuredCoverage] = [inputVariants[0], inputVariants[1]];
  both(compactCoverage, {...clone(fixtures.compactCoverage), requirementProofBinding: bindingInput()}, 'both proof modes');
  both(compactCoverage, {...clone(fixtures.compactCoverage), localEnvironmentPolicy: null}, 'compact without local policy');
  both(compactCoverage, replaced(fixtures.compactCoverage, ['compactProofContract'], null), 'compact proof null');
  both(structuredCoverage, {...clone(fixtures.structuredCoverage), compactProofContract: resolverInput()}, 'structured with compact proof');
  both(structuredCoverage, replaced(fixtures.structuredCoverage, ['requirementProofBinding'], null), 'structured proof null');
  const structuredWithPolicy = {...clone(fixtures.structuredCoverage), localEnvironmentPolicy: {authority: 'caller_provided', localEnvironmentClasses: ['local-go']}};
  valid('input', '02-coverage-structured', structuredWithPolicy, true, 'structured local policy is admitted');
  plan('coverage', structuredWithPolicy);
  const workspace = inputVariants[6];
  for (const key of ['diffInput', 'graphInput']) {
    for (const value of [null, undefined]) {
      const changed = replaced(fixtures.workspace, [key], value);
      valid('input', workspace.id, changed, true, key + ' absent or null'); plan('workspace', changed);
    }
    both(workspace, replaced(fixtures.workspace, [key], []), key + ' array');
    both(workspace, replaced(fixtures.workspace, [key, 'schemaVersion'], 2), key + ' version');
  }
  both(workspace, replaced(fixtures.workspace, ['context', 'schemaVersion'], 3), 'retired context version');
  both(workspace, replaced(fixtures.workspace, ['context', 'foreign'], true), 'unknown context member');
  both(workspace, replaced(fixtures.workspace, ['graphInput', 'context', 'contextKind'], 'foreign'), 'graph context kind');
  for (const [id, expected] of [['w' + 'a'.repeat(255), true], ['ab.'.repeat(85) + 'c', true], ['ab.'.repeat(85) + 'cd', false], ['bad id', false],
    ['1workspace', false], ['', false], ['a..b', false]]) {
    const changed = replaced(fixtures.workspace, ['workspaceId'], id);
    if (expected) {valid('input', workspace.id, changed, true, 'workspaceId ' + id.length); plan('workspace', changed);} else both(workspace, changed, 'workspaceId ' + JSON.stringify(id));
  }
});

test('schema acceptance never exceeds native admission across nested clause mutants', t => {
  let schemaRefused = 0, nativeRefused = 0, total = 0;
  for (const row of inputVariants) {
    const [input, flags] = fixtures.inputs[row.id];
    const mutants = [];
    // Contexts nested in diff and graph inputs share the root context owner.
    const shared = path => [['diffInput', 'baseContext'], ['diffInput', 'currentContext'], ['graphInput', 'context']]
      .some(prefix => prefix.every((key, index) => path[index] === key));
    for (const path of objectPaths(input).filter(path => !shared(path))) {
      if (path.length) mutants.push(['unknown member', replaced(input, [...path, 'foreign'], true)]);
      for (const key of Object.keys(at(input, path))) {
        mutants.push(['remove ' + [...path, key].join('/'), replaced(input, [...path, key])]);
        mutants.push(['null ' + [...path, key].join('/'), replaced(input, [...path, key], null)]);
      }
    }
    const leaves = leafPaths(input).filter(path => !shared(path));
    for (const path of leaves.filter((_, index) => index % Math.max(1, Math.floor(leaves.length / 60)) === 0)) {
      mutants.push(['flip ' + path.join('/'), replaced(input, path, flipped(at(input, path)))]);
    }
    for (const [label, mutant] of mutants) {
      total++;
      const schema = checks.input.get(row.id)(mutant);
      const result = run(browserArgs(row.view, flags), mutant);
      assert.ok(result.status === 0 || result.status === 1, `${row.id}/${label} exit`);
      if (result.status === 0) {
        assert.equal(schema, true, `${row.id}/${label}: native admitted a structurally refused value ${JSON.stringify(checks.input.get(row.id).errors?.slice(0, 2))}`);
        const value = JSON.parse(result.stdout); assertPlan('output', '01-plan-' + row.view, value, row.view);
      } else {
        refusedResult(result, `${row.id}/${label}`); nativeRefused++;
        if (!schema) schemaRefused++;
      }
    }
  }
  t.diagnostic(`mutants=${total} nativeRefused=${nativeRefused} schemaRefused=${schemaRefused}`);
  assert.ok(schemaRefused >= 900 && nativeRefused >= schemaRefused, `schema refused ${schemaRefused} of ${nativeRefused} native refusals`);
});

test('semantic refusals remain native after structural acceptance', () => {
  const accepted = (variant, value) => valid('input', variant, value, true, 'semantic-only');
  const unrelated = replaced(fixtures.workspace, ['graphInput', 'context'], fixtures.otherContext);
  accepted('07-workspace', unrelated); refused(browserArgs('workspace'), unrelated, 'graph context mismatch');
  const swapped = replaced(fixtures.workspace, ['diffInput', 'currentContext'], fixtures.otherContext);
  accepted('07-workspace', swapped); refused(browserArgs('workspace'), swapped, 'diff current context mismatch');
  const forged = replaced(fixtures.workspace, ['context', 'snapshotId'], 'sha256:' + 'a'.repeat(64));
  accepted('07-workspace', forged); refused(browserArgs('workspace'), forged, 'snapshot identity replay');
  const timestamped = replaced(fixtures.workspace, ['workspaceId'], 'workspace.20261011');
  accepted('07-workspace', timestamped); refused(browserArgs('workspace'), timestamped, 'timestamp-like workspace id');
  accepted('03-proof-compact', fixtures.compactProof); refused(browserArgs('proof'), fixtures.compactProof, 'compact proof without local policy flag');
});

function basePlan() {
  return plan('workspace', fixtures.workspace, ['--port', '8080']);
}
test('plan output clauses, bounds and the port partition are exact', () => {
  const fixed = basePlan(), ephemeral = plan('workspace', fixtures.workspace);
  for (const value of [fixed, ephemeral]) {
    for (const key of planKeys) valid('output', '01-plan-workspace', replaced(value, [key]), false, 'missing ' + key);
    valid('output', '01-plan-workspace', {...clone(value), foreign: true}, false, 'unknown');
    for (const key of planKeys) valid('output', '01-plan-workspace', replaced(value, [key], typeof value[key] === 'string' ? 7 : 'wrong'), false, 'type ' + key);
  }
  const accept = (path, next, expected, label, base = fixed) => valid('output', '01-plan-workspace', replaced(base, path, next), expected, label);
  for (const host of ['127.0.0.1', '::1']) accept(['host'], host, true, host);
  for (const host of ['localhost', '0.0.0.0', '', '127.0.0.2']) accept(['host'], host, false, host);
  for (const port of [1, 80, 65535]) accept(['port'], port, true, 'port ' + port);
  for (const port of [0, -1, 65536, 1.5]) accept(['port'], port, false, 'fixed port ' + port);
  for (const port of [1, 65535]) accept(['port'], port, false, 'ephemeral port ' + port, ephemeral);
  accept(['url'], null, false, 'fixed without url');
  accept(['url'], 'http://127.0.0.1:1/', true, 'url with another fixed port');
  valid('output', '01-plan-workspace', {...clone(ephemeral), url: 'http://127.0.0.1:8080/'}, false, 'ephemeral with url');
  valid('output', '01-plan-workspace', {...clone(ephemeral), portSelection: 'fixed'}, false, 'fixed selection with port 0');
  valid('output', '01-plan-workspace', {...clone(fixed), portSelection: 'ephemeral'}, false, 'ephemeral selection with fixed port');
  for (const url of ['http://[::1]:8080/', 'http://127.0.0.1/', 'http://127.0.0.1:65535/']) accept(['url'], url, true, url);
  for (const url of ['http://localhost:8080/', 'https://127.0.0.1:8080/', 'http://127.0.0.1:8080', 'http://127.0.0.1:8080/x', 'http://127.0.0.1:0/',
    'http://::1:8080/', 'http://127.0.0.1:08080/', ' http://127.0.0.1:8080/', 'http://127.0.0.1:8080/\n']) accept(['url'], url, false, url);
  for (const [key, good, bad] of [['portSelection', [], ['dynamic', '']], ['view', [], ['proof', 'foreign']], ['renderedViewKind', [], ['proofkit.requirement-source-view']],
    ['renderedAuthority', [], ['lookup_only']], ['authority', [], ['presentation_adapter']], ['planKind', [], ['proofkit.other']], ['schemaVersion', [], [0, 2, '1']]]) {
    for (const value of good) accept([key], value, true, key);
    for (const value of bad) accept([key], value, false, key + ' ' + value);
  }
  for (const length of [1, 2, 1 << 20]) accept(['htmlByteLength'], length, true, 'html ' + length);
  for (const length of [0, -1, 1.5]) accept(['htmlByteLength'], length, false, 'html ' + length);
  for (const claims of [[], serverClaims.slice(1), [...serverClaims, serverClaims[0]], serverClaims.toReversed(), [...serverClaims.slice(0, 5), 'Foreign claim.']]) {
    accept(['nonClaims'], claims, false, 'claims');
  }
  const view = plan('workspace', fixtures.workspace, [], 'output');
  valid('view', '01-plan', view, true, 'browser workspace plan is the project plan structure');
  for (const other of views.filter(item => item !== 'workspace')) valid('view', '01-plan', plan(other, fixtures.inputs[inputVariants.find(row => row.view === other).id][0],
    fixtures.inputs[inputVariants.find(row => row.view === other).id][1]), false, other + ' plan through view');
});

function readFirstLine(child) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error('server did not publish its URL')), 20000);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      buffer += chunk;
      const end = buffer.indexOf('\n');
      if (end >= 0) {clearTimeout(timer); resolve(buffer.slice(0, end + 1));}
    });
    child.on('exit', code => {clearTimeout(timer); reject(new Error('server exited before publishing: ' + code));});
  });
}
function health(url) {
  return new Promise((resolve, reject) => {
    get(new URL('healthz', url), response => {
      let body = ''; response.setEncoding('utf8');
      response.on('data', chunk => {body += chunk;}); response.on('end', () => resolve([response.statusCode, body]));
    }).on('error', reject);
  });
}
async function serveOnce(args, input) {
  const child = spawn(binary, args, {stdio: ['pipe', 'pipe', 'pipe']});
  let stderr = ''; child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => {stderr += chunk;});
  const exited = new Promise(resolve => child.on('exit', (code, signal) => resolve([code, signal])));
  child.stdin.end(input === undefined ? '' : JSON.stringify(input));
  try {
    const line = await readFirstLine(child);
    const match = /^Proofkit requirement browser: (http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/)\n$/.exec(line);
    assert.ok(match, `unexpected serving record ${JSON.stringify(line)}`);
    assert.throws(() => JSON.parse(line), SyntaxError, 'browse serving must not emit a JSON record');
    const [status, body] = await health(match[1]);
    assert.equal(status, 200); assert.equal(JSON.parse(body).view, 'workspace');
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
    const [code, signal] = await exited; clearTimeout(timer);
    assert.equal(signal, null); assert.equal(code, 0); assert.equal(stderr, '');
    return line;
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}

test('serving browse mode emits one non-JSON URL record and terminates on SIGTERM', async () => {
  await serveOnce(browserArgs('workspace', ['--serve', '--host', '127.0.0.1', '--port', '0']), fixtures.workspace);
  for (const [args, label] of [
    [['--json-layout', 'compact', ...browserArgs('workspace', ['--serve'])], 'serving layout'],
    [browserArgs('workspace', ['--serve', '--session-mode', 'one-shot-question']), 'one-shot without --open'],
    [browserArgs('workspace', ['--session-timeout-seconds', '1']), 'timeout without one-shot'],
    [browserArgs('source', ['--serve', '--session-mode', 'browse']), 'session mode outside workspace'],
    [browserArgs('workspace', ['--host', '0.0.0.0']), 'non-loopback host'],
    [browserArgs('workspace', ['--port', '65536']), 'port above bound'],
    [browserArgs('workspace', ['--port', '-1']), 'negative port'],
    [browserArgs('workspace', ['--scope', 'graph']), 'proof scope outside proof'],
    [browserArgs('coverage', ['--local-environment-class', 'local-go']), 'local policy outside proof'],
  ]) refused(args, fixtures.workspace, label);
});

test('a CLI that exits before reading its stdin is accepted only as a refusal', () => {
  // The flag refusal exits before reading stdin, so the child leaves every byte of the payload unread.
  const payload = {...clone(fixtures.workspace), padding: 'x'.repeat(8 << 20)};
  const args = browserArgs('workspace', ['--serve', '--session-mode', 'one-shot-question']);
  assert.equal(refused(args, payload, 'oversized one-shot without --open').stdinUnreadBytes, Buffer.byteLength(JSON.stringify(payload)));
  // Unread input passes the transport check only with a refusal status, so a caller that expects success fails on that status.
  assert.throws(() => json(args, payload), error => error.code === 'ERR_ASSERTION' && error.actual === 1 && error.expected === 0);
});

test('the project view whole chain emits the workspace plan and refuses incomplete roots', () => {
  const repository = join(directory, 'project'); mkdirSync(repository); writeFileSync(join(repository, 'README.md'), '# Pilot\n');
  const request = JSON.parse(readFileSync(new URL('internal/app/testdata/materialization-native-request.v2.json', root), 'utf8'));
  request.sourcePlan = json(['adopt', 'plan', '--repo-root', repository, '--mode', 'fresh']);
  const planned = json(['adopt', 'materialize', 'plan', '--repo-root', repository, '--input', '-'], request);
  const applied = json(['adopt', 'materialize', 'apply', '--repo-root', repository, '--input', '-', '--expect-transaction', planned.transaction.transactionId,
    '--expect-desired-state', planned.transaction.desiredStateId], request);
  assert.equal(applied.state, 'passed');
  for (const flags of [[], ['--port', '9000'], ['--host', '::1']]) {
    const value = json(['view', '--repo-root', repository, ...flags]);
    assertPlan('view', '01-plan', value, 'workspace');
    valid('output', '01-plan-workspace', value, true, 'project plan through browser workspace variant');
    assert.equal(value.portSelection, flags[0] === '--port' ? 'fixed' : 'ephemeral');
  }
  const compact = run(['--json-layout', 'compact', 'view', '--repo-root', repository]);
  assert.equal(compact.status, 0); assertPlan('view', '01-plan', JSON.parse(compact.stdout), 'workspace');
  for (const [args, label] of [[['view', '--repo-root', join(directory, 'absent')], 'absent root'], [['view', '--repo-root', join(directory, 'catalog')], 'unmaterialized root'],
    [['view', '--repo-root', repository, '--session-mode', 'one-shot-question', '--serve'], 'one-shot without --open'],
    [['--json-layout', 'compact', 'view', '--repo-root', repository, '--serve'], 'serving layout'], [['view', '--repo-root', repository, '--host', 'localhost'], 'non-loopback host']]) {
    refused(args, undefined, label);
  }
  fixtures.project = repository;
});

test('project view browse serving emits only the URL record', async () => {
  assert.ok(fixtures.project, 'project fixture was not materialized');
  await serveOnce(['view', '--repo-root', fixtures.project, '--serve', '--host', '127.0.0.1', '--port', '0']);
});

// --open launches the platform opener (open on macOS, xdg-open elsewhere). A
// PATH shim records the URL instead, so the oracle drives the real one-shot
// session over HTTP without a browser engine.
function launcherEnvironment() {
  assert.notEqual(process.platform, 'win32', 'the launcher shim is POSIX-only');
  const shim = mkdtempSync(join(directory, 'launcher-'));
  const urlFile = join(shim, 'browser-url');
  writeFileSync(join(shim, process.platform === 'darwin' ? 'open' : 'xdg-open'),
    '#!/bin/sh\nprintf \'%s\\n\' "$1" > "$PROOFKIT_ORACLE_BROWSER_URL_FILE"\n', {mode: 0o755});
  return {urlFile, env: {...process.env, PATH: shim + delimiter + process.env.PATH, PROOFKIT_ORACLE_BROWSER_URL_FILE: urlFile}};
}
function httpCall(url, {method = 'GET', headers = {}, body} = {}) {
  return new Promise((resolve, reject) => {
    const call = httpRequest(url, {method, headers}, response => {
      let text = ''; response.setEncoding('utf8');
      response.on('data', chunk => {text += chunk;}); response.on('end', () => resolve([response.statusCode, text]));
    });
    call.on('error', reject);
    call.end(body);
  });
}
// An authenticated session request carries the page capability, the session
// origin and a JSON body, as the workspace page does.
async function postSession(url, path, payload) {
  const [status, page] = await httpCall(url);
  assert.equal(status, 200, 'one-shot workspace page');
  const capability = /name="proofkit-browser-capability" content="([A-Za-z0-9_-]{43})"/.exec(page);
  assert.ok(capability, 'the one-shot workspace publishes its capability');
  const body = JSON.stringify(payload);
  return httpCall(new URL(path, url), {method: 'POST', body, headers: {origin: url.slice(0, -1), 'content-type': 'application/json',
    'content-length': Buffer.byteLength(body), 'x-proofkit-browser-capability': capability[1]}});
}
// Runs one real one-shot CLI session, optionally interacts with it, and
// returns its exit code, its stdout packet and the interaction response.
async function oneShotSession(args, input, interact) {
  const {urlFile, env} = launcherEnvironment();
  const child = spawn(binary, args, {stdio: ['pipe', 'pipe', 'pipe'], env});
  let stdout = '', stderr = '', exit;
  child.stdout.setEncoding('utf8'); child.stdout.on('data', chunk => {stdout += chunk;});
  child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => {stderr += chunk;});
  const exited = new Promise(resolve => child.on('exit', (code, signal) => {exit = [code, signal]; resolve(exit);}));
  child.stdin.end(input === undefined ? '' : JSON.stringify(input));
  try {
    let url = '';
    const deadline = Date.now() + 30000;
    while (!url) {
      assert.equal(exit, undefined, `one-shot CLI exited before launching the browser: ${stdout} ${stderr}`);
      assert.ok(Date.now() < deadline, 'the browser launcher did not receive the one-shot URL');
      const text = existsSync(urlFile) ? readFileSync(urlFile, 'utf8') : '';
      if (text.endsWith('\n')) url = text.slice(0, -1); else await sleep(20);
    }
    assert.match(url, /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/$/);
    const response = interact ? await interact(url) : undefined;
    const timer = setTimeout(() => child.kill('SIGKILL'), 30000);
    const [code, signal] = await exited; clearTimeout(timer);
    assert.equal(signal, null, `one-shot CLI did not finish: ${stdout}`); assert.equal(stderr, '');
    return {code, packet: JSON.parse(stdout), response};
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}

const oneShotQuestion = 'Does this remain true?';
test('one-shot sessions of both commands emit exactly their submitted and terminal variants', async () => {
  assert.ok(fixtures.project, 'project fixture was not materialized');
  const oneShotFlags = seconds => ['--serve', '--open', '--session-mode', 'one-shot-question', '--session-timeout-seconds', seconds];
  // Each requirement invariant starts with its statement completion when the
  // statement stem is empty; the quote is the first word of that invariant.
  const materialization = JSON.parse(readFileSync(new URL('internal/app/testdata/materialization-native-request.v2.json', root), 'utf8'));
  const quoted = source => {
    const [group] = source.groups, [member] = group.members;
    assert.equal(group.statementStem, '');
    const exactQuote = member.statementCompletion.split(' ')[0];
    return {anchorId: `requirement:${member.requirementId}:invariant`, exactQuote, startCodePoint: 0, endCodePoint: [...exactQuote].length, question: oneShotQuestion};
  };
  const sessions = [
    ['output', seconds => browserArgs('workspace', oneShotFlags(seconds)), fixtures.workspace, quoted(fixtures.source)],
    ['view', seconds => ['view', '--repo-root', fixtures.project, ...oneShotFlags(seconds)], undefined, quoted(materialization.requirementSources[0])],
  ];
  fixtures.oneShot = {};
  for (const [key, args, input, annotation] of sessions) {
    const submitted = await oneShotSession(args('60'), input, url => postSession(url, 'api/v1/handoff', {annotations: [annotation]}));
    assert.equal(submitted.response[0], 200, `${key} handoff: ${submitted.response[1]}`); assert.equal(submitted.code, 0, key);
    assert.deepEqual(submitted.packet, JSON.parse(submitted.response[1]), `${key} stdout carries the admitted handoff packet`);
    assert.equal(submitted.packet.state, 'submitted'); assert.equal(submitted.packet.annotations[0].question, oneShotQuestion);
    assert.deepEqual(selected(key, submitted.packet), ['03-one-shot-submitted'], `${key} submitted selection`);
    const snapshotId = submitted.packet.snapshotRefs[0].snapshotId;
    const cancelled = await oneShotSession(args('60'), input, url => postSession(url, 'api/v1/cancel', {requestId: 'oracle.cancel', snapshotId}));
    assert.equal(cancelled.response[0], 200, `${key} cancel: ${cancelled.response[1]}`); assert.equal(cancelled.code, 1, key);
    const expired = await oneShotSession(args('1'), input);
    assert.equal(expired.code, 1, key);
    for (const [state, packet] of [['cancelled', cancelled.packet], ['expired', expired.packet]]) {
      assert.equal(packet.state, state); assert.deepEqual(packet.snapshotRefs, submitted.packet.snapshotRefs, `${key} ${state} snapshot`);
      assert.deepEqual(selected(key, packet), ['02-one-shot-terminal'], `${key} ${state} selection`);
    }
    fixtures.oneShot[key] = {submitted: submitted.packet, terminal: expired.packet};
  }
});

test('one-shot CLI packets bind the exact terminal and submitted structures for both commands', () => {
  for (const [key, prefix] of [['output', '01-plan-'], ['view', '01-plan']]) {
    assert.ok(fixtures.oneShot?.[key], `${key} one-shot packets were not observed`);
    const {submitted, terminal: t} = fixtures.oneShot[key];
    assert.equal(submitted.context.profile, 'review');
    valid(key, '02-one-shot-terminal', replaced(t, ['state'], 'submitted'), false, 'terminal submitted');
    valid(key, '03-one-shot-submitted', replaced(submitted, ['state'], 'cancelled'), false, 'submitted cancelled');
    for (const variant of [...checks[key].keys()].filter(id => id.startsWith(prefix))) {
      valid(key, variant, t, false, 'terminal as plan'); valid(key, variant, submitted, false, 'submitted as plan');
    }
    const records = [
      ['02-one-shot-terminal', t, [[[], terminalKeys], [['snapshotRefs', 0], ['role', 'snapshotId']]]],
      ['03-one-shot-submitted', submitted, [[[], submittedKeys], [['annotations', 0], annotationKeys], [['annotations', 0, 'anchor'], anchorKeys],
        [['snapshotRefs', 0], ['role', 'snapshotId']]]],
    ];
    for (const [variant, value, inventories] of records) {
      for (const [path, keys] of inventories) {
        assert.deepEqual(Object.keys(at(value, path)).sort(), keys, variant + path.join('/'));
        valid(key, variant, replaced(value, [...path, 'foreign'], true), false, variant + ' unknown at ' + path.join('/'));
        for (const field of keys) {
          valid(key, variant, replaced(value, [...path, field]), false, `${variant} missing ${[...path, field].join('/')}`);
          valid(key, variant, replaced(value, [...path, field], flipped(at(value, [...path, field])) ?? 7), false, `${variant} type ${field}`);
        }
      }
    }
    const reject = (variant, value, path, next, label) => valid(key, variant, replaced(value, path, next), false, label);
    const accept = (variant, value, path, next, label) => valid(key, variant, replaced(value, path, next), true, label);
    for (const bad of ['submitted', 'foreign', '']) reject('02-one-shot-terminal', t, ['state'], bad, 'terminal state ' + bad);
    for (const [path, bad] of [[['handoffKind'], 'proofkit.other'], [['schemaVersion'], 1], [['snapshotRefs'], []], [['snapshotRefs'], [...snapshotRefsOf(t), ...snapshotRefsOf(t)]],
      [['snapshotRefs', 0, 'role'], 'base'], [['snapshotRefs', 0, 'snapshotId'], 'sha256:' + 'A'.repeat(64)], [['nonClaims'], serverClaims.slice(1)]]) {
      reject('02-one-shot-terminal', t, path, bad, 'terminal ' + path.join('/')); reject('03-one-shot-submitted', submitted, path, bad, 'submitted ' + path.join('/'));
    }
    for (const [path, bad] of [[['instructionAuthority'], 'operator'], [['sourceTextAuthority'], 'trusted'], [['annotations', 0, 'anchor', 'coordinateSpace'], 'source_wire'],
      [['annotations', 0, 'targetId'], 'sha256:short'], [['annotations', 0, 'startCodePoint'], -1], [['annotations', 0, 'startCodePoint'], 0.5],
      [['annotations', 0, 'endCodePoint'], 0], [['annotations', 0, 'exactQuote'], ''], [['annotations', 0, 'exactQuote'], ' \u0085\u3000 '],
      [['annotations', 0, 'question'], ''], [['annotations', 0, 'question'], ' Why?'], [['annotations', 0, 'question'], 'Why?\u0085'],
      [['annotations'], []], [['context', 'profile'], 'routing'], [['context', 'foreign'], true]]) {
      reject('03-one-shot-submitted', submitted, path, bad, 'submitted ' + path.join('/') + ' ' + JSON.stringify(bad));
    }
    for (const [path, good] of [[['annotations', 0, 'question'], '\ufeffWhy?\ufeff'], [['annotations', 0, 'exactQuote'], ' a '], [['annotations', 0, 'startCodePoint'], 0],
      [['annotations', 0, 'prefix'], 'p'.repeat(32)], [['annotations', 0, 'suffix'], 's'.repeat(32)], [['annotations', 0, 'question'], 'q'.repeat(4096)],
      [['annotations', 0, 'exactQuote'], 'x'.repeat(65536)], [['annotations'], Array(64).fill(submitted.annotations[0])],
      [['annotations', 0, 'anchor', 'jsonPointer'], ''], [['annotations', 0, 'anchor', 'sourceDigest'], '']]) {
      accept('03-one-shot-submitted', submitted, path, good, 'submitted bound ' + path.join('/'));
    }
    for (const [path, bad] of [[['annotations', 0, 'prefix'], 'p'.repeat(33)], [['annotations', 0, 'suffix'], 's'.repeat(33)],
      [['annotations', 0, 'question'], 'q'.repeat(4097)], [['annotations', 0, 'exactQuote'], 'x'.repeat(65537)], [['annotations'], Array(65).fill(submitted.annotations[0])]]) {
      reject('03-one-shot-submitted', submitted, path, bad, 'submitted above bound ' + path.join('/'));
    }
  }
});
