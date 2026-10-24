import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport, spawnWithInputFile} from './cli-process.mjs';
import {expandSharedDefinitions} from './schema-definitions.mjs';

// Independent oracle: expected inventories, vocabularies and fixtures are
// authored here, never derived from the schemas under test.
const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_PROFILE_REGISTRY_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const identities = {
  'conformance-profile/input': {contractId: 'proofkit.conformance-profile.input.v2', version: 2, variants: [['01-root', 'default JSON mode']]},
  'conformance-profile/output': {contractId: 'proofkit.conformance-profile.output.v2', version: 2, variants: [
    ['01-list', '--list'], ['02-profile', '--profile <id> with --format json or without --format (defaults json)'], ['03-verify', '--verify']]},
  'migration-plan/input': {contractId: 'proofkit.migration-plan.input.v1', version: 1, variants: [['01-root', 'default JSON mode']]},
  'migration-plan/output': {contractId: 'proofkit.migration-plan.output.v1', version: 1, variants: [['01-root', 'default JSON mode']]},
  'workspace-registry/input': {contractId: 'proofkit.workspace-registry.input.v1', version: 1, variants: [['01-root', 'default JSON mode']]},
  'workspace-registry/output': {contractId: 'proofkit.workspace-registry.output.v1', version: 1, variants: [['01-root', 'default JSON mode']]},
};
const checks = new Map(Object.entries(identities).map(([key, identity]) => {
  const [command, direction] = key.split('/');
  const record = contract.commands.find(row => row.command === command)[direction + 'Contract'];
  assert.equal(record.contractId, identity.contractId, key + '/contractId');
  assert.equal(record.schemaVersion, identity.version, key + '/schemaVersion');
  assert.equal(record.rootDefinitionRef, identity.contractId + '.json-schema', key + '/rootDefinitionRef');
  assert.equal(contract.contractDefinitions.some(row => row.definitionId === identity.contractId + '.root-shape'), false, key + '/predecessor');
  const definition = contract.contractDefinitions.find(row => row.definitionId === record.rootDefinitionRef);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema');
  assert.equal(record.rootDefinitionDigest, definition.canonicalDigest);
  assert.deepEqual(definition.fieldTree.variants.map(row => [row.variantId, ...row.when]), identity.variants, key + '/variants');
  // Ajv validates the published schema; navigation reads its shared-definition expansion.
  return [key, definition.fieldTree.variants.map(row => ({
    id: row.variantId, schema: expandSharedDefinitions(row.schema), check: new Ajv2020({strict: false, validateFormats: false}).compile(row.schema),
  }))];
}));

let directory, binary, proof;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-profile-registry-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 120000, maxBuffer: 2 << 20,
    env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
  proof = resolvedProof(compactInput());
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, replacement) {
  if (path.length === 0) return replacement;
  const result = structuredClone(value); at(result, path.slice(0, -1))[path.at(-1)] = replacement; return result;
}
function without(value, path) {
  const result = structuredClone(value); delete at(result, path.slice(0, -1))[path.at(-1)]; return result;
}
function schema(command, direction, index, value, expected = true, label = '') {
  const check = checks.get(command + '/' + direction)[index].check;
  assert.equal(check(value), expected, `${command}/${direction}/${index}/${label}: ${JSON.stringify(check.errors?.slice(0, 2))}`);
}
function run(command, input, flags = []) {
  const result = spawnWithInputFile(binary, [command, '--input', '-', ...flags], {
    input: typeof input === 'string' ? input : JSON.stringify(input), encoding: 'utf8', timeout: 10000, maxBuffer: 8 << 20,
  });
  assertCLITransport(result);
  return result;
}
// Variant selection is a public flag rule: --list, --profile and --verify select disjoint carriers.
function outputIndex(command, flags) {
  if (command !== 'conformance-profile') return 0;
  return flags.includes('--list') ? 0 : flags.includes('--verify') ? 2 : 1;
}
function expectJSON(command, input, flags, status, label = '') {
  const result = run(command, input, flags);
  assert.equal(result.stderr, '', label + result.stderr);
  assert.equal(result.status, status, label + result.stdout);
  const value = JSON.parse(result.stdout), index = outputIndex(command, flags);
  checks.get(command + '/output').forEach((variant, position) => {
    assert.equal(variant.check(value), position === index, `${command}/${label}: variant ${variant.id} selection ${JSON.stringify(variant.check.errors?.slice(0, 2))}`);
  });
  return value;
}
function expectRefused(command, input, flags = [], label = '') {
  const result = run(command, input, flags);
  assert.equal(result.status, 1, label); assert.equal(result.stdout, '', label); assert.notEqual(result.stderr, '', label);
  return result.stderr;
}

// Structural acceptance must agree with the public CLI. Under --verify an
// admission refusal is reported as the single failure of a failed report.
function admits(command, input, accepted, label) {
  schema(command, 'input', 0, input, accepted, label);
  if (command === 'conformance-profile') {
    if (accepted) {
      expectJSON(command, input, ['--list'], 0, label);
      return;
    }
    expectRefused(command, input, ['--list'], label);
    const verify = expectJSON(command, input, ['--verify'], 1, label);
    assert.equal(verify.ruleResults.length, 1, label); assert.deepEqual(verify.nonClaims, []); assert.equal(verify.summary.profileCount, 0);
    return;
  }
  if (!accepted) {
    expectRefused(command, input, [], label);
    return;
  }
  const result = run(command, input);
  assert.equal(result.stderr, '', label + result.stderr);
  schema(command, 'output', 0, JSON.parse(result.stdout), true, label);
}
// Native-only predicates are named in descriptions; structure admits them and the CLI refuses.
function nativeOnly(command, input, label) {
  schema(command, 'input', 0, input, true, label);
  expectRefused(command, input, command === 'conformance-profile' ? ['--list'] : [], label);
}
function kinds(command, input, path, own, label) {
  for (const [kind, value] of [['null', null], ['boolean', false], ['number', 42], ['string', 'wrong-kind'], ['array', []], ['object', {}]]) {
    if (!own.includes(kind)) admits(command, replace(input, path, value), false, label + '/kind/' + kind + '/' + path.join('.'));
  }
}
function closedRecord(command, input, path, required, optional = []) {
  const label = 'record/' + path.join('.');
  admits(command, replace(input, [...path, 'foreign'], true), false, label + '/foreign');
  for (const key of required) admits(command, without(input, [...path, key]), false, label + '/required/' + key);
  for (const key of optional) admits(command, without(input, [...path, key]), true, label + '/optional/' + key);
}
function identifier(command, input, path, valid = 'a') {
  const label = 'id/' + path.join('.');
  kinds(command, input, path, ['string'], label);
  for (const value of ['', '1bad', 'bad.', 'bad..id', 'bad id', ' padded', 'a'.repeat(257)]) admits(command, replace(input, path, value), false, label + '/' + value.slice(0, 12));
  admits(command, replace(input, path, valid + 'b'.repeat(256 - valid.length)), true, label + '/256');
}
function text(command, input, path) {
  const label = 'text/' + path.join('.');
  kinds(command, input, path, ['string'], label);
  for (const value of ['', ' ', '\t\u3000\n']) admits(command, replace(input, path, value), false, label + '/blank');
}
function texts(command, input, path, minimum) {
  const label = 'texts/' + path.join('.');
  kinds(command, input, path, ['array'], label);
  admits(command, replace(input, path, []), minimum === 0, label + '/empty');
  for (const value of [null, false, 42, '', ' ', [], {}]) admits(command, replace(input, path, [value]), false, label + '/item/' + JSON.stringify(value));
}
function vocabulary(command, input, path, values) {
  kinds(command, input, path, ['string'], 'enum/' + path.join('.'));
  for (const value of values) admits(command, replace(input, path, value), true, 'enum/' + path.join('.') + '/' + value);
  for (const value of ['foreign-fixture-value', values[0].toUpperCase(), ' ' + values[0]]) admits(command, replace(input, path, value), false, 'enum/' + path.join('.') + '/foreign');
}

function compactInput(anchor = 'case.local') {
  return {schema_version: 2, authority_state: 'caller_owned_declaration', contract_id: 'contract.profile-registry',
    contract_kind: 'requirement_proof_route_declaration', normalization_profile: 'proofkit.compact.declaration.v2',
    non_claims: ['Synthetic profile registry declaration only.'],
    surface_columns: ['surface_id', 'required_environment_classes', 'preconditioned_environment_classes'],
    surfaces: [['surface.local', ['local-go'], []], ['surface.remote', ['remote-ci'], ['remote-ci']]],
    witness_columns: ['selector', 'environment_classes', 'verify_commands', 'resolution_order_index'],
    binding_columns: ['requirement_id', 'surface_id', 'scenario_id', 'invariant_role', 'owned_invariant', 'blocking_status',
      'required_environment_classes', 'positive_witness', 'falsification_witness', 'verify_commands', 'declared_mutation_resistance_claim_id'],
    bindings: [
      ['REQ-LOCAL-001', 'surface.local', 'surface.local::' + anchor, 'contract', 'invariant.local', 'blocking', ['local-go'],
        ['tests/local.go::TestLocal', ['local-go'], ['go test ./tests -run TestLocal'], 0],
        ['tests/local.go::TestLocalReject', ['local-go'], ['go test ./tests -run TestLocalReject'], 1],
        ['go test ./tests'], 'claim.local'],
      ['REQ-REMOTE-001', 'surface.remote', 'surface.remote::case.remote', 'contract', 'invariant.remote', 'blocking', ['remote-ci'],
        ['tests/remote.go::TestRemote', ['remote-ci'], ['go test ./tests -run TestRemote'], 2],
        ['tests/remote.go::TestRemoteReject', ['remote-ci'], ['go test ./tests -run TestRemoteReject'], 3],
        ['go test ./tests/remote'], 'claim.remote']]};
}
// Whole chain: compact declaration -> resolver -> conformance proof contract.
function resolvedProof(compact) {
  const result = run('requirement-proof-resolver', compact, ['--local-environment-class', 'local-go']);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout).conformanceProofContract;
}
const manifestClaim = 'Profile registry fixture manifest is not live proof.';
function conformanceInput(proofContract = proof) {
  const expected = {contractId: 'proofkit.fixture.conformance', contractKind: 'proofkit.conformance-manifest', authorityState: 'canonical',
    normalizationProfile: 'proofkit.fixture.v1', sourceContract: 'docs/contracts/fixture.json', nonClaims: [manifestClaim]};
  return {schemaVersion: 2, profileId: 'local',
    policy: {knownEnvironmentClasses: ['local-go', 'remote-ci'], localEnvironmentClasses: ['local-go'], blockingStatuses: ['blocking'],
      failOnUnusedAllowedEnvironmentClass: true, expectedManifest: expected},
    manifest: {...structuredClone(expected), schemaVersion: 1, profiles: [
      {profileId: 'local', purpose: 'Local proof profile.', preconditionPolicy: 'local_only', requiredSurfaceIds: ['surface.local'],
        optionalSurfaceIds: [], allowedEnvironmentClasses: ['local-go'], nonClaims: ['Local profile fixture does not run commands.']},
      {profileId: 'remote', purpose: 'Remote proof profile.', preconditionPolicy: 'allow_preconditioned', requiredSurfaceIds: ['surface.remote'],
        optionalSurfaceIds: ['surface.local'], allowedEnvironmentClasses: ['local-go', 'remote-ci'], nonClaims: ['Remote profile fixture does not run commands.']}]},
    proofContract: structuredClone(proofContract)};
}
function invalidConformance() {
  return replace(conformanceInput(), ['manifest', 'profiles', 1, 'requiredSurfaceIds'], ['surface.remote', 'surface.zz']);
}

function migrationInput() {
  return {schemaVersion: 1, migrationId: 'proofkit.registry.migration',
    sourceProofOwners: [{ownerId: 'legacy.owner', ownerKind: 'local_script', path: 'scripts/legacy.mjs', retirementPolicy: 'candidate'},
      {ownerId: 'kept.owner', ownerKind: 'local_doc', path: 'docs/kept.md', retirementPolicy: 'retain'}],
    targetProofkitRefs: [{path: 'proofkit/report.json', targetId: 'proofkit.registry.target', targetKind: 'proofkit_report'}],
    parityEvidenceRefs: [{evidenceId: 'proofkit.registry.parity', evidenceRef: 'artifacts/parity.json', nonClaim: 'Caller-owned parity fixture.',
      sourceOwnerId: 'legacy.owner', targetId: 'proofkit.registry.target'}],
    retainedOwners: ['kept.owner'],
    retirementCandidates: [{ownerId: 'legacy.owner', reason: 'Parity evidence exists for the fixture.', removalRef: 'scripts/legacy.mjs'}],
    followUpCommands: [
      {command: 'go test ./...', commandId: 'proofkit.registry.validate', nonClaim: 'Not executed by the plan.', owner: 'consumer_repository', phase: 'post-retirement-validation'},
      {command: 'go vet ./...', commandId: 'proofkit.registry.baseline', nonClaim: 'Not executed by the plan.', owner: 'consumer_repository', phase: 'baseline'}],
    nonClaims: ['Registry fixture is not merge approval.']};
}
const blockerReasons = {
  'retained owner must reference a source proof owner': 'sourceProofOwners.ownerId',
  'parity evidence must reference a source proof owner': 'sourceProofOwners.ownerId',
  'parity evidence must reference a target proofkit ref': 'targetProofkitRefs.targetId',
  'retirement candidate must reference a source proof owner': 'sourceProofOwners.ownerId',
  'retirement candidate must not reference a retained source proof owner': 'sourceProofOwners.retirementPolicy',
  'retirement candidate must not be listed in retainedOwners': 'retainedOwners',
  'retirement candidate requires caller-provided parity evidence for a declared target': 'parityEvidenceRefs',
  'retirement candidate requires post-retirement validation commands': 'followUpCommands[phase=post-retirement-validation]',
};
function blockedMigration() {
  const input = migrationInput();
  input.retainedOwners = ['ghost.owner', 'kept.owner', 'legacy.owner'];
  input.parityEvidenceRefs.push({evidenceId: 'proofkit.registry.ghost', evidenceRef: 'artifacts/ghost.json', nonClaim: 'Ghost parity.',
    sourceOwnerId: 'ghost.source', targetId: 'ghost.target'});
  input.retirementCandidates.push({ownerId: 'kept.owner', reason: 'Retained owner fixture.', removalRef: 'docs/kept.md'},
    {ownerId: 'unknown.owner', reason: 'Unknown owner fixture.', removalRef: 'docs/unknown.md'});
  input.followUpCommands = input.followUpCommands.filter(row => row.phase !== 'post-retirement-validation');
  return input;
}

const lockfile = '{"lockfileVersion": 1, "workspaces": {"": {"name": "fixture-root"}, "packages/app": {}, "packages/lib": {}}, ' +
  '"packages": {"@fixture/app": ["@fixture/app@workspace:packages/app"], "@fixture/lib": ["@fixture/lib@workspace:packages/lib"]}}';
function workspaceInput() {
  return {schemaVersion: 1, knownPackageNames: ['@fixture/app', '@fixture/lib'], nonClaims: ['Registry fixture does not execute scripts.'],
    root: {name: 'fixture-root', dependencyRefs: [], scripts: [{name: 'check', command: 'bun run --filter @fixture/app test'}]},
    packages: [
      {name: '@fixture/app', dirName: 'app', dependencyRefs: [{field: 'dependencies', name: '@fixture/lib', version: 'workspace:*'}],
        scripts: [{name: 'test', command: 'bun test --package @fixture/app'}]},
      {name: '@fixture/lib', dirName: 'lib', scripts: [{name: 'test', command: 'bun test'}]}],
    scriptPolicy: {admittedRootScriptNames: ['check'], exactRootScripts: [{name: 'check', command: 'bun run --filter @fixture/app test'}],
      requiredPackageScriptNames: ['test'], requiredRootScriptNames: ['check'],
      selfTargetOptionNames: ['--package'], targetNamePrefixes: ['@fixture/'], targetOptionNames: ['--filter']},
    dependencyPolicy: {internalDependencyLabel: 'internal', internalNamePrefixes: ['@fixture/'], workspaceVersion: 'workspace:*'},
    lockfilePolicy: {lockfileText: lockfile, expectedSnippets: [{snippet: '"lockfileVersion": 1', failureMessage: 'Lockfile version drifted.'}]}};
}
function failingWorkspace() {
  const input = workspaceInput();
  input.knownPackageNames.push('@fixture/ghost');
  input.root.scripts.push({name: 'odd', command: 'bun run --filter @fixture/missing x'});
  input.root.dependencyRefs = [{field: 'dependencies', name: '@fixture/lib', version: '1.0.0'}];
  input.scriptPolicy.requiredPackageScriptNames = ['build', 'test'];
  input.scriptPolicy.exactRootScripts[0].command = 'different';
  input.lockfilePolicy = {lockfileText: '"name": "other"', expectedSnippets: [{snippet: 'absent', failureMessage: 'Custom lockfile failure.'}]};
  return input;
}

const ruleOrder = ['bun-lockfile', 'dependencies', 'known-package-facts', 'package-scripts', 'root-scripts', 'script-targets']
  .map(name => 'proofkit.workspace-registry.' + name);
const workspaceBuiltinClaims = [
  'Workspace registry admission does not execute scripts or native witnesses.',
  'Workspace registry admission does not generate, refresh, or authenticate lockfiles.',
  'Workspace registry admission does not infer required script policy, namespace policy, package-manager semantics, CI policy, or merge approval.',
  'Workspace registry admission reads only caller-provided facts and does not prove repository freshness.',
];
const migrationBuiltinClaims = [
  'Migration plans do not approve merge, rollout, or old-owner retirement.',
  'Migration plans do not authenticate parity evidence or decide proof freshness.',
  'Migration plans do not edit files or delete old proof owners.',
  'Migration plans do not execute native witnesses.',
];

test('every public variant and state is selected by its flags and validated', () => {
  const list = expectJSON('conformance-profile', conformanceInput(), ['--list'], 0);
  assert.deepEqual(list, {profiles: ['local', 'remote']});
  for (const flags of [['--profile', 'local'], ['--profile', 'remote', '--format', 'json']]) {
    const profile = expectJSON('conformance-profile', conformanceInput(), flags, 0);
    assert.equal(profile.profileResolutionState, 'resolved'); assert.deepEqual(profile.failures, []);
    assert.equal(profile.witnessMappingCount, profile.bindingCount * 2);
  }
  const invalid = expectJSON('conformance-profile', invalidConformance(), ['--profile', 'remote'], 1);
  assert.equal(invalid.profileResolutionState, 'invalid'); assert.ok(invalid.failures.length > 0);
  const passed = expectJSON('conformance-profile', conformanceInput(), ['--verify'], 0);
  assert.equal(passed.state, 'passed'); assert.deepEqual(passed.nonClaims, [manifestClaim]);
  const failed = expectJSON('conformance-profile', invalidConformance(), ['--verify'], 1);
  assert.deepEqual(failed.ruleResults.map(rule => rule.ruleId), failed.ruleResults.map((_, index) => 'proofkit.conformance-profile.failure.' + String(index + 1).padStart(3, '0')));
  for (const input of ['{}', '[]', '"text"', 'null', JSON.stringify({...conformanceInput(), foreign: true})]) {
    const refused = expectJSON('conformance-profile', input, ['--verify'], 1, 'verify-refusal');
    assert.equal(refused.ruleResults.length, 1); assert.deepEqual(refused.nonClaims, []);
    expectRefused('conformance-profile', input, ['--list']);
    expectRefused('conformance-profile', input, ['--profile', 'local']);
  }
  expectRefused('conformance-profile', conformanceInput(), ['--profile', 'missing']);
  const duplicate = replace(conformanceInput(), ['manifest', 'profiles', 1], structuredClone(conformanceInput().manifest.profiles[0]));
  assert.deepEqual(expectJSON('conformance-profile', duplicate, ['--list'], 0).profiles, ['local', 'local']);
  expectRefused('conformance-profile', duplicate, ['--profile', 'local']);
  expectJSON('conformance-profile', duplicate, ['--verify'], 1);
  for (const [input, status] of [[conformanceInput(), 0], [invalidConformance(), 1]]) {
    const markdown = run('conformance-profile', input, ['--profile', 'remote', '--format', 'markdown']);
    assert.equal(markdown.status, status); assert.equal(markdown.stderr, '');
    assert.ok(markdown.stdout.startsWith('# Conformance Profile: remote\n'));
    assert.throws(() => JSON.parse(markdown.stdout), SyntaxError, 'markdown must stay outside the JSON variants');
  }
  for (const command of ['conformance-profile', 'migration-plan', 'workspace-registry']) {
    const flags = command === 'conformance-profile' ? ['--list'] : [];
    expectRefused(command, '{"schemaVersion":1,"schemaVersion":1}', flags);
    expectRefused(command, '{', flags);
    const allowed = contract.commands.find(row => row.command === command).allowedFlags;
    assert.equal(allowed.includes('--agent-envelope') || allowed.includes('--contract-envelope'), false, command + ' gained an envelope mode');
  }
  const ready = expectJSON('migration-plan', migrationInput(), [], 0);
  assert.equal(ready.planState, 'ready_for_caller_review'); assert.deepEqual(ready.blockers, []);
  assert.equal(ready.phases[3].actions.length, 1);
  const blocked = expectJSON('migration-plan', blockedMigration(), [], 1);
  assert.equal(blocked.planState, 'blocked'); assert.deepEqual(blocked.phases[3].actions, []);
  assert.deepEqual(new Set(blocked.blockers.map(row => row.reason)), new Set(Object.keys(blockerReasons)));
  for (const blocker of blocked.blockers) assert.deepEqual(blocker.requiredEvidence, [blockerReasons[blocker.reason]]);
  expectRefused('migration-plan', {...migrationInput(), foreign: true});
  const workspace = expectJSON('workspace-registry', workspaceInput(), [], 0);
  assert.deepEqual(workspace.ruleResults.map(rule => rule.ruleId), ruleOrder);
  assert.deepEqual(workspace.ruleResults.map(rule => rule.status), ruleOrder.map(() => 'passed'));
  const skipped = expectJSON('workspace-registry', {...workspaceInput(), dependencyPolicy: null, lockfilePolicy: undefined}, [], 0);
  assert.deepEqual(skipped.ruleResults.slice(0, 2).map(rule => rule.status), ['skipped', 'skipped']);
  const failing = expectJSON('workspace-registry', failingWorkspace(), [], 1);
  assert.deepEqual(failing.ruleResults.map(rule => rule.status), ruleOrder.map(() => 'failed'));
  assert.deepEqual(failing.nonClaims.slice(0, 4), workspaceBuiltinClaims);
  expectRefused('workspace-registry', {...workspaceInput(), foreign: true});
});

test('whole chains feed producer records into each structural input', () => {
  // Resolver conformanceProofContract is consumed verbatim by conformance-profile.
  schema('conformance-profile', 'input', 0, conformanceInput());
  const report = expectJSON('conformance-profile', conformanceInput(), ['--profile', 'remote'], 0);
  assert.deepEqual(report.surfaces, ['surface.local', 'surface.remote']);
  // Manifest facts project the registry facts consumed by workspace-registry.
  const facts = run('workspace-manifest-facts', {schemaVersion: 1, projectionId: 'proofkit.registry.facts', nonClaims: ['Facts fixture only.'],
    dependencyFields: ['dependencies'],
    root: {manifestPath: 'package.json', manifest: {name: 'fixture-root', scripts: {check: 'bun run --filter @fixture/app test'}, dependencies: {}}},
    packages: [
      {manifestPath: 'packages/app/package.json', packageDir: 'packages/app', dirName: 'app',
        manifest: {name: '@fixture/app', scripts: {test: 'bun test --package @fixture/app'}, dependencies: {'@fixture/lib': 'workspace:*'}}},
      {manifestPath: 'packages/lib/package.json', packageDir: 'packages/lib', dirName: 'lib',
        manifest: {name: '@fixture/lib', scripts: {test: 'bun test'}, dependencies: {}}}]});
  assert.equal(facts.status, 0, facts.stderr);
  const projected = JSON.parse(facts.stdout);
  const registry = {...workspaceInput(), knownPackageNames: projected.knownPackageNames, root: projected.root, packages: projected.packages};
  schema('workspace-registry', 'input', 0, registry);
  expectJSON('workspace-registry', registry, [], 0);
  // Parity admission claims become caller-composed migration parity evidence.
  const parity = run('migration-parity-admission', {schemaVersion: 1, paritySetId: 'proofkit.registry.parity-set', nonClaims: ['Parity fixture only.'],
    sourceProofOwners: [{ownerId: 'legacy.owner', ownerKind: 'local_script', path: 'scripts/legacy.mjs'}],
    targetProofkitRefs: [{targetId: 'proofkit.registry.target', targetKind: 'proofkit_report', path: 'proofkit/report.json'}],
    parityRecords: [{equivalenceKind: 'report_summary_projection', evidenceId: 'proofkit.registry.parity', evidenceRefs: ['artifacts/parity.json'],
      legacyDigest: 'sha256:' + 'a'.repeat(64), legacySubjectRef: 'legacy.report', nonClaims: ['Fixture parity only.'],
      proofkitDigest: 'sha256:' + 'a'.repeat(64), proofkitSubjectRef: 'proofkit.report', reason: 'same projection', receiptRefs: [],
      sourceOwnerId: 'legacy.owner', status: 'caller_declared_match', targetId: 'proofkit.registry.target'}]});
  assert.equal(parity.status, 0, parity.stderr);
  const claims = JSON.parse(parity.stdout).diagnostics.find(row => row.key === 'admittedParityClaimRefs').value;
  const migration = {...migrationInput(), parityEvidenceRefs: claims.map(claim => ({evidenceId: claim.evidenceId, evidenceRef: claim.evidenceRefs[0],
    nonClaim: 'Composed from admitted parity claims.', sourceOwnerId: claim.sourceOwnerId, targetId: claim.targetId}))};
  schema('migration-plan', 'input', 0, migration);
  assert.equal(expectJSON('migration-plan', migration, [], 0).planState, 'ready_for_caller_review');
});

test('independent root and nested input inventories match the published structures', () => {
  const property = (shape, path) => path.reduce((node, key) => key === '[]' ? node.items : node.properties[key], shape);
  const inventory = (command, path, required, optional = []) => {
    const node = property(checks.get(command + '/input')[0].schema, path);
    assert.equal(node.additionalProperties, false, command + '/' + path.join('.'));
    assert.deepEqual([...(node.required ?? [])].sort(), [...required].sort(), command + '/required/' + path.join('.'));
    assert.deepEqual(Object.keys(node.properties).sort(), [...required, ...optional].sort(), command + '/members/' + path.join('.'));
  };
  const manifestIdentity = ['authorityState', 'contractId', 'contractKind', 'nonClaims', 'normalizationProfile', 'sourceContract'];
  inventory('conformance-profile', [], ['manifest', 'policy', 'proofContract', 'schemaVersion'], ['profileId']);
  inventory('conformance-profile', ['policy'], ['blockingStatuses', 'expectedManifest', 'knownEnvironmentClasses', 'localEnvironmentClasses'], ['failOnUnusedAllowedEnvironmentClass']);
  inventory('conformance-profile', ['policy', 'expectedManifest'], manifestIdentity);
  inventory('conformance-profile', ['manifest'], [...manifestIdentity, 'profiles', 'schemaVersion']);
  inventory('conformance-profile', ['manifest', 'profiles', '[]'], ['allowedEnvironmentClasses', 'nonClaims', 'optionalSurfaceIds', 'preconditionPolicy', 'profileId', 'purpose', 'requiredSurfaceIds']);
  inventory('conformance-profile', ['proofContract'], ['bindings', 'contractId', 'declarationKind', 'schemaVersion', 'surfaces']);
  inventory('conformance-profile', ['proofContract', 'surfaces', '[]'], ['preconditionedEnvironmentClasses', 'requiredEnvironmentClasses', 'surfaceId']);
  inventory('conformance-profile', ['proofContract', 'bindings', '[]'], ['bindingRecordId', 'blockingStatus', 'declaredMutationResistanceClaimId',
    'invariantRole', 'ownedInvariant', 'requiredEnvironmentClasses', 'requirementId', 'scenarioId', 'surfaceId', 'verifyCommands', 'witnessRefs']);
  inventory('migration-plan', [], ['followUpCommands', 'migrationId', 'nonClaims', 'parityEvidenceRefs', 'retainedOwners', 'retirementCandidates',
    'schemaVersion', 'sourceProofOwners', 'targetProofkitRefs']);
  inventory('migration-plan', ['sourceProofOwners', '[]'], ['ownerId', 'ownerKind', 'path', 'retirementPolicy']);
  inventory('migration-plan', ['targetProofkitRefs', '[]'], ['path', 'targetId', 'targetKind']);
  inventory('migration-plan', ['parityEvidenceRefs', '[]'], ['evidenceId', 'evidenceRef', 'nonClaim', 'sourceOwnerId', 'targetId']);
  inventory('migration-plan', ['retirementCandidates', '[]'], ['ownerId', 'reason', 'removalRef']);
  inventory('migration-plan', ['followUpCommands', '[]'], ['command', 'commandId', 'nonClaim', 'owner', 'phase']);
  inventory('workspace-registry', [], ['knownPackageNames', 'packages', 'root', 'schemaVersion', 'scriptPolicy'], ['dependencyPolicy', 'lockfilePolicy', 'nonClaims']);
  inventory('workspace-registry', ['root'], ['scripts'], ['dependencyRefs', 'name']);
  inventory('workspace-registry', ['packages', '[]'], ['dirName', 'name', 'scripts'], ['dependencyRefs']);
  inventory('workspace-registry', ['root', 'scripts', '[]'], ['command', 'name']);
  inventory('workspace-registry', ['scriptPolicy'], ['selfTargetOptionNames', 'targetNamePrefixes', 'targetOptionNames'],
    ['admittedRootScriptNames', 'exactRootScripts', 'requiredPackageScriptNames', 'requiredRootScriptNames']);
  for (const [path, required, optional] of [
    [['root', 'dependencyRefs'], ['field', 'name', 'version'], []], [['scriptPolicy', 'exactRootScripts'], ['name'], ['command']],
    [['dependencyPolicy'], ['internalNamePrefixes', 'workspaceVersion'], ['internalDependencyLabel']], [['lockfilePolicy'], ['lockfileText'], ['expectedSnippets']],
  ]) {
    const nullable = property(checks.get('workspace-registry/input')[0].schema, path).anyOf;
    assert.deepEqual(nullable.map(row => row.type).sort(), [path.length === 1 ? 'object' : 'array', 'null'].sort(), path.join('.'));
    const node = nullable.find(row => row.type !== 'null');
    const record = node.type === 'array' ? node.items : node;
    assert.deepEqual([...record.required].sort(), required, path.join('.'));
    assert.deepEqual(Object.keys(record.properties).sort(), [...required, ...optional].sort(), path.join('.'));
  }
});

test('conformance input clauses agree with schema and public CLI admission', () => {
  const input = conformanceInput();
  const binding = ['proofContract', 'bindings', 0], witness = [...binding, 'witnessRefs', 0], profile = ['manifest', 'profiles', 0];
  admits('conformance-profile', input, true, 'positive');
  closedRecord('conformance-profile', input, [], ['manifest', 'policy', 'proofContract', 'schemaVersion'], ['profileId']);
  closedRecord('conformance-profile', input, ['policy'], ['blockingStatuses', 'expectedManifest', 'knownEnvironmentClasses', 'localEnvironmentClasses'], ['failOnUnusedAllowedEnvironmentClass']);
  closedRecord('conformance-profile', input, ['policy', 'expectedManifest'], ['authorityState', 'contractId', 'contractKind', 'nonClaims', 'normalizationProfile', 'sourceContract']);
  closedRecord('conformance-profile', input, ['manifest'], ['authorityState', 'contractId', 'contractKind', 'nonClaims', 'normalizationProfile', 'profiles', 'schemaVersion', 'sourceContract']);
  closedRecord('conformance-profile', input, profile, ['allowedEnvironmentClasses', 'nonClaims', 'optionalSurfaceIds', 'preconditionPolicy', 'profileId', 'purpose', 'requiredSurfaceIds']);
  closedRecord('conformance-profile', input, ['proofContract'], ['bindings', 'contractId', 'declarationKind', 'schemaVersion', 'surfaces']);
  closedRecord('conformance-profile', input, ['proofContract', 'surfaces', 0], ['preconditionedEnvironmentClasses', 'requiredEnvironmentClasses', 'surfaceId']);
  closedRecord('conformance-profile', input, binding, ['bindingRecordId', 'blockingStatus', 'declaredMutationResistanceClaimId', 'invariantRole',
    'ownedInvariant', 'requiredEnvironmentClasses', 'requirementId', 'scenarioId', 'surfaceId', 'verifyCommands', 'witnessRefs']);
  closedRecord('conformance-profile', input, witness, ['environmentClasses', 'resolutionOrderIndex', 'role', 'selector', 'verifyCommands', 'witnessRouteId']);
  for (const [path, versions] of [[['schemaVersion'], [1, 3, '2', 2.5, null]], [['manifest', 'schemaVersion'], [0, 2, '1']], [['proofContract', 'schemaVersion'], [1, 3, '2']]]) {
    for (const version of versions) admits('conformance-profile', replace(input, path, version), false, 'version/' + path.join('.'));
  }
  admits('conformance-profile', replace(input, ['proofContract', 'declarationKind'], 'proofkit.requirement-proof-route'), false, 'declaration');
  for (const value of [null, 'true', 1]) admits('conformance-profile', replace(input, ['policy', 'failOnUnusedAllowedEnvironmentClass'], value), false, 'flag');
  admits('conformance-profile', replace(input, ['policy', 'failOnUnusedAllowedEnvironmentClass'], false), true, 'flag/false');
  admits('conformance-profile', replace(input, ['profileId'], null), false, 'profileId/null');
  for (const path of [['profileId'], [...profile, 'purpose'], ['manifest', 'contractId'], [...witness, 'selector']]) text('conformance-profile', input, path);
  for (const path of [['policy', 'knownEnvironmentClasses'], ['policy', 'blockingStatuses'], [...profile, 'requiredSurfaceIds'], [...profile, 'allowedEnvironmentClasses'],
    [...profile, 'nonClaims'], ['proofContract', 'surfaces', 0, 'requiredEnvironmentClasses'], [...binding, 'verifyCommands'], [...witness, 'environmentClasses']]) texts('conformance-profile', input, path, 1);
  texts('conformance-profile', input, [...profile, 'optionalSurfaceIds'], 0);
  texts('conformance-profile', input, ['proofContract', 'surfaces', 0, 'preconditionedEnvironmentClasses'], 0);
  admits('conformance-profile', replace(input, [...profile, 'purpose'], ' \tPadded purpose.\u2003'), true, 'text/padded');
  admits('conformance-profile', replace(input, [...profile, 'purpose'], 'Null \u0000 purpose.'), false, 'text/NUL');
  for (const path of [[...binding, 'ownedInvariant'], [...binding, 'invariantRole'], [...binding, 'declaredMutationResistanceClaimId']]) identifier('conformance-profile', input, path);
  for (const value of ['Local', 'local.go', 'local_go', '-local', 'local-', 'local--go', ' local', 'a'.repeat(257)]) {
    admits('conformance-profile', replace(input, [...profile, 'profileId'], value), false, 'profileId/' + value.slice(0, 10));
  }
  for (const value of ['local-go', 'a1-b2', 'a'.repeat(256)]) admits('conformance-profile', replace(input, [...profile, 'profileId'], value), true, 'profileId/' + value.slice(0, 10));
  for (const value of [' local_only\n', 'allow_preconditioned']) admits('conformance-profile', replace(input, [...profile, 'preconditionPolicy'], value), true, 'precondition/' + value);
  for (const value of ['remote_only', 'Local_only', '', 'local only']) admits('conformance-profile', replace(input, [...profile, 'preconditionPolicy'], value), false, 'precondition/' + value);
  const digest = at(input, [...binding, 'bindingRecordId']);
  admits('conformance-profile', replace(input, [...binding, 'bindingRecordId'], ' sha256:\t' + digest.slice(7) + '\n'), true, 'digest/padded');
  for (const value of [digest.toUpperCase(), digest.slice(0, -1), digest + '0', digest.slice(7), 'sha256:' + 'g'.repeat(64)]) {
    admits('conformance-profile', replace(input, [...binding, 'bindingRecordId'], value), false, 'digest/' + value.slice(0, 12));
  }
  admits('conformance-profile', replace(input, [...binding, 'scenarioId'], '\tsurface.local::case.local '), true, 'scenario/padded');
  for (const value of ['case.local', 'surface.local:case.local', 'surface.local::', '::case.local', 'surface.local::case local', 'surface.local:::case']) {
    admits('conformance-profile', replace(input, [...binding, 'scenarioId'], value), false, 'scenario/' + value);
  }
  const witnesses = at(input, [...binding, 'witnessRefs']);
  admits('conformance-profile', replace(input, [...binding, 'witnessRefs'], [witnesses[1], witnesses[0]]), true, 'witness/order');
  for (const refs of [[witnesses[0]], [witnesses[0], witnesses[0]], [witnesses[1], witnesses[1]], [...witnesses, witnesses[0]], []]) {
    admits('conformance-profile', replace(input, [...binding, 'witnessRefs'], refs), false, 'witness/roles/' + refs.length);
  }
  for (const value of ['negative', 'Positive', null]) admits('conformance-profile', replace(input, [...witness, 'role'], value), false, 'witness/role');
  admits('conformance-profile', replace(input, [...witness, 'resolutionOrderIndex'], 9007199254740991), true, 'order/max');
  for (const value of [9007199254740992, -1, 1.5, '1', null]) admits('conformance-profile', replace(input, [...witness, 'resolutionOrderIndex'], value), false, 'order/' + value);
  nativeOnly('conformance-profile', replace(input, ['proofContract', 'surfaces'], []), 'binding surface reference');
  admits('conformance-profile', replace(replace(input, ['proofContract', 'surfaces'], []), ['proofContract', 'bindings'], []), true, 'proof/empty');
  admits('conformance-profile', replace(input, ['manifest', 'profiles'], []), true, 'profiles/empty');
  // Exact scenario component bound: 256 is admitted through the whole chain, 257 is refused by both owners.
  const boundary = conformanceInput(resolvedProof(compactInput('a' + 'b'.repeat(255))));
  admits('conformance-profile', boundary, true, 'scenario/256');
  const scenario = at(boundary, [...binding, 'scenarioId']);
  const long = replace(boundary, [...binding, 'scenarioId'], scenario + 'b');
  admits('conformance-profile', long, false, 'scenario/257');
  assert.match(expectRefused('conformance-profile', long, ['--list']), /256-byte/);
  nativeOnly('conformance-profile', replace(input, ['manifest', 'contractId'], 'proofkit.other'), 'manifest drift');
  nativeOnly('conformance-profile', replace(input, ['policy', 'knownEnvironmentClasses'], ['remote-ci', 'local-go']), 'unsorted known classes');
  nativeOnly('conformance-profile', replace(input, ['policy', 'localEnvironmentClasses'], ['other']), 'local outside known');
  nativeOnly('conformance-profile', replace(input, [...profile, 'profileId'], 'local-20260101'), 'timestamp profile');
  nativeOnly('conformance-profile', replace(input, [...profile, 'purpose'], 'Authorization: Bearer abcdefghijklmnop'), 'secret purpose');
  nativeOnly('conformance-profile', replace(input, [...binding, 'bindingRecordId'], 'sha256:' + 'a'.repeat(64)), 'identity digest');
  nativeOnly('conformance-profile', replace(input, [...binding, 'verifyCommands'], ['go test ./... && curl example.test']), 'shell control');
  nativeOnly('conformance-profile', replace(input, [...profile, 'optionalSurfaceIds'], ['surface.local']), 'surface overlap');
});

test('migration and workspace input clauses agree with schema and public CLI admission', () => {
  const m = migrationInput();
  admits('migration-plan', m, true, 'positive');
  admits('migration-plan', blockedMigration(), true, 'blocked');
  closedRecord('migration-plan', m, [], ['followUpCommands', 'migrationId', 'nonClaims', 'parityEvidenceRefs', 'retainedOwners', 'retirementCandidates',
    'schemaVersion', 'sourceProofOwners', 'targetProofkitRefs']);
  closedRecord('migration-plan', m, ['sourceProofOwners', 0], ['ownerId', 'ownerKind', 'path', 'retirementPolicy']);
  closedRecord('migration-plan', m, ['targetProofkitRefs', 0], ['path', 'targetId', 'targetKind']);
  closedRecord('migration-plan', m, ['parityEvidenceRefs', 0], ['evidenceId', 'evidenceRef', 'nonClaim', 'sourceOwnerId', 'targetId']);
  closedRecord('migration-plan', m, ['retirementCandidates', 0], ['ownerId', 'reason', 'removalRef']);
  closedRecord('migration-plan', m, ['followUpCommands', 0], ['command', 'commandId', 'nonClaim', 'owner', 'phase']);
  for (const version of [0, 2, '1', 1.5, null]) admits('migration-plan', {...m, schemaVersion: version}, false, 'version');
  for (const path of [['migrationId'], ['sourceProofOwners', 0, 'ownerId'], ['targetProofkitRefs', 0, 'targetId'], ['parityEvidenceRefs', 0, 'evidenceId'],
    ['followUpCommands', 0, 'commandId']]) identifier('migration-plan', m, path);
  vocabulary('migration-plan', m, ['sourceProofOwners', 0, 'ownerKind'], ['local_script', 'local_manifest', 'local_doc', 'local_test', 'other']);
  vocabulary('migration-plan', m, ['sourceProofOwners', 0, 'retirementPolicy'], ['candidate', 'retain']);
  vocabulary('migration-plan', m, ['targetProofkitRefs', 0, 'targetKind'], ['proofkit_input', 'proofkit_report', 'proofkit_profile', 'proofkit_view']);
  vocabulary('migration-plan', m, ['followUpCommands', 0, 'phase'], ['baseline', 'parallel-proof', 'parity-check', 'retire-old-owner', 'post-retirement-validation']);
  vocabulary('migration-plan', m, ['followUpCommands', 0, 'owner'], ['consumer_repository']);
  for (const path of [['sourceProofOwners', 0, 'path'], ['parityEvidenceRefs', 0, 'nonClaim'], ['retirementCandidates', 0, 'reason'], ['followUpCommands', 0, 'command']]) {
    text('migration-plan', m, path);
  }
  admits('migration-plan', replace(m, ['sourceProofOwners', 0, 'path'], ' scripts/legacy.mjs\t'), true, 'path/padded');
  for (const path of [['sourceProofOwners'], ['targetProofkitRefs']]) texts('migration-plan', m, path, 1);
  for (const path of [['parityEvidenceRefs'], ['retirementCandidates'], ['followUpCommands']]) admits('migration-plan', replace(m, path, []), true, 'empty/' + path);
  texts('migration-plan', m, ['nonClaims'], 0);
  kinds('migration-plan', m, ['retainedOwners'], ['array'], 'retained');
  admits('migration-plan', replace(m, ['retainedOwners'], [' \u00a0kept.owner\t']), true, 'retained/padded');
  admits('migration-plan', replace(m, ['retainedOwners'], ['\ta' + 'b'.repeat(255) + ' ']), true, 'retained/256');
  admits('migration-plan', replace(m, ['retainedOwners'], ['\ta' + 'b'.repeat(256) + ' ']), false, 'retained/257');
  for (const value of ['kept owner', '1kept', '', null]) admits('migration-plan', replace(m, ['retainedOwners'], [value]), false, 'retained/' + value);
  nativeOnly('migration-plan', replace(m, ['sourceProofOwners', 0, 'path'], '../legacy.mjs'), 'unsafe path');
  nativeOnly('migration-plan', replace(m, ['followUpCommands', 0, 'command'], 'go test ./... && curl example.test'), 'shell control');
  nativeOnly('migration-plan', replace(m, ['migrationId'], 'proofkit.2026-01-01'), 'timestamp id');
  nativeOnly('migration-plan', replace(m, ['retainedOwners'], ['kept.owner', ' kept.owner']), 'duplicate retained');
  nativeOnly('migration-plan', replace(m, ['retirementCandidates', 0, 'reason'], 'token=ghp_secretvalue'), 'secret reason');

  const w = workspaceInput();
  admits('workspace-registry', w, true, 'positive');
  admits('workspace-registry', failingWorkspace(), true, 'failing');
  closedRecord('workspace-registry', w, [], ['knownPackageNames', 'packages', 'root', 'schemaVersion', 'scriptPolicy'], ['dependencyPolicy', 'lockfilePolicy', 'nonClaims']);
  closedRecord('workspace-registry', w, ['root'], ['scripts'], ['dependencyRefs', 'name']);
  closedRecord('workspace-registry', w, ['packages', 0], ['dirName', 'name', 'scripts'], ['dependencyRefs']);
  closedRecord('workspace-registry', w, ['root', 'scripts', 0], ['command', 'name']);
  closedRecord('workspace-registry', w, ['packages', 0, 'dependencyRefs', 0], ['field', 'name', 'version']);
  closedRecord('workspace-registry', w, ['scriptPolicy'], ['selfTargetOptionNames', 'targetNamePrefixes', 'targetOptionNames'],
    ['admittedRootScriptNames', 'exactRootScripts', 'requiredPackageScriptNames', 'requiredRootScriptNames']);
  closedRecord('workspace-registry', w, ['scriptPolicy', 'exactRootScripts', 0], ['name'], ['command']);
  closedRecord('workspace-registry', w, ['dependencyPolicy'], ['internalNamePrefixes', 'workspaceVersion'], ['internalDependencyLabel']);
  closedRecord('workspace-registry', w, ['lockfilePolicy'], ['lockfileText'], ['expectedSnippets']);
  closedRecord('workspace-registry', w, ['lockfilePolicy', 'expectedSnippets', 0], ['failureMessage', 'snippet']);
  for (const version of [0, 2, '1', null]) admits('workspace-registry', {...w, schemaVersion: version}, false, 'version');
  for (const path of [['dependencyPolicy'], ['lockfilePolicy'], ['root', 'dependencyRefs'], ['packages', 0, 'dependencyRefs'], ['scriptPolicy', 'admittedRootScriptNames'],
    ['scriptPolicy', 'exactRootScripts'], ['scriptPolicy', 'requiredPackageScriptNames'], ['scriptPolicy', 'requiredRootScriptNames'], ['lockfilePolicy', 'expectedSnippets']]) {
    admits('workspace-registry', replace(w, path, null), true, 'nullable/' + path.join('.'));
    kinds('workspace-registry', w, path, [path.length === 1 ? 'object' : 'array', 'null'], 'nullable');
  }
  for (const path of [['nonClaims'], ['root', 'name'], ['scriptPolicy', 'exactRootScripts', 0, 'command'], ['dependencyPolicy', 'internalDependencyLabel']]) {
    admits('workspace-registry', replace(w, path, null), false, 'non-null optional/' + path.join('.'));
  }
  for (const path of [['knownPackageNames'], ['scriptPolicy', 'selfTargetOptionNames'], ['scriptPolicy', 'targetNamePrefixes'], ['scriptPolicy', 'targetOptionNames'],
    ['dependencyPolicy', 'internalNamePrefixes']]) texts('workspace-registry', w, path, 1);
  texts('workspace-registry', w, ['nonClaims'], 0);
  for (const value of [[], [' check ']]) admits('workspace-registry', replace(w, ['scriptPolicy', 'admittedRootScriptNames'], value), true, 'admitted-names');
  for (const value of [[' '], [42]]) admits('workspace-registry', replace(w, ['scriptPolicy', 'admittedRootScriptNames'], value), false, 'admitted-names');
  for (const path of [['root', 'name'], ['packages', 0, 'name'], ['lockfilePolicy', 'lockfileText'], ['lockfilePolicy', 'expectedSnippets', 0, 'failureMessage'],
    ['packages', 0, 'dependencyRefs', 0, 'version']]) text('workspace-registry', w, path);
  for (const value of ['...', '.app', 'app.', ' app\t', 'app dir']) admits('workspace-registry', replace(w, ['packages', 0, 'dirName'], value), true, 'dirName/' + value);
  for (const value of ['.', '..', ' .. ', 'app/x', 'app\\x', 'a\u0000p', '', '  ']) admits('workspace-registry', replace(w, ['packages', 0, 'dirName'], value), false, 'dirName/' + JSON.stringify(value));
  for (const path of [['root', 'scripts', 0, 'command'], ['scriptPolicy', 'exactRootScripts', 0, 'command']]) {
    admits('workspace-registry', replace(w, path, '\nbun run --filter @fixture/app test\r\n'), true, 'command/padded-newline');
    admits('workspace-registry', replace(w, path, 'bun run\t--filter @fixture/app test'), true, 'command/tab');
    for (const value of ['bun run\ntest', 'bun run\rtest', 'bun\u0000run', ' ']) admits('workspace-registry', replace(w, path, value), false, 'command/' + JSON.stringify(value));
  }
  nativeOnly('workspace-registry', replace(w, ['knownPackageNames'], ['@fixture/app', ' @fixture/app']), 'duplicate known');
  nativeOnly('workspace-registry', replace(w, ['packages', 1, 'name'], '@fixture/app'), 'duplicate package');
  nativeOnly('workspace-registry', replace(w, ['lockfilePolicy', 'expectedSnippets', 0, 'failureMessage'], 'token=ghp_secretvalue'), 'secret message');
});

// Free-text leaves are caller or native message text; every other string leaf
// is a literal, vocabulary or identifier grammar and must reject foreign text.
function freeText(command, output, name, value) {
  if (command === 'conformance-profile') {
    return /^(purpose|nonClaims\.\d+|failures\.\d+|environmentClasses\.\d+|verifyCommands\.\d+)$/.test(name)
      || output.state === 'failed' && /^ruleResults\.\d+\.message$/.test(name);
  }
  if (command === 'migration-plan') {
    // Builtin claims are required members of the sorted claim union.
    if (/^nonClaims\.\d+$/.test(name)) return !migrationBuiltinClaims.includes(value);
    return /^(sourceProofOwners\.\d+\.path|targetProofkitRefs\.\d+\.path|parityEvidenceRefs\.\d+\.(evidenceRef|nonClaim)|retirementCandidates\.\d+\.(reason|removalRef)|phases\.\d+\.actions\.\d+\.evidenceRefs\.\d+)$/.test(name);
  }
  // Workspace diagnostic strings are failure messages; counters are numbers or booleans.
  return /^nonClaims\.([4-9]|\d{2,})$/.test(name) || /^(diagnostics\.\d+|ruleResults\.\d+\.diagnostics\.\d+)\.value$/.test(name);
}
const literalBooleans = {
  'workspace-registry': name => /^ruleResults\.\d+\.diagnostics\.\d+\.value$/.test(name),
  'conformance-profile': () => false, 'migration-plan': () => false,
};
function carrier(command, index, output, label) {
  const reject = (path, replacement, why) => schema(command, 'output', index, replace(output, path, replacement), false, `${label}/${why}/${path.join('.')}`);
  const kind = value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
  function visit(value, path) {
    if (path.length) {
      for (const [type, sample] of [['null', null], ['boolean', true], ['number', 7], ['string', 'wrong-kind'], ['array', []], ['object', {}]]) {
        if (type !== kind(value)) reject(path, sample, 'kind-' + type);
      }
    }
    if (kind(value) === 'object') {
      reject([...path, 'foreign'], true, 'foreign');
      for (const key of Object.keys(value)) schema(command, 'output', index, without(output, [...path, key]), false, `${label}/required/${[...path, key].join('.')}`);
    }
    if (kind(value) === 'array') for (const item of [null, true, 7, [], {}]) reject(path, [...value, item], 'item');
    if (kind(value) === 'string') {
      const permitted = freeText(command, output, path.join('.'), value);
      schema(command, 'output', index, replace(output, path, 'Foreign value!'), permitted, `${label}/foreign-text/${path.join('.')}`);
      if (permitted) schema(command, 'output', index, replace(output, path, ' '), false, `${label}/blank/${path.join('.')}`);
    }
    if (kind(value) === 'number') {
      for (const bad of [-1, 0.5]) reject(path, bad, 'number-' + bad);
    }
    if (kind(value) === 'boolean' && literalBooleans[command](path.join('.'))) reject(path, !value, 'boolean-literal');
    if (kind(value) === 'object' || kind(value) === 'array') for (const [key, child] of Object.entries(value)) visit(child, [...path, Array.isArray(value) ? Number(key) : key]);
  }
  visit(output, []);
}

test('observed outputs reject every clause mutant of their carrier', () => {
  for (const [input, flags, status] of [[conformanceInput(), ['--list'], 0], [conformanceInput(), ['--profile', 'remote'], 0],
    [invalidConformance(), ['--profile', 'remote'], 1], [conformanceInput(), ['--verify'], 0], [invalidConformance(), ['--verify'], 1], ['{}', ['--verify'], 1]]) {
    carrier('conformance-profile', outputIndex('conformance-profile', flags), expectJSON('conformance-profile', input, flags, status), flags.join(' '));
  }
  for (const [input, status, label] of [[migrationInput(), 0, 'ready'], [blockedMigration(), 1, 'blocked']]) {
    carrier('migration-plan', 0, expectJSON('migration-plan', input, [], status), label);
  }
  for (const [input, status, label] of [[workspaceInput(), 0, 'passed'], [{...workspaceInput(), dependencyPolicy: null, lockfilePolicy: null}, 0, 'skipped'],
    [failingWorkspace(), 1, 'failed']]) {
    carrier('workspace-registry', 0, expectJSON('workspace-registry', input, [], status), label);
  }
});

test('output sums couple states, counters and exact limits', () => {
  const profile = expectJSON('conformance-profile', conformanceInput(), ['--profile', 'local'], 0);
  for (const key of ['bindingCount', 'commandCount', 'optionalSurfaceCount', 'preconditionedBindingCount', 'requirementCount', 'scenarioCount', 'surfaceCount', 'witnessMappingCount']) {
    schema('conformance-profile', 'output', 1, {...profile, [key]: 0}, true, key + '/0');
  }
  schema('conformance-profile', 'output', 1, {...profile, requiredSurfaceCount: 0}, false, 'requiredSurfaceCount/0');
  schema('conformance-profile', 'output', 1, {...profile, schemaVersion: 1}, false, 'profile/version');
  schema('conformance-profile', 'output', 1, {...profile, nonClaims: []}, false, 'profile/nonClaims');
  for (const state of ['resolved', 'invalid']) schema('conformance-profile', 'output', 1, {...profile, profileResolutionState: state}, true, state);
  const verify = expectJSON('conformance-profile', conformanceInput(), ['--verify'], 0);
  const failure = index => ({diagnostics: [], message: 'Independent failure.', ruleId: 'proofkit.conformance-profile.failure.' + index, status: 'failed'});
  for (const [rules, valid] of [[[failure('001')], true], [[failure('999'), failure('1000')], true], [[failure('000')], false], [[failure('01')], false],
    [[failure('0001')], false], [[...verify.ruleResults, failure('001')], false], [[], false], [[verify.ruleResults[0], verify.ruleResults[0]], false]]) {
    schema('conformance-profile', 'output', 2, {...verify, state: 'failed', ruleResults: rules}, valid, 'verify-rules/' + rules.map(rule => rule.ruleId).join(','));
  }
  schema('conformance-profile', 'output', 2, {...verify, diagnostics: [{key: 'x', value: 'y'}]}, false, 'verify/diagnostics');
  schema('conformance-profile', 'output', 2, {...verify, reportId: 'proofkit.conformance-profile.local'}, false, 'verify/reportId');
  const list = expectJSON('conformance-profile', conformanceInput(), ['--list'], 0);
  for (const [ids, valid] of [[[], true], [['a'.repeat(256)], true], [['a'.repeat(257)], false], [['Local'], false], [['local.go'], false]]) {
    schema('conformance-profile', 'output', 0, {...list, profiles: ids}, valid, 'list/' + ids.join(',').slice(0, 10));
  }
  schema('conformance-profile', 'output', 0, {...list, schemaVersion: 2}, false, 'list/no-version');

  const ready = expectJSON('migration-plan', migrationInput(), [], 0), blocked = expectJSON('migration-plan', blockedMigration(), [], 1);
  schema('migration-plan', 'output', 0, {...ready, planState: 'blocked'}, false, 'ready-as-blocked');
  schema('migration-plan', 'output', 0, {...blocked, planState: 'ready_for_caller_review'}, false, 'blocked-as-ready');
  schema('migration-plan', 'output', 0, {...ready, blockers: blocked.blockers}, false, 'ready-with-blockers');
  schema('migration-plan', 'output', 0, replace(blocked, ['phases', 3, 'actions'], ready.phases[3].actions), false, 'blocked-with-retire');
  schema('migration-plan', 'output', 0, {...ready, phases: [...ready.phases].reverse()}, false, 'phase-order');
  schema('migration-plan', 'output', 0, {...ready, nonClaims: migrationBuiltinClaims.slice(1).concat('Other claim.')}, false, 'builtin-claim-missing');
  schema('migration-plan', 'output', 0, {...ready, nonClaims: migrationBuiltinClaims}, true, 'builtin-claims-only');
  // Independently spelled blockerId suffixes: every reason word survives and a
  // camelCase field name splits into lowercase words.
  const blockerSuffixes = {
    'retained owner must reference a source proof owner': 'retained-owner-must-reference-a-source-proof-owner',
    'parity evidence must reference a source proof owner': 'parity-evidence-must-reference-a-source-proof-owner',
    'parity evidence must reference a target proofkit ref': 'parity-evidence-must-reference-a-target-proofkit-ref',
    'retirement candidate must reference a source proof owner': 'retirement-candidate-must-reference-a-source-proof-owner',
    'retirement candidate must not reference a retained source proof owner': 'retirement-candidate-must-not-reference-a-retained-source-proof-owner',
    'retirement candidate must not be listed in retainedOwners': 'retirement-candidate-must-not-be-listed-in-retained-owners',
    'retirement candidate requires caller-provided parity evidence for a declared target': 'retirement-candidate-requires-caller-provided-parity-evidence-for-a-declared-target',
    'retirement candidate requires post-retirement validation commands': 'retirement-candidate-requires-post-retirement-validation-commands',
  };
  assert.ok(blocked.blockers.some(row => row.reason === 'retirement candidate must not be listed in retainedOwners'));
  for (const row of blocked.blockers) {
    assert.equal(row.blockerId, `proofkit.migration-plan.blocker.${row.ownerId}.${blockerSuffixes[row.reason]}`, row.reason);
  }
  const blocker = blocked.blockers[0];
  for (const [field, value] of [['requiredEvidence', ['retainedOwners']], ['blockerId', blocker.blockerId.replace(/[^.]+$/, 'other-reason')],
    ['reason', 'retained owner must reference a target']]) {
    schema('migration-plan', 'output', 0, replace(blocked, ['blockers', 0, field], value), false, 'blocker/' + field);
  }
  const retire = ready.phases[3].actions[0];
  assert.equal(retire.actionId, 'proofkit.migration-plan.action.retire-legacy.owner');
  assert.equal(retire.instruction, 'Review retirement candidate legacy.owner: Parity evidence exists for the fixture.');
  schema('migration-plan', 'output', 0, replace(ready, ['phases', 3, 'actions', 0, 'actionId'], 'proofkit.migration-plan.action.retire-' + 'a'.repeat(256)), true, 'retire-id/256');
  schema('migration-plan', 'output', 0, replace(ready, ['phases', 3, 'actions', 0, 'actionId'], 'proofkit.migration-plan.action.retire-' + 'a'.repeat(257)), false, 'retire-id/257');
  schema('migration-plan', 'output', 0, replace(ready, ['phases', 3, 'actions', 0, 'evidenceRefs'], []), false, 'retire-evidence/empty');
  schema('migration-plan', 'output', 0, replace(ready, ['phases', 2, 'actions', 0, 'evidenceRefs'], []), true, 'parity-evidence/empty');
  schema('migration-plan', 'output', 0, replace(ready, ['phases', 0, 'actions', 0, 'evidenceRefs'], []), false, 'baseline-evidence/empty');

  const passed = expectJSON('workspace-registry', workspaceInput(), [], 0), failed = expectJSON('workspace-registry', failingWorkspace(), [], 1);
  schema('workspace-registry', 'output', 0, {...passed, state: 'failed'}, false, 'passed-as-failed');
  schema('workspace-registry', 'output', 0, {...failed, state: 'passed'}, false, 'failed-as-passed');
  schema('workspace-registry', 'output', 0, replace(passed, ['summary', 'failureCount'], 1), false, 'passed-failure-count');
  schema('workspace-registry', 'output', 0, replace(failed, ['summary', 'failureCount'], 0), false, 'failed-failure-count');
  schema('workspace-registry', 'output', 0, replace(passed, ['ruleResults', 2], failed.ruleResults[2]), false, 'passed-with-failed-rule');
  schema('workspace-registry', 'output', 0, {...passed, ruleResults: [...passed.ruleResults].reverse()}, false, 'rule-order');
  schema('workspace-registry', 'output', 0, {...passed, nonClaims: [...workspaceBuiltinClaims].reverse()}, false, 'builtin-order');
  schema('workspace-registry', 'output', 0, {...passed, nonClaims: workspaceBuiltinClaims.slice(0, 3)}, false, 'builtin-missing');
  schema('workspace-registry', 'output', 0, {...passed, nonClaims: [...workspaceBuiltinClaims, 'Independent caller claim.', 'Another.']}, true, 'caller-claims');
  schema('workspace-registry', 'output', 0, replace(passed, ['summary', 'checkedItemCount'], 0), false, 'checked-zero');
  const lockRule = failed.ruleResults[0];
  assert.equal(lockRule.message, `${lockRule.diagnostics.filter(row => row.key.startsWith('failure.')).length} workspace registry issue(s) found`);
  for (const [message, valid] of [['1 workspace registry issue(s) found', true], ['0 workspace registry issue(s) found', false], ['01 workspace registry issue(s) found', false], ['passed', false]]) {
    schema('workspace-registry', 'output', 0, replace(failed, ['ruleResults', 0, 'message'], message), valid, 'message/' + message);
  }
  for (const [key, valid] of [['failure.001', true], ['failure.1000', true], ['failure.000', false], ['failure.01', false], ['failures.001', false]]) {
    schema('workspace-registry', 'output', 0, replace(failed, ['diagnostics', 0, 'key'], key), valid, 'failure-key/' + key);
  }
  const skipped = expectJSON('workspace-registry', {...workspaceInput(), dependencyPolicy: null, lockfilePolicy: null}, [], 0);
  schema('workspace-registry', 'output', 0, replace(skipped, ['ruleResults', 0, 'diagnostics', 0, 'value'], 1), false, 'skipped-checks');
  schema('workspace-registry', 'output', 0, replace(skipped, ['ruleResults', 1, 'status'], 'passed'), false, 'skipped-as-passed');
  schema('workspace-registry', 'output', 0, replace(passed, ['ruleResults', 2, 'status'], 'skipped'), false, 'unskippable-rule');
});
