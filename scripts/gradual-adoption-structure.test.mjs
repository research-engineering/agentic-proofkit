import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport, spawnWithInputFile} from './cli-process.mjs';
import {expandSharedDefinitions} from './schema-definitions.mjs';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_GRADUAL_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const commands = ['gradual-adoption', 'gradual-adoption-guidance', 'gradual-adoption-bootstrap'];
const requiredInputs = {
  'gradual-adoption': ['adoptionId', 'adoptionMode', 'agentReport', 'budget', 'module', 'nativeWitnesses', 'nonClaims', 'packageVersionRef', 'proofBinding', 'repository', 'rollback', 'rolloutClaim', 'schemaVersion'],
  'gradual-adoption-guidance': ['guidanceId', 'guidanceMode', 'nonClaims', 'schemaVersion', 'sourceReport'],
  'gradual-adoption-bootstrap': ['bootstrapId', 'budget', 'guidanceMode', 'nativeWitnesses', 'packageVersionRef', 'repository', 'rollback', 'schemaVersion'],
};
const optionalInputs = {
  'gradual-adoption': [],
  'gradual-adoption-guidance': ['agentGuidance', 'modernization', 'ownerRoute', 'scopeEvidence'],
  'gradual-adoption-bootstrap': ['checkedScope', 'commands', 'module', 'nonClaims', 'ownerRoute', 'paths', 'proofBindingPath', 'touchedRuleIds'],
};
const hardInputTypes = {
  'gradual-adoption': {adoptionId: 'string', adoptionMode: 'string', agentReport: 'object', budget: 'object', module: 'object',
    nativeWitnesses: 'object', nonClaims: 'array', packageVersionRef: 'string', proofBinding: 'object', repository: 'object', rollback: 'object', rolloutClaim: 'boolean'},
  'gradual-adoption-guidance': {guidanceId: 'string', guidanceMode: 'string', nonClaims: 'array', sourceReport: 'object'},
  'gradual-adoption-bootstrap': {bootstrapId: 'string', budget: 'object', guidanceMode: 'string', nativeWitnesses: 'object', packageVersionRef: 'string', repository: 'object', rollback: 'object'},
};
const reportKeys = ['diagnostics', 'nonClaims', 'reportId', 'reportKind', 'ruleResults', 'schemaVersion', 'state', 'summary'];
const outputKeys = {
  'gradual-adoption': reportKeys, 'gradual-adoption-guidance': reportKeys,
  'gradual-adoption-bootstrap': ['agentActionPlan', 'exitCode', 'nextCommands', 'payloads', 'plannedFiles', 'report', 'witnessPlan'],
};
const checks = new Map(commands.flatMap(command => ['input', 'output'].map(direction => {
  const record = contract.commands.find(row => row.command === command)[direction + 'Contract'];
  const definition = contract.contractDefinitions.find(row => row.definitionId === record.rootDefinitionRef);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema');
  // Ajv validates the published schema; navigation reads its shared-definition expansion.
  return [command + '/' + direction, definition.fieldTree.variants.map(row => ({
    id: row.variantId, check: new Ajv2020({strict: false, validateFormats: false}).compile(row.schema), schema: expandSharedDefinitions(row.schema),
  }))];
})));
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-gradual-contract-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 120000, maxBuffer: 2 << 20,
    env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

function bootstrap() {
  return {
    schemaVersion: 1, bootstrapId: 'proofkit.fixture.bootstrap', packageVersionRef: 'proofkit@fixture',
    guidanceMode: 'observe', checkedScope: 'none', touchedRuleIds: [], commands: ['go test ./...'],
    nonClaims: ['Fixture does not prove witness execution.'], proofBindingPath: 'proofkit/bindings.json',
    budget: {copiedVerifierFileCount: 0, customRuleCount: 0, maxAddedSeconds: 10, maxCustomRuleCount: 0,
      maxProfileLines: 80, maxSetupMinutes: 20, profileLines: 42},
    repository: {customRuleBoundary: 'profile_only', primaryLanguages: ['go'], profilePath: 'proofkit/profile.json',
      repositoryClass: 'go_cli', repositoryId: 'proofkit.fixture.repository', verifierCodeCopied: false},
    rollback: {disableCommand: 'remove proofkit report', owner: 'repository owner', versionPin: 'proofkit@fixture'},
    module: {moduleId: 'proofkit.fixture.module', requirementIds: ['REQ-FIXTURE-001'], specPath: 'docs/specs/fixture/requirements.json'},
    nativeWitnesses: {commands: [{id: 'proofkit.fixture.command', schemaVersion: 1, argv: ['go', 'test', './...'], cwd: '.',
      timeoutMs: 60000, networkPolicy: 'none', credentialClass: 'none', cachePolicy: 'read-only', parallelGroup: 'local-go',
      environment: {inherit: 'none', allowlist: [], classes: ['local-go']}, exitCodePolicy: {kind: 'zero', successCodes: [0]}, expectedArtifacts: []}],
    vocabulary: {artifactKinds: ['json'], credentialClasses: ['none'], environmentClasses: ['local-go'], parallelGroups: ['local-go'],
      environmentClassPolicies: [{environmentClass: 'local-go', credentialClasses: ['none'], networkPolicies: ['none'], cachePolicies: ['read-only']}]}},
    paths: {adoptionGuidancePath: 'proofkit/guidance.json', adoptionProfilePath: 'proofkit/adoption.json',
      adoptionReportArtifactPath: 'artifacts/adoption.json', guidanceReportArtifactPath: 'artifacts/guidance.json', witnessPlanInputPath: 'proofkit/witness.json'},
    ownerRoute: {evidencePaths: ['artifacts/adoption.json'], primaryOwner: 'repository owner',
      proofBindingPaths: ['proofkit/bindings.json'], specPaths: ['docs/specs/fixture/requirements.json']},
  };
}
function adoption() {
  const b = bootstrap();
  return {schemaVersion: 1, adoptionId: 'proofkit.fixture.adoption', adoptionMode: 'non_blocking', rolloutClaim: false,
    packageVersionRef: b.packageVersionRef, budget: b.budget, module: b.module, nativeWitnesses: b.nativeWitnesses,
    repository: b.repository, rollback: b.rollback, nonClaims: b.nonClaims,
    proofBinding: {bindingFormat: 'requirement_to_witness', bindingPath: b.proofBindingPath,
      requirementIds: b.module.requirementIds, witnessCommandIds: ['proofkit.fixture.command']},
    agentReport: {artifactPath: 'artifacts/adoption.json', outputMode: 'non_blocking', reportKind: 'proofkit.gradual-adoption',
      routeQuestions: ['what changed', 'what proves it', 'who owns it'], schemaId: 'proofkit.fixture.profile'},
  };
}
function guidance() {
  return {schemaVersion: 1, guidanceId: 'proofkit.fixture.guidance', guidanceMode: 'observe', nonClaims: bootstrap().nonClaims,
    sourceReport: {schemaVersion: 1, reportId: 'proofkit.fixture.source', reportKind: 'proofkit.fixture.source', state: 'passed', ruleResults: []},
    scopeEvidence: {basis: 'caller_provided_touched_rule_ids', checkedScope: 'none', touchedRuleIds: []}, ownerRoute: bootstrap().ownerRoute,
    agentGuidance: {artifactPath: 'artifacts/guidance.json', blockedPreconditions: [], callerSuggestedAutofixCandidates: [], commands: [],
      minimalAdoptionPath: ['Keep adoption non-blocking.'], proofBindingsMissing: [], reportKind: 'proofkit.gradual-adoption-guidance',
      requiredNextActions: [], routeQuestions: ['what changed', 'what proves it', 'who owns it'], schemaId: 'proofkit.fixture.guidance'},
  };
}
function envelope() {
  const b = bootstrap(), g = guidance();
  return {schema: 'proofkit.gradual-adoption-profile.v1', input: adoption(),
    guidance: {guidanceId: g.guidanceId, defaultMode: g.guidanceMode, nonClaims: g.nonClaims,
      scopeEvidence: g.scopeEvidence, ownerRoute: g.ownerRoute, agentGuidance: g.agentGuidance},
    bootstrap: {bootstrapId: b.bootstrapId, defaultMode: b.guidanceMode, scopeEvidence: {checkedScope: b.checkedScope, touchedRuleIds: []},
      commands: b.commands, nonClaims: b.nonClaims, paths: b.paths}};
}
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, replacement) {
  const result = structuredClone(value); at(result, path.slice(0, -1))[path.at(-1)] = replacement; return result;
}
function schema(command, direction, index, value, expected = true, label = '') {
  const check = checks.get(command + '/' + direction)[index].check;
  assert.equal(check(value), expected, `${command}/${direction}/${index}/${label}: ${JSON.stringify(check.errors)}`);
}
const pathLauncher = {AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'path', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: ''};
function invoke(command, input, phase = 'passed', flags = [], inputIndex = 0, launcher = pathLauncher) {
  if (typeof input !== 'string' && phase !== 'refused' && phase !== 'repair') schema(command, 'input', inputIndex, input);
  const result = spawnWithInputFile(binary, [command, '--input', '-', ...flags], {
    input: typeof input === 'string' ? input : JSON.stringify(input), encoding: 'utf8', timeout: 10000, maxBuffer: 8 << 20,
    env: {...process.env, ...launcher},
  });
  assertCLITransport(result);
  if (phase === 'refused') {
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.notEqual(result.stderr, ''); return result;
  }
  assert.equal(result.stderr, '', result.stderr);
  assert.equal(result.status, phase === 'passed' ? 0 : 1, result.stdout);
  const value = JSON.parse(result.stdout);
  let outputIndex = 0;
  if (flags.includes('--materialization-manifest')) outputIndex = 1;
  if (flags.includes('--agent-envelope')) outputIndex = command === 'gradual-adoption-bootstrap' ? 2 : 1;
  if (phase === 'repair') outputIndex++;
  schema(command, 'output', outputIndex, value);
  if (phase !== 'repair') {
    const state = value.state ?? value.report?.state ?? value.sourceReport?.state;
    assert.equal(state, phase);
  } else assert.equal(value.envelopeId, 'proofkit.agent-envelope.invalid-input');
  return value;
}

test('whole public variants conserve success, reporting failure, repair and payload chains', () => {
  for (const [command, input] of [['gradual-adoption', adoption()], ['gradual-adoption-guidance', guidance()], ['gradual-adoption-bootstrap', bootstrap()]]) {
    const output = invoke(command, input);
    if (command === 'gradual-adoption-bootstrap') {
      invoke('gradual-adoption', output.payloads.adoptionProfile);
      invoke('gradual-adoption-guidance', output.payloads.adoptionGuidance);
      const manifest = invoke(command, input, 'passed', ['--materialization-manifest']);
      assert.equal(manifest.files.filter(file => file.contentKind === 'json').length, 4);
      for (const file of manifest.files.filter(file => file.contentKind === 'json')) {
        assert.deepEqual(JSON.parse(file.content), output.payloads[file.payloadKey]);
      }
    }
    if (command !== 'gradual-adoption') {
      invoke(command, input, 'passed', ['--agent-envelope']);
      invoke(command, '{}', 'repair', ['--agent-envelope']);
      invoke(command, '{"schemaVersion":1,"schemaVersion":1}', 'refused', ['--agent-envelope']);
    }
    invoke(command, '{}', 'refused');
    invoke(command, {...input, foreign: 'unknown'}, 'refused');
    const failed = command === 'gradual-adoption-guidance' ? {...input, agentGuidance: false} : replace(input, ['budget', 'profileLines'], 99);
    invoke(command, failed, 'failed');
    if (command !== 'gradual-adoption') invoke(command, failed, 'failed', ['--agent-envelope']);
    if (command === 'gradual-adoption-bootstrap') invoke(command, failed, 'failed', ['--materialization-manifest']);
  }
});

test('guidance optional, ignored and arbitrary JSON domains are not replaced by successful-output shapes', () => {
  const input = guidance();
  for (const member of [null, false, 0, '', [], {unknown: {nested: [null, true, 1, 'text']}}]) {
    for (const field of ['agentGuidance', 'ownerRoute', 'scopeEvidence', 'modernization']) {
      invoke('gradual-adoption-guidance', {...input, [field]: member}, field === 'modernization' && member === null ? 'passed' : 'failed');
    }
    for (const field of ['summary', 'diagnostics', 'nonClaims']) invoke('gradual-adoption-guidance', replace(input, ['sourceReport', field], member));
    const source = {...input.sourceReport, ruleResults: [{ruleId: 'proofkit.fixture.rule', status: 'passed', diagnostics: member, message: member}]};
    invoke('gradual-adoption-guidance', {...input, sourceReport: source});
  }
  for (const field of ['agentGuidance', 'ownerRoute', 'scopeEvidence']) {
    const copy = structuredClone(input); delete copy[field]; invoke('gradual-adoption-guidance', copy, 'failed');
  }
  const contractInput = envelope(); delete contractInput.bootstrap;
  invoke('gradual-adoption-guidance', contractInput, 'passed', ['--contract-envelope'], 1);
  invoke('gradual-adoption', {schema: contractInput.schema, input: contractInput.input}, 'passed', ['--contract-envelope'], 1);
});

test('eight guidance override variants preserve ignored operands without losing required objects', () => {
  for (let mask = 0; mask < 8; mask++) {
    const input = envelope(), flags = ['--contract-envelope']; delete input.bootstrap;
    if (mask & 1) {delete input.guidance.defaultMode; flags.push('--guidance-mode', 'observe');}
    if (mask & 4) input.guidance.scopeEvidence.checkedScope = 'touched';
    if (mask & 2) {delete input.guidance.scopeEvidence.checkedScope; flags.push('--checked-scope', mask & 4 ? 'touched' : 'none');}
    if (mask & 4) {delete input.guidance.scopeEvidence.touchedRuleIds; flags.push('--touched-rule-id', 'proofkit.fixture.rule');}
    invoke('gradual-adoption-guidance', input, 'passed', flags, mask + 1);
    for (const arbitrary of [null, false, 42, 'ignored-fixture-value', [], {ignored: true}]) {
      if (mask & 1) invoke('gradual-adoption-guidance', replace(input, ['guidance', 'defaultMode'], arbitrary), 'passed', flags, mask + 1);
      if (mask & 2) invoke('gradual-adoption-guidance', replace(input, ['guidance', 'scopeEvidence', 'checkedScope'], arbitrary), 'passed', flags, mask + 1);
      if (mask & 4) invoke('gradual-adoption-guidance', replace(input, ['guidance', 'scopeEvidence', 'touchedRuleIds'], arbitrary), 'passed', flags, mask + 1);
    }
    if (!(mask & 1)) {
      schema('gradual-adoption-guidance', 'input', mask + 1, replace(input, ['guidance', 'defaultMode'], 'foreign-fixture-value'), false);
    }
    for (const field of ['ownerRoute', 'agentGuidance', 'scopeEvidence']) {
      const missing = structuredClone(input); delete missing.guidance[field];
      schema('gradual-adoption-guidance', 'input', mask + 1, missing, false);
      for (const wrong of [null, false, 1, '', []]) {
        schema('gradual-adoption-guidance', 'input', mask + 1, replace(input, ['guidance', field], wrong), false);
      }
      invoke('gradual-adoption-guidance', replace(input, ['guidance', field], null), 'refused', flags, mask + 1);
    }
  }
  invoke('gradual-adoption-guidance', guidance(), 'refused', ['--guidance-mode', 'observe']);
  for (const flags of [[], ['--materialization-manifest'], ['--agent-envelope']]) {
    invoke('gradual-adoption-bootstrap', envelope(), 'passed', ['--contract-envelope', ...flags], 1);
  }
});

function inputKinds(command, index, input, path, type) {
  for (const [kind, value] of [['null', null], ['boolean', false], ['number', 42], ['string', 'fixture'], ['array', []], ['object', {}]]) {
    if (kind !== type) schema(command, 'input', index, replace(input, path, value), false, 'nested/kind/' + path.join('.'));
  }
}

function inputObject(command, index, input, path, required, optional = [], open = false) {
  inputKinds(command, index, input, path, 'object');
  schema(command, 'input', index, replace(input, [...path, 'foreign'], true), open, 'nested/closed/' + path.join('.'));
  for (const key of required) {
    const missing = structuredClone(input); delete at(missing, path)[key];
    schema(command, 'input', index, missing, false, 'nested/required/' + [...path, key].join('.'));
  }
  for (const key of optional) {
    const missing = structuredClone(input); delete at(missing, path)[key];
    schema(command, 'input', index, missing, true, 'nested/optional/' + [...path, key].join('.'));
  }
}

function inputID(command, index, input, path) {
  inputKinds(command, index, input, path, 'string');
  for (const value of ['', '1bad', 'bad/', 'bad.', 'bad..id', 'A'.repeat(257)]) schema(command, 'input', index, replace(input, path, value), false);
  for (const length of [1, 255, 256]) schema(command, 'input', index, replace(input, path, 'A'.repeat(length)));
}

function inputText(command, index, input, path) {
  inputKinds(command, index, input, path, 'string');
  schema(command, 'input', index, replace(input, path, ''), false);
}

function inputTexts(command, index, input, path, minimum) {
  inputKinds(command, index, input, path, 'array');
  schema(command, 'input', index, replace(input, path, []), minimum === 0);
  for (const value of [null, false, 42, '', [], {}]) schema(command, 'input', index, replace(input, path, [value]), false);
}

test('direct nonClaims item domains are distinct from envelope and output lists', () => {
  for (const [command, input] of [['gradual-adoption', adoption()], ['gradual-adoption-guidance', guidance()]]) {
    inputTexts(command, 0, input, ['nonClaims'], 1);
    invoke(command, {...input, nonClaims: ['A nonempty fixture claim.']});
    for (const items of [[], [null], [false], [42], [''], [[]], [{}]]) invoke(command, {...input, nonClaims: items}, 'refused');
  }
});

test('native witness parent composition preserves required members and reporting domains', () => {
  const cases = [
    ['gradual-adoption', 0, adoption(), ['nativeWitnesses'], []],
    ['gradual-adoption', 1, {schema: envelope().schema, input: adoption()}, ['input', 'nativeWitnesses'], ['--contract-envelope']],
    ['gradual-adoption-bootstrap', 0, bootstrap(), ['nativeWitnesses'], []],
    ['gradual-adoption-bootstrap', 1, envelope(), ['input', 'nativeWitnesses'], ['--contract-envelope']],
  ];
  for (let mask = 0; mask < 8; mask++) {
    const input = envelope(), flags = ['--contract-envelope']; delete input.bootstrap;
    if (mask & 1) {delete input.guidance.defaultMode; flags.push('--guidance-mode', 'observe');}
    if (mask & 4) input.guidance.scopeEvidence.checkedScope = 'touched';
    if (mask & 2) {delete input.guidance.scopeEvidence.checkedScope; flags.push('--checked-scope', mask & 4 ? 'touched' : 'none');}
    if (mask & 4) {delete input.guidance.scopeEvidence.touchedRuleIds; flags.push('--touched-rule-id', 'proofkit.fixture.rule');}
    cases.push(['gradual-adoption-guidance', mask + 1, input, ['input', 'nativeWitnesses'], flags]);
  }
  for (const [command, index, input, path, flags] of cases) {
    inputObject(command, index, input, path, ['commands', 'vocabulary'], [], true);
    inputKinds(command, index, input, [...path, 'commands'], 'array');
    inputKinds(command, index, input, [...path, 'vocabulary'], 'object');
    for (const member of ['commands', 'vocabulary']) {
      const missing = structuredClone(input); delete at(missing, path)[member];
      invoke(command, missing, 'refused', flags, index);
    }
    for (const value of [null, false, 42, '', []]) invoke(command, replace(input, [...path, 'vocabulary'], value), 'refused', flags, index);
    for (const value of [null, false, 42, '', {}]) invoke(command, replace(input, [...path, 'commands'], value), 'refused', flags, index);
    for (const value of [null, false, 42, '', [], {}]) {
      const wrong = replace(input, [...path, 'commands'], [value]);
      schema(command, 'input', index, wrong, false, 'witness-command-item-kind');
      invoke(command, wrong, 'refused', flags, index);
    }
    const empty = replace(input, [...path, 'commands'], []);
    schema(command, 'input', index, empty);
    invoke(command, empty, 'failed', flags, index);
    const extra = replace(input, [...path, 'foreign'], true);
    schema(command, 'input', index, extra);
    invoke(command, extra, 'failed', flags, index);
  }
});

test('nested hard input predicates preserve source records and contract extraction domains', () => {
  const command = 'gradual-adoption-guidance', input = guidance();
  input.sourceReport.ruleResults = [{ruleId: 'proofkit.fixture.rule', status: 'passed', diagnostics: null, message: false}];
  invoke(command, input);
  inputObject(command, 0, input, ['sourceReport'], ['reportId', 'reportKind', 'ruleResults', 'schemaVersion', 'state'], ['diagnostics', 'nonClaims', 'summary']);
  inputObject(command, 0, input, ['sourceReport', 'ruleResults', 0], ['ruleId', 'status'], ['diagnostics', 'message']);
  inputID(command, 0, input, ['sourceReport', 'reportId']);
  inputID(command, 0, input, ['sourceReport', 'ruleResults', 0, 'ruleId']);
  inputText(command, 0, input, ['sourceReport', 'reportKind']);
  inputKinds(command, 0, input, ['sourceReport', 'ruleResults'], 'array');
  schema(command, 'input', 0, replace(input, ['sourceReport', 'ruleResults'], []));
  for (const value of [null, false, 42, '', []]) schema(command, 'input', 0, replace(input, ['sourceReport', 'ruleResults', 0], value), false);
  for (const value of [null, false, '1', 0, 2, 0.5]) schema(command, 'input', 0, replace(input, ['sourceReport', 'schemaVersion'], value), false);
  for (const path of [['sourceReport', 'state'], ['sourceReport', 'ruleResults', 0, 'status']]) {
    inputKinds(command, 0, input, path, 'string');
    for (const state of ['blocked', 'failed', 'passed', 'skipped', 'warning']) schema(command, 'input', 0, replace(input, path, state));
    const invalid = replace(input, path, 'foreign-fixture-value');
    schema(command, 'input', 0, invalid, false, 'source-enum/' + path.join('.'));
    invoke(command, invalid, 'refused');
  }
  for (let mask = 0; mask < 8; mask++) {
    const value = envelope(); delete value.bootstrap;
    const required = ['agentGuidance', 'guidanceId', 'nonClaims', 'ownerRoute', 'scopeEvidence'];
    const optional = ['modernization'];
    if (mask & 1) optional.push('defaultMode'); else required.push('defaultMode');
    inputObject(command, mask + 1, value, ['guidance'], required, optional, true);
    inputID(command, mask + 1, value, ['guidance', 'guidanceId']);
    inputTexts(command, mask + 1, value, ['guidance', 'nonClaims'], 1);
    for (const key of ['agentGuidance', 'ownerRoute']) inputKinds(command, mask + 1, value, ['guidance', key], 'object');
    const scopeRequired = [], scopeOptional = [];
    (mask & 2 ? scopeOptional : scopeRequired).push('checkedScope');
    (mask & 4 ? scopeOptional : scopeRequired).push('touchedRuleIds');
    inputObject(command, mask + 1, value, ['guidance', 'scopeEvidence'], scopeRequired, scopeOptional, true);
    if (!(mask & 2)) inputText(command, mask + 1, value, ['guidance', 'scopeEvidence', 'checkedScope']);
    if (!(mask & 4)) inputTexts(command, mask + 1, value, ['guidance', 'scopeEvidence', 'touchedRuleIds'], 0);
    if (!(mask & 1)) {
      inputKinds(command, mask + 1, value, ['guidance', 'defaultMode'], 'string');
      for (const mode of ['observe', 'warn', 'enforce-touched', 'enforce-all']) schema(command, 'input', mask + 1, replace(value, ['guidance', 'defaultMode'], mode));
    }
  }
  const b = envelope(), bootstrapCommand = 'gradual-adoption-bootstrap';
  inputObject(bootstrapCommand, 1, b, ['bootstrap'], ['bootstrapId', 'commands', 'defaultMode', 'nonClaims', 'paths', 'scopeEvidence'], [], true);
  inputObject(bootstrapCommand, 1, b, ['input'], ['budget', 'nativeWitnesses', 'packageVersionRef', 'proofBinding', 'repository', 'rollback'], ['module'], true);
  inputObject(bootstrapCommand, 1, b, ['input', 'proofBinding'], ['bindingPath'], [], true);
  inputObject(bootstrapCommand, 1, b, ['guidance'], ['ownerRoute'], [], true);
  inputObject(bootstrapCommand, 1, b, ['bootstrap', 'scopeEvidence'], ['checkedScope', 'touchedRuleIds'], [], true);
  for (const key of ['budget', 'repository', 'rollback', 'nativeWitnesses']) inputKinds(bootstrapCommand, 1, b, ['input', key], 'object');
  for (const path of [['guidance', 'ownerRoute'], ['bootstrap', 'paths']]) inputKinds(bootstrapCommand, 1, b, path, 'object');
  inputID(bootstrapCommand, 1, b, ['bootstrap', 'bootstrapId']);
  for (const path of [['input', 'packageVersionRef'], ['input', 'proofBinding', 'bindingPath'], ['bootstrap', 'scopeEvidence', 'checkedScope']]) inputText(bootstrapCommand, 1, b, path);
  for (const path of [['bootstrap', 'commands'], ['bootstrap', 'nonClaims'], ['bootstrap', 'scopeEvidence', 'touchedRuleIds']]) inputTexts(bootstrapCommand, 1, b, path, 0);
  inputKinds(bootstrapCommand, 1, b, ['bootstrap', 'defaultMode'], 'string');
  for (const mode of ['observe', 'warn', 'enforce-touched', 'enforce-all']) schema(bootstrapCommand, 'input', 1, replace(b, ['bootstrap', 'defaultMode'], mode));
  schema(bootstrapCommand, 'input', 1, replace(b, ['bootstrap', 'defaultMode'], 'foreign-fixture-value'), false);
});

test('bootstrap unique nonClaims normalize order while duplicate claims remain failures', () => {
  const claims = ['Zulu fixture caveat.', 'Alpha fixture caveat.'];
  const input = {...bootstrap(), nonClaims: claims};
  const value = invoke('gradual-adoption-bootstrap', input);
  assert(value.report.nonClaims.includes(claims[0]) && value.report.nonClaims.includes(claims[1]));
  assert.deepEqual(value.report.nonClaims, [...value.report.nonClaims].sort());
  const builtin = ['Bootstrap reports do not execute native witnesses.', 'Bootstrap reports do not own repository proof truth.',
    'Bootstrap reports do not prove rollout readiness.', 'Bootstrap reports do not write caller repository files.'];
  const duplicateCaller = invoke('gradual-adoption-bootstrap', {...input, nonClaims: [claims[0], claims[0]]}, 'failed');
  assert.deepEqual(duplicateCaller.report.nonClaims, builtin);
  for (const claim of builtin) {
    const collision = invoke('gradual-adoption-bootstrap', {...input, nonClaims: [claim]}, 'failed');
    assert.deepEqual(collision.report.nonClaims, []);
  }
});

test('contract roots independently conserve required objects and exact header identity', () => {
  const all = envelope();
  const fixtures = {
    'gradual-adoption': {schema: all.schema, input: all.input},
    'gradual-adoption-guidance': {schema: all.schema, input: all.input, guidance: all.guidance},
    'gradual-adoption-bootstrap': all,
  };
  const roots = {'gradual-adoption': ['input', 'schema'], 'gradual-adoption-guidance': ['guidance', 'input', 'schema'],
    'gradual-adoption-bootstrap': ['bootstrap', 'guidance', 'input', 'schema']};
  for (const command of commands) {
    const input = fixtures[command];
    schema(command, 'input', 1, input);
    schema(command, 'input', 1, {...input, foreign: {}}, false);
    for (const key of roots[command]) {
      const missing = structuredClone(input); delete missing[key]; schema(command, 'input', 1, missing, false);
      for (const wrong of key === 'schema' ? [null, false, 1, [], {}] : [null, false, 1, '', []]) {
        schema(command, 'input', 1, {...input, [key]: wrong}, false);
      }
    }
    for (const header of ['', 'foreign-fixture-value', 'proofkit.gradual-adoption-profile.v2']) schema(command, 'input', 1, {...input, schema: header}, false);
  }
});

test('structural predicates independently reject hard field and output carrier drift', () => {
  for (const [command, input] of [['gradual-adoption', adoption()], ['gradual-adoption-guidance', guidance()], ['gradual-adoption-bootstrap', bootstrap()]]) {
    const definition = checks.get(command + '/input')[0].schema;
    schema(command, 'input', 0, {...input, foreign: false}, false);
    assert.deepEqual([...definition.required].sort(), [...requiredInputs[command]].sort());
    assert.deepEqual(Object.keys(definition.properties).sort(), [...requiredInputs[command], ...optionalInputs[command]].sort());
    for (const version of [0, 2, 1.5, '1', null, false]) schema(command, 'input', 0, {...input, schemaVersion: version}, false);
    for (const key of requiredInputs[command]) {
      const missing = structuredClone(input); delete missing[key]; schema(command, 'input', 0, missing, false);
    }
    for (const [key, type] of Object.entries(hardInputTypes[command])) {
      assert.equal(definition.properties[key].type, type);
      for (const bad of type === 'object' ? [null, [], '', 1, false] : type === 'string' ? [null, {}, [], 1, false] : type === 'array' ? [null, {}, '', 1, false] : [null, {}, [], 1, 'false']) {
        schema(command, 'input', 0, {...input, [key]: bad}, false);
      }
      if (key === 'guidanceMode') {
        for (const mode of ['observe', 'warn', 'enforce-touched', 'enforce-all']) schema(command, 'input', 0, {...input, [key]: mode});
        schema(command, 'input', 0, {...input, [key]: 'foreign-fixture-value'}, false);
        invoke(command, {...input, [key]: 'foreign-fixture-value'}, 'refused');
      }
    }
    const idKey = {'gradual-adoption': 'adoptionId', 'gradual-adoption-guidance': 'guidanceId', 'gradual-adoption-bootstrap': 'bootstrapId'}[command];
    for (const invalid of ['', '1bad', 'bad/', 'bad.', 'bad..id', 'A'.repeat(257)]) schema(command, 'input', 0, {...input, [idKey]: invalid}, false);
    for (const length of [1, 255, 256]) schema(command, 'input', 0, {...input, [idKey]: 'A'.repeat(length)});
    for (const key of ['adoptionMode', 'packageVersionRef'].filter(key => key in input)) schema(command, 'input', 0, {...input, [key]: ''}, false);
    if (command !== 'gradual-adoption-bootstrap') {
      for (const claims of [[], ['']]) schema(command, 'input', 0, {...input, nonClaims: claims}, false);
    }
    const output = invoke(command, input), shape = checks.get(command + '/output')[0].schema;
    assert.deepEqual([...shape.required].sort(), [...outputKeys[command]].sort());
    for (const key of outputKeys[command]) {
      const missing = structuredClone(output); delete missing[key]; schema(command, 'output', 0, missing, false);
    }
    schema(command, 'output', 0, {...output, foreign: false}, false);
    const report = command === 'gradual-adoption-bootstrap' ? output.report : output;
    const path = command === 'gradual-adoption-bootstrap' ? ['report', 'reportKind'] : ['reportKind'];
    schema(command, 'output', 0, replace(output, path, 'proofkit.foreign'), false);
    assert.equal(report.schemaVersion, 1);
  }
});

function candidate() {
  return {admissionState: 'advisory', boundaryId: 'proofkit.fixture.boundary', candidateOwner: 'repository owner',
    affectedPaths: ['src/example.go'], blockedPreconditions: [], contractWitnessRefs: [], migrationRefs: [], nativeWitnessRefs: [],
    nonClaims: ['Candidate boundary guidance is advisory until the consuming repository owner admits it in stable requirements and proof bindings.'],
    observedFacts: ['The fixture names a candidate, not repository truth.'], ownerQuestions: ['Who owns this boundary?'],
    proofBindingRefs: [], requirementRefs: ['REQ-FIXTURE-001'], uncertainties: ['Owner admission remains unverified.']};
}

// Native producer objects are independent of the descriptor being tested.
// Retained caller JSON and optional degradation metadata have distinct domains.
function outputArrayRange(command, index, path) {
  const name = path.join('.');
  const envelope = command === 'gradual-adoption-guidance' && index === 1 || command === 'gradual-adoption-bootstrap' && index === 2;
  if (envelope && /^actionPlan\.\d+\.evidenceRefs$/.test(name)) return [0, 96];
  if (envelope && /^actionPlan\.\d+\.nonClaims$/.test(name)) return [1, null];
  if (envelope && name === 'bounds.boundsViolations') return [1, null];
  if (envelope) return {
    actionPlan: [0, 24], blockedPreconditions: [0, 12], clarificationQuestions: [0, 12],
    commands: [0, 24], contextRefs: [0, 48], omitted: [0, 24], receiptRefs: [0, 0], routeQuestions: [3, 3], nonClaims: [1, null],
  }[name];
  if (command === 'gradual-adoption') {
    if (name === 'diagnostics') return [6, 6];
    if (/^ruleResults\.\d+\.diagnostics$/.test(name)) return [0, 0];
  }
  if (command === 'gradual-adoption-guidance') {
    if (name === 'diagnostics') return [2, 2];
    if (name === 'diagnostics.0.value.agentActionPlan') return [4, 5];
  }
  if (command === 'gradual-adoption-bootstrap') {
    if (index === 1) return {files: [6, 6], nextCommands: [3, 3]}[name];
    const exact = {agentActionPlan: [3, 3], nextCommands: [3, 3], plannedFiles: [6, 6],
      'report.diagnostics': [4, 4], 'report.diagnostics.0.value': [3, 3],
      'report.diagnostics.1.value': [3, 3], 'report.diagnostics.2.value': [6, 6],
      'payloads.adoptionGuidance.sourceReport.diagnostics': [6, 6]};
    if (exact[name]) return exact[name];
    if (/^(report|payloads\.adoptionGuidance\.sourceReport)\.ruleResults\.\d+\.diagnostics$/.test(name)) return [0, 0];
  }
  if (name === 'ruleResults' || name.endsWith('.ruleResults')) return [1, null];
}

function carrierValuePredicates(command, index, output, value, path, label) {
  const name = path.join('.'), key = path.at(-1);
  const envelope = command === 'gradual-adoption-guidance' && index === 1 || command === 'gradual-adoption-bootstrap' && index === 2;
  const reject = replacement => schema(command, 'output', index, replace(output, path, replacement), false, label + '/value/' + name);
  if (typeof value === 'number') {
    reject(-1); reject(0.5);
    // A representable overflow refutes the upper guard, not adjacent int64 tokens.
    reject(2 ** 64);
    if (key === 'exitCode') reject(2);
    if (['fileCount', 'payloadFileCount', 'plannedFileCount', 'payloadCount', 'copiedVerifierFileCount'].includes(key) || name === 'costContract.graphQueryCount') {
      reject(value + 1); if (value > 0) reject(value - 1);
    }
    const costMaximum = {actionEvidenceRefCount: 96, actionItemCount: 24, blockedPreconditionCount: 12,
      clarificationQuestionCount: 12, commandRefCount: 24, loadedRefCount: 48, receiptRecordCount: 24, routeQuestionCount: 12};
    if (envelope && path[0] === 'costContract' && key in costMaximum) reject(costMaximum[key] + 1);
    if (['bounds.prunedLocalReferenceCount', 'bounds.boundsViolationCount'].includes(name)) reject(0);
  }
  if (typeof value === 'boolean' && (command === 'gradual-adoption-bootstrap' && ['report.summary.rolloutClaim', 'payloads.adoptionProfile.rolloutClaim'].includes(name)
    || ['costContract.omittedEdgesCounted', 'bounds.truncated', 'bounds.referenceClosurePreserved'].includes(name))) reject(!value);
  if (typeof value === 'string') {
    if (['guidanceMode', 'sourceReportState', 'state', 'status', 'phase', 'actionKind', 'expectedAnswerKind',
      'evidenceRole', 'admissionState', 'bindingFormat', 'materializationStatus', 'contentKind', 'payloadKey', 'key'].includes(key)) reject('foreign-fixture-value');
    if (envelope && (path[0] === 'contextRefs' && ['kind', 'role'].includes(key) || ['bounds.fanout', 'costContract.stopReason'].includes(name))) reject('foreign-fixture-value');
    if (envelope && path[0] === 'contextRefs' && ['kind', 'role'].includes(key)) {
      const values = key === 'kind' ? ['path', 'rule', 'candidate-boundary']
        : ['evidence', 'proof_binding', 'spec_source', 'rule_reference', 'candidate_boundary', 'command_registry', 'owner_surface', 'supporting'];
      for (const member of values) schema(command, 'output', index, replace(output, path, member), true, label + '/enum/' + name);
    }
    if (key === 'owner') {
      if (/(^|\.)agentActionPlan\.\d+\.owner$/.test(name) || envelope && path[0] === 'commands') reject('foreign-fixture-value');
      else if (envelope) reject('');
    }
    if (name === 'envelopeId' || key === 'adoptionMode' || key === 'outputMode' || name === 'payloads.adoptionGuidance.scopeEvidence.basis') reject('foreign-fixture-value');
    if (['payloads.adoptionProfile.agentReport.schemaId', 'payloads.adoptionGuidance.agentGuidance.schemaId'].includes(name)) reject('foreign-fixture-value');
    if (key === 'reportKind' && name !== 'diagnostics.1.value.reportKind') reject('proofkit.foreign');
    if (key === 'contentSha256' || key === 'stableHash') for (const wrong of ['', 'sha256:' + 'a'.repeat(63), 'sha256:' + 'a'.repeat(65), 'sha256:' + 'A'.repeat(64)]) reject(wrong);
    const permitsEmpty = name === 'sourceReport.reportId' || path[0] === 'commands' && key !== 'owner'
      || /^contextRefs\.\d+\.ref$/.test(name);
    if (envelope && !permitsEmpty) reject('');
  }
  if (Array.isArray(value)) {
    const textLists = ['affectedPaths', 'blockedPreconditions', 'callerSuggestedAutofixCandidates', 'commandIds', 'commands',
      'contractWitnessRefs', 'evidenceRefs', 'migrationRefs', 'minimalAdoptionPath', 'nativeWitnessRefs', 'nonClaims',
      'observedFacts', 'ownerQuestions', 'proofBindingRefs', 'proofBindingsMissing', 'requiredNextActions',
      'requirementIds', 'requirementRefs', 'sourceFailedRuleIds', 'sourceWarningRuleIds', 'specPaths', 'evidencePaths',
      'proofBindingPaths', 'touchedRuleIds', 'uncertainties', 'witnessCommandIds'];
    // Empty typed lists need an item refuter too; object arrays, zero-tuples
    // and opaque caller trees are separate domains, not inferred from [] alone.
    if (textLists.includes(key) && !name.startsWith('witnessPlan.') && !(envelope && name === 'commands')) {
      for (const bad of [null, false, 42, [], {}]) reject([bad]);
      if (envelope) reject(['']);
      if (!envelope) for (const valid of [[], [''], ['Independent normalized text.']]) {
        const permitted = name !== 'payloads.adoptionProfile.nonClaims' || valid.length > 0 && valid[0] !== '';
        schema(command, 'output', index, replace(output, path, valid), permitted, label + '/text-list/' + name);
      }
    }
    const range = outputArrayRange(command, index, path);
    if (!range) return;
    const [minimum, maximum] = range;
    if (minimum > 0) reject(value.slice(0, minimum - 1));
    if (maximum !== null) {
      const item = value[0] ?? null;
      reject(Array.from({length: maximum + 1}, (_, i) => structuredClone(value[i] ?? item)));
    }
  }
}

function carrierPredicates(command, index, output, label) {
  const raw = path => ['payloads.adoptionProfile.budget', 'payloads.adoptionProfile.repository', 'payloads.adoptionProfile.rollback',
    'payloads.adoptionProfile.nativeWitnesses', 'payloads.witnessPlanInput'].some(prefix => path.join('.').startsWith(prefix + '.') || path.join('.') === prefix);
  const optionalBounds = new Set(['truncated', 'referenceClosurePreserved', 'prunedLocalReferenceCount', 'boundsViolationCount', 'boundsViolations']);
  const kinds = [['null', null], ['boolean', false], ['number', 42], ['string', 'wrong-type'], ['array', []], ['object', {}]];
  const kind = value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
  function visit(value, path = []) {
    if (path.length) {
      const nullablePayload = command === 'gradual-adoption-bootstrap' && index === 0
        && /^(plannedFiles|report\.diagnostics\.2\.value)\.\d+\.payloadKey$/.test(path.join('.'));
      const allowed = new Set(nullablePayload ? ['null', 'string'] : [kind(value)]);
      for (const [type, replacement] of kinds) if (!allowed.has(type)) {
        schema(command, 'output', index, replace(output, path, replacement), false, label + '/kind/' + type + '/' + path.join('.'));
      }
      if (nullablePayload) {
        for (const replacement of [null, 'adoptionGuidance']) schema(command, 'output', index, replace(output, path, replacement), true, label + '/nullable/' + path.join('.'));
      }
    }
    if (raw(path)) return;
    if (path.length) carrierValuePredicates(command, index, output, value, path, label);
    if (value !== null && !Array.isArray(value) && typeof value === 'object') {
      schema(command, 'output', index, replace(output, [...path, 'foreign'], true), false, label);
      for (const key of Object.keys(value)) {
        if (path.join('.') === 'bounds' && optionalBounds.has(key)) continue;
        const missing = structuredClone(output); delete at(missing, path)[key];
        schema(command, 'output', index, missing, false, label + '/required/' + [...path, key]);
        if (key === 'schemaVersion') for (const version of [0, 2]) schema(command, 'output', index, replace(output, [...path, key], version), false, label + '/wire-version');
      }
    }
    if (path.length) {
      const wrong = value === null ? false : typeof value === 'string' ? 1 : typeof value === 'number' || typeof value === 'boolean' ? 'wrong-type' : Array.isArray(value) ? {} : [];
      schema(command, 'output', index, replace(output, path, wrong), false, label + '/type/' + path);
    }
    if (value !== null && typeof value === 'object') for (const [key, child] of Object.entries(value)) visit(child, [...path, key]);
  }
  visit(output);
}

test('populated, blocked, failed-reference and normalized payload output domains have independent carrier oracles', () => {
  const rich = guidance(); rich.modernization = {candidateBoundaries: [candidate()], promoteOnlyAfterOwnerReview: true};
  const ordinary = invoke('gradual-adoption-guidance', rich);
  assert.equal(ordinary.diagnostics[0].value.candidateBoundaries.length, 1);
  carrierPredicates('gradual-adoption-guidance', 0, ordinary, 'candidate');
  const wrapped = invoke('gradual-adoption-guidance', rich, 'passed', ['--agent-envelope']);
  carrierPredicates('gradual-adoption-guidance', 1, wrapped, 'candidate-envelope');
  const blocked = guidance(); blocked.guidanceMode = 'enforce-all'; blocked.scopeEvidence.checkedScope = 'all';
  blocked.sourceReport.state = 'blocked'; blocked.agentGuidance.requiredNextActions = ['Resolve the source precondition.'];
  carrierPredicates('gradual-adoption-guidance', 0, invoke('gradual-adoption-guidance', blocked, 'blocked'), 'blocked');
  carrierPredicates('gradual-adoption-guidance', 1, invoke('gradual-adoption-guidance', blocked, 'blocked', ['--agent-envelope']), 'blocked-envelope');
  const malformed = guidance(); malformed.modernization = {candidateBoundaries: [{}], promoteOnlyAfterOwnerReview: true};
  for (const [command, input, index] of [['gradual-adoption-bootstrap', replace(bootstrap(), ['paths', 'adoptionProfilePath'], null), 2],
    ['gradual-adoption-guidance', malformed, 1]]) {
    const value = invoke(command, input, 'failed', ['--agent-envelope']);
    const empty = value.contextRefs.findIndex(ref => ref.ref === ''); assert.notEqual(empty, -1);
    schema(command, 'output', index, replace(value, ['contextRefs', empty, 'ref'], false), false);
    carrierPredicates(command, index, value, 'failed-ref');
  }
  for (const [command, input] of [['gradual-adoption', adoption()], ['gradual-adoption-bootstrap', bootstrap()]]) {
    carrierPredicates(command, 0, invoke(command, input), 'ordinary');
  }
  for (const input of [bootstrap(), replace(bootstrap(), ['budget', 'profileLines'], 99), replace(bootstrap(), ['module'], {})]) {
    const phase = input.budget.profileLines === 99 || Object.keys(input.module).length === 0 ? 'failed' : 'passed';
    const value = invoke('gradual-adoption-bootstrap', input, phase);
    carrierPredicates('gradual-adoption-bootstrap', 0, value, 'payload');
    invoke('gradual-adoption', value.payloads.adoptionProfile, phase);
    const guidanceResult = spawnWithInputFile(binary, ['gradual-adoption-guidance', '--input', '-'], {input: JSON.stringify(value.payloads.adoptionGuidance), encoding: 'utf8', timeout: 10000});
    assertCLITransport(guidanceResult); assert.equal(guidanceResult.stderr, '');
    schema('gradual-adoption-guidance', 'output', 0, JSON.parse(guidanceResult.stdout));
    const manifest = invoke('gradual-adoption-bootstrap', input, phase, ['--materialization-manifest']);
    carrierPredicates('gradual-adoption-bootstrap', 1, manifest, 'manifest');
  }
});

test('finite output domains preserve exact state sets, literals and diagnostic item types', () => {
  const definition = (command, index) => checks.get(command + '/output')[index].schema;
  const property = (shape, key) => shape.properties[key];
  const reportStates = ['failed', 'passed'], guidanceStates = ['blocked', 'failed', 'passed'];
  const sourceStates = ['blocked', 'failed', 'passed', 'skipped', 'warning'];
  const exactEnum = (shape, values, label) => {
    assert.deepEqual(shape.enum, [...values].sort(), label + '/exact-enum');
    const check = new Ajv2020({strict: false, validateFormats: false}).compile(shape);
    for (const value of values) assert.equal(check(value), true, label + '/' + value);
    for (const value of [...sourceStates, 'foreign-fixture-value'].filter(value => !values.includes(value))) {
      assert.equal(check(value), false, label + '/forbidden/' + value);
    }
  };
  const reportDomain = (shape, values, label) => {
    exactEnum(property(shape, 'state'), values, label + '/state');
    exactEnum(property(property(shape, 'ruleResults').items, 'status'), values === guidanceStates ? sourceStates : values, label + '/status');
  };
  const adoptionShape = definition('gradual-adoption', 0), guidanceShape = definition('gradual-adoption-guidance', 0);
  const bootstrapShape = definition('gradual-adoption-bootstrap', 0), bootstrapReport = property(bootstrapShape, 'report');
  reportDomain(adoptionShape, reportStates, 'adoption');
  reportDomain(guidanceShape, guidanceStates, 'guidance');
  reportDomain(bootstrapReport, reportStates, 'bootstrap');
  const payloadSource = property(property(property(bootstrapShape, 'payloads'), 'adoptionGuidance'), 'sourceReport');
  reportDomain(payloadSource, reportStates, 'bootstrap/payload-source');
  exactEnum(property(property(guidanceShape, 'summary'), 'sourceReportState'), sourceStates, 'guidance/summary');
  const sourceDiagnostic = property(property(guidanceShape, 'diagnostics').prefixItems[1], 'value');
  exactEnum(property(sourceDiagnostic, 'state'), sourceStates, 'guidance/source-diagnostic');
  const bootstrapStates = property(property(bootstrapReport, 'diagnostics').prefixItems[3], 'value');
  exactEnum(property(bootstrapStates, 'adoptionGuidanceState'), guidanceStates, 'bootstrap/source-guidance');
  exactEnum(property(bootstrapStates, 'adoptionProfileState'), reportStates, 'bootstrap/source-profile');
  const diagnosticBranches = property(property(guidanceShape, 'ruleResults').items, 'diagnostics').items.oneOf;
  const stateDiagnostic = diagnosticBranches.find(shape => property(shape, 'key').const === 'sourceReportState');
  assert(stateDiagnostic, 'sourceReportState diagnostic branch is required');
  exactEnum(property(stateDiagnostic, 'value'), sourceStates, 'guidance/rule-diagnostic');
  const ordinary = invoke('gradual-adoption-guidance', guidance());
  for (const key of ['enforcementFailedRuleIds', 'sourceFailedRuleIds', 'proofBindingsMissing', 'blockedPreconditions', 'sourceWarningRuleIds', 'candidateBoundaryIds']) {
    const path = ['ruleResults', 0, 'diagnostics'];
    carrierPredicates('gradual-adoption-guidance', 0, replace(ordinary, path, [{key, value: ['Independent diagnostic.']}]), key + '/record');
    for (const value of [[], [''], ['Independent diagnostic.']]) schema('gradual-adoption-guidance', 'output', 0, replace(ordinary, path, [{key, value}]));
    for (const bad of [null, false, 42, [], {}]) schema('gradual-adoption-guidance', 'output', 0, replace(ordinary, path, [{key, value: [bad]}]), false, key + '/item');
  }
  carrierPredicates('gradual-adoption-guidance', 0, replace(ordinary, ['ruleResults', 0, 'diagnostics'], [{key: 'sourceReportState', value: 'passed'}]), 'sourceReportState/record');
  for (const state of sourceStates) schema('gradual-adoption-guidance', 'output', 0,
    replace(ordinary, ['ruleResults', 0, 'diagnostics'], [{key: 'sourceReportState', value: state}]));
  schema('gradual-adoption-guidance', 'output', 0, replace(ordinary, ['ruleResults', 0, 'diagnostics'], [{key: 'sourceReportState', value: 'foreign-fixture-value'}]), false);
  const manifest = invoke('gradual-adoption-bootstrap', bootstrap(), 'passed', ['--materialization-manifest']);
  assert.equal(manifest.manifestKind, 'proofkit.gradual-adoption-bootstrap-materialization-manifest');
  schema('gradual-adoption-bootstrap', 'output', 1, {...manifest, manifestKind: 'proofkit.foreign-manifest'}, false, 'manifestKind/exact-literal');
  exactEnum(property(property(definition('gradual-adoption-bootstrap', 1), 'sourceReport'), 'state'), reportStates, 'manifest/source');
  for (const [command, index] of [['gradual-adoption-guidance', 1], ['gradual-adoption-bootstrap', 2]]) {
    const source = property(definition(command, index), 'sourceReport');
    exactEnum(property(source, 'state'), guidanceStates, command + '/envelope-source');
    const input = command === 'gradual-adoption-guidance' ? guidance() : bootstrap();
    const value = invoke(command, input, 'passed', ['--agent-envelope']);
    assert.equal(value.sourceReport.nonClaim, 'Source report is projected because agent guidance envelopes do not carry full caller-owned report payloads.');
    schema(command, 'output', index, replace(value, ['sourceReport', 'nonClaim'], 'Different nonempty projection boundary.'), false, 'sourceReport/nonClaim/exact-literal');
  }
});

test('shared witness and repair predicates retain their exact finite domains', () => {
  const property = (shape, key) => shape.properties[key];
  const shared = direction => {
    const ref = contract.commands.find(row => row.command === 'witness-plan')[direction + 'Contract'].rootDefinitionRef;
    return expandSharedDefinitions(contract.contractDefinitions.find(row => row.definitionId === ref).fieldTree.variants[0].schema);
  };
  const sharedInput = shared('input');
  const witnessCommand = shape => {
    const command = property(shape, 'commands').items;
    assert.deepEqual(property(command, 'cachePolicy').enum, ['disabled', 'read-only', 'write-local']);
    assert.deepEqual(property(command, 'networkPolicy').enum, ['external', 'loopback', 'none']);
    assert.equal(property(command, 'schemaVersion').const, 1);
    assert.deepEqual(property(command, 'environment').oneOf.map(row => property(row, 'inherit').const).sort(), ['allowlist', 'none']);
    assert.deepEqual(property(command, 'exitCodePolicy').oneOf.map(row => property(row, 'kind').const).sort(), ['listed', 'zero']);
  };
  const witnesses = [];
  for (const command of commands) for (const {schema: shape} of checks.get(command + '/input')) {
    const parent = command === 'gradual-adoption-guidance' || shape.properties.input ? shape.properties.input : shape;
    if (parent) witnesses.push(property(parent, 'nativeWitnesses'));
  }
  const payloads = checks.get('gradual-adoption-bootstrap/output')[0].schema.properties.payloads;
  witnesses.push(property(property(payloads, 'adoptionProfile'), 'nativeWitnesses'), property(payloads, 'witnessPlanInput'));
  for (const shape of witnesses) {
    assert.deepEqual(property(shape, 'commands').items, property(sharedInput, 'commands').items, 'shared command shape must preserve the standalone oracle boundary');
    assert.deepEqual(property(shape, 'vocabulary'), property(sharedInput, 'vocabulary'), 'shared vocabulary shape must preserve the standalone oracle boundary');
    witnessCommand(shape);
    const policies = property(property(shape, 'vocabulary'), 'environmentClassPolicies').anyOf.find(row => row.type === 'array').items;
    assert.deepEqual(property(policies, 'cachePolicies').items.enum, ['disabled', 'read-only', 'write-local']);
    assert.deepEqual(property(policies, 'networkPolicies').items.enum, ['external', 'loopback', 'none']);
  }
  witnessCommand(checks.get('gradual-adoption-bootstrap/output')[0].schema.properties.witnessPlan);
  assert.deepEqual(checks.get('gradual-adoption-bootstrap/output')[0].schema.properties.witnessPlan, shared('output'), 'nested plan must preserve the independently exercised standalone output shape');
  for (const [command, index] of [['gradual-adoption-guidance', 2], ['gradual-adoption-bootstrap', 3]]) {
    const shape = checks.get(command + '/output')[index].schema;
    const repair = invoke(command, '{}', 'repair', ['--agent-envelope']);
    for (const [path, expected] of [
      [['schemaVersion'], 1], [['envelopeId'], 'proofkit.agent-envelope.invalid-input'],
      [['sourceReport', 'reportId'], 'proofkit.agent-envelope.invalid-input'], [['sourceReport', 'reportKind'], 'proofkit.agent-envelope.invalid-input'],
      [['sourceReport', 'state'], 'failed'], [['sourceReport', 'nonClaim'], 'Source report is projected because agent guidance envelopes do not carry full caller-owned report payloads.'],
      [['costContract', 'graphQueryCount'], 0], [['costContract', 'omittedEdgesCounted'], true],
    ]) {
      assert.equal(at(repair, path), expected);
      const wrong = typeof expected === 'string' ? 'foreign-fixture-value' : typeof expected === 'number' ? expected + 1 : !expected;
      schema(command, 'output', index, replace(repair, path, wrong), false, 'repair/literal/' + path.join('.'));
    }
    assert.equal(property(property(shape, 'actionPlan').items, 'phase').const, 'route');
    assert.equal(property(property(shape, 'clarificationQuestions').items, 'expectedAnswerKind').const, 'missing_context_ref');
    assert.deepEqual(property(property(shape, 'bounds'), 'fanout').enum, ['bounded', 'full-gate', 'wide', 'wide_or_full_gate_required']);
    assert.equal(property(property(shape, 'bounds'), 'truncated').const, true);
    assert.equal(property(property(shape, 'bounds'), 'referenceClosurePreserved').const, false);
    assert.deepEqual(property(property(shape, 'costContract'), 'stopReason').enum, ['blocked_precondition', 'caller_review_required', 'wide_or_full_gate_required']);
  }
});

test('declared ordinary envelope items retain predicates even when the native collection is empty', () => {
  for (const [command, input, index] of [['gradual-adoption-guidance', guidance(), 1], ['gradual-adoption-bootstrap', bootstrap(), 2]]) {
    const native = invoke(command, input, 'passed', ['--agent-envelope']);
    // These are structural fixtures, not claims that the native producer emits
    // these records or that their references/counts have semantic admission.
    const value = {...native,
      clarificationQuestions: [{askWhen: 'Inspect the declared precondition.', blocking: false, evidenceRefs: ['proofkit.fixture.evidence'],
        expectedAnswerKind: 'missing_witness', nonClaim: 'Structural fixture only.', owner: 'consumer_repository',
        question: 'Which witness is required?', questionId: 'proofkit.fixture.question'}],
      blockedPreconditions: [{description: 'Independent fixture precondition.', evidenceRefs: ['proofkit.fixture.evidence'],
        nonClaim: 'Structural fixture only.', owner: 'consumer_repository', preconditionId: 'proofkit.fixture.precondition'}],
      omitted: [{escalation: 'Inspect the omitted fixture.', nonClaim: 'Structural fixture only.', omissionId: 'proofkit.fixture.omission',
        omittedCount: 1, omittedKind: 'fixture', reason: 'Independent fixture omission.', sourceField: 'fixture'}],
      bounds: {...native.bounds, boundsViolations: ['Independent fixture bound.'], boundsViolationCount: 1,
        prunedLocalReferenceCount: 1, referenceClosurePreserved: false, truncated: true},
    };
    schema(command, 'output', index, value);
    carrierPredicates(command, index, value, 'declared-items');
    const answers = ['blocked_external_input', 'missing_witness', 'owner_boundary_decision'];
    const shape = checks.get(command + '/output')[index].schema.properties.clarificationQuestions.items;
    assert.deepEqual(shape.properties.expectedAnswerKind.enum, answers, command + '/clarification/enum-presence');
    for (const answer of answers) schema(command, 'output', index, replace(value, ['clarificationQuestions', 0, 'expectedAnswerKind'], answer));
  }
});

test('all described finite enums retain the independently authored owner vocabulary', () => {
  const reportStates = ['failed', 'passed'], guidanceStates = ['blocked', 'failed', 'passed'];
  const sourceStates = ['blocked', 'failed', 'passed', 'skipped', 'warning'];
  const domains = {
    cachePolicy: ['disabled', 'read-only', 'write-local'], cachePolicies: ['disabled', 'read-only', 'write-local'],
    networkPolicy: ['external', 'loopback', 'none'], networkPolicies: ['external', 'loopback', 'none'],
    guidanceMode: ['enforce-all', 'enforce-touched', 'observe', 'warn'], defaultMode: ['enforce-all', 'enforce-touched', 'observe', 'warn'],
    phase: ['bind', 'modernize-boundary', 'promote', 'route', 'verify'],
    expectedAnswerKind: ['blocked_external_input', 'missing_witness', 'owner_boundary_decision'],
    kind: ['candidate-boundary', 'path', 'rule'],
    role: ['candidate_boundary', 'command_registry', 'evidence', 'owner_surface', 'proof_binding', 'rule_reference', 'spec_source', 'supporting'],
    fanout: ['bounded', 'full-gate', 'wide', 'wide_or_full_gate_required'],
    stopReason: ['blocked_precondition', 'caller_review_required', 'wide_or_full_gate_required'],
    payloadKey: ['adoptionGuidance', 'adoptionProfile', 'proofBinding', 'witnessPlanInput'],
    adoptionGuidanceState: guidanceStates, adoptionProfileState: reportStates, sourceReportState: sourceStates,
  };
  for (const command of commands) for (const direction of ['input', 'output']) {
    for (const [index, {schema: shape}] of checks.get(command + '/' + direction).entries()) {
      function visit(node, path = []) {
        if (!node || typeof node !== 'object') return;
        if (node.enum) {
          const key = path[path.lastIndexOf('properties') + 1];
          let expected = domains[key];
          if (key === 'state' || key === 'status') {
            expected = direction === 'input' ? sourceStates : command === 'gradual-adoption-guidance'
              ? key === 'status' || path.includes('diagnostics') ? sourceStates : guidanceStates
              : command === 'gradual-adoption-bootstrap' && index === 2 ? guidanceStates : reportStates;
          }
          if (key === 'reportKind') expected = ['proofkit.' + (path.includes('adoptionGuidance') ? 'gradual-adoption' : command)];
          if (key === 'value' && command === 'gradual-adoption-guidance' && path.includes('ruleResults')) expected = sourceStates;
          assert(expected, `${command}/${direction}/${index}/${path.join('/')}: enum needs an independent owner domain`);
          assert.deepEqual(node.enum, expected, `${command}/${direction}/${index}/${path.join('/')}: exact enum`);
        }
        for (const [key, value] of Object.entries(node)) visit(value, [...path, key]);
      }
      visit(shape);
    }
  }
});

test('post-redaction identity and all starter consumers preserve native wire domains', () => {
  const redacted = guidance(); redacted.guidanceId = 'eyJfixture.owner';
  const envelope = invoke('gradual-adoption-guidance', redacted, 'passed', ['--agent-envelope']);
  assert.equal(envelope.envelopeId, '<redacted-diagnostic-value>');
  schema('gradual-adoption-guidance', 'output', 1, {...envelope, envelopeId: 'foreign-fixture-value'}, false);
  const execute = (command, input, pointer, exit) => {
    const flags = pointer ? ['--input-pointer', pointer] : [];
    const result = spawnWithInputFile(binary, [command, '--input', '-', ...flags], {input, encoding: 'utf8', timeout: 10000, maxBuffer: 8 << 20});
    assertCLITransport(result);
    assert.equal(result.status, exit, result.stderr); assert.equal(result.stderr, '');
    return result;
  };
  const normal = spawnWithInputFile(binary, ['gradual-adoption-bootstrap', '--input', '-'], {input: JSON.stringify(bootstrap()), encoding: 'utf8', timeout: 10000});
  assertCLITransport(normal); assert.equal(normal.status, 0); assert.equal(normal.stderr, '');
  const payloads = JSON.parse(normal.stdout);
  assert.equal(payloads.nextCommands[2], 'agentic-proofkit witness-plan --input proofkit/witness.json');
  const plan = execute('witness-plan', normal.stdout, '/payloads/witnessPlanInput', 0);
  assert.deepEqual(JSON.parse(plan.stdout), payloads.witnessPlan);
  for (const token of ['9007199254740993', '9223372036854775807']) {
    const input = JSON.stringify(bootstrap()).replace('"profileLines":42', '"profileLines":' + token);
    assert(input.includes('"profileLines":' + token));
    const producer = spawnWithInputFile(binary, ['gradual-adoption-bootstrap', '--input', '-'], {input, encoding: 'utf8', timeout: 10000, maxBuffer: 8 << 20});
    assertCLITransport(producer); assert.equal(producer.status, 1); assert.equal(producer.stderr, '');
    assert(new RegExp('"profileLines"\\s*:\\s*' + token + '(?=[,}\\s])').test(producer.stdout));
    const profile = execute('gradual-adoption', producer.stdout, '/payloads/adoptionProfile', 1);
    assert(new RegExp('"profileLineCount"\\s*:\\s*' + token + '(?=[,}\\s])').test(profile.stdout));
    execute('gradual-adoption-guidance', producer.stdout, '/payloads/adoptionGuidance', 0);
    execute('witness-plan', producer.stdout, '/payloads/witnessPlanInput', 0);
    const manifest = spawnWithInputFile(binary, ['gradual-adoption-bootstrap', '--input', '-', '--materialization-manifest'], {input, encoding: 'utf8', timeout: 10000, maxBuffer: 8 << 20});
    assertCLITransport(manifest); assert.equal(manifest.status, 1); assert.equal(manifest.stderr, '');
    const content = JSON.parse(manifest.stdout).files.find(file => file.payloadKey === 'adoptionProfile').content;
    assert(new RegExp('"profileLines"\\s*:\\s*' + token + '(?=[,}\\s])').test(content));
    execute('gradual-adoption', content, '', 1);
  }
});

test('caller/generated intersections preserve the prefix without duplicate instructions', () => {
  const launchers = [
    {env: pathLauncher, prefix: 'agentic-proofkit'},
    {env: {AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'npm_offline', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: ''}, prefix: 'npm exec --offline -- agentic-proofkit'},
    {env: {AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'python_module', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: '/tmp/proofkit venv/bin/python'}, prefix: "'/tmp/proofkit venv/bin/python' -m agentic_proofkit"},
  ];
  for (const launcher of launchers) {
    const generated = [`${launcher.prefix} gradual-adoption --input proofkit/adoption.json`,
      `${launcher.prefix} gradual-adoption-guidance --input proofkit/guidance.json`,
      `${launcher.prefix} witness-plan --input proofkit/witness.json`];
    for (let mask = 0; mask < 8; mask++) {
      const caller = ['go test ./...', ...generated.filter((_, index) => mask & 1 << index)];
      const expected = [...caller, ...generated.filter((_, index) => !(mask & 1 << index))];
      const input = {...bootstrap(), commands: caller};
      const ordinary = invoke('gradual-adoption-bootstrap', input, 'passed', [], 0, launcher.env);
      assert.deepEqual(ordinary.payloads.adoptionGuidance.agentGuidance.commands, expected);
      assert.deepEqual(ordinary.nextCommands, generated);
      invoke('gradual-adoption-guidance', ordinary.payloads.adoptionGuidance, 'passed', [], 0, launcher.env);
      const agent = invoke('gradual-adoption-bootstrap', input, 'passed', ['--agent-envelope'], 0, launcher.env);
      assert.deepEqual(agent.commands.map(row => row.command), generated);
      const manifest = invoke('gradual-adoption-bootstrap', input, 'passed', ['--materialization-manifest'], 0, launcher.env);
      assert.deepEqual(JSON.parse(manifest.files.find(file => file.payloadKey === 'adoptionGuidance').content).agentGuidance.commands, expected);
      const aggregate = envelope(); aggregate.bootstrap.commands = caller;
      for (const flags of [[], ['--agent-envelope'], ['--materialization-manifest']]) {
        const value = invoke('gradual-adoption-bootstrap', aggregate, 'passed', ['--contract-envelope', ...flags], 1, launcher.env);
        if (flags.includes('--agent-envelope')) assert.deepEqual(value.commands.map(row => row.command), generated);
        else if (flags.includes('--materialization-manifest')) assert.deepEqual(JSON.parse(value.files.find(file => file.payloadKey === 'adoptionGuidance').content).agentGuidance.commands, expected);
        else assert.deepEqual(value.payloads.adoptionGuidance.agentGuidance.commands, expected);
      }
    }
    for (const flags of [[], ['--agent-envelope'], ['--materialization-manifest']]) {
      invoke('gradual-adoption-bootstrap', {...bootstrap(), commands: ['agentic-proofkit witness-scheduler-plan --input proofkit/witness.json']}, 'passed', flags, 0, launcher.env);
      invoke('gradual-adoption-bootstrap', {...bootstrap(), commands: ['go test ./...', 'go test ./...']}, 'failed', flags, 0, launcher.env);
    }
  }
});

test('reachable envelope degradation preserves bounded arrays, omissions and required fields', () => {
  for (const count of [23, 24, 25]) {
    const input = guidance(); input.agentGuidance.commands = Array.from({length: count}, (_, index) => `go test ./... -run Test${String(index).padStart(3, '0')}`);
    const value = invoke('gradual-adoption-guidance', input, 'passed', ['--agent-envelope']);
    assert.equal(value.commands.length, Math.min(count, 24));
    carrierPredicates('gradual-adoption-guidance', 1, value, 'commands/' + count);
  }
  for (const count of [47, 48, 49, 97]) {
    const input = guidance(); input.ownerRoute.evidencePaths = Array.from({length: count - 2}, (_, index) => `artifacts/evidence-${String(index).padStart(3, '0')}.json`);
    const value = invoke('gradual-adoption-guidance', input, 'passed', ['--agent-envelope']);
    assert.equal(value.contextRefs.length, Math.min(count, 48));
    carrierPredicates('gradual-adoption-guidance', 1, value, 'contexts/' + count);
  }
  for (const count of [11, 12, 13]) {
    const input = guidance(); input.agentGuidance.blockedPreconditions = Array.from({length: count}, (_, index) => `Prerequisite ${String(index).padStart(3, '0')}`);
    input.agentGuidance.requiredNextActions = ['Resolve the preconditions.'];
    const value = invoke('gradual-adoption-guidance', input, 'passed', ['--agent-envelope']);
    assert.equal(value.blockedPreconditions.length, Math.min(count, 12));
    assert.equal(value.clarificationQuestions.length, Math.min(count, 12));
    carrierPredicates('gradual-adoption-guidance', 1, value, 'blocked/' + count);
  }
});

test('isolated schema controls falsify optionality, phase widening and payload carrier omissions', () => {
  const compile = value => new Ajv2020({strict: false, validateFormats: false}).compile(value);
  const weakenedBudget = structuredClone(checks.get('gradual-adoption-bootstrap/input')[0].schema);
  weakenedBudget.required = weakenedBudget.required.filter(key => key !== 'budget');
  const noBudget = bootstrap(); delete noBudget.budget;
  schema('gradual-adoption-bootstrap', 'input', 0, noBudget, false);
  assert.equal(compile(weakenedBudget)(noBudget), true, 'missing-required control did not distinguish weakened schema');
  const g = guidance(), direct = checks.get('gradual-adoption-guidance/input')[0].schema;
  const requireModernization = structuredClone(direct); requireModernization.required.push('modernization');
  assert.equal(compile(requireModernization)(g), false, 'optional modernization control survived');
  const requireSuccessfulChildren = structuredClone(direct);
  requireSuccessfulChildren.properties.agentGuidance = {type: 'object'};
  const failed = {...g, agentGuidance: false};
  schema('gradual-adoption-guidance', 'input', 0, failed);
  assert.equal(compile(requireSuccessfulChildren)(failed), false, 'failure-bearing JSON control survived');
  const sourcePayload = replace(g, ['sourceReport', 'summary'], [false, null, 1]);
  const constrainIgnored = structuredClone(direct); constrainIgnored.properties.sourceReport.properties.summary = {type: 'object'};
  schema('gradual-adoption-guidance', 'input', 0, sourcePayload);
  assert.equal(compile(constrainIgnored)(sourcePayload), false, 'ignored source payload control survived');
  const requireOverride = structuredClone(checks.get('gradual-adoption-guidance/input')[2].schema);
  const e = envelope(); delete e.bootstrap; delete e.guidance.defaultMode;
  schema('gradual-adoption-guidance', 'input', 2, e);
  requireOverride.properties.guidance.required.push('defaultMode');
  assert.equal(compile(requireOverride)(e), false, 'mode override control survived');
  const payloads = invoke('gradual-adoption-bootstrap', bootstrap());
  const omitCarrier = structuredClone(checks.get('gradual-adoption-bootstrap/output')[0].schema);
  delete omitCarrier.properties.payloads.properties.witnessPlanInput;
  assert.equal(compile(omitCarrier)(payloads), false, 'closed payload omission control survived');
  const manifest = invoke('gradual-adoption-bootstrap', bootstrap(), 'passed', ['--materialization-manifest']);
  const caller = manifest.files.findIndex(file => file.contentKind === 'caller_owned');
  for (const field of ['content', 'contentSha256', 'payloadKey']) {
    schema('gradual-adoption-bootstrap', 'output', 1, replace(manifest, ['files', caller, field], 'foreign'), false);
  }
});
