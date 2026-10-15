import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {impactInput} from './impact-fixtures.mjs';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_ADOPTION_ENVELOPE_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));

// Independently authored public identities and variant partitions. They are
// restated here, never derived from the definitions under test.
const aggregateCondition = (agent, manifest, mode, pilot) =>
  `--agent-envelope=${agent} --materialization-manifest=${manifest} --mode=${mode} --pilot=${pilot}`;
const guidanceIds = [0, 1, 2, 3, 4, 5, 6, 7].map(mask => `${String(mask + 3).padStart(2, '0')}-guidance-${mask.toString(2).padStart(3, '0')}`);
const expected = {
  'adoption-contract-envelope/input': {
    id: 'proofkit.adoption-contract-envelope.input.v3.json-schema', contractId: 'proofkit.adoption-contract-envelope.input.v3', schemaVersion: 2, rootType: 'object',
    predecessor: 'proofkit.adoption-contract-envelope.input.v2.root-shape',
    variants: [['01-adoption', ['--mode adoption']], ['02-bootstrap', ['--mode bootstrap']],
      ...guidanceIds.map((id, mask) => [id, [`--mode guidance; guidance-mode override=${Boolean(mask & 1)}, checked-scope override=${Boolean(mask & 2)}, touched-rule-id override=${Boolean(mask & 4)}`]]),
      ['11-pilot-all', ['--mode pilot --pilot all']], ['12-pilot-first', ['--mode pilot --pilot first', '--mode pilot without --pilot (defaults first)']],
      ['13-pilot-stack-diverse', ['--mode pilot --pilot stack-diverse']], ['14-workflow', ['--mode workflow']]],
  },
  'adoption-contract-envelope/output': {
    id: 'proofkit.adoption-contract-envelope.output.v1.json-schema', contractId: 'proofkit.adoption-contract-envelope.output.v1', schemaVersion: 1, rootType: 'union',
    predecessor: 'proofkit.adoption-contract-envelope.output.v1.root-shape',
    variants: [['01-adoption-report', [aggregateCondition('absent', 'absent', 'adoption', 'absent')]],
      ['02-bootstrap', [aggregateCondition('absent', 'absent', 'bootstrap', 'absent')]],
      ['03-bootstrap-agent', [aggregateCondition('present', 'absent', 'bootstrap', 'absent')]],
      ['04-bootstrap-materialization', [aggregateCondition('absent', 'present', 'bootstrap', 'absent')]],
      ['05-guidance-agent', [aggregateCondition('present', 'absent', 'guidance', 'absent')]],
      ['06-guidance-report', [aggregateCondition('absent', 'absent', 'guidance', 'absent')]],
      ['07-pilot-all', [aggregateCondition('absent', 'absent', 'pilot', 'all')]],
      ['08-pilot-first', [aggregateCondition('absent', 'absent', 'pilot', 'absent'), aggregateCondition('absent', 'absent', 'pilot', 'first')]],
      ['09-pilot-stack-diverse', [aggregateCondition('absent', 'absent', 'pilot', 'stack-diverse')]],
      ['10-workflow-agent', [aggregateCondition('present', 'absent', 'workflow', 'absent')]],
      ['11-workflow-plan', [aggregateCondition('absent', 'absent', 'workflow', 'absent')]]],
  },
  'adoption-workflow-plan/input': {
    id: 'proofkit.adoption-workflow-plan.input.v1.json-schema', contractId: 'proofkit.adoption-workflow-plan.input.v1', schemaVersion: 1, rootType: 'object',
    predecessor: 'proofkit.adoption-workflow-plan.input.v1.root-shape',
    variants: [['01-contract-envelope', ['--contract-envelope']], ['02-direct', ['without --contract-envelope']]],
  },
  'adoption-workflow-plan/output': {
    id: 'proofkit.adoption-workflow-plan.output.v1.json-schema', contractId: 'proofkit.adoption-workflow-plan.output.v1', schemaVersion: 1, rootType: 'object',
    predecessor: 'proofkit.adoption-workflow-plan.output.v1.root-shape',
    variants: [['01-agent-envelope', ['--agent-envelope']], ['02-workflow-plan', ['without --agent-envelope']]],
  },
  'pilot-admission/input': {
    id: 'proofkit.pilot-admission.input.v2.json-schema', contractId: 'proofkit.pilot-admission.input.v2', schemaVersion: 2, rootType: 'object',
    predecessor: 'proofkit.pilot-admission.input.v2.root-shape',
    variants: [['01-contract-all', ['--contract-envelope --pilot all']],
      ['02-contract-first', ['--contract-envelope --pilot first', '--contract-envelope without --pilot (defaults first)']],
      ['03-contract-stack-diverse', ['--contract-envelope --pilot stack-diverse', '--contract-envelope --stack-diverse']],
      ['04-direct', ['without --contract-envelope; --pilot first', 'without --contract-envelope; without --pilot (defaults first)',
        'without --contract-envelope; --pilot stack-diverse', 'without --contract-envelope; --stack-diverse']]],
  },
  'pilot-admission/output': {
    id: 'proofkit.pilot-admission.output.v1.json-schema', contractId: 'proofkit.pilot-admission.output.v1', schemaVersion: 1, rootType: 'union',
    predecessor: 'proofkit.pilot-admission.output.v1.root-shape',
    variants: [['01-all', ['--contract-envelope --pilot all']], ['02-report', ['--contract-envelope --pilot first', '--contract-envelope --pilot stack-diverse',
      '--contract-envelope --stack-diverse', '--contract-envelope without --pilot (defaults first)', 'direct input']]],
  },
};

const aggregateKeys = ['envelopeId', 'gradual', 'nonClaims', 'pilot', 'schema', 'workflow'];
const childKeys = {workflow: ['schema', 'workflow'], gradual: ['bootstrap', 'guidance', 'input', 'schema'], pilot: ['input', 'schema', 'stackDiverseInput']};
const workflowRequired = ['inputRefs', 'nonClaims', 'scenario', 'schemaVersion', 'workflowId'];
const workflowOptional = ['presetId'];
const refKeys = ['inputKind', 'path', 'refId'];
const planKeys = ['blockers', 'inputRefs', 'nonClaims', 'phases', 'planKind', 'planState', 'scenario', 'schemaVersion', 'workflowId'];
const blockerKeys = ['blockerId', 'nonClaim', 'reason', 'requiredInputKinds', 'scenario'];
const planCommandKeys = ['argv', 'commandId', 'inputRefIds', 'nonClaim', 'owner'];
const phases = ['profile', 'bootstrap', 'bind', 'migrate', 'plan-gates', 'collect-evidence', 'release'];
const scenarios = ['existing_gradual_adoption', 'legacy_proof_migration', 'new_repository', 'release_channel'];
const inputKinds = ['adoption_checklist', 'branch_authority', 'external_consumer', 'gradual_adoption_bootstrap', 'gradual_adoption_guidance', 'migration_plan',
  'receipt_producer_admission', 'registry_consumer', 'release_authority', 'repo_profile_scaffold', 'requirement_bindings', 'selective_gate_evidence',
  'selective_gate_plan', 'witness_plan'];
const presets = ['agentic_runtime_repo', 'generated_docs_contract_repo', 'python_service', 'python_typescript_service', 'typescript_monorepo', 'typescript_workspace'];
const envelopeKeys = ['actionPlan', 'blockedPreconditions', 'bounds', 'clarificationQuestions', 'commands', 'contextRefs', 'costContract', 'envelopeId',
  'nonClaims', 'omitted', 'receiptRefs', 'routeQuestions', 'schemaVersion', 'sourceReport'];
const pilotRequired = ['agentReportRoutes', 'blockingRequirements', 'cacheScheduler', 'falsePositiveBudget', 'infrastructureBudget', 'nonClaims', 'pilotId',
  'profile', 'rollback', 'schemaVersion', 'timingBudget'];
const pilotOptional = ['cacheNegativeChecks', 'impactDemo', 'impactDemos', 'metrics', 'packageVersionRef', 'pilotMode', 'rolloutClaim', 'stackDiversity'];
const reportKeys = ['diagnostics', 'nonClaims', 'reportId', 'reportKind', 'ruleResults', 'schemaVersion', 'state', 'summary'];
const pilotSummaryKeys = ['agentReportRouteCount', 'cacheNegativeCheckCount', 'changedRequirementCount', 'copiedVerifierFileCount', 'customRuleCount',
  'explicitlyDeferredRequirementCount', 'falsePositiveSampleWindowRuns', 'generatedMirrorImpactPathCount', 'impactDemoCount', 'impactObligationCount',
  'maxAddedSeconds', 'pilotMode', 'profileLineCount', 'repositoryClass', 'sourceOwnedImpactPathCount', 'stackDiversityDimensionCount',
  'totalBlockingRequirementCount', 'witnessBackedRequirementCount'];
const pilotDiagnosticKeys = ['blockingRequirements', 'cacheNegativeChecks', 'customRules', 'impactDemos', 'packageVersionRef', 'rollbackVersionPin',
  'stackDiversity', 'timingReportArtifactPath'];
const repairId = 'proofkit.agent-envelope.invalid-input';

const definitionOf = (command, direction) => {
  const binding = contract.commands.find(row => row.command === command)[direction + 'Contract'];
  return {binding, definition: contract.contractDefinitions.find(row => row.definitionId === binding.rootDefinitionRef)};
};
const compile = schema => new Ajv2020({strict: false, validateFormats: false}).compile(schema);
const checks = new Map(Object.keys(expected).map(key => {
  const [command, direction] = key.split('/');
  const {definition} = definitionOf(command, direction);
  return [key, new Map(definition.fieldTree.variants.map(row => [row.variantId, {check: compile(row.schema), schema: row.schema}]))];
}));
function schema(key, variant, value, accepted = true, label = '') {
  const {check} = checks.get(key).get(variant);
  assert.equal(check(value), accepted, `${key}/${variant}/${label}: ${JSON.stringify(check.errors?.slice(0, 3))}`);
}

let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-adoption-envelope-contract-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 180000, maxBuffer: 2 << 20, env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

// Fixtures are independent wire records, not Go builder output.
function workflowInput(scenario = 'release_channel', kinds = ['registry_consumer', 'release_authority'], presetId = null) {
  return {schemaVersion: 1, workflowId: 'proofkit.oracle.workflow', scenario, presetId,
    inputRefs: kinds.map(kind => ({inputKind: kind, path: `proofkit/${kind}.json`, refId: `proofkit.oracle.${kind}`})),
    nonClaims: ['Oracle workflow fixture does not execute planned commands.']};
}
function pilotDemo(id) {
  return {demoId: id, sourceOwnedChangedPaths: ['tests/impact_test.go'], generatedMirrorPaths: ['docs/generated.md'], impactInput: impactInput(true)};
}
function pilotInput(stackDiverse = false) {
  const input = {
    schemaVersion: 2, pilotId: stackDiverse ? 'proofkit.oracle.pilot.stack' : 'proofkit.oracle.pilot.first',
    profile: {commandMatcherBridge: 'none', customRuleBoundary: 'profile_only', primaryLanguages: ['go'], repositoryClass: 'go_cli',
      repositoryId: 'proofkit.oracle.repository', structuredWitnessCommands: true, verifierCodeCopied: false},
    blockingRequirements: {dispositionPolicy: 'all_blocking_requirements_must_be_witnessed_or_explicitly_deferred', explicitlyDeferredRequirements: 0,
      requirements: [{evidence: 'docs/specs/oracle.json', owner: 'oracle owner', requirementId: 'REQ-ORACLE-001', status: 'witness_backed'}],
      totalBlockingRequirements: 1, unmappedRequirements: 0, witnessBackedRequirements: 1},
    agentReportRoutes: [{artifactPath: 'artifacts/oracle.json', command: 'agentic-proofkit render', expectedUpdatePath: 'docs/specs/oracle.json',
      reportKind: 'proofkit.oracle.report', schemaId: 'proofkit.oracle.schema', taskType: 'proofkit.oracle.review'}],
    cacheScheduler: {cacheKeyInputs: ['go.mod'], destructiveConcurrencyAllowed: false, invalidationInputs: ['go.sum'], maxParallelGroups: 1,
      parallelGroups: ['local'], schedulerPolicy: 'bounded_parallel_groups'},
    timingBudget: {maxAddedSeconds: 5, measuredSeparately: true, reportArtifactPath: 'artifacts/timing.json', trackedFixtureAsBaseline: false},
    infrastructureBudget: {copiedVerifierFileCount: 0, customRuleCount: 0, customRules: [], manualTruthSurfaceCount: 0, manualUpdateStepCount: 0,
      maxCustomRuleCount: 0, maxManualTruthSurfaceCount: 0, maxManualUpdateStepCount: 0, maxProfileLines: 100, profileLines: 20},
    falsePositiveBudget: {dispositionOwner: 'oracle owner', enforcementMode: 'non_blocking', maxAllowedFalsePositiveCount: 0, sampleWindowRuns: 1},
    rollback: {owner: 'oracle owner', rollbackCommand: 'agentic-proofkit previous-version', versionPin: 'package.json'},
    impactDemos: [pilotDemo('proofkit.oracle.demo')], cacheNegativeChecks: [],
    nonClaims: ['Oracle pilot fixture does not claim rollout readiness.'], packageVersionRef: 'package.json', pilotMode: 'non_blocking', rolloutClaim: false,
  };
  if (stackDiverse) {
    input.stackDiversity = {baselinePilotId: 'proofkit.oracle.pilot.first', dimensions: ['docs_spec_layout', 'generated_artifact_policy',
      'language_runtime_test_shape', 'proof_environment_classes', 'repository_topology'].map(dimension => ({baseline: 'baseline ' + dimension,
      candidate: 'candidate ' + dimension, dimension, evidence: 'docs/evidence/' + dimension + '.md'}))};
    input.cacheNegativeChecks = ['package_version', 'profile', 'schema', 'source'].map(inputClass => ({checkId: 'proofkit.oracle.cache.' + inputClass,
      evidence: 'Invalidates on ' + inputClass, expectedOutcome: 'invalidate_output', invalidatedInputClass: inputClass, liveOrCredentialedCacheable: false}));
  }
  return input;
}
function witnesses() {
  return {commands: [{id: 'proofkit.oracle.command', schemaVersion: 1, argv: ['go', 'test', './...'], cwd: '.', timeoutMs: 60000, networkPolicy: 'none',
    credentialClass: 'none', cachePolicy: 'read-only', parallelGroup: 'local-go', environment: {inherit: 'none', allowlist: [], classes: ['local-go']},
    exitCodePolicy: {kind: 'zero', successCodes: [0]}, expectedArtifacts: []}],
  vocabulary: {artifactKinds: ['json'], credentialClasses: ['none'], environmentClasses: ['local-go'], parallelGroups: ['local-go'],
    environmentClassPolicies: [{environmentClass: 'local-go', credentialClasses: ['none'], networkPolicies: ['none'], cachePolicies: ['read-only']}]}};
}
function gradual() {
  const owner = {evidencePaths: ['artifacts/adoption.json'], primaryOwner: 'oracle owner', proofBindingPaths: ['proofkit/bindings.json'],
    specPaths: ['docs/specs/oracle/requirements.json']};
  return {schema: 'proofkit.gradual-adoption-profile.v1',
    input: {schemaVersion: 1, adoptionId: 'proofkit.oracle.adoption', adoptionMode: 'non_blocking', rolloutClaim: false, packageVersionRef: 'proofkit@oracle',
      budget: {copiedVerifierFileCount: 0, customRuleCount: 0, maxAddedSeconds: 10, maxCustomRuleCount: 0, maxProfileLines: 80, maxSetupMinutes: 20, profileLines: 42},
      repository: {customRuleBoundary: 'profile_only', primaryLanguages: ['go'], profilePath: 'proofkit/profile.json', repositoryClass: 'go_cli',
        repositoryId: 'proofkit.oracle.repository', verifierCodeCopied: false},
      rollback: {disableCommand: 'remove proofkit report', owner: 'oracle owner', versionPin: 'proofkit@oracle'},
      module: {moduleId: 'proofkit.oracle.module', requirementIds: ['REQ-ORACLE-001'], specPath: 'docs/specs/oracle/requirements.json'},
      nativeWitnesses: witnesses(), nonClaims: ['Oracle gradual fixture does not prove rollout.'],
      proofBinding: {bindingFormat: 'requirement_to_witness', bindingPath: 'proofkit/bindings.json', requirementIds: ['REQ-ORACLE-001'],
        witnessCommandIds: ['proofkit.oracle.command']},
      agentReport: {artifactPath: 'artifacts/adoption.json', outputMode: 'non_blocking', reportKind: 'proofkit.gradual-adoption',
        routeQuestions: ['what changed', 'what proves it', 'who owns it'], schemaId: 'proofkit.oracle.profile'}},
    guidance: {guidanceId: 'proofkit.oracle.guidance', defaultMode: 'observe', nonClaims: ['Oracle guidance does not prove rollout.'],
      scopeEvidence: {checkedScope: 'none', touchedRuleIds: []}, ownerRoute: owner,
      agentGuidance: {artifactPath: 'artifacts/guidance.json', blockedPreconditions: [], callerSuggestedAutofixCandidates: [], commands: [],
        minimalAdoptionPath: ['Keep adoption non-blocking.'], proofBindingsMissing: [], reportKind: 'proofkit.gradual-adoption-guidance',
        requiredNextActions: [], routeQuestions: ['what changed', 'what proves it', 'who owns it'], schemaId: 'proofkit.oracle.guidance'}},
    bootstrap: {bootstrapId: 'proofkit.oracle.bootstrap', defaultMode: 'observe', scopeEvidence: {checkedScope: 'none', touchedRuleIds: []},
      commands: ['go test ./...'], nonClaims: ['Oracle bootstrap does not prove rollout.'],
      paths: {adoptionGuidancePath: 'proofkit/guidance.json', adoptionProfilePath: 'proofkit/adoption.json', adoptionReportArtifactPath: 'artifacts/adoption.json',
        guidanceReportArtifactPath: 'artifacts/guidance.json', witnessPlanInputPath: 'proofkit/witness.json'}}};
}
function aggregate() {
  return {schema: 'proofkit.adoption-contract-envelope.v2', envelopeId: 'proofkit.oracle.aggregate',
    workflow: {schema: 'proofkit.adoption-workflow.v1', workflow: workflowInput()}, gradual: gradual(),
    pilot: {schema: 'proofkit.pilot-admission.v2', input: pilotInput(), stackDiverseInput: pilotInput(true)},
    nonClaims: ['Oracle aggregate does not execute native witnesses.']};
}

const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, replacement) {
  const result = structuredClone(value); at(result, path.slice(0, -1))[path.at(-1)] = replacement; return result;
}
function remove(value, path) {
  const result = structuredClone(value); delete at(result, path.slice(0, -1))[path.at(-1)]; return result;
}
const flagValue = (flags, flag) => flags.includes(flag) ? flags[flags.indexOf(flag) + 1] : undefined;

// Variant selection rules restated from the CLI option semantics.
function inputVariant(command, flags) {
  if (command === 'adoption-workflow-plan') return flags.includes('--contract-envelope') ? '01-contract-envelope' : '02-direct';
  if (command === 'pilot-admission') {
    if (!flags.includes('--contract-envelope')) return '04-direct';
    const pilot = flags.includes('--stack-diverse') ? 'stack-diverse' : flagValue(flags, '--pilot') ?? 'first';
    return {all: '01-contract-all', first: '02-contract-first', 'stack-diverse': '03-contract-stack-diverse'}[pilot];
  }
  const mode = flagValue(flags, '--mode');
  if (mode === 'guidance') {
    const mask = (flags.includes('--guidance-mode') ? 1 : 0) | (flags.includes('--checked-scope') ? 2 : 0) | (flags.includes('--touched-rule-id') ? 4 : 0);
    return guidanceIds[mask];
  }
  if (mode === 'pilot') return {all: '11-pilot-all', first: '12-pilot-first', 'stack-diverse': '13-pilot-stack-diverse'}[flagValue(flags, '--pilot') ?? 'first'];
  return {adoption: '01-adoption', bootstrap: '02-bootstrap', workflow: '14-workflow'}[mode];
}
function outputVariant(command, flags) {
  if (command === 'adoption-workflow-plan') return flags.includes('--agent-envelope') ? '01-agent-envelope' : '02-workflow-plan';
  if (command === 'pilot-admission') return flagValue(flags, '--pilot') === 'all' ? '01-all' : '02-report';
  const condition = aggregateCondition(flags.includes('--agent-envelope') ? 'present' : 'absent', flags.includes('--materialization-manifest') ? 'present' : 'absent',
    flagValue(flags, '--mode'), flagValue(flags, '--pilot') ?? 'absent');
  return expected['adoption-contract-envelope/output'].variants.find(([, when]) => when.includes(condition))[0];
}
const stateOf = value => Array.isArray(value) ? (value.every(row => row.state === 'passed') ? 'passed' : 'failed')
  : value.planState ? (value.planState === 'ready_for_caller_review' ? 'passed' : 'failed')
    : value.state ?? value.report?.state ?? value.sourceReport?.state;

function run(command, input, flags = [], env = {}) {
  const result = spawnSync(binary, [command, '--input', '-', ...flags], {
    input: typeof input === 'string' ? input : JSON.stringify(input), encoding: 'utf8', timeout: 20000, maxBuffer: 16 << 20,
    env: {...process.env, AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'path', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: '', ...env},
  });
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  return result;
}
// phase: passed | failed | refused (stderr only) | repair (invalid-input envelope).
// structural=false marks a native semantic refusal the schema does not express.
function invoke(command, input, flags, phase, {structural = true, label = ''} = {}) {
  const key = command + '/input', variant = inputVariant(command, flags);
  if (typeof input !== 'string') schema(key, variant, input, phase === 'passed' || phase === 'failed' || !structural, 'input/' + label);
  const result = run(command, input, flags);
  if (phase === 'refused') {
    assert.equal(result.status, 1, label); assert.equal(result.stdout, '', label); assert.notEqual(result.stderr, '', label);
    return null;
  }
  assert.equal(result.stderr, '', `${label}: ${result.stderr}`);
  const value = JSON.parse(result.stdout);
  schema(command + '/output', outputVariant(command, flags), value, true, 'output/' + label);
  if (phase === 'repair') {
    assert.equal(result.status, 1, label); assert.equal(value.envelopeId, repairId, label);
  } else {
    assert.equal(result.status, phase === 'passed' ? 0 : 1, `${label}: ${result.stdout.slice(0, 400)}`);
    assert.equal(stateOf(value), phase, label);
  }
  return value;
}

const aggregateModes = [
  ['--mode', 'adoption'], ['--mode', 'bootstrap'], ['--mode', 'bootstrap', '--agent-envelope'], ['--mode', 'bootstrap', '--materialization-manifest'],
  ['--mode', 'guidance'], ['--mode', 'guidance', '--agent-envelope'], ['--mode', 'pilot'], ['--mode', 'pilot', '--pilot', 'first'],
  ['--mode', 'pilot', '--pilot', 'all'], ['--mode', 'pilot', '--pilot', 'stack-diverse'], ['--mode', 'workflow'], ['--mode', 'workflow', '--agent-envelope'],
];
const agentFlags = flags => flags.includes('--agent-envelope');

test('published identities, variant partitions and conditions are exact', () => {
  for (const [key, want] of Object.entries(expected)) {
    const [command, direction] = key.split('/');
    const {binding, definition} = definitionOf(command, direction);
    assert.equal(binding.rootDefinitionRef, want.id, key);
    assert.equal(binding.contractId, want.contractId, key);
    assert.equal(binding.schemaVersion, want.schemaVersion, key);
    assert.equal(binding.rootType, want.rootType, key); assert.equal(definition.rootType, want.rootType, key);
    assert.equal(definition.fieldTree.kind, 'structural_json_schema', key);
    assert.equal(contract.contractDefinitions.some(row => row.definitionId === want.predecessor), false, key + ' predecessor retained');
    assert.deepEqual(definition.fieldTree.variants.map(row => [row.variantId, row.when]), want.variants, key);
    for (const row of definition.fieldTree.variants) {
      const array = row.variantId === '01-all' || row.variantId === '07-pilot-all';
      assert.equal(row.rootKind, array ? 'array' : 'object', key + '/' + row.variantId);
      if (array) assert.deepEqual([row.allowedFields, row.requiredFields], [[], []]);
    }
    assert.equal(definition.fieldTree.conditionModel, key === 'adoption-contract-envelope/output' ? 'cli_flag_conjunction_v1' : undefined, key);
  }
  for (const command of ['adoption-contract-envelope', 'adoption-workflow-plan', 'pilot-admission']) {
    assert.deepEqual(contract.commands.find(row => row.command === command).outputModes, ['json'], command);
  }
  for (const [id] of expected['adoption-contract-envelope/input'].variants) {
    const shape = checks.get('adoption-contract-envelope/input').get(id).schema;
    assert.deepEqual([...shape.required].sort(), aggregateKeys, id);
    for (const [child, keys] of Object.entries(childKeys)) assert.deepEqual([...shape.properties[child].required].sort(), keys, id + '/' + child);
  }
});

test('every aggregate condition emits its exact output variant in success, failure and repair', () => {
  const failing = {
    adoption: value => replace(value, ['gradual', 'input', 'budget', 'profileLines'], 99),
    bootstrap: value => replace(value, ['gradual', 'input', 'budget', 'profileLines'], 99),
    guidance: value => replace(value, ['gradual', 'guidance', 'agentGuidance'], {}),
    pilot: value => replace(replace(value, ['pilot', 'input', 'rolloutClaim'], true), ['pilot', 'stackDiverseInput', 'pilotMode'], 'blocking'),
    workflow: value => replace(value, ['workflow', 'workflow', 'inputRefs'], []),
  };
  const outputs = new Set();
  for (const flags of aggregateModes) {
    const mode = flagValue(flags, '--mode');
    const value = invoke('adoption-contract-envelope', aggregate(), flags, 'passed', {label: flags.join(' ')});
    outputs.add(outputVariant('adoption-contract-envelope', flags));
    if (flagValue(flags, '--pilot') === 'all') assert.deepEqual(value.map(row => row.reportId), ['proofkit.oracle.pilot.first', 'proofkit.oracle.pilot.stack']);
    invoke('adoption-contract-envelope', failing[mode](aggregate()), flags, 'failed', {label: 'failed ' + flags.join(' ')});
    const broken = remove(aggregate(), ['envelopeId']);
    invoke('adoption-contract-envelope', broken, flags, agentFlags(flags) ? 'repair' : 'refused', {label: 'refused ' + flags.join(' ')});
    if (agentFlags(flags)) {
      for (const text of ['{', '{"schema":1,"schema":1}']) invoke('adoption-contract-envelope', text, flags, 'repair', {label: 'framing'});
    }
  }
  assert.equal(outputs.size, 11);
  for (const flags of [['--mode', 'adoption', '--agent-envelope'], ['--mode', 'workflow', '--materialization-manifest'], ['--mode', 'workflow', '--pilot', 'all'],
    ['--mode', 'bootstrap', '--agent-envelope', '--materialization-manifest'], ['--mode', 'bootstrap', '--guidance-mode', 'observe'], ['--mode', 'audit'], []]) {
    const result = run('adoption-contract-envelope', aggregate(), flags);
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.notEqual(result.stderr, '');
  }
  const text = run('adoption-contract-envelope', aggregate(), ['--mode', 'workflow', '--format', 'text']);
  assert.equal(text.status, 1); assert.equal(text.stdout, '', 'text format is not a claimed output variant');
});

test('aggregate input variants admit exactly their delegated child and reject structural drift', () => {
  const modeFlags = [['--mode', 'adoption'], ['--mode', 'bootstrap'], ...[0, 1, 2, 3, 4, 5, 6, 7].map(mask => {
    const flags = ['--mode', 'guidance'];
    if (mask & 1) flags.push('--guidance-mode', 'observe');
    if (mask & 2) flags.push('--checked-scope', mask & 4 ? 'touched' : 'none');
    if (mask & 4) flags.push('--touched-rule-id', 'proofkit.oracle.rule');
    return flags;
  }), ['--mode', 'pilot', '--pilot', 'all'], ['--mode', 'pilot'], ['--mode', 'pilot', '--pilot', 'stack-diverse'], ['--mode', 'workflow']];
  assert.deepEqual(modeFlags.map(flags => inputVariant('adoption-contract-envelope', flags)), expected['adoption-contract-envelope/input'].variants.map(([id]) => id));
  const selected = {
    workflow: ['14-workflow'], input: ['01-adoption', '02-bootstrap', ...guidanceIds], bootstrap: ['02-bootstrap'], guidance: ['02-bootstrap', ...guidanceIds],
    pilotInput: ['11-pilot-all', '12-pilot-first'], pilotStack: ['11-pilot-all', '13-pilot-stack-diverse'],
  };
  for (const flags of modeFlags) {
    const id = inputVariant('adoption-contract-envelope', flags);
    let base = aggregate();
    if (flags.includes('--touched-rule-id')) base = replace(base, ['gradual', 'guidance', 'scopeEvidence', 'checkedScope'], 'touched');
    const accepted = (value, label) => {
      schema('adoption-contract-envelope/input', id, value, true, label);
      const result = run('adoption-contract-envelope', value, flags);
      assert.equal(result.stderr, '', label + ': ' + result.stderr);
      schema('adoption-contract-envelope/output', outputVariant('adoption-contract-envelope', flags), JSON.parse(result.stdout), true, label);
    };
    const refusedBoth = (value, label) => {
      schema('adoption-contract-envelope/input', id, value, false, label);
      invoke('adoption-contract-envelope', value, flags, 'refused', {label});
    };
    accepted(base, 'base');
    accepted(replace(base, ['nonClaims'], []), 'empty claims');
    accepted(replace(base, ['nonClaims'], ['zulu', 'alpha']), 'unsorted claims');
    accepted(replace(base, ['envelopeId'], 'A'.repeat(256)), 'id limit');
    refusedBoth(replace(base, ['envelopeId'], 'A'.repeat(257)), 'id bound');
    for (const wrong of ['', '1bad', 'bad id', 'bad.', 7, null]) refusedBoth(replace(base, ['envelopeId'], wrong), 'id ' + wrong);
    refusedBoth({...base, foreign: true}, 'root foreign');
    refusedBoth(replace(base, ['schema'], 'proofkit.adoption-contract-envelope.v1'), 'root header');
    for (const claims of [['same', 'same'], [''], [' '], [7], 'claim', null]) refusedBoth(replace(base, ['nonClaims'], claims), 'claims ' + JSON.stringify(claims));
    for (const key of aggregateKeys) refusedBoth(remove(base, [key]), 'missing ' + key);
    for (const [child, keys] of Object.entries(childKeys)) {
      refusedBoth(replace(base, [child], []), child + ' type');
      refusedBoth(replace(base, [child, 'foreign'], {}), child + ' foreign');
      for (const key of keys) {
        refusedBoth(remove(base, [child, key]), child + ' missing ' + key);
        refusedBoth(replace(base, [child, key], key === 'schema' ? 'proofkit.foreign.v1' : 'not-an-object'), child + ' wrong ' + key);
      }
    }
    // Unselected children are object-typed only; selected children reach their owner.
    for (const [name, path, selectedBy] of [['workflow', ['workflow', 'workflow'], 'workflow'], ['input', ['gradual', 'input'], 'input'],
      ['bootstrap', ['gradual', 'bootstrap'], 'bootstrap'], ['guidance', ['gradual', 'guidance'], 'guidance'],
      ['pilot input', ['pilot', 'input'], 'pilotInput'], ['pilot stack', ['pilot', 'stackDiverseInput'], 'pilotStack']]) {
      const value = replace(base, path, {foreign: [true, null]});
      if (selected[selectedBy].includes(id)) refusedBoth(value, 'selected ' + name);
      else accepted(value, 'unselected ' + name);
    }
    if (id === '14-workflow') {
      refusedBoth(replace(base, ['workflow', 'workflow', 'scenario'], 'unknown_scenario'), 'workflow scenario');
      refusedBoth(replace(base, ['workflow', 'workflow', 'inputRefs', 0, 'foreign'], true), 'workflow ref foreign');
      invoke('adoption-contract-envelope', replace(base, ['workflow', 'workflow', 'inputRefs', 0, 'path'], '../escape.json'), flags, 'refused', {structural: false, label: 'workflow path'});
    }
    if (selected.pilotInput.includes(id) || selected.pilotStack.includes(id)) {
      const member = selected.pilotInput.includes(id) ? 'input' : 'stackDiverseInput';
      refusedBoth(replace(base, ['pilot', member, 'rollback', 'foreign'], true), 'pilot rollback foreign');
      refusedBoth(replace(base, ['pilot', member, 'impactDemos'], [{demoId: 'proofkit.oracle.demo'}]), 'pilot demo without impact');
      accepted(replace(base, ['pilot', member, 'timingBudget', 'foreign'], true), 'pilot open timing');
    }
    if (guidanceIds.includes(id)) {
      const mask = guidanceIds.indexOf(id);
      for (const [bit, path] of [[1, ['gradual', 'guidance', 'defaultMode']], [2, ['gradual', 'guidance', 'scopeEvidence', 'checkedScope']],
        [4, ['gradual', 'guidance', 'scopeEvidence', 'touchedRuleIds']]]) {
        if (mask & bit) {
          accepted(remove(base, path), 'override ignores ' + path.at(-1));
          accepted(replace(base, path, {ignored: [1]}), 'override ignores value ' + path.at(-1));
        } else {
          refusedBoth(remove(base, path), 'required ' + path.at(-1));
        }
      }
    }
  }
});

test('workflow plan variants, clauses and boundaries agree with the CLI', () => {
  const command = 'adoption-workflow-plan', direct = [], contractFlags = ['--contract-envelope'];
  const wrap = value => ({schema: 'proofkit.adoption-workflow.v1', workflow: value});
  for (const scenario of scenarios) {
    for (const presetId of [null, presets[0]]) {
      for (const kinds of [[], inputKinds]) {
        const value = workflowInput(scenario, kinds, presetId);
        const ready = kinds.length > 0 && (presetId !== null || ['legacy_proof_migration', 'release_channel'].includes(scenario));
        const plan = invoke(command, value, direct, ready ? 'passed' : 'failed', {label: scenario});
        assert.deepEqual(Object.keys(plan).sort(), planKeys);
        assert.deepEqual(plan.phases.map(phase => phase.phase), phases);
        for (const blocker of plan.blockers) assert.deepEqual(Object.keys(blocker).sort(), blockerKeys);
        for (const phase of plan.phases) for (const row of phase.commands) assert.deepEqual(Object.keys(row).sort(), planCommandKeys);
        const envelope = invoke(command, value, ['--agent-envelope'], ready ? 'passed' : 'failed', {label: scenario + ' envelope'});
        assert.deepEqual(Object.keys(envelope).sort(), envelopeKeys);
        assert.deepEqual(invoke(command, wrap(value), contractFlags, ready ? 'passed' : 'failed', {label: 'contract'}), plan);
        invoke(command, wrap(value), [...contractFlags, '--agent-envelope'], ready ? 'passed' : 'failed', {label: 'contract envelope'});
      }
    }
  }
  const base = workflowInput();
  for (const key of workflowRequired) {
    invoke(command, remove(base, [key]), direct, 'refused', {label: 'missing ' + key});
    invoke(command, remove(base, [key]), ['--agent-envelope'], 'repair', {label: 'missing envelope ' + key});
  }
  for (const key of workflowOptional) invoke(command, remove(base, [key]), direct, 'passed', {label: 'optional ' + key});
  for (const preset of presets) invoke(command, replace(base, ['presetId'], preset), direct, 'passed', {label: 'preset ' + preset});
  const refused = (value, label, structural = true) => invoke(command, value, direct, 'refused', {label, structural});
  refused({...base, foreign: true}, 'root foreign');
  refused(replace(base, ['inputRefs', 0, 'foreign'], true), 'ref foreign');
  for (const key of refKeys) refused(remove(base, ['inputRefs', 0, key]), 'ref missing ' + key);
  for (const [path, values] of [[['scenario'], ['unknown', 1, null]], [['presetId'], ['unknown_preset', false, 1]], [['schemaVersion'], [2, '1', null]],
    [['workflowId'], ['', 'bad id', 'A'.repeat(257), null]], [['inputRefs'], [{}, 'x', null]], [['inputRefs', 0], ['ref', null]],
    [['inputRefs', 0, 'inputKind'], ['unknown_kind', 1]], [['inputRefs', 0, 'refId'], ['1bad', 'A'.repeat(257)]], [['inputRefs', 0, 'path'], ['', 7]],
    [['nonClaims'], [[], [''], ['\u3000'], ['same', 'same'], [false], 'x', ['Adoption workflow plans do not scan repository state.']]]]) {
    for (const value of values) refused(replace(base, path, value), path.join('.') + '=' + JSON.stringify(value).slice(0, 40));
  }
  invoke(command, replace(base, ['workflowId'], 'A'.repeat(256)), direct, 'passed', {label: 'id limit'});
  invoke(command, replace(base, ['nonClaims'], ['zulu', 'alpha']), direct, 'passed', {label: 'unsorted claims'});
  for (const [path, value] of [[['inputRefs', 0, 'path'], '/abs.json'], [['inputRefs', 0, 'refId'], 'proofkit.20260101'],
    [['nonClaims'], ['Adoption workflow plans do not scan repository state. ']], [['inputRefs', 1, 'inputKind'], 'registry_consumer']]) {
    refused(replace(base, path, value), 'semantic ' + path.join('.'), false);
  }
  const allKinds = workflowInput('existing_gradual_adoption', inputKinds, presets[0]);
  invoke(command, allKinds, direct, 'passed', {label: 'kind vocabulary limit'});
  const overflow = replace(allKinds, ['inputRefs'], [...allKinds.inputRefs, {inputKind: 'witness_plan', path: 'proofkit/extra.json', refId: 'proofkit.oracle.extra'}]);
  refused(overflow, 'kind vocabulary bound');
  invoke(command, '{"schemaVersion":1,"schemaVersion":1}', ['--agent-envelope'], 'refused', {label: 'framing is not admission'});
  for (const value of [wrap(base), {schema: 'proofkit.adoption-workflow.v1', workflow: base, foreign: true}]) {
    schema(command + '/input', '01-contract-envelope', value, !value.foreign);
  }
  for (const value of [{workflow: base}, {schema: 'proofkit.adoption-workflow.v2', workflow: base}, wrap([]), {...wrap(base), foreign: 1}]) {
    invoke(command, value, contractFlags, 'refused', {label: 'contract drift'});
    invoke(command, value, [...contractFlags, '--agent-envelope'], 'repair', {label: 'contract repair'});
  }
  // A local identity beyond the envelope bound degrades instead of refusing.
  const long = replace(base, ['inputRefs', 0, 'refId'], 'A'.repeat(250));
  const degraded = invoke(command, long, ['--agent-envelope'], 'passed', {label: 'degraded'});
  assert.equal(degraded.bounds.truncated, true); assert(degraded.omitted.length > 0);
});

test('workflow plan and envelope carriers reject independent drift', () => {
  const command = 'adoption-workflow-plan';
  const ready = invoke(command, workflowInput(), [], 'passed');
  const blocked = invoke(command, workflowInput('new_repository', []), [], 'failed');
  const reject = (variant, value, label) => schema(command + '/output', variant, value, false, label);
  for (const key of planKeys) reject('02-workflow-plan', remove(ready, [key]), 'missing ' + key);
  reject('02-workflow-plan', {...ready, foreign: true}, 'foreign');
  reject('02-workflow-plan', {...ready, blockers: blocked.blockers}, 'ready with blockers');
  reject('02-workflow-plan', {...blocked, blockers: []}, 'blocked without blockers');
  reject('02-workflow-plan', {...ready, planState: 'approved'}, 'state enum');
  reject('02-workflow-plan', {...ready, planKind: 'proofkit.foreign'}, 'kind');
  reject('02-workflow-plan', {...ready, schemaVersion: 2}, 'version');
  reject('02-workflow-plan', {...ready, phases: ready.phases.slice(1)}, 'phase count');
  reject('02-workflow-plan', {...ready, phases: [ready.phases[1], ready.phases[0], ...ready.phases.slice(2)]}, 'phase order');
  reject('02-workflow-plan', replace(ready, ['phases', 0, 'commands'], [ready.phases[6].commands[0]]), 'command outside its phase');
  reject('02-workflow-plan', replace(ready, ['phases', 6, 'commands', 0, 'foreign'], 1), 'command foreign');
  reject('02-workflow-plan', replace(ready, ['phases', 6, 'commands', 0, 'argv'], []), 'empty argv');
  reject('02-workflow-plan', replace(ready, ['phases', 6, 'commands', 0, 'owner'], 'proofkit'), 'owner');
  reject('02-workflow-plan', replace(blocked, ['blockers', 0, 'blockerId'], 'proofkit.adoption-workflow.blocker.invented'), 'blocker vocabulary');
  reject('02-workflow-plan', replace(blocked, ['blockers', 0, 'requiredInputKinds'], ['unknown_kind']), 'blocker kinds');
  reject('02-workflow-plan', replace(ready, ['nonClaims'], ready.nonClaims.slice(1)), 'builtin claim removed');
  reject('02-workflow-plan', replace(ready, ['inputRefs', 0, 'inputKind'], 'unknown'), 'ref kind');
  const envelope = invoke(command, workflowInput(), ['--agent-envelope'], 'passed');
  const repair = invoke(command, {}, ['--agent-envelope'], 'repair');
  for (const value of [envelope, repair]) {
    for (const key of envelopeKeys) reject('01-agent-envelope', remove(value, [key]), 'envelope missing ' + key);
    reject('01-agent-envelope', {...value, foreign: true}, 'envelope foreign');
    reject('01-agent-envelope', {...value, schemaVersion: 2}, 'envelope version');
  }
  reject('01-agent-envelope', {...envelope, envelopeId: repairId}, 'mixed identity');
  reject('01-agent-envelope', replace(envelope, ['sourceReport', 'reportKind'], 'proofkit.foreign'), 'source kind');
  reject('01-agent-envelope', replace(envelope, ['contextRefs', 0, 'role'], 'invented_role'), 'context role');
  reject('01-agent-envelope', replace(envelope, ['actionPlan', 0, 'phase'], 'promote'), 'action phase');
  reject('01-agent-envelope', replace(envelope, ['receiptRefs'], [{}]), 'receipt refs');
  reject('01-agent-envelope', replace(repair, ['sourceReport', 'state'], 'passed'), 'repair state');
});

test('pilot variants, clauses and boundaries agree with the CLI', () => {
  const command = 'pilot-admission';
  const direct = [], stack = ['--pilot', 'stack-diverse'];
  invoke(command, pilotInput(), direct, 'passed', {label: 'first'});
  invoke(command, pilotInput(), ['--pilot', 'first'], 'passed');
  invoke(command, pilotInput(true), stack, 'passed', {label: 'stack'});
  invoke(command, pilotInput(true), ['--stack-diverse'], 'passed');
  invoke(command, pilotInput(), stack, 'failed', {label: 'first input under stack requirements'});
  // Report-echoed caller text: secret-shaped values refuse without stdout or
  // echo, an ordinary unknown word stays a failed report carrying the word.
  const secret = 'GL' + 'PAT' + '-EXAMPLE-01';
  for (const [label, path] of [['status', ['blockingRequirements', 'requirements', 0, 'status']], ['pilotMode', ['pilotMode']],
    ['dimension', ['stackDiversity', 'dimensions', 0, 'dimension']], ['outcome', ['cacheNegativeChecks', 0, 'expectedOutcome']],
    ['input class', ['cacheNegativeChecks', 0, 'invalidatedInputClass']]]) {
    const refused = invoke(command, replace(pilotInput(true), path, secret), stack, 'refused', {structural: false, label: 'secret ' + label});
    assert.equal(refused, null);
    const result = run(command, replace(pilotInput(true), path, secret), stack);
    assert.ok(!result.stderr.includes(secret), 'refused value is not echoed: ' + label);
    const failed = invoke(command, replace(pilotInput(true), path, 'unrecognized_word'), stack, 'failed', {label: 'ordinary ' + label});
    assert.ok(JSON.stringify(failed).includes('unrecognized_word'), 'ordinary value stays a collected failure: ' + label);
  }
  invoke(command, replace(pilotInput(true), ['pilotMode'], {mode: [secret]}), stack, 'refused', {structural: false, label: 'nested pilotMode secret'});
  // pilotMode is echoed as serialized JSON: a credential key with its value
  // refuses, while ordinary values under empty or control-character keys stay
  // failed reports that echo the value.
  const sensitive = 'synthetic-fixture-value';
  for (const [label, value] of [['password pair', {password: sensitive}], ['token pair', {token: 'abcdefghijklmnop'}],
    ['authorization pair', {authorization: 'Basic ' + sensitive}], ['split array', ['password=', sensitive]]]) {
    invoke(command, replace(pilotInput(true), ['pilotMode'], value), stack, 'refused', {structural: false, label: 'pilotMode ' + label});
    assert.ok(!run(command, replace(pilotInput(true), ['pilotMode'], value), stack).stderr.includes(sensitive), 'refused pilotMode is not echoed: ' + label);
  }
  for (const [label, value] of [['empty key', {'': 'ordinary'}], ['control key', {'a\u0001': 'ordinary'}]]) {
    const failed = invoke(command, replace(pilotInput(true), ['pilotMode'], value), stack, 'failed', {label: 'pilotMode ' + label});
    assert.deepEqual(failed.summary.pilotMode, value, 'ordinary pilotMode is echoed: ' + label);
  }
  const envelope = {schema: 'proofkit.pilot-admission.v2', input: pilotInput(), stackDiverseInput: pilotInput(true)};
  const pair = invoke(command, envelope, ['--contract-envelope', '--pilot', 'all'], 'passed', {label: 'all'});
  assert.equal(pair.length, 2);
  invoke(command, {schema: envelope.schema, input: pilotInput()}, ['--contract-envelope'], 'passed');
  invoke(command, {schema: envelope.schema, input: pilotInput()}, ['--contract-envelope', '--pilot', 'first'], 'passed');
  invoke(command, {schema: envelope.schema, stackDiverseInput: pilotInput(true)}, ['--contract-envelope', '--stack-diverse'], 'passed');
  invoke(command, {schema: envelope.schema, stackDiverseInput: pilotInput(true)}, ['--contract-envelope', '--pilot', 'stack-diverse'], 'passed');
  invoke(command, replace(envelope, ['stackDiverseInput', 'pilotMode'], 'blocking'), ['--contract-envelope', '--pilot', 'all'], 'failed', {label: 'all failed'});
  for (const value of [{schema: envelope.schema, input: pilotInput(), stackDiverseInput: pilotInput(true)}, {schema: 'proofkit.pilot-admission.v1', input: pilotInput()}, {input: pilotInput()}]) {
    invoke(command, value, ['--contract-envelope'], 'refused', {label: 'contract drift'});
  }
  invoke(command, {schema: envelope.schema, input: pilotInput()}, ['--contract-envelope', '--pilot', 'all'], 'refused', {label: 'all member missing'});
  for (const flags of [['--pilot', 'all'], ['--pilot', 'later'], ['--pilot', 'first', '--stack-diverse'], ['--contract-envelope', '--input-pointer', '/input'], ['--format', 'text']]) {
    const result = run(command, pilotInput(), flags);
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.notEqual(result.stderr, '');
  }
  const base = pilotInput();
  const check = (value, phase, label, structural = true) => {
    invoke(command, value, direct, phase, {label, structural});
    invoke(command, value, stack, phase === 'passed' ? 'failed' : phase, {label: 'stack ' + label, structural});
  };
  for (const key of pilotRequired) check(remove(base, [key]), 'refused', 'missing ' + key);
  for (const key of ['cacheNegativeChecks', 'metrics', 'stackDiversity']) check(remove(base, [key]), 'passed', 'optional ' + key);
  for (const key of ['packageVersionRef', 'pilotMode', 'rolloutClaim']) check(remove(base, [key]), 'failed', 'failure-collected ' + key);
  check({...base, foreign: true}, 'refused', 'root foreign');
  for (const [path, keys] of [[['profile'], ['primaryLanguages', 'repositoryClass', 'repositoryId']], [['rollback'], ['owner', 'rollbackCommand', 'versionPin']]]) {
    check(replace(base, [...path, 'foreign'], true), 'refused', path + ' closed');
    for (const key of keys) check(remove(base, [...path, key]), 'refused', path + ' missing ' + key);
  }
  for (const key of ['commandMatcherBridge', 'customRuleBoundary', 'structuredWitnessCommands', 'verifierCodeCopied']) {
    check(remove(base, ['profile', key]), 'failed', 'profile policy ' + key);
  }
  for (const [path, required] of [[['cacheScheduler'], ['parallelGroups']], [['timingBudget'], ['reportArtifactPath']], [['falsePositiveBudget'], ['dispositionOwner']],
    [['agentReportRoutes', 0], ['artifactPath', 'command', 'expectedUpdatePath', 'reportKind', 'schemaId', 'taskType']], [['impactDemos', 0], ['impactInput']],
    [['blockingRequirements'], []], [['infrastructureBudget'], []]]) {
    check(replace(base, [...path, 'foreign'], true), 'failed', path.join('.') + ' open');
    for (const key of required) check(remove(base, [...path, key]), 'refused', path.join('.') + ' missing ' + key);
    for (const wrong of [null, 'x', 7, []]) check(replace(base, path, wrong), 'refused', path.join('.') + ' type ' + JSON.stringify(wrong));
  }
  for (const [path, values] of [[['schemaVersion'], [1, '2', null]], [['pilotId'], ['1bad', 'A'.repeat(257), null]], [['profile', 'repositoryId'], ['bad id']],
    [['profile', 'repositoryClass'], ['', ' ', 7]], [['profile', 'primaryLanguages'], [[], ['go', 'go'], [''], 'go']],
    [['nonClaims'], [[], ['a', 'a'], ['\t'], null]], [['cacheScheduler', 'parallelGroups'], [[], ['a', 'a'], [7]]],
    [['agentReportRoutes'], [{}, 'x']], [['agentReportRoutes', 0, 'taskType'], ['bad task']], [['agentReportRoutes', 0, 'command'], ['', 7]],
    [['impactDemos', 0, 'demoId'], ['bad id', 7]], [['impactDemos', 0, 'impactInput'], [{}, null]], [['impactDemos', 0, 'impactInput', 'schemaVersion'], [1]],
    [['stackDiversity'], ['x', {}, {baselinePilotId: 'proofkit.base', dimensions: 'x'}, {baselinePilotId: 'proofkit.base', dimensions: [{baseline: 'a'}]}]],
    [['cacheNegativeChecks'], ['x', {}, [7], [{checkId: 'proofkit.check'}], [{checkId: 'proofkit.check', evidence: ''}]]],
    [['infrastructureBudget', 'customRules'], [[7], [{owner: 'o', purpose: 'p'}]]]]) {
    for (const value of values) check(replace(base, path, value), 'refused', path.join('.') + '=' + JSON.stringify(value).slice(0, 40));
  }
  for (const [path, value] of [[['agentReportRoutes'], []], [['impactDemos'], []], [['impactDemos'], 'none'], [['pilotMode'], 'blocking'], [['rolloutClaim'], true],
    [['packageVersionRef'], 7], [['infrastructureBudget', 'customRules'], 'none'], [['blockingRequirements', 'requirements'], [1]],
    [['timingBudget', 'maxAddedSeconds'], -1], [['cacheScheduler', 'cacheKeyInputs'], 'go.mod'],
    [['cacheNegativeChecks'], [{checkId: 'proofkit.check', evidence: 'e', invalidatedInputClass: 'unknown', foreign: 1}]],
    [['stackDiversity'], {baselinePilotId: 'proofkit.base', foreign: 1, dimensions: [{baseline: 'a', candidate: 'a', evidence: 'e', dimension: 7, foreign: 1}]}]]) {
    check(replace(base, path, value), 'failed', 'reporting ' + path.join('.'));
  }
  for (const [path, value] of [[['pilotId'], 'A'.repeat(256)], [['stackDiversity'], null], [['cacheNegativeChecks'], null], [['impactDemos', 0, 'demoId'], null],
    [['profile', 'primaryLanguages'], ['ts', 'go']], [['metrics'], [null, {x: 1}]], [['agentReportRoutes', 0, 'artifactPath'], ' artifacts/oracle.json ']]) {
    check(replace(base, path, value), 'passed', 'accepted ' + path.join('.'));
  }
  check(remove(base, ['impactDemos', 0, 'demoId']), 'passed', 'demo fallback id');
  // impactDemo is admitted only when impactDemos is not an array.
  const single = {...remove(base, ['impactDemos']), impactDemo: pilotDemo('proofkit.oracle.single')};
  check(single, 'passed', 'single demo');
  check({...single, impactDemos: 'ignored'}, 'passed', 'single demo over text');
  check({...single, impactDemo: null}, 'refused', 'null single demo');
  check({...single, impactDemo: 7, impactDemos: 'ignored'}, 'refused', 'invalid single demo');
  check({...base, impactDemo: 7}, 'passed', 'single demo ignored by array');
  for (const [path, value] of [[['agentReportRoutes', 0, 'command'], 'render && curl example.test'], [['rollback', 'rollbackCommand'], 'revert; rm -rf x'],
    [['agentReportRoutes', 0, 'artifactPath'], '/tmp/report.json'], [['profile', 'primaryLanguages'], ['go', ' go']], [['pilotId'], 'proofkit.20260101']]) {
    check(replace(base, path, value), 'refused', 'semantic ' + path.join('.'), false);
  }
});

test('pilot report carriers reject independent drift and keep state rules', () => {
  const command = 'pilot-admission';
  const passed = invoke(command, pilotInput(), [], 'passed');
  const failed = invoke(command, pilotInput(), ['--pilot', 'stack-diverse'], 'failed');
  assert.deepEqual(Object.keys(passed).sort(), reportKeys);
  assert.deepEqual(Object.keys(passed.summary).sort(), pilotSummaryKeys);
  assert.deepEqual(passed.diagnostics.map(row => row.key), pilotDiagnosticKeys);
  assert.deepEqual(passed.ruleResults.map(row => [row.ruleId, row.status]), [['proofkit.pilot-admission.accepted', 'passed']]);
  assert(failed.ruleResults.every((row, index) => row.ruleId === `proofkit.pilot-admission.failure.${String(index + 1).padStart(3, '0')}` && row.status === 'failed'));
  const reject = (value, label) => schema(command + '/output', '02-report', value, false, label);
  for (const key of reportKeys) reject(remove(passed, [key]), 'missing ' + key);
  for (const key of pilotSummaryKeys) reject(remove(passed, ['summary', key]), 'summary missing ' + key);
  reject({...passed, foreign: true}, 'foreign');
  reject(replace(passed, ['summary', 'foreign'], 1), 'summary foreign');
  reject({...passed, ruleResults: failed.ruleResults}, 'passed with failures');
  reject({...failed, ruleResults: passed.ruleResults}, 'failed with accepted rule');
  reject({...passed, state: 'blocked'}, 'state enum');
  reject({...passed, reportKind: 'proofkit.foreign'}, 'kind');
  reject({...passed, schemaVersion: 2}, 'version');
  reject({...passed, nonClaims: []}, 'empty claims');
  reject(replace(passed, ['summary', 'pilotMode'], 'blocking'), 'passed pilot mode');
  reject(replace(passed, ['summary', 'copiedVerifierFileCount'], 1), 'passed copied files');
  reject(replace(passed, ['summary', 'maxAddedSeconds'], -0.5), 'negative seconds');
  reject(replace(passed, ['summary', 'impactDemoCount'], 1.5), 'fractional count');
  reject({...passed, diagnostics: [passed.diagnostics[1], passed.diagnostics[0], ...passed.diagnostics.slice(2)]}, 'diagnostic order');
  reject({...passed, diagnostics: passed.diagnostics.slice(1)}, 'diagnostic count');
  reject(replace(passed, ['diagnostics', 3, 'value', 0, 'state'], 'unknown'), 'impact state');
  reject(replace(passed, ['diagnostics', 3, 'value', 0, 'foreign'], 1), 'impact demo foreign');
  reject(replace(failed, ['ruleResults', 0, 'ruleId'], 'proofkit.pilot-admission.failure.1'), 'failure id width');
  reject(replace(failed, ['ruleResults', 0, 'diagnostics'], [{key: 'x', value: 1}]), 'rule diagnostics');
  schema(command + '/output', '02-report', replace(failed, ['summary', 'pilotMode'], {raw: [null]}), true, 'raw failed pilot mode');
  const pair = invoke(command, {schema: 'proofkit.pilot-admission.v2', input: pilotInput(), stackDiverseInput: pilotInput(true)}, ['--contract-envelope', '--pilot', 'all'], 'passed');
  for (const value of [[], [pair[0]], [...pair, pair[0]], {0: pair[0], 1: pair[1]}, [pair[0], {...pair[1], foreign: 1}]]) {
    schema(command + '/output', '01-all', value, false, 'pair drift');
  }
});

test('whole chains preserve child carriers across aggregate, contract and pointer routes', () => {
  const value = aggregate();
  const viaAggregate = invoke('adoption-contract-envelope', value, ['--mode', 'workflow'], 'passed');
  const viaContract = invoke('adoption-workflow-plan', value.workflow, ['--contract-envelope'], 'passed');
  const pointer = run('adoption-workflow-plan', value, ['--input-pointer', '/workflow/workflow']);
  assert.equal(pointer.status, 0, pointer.stderr);
  assert.deepEqual(viaAggregate, viaContract); assert.deepEqual(JSON.parse(pointer.stdout), viaContract);
  assert.deepEqual(invoke('adoption-contract-envelope', value, ['--mode', 'workflow', '--agent-envelope'], 'passed'),
    invoke('adoption-workflow-plan', value.workflow, ['--contract-envelope', '--agent-envelope'], 'passed'));
  const pilotAll = invoke('adoption-contract-envelope', value, ['--mode', 'pilot', '--pilot', 'all'], 'passed');
  assert.deepEqual(pilotAll, invoke('pilot-admission', value.pilot, ['--contract-envelope', '--pilot', 'all'], 'passed'));
  const pilotPointer = run('pilot-admission', value, ['--input-pointer', '/pilot/stackDiverseInput', '--stack-diverse']);
  assert.equal(pilotPointer.status, 0, pilotPointer.stderr);
  assert.deepEqual(JSON.parse(pilotPointer.stdout), pilotAll[1]);
  schema('pilot-admission/output', '02-report', pilotAll[0]);
  const bootstrap = invoke('adoption-contract-envelope', value, ['--mode', 'bootstrap'], 'passed');
  const profile = run('gradual-adoption', JSON.stringify(bootstrap), ['--input-pointer', '/payloads/adoptionProfile']);
  assert.equal(profile.status, 0, profile.stderr);
  schema('adoption-contract-envelope/output', '01-adoption-report', JSON.parse(profile.stdout), true, 'payload chain');
  const guidance = run('gradual-adoption-guidance', JSON.stringify(bootstrap), ['--input-pointer', '/payloads/adoptionGuidance']);
  assert.equal(guidance.status, 0, guidance.stderr);
  schema('adoption-contract-envelope/output', '06-guidance-report', JSON.parse(guidance.stdout), true, 'guidance chain');
  const manifest = invoke('adoption-contract-envelope', value, ['--mode', 'bootstrap', '--materialization-manifest'], 'passed');
  for (const file of manifest.files.filter(file => file.contentKind === 'json')) assert.deepEqual(JSON.parse(file.content), bootstrap.payloads[file.payloadKey]);
  for (const flags of [['--mode', 'adoption'], ['--mode', 'guidance']]) {
    const direct = run(flags[1] === 'adoption' ? 'gradual-adoption' : 'gradual-adoption-guidance', {schema: value.gradual.schema, input: value.gradual.input,
      ...(flags[1] === 'guidance' ? {guidance: value.gradual.guidance} : {})}, ['--contract-envelope']);
    assert.equal(direct.status, 0, direct.stderr);
    assert.deepEqual(invoke('adoption-contract-envelope', value, flags, 'passed'), JSON.parse(direct.stdout));
  }
});

test('isolated schema controls falsify weakened clauses', () => {
  const variant = (key, id) => structuredClone(checks.get(key).get(id).schema);
  const workflow = variant('adoption-workflow-plan/input', '02-direct');
  workflow.additionalProperties = true;
  assert.equal(compile(workflow)({...workflowInput(), foreign: true}), true, 'open-root control');
  schema('adoption-workflow-plan/input', '02-direct', {...workflowInput(), foreign: true}, false);
  const pilot = variant('pilot-admission/input', '04-direct');
  delete pilot.anyOf;
  const singleNull = {...remove(pilotInput(), ['impactDemos']), impactDemo: null};
  assert.equal(compile(pilot)(singleNull), true, 'conditional-demo control');
  schema('pilot-admission/input', '04-direct', singleNull, false);
  const aggregateShape = variant('adoption-contract-envelope/input', '14-workflow');
  aggregateShape.properties.gradual.properties.input = {type: 'object', additionalProperties: false, properties: {}};
  assert.equal(compile(aggregateShape)(aggregate()), false, 'unselected-child control');
  schema('adoption-contract-envelope/input', '14-workflow', aggregate());
  const report = variant('pilot-admission/output', '02-report');
  delete report.oneOf;
  const failed = JSON.parse(run('pilot-admission', pilotInput(), ['--pilot', 'stack-diverse']).stdout);
  const forged = {...failed, state: 'passed'};
  assert.equal(compile(report)(forged), true, 'state-rule control');
  schema('pilot-admission/output', '02-report', forged, false);
  const plan = variant('adoption-workflow-plan/output', '02-workflow-plan');
  delete plan.oneOf;
  const blocked = JSON.parse(run('adoption-workflow-plan', workflowInput('new_repository', [])).stdout);
  const unblocked = {...blocked, blockers: []};
  assert.equal(compile(plan)(unblocked), true, 'plan-state control');
  schema('adoption-workflow-plan/output', '02-workflow-plan', unblocked, false);
});
