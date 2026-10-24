import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport, spawnWithInputFile} from './cli-process.mjs';
import {stableJSONStringify} from './stable-json.mjs';

// Independent oracle for agent-route, change-workflow-plan and
// native-evidence-guidance. Expected inventories below are authored from the
// public CLI behavior, never derived from the schemas under test.
const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_AGENT_WORKFLOW_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const compile = schema => new Ajv2020({strict: false, validateFormats: false}).compile(schema);
const identities = {
  'agent-route/input': ['proofkit.agent-route.input.v2', 1, ['01-direct']],
  'agent-route/output': ['proofkit.agent-route.output.v3', 3, ['01-agent-brief', '02-agent-envelope-full', '03-invalid-input-repair', '04-routed', '05-unknown-goal']],
  'change-workflow-plan/input': ['proofkit.change-workflow-plan.input.v1', 1, ['01-root']],
  'change-workflow-plan/output': ['proofkit.change-workflow-plan.output.v1', 1, ['01-agent-envelope', '02-next-action', '03-accept-stage', '04-workflow-complete']],
  'native-evidence-guidance/output': ['proofkit.native-evidence-guidance.output.v1', 1, ['01-root']],
};
const owners = new Map(Object.keys(identities).map(key => {
  const [command, direction] = key.split('/');
  const record = contract.commands.find(row => row.command === command)[direction + 'Contract'];
  const definition = contract.contractDefinitions.find(row => row.definitionId === record.rootDefinitionRef);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema', key);
  return [key, {record, definition, variants: definition.fieldTree.variants.map(row => ({id: row.variantId, schema: row.schema, check: compile(row.schema)}))}];
}));
const ROUTE_IN = 'agent-route/input', ROUTE_OUT = 'agent-route/output';
const FLOW_IN = 'change-workflow-plan/input', FLOW_OUT = 'change-workflow-plan/output', GUIDE = 'native-evidence-guidance/output';
const [BRIEF, FULL, REPAIR, ROUTED, UNKNOWN] = [0, 1, 2, 3, 4];
const [ENVELOPE, NEXT, ACCEPT, COMPLETE] = [0, 1, 2, 3];

function valid(key, index, value, expected = true, label = '') {
  const check = owners.get(key).variants[index].check;
  assert.equal(check(value), expected, `${key}#${index} ${label}: ${JSON.stringify(check.errors)?.slice(0, 600)}`);
}
// The observed value must satisfy exactly its selected variant.
function selects(key, index, value, label = '') {
  owners.get(key).variants.forEach((variant, position) => {
    assert.equal(variant.check(value), position === index, `${key} ${label}: variant ${variant.id} ${JSON.stringify(variant.check.errors)?.slice(0, 600)}`);
  });
}
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replaced(value, path, next) {
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = next; return copy;
}
function removed(value, path) {
  const copy = structuredClone(value); delete at(copy, path.slice(0, -1))[path.at(-1)]; return copy;
}

let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-agent-workflow-contract-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 180000, maxBuffer: 2 << 20, env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

const pathLauncher = {AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'path', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: ''};
function run(args, input, {env = pathLauncher, cwd} = {}) {
  const result = spawnWithInputFile(binary, args, {
    input: input === undefined ? undefined : typeof input === 'string' ? input : JSON.stringify(input),
    encoding: 'utf8', timeout: 20000, maxBuffer: 16 << 20, env: {...process.env, ...env}, cwd,
  });
  assertCLITransport(result);
  return result;
}
function emitted(result, status) {
  assert.equal(result.stderr, '', result.stderr); assert.equal(result.status, status, result.stdout.slice(0, 400));
  return JSON.parse(result.stdout);
}
function refused(result) {
  assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.notEqual(result.stderr, '');
}
const keysOf = value => Object.keys(value).sort();

// Change-workflow and guidance inventories are shared by the identity test.
const stages = ['architecture', 'design', 'implementation_plan', 'implementation', 'verification', 'pull_request', 'closeout'];
const checkpointStates = ['not_started', 'ready_for_review', 'review_findings', 'review_passed'];
const flowInputKeys = ['checkpoint', 'completedStageIds', 'contextRefs', 'governingAuthorityRefId', 'requiredContextRefIds', 'schemaVersion'];
const planKeys = ['authority', 'completedStageIds', 'nonClaims', 'omittedContextCount', 'omittedContextRefIds', 'outputKind', 'reportId', 'reportKind',
  'retainedContextRefIds', 'retainedContextRefs', 'schemaVersion', 'workflowProfileId'];
const activeKeys = ['action', 'activeStageId', 'checkpointState', 'prompt'];
const promptKeys = ['candidateAction', 'coordinates', 'expectedNextCheckpoint', 'nonClaim', 'observedFact', 'ownerOrEscalationTarget',
  'proofCommandOrMissingWitness', 'stopCondition', 'uncertainty'];
const slotIds = ['semantic_owner', 'subject_identity_currentness', 'execution_root_source_snapshot', 'exact_argv', 'stdin_input_bytes',
  'toolchain_environment', 'positive_control', 'near_miss_falsifier', 'oracle_rule', 'input_work_bounds', 'environment_network_policy',
  'resource_bounds', 'output_bounds', 'process_lifecycle', 'exit_mapping', 'nondisclosure', 'cleanup_crash_inventory', 'receipt_identity',
  'currentness_trust', 'escalation', 'retirement', 'non_claims'];
const applicability = ['always', 'declared_input_channels', 'environment_or_network_access', 'external_process', 'mutable_artifacts'];

// ---------------------------------------------------------------- agent-route
const routeRequired = ['goal', 'mode', 'routeId', 'schemaVersion'];
const routeOptional = ['availableInputs', 'browserMode', 'knownChangedPaths', 'nonClaims', 'observedReports', 'openBrowser'];
const reportKeys = ['callerNonClaims', 'diagnostics', 'escalations', 'guidanceSlice', 'nextCommands', 'nonClaims', 'observedReports', 'omitted',
  'reportId', 'reportKind', 'requiredInputs', 'schemaVersion', 'selectedRouteFamily', 'state', 'stopConditions', 'summary'];
const summaryKeys = ['availableCommandCount', 'availableInputCount', 'browserMode', 'callerNonClaimCount', 'goal', 'knownChangedPaths',
  'launcherProfile', 'mode', 'observedReportCount', 'openBrowser'];
const sliceKeys = ['authorityRefs', 'lookupOnly', 'nonClaims', 'routeFamily', 'sliceId', 'sliceSummary', 'sourceAuthority'];
const briefKeys = ['blockers', 'boundaryPolicyRefs', 'contextRefs', 'detailAccess', 'nextAction', 'omissionSummary', 'packetId', 'packetKind', 'routeFamily', 'schemaVersion', 'state'];
const detailKeys = ['commandRef', 'launcherProfile', 'outputArgs', 'requiresOriginalInput', 'requiresOriginalLauncherContext', 'sourceReportDigest', 'sourceReportId'];
const envelopeKeys = ['actionPlan', 'blockedPreconditions', 'bounds', 'clarificationQuestions', 'commands', 'contextRefs', 'costContract', 'envelopeId',
  'nonClaims', 'omitted', 'receiptRefs', 'routeQuestions', 'schemaVersion', 'sourceReport'];
const builtinRouteClaims = [
  'A routed state is command-selection evidence only; downstream command reports own their own admission result states.',
  'agent-route does not decide product meaning, proof freshness, producer trust, merge, release, rollout, deployment, or production readiness.',
  'agent-route does not read repository state, execute returned commands, inspect native tests, or write files.',
  'agent-route selects a deterministic Proofkit command family from explicit caller-owned facts only.',
];
const inputKinds = ['adoption_workflow', 'authoring_plan', 'binding_witness_plan_input', 'capability_map', 'changed_path_set', 'compact_proof_binding',
  'coverage_compose_input', 'coverage_view_input', 'deployment_evidence_input', 'impact_input', 'migration_parity', 'migration_plan',
  'obligation_decision', 'obligation_decision_input', 'overview_claims', 'proof_binding', 'readiness_closeout_input', 'registry_consumer_input',
  'release_authority_input', 'requirement_context_catalog', 'requirement_context_repo_root', 'requirement_context_slice_input',
  'requirement_semantic_diff_input', 'requirement_source', 'requirement_source_transition', 'requirement_traceability_graph_input',
  'requirement_workspace_input', 'scaffold_profile_plan', 'scaffold_project_structure', 'selective_evidence', 'selective_gate_plan_input',
  'spec_tree_bundle', 'test_discovery', 'test_inventory', 'typescript_public_api_manifest', 'typescript_public_api_repo_root', 'witness_command_catalog'];
const routeGoals = ['admit_receipts', 'adopt_repository', 'author_requirements', 'bind_requirement_proofs', 'check_overview_claims', 'decide_obligations',
  'inspect_coverage', 'inspect_requirement_context', 'inspect_requirement_traceability', 'inventory_tests', 'plan_selective_checks',
  'release_or_deploy_evidence', 'render_human_view', 'retire_local_infrastructure', 'review_requirement_change', 'scaffold_first_module',
  'unknown', 'validate_requirement_source', 'verify_typescript_public_api'];

function routeInput(extra = {}) {
  return {schemaVersion: 1, routeId: 'consumer.route.fixture', goal: 'validate_requirement_source', mode: 'observe',
    availableInputs: [{kind: 'requirement_source', ref: 'docs/specs/example/requirements.v2.json'}], ...extra};
}
function everyInput() {
  return inputKinds.map(kind => ({kind, ref: kind.endsWith('_repo_root') ? '.' : 'inputs/' + kind + '.json'}));
}
function route(input, flags = [], env) {
  return run(['agent-route', '--input', '-', ...flags], input, {env});
}
// Inputs selected through --input-pointer are validated at their selected value.
function routedResult(input, flags, index, status, env) {
  if (typeof input !== 'string' && index !== REPAIR && !flags.includes('--input-pointer')) valid(ROUTE_IN, 0, input, true, 'fixture input');
  const result = route(input, flags, env);
  const value = emitted(result, status);
  selects(ROUTE_OUT, index, value, flags.join(' '));
  return [value, result.stdout];
}
const routed = (...args) => routedResult(...args)[0];

test('published identities and independently authored root inventories', () => {
  for (const [key, [contractId, version, variants]] of Object.entries(identities)) {
    const owner = owners.get(key);
    assert.equal(owner.record.contractId, contractId, key);
    assert.equal(owner.record.schemaVersion, version, key);
    assert.match(owner.record.rootDefinitionRef, /\.json-schema$/);
    assert.deepEqual(owner.variants.map(variant => variant.id), variants, key);
    assert(!contract.contractDefinitions.some(row => row.definitionId === contractId + '.root-shape'), key + ' predecessor remains');
  }
  const input = owners.get(ROUTE_IN).variants[0].schema;
  assert.deepEqual([...input.required].sort(), routeRequired);
  assert.deepEqual(Object.keys(input.properties).sort(), [...routeRequired, ...routeOptional].sort());
  const output = owners.get(ROUTE_OUT).variants.map(variant => variant.schema);
  assert.deepEqual([...output[BRIEF].required].sort(), briefKeys);
  for (const index of [FULL, REPAIR]) assert.deepEqual([...output[index].required].sort(), envelopeKeys);
  for (const index of [ROUTED, UNKNOWN]) {
    assert.deepEqual([...output[index].required].sort(), reportKeys);
    assert.deepEqual([...output[index].properties.summary.required].sort(), summaryKeys);
    assert.deepEqual([...output[index].properties.guidanceSlice.required].sort(), sliceKeys);
  }
  assert.deepEqual([...output[BRIEF].properties.detailAccess.required].sort(), detailKeys);
  assert.deepEqual([...owners.get(FLOW_IN).variants[0].schema.required].sort(), flowInputKeys);
  const plans = owners.get(FLOW_OUT).variants.map(variant => variant.schema);
  assert.deepEqual([...plans[ENVELOPE].required].sort(), envelopeKeys);
  assert.deepEqual([...plans[NEXT].required].sort(), [...planKeys, ...activeKeys].sort());
  assert.deepEqual([...plans[ACCEPT].required].sort(), [...planKeys, ...activeKeys, 'successorStateDelta'].sort());
  assert.deepEqual([...plans[COMPLETE].required].sort(), planKeys);
  assert.deepEqual([...plans[NEXT].properties.prompt.required].sort(), promptKeys);
  const guide = owners.get(GUIDE).variants[0].schema;
  assert.deepEqual([...guide.required].sort(), ['guidanceId', 'nonClaims', 'schemaVersion', 'slots']);
});

test('agent-route selects every public variant from flags, goal and admission result', () => {
  const report = routed(routeInput(), [], ROUTED, 0);
  assert.deepEqual(keysOf(report), reportKeys); assert.deepEqual(keysOf(report.summary), summaryKeys);
  assert.deepEqual(keysOf(report.guidanceSlice), sliceKeys); assert.equal(report.state, 'routed'); assert.equal(report.schemaVersion, 3);
  for (const claim of builtinRouteClaims) assert(report.nonClaims.includes(claim));
  const missing = routed(routeInput({availableInputs: []}), [], ROUTED, 1);
  assert.equal(missing.state, 'blocked_missing_input'); assert.deepEqual(missing.nextCommands, []);
  const failed = routeInput({observedReports: [{kind: 'release', ref: 'reports/release.json', state: 'failed'}]});
  assert.equal(routed(failed, [], ROUTED, 1).state, 'blocked_ambiguous_state');
  const unknownInput = routeInput({goal: 'unknown'});
  const unknown = routed(unknownInput, [], UNKNOWN, 1);
  assert.equal(unknown.state, 'blocked_unknown_goal'); assert.equal(unknown.selectedRouteFamily, 'unknown');
  const bare = route(routeInput(), ['--agent-envelope']), explicit = route(routeInput(), ['--agent-envelope', '--agent-envelope-mode', 'brief']);
  assert.equal(bare.stdout, explicit.stdout);
  const brief = routed(routeInput(), ['--agent-envelope'], BRIEF, 0);
  assert.deepEqual(keysOf(brief), briefKeys); assert.deepEqual(keysOf(brief.detailAccess), detailKeys);
  assert.equal(brief.nextAction.argvState, 'inline');
  assert.equal(routed(routeInput({availableInputs: []}), ['--agent-envelope'], BRIEF, 1).nextAction, null);
  assert.equal(routed(unknownInput, ['--agent-envelope'], BRIEF, 1).blockers[0].kind, 'unknown_goal');
  const full = routed(routeInput(), ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 0);
  assert.deepEqual(keysOf(full), envelopeKeys); assert.equal(full.envelopeId, 'consumer.route.fixture.agent-envelope');
  routed(unknownInput, ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 1);
  const invalid = routeInput({availableInputs: [{kind: 'requirement_source', ref: '../outside.json'}]});
  for (const [input, flags] of [[invalid, ['--agent-envelope']], [invalid, ['--agent-envelope', '--agent-envelope-mode', 'full']],
    ['{', ['--agent-envelope']], ['{"a":1,"a":1}', ['--agent-envelope']], [{wrapped: routeInput()}, ['--agent-envelope', '--input-pointer', '/missing']]]) {
    const repair = routed(input, flags, REPAIR, 1);
    assert.equal(repair.envelopeId, 'proofkit.agent-envelope.invalid-input');
  }
  valid(ROUTE_IN, 0, routeInput(), true, 'pointer target');
  assert.deepEqual(routed({wrapped: routeInput()}, ['--input-pointer', '/wrapped'], ROUTED, 0), report);
  for (const [input, flags] of [[invalid, []], ['{', []], [routeInput(), ['--agent-envelope-mode', 'full']],
    [routeInput(), ['--agent-envelope', '--agent-envelope-mode', 'expanded']], [routeInput(), ['--format', 'text']]]) {
    refused(route(input, flags));
  }
  const npm = routed(routeInput(), [], ROUTED, 0, {AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'npm_offline', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: ''});
  assert.deepEqual(npm.nextCommands[0].argv.slice(0, 5), ['npm', 'exec', '--offline', '--', 'agentic-proofkit']);
  const python = {AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'python_module', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: '/opt/fixture/python3'};
  assert.equal(routed(routeInput(), [], ROUTED, 0, python).summary.launcherProfile, 'python_module');
  assert.equal(routed(routeInput(), ['--agent-envelope'], BRIEF, 0, python).detailAccess.launcherProfile, 'python_module');
  for (const goal of routeGoals) {
    const input = routeInput({goal, availableInputs: everyInput(), browserMode: 'serve_local_view', openBrowser: true});
    routed(input, [], goal === 'unknown' ? UNKNOWN : ROUTED, goal === 'unknown' ? 1 : 0);
    routed(input, ['--agent-envelope'], BRIEF, goal === 'unknown' ? 1 : 0);
    routed(input, ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, goal === 'unknown' ? 1 : 0);
    routed(routeInput({goal, availableInputs: []}), [], goal === 'unknown' ? UNKNOWN : ROUTED, 1);
  }
});

test('agent-route chains brief detail access, report digest, full detail and a routed downstream command', () => {
  const workspace = join(directory, 'chain');
  mkdirSync(join(workspace, 'inputs'), {recursive: true});
  const changes = {schemaVersion: 1, reportId: 'consumer.changes', nonClaims: [], preexistingFailures: [], sources: [{sourceId: 'git.diff', paths: ['src/a.go']}]};
  writeFileSync(join(workspace, 'inputs/changes.json'), JSON.stringify(changes));
  const input = routeInput({goal: 'plan_selective_checks', availableInputs: [{kind: 'changed_path_set', ref: 'inputs/changes.json'}]});
  const brief = routed(input, ['--agent-envelope'], BRIEF, 0);
  const reportArgs = brief.detailAccess.outputArgs.report, fullArgs = brief.detailAccess.outputArgs.full;
  // The brief binds the exact canonical bytes the report invocation emits.
  const [report, reportBytes] = routedResult(input, reportArgs, ROUTED, 0);
  const digest = 'sha256:' + createHash('sha256').update(reportBytes).digest('hex');
  assert.equal(brief.detailAccess.sourceReportDigest, digest); assert.equal(brief.detailAccess.sourceReportId, report.reportId);
  const full = routed(input, fullArgs, FULL, 0);
  assert(full.commands.some(command => command.commandId === brief.nextAction.commandId));
  assert.deepEqual(brief.nextAction.argv, report.nextCommands[0].argv);
  for (const ref of brief.contextRefs) {
    assert.equal(at(report, ref.sourceReportPointer.split('/').slice(1)), 'inputs/changes.json');
  }
  const [launcher, ...args] = report.nextCommands[0].argv;
  assert.equal(launcher, 'agentic-proofkit');
  const downstream = spawnSync(binary, args, {cwd: workspace, encoding: 'utf8', timeout: 20000, env: {...process.env, ...pathLauncher}});
  assert.equal(downstream.stderr, ''); assert.equal(downstream.status, 0);
  const changedRecord = contract.commands.find(row => row.command === 'changed-path-set').outputContract;
  const changedDefinition = contract.contractDefinitions.find(row => row.definitionId === changedRecord.rootDefinitionRef);
  assert.equal(compile(changedDefinition.fieldTree.variants[0].schema)(JSON.parse(downstream.stdout)), true, 'downstream report violates its own contract');
});

test('agent-route input clauses agree with native admission at the public CLI', () => {
  const base = routeInput({
    browserMode: 'serve_local_view', openBrowser: true, knownChangedPaths: ['a.go', 'b.go'],
    observedReports: [{kind: 'evidence', ref: 'reports/a.json', state: 'passed'}], nonClaims: ['Caller claim.'],
  });
  const accepted = (input, label) => {
    valid(ROUTE_IN, 0, input, true, label);
    const result = route(input);
    assert.equal(result.stderr, '', label + ': ' + result.stderr); assert(result.status === 0 || result.status === 1);
    selects(ROUTE_OUT, ROUTED, JSON.parse(result.stdout), label);
  };
  const rejected = (input, label) => {
    valid(ROUTE_IN, 0, input, false, label);
    refused(route(input));
    selects(ROUTE_OUT, REPAIR, emitted(route(input, ['--agent-envelope']), 1), label + '/repair');
  };
  // Refusals the schema cannot express remain native: the schema admits them.
  const nativeOnly = (input, label) => {
    valid(ROUTE_IN, 0, input, true, label);
    refused(route(input));
  };
  accepted(base, 'base');
  for (const key of routeRequired) rejected(removed(base, [key]), 'required/' + key);
  for (const key of routeOptional) {
    accepted(key === 'browserMode' ? removed(removed(base, [key]), ['openBrowser']) : removed(base, [key]), 'optional/' + key);
    accepted(key === 'browserMode' ? {...base, browserMode: null, openBrowser: null} : {...base, [key]: null}, 'nullable/' + key);
  }
  rejected({...base, foreign: true}, 'root closure');
  for (const [path, wrong] of [[['schemaVersion'], [2, '1', 1.5, 0, null]], [['routeId'], ['', '1route', 'route id', 'route.', 'route..id', 7, null]],
    [['goal'], ['foreign', '', 1, null]], [['mode'], ['strict', '', null]], [['browserMode'], ['foreign', 1]], [['openBrowser'], ['true', 1, {}]],
    [['availableInputs'], [{}, 'inputs', 1]], [['availableInputs', 0], [null, 'x.json', []]], [['availableInputs', 0, 'kind'], ['foreign', 1, null]],
    [['availableInputs', 0, 'ref'], ['', ' \t', 1, null]], [['knownChangedPaths'], ['a.go', {}]], [['knownChangedPaths', 0], ['', 1, null]],
    [['observedReports'], [{}, 1]], [['observedReports', 0, 'kind'], ['foreign', null]], [['observedReports', 0, 'state'], ['foreign', 'routed', null]],
    [['observedReports', 0, 'ref'], ['', '  ', 7]], [['nonClaims'], ['Caller claim.', {}]], [['nonClaims', 0], ['', ' Caller claim.', 'Caller claim. ', 1, null]],
  ]) for (const value of wrong) rejected(replaced(base, path, value), path.join('.') + '=' + JSON.stringify(value));
  for (const path of [['availableInputs', 0], ['observedReports', 0]]) rejected(replaced(base, [...path, 'foreign'], true), path.join('.') + '/closure');
  for (const [path, key] of [[['availableInputs', 0], 'kind'], [['availableInputs', 0], 'ref'], [['observedReports', 0], 'state'], [['observedReports', 0], 'ref']]) {
    rejected(removed(base, [...path, key]), path.join('.') + '/required/' + key);
  }
  // Exact limits are admitted; one more is refused by both owners.
  accepted({...base, routeId: 'r'.repeat(96)}, 'route-id-limit');
  rejected({...base, routeId: 'r'.repeat(97)}, 'route-id-limit+1');
  const claims = count => Array.from({length: count}, (_, index) => `Claim ${String(index).padStart(2, '0')}.`);
  accepted({...base, nonClaims: claims(8)}, 'claims-limit');
  rejected({...base, nonClaims: claims(9)}, 'claims-limit+1');
  accepted({...base, nonClaims: ['\u00e9'.repeat(240)]}, 'claim-runes-limit');
  rejected({...base, nonClaims: ['\u00e9'.repeat(241)]}, 'claim-runes-limit+1');
  accepted({...base, availableInputs: everyInput()}, 'input-kind-limit');
  rejected({...base, availableInputs: [...everyInput(), {kind: 'requirement_source', ref: 'extra.json'}]}, 'input-kind-limit+1');
  accepted({...base, browserMode: 'view_plan', openBrowser: false}, 'closed-browser');
  rejected({...base, browserMode: 'view_plan'}, 'open-without-serve');
  rejected(removed(base, ['browserMode']), 'open-with-default-mode');
  rejected({...base, knownChangedPaths: ['a.go', 'a.go']}, 'duplicate-paths');
  rejected({...base, nonClaims: ['Caller claim.', 'Caller claim.']}, 'duplicate-claims');
  accepted({...base, availableInputs: [{kind: 'requirement_source', ref: '  docs/specs/requirements.json\t'}]}, 'trimmed-ref');
  accepted({...base, availableInputs: [{kind: 'typescript_public_api_repo_root', ref: '.'}, {kind: 'typescript_public_api_manifest', ref: 'api.json'}],
    goal: 'verify_typescript_public_api'}, 'repo-root-dot');
  nativeOnly(replaced(base, ['availableInputs', 0, 'ref'], '../outside.json'), 'escaping-ref');
  nativeOnly(replaced(base, ['availableInputs', 0, 'ref'], '-'), 'stdin-ref');
  nativeOnly(replaced(base, ['availableInputs', 0, 'ref'], '.'), 'dot-ref-for-file-kind');
  nativeOnly({...base, availableInputs: [base.availableInputs[0], base.availableInputs[0]]}, 'duplicate-kind');
  nativeOnly({...base, observedReports: [base.observedReports[0], base.observedReports[0]]}, 'duplicate-observed-ref');
  nativeOnly({...base, nonClaims: ['b', 'a']}, 'unsorted-claims');
  nativeOnly({...base, knownChangedPaths: ['b.go', 'a.go']}, 'unsorted-paths');
  nativeOnly({...base, routeId: 'route.20240101'}, 'timestamp-route-id');
});

// Generic carrier refuters over observed outputs: every closed object refuses a
// foreign member and the removal of each non-optional member; every node
// refuses other JSON kinds; text refuses emptiness; integers refuse negatives
// and fractions; enumerated paths refuse a foreign member.
function carrierPredicates(key, index, output, {optional = [], nullable = [], emptyText = [], enums = []}, label) {
  const match = (patterns, name) => patterns.some(pattern => pattern.test(name));
  const kind = value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
  const samples = [['null', null], ['boolean', false], ['number', 42], ['string', 'wrong type'], ['array', []], ['object', {}]];
  const reject = (value, what) => valid(key, index, value, false, `${label}/${what}`);
  const visit = (value, path) => {
    const name = path.join('.');
    if (path.length) {
      for (const [type, sample] of samples) {
        if (type === kind(value) || type === 'null' && match(nullable, name) || kind(value) === 'null' && match(nullable, name) && type === 'object') continue;
        reject(replaced(output, path, sample), 'kind/' + type + '/' + name);
      }
    }
    if (typeof value === 'string') {
      if (!match(emptyText, name)) reject(replaced(output, path, ''), 'empty/' + name);
      if (match(enums, name)) reject(replaced(output, path, 'foreign-fixture-value'), 'enum/' + name);
    }
    if (typeof value === 'number') {
      reject(replaced(output, path, -1), 'negative/' + name); reject(replaced(output, path, value + 0.5), 'fraction/' + name);
    }
    if (kind(value) === 'object') {
      reject(path.length ? replaced(output, [...path, 'foreign'], true) : {...output, foreign: true}, 'closure/' + name);
      for (const member of Object.keys(value)) {
        const child = [...path, member].join('.');
        if (!match(optional, child)) reject(removed(output, [...path, member]), 'required/' + child);
        else valid(key, index, removed(output, [...path, member]), true, 'optional/' + child);
      }
    }
    if (value !== null && typeof value === 'object') for (const [member, child] of Object.entries(value)) visit(child, [...path, member]);
  };
  visit(output, []);
}

const kernelBounds = [/^bounds\.(truncated|referenceClosurePreserved|prunedLocalReferenceCount|boundsViolationCount|boundsViolations)$/];
const kernelNulls = [/^sourceReport\.(artifactRef|stableHash)$/, /^bounds\.maxTokenBudget$/, /^costContract\.(maxTokenBudget|affectedRequirementCount)$/];
const routeReportEnums = [/^(state|selectedRouteFamily|reportKind)$/, /^summary\.(browserMode|goal|launcherProfile|mode)$/,
  /^guidanceSlice\.(routeFamily|sliceId|sliceSummary|sourceAuthority)$/, /^guidanceSlice\.nonClaims\.\d+$/, /^guidanceSlice\.authorityRefs\.\d+\.\w+$/,
  /^(escalations|stopConditions)\.\d+$/, /^nextCommands\.\d+\.(command|why|browserMode)$/, /^omitted\.\d+\.(command|missingInputKind|reason)$/,
  /^requiredInputs\.\d+\.(kind|reason)$/, /^requiredInputs\.\d+\.oneOf\.\d+$/, /^requiredInputs\.\d+\.oneOfBundles\.\d+\.\d+$/,
  /^observedReports\.\d+\.(kind|state)$/, /^diagnostics\.\d+\.key$/, /^diagnostics\.[0-2]\.value$/];
const briefEnums = [/^(state|routeFamily|packetKind)$/, /^blockers\.\d+\.(kind|state|subject)$/, /^contextRefs\.\d+\.role$/,
  /^detailAccess\.(commandRef|launcherProfile)$/, /^nextAction\.(commandRef|owner|argvState)$/, /^omissionSummary\.detailClasses\.\d+$/,
  /^boundaryPolicyRefs\.\d+$/, /^detailAccess\.outputArgs\.full\.\d+$/];
const fullEnums = [/^sourceReport\.(reportKind|state|nonClaim)$/, /^contextRefs\.\d+\.role$/, /^commands\.\d+\.(proofkitRoute|owner|nonClaim)$/,
  /^actionPlan\.\d+\.phase$/, /^costContract\.stopReason$/, /^bounds\.fanout$/, /^routeQuestions\.\d+\.(question|nonClaim)$/,
  /^clarificationQuestions\.\d+\.expectedAnswerKind$/];

test('agent-route output carriers refuse structural drift in every observed variant', () => {
  const serve = routeInput({goal: 'render_human_view', availableInputs: everyInput(), browserMode: 'serve_local_view', openBrowser: true,
    nonClaims: ['Caller claim.'], knownChangedPaths: ['a.go'], observedReports: [{kind: 'evidence', ref: 'reports/a.json', state: 'passed'}]});
  const blocked = routeInput({goal: 'inspect_requirement_context', availableInputs: [],
    observedReports: Array.from({length: 14}, (_, index) => ({kind: 'evidence', ref: `reports/${String(index).padStart(2, '0')}.json`, state: 'warning'}))});
  const diagnostics = routeInput({goal: 'plan_selective_checks', availableInputs: [], knownChangedPaths: ['a.go']});
  const verify = routeInput({goal: 'verify_typescript_public_api', availableInputs: [{kind: 'typescript_public_api_manifest', ref: 'api.json'}]});
  const cases = [
    [ROUTED, routed(serve, [], ROUTED, 0), 'serve-report'], [ROUTED, routed(blocked, [], ROUTED, 1), 'blocked-report'],
    [ROUTED, routed(diagnostics, [], ROUTED, 1), 'diagnostic-report'], [ROUTED, routed(verify, [], ROUTED, 1), 'missing-arg-report'],
    [UNKNOWN, routed(routeInput({goal: 'unknown', nonClaims: ['Caller claim.']}), [], UNKNOWN, 1), 'unknown-report'],
    [BRIEF, routed(serve, ['--agent-envelope'], BRIEF, 0), 'serve-brief'], [BRIEF, routed(blocked, ['--agent-envelope'], BRIEF, 1), 'blocked-brief'],
    [BRIEF, routed(routeInput({goal: 'unknown'}), ['--agent-envelope'], BRIEF, 1), 'unknown-brief'],
    [FULL, routed(serve, ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 0), 'serve-full'],
    [FULL, routed(blocked, ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 1), 'blocked-full'],
    [FULL, routed(routeInput({goal: 'unknown'}), ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 1), 'unknown-full'],
    [REPAIR, routed('{', ['--agent-envelope'], REPAIR, 1), 'repair'],
  ];
  for (const [index, output, label] of cases) {
    const options = {
      [ROUTED]: {enums: routeReportEnums}, [UNKNOWN]: {enums: routeReportEnums},
      [BRIEF]: {enums: briefEnums, nullable: [/^nextAction$/]},
      [FULL]: {enums: fullEnums, optional: kernelBounds, nullable: kernelNulls, emptyText: [/^omitted\.\d+\.subject$/]},
      [REPAIR]: {optional: kernelBounds, nullable: kernelNulls},
    }[index];
    carrierPredicates(ROUTE_OUT, index, output, options, label);
  }
  const full = cases[9][1];
  assert.equal(full.blockedPreconditions.length, 12); assert.equal(full.bounds.truncated, true);
  const brief = cases[6][1];
  assert.equal(brief.blockers.length, 4); assert.equal(brief.omissionSummary.omittedBlockerCount, 11);
  valid(ROUTE_OUT, BRIEF, {...brief, blockers: [...brief.blockers, brief.blockers[0]]}, false, 'blocker-limit+1');
  const report = cases[0][1];
  valid(ROUTE_OUT, ROUTED, {...report, nonClaims: report.nonClaims.filter(claim => claim !== builtinRouteClaims[0])}, false, 'builtin-claim');
  valid(ROUTE_OUT, ROUTED, {...report, nonClaims: [...report.nonClaims, report.nonClaims[0]]}, false, 'duplicate-claim');
  valid(ROUTE_OUT, ROUTED, {...report, callerNonClaims: ['\u00e9'.repeat(241)]}, false, 'caller-claim-runes');
  valid(ROUTE_OUT, ROUTED, {...report, callerNonClaims: ['\u00e9'.repeat(240)]}, true, 'caller-claim-runes-limit');
  valid(ROUTE_OUT, ROUTED, {...report, nextCommands: Array.from({length: 11}, () => report.nextCommands[0])}, false, 'next-command-limit+1');
  valid(ROUTE_OUT, ROUTED, {...report, nextCommands: Array.from({length: 10}, () => report.nextCommands[0])}, true, 'next-command-limit');
  const browser = report.nextCommands.find(command => command.command === 'requirement-browser-server');
  const plain = report.nextCommands.find(command => command.command !== 'requirement-browser-server');
  valid(ROUTE_OUT, ROUTED, {...report, nextCommands: [{...plain, browserMode: 'view_plan'}]}, false, 'browser-mode-on-plain-command');
  valid(ROUTE_OUT, ROUTED, {...report, nextCommands: [removed(browser, ['browserMode'])]}, false, 'browser-command-without-mode');
  const diag = cases[2][1];
  assert.deepEqual(diag.diagnostics.map(item => item.key), ['goal', 'mode', 'state', 'missingRequiredInputCount']);
  const swapped = structuredClone(cases[1][1]);
  assert.deepEqual(swapped.diagnostics.map(item => item.key), ['goal', 'mode', 'state', 'missingRequiredInputCount', 'blockingObservedReportCount']);
  swapped.diagnostics = [swapped.diagnostics[0], swapped.diagnostics[1], swapped.diagnostics[2], swapped.diagnostics[4], swapped.diagnostics[3]];
  valid(ROUTE_OUT, ROUTED, swapped, false, 'diagnostic-order');
  valid(ROUTE_OUT, ROUTED, replaced(diag, ['diagnostics', 3, 'value'], 0), false, 'zero-missing-count');
  const unknown = cases[4][1];
  valid(ROUTE_OUT, UNKNOWN, replaced(unknown, ['summary', 'availableCommandCount'], 1), false, 'unknown-command-count');
  valid(ROUTE_OUT, ROUTED, replaced(report, ['summary', 'goal'], 'unknown'), false, 'known-report-unknown-goal');
  const full0 = cases[8][1];
  for (const id of ['consumer.route.fixture.agent-envelope', '<redacted-diagnostic-value>']) valid(ROUTE_OUT, FULL, {...full0, envelopeId: id}, true, 'envelope-id');
  for (const id of ['consumer.route.fixture.agent-brief', 'r'.repeat(97) + '.agent-envelope']) valid(ROUTE_OUT, FULL, {...full0, envelopeId: id}, false, 'envelope-id');
});

test('agent-route brief compaction boundary and redaction-degraded envelopes stay inside their variants', () => {
  const sized = length => routeInput({availableInputs: [{kind: 'requirement_source', ref: 'docs/' + 'a'.repeat(length) + '.json'}]});
  // The packet bound applies to the canonical pretty bytes the CLI emits.
  const [probe, probeBytes] = routedResult(sized(100), ['--agent-envelope'], BRIEF, 0);
  assert.equal(probe.nextAction.argvState, 'inline');
  const exact = 100 + 3072 - Buffer.byteLength(probeBytes);
  const [atLimit, limitBytes] = routedResult(sized(exact), ['--agent-envelope'], BRIEF, 0);
  assert.equal(atLimit.nextAction.argvState, 'inline'); assert.equal(Buffer.byteLength(limitBytes), 3072);
  assert(Buffer.byteLength(stableJSONStringify(atLimit)) < 3072, 'compact bytes are not the bounded carrier');
  const compacted = routed(sized(exact + 1), ['--agent-envelope'], BRIEF, 0);
  assert.equal(compacted.nextAction.argvState, 'detail_required'); assert(!('argv' in compacted.nextAction));
  valid(ROUTE_OUT, BRIEF, replaced(compacted, ['nextAction', 'argv'], atLimit.nextAction.argv), false, 'deferred-with-argv');
  valid(ROUTE_OUT, BRIEF, removed(atLimit, ['nextAction', 'argv']), false, 'inline-without-argv');
  // Secret-shaped suffixes and display-unsafe refs degrade only inside the envelope.
  const shaped = routeInput({routeId: 'eyJa.b', availableInputs: [{kind: 'requirement_source', ref: 'source.json'}, {kind: 'requirement_source_transition', ref: 'transition.json'}]});
  const degraded = routed(shaped, ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 0);
  assert.equal(degraded.envelopeId, '<redacted-diagnostic-value>');
  assert.deepEqual(degraded.omitted.map(item => item.omittedKind), ['unsafeLocalIdentity']);
  assert.equal(routed(shaped, ['--agent-envelope'], BRIEF, 0).packetId, 'eyJa.b.agent-brief');
  // Route omission records keep their command vocabulary beside kernel records.
  const omittedRoute = routed(routeInput(), ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 0);
  const commandOmission = omittedRoute.omitted.findIndex(item => item.subject === 'requirement-source-transition');
  assert.notEqual(commandOmission, -1);
  for (const field of ['reason', 'escalation', 'subject']) {
    valid(ROUTE_OUT, FULL, replaced(omittedRoute, ['omitted', commandOmission, field], 'foreign-fixture-value'), false, 'route-omission/' + field);
  }
  valid(ROUTE_OUT, FULL, replaced(omittedRoute, ['omitted', commandOmission, 'omittedCount'], 2), false, 'route-omission/count');
  const unsafe = routeInput({availableInputs: [{kind: 'requirement_source', ref: 'docs/\u202ereport.json'}]});
  const display = routed(unsafe, ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 0);
  assert(display.commands[0].argv.includes('<redacted-diagnostic-value>'));
  const long = routed(sized(5000), ['--agent-envelope', '--agent-envelope-mode', 'full'], FULL, 0);
  assert(long.contextRefs.some(ref => ref.path.endsWith('...<truncated-diagnostic>')));
});

// ------------------------------------------------------- change-workflow-plan
const digest = digit => 'sha256:' + digit.repeat(64);
const ref = (refId, refKind, subjectDigest, dependencyRefIds = []) => ({artifactPath: 'evidence/' + refId + '.json', dependencyRefIds, refId, refKind, subjectDigest});
function flowInput(stage, state, {authority = true, witness = false, extra = []} = {}) {
  const contextRefs = [ref('ctx.artifact', 'artifact', digest('2')), ref('ctx.authority', 'authority', digest('1')), ref('ctx.finding', 'finding', digest('3')),
    ...(witness ? [ref('ctx.witness', 'witness', digest('4'))] : []), ...extra];
  const input = {schemaVersion: 1, completedStageIds: stages.slice(0, stage), contextRefs, governingAuthorityRefId: authority ? 'ctx.authority' : null,
    requiredContextRefIds: witness ? ['ctx.witness'] : [], checkpoint: null};
  if (stage === stages.length) return input;
  input.checkpoint = {state};
  if (state !== 'not_started' || stage > 0) Object.assign(input.checkpoint, {subjectDigest: digest('2'), subjectRefId: 'ctx.artifact'});
  if (state === 'review_findings' || state === 'review_passed') input.checkpoint.assessmentSubjectDigest = digest('2');
  if (state === 'review_findings') input.checkpoint.findingRefs = ['ctx.finding'];
  return input;
}
function plan(input, flags = []) {
  return run(['change', 'plan', '--input', '-', ...flags], input);
}
function planned(input, flags = []) {
  if (typeof input !== 'string') valid(FLOW_IN, 0, input, true, 'fixture input');
  const value = emitted(plan(input, flags), 0);
  const index = flags.includes('--agent-envelope') ? ENVELOPE : value.outputKind === 'workflow_complete' ? COMPLETE : value.successorStateDelta ? ACCEPT : NEXT;
  selects(FLOW_OUT, index, value, flags.join(' ') + ' ' + JSON.stringify(input).slice(0, 80));
  return [index, value];
}

test('change-workflow-plan selects JSON variants for every relation row and leaves text unclaimed', () => {
  const actions = {not_started: ['author', 'author', 'author', 'implement', 'verify', 'open_pull_request', 'closeout'],
    ready_for_review: Array(7).fill('review'), review_findings: Array(7).fill('repair'), review_passed: Array(7).fill('accept_stage')};
  for (let stage = 0; stage < stages.length; stage++) for (const state of checkpointStates) {
    const [index, value] = planned(flowInput(stage, state));
    assert.equal(index, state === 'review_passed' ? ACCEPT : NEXT);
    assert.deepEqual(keysOf(value), [...planKeys, ...activeKeys, ...(index === ACCEPT ? ['successorStateDelta'] : [])].sort());
    assert.deepEqual(keysOf(value.prompt), promptKeys);
    assert.equal(value.action, actions[state][stage]); assert.equal(value.activeStageId, stages[stage]);
    const [, envelope] = planned(flowInput(stage, state), ['--agent-envelope']);
    assert.deepEqual(keysOf(envelope), envelopeKeys); assert.equal(envelope.actionPlan.length, stage === 4 && state === 'not_started' ? 0 : 1);
    for (const flags of [['--format', 'text'], ['--format', 'text', '--color', 'never']]) {
      const text = plan(flowInput(stage, state), flags);
      assert.equal(text.status, 0); assert.equal(text.stderr, '');
      assert.throws(() => JSON.parse(text.stdout), SyntaxError, 'text presentation must stay outside the JSON variants');
    }
  }
  const [terminal, complete] = planned(flowInput(stages.length));
  assert.equal(terminal, COMPLETE); assert.deepEqual(keysOf(complete), planKeys);
  assert.equal(planned(flowInput(stages.length), ['--agent-envelope'])[1].actionPlan[0].phase, 'terminal');
  const [, blocked] = planned(flowInput(0, 'not_started', {authority: false}), ['--agent-envelope']);
  assert.deepEqual(blocked.actionPlan, []); assert.equal(blocked.blockedPreconditions.length, 1);
  const [, witnessed] = planned(flowInput(4, 'not_started', {witness: true}), ['--agent-envelope']);
  assert.equal(witnessed.actionPlan.length, 1);
  refused(plan(flowInput(0, 'not_started'), ['--agent-envelope', '--format', 'text']));
  refused(run(['change-workflow-plan', '--input', '-'], flowInput(0, 'not_started')));
});

test('change-workflow-plan successor deltas chain the public CLI from the first stage to completion', () => {
  let snapshot = flowInput(0, 'not_started', {witness: true}), steps = 0;
  for (;;) {
    const [index, value] = planned(snapshot);
    planned(snapshot, ['--agent-envelope']);
    if (index === COMPLETE) break;
    assert(++steps < 64, 'workflow chain did not terminate');
    snapshot = structuredClone(snapshot);
    if (index === ACCEPT) {
      snapshot.completedStageIds = value.successorStateDelta.completedStageIds;
      snapshot.checkpoint = value.successorStateDelta.checkpoint;
      continue;
    }
    const subject = {subjectDigest: digest('2'), subjectRefId: 'ctx.artifact'};
    snapshot.checkpoint = value.action === 'review' ? {state: 'review_passed', ...subject, assessmentSubjectDigest: digest('2')} : {state: 'ready_for_review', ...subject};
  }
  assert.equal(steps, stages.length * 3);
});

test('change-workflow-plan input clauses agree with native admission at the public CLI', () => {
  const base = flowInput(1, 'review_findings', {witness: true});
  const accepted = (input, label) => {
    valid(FLOW_IN, 0, input, true, label);
    const result = plan(input); assert.equal(result.stderr, '', label + ': ' + result.stderr); assert.equal(result.status, 0);
  };
  const rejected = (input, label) => {valid(FLOW_IN, 0, input, false, label); refused(plan(input)); refused(plan(input, ['--agent-envelope']));};
  const nativeOnly = (input, label) => {valid(FLOW_IN, 0, input, true, label); refused(plan(input));};
  accepted(base, 'base');
  for (const key of flowInputKeys) rejected(removed(base, [key]), 'required/' + key);
  rejected({...base, foreign: true}, 'root-closure');
  for (const key of ['artifactPath', 'dependencyRefIds', 'refId', 'refKind', 'subjectDigest']) rejected(removed(base, ['contextRefs', 0, key]), 'context/' + key);
  rejected(replaced(base, ['contextRefs', 0, 'foreign'], true), 'context-closure');
  rejected(replaced(base, ['checkpoint', 'foreign'], true), 'checkpoint-closure');
  for (const [path, wrong] of [[['schemaVersion'], [2, '1', 1.5, null]], [['completedStageIds'], ['architecture', {}, null]],
    [['completedStageIds', 0], ['design', 'foreign', 1]], [['contextRefs'], [{}, null]], [['contextRefs', 0, 'refKind'], ['foreign', null]],
    [['contextRefs', 0, 'refId'], ['', '1ctx', 'ctx..a', 'a'.repeat(257), 1]], [['contextRefs', 0, 'subjectDigest'], ['', digest('A'), 'sha512:' + '2'.repeat(64), digest('2') + '0']],
    [['contextRefs', 0, 'artifactPath'], ['', 7, null]], [['contextRefs', 0, 'dependencyRefIds'], [{}, ['ctx.authority', 'ctx.authority']]],
    [['governingAuthorityRefId'], [false, '', 'not an id']], [['requiredContextRefIds'], [{}, ['ctx.witness', 'ctx.witness']]],
    [['checkpoint'], [[], 'review_findings']], [['checkpoint', 'state'], ['foreign', null]], [['checkpoint', 'findingRefs'], [[], 'ctx.finding', ['ctx.finding', 'ctx.finding']]],
  ]) for (const value of wrong) rejected(replaced(base, path, value), path.join('.') + '=' + JSON.stringify(value));
  // Stage-dependent checkpoint variants and the terminal null checkpoint.
  rejected(removed(flowInput(1, 'not_started'), ['checkpoint', 'subjectDigest']), 'incoming-subject');
  rejected({...flowInput(0, 'not_started'), checkpoint: {state: 'not_started', subjectDigest: digest('2'), subjectRefId: 'ctx.artifact'}}, 'first-stage-subject');
  rejected(removed(flowInput(2, 'review_passed'), ['checkpoint', 'assessmentSubjectDigest']), 'assessment');
  rejected(replaced(flowInput(2, 'review_passed'), ['checkpoint', 'findingRefs'], ['ctx.finding']), 'passed-with-findings');
  rejected({...flowInput(stages.length), checkpoint: {state: 'not_started'}}, 'terminal-checkpoint');
  rejected({...flowInput(3, 'not_started'), checkpoint: null}, 'incomplete-null');
  rejected({...base, completedStageIds: ['design']}, 'non-prefix');
  rejected({...base, completedStageIds: [...stages, 'closeout']}, 'surplus-stage');
  accepted({...base, checkpoint: {...base.checkpoint, subjectDigest: ' \t' + digest('2').replace(':', ':\u00a0') + '\u3000'}}, 'whitespace-digest');
  // Exact limits.
  const many = (count, prefix) => Array.from({length: count}, (_, index) => `${prefix}${String(index).padStart(3, '0')}`);
  const findingRefs = many(12, 'ctx.finding');
  const findings = {...base, contextRefs: [...base.contextRefs.slice(0, 2), ...findingRefs.map(id => ref(id, 'finding', digest('3'))), base.contextRefs[3]],
    checkpoint: {...base.checkpoint, findingRefs}};
  accepted(findings, 'finding-limit');
  rejected({...findings, checkpoint: {...findings.checkpoint, findingRefs: [...findingRefs, 'ctx.finding999']}}, 'finding-limit+1');
  const dependencies = many(8, 'ctx.dep');
  const deep = {...base, contextRefs: [ref('ctx.artifact', 'artifact', digest('2'), dependencies), ...base.contextRefs.slice(1),
    ...dependencies.map(id => ref(id, 'artifact', digest('5')))].sort((a, b) => a.refId < b.refId ? -1 : 1)};
  accepted(deep, 'dependency-limit');
  rejected(replaced(deep, ['contextRefs', 0, 'dependencyRefIds'], [...dependencies, 'ctx.dep999']), 'dependency-limit+1');
  const candidates = count => ({...base, contextRefs: [...base.contextRefs, ...many(count - 4, 'ctx.zz').map(id => ref(id, 'artifact', digest('6')))]});
  accepted(candidates(48), 'candidate-limit');
  rejected(candidates(49), 'candidate-limit+1');
  const required = count => ({...base, contextRefs: [...base.contextRefs, ...many(count - 1, 'ctx.zz').map(id => ref(id, 'artifact', digest('6')))],
    requiredContextRefIds: [...base.requiredContextRefIds, ...many(count - 1, 'ctx.zz')].sort()});
  accepted(required(12), 'required-limit');
  rejected(required(13), 'required-limit+1');
  const id256 = 'c' + 'x'.repeat(255);
  accepted({...base, contextRefs: [...base.contextRefs, ref(id256, 'artifact', digest('6'))]}, 'ref-id-limit');
  rejected({...base, contextRefs: [...base.contextRefs, ref(id256 + 'x', 'artifact', digest('6'))]}, 'ref-id-limit+1');
  accepted(replaced(base, ['contextRefs', 0, 'artifactPath'], 'a'.repeat(384)), 'path-limit');
  rejected(replaced(base, ['contextRefs', 0, 'artifactPath'], 'a'.repeat(385)), 'path-limit+1');
  nativeOnly(replaced(base, ['contextRefs', 0, 'artifactPath'], '\u00e9'.repeat(384)), 'path-byte-limit');
  nativeOnly(replaced(base, ['contextRefs', 0, 'artifactPath'], '../outside.json'), 'escaping-path');
  nativeOnly({...base, contextRefs: [base.contextRefs[1], base.contextRefs[0], ...base.contextRefs.slice(2)]}, 'unsorted-context');
  nativeOnly({...base, requiredContextRefIds: ['ctx.unknown']}, 'unresolved-required');
  nativeOnly({...base, governingAuthorityRefId: 'ctx.artifact'}, 'authority-kind');
  nativeOnly(replaced(base, ['checkpoint', 'assessmentSubjectDigest'], digest('9')), 'assessment-mismatch');
  nativeOnly({...base, requiredContextRefIds: ['ctx.20240101']}, 'timestamp-id');
});

const flowEnums = [/^(authority|outputKind|reportId|reportKind|workflowProfileId|action|activeStageId|checkpointState)$/, /^completedStageIds\.\d+$/,
  /^nonClaims\.\d+$/, /^retainedContextRefs\.\d+\.refKind$/, /^prompt\.(candidateAction|expectedNextCheckpoint|nonClaim|stopCondition|uncertainty)$/,
  /^prompt\.(coordinates|observedFact)\.(activeStageId|checkpointState)$/, /^prompt\.observedFact\.completedStageIds\.\d+$/,
  /^prompt\.proofCommandOrMissingWitness\.state$/, /^successorStateDelta\.(completedStageIds\.\d+|checkpoint\.state)$/];
const flowEnvelopeEnums = [/^envelopeId$/, /^nonClaims\.\d+$/, /^contextRefs\.\d+\.(kind|nonClaim|owner|purpose|role)$/,
  /^actionPlan\.\d+\.(instruction|outputKind|phase|rationale|stepId|nonClaims\.\d+)$/, /^actionPlan\.\d+\.successorStateDelta\.(completedStageIds\.\d+|checkpoint\.state)$/,
  /^(blockedPreconditions|clarificationQuestions)\.\d+\.(description|nonClaim|owner|preconditionId|questionId|askWhen|expectedAnswerKind|question)$/,
  /^routeQuestions\.\d+\.(nonClaim|question|questionId)$/, /^bounds\.(fanout|escalation|nonClaim)$/, /^omitted\.\d+\.(kind|nonClaim|omissionId|reason)$/,
  /^sourceReport\.(reportId|reportKind|state)$/, /^costContract\.stopReason$/];

test('change-workflow-plan output carriers refuse structural drift in every variant', () => {
  const omitted = flowInput(3, 'review_findings', {witness: true, extra: [ref('ctx.zz.unrequired', 'artifact', digest('7'))]});
  for (const [input, flags, label] of [[omitted, [], 'findings'], [flowInput(2, 'review_passed'), [], 'accept'], [flowInput(6, 'review_passed'), [], 'final-accept'],
    [flowInput(0, 'not_started'), [], 'first'], [flowInput(stages.length), [], 'complete'], [omitted, ['--agent-envelope'], 'envelope-findings'],
    [flowInput(2, 'review_passed'), ['--agent-envelope'], 'envelope-accept'], [flowInput(4, 'not_started', {authority: false}), ['--agent-envelope'], 'envelope-blocked'],
    [flowInput(stages.length), ['--agent-envelope'], 'envelope-terminal']]) {
    const [index, value] = planned(input, flags);
    carrierPredicates(FLOW_OUT, index, value, index === ENVELOPE ? {
      enums: flowEnvelopeEnums, optional: [/^bounds\.truncated$/, /^actionPlan\.\d+\.(successorStateDelta|subjectDigest|subjectRefId)$/],
      nullable: [...kernelNulls.filter(pattern => !String(pattern).includes('stableHash')), /^actionPlan\.\d+\.successorStateDelta\.checkpoint$/],
    } : {enums: flowEnums, optional: [/^prompt\.coordinates\.(governingAuthorityRefId|findingRefs)$/],
      nullable: [/^prompt\.observedFact\.governingAuthorityRefId$/, /^successorStateDelta\.checkpoint$/]}, label);
  }
  const [, findings] = planned(omitted);
  for (const field of ['subjectDigest', 'subjectRefId']) valid(FLOW_OUT, NEXT, removed(findings, ['prompt', 'coordinates', field]), false, 'subject-pair/' + field);
  valid(FLOW_OUT, NEXT, removed(removed(removed(findings, ['prompt', 'coordinates', 'subjectDigest']), ['prompt', 'coordinates', 'subjectRefId']),
    ['prompt', 'coordinates', 'findingRefs']), true, 'no-subject');
  valid(FLOW_OUT, NEXT, {...findings, completedStageIds: ['design']}, false, 'non-prefix');
  valid(FLOW_OUT, NEXT, {...findings, retainedContextRefIds: ['ctx.artifact', 'ctx.artifact']}, false, 'duplicate-retained');
  valid(FLOW_OUT, NEXT, {...findings, action: 'accept_stage'}, false, 'successor-action-without-delta');
  const [, accept] = planned(flowInput(2, 'review_passed'));
  valid(FLOW_OUT, ACCEPT, replaced(accept, ['successorStateDelta', 'completedStageIds'], []), false, 'empty-successor-prefix');
  valid(FLOW_OUT, ACCEPT, removed(accept, ['successorStateDelta']), false, 'missing-delta');
  const [, done] = planned(flowInput(stages.length));
  valid(FLOW_OUT, COMPLETE, {...done, completedStageIds: stages.slice(0, 6)}, false, 'incomplete-terminal');
  const [, envelope] = planned(omitted, ['--agent-envelope']);
  valid(FLOW_OUT, ENVELOPE, {...envelope, actionPlan: [envelope.actionPlan[0], envelope.actionPlan[0]]}, false, 'action-limit+1');
  valid(FLOW_OUT, ENVELOPE, {...envelope, omitted: [envelope.omitted[0], envelope.omitted[0]]}, false, 'omission-limit+1');
  valid(FLOW_OUT, ENVELOPE, {...envelope, nonClaims: envelope.nonClaims.slice(1)}, false, 'merged-claims');
  valid(FLOW_OUT, ENVELOPE, {...envelope, routeQuestions: envelope.routeQuestions.slice(1)}, false, 'route-questions');
  const [, blocked] = planned(flowInput(4, 'not_started', {authority: false}), ['--agent-envelope']);
  assert.equal(blocked.blockedPreconditions.length, 2);
  valid(FLOW_OUT, ENVELOPE, {...blocked, blockedPreconditions: [...blocked.blockedPreconditions, ...blocked.blockedPreconditions]}, false, 'blocker-limit+1');
});

// -------------------------------------------------- native-evidence-guidance
test('native-evidence-guidance binds the fixed template in JSON mode and leaves text unclaimed', () => {
  const guidance = emitted(run(['native-evidence-guidance']), 0);
  selects(GUIDE, 0, guidance);
  assert.deepEqual(keysOf(guidance), ['guidanceId', 'nonClaims', 'schemaVersion', 'slots']);
  assert.deepEqual(guidance.slots.map(slot => slot.slotId), slotIds);
  assert.deepEqual(guidance.slots.map(slot => slot.order), slotIds.map((_, index) => index + 1));
  for (const slot of guidance.slots) {
    assert.deepEqual(keysOf(slot), ['applicabilityClass', 'completionCriterion', 'order', 'question', 'requiredConsumerDecision', 'slotId']);
    assert(applicability.includes(slot.applicabilityClass));
  }
  assert.equal(emitted(run(['native-evidence-guidance', '--format', 'json']), 0).guidanceId, guidance.guidanceId);
  for (const flags of [['--format', 'text'], ['--format', 'text', '--color', 'never']]) {
    const text = run(['native-evidence-guidance', ...flags]);
    assert.equal(text.status, 0); assert.equal(text.stderr, '');
    assert.throws(() => JSON.parse(text.stdout), SyntaxError);
    for (const id of slotIds) assert(text.stdout.includes(id + ':'));
  }
  for (const flags of [['--input', '-'], ['--agent-envelope'], ['--color', 'never'], ['--format', 'yaml']]) refused(run(['native-evidence-guidance', ...flags]));
  carrierPredicates(GUIDE, 0, guidance, {enums: [/^(guidanceId)$/, /^nonClaims\.\d+$/, /^slots\.\d+\.\w+$/]}, 'guidance');
  const swapped = structuredClone(guidance); [swapped.slots[0], swapped.slots[1]] = [swapped.slots[1], swapped.slots[0]];
  valid(GUIDE, 0, swapped, false, 'slot-order');
  valid(GUIDE, 0, {...guidance, slots: guidance.slots.slice(1)}, false, 'missing-slot');
  valid(GUIDE, 0, {...guidance, slots: [...guidance.slots, guidance.slots[0]]}, false, 'surplus-slot');
  for (const member of applicability.filter(value => value !== guidance.slots[0].applicabilityClass)) {
    valid(GUIDE, 0, replaced(guidance, ['slots', 0, 'applicabilityClass'], member), false, 'neighbor-applicability');
  }
  valid(GUIDE, 0, replaced(guidance, ['slots', 0, 'question'], guidance.slots[0].question + ' '), false, 'slot-text');
  valid(GUIDE, 0, {...guidance, schemaVersion: 2}, false, 'wire-version');
});

// Each refinement is load-bearing: weakening it admits a native refusal, and
// tightening an admission-trimmed domain refuses a value the CLI accepts.
test('isolated schema controls falsify weakened refinements and over-tightened native domains', () => {
  const control = (key, index, mutate, value, expected, label) => {
    const schema = structuredClone(owners.get(key).variants[index].schema); mutate(schema);
    assert.equal(compile(schema)(value), expected, label);
  };
  const open = routeInput({browserMode: 'view_plan', openBrowser: true});
  valid(ROUTE_IN, 0, open, false); refused(route(open));
  control(ROUTE_IN, 0, schema => {delete schema.if; delete schema.then;}, open, true, 'openBrowser relation control');
  const duplicate = routeInput({knownChangedPaths: ['a.go', 'a.go']});
  control(ROUTE_IN, 0, schema => {delete schema.properties.knownChangedPaths.anyOf[1].uniqueItems;}, duplicate, true, 'duplicate path control');
  const longClaim = routeInput({nonClaims: ['\u00e9'.repeat(241)]});
  control(ROUTE_IN, 0, schema => {delete schema.properties.nonClaims.anyOf[1].items.maxLength;}, longClaim, true, 'claim rune control');
  const trimmed = routeInput({availableInputs: [{kind: 'requirement_source', ref: ' docs/requirements.json '}]});
  assert.equal(route(trimmed).status, 0);
  control(ROUTE_IN, 0, schema => {schema.properties.availableInputs.anyOf[1].items.properties.ref = {type: 'string', pattern: '^\\S(?:.*\\S)?$'};},
    trimmed, false, 'trimmed ref domain control');
  const firstSubject = {...flowInput(0, 'not_started'), checkpoint: {state: 'not_started', subjectDigest: digest('2'), subjectRefId: 'ctx.artifact'}};
  control(FLOW_IN, 0, schema => {delete schema.allOf;}, firstSubject, true, 'stage checkpoint control');
  control(FLOW_IN, 0, schema => {delete schema.properties.completedStageIds.prefixItems; schema.properties.completedStageIds.items = {type: 'string'};},
    {...flowInput(1, 'not_started'), completedStageIds: ['closeout']}, true, 'stage prefix control');
  const spaced = {...flowInput(1, 'ready_for_review'), checkpoint: {...flowInput(1, 'ready_for_review').checkpoint, subjectDigest: ' ' + digest('2')}};
  assert.equal(plan(spaced).status, 0);
  control(FLOW_IN, 0, schema => {schema.properties.checkpoint.anyOf[1].properties.subjectDigest = {type: 'string', pattern: '^sha256:[0-9a-f]{64}$'};},
    spaced, false, 'trimmed digest domain control');
  const brief = routed(routeInput({availableInputs: [], observedReports: Array.from({length: 6}, (_, index) => ({kind: 'evidence', ref: `r/${index}.json`, state: 'failed'}))}),
    ['--agent-envelope'], BRIEF, 1);
  const tooMany = {...brief, blockers: [...brief.blockers, brief.blockers[0]]};
  control(ROUTE_OUT, BRIEF, schema => {delete schema.properties.blockers.maxItems;}, tooMany, true, 'blocker bound control');
  const report = routed(routeInput(), [], ROUTED, 0);
  const missingClaim = {...report, nonClaims: report.nonClaims.slice(1)};
  control(ROUTE_OUT, ROUTED, schema => {delete schema.properties.nonClaims.allOf; schema.properties.nonClaims.minItems = 1;}, missingClaim, true, 'builtin claim control');
  const guidance = emitted(run(['native-evidence-guidance']), 0);
  const swapped = structuredClone(guidance); [swapped.slots[0], swapped.slots[1]] = [swapped.slots[1], swapped.slots[0]];
  control(GUIDE, 0, schema => {schema.properties.slots = {type: 'array', minItems: 22, maxItems: 22, items: {type: 'object'}};}, swapped, true, 'slot order control');
  const [, done] = planned(flowInput(stages.length));
  control(FLOW_OUT, COMPLETE, schema => {schema.properties.completedStageIds.minItems = 0;}, {...done, completedStageIds: stages.slice(0, 6)}, true, 'terminal prefix control');
});
