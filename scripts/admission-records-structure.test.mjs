import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport} from './cli-process.mjs';
import {expandSharedDefinitions} from './schema-definitions.mjs';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_ADMISSION_RECORDS_CONTRACT || new URL('proofkit/cli-contract.v2.json', root), 'utf8'));
const commands = ['capability-map-admission', 'deployment-evidence-admission', 'repo-profile-admission', 'spec-proof-bundle-admission'];

// Independently authored inventories; they are compared with, never derived from, the schemas under test.
const reportKeys = ['diagnostics', 'nonClaims', 'reportId', 'reportKind', 'ruleResults', 'schemaVersion', 'state', 'summary'];
const rootInventory = {
  'capability-map-admission': {
    required: ['authority', 'capabilities', 'mapId', 'proofScope', 'repository', 'schemaVersion', 'trustMode'],
    optional: ['nonClaims', 'requiredVerification', 'scenarioAnchors'],
  },
  'deployment-evidence-admission': {required: ['admissionId', 'evidence', 'nonClaims', 'policy', 'schemaVersion'], optional: ['rawOperatorEvidence']},
  'repo-profile-admission': {required: ['facts', 'policy', 'profile'], optional: ['schemaVersion']},
  'spec-proof-bundle-admission': {
    required: ['bundleId', 'mergeRequiredReceiptIds', 'nonClaims', 'requirementBindings', 'schemaVersion', 'witnessPlan'],
    optional: ['receiptAdmission', 'receiptProducerAdmission'],
  },
};
const summaryKeys = {
  'capability-map-admission': ['agentActionCount', 'candidateProofBindingSeedCount', 'candidateRequirementSeedCount', 'capabilityCount', 'failureCount',
    'mapId', 'repositoryId', 'scenarioAnchorCount', 'scenarioShapeCount', 'scopeId', 'trustMode', 'verificationCommandCount'],
  'deployment-evidence-admission': ['blockedReasonCount', 'endpointCount', 'evidenceId', 'factCount', 'failureCount', 'requiredFactIdCount', 'requiredFactKindCount'],
  'repo-profile-admission': ['commandMatcherCount', 'distinctWitnessCommandCount', 'environmentClassCount', 'generatedArtifactCount'],
  'spec-proof-bundle-admission': ['bindingCommandCount', 'bindingCount', 'failureCount', 'mergeRequiredReceiptCount', 'receiptCount',
    'receiptProducerAttached', 'requirementCount', 'witnessCommandCount'],
};
const reportKinds = {
  'capability-map-admission': 'proofkit.capability-map-admission', 'deployment-evidence-admission': 'proofkit.deployment-evidence-admission',
  'repo-profile-admission': 'proofkit.repo-profile-structural', 'spec-proof-bundle-admission': 'proofkit.spec-proof-bundle-admission',
};
// Trust mode x state, the three report states with failures split on collected blockers, and passed/failed.
const branchCounts = {'capability-map-admission': 4, 'deployment-evidence-admission': 4, 'repo-profile-admission': 2, 'spec-proof-bundle-admission': 2};
const builtinClaims = {
  'capability-map-admission': [
    'Capability map admission does not scan repositories, read code, write files, execute witnesses, or approve merge.',
    'Capability map outputs are candidate-only until the consuming repository materializes and admits requirement sources, proof bindings, and test inventories.',
  ],
  'deployment-evidence-admission': ['Deployment evidence admission reports do not read files or repositories.'],
  'repo-profile-admission': ['Repo-profile structural admission does not read repository state.'],
  'spec-proof-bundle-admission': ['Spec proof bundle admission does not execute native witnesses.'],
};

const ajv = () => new Ajv2020({strict: false, validateFormats: false});
const definitionOf = id => contract.contractDefinitions.find(row => row.definitionId === id);
const checks = new Map(commands.flatMap(command => ['input', 'output'].map(direction => {
  const record = contract.commands.find(row => row.command === command)[direction + 'Contract'];
  const definition = definitionOf(record.rootDefinitionRef);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema', command + '/' + direction);
  const [variant] = definition.fieldTree.variants;
  // Ajv validates the published schema; navigation and standalone branches use
  // its expansion, because shared definitions resolve only at the variant root.
  const schema = expandSharedDefinitions(variant.schema);
  return [command + '/' + direction, {
    record, definition, variant, schema, check: ajv().compile(variant.schema),
    branches: (schema.oneOf ?? []).map(branch => ajv().compile(branch)),
  }];
})));

let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-admission-records-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 180000, maxBuffer: 2 << 20, env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

const clone = value => structuredClone(value);
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, replacement) {
  const result = clone(value); at(result, path.slice(0, -1))[path.at(-1)] = replacement; return result;
}
function remove(value, path) {
  const result = clone(value); delete at(result, path.slice(0, -1))[path.at(-1)]; return result;
}
function schema(command, direction, value, expected = true, label = '') {
  const {check} = checks.get(command + '/' + direction);
  assert.equal(check(value), expected, `${command}/${direction}/${label}: ${JSON.stringify(check.errors?.slice(0, 3))}`);
}
function branchIndex(command, value) {
  const matches = checks.get(command + '/output').branches.flatMap((branch, index) => branch(value) ? [index] : []);
  assert.equal(matches.length, 1, `${command} output must select exactly one branch: ${matches}`);
  return matches[0];
}
function run(command, input, flags = []) {
  const result = spawnSync(binary, [command, '--input', '-', ...flags], {
    input: typeof input === 'string' ? input : JSON.stringify(input), encoding: 'utf8', timeout: 30000, maxBuffer: 32 << 20,
  });
  assertCLITransport(result);
  return result;
}
// Admitted inputs must satisfy the input schema; the emitted JSON must satisfy the output schema.
function invoke(command, input, phase = 'passed', flags = []) {
  if (typeof input !== 'string' && flags.length === 0) schema(command, 'input', input, true, 'admitted-input');
  const result = run(command, input, flags);
  assert.equal(result.stderr, '', `${command}: ${result.stderr}`);
  assert.equal(result.status, phase === 'passed' ? 0 : 1, result.stdout.slice(0, 400));
  const value = JSON.parse(result.stdout);
  schema(command, 'output', value, true, 'emitted-output');
  assert.equal(value.state, phase);
  return value;
}
function refused(command, input, structural = true, label = '') {
  if (typeof input !== 'string') schema(command, 'input', input, !structural, 'refused/' + label);
  const result = run(command, input);
  assert.equal(result.status, 1, label); assert.equal(result.stdout, '', label); assert.notEqual(result.stderr, '', label);
}
function rejected(command, direction, value, label) { schema(command, direction, value, false, label); }

function capability(mode = 'code_baseline') {
  return {
    schemaVersion: 1, mapId: 'sample.backend.auth.capability_map', authority: 'caller_owned_observation', trustMode: mode,
    repository: {repositoryId: 'sample_repo', primaryLanguages: ['python', 'typescript'], nonClaims: ['Repository metadata is a test fixture.']},
    proofScope: {scopeId: 'sample.backend.auth.scope', dirtyState: 'clean', baseRef: 'origin/main', headRef: 'HEAD', nonClaims: ['Proof scope fixture does not prove checkout freshness.']},
    capabilities: [{
      capabilityId: 'sample.backend.auth', ownerId: 'sample.backend', summary: 'Authentication requests fail closed when headers are absent.',
      sourcePaths: ['service/src/auth', 'service/tests/auth_test.py'], riskClasses: ['runtime', 'security'], nonClaims: ['Capability fixture does not claim readiness.'],
      scenarioShapes: [{
        scenarioId: 'sample.backend.auth.missing_header', candidateRequirementId: 'REQ-SAMPLE-AUTH-001', summary: 'Requests without headers fail closed.',
        requiredEvidence: ['negative_test'], ownerQuestions: ['Should health checks bypass this invariant?'], nonClaims: ['Scenario fixture is not exhaustive.'],
      }],
    }],
    scenarioAnchors: [{
      scenarioId: 'sample.backend.auth.missing_header', selector: 'service/tests/auth_test.py::test_missing_header', sourcePath: 'service/tests/auth_test.py',
      commandRefs: ['sample.pytest.auth'], status: 'candidate', positiveWitness: false, falsificationWitness: true, nonClaims: ['Anchor fixture does not execute pytest.'],
    }],
    requiredVerification: [{
      commandId: 'sample.pytest.auth', command: 'uv run pytest service/tests/auth_test.py', environmentClass: 'local_python',
      reason: 'The failure mode needs an executable negative witness.', nonClaims: ['Command fixture does not prove test freshness.'],
    }],
    nonClaims: ['Capability map fixture is not merge evidence.'],
  };
}
function deployment() {
  const claim = 'Deployment evidence fixture does not prove live deployment.';
  return {
    schemaVersion: 1, admissionId: 'proofkit.test.deployment',
    evidence: {
      schema: 'deployment.evidence.v1', proofScope: 'local', deploymentClaim: 'candidate', evidenceId: 'proofkit.test.evidence', nonClaims: [claim],
      facts: [{factId: 'proofkit.test.fact', kind: 'release_artifact', sourceCommits: ['a'.repeat(40)], imageRefs: ['registry.example.test/proofkit@sha256:' + 'a'.repeat(64)]}],
    },
    policy: {
      expectedDeploymentClaim: 'candidate', expectedEvidenceSchema: 'deployment.evidence.v1', expectedProofScope: 'local', forbiddenValueIndicators: [],
      localRefIndicators: ['localhost', '127.0.0.1'], requiredFactIds: ['proofkit.test.fact'], requiredFactKinds: ['release_artifact'],
      requiredNonClaims: [claim], requireDigestPinnedImageRefs: true, requireLowercaseSourceCommits: true, temporaryEndpointHostSuffixes: ['trycloudflare.com'],
    },
    rawOperatorEvidence: [], nonClaims: ['Deployment evidence admission fixture is not release proof.'],
  };
}
function repoProfile() {
  return {
    profile: {
      schema: 'proofkit.repo-profile.v1', repository: {name: 'example', primaryLanguages: ['go'], rootPackageName: 'example-root'},
      documents: {policyPath: 'docs/docs-policy.yaml', routerPath: 'docs/INDEX.md', generatedArtifacts: []},
      requirements: {idPattern: 'REQ-[A-Z0-9-]+', specGlobs: ['docs/specs/example/requirements.v1.json']},
      proofs: {bindingPath: 'docs/contracts/bindings.json', environmentClasses: ['local-go'], proofLikePaths: ['docs/contracts/*.json'], retiredProofLikePaths: []},
      commandMatchers: [{allowedArgv: ['go', 'test', './...'], credentialClass: 'none', id: 'proofkit.test.go', kind: 'exact_argv', networkPolicy: 'none', parallelGroup: 'local'}],
      nonClaims: ['Repo profile fixture does not read repository state.'],
    },
    facts: {
      commandEnvironmentPairs: [{command: 'go test ./...', environmentClasses: ['local-go']}], docsPolicyGeneratedArtifacts: [], packageScripts: [],
      rootPackageName: 'example-root', rootScripts: [],
      trackedFiles: ['docs/INDEX.md', 'docs/contracts/bindings.json', 'docs/docs-policy.yaml', 'docs/specs/example/requirements.v1.json'],
    },
    policy: {environmentPolicy: {liveGithubRequiredClasses: [], localSecretRequiredClasses: []}, packageNamePattern: null},
  };
}
const digest = 'sha256:' + 'a'.repeat(64);
// Fixture receipts record the node digest the public scheduler reports for their command in the repository plan.
let nodeDigestCache;
function nodeDigest(commandId) {
  nodeDigestCache ??= JSON.parse(run('witness-scheduler-plan', JSON.parse(readFileSync(new URL('proofkit/witness-plan.json', root), 'utf8'))).stdout)
    .diagnostics.find(diagnostic => diagnostic.key === 'proofNodeDigests').value;
  const row = nodeDigestCache.find(node => node.commandId === commandId);
  assert.ok(row, commandId);
  return row.proofNodeDigest;
}
function receipt(overrides = {}) {
  return {
    artifactRefs: [{kind: 'report', path: 'artifacts/test/report.json', sha256: digest}], commandDigest: digest, dependencyDigest: null,
    environmentClass: 'local-go', environmentDigest: digest, evidenceRefs: ['artifacts/test/report.json'], exitCode: 0,
    finishedAt: '2026-06-22T00:00:01Z', lockfileDigest: null, nonClaims: ['Test receipt does not claim freshness.'], preconditionDigest: digest,
    producerAdmissionClass: 'advisory', producerId: 'local.test', proofBindingDigest: digest, proofNodeDigest: nodeDigest('proofkit.go-test'), proofPlanId: 'proofkit.self-hosting.witness-plan',
    provenanceRef: 'artifacts/test/provenance.json', receiptId: 'receipt.test.one', receiptKind: 'proofkit.go-test', runnerClass: 'local',
    runnerIdentity: 'local.test', sourceRevision: 'test-revision', startedAt: '2026-06-22T00:00:00Z', status: 'passed', toolchainDigest: digest,
    witnessSelectorDigest: digest, witnessSelectors: ['REQ-PROOFKIT-PACKAGE-001'], ...overrides,
  };
}
// Child operands are produced by the public child command, exactly as the bundle input guide prescribes.
function receiptChild(receipts) {
  const nonClaims = ['Test child report does not claim producer authenticity.'];
  const result = run('proof-receipt-admission', {schemaVersion: 2, receiptSetId: 'proofkit.test.child-report', receipts, nonClaims});
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  return {exitCode: result.status, failures: report.diagnostics.find(row => row.key === 'failures').value, nonClaims, producers: [], receipts, report};
}
function producerChild(receipts, producers) {
  const input = {schemaVersion: 1, policyId: 'proofkit.test.producer-policy', receiptKinds: ['proofkit.go-test'], environmentClasses: ['local-go'],
    producers, receipts, nonClaims: ['Test producer admission input does not authenticate producers.']};
  const result = run('receipt-producer-admission', input);
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  return {exitCode: result.status, failures: report.diagnostics.find(row => row.key === 'failures').value, nonClaims: input.nonClaims,
    producers, receipts, receiptKinds: input.receiptKinds, environmentClasses: input.environmentClasses, report};
}
const producer = () => ({admissionLevel: 'merge_satisfying', environmentClasses: ['local-go'], evidenceRefs: ['proofkit/receipt-producer-policy.json'],
  nonClaim: 'Test protected producer does not prove live workflow identity.', owner: 'proofkit.test', producerId: 'github.actions.package.protected', receiptKinds: ['proofkit.go-test']});
const producerReceipt = () => ({artifactRefs: ['artifacts/test/report.json'], environmentClass: 'local-go', evidenceRef: 'artifacts/test/report.json',
  nonClaim: 'Test producer receipt does not prove live workflow identity.', producerId: 'github.actions.package.protected', provenanceRef: 'artifacts/test/provenance.json',
  receiptId: 'receipt.test.one', receiptKind: 'proofkit.go-test', satisfiesMergeObligation: true, status: 'passed', subjectRef: 'proofkit.package-boundary.self-hosting'});
let bundleCache;
function bundle(merge = false) {
  bundleCache ??= {
    bindings: JSON.parse(readFileSync(new URL('proofkit/requirement-bindings.json', root), 'utf8')),
    plan: JSON.parse(readFileSync(new URL('proofkit/witness-plan.json', root), 'utf8')),
    receipt: receiptChild([receipt()]),
    merge: receiptChild([receipt({producerAdmissionClass: 'merge_satisfying', producerId: 'github.actions.package.protected'})]),
    producer: producerChild([producerReceipt()], [producer()]),
  };
  return clone({
    schemaVersion: 1, bundleId: 'proofkit.test.spec-proof-bundle', mergeRequiredReceiptIds: merge ? ['receipt.test.one'] : [],
    nonClaims: ['Test bundle input does not claim release readiness.'], requirementBindings: bundleCache.bindings, witnessPlan: bundleCache.plan,
    receiptAdmission: merge ? bundleCache.merge : bundleCache.receipt, receiptProducerAdmission: merge ? bundleCache.producer : null,
  });
}

const kinds = [['null', null], ['boolean', false], ['number', 42], ['string', 'wrong-kind'], ['array', []], ['object', {}]];
const kindOf = value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
function wrongKinds(command, direction, value, path, allowed, label) {
  for (const [kind, replacement] of kinds) {
    if (!allowed.includes(kind)) rejected(command, direction, replace(value, path, replacement), `${label}/kind/${kind}/${path.join('.')}`);
  }
}
// Output carriers are closed at every object; every leaf keeps exactly its emitted JSON kind
// unless an independently declared multi-kind leaf names its admitted kinds.
function carrier(command, output, label, multiKind = {}) {
  const visit = (value, path) => {
    const name = path.join('.').replace(/\.\d+(?=\.|$)/g, '.*');
    if (path.length) wrongKinds(command, 'output', output, path, multiKind[name] ?? [kindOf(value)], label);
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      rejected(command, 'output', replace(output, [...path, 'foreign'], true), `${label}/closed/${name}`);
      for (const key of Object.keys(value)) rejected(command, 'output', remove(output, [...path, key]), `${label}/required/${name}.${key}`);
    }
    if (value !== null && typeof value === 'object') for (const [key, child] of Object.entries(value)) visit(child, [...path, Array.isArray(value) ? Number(key) : key]);
  };
  visit(output, []);
}
function reportPredicates(command, output, label) {
  for (const version of [0, 2, '1', 1.5]) rejected(command, 'output', {...output, schemaVersion: version}, label + '/version');
  rejected(command, 'output', {...output, reportKind: 'proofkit.foreign'}, label + '/kind');
  rejected(command, 'output', {...output, state: 'foreign-fixture-value'}, label + '/state');
  rejected(command, 'output', {...output, nonClaims: output.nonClaims.filter(claim => claim !== builtinClaims[command][0])}, label + '/builtin-claim');
  rejected(command, 'output', {...output, nonClaims: [...output.nonClaims, '']}, label + '/empty-claim');
  for (const [index, rule] of output.ruleResults.entries()) {
    rejected(command, 'output', replace(output, ['ruleResults', index, 'status'], 'warning'), label + '/rule-status');
    rejected(command, 'output', replace(output, ['ruleResults', index, 'ruleId'], 'proofkit.foreign.rule'), label + '/rule-id');
    rejected(command, 'output', replace(output, ['ruleResults', index, 'diagnostics'], [...rule.diagnostics, {key: 'foreign', value: true}]), label + '/rule-diagnostics');
  }
  rejected(command, 'output', {...output, diagnostics: [...output.diagnostics, {key: 'foreign', value: true}]}, label + '/diagnostics-tuple');
  for (const [key, value] of Object.entries(output.summary)) {
    if (typeof value === 'number') for (const bad of [-1, 0.5, 2 ** 64]) rejected(command, 'output', replace(output, ['summary', key], bad), label + '/count/' + key);
  }
}

test('published directions are exact native structural owners with conserved public identities', () => {
  for (const command of commands) {
    const row = contract.commands.find(item => item.command === command);
    assert.deepEqual(row.outputModes, ['json'], command + ' claims no text variant');
    assert.deepEqual(row.allowedFlags, ['--input', '--input-pointer']);
    for (const direction of ['input', 'output']) {
      const {record, definition, variant, schema: shape} = checks.get(command + '/' + direction);
      // Bundle input v2 binds receipts to plan nodes; its wire stays version 1.
      const version = command === 'spec-proof-bundle-admission' && direction === 'input' ? 2 : 1;
      assert.equal(record.contractId, `proofkit.${command}.${direction}.v${version}`);
      assert.equal(record.schemaVersion, 1);
      assert.equal(record.rootDefinitionRef, `proofkit.${command}.${direction}.v${version}.json-schema`);
      assert.equal(definitionOf(`proofkit.${command}.${direction}.v1.root-shape`), undefined, 'predecessor retired');
      if (version > 1) assert.equal(definitionOf(`proofkit.${command}.${direction}.v1.json-schema`), undefined, 'structural predecessor retired');
      assert.equal(definition.fieldTree.variants.length, 1);
      assert.equal(variant.variantId, '01-root'); assert.deepEqual(variant.when, ['default JSON mode']);
      if (direction === 'input') {
        const inventory = rootInventory[command];
        assert.deepEqual([...shape.required].sort(), [...inventory.required].sort());
        assert.deepEqual(Object.keys(shape.properties).sort(), [...inventory.required, ...inventory.optional].sort());
        assert.equal(shape.additionalProperties, false);
      } else {
        assert.equal(shape.oneOf.length, branchCounts[command]);
        for (const branch of shape.oneOf) {
          assert.deepEqual([...branch.required].sort(), reportKeys); assert.deepEqual(Object.keys(branch.properties).sort(), reportKeys);
          assert.equal(branch.additionalProperties, false);
          assert.deepEqual([...branch.properties.summary.required].sort(), [...summaryKeys[command]].sort());
          assert.equal(branch.properties.reportKind.enum?.[0] ?? branch.properties.reportKind.const, reportKinds[command]);
        }
      }
    }
  }
  assert.deepEqual(contract.commands.find(item => item.command === 'repo-profile-admission').inputContract.compatibility,
    {'profile.schema': 'required proofkit.repo-profile.v1', schemaVersion: 'optional transitional top-level field; if present it must be 1'});
});

test('capability map variants select their exact trust-mode and state branch', () => {
  const cases = [
    ['audit_from_code', 'passed', input => input, 0],
    ['audit_from_code', 'failed', input => replace(input, ['scenarioAnchors', 0, 'scenarioId'], 'sample.backend.auth.undeclared'), 1],
    ['code_baseline', 'passed', input => input, 2],
    ['code_baseline', 'failed', input => ({...input, scenarioAnchors: null}), 3],
  ];
  for (const [mode, phase, mutate, index] of cases) {
    const output = invoke('capability-map-admission', mutate(capability(mode)), phase);
    assert.equal(branchIndex('capability-map-admission', output), index, mode + '/' + phase);
    assert.equal(output.summary.trustMode, mode); assert.equal(output.reportId, 'sample.backend.auth.capability_map');
    carrier('capability-map-admission', output, mode + '/' + phase);
    reportPredicates('capability-map-admission', output, mode + '/' + phase);
    for (const [path, wrong] of [[['summary', 'trustMode'], mode === 'code_baseline' ? 'audit_from_code' : 'code_baseline'],
      [['summary', 'capabilityCount'], 33], [['summary', 'capabilityCount'], 0], [['summary', 'scenarioAnchorCount'], 257],
      [['summary', 'verificationCommandCount'], 129], [['diagnostics', 2, 'value', 0], 'Foreign instruction.'],
      [['ruleResults', 1, 'ruleId'], 'proofkit.capability-map-admission.trust-mode.other'],
      [['summary', 'failureCount'], phase === 'passed' ? 1 : 0], [['reportId'], '1bad']]) {
      rejected('capability-map-admission', 'output', replace(output, path, wrong), 'drift/' + path.join('.'));
    }
  }
  const baseline = invoke('capability-map-admission', capability());
  const binding = baseline.diagnostics[4].value[0];
  assert.deepEqual(binding.witnessKinds, ['falsification']);
  for (const kinds of [['positive'], ['positive', 'falsification']]) schema('capability-map-admission', 'output', replace(baseline, ['diagnostics', 4, 'value', 0, 'witnessKinds'], kinds));
  for (const kinds of [[], ['falsification', 'positive'], ['negative'], ['positive', 'positive']]) {
    rejected('capability-map-admission', 'output', replace(baseline, ['diagnostics', 4, 'value', 0, 'witnessKinds'], kinds), 'witness-kinds');
  }
  for (const [key, value] of [['evidenceAuthority', 'untrusted_code_observation'], ['executableEvidenceState', 'foreign'], ['state', 'admitted'], ['commandRefs', []], ['sourcePath', ' padded']]) {
    rejected('capability-map-admission', 'output', replace(baseline, ['diagnostics', 4, 'value', 0, key], value), 'binding/' + key);
  }
  const audit = invoke('capability-map-admission', {...capability('audit_from_code'), scenarioAnchors: []});
  const actions = audit.diagnostics[5].value;
  assert.deepEqual(actions.map(action => action.type), ['add_scenario_anchor', 'resolve_owner_questions']);
  for (const [index, key, value] of [[0, 'severity', 'blocking'], [0, 'commandRefs', ['sample.pytest.auth']], [1, 'type', 'add_scenario_anchor'],
    [0, 'actionId', 'proofkit.capability-map.sample.backend.auth.missing_header.resolve-owner-questions'], [1, 'message', 'Foreign message.']]) {
    rejected('capability-map-admission', 'output', replace(audit, ['diagnostics', 5, 'value', index, key], value), 'action/' + key);
  }
  refused('capability-map-admission', '{}');
  refused('capability-map-admission', '{"schemaVersion":1,"schemaVersion":1}');
});

test('capability map input clauses agree with native admission at every closed record and bound', () => {
  const command = 'capability-map-admission', base = capability('audit_from_code');
  for (const key of rootInventory[command].required) refused(command, remove(base, [key]), true, 'required/' + key);
  for (const key of rootInventory[command].optional) {
    invoke(command, remove(base, [key]), key === 'requiredVerification' ? 'failed' : 'passed');
    invoke(command, {...base, [key]: null}, key === 'requiredVerification' ? 'failed' : 'passed');
  }
  const records = [[], ['repository'], ['proofScope'], ['capabilities', 0], ['capabilities', 0, 'scenarioShapes', 0], ['scenarioAnchors', 0], ['requiredVerification', 0]];
  const required = {
    repository: ['repositoryId'], proofScope: ['dirtyState', 'scopeId'], 'capabilities.0': ['capabilityId', 'ownerId', 'scenarioShapes', 'sourcePaths', 'summary'],
    'capabilities.0.scenarioShapes.0': ['scenarioId', 'summary'], 'scenarioAnchors.0': ['scenarioId', 'selector', 'sourcePath', 'status'],
    'requiredVerification.0': ['command', 'commandId', 'environmentClass', 'reason'],
  };
  const optional = {
    repository: ['nonClaims', 'primaryLanguages'], proofScope: ['baseRef', 'headRef', 'nonClaims'], 'capabilities.0': ['nonClaims', 'riskClasses'],
    'capabilities.0.scenarioShapes.0': ['candidateRequirementId', 'nonClaims', 'ownerQuestions', 'requiredEvidence'],
    'scenarioAnchors.0': ['commandRefs', 'falsificationWitness', 'nonClaims', 'positiveWitness'], 'requiredVerification.0': ['nonClaims'],
  };
  for (const path of records) {
    refused(command, replace(base, [...path, 'foreign'], true), true, 'closed/' + path.join('.'));
    const name = path.join('.');
    for (const key of required[name] ?? []) refused(command, remove(base, [...path, key]), true, `required/${name}.${key}`);
    for (const key of optional[name] ?? []) {
      schema(command, 'input', remove(base, [...path, key]));
      schema(command, 'input', replace(base, [...path, key], null));
    }
    if (path.length) wrongKinds(command, 'input', base, path, ['object'], 'record');
  }
  invoke(command, replace(replace(base, ['scenarioAnchors', 0, 'positiveWitness'], null), ['proofScope', 'baseRef'], null));
  for (const [path, type] of [[['mapId'], 'string'], [['schemaVersion'], 'number'], [['capabilities'], 'array'], [['capabilities', 0, 'sourcePaths'], 'array'],
    [['repository', 'primaryLanguages'], 'array'], [['scenarioAnchors', 0, 'positiveWitness'], 'boolean'], [['capabilities', 0, 'summary'], 'string']]) {
    const nullable = ['primaryLanguages', 'positiveWitness'].includes(path.at(-1));
    wrongKinds(command, 'input', base, path, nullable ? [type, 'null'] : [type], 'leaf');
  }
  for (const [path, value] of [[['authority'], 'caller_owned'], [['trustMode'], 'trust_me'], [['proofScope', 'dirtyState'], 'dirty'],
    [['scenarioAnchors', 0, 'status'], 'active'], [['capabilities', 0, 'scenarioShapes', 0, 'requiredEvidence'], ['mutation_test']],
    [['schemaVersion'], 2], [['mapId'], '1bad'], [['mapId'], ' padded'], [['capabilities', 0, 'sourcePaths'], ['']]]) {
    refused(command, replace(base, path, value), true, 'enum/' + path.join('.'));
  }
  const runes = count => '\u00e9'.repeat(count), texts = count => Array.from({length: count}, (_, i) => `Claim ${String(i).padStart(3, '0')}.`);
  const ids = count => Array.from({length: count}, (_, i) => `id_${String(i).padStart(3, '0')}`);
  const anchors = count => Array.from({length: count}, (_, i) => ({scenarioId: 'sample.backend.auth.missing_header', status: 'missing',
    selector: `service/tests/auth_test.py::anchor_${String(i).padStart(3, '0')}`, sourcePath: 'service/tests/auth_test.py'}));
  const commandsOf = count => Array.from({length: count}, (_, i) => ({commandId: `sample.command_${String(i).padStart(3, '0')}`, command: 'uv run pytest', environmentClass: 'local_python', reason: 'Fixture.'}));
  const capabilities = count => Array.from({length: count}, (_, i) => ({...base.capabilities[0], capabilityId: `sample.capability_${String(i).padStart(2, '0')}`}));
  const shapes = count => Array.from({length: count}, (_, i) => ({scenarioId: `sample.scenario_${String(i).padStart(2, '0')}`, summary: 'Scenario.'}));
  const bounds = [
    [['capabilities'], capabilities(32), capabilities(33)],
    [['capabilities', 0, 'scenarioShapes'], shapes(16), shapes(17)],
    [['scenarioAnchors'], anchors(256), anchors(257)],
    [['requiredVerification'], commandsOf(128), commandsOf(129)],
    [['nonClaims'], texts(12), texts(13)],
    [['nonClaims'], [runes(240)], [runes(241)]],
    [['capabilities', 0, 'scenarioShapes', 0, 'ownerQuestions'], texts(8), texts(9)],
    [['capabilities', 0, 'scenarioShapes', 0, 'ownerQuestions'], [runes(240)], [runes(241)]],
    [['capabilities', 0, 'summary'], ' \u3000' + runes(280) + '\t', runes(281)],
    [['requiredVerification', 0, 'reason'], runes(280) + '\u2028', runes(281)],
    [['requiredVerification', 0, 'command'], '\t' + 'c'.repeat(240), 'c'.repeat(241)],
    [['repository', 'primaryLanguages'], ids(16), ids(17)],
    [['mapId'], 'm' + 'a'.repeat(255), 'm' + 'a'.repeat(256)],
    [['scenarioAnchors', 0, 'selector'], ' service/tests/auth_test.py::a' + 'b'.repeat(255) + '\u0085', 'service/tests/auth_test.py::a' + 'b'.repeat(256)],
  ];
  for (const [path, limit, beyond] of bounds) {
    const accepted = replace(base, path, limit);
    schema(command, 'input', accepted, true, 'limit/' + path.join('.'));
    const result = run(command, accepted);
    assert.equal(result.stderr, '', path.join('.')); schema(command, 'output', JSON.parse(result.stdout));
    refused(command, replace(base, path, beyond), true, 'beyond/' + path.join('.'));
  }
  invoke(command, {...base, nonClaims: []});
  for (const value of [[''], [' padded claim'], ['claim', 'claim'], [false]]) refused(command, {...base, nonClaims: value}, true, 'claims');
  for (const selector of ['service/tests/auth_test.py', 'a::b::c', 'a:::b', '::anchor', 'path::', 'path::1anchor', ' ']) {
    refused(command, replace(base, ['scenarioAnchors', 0, 'selector'], selector), true, 'selector/' + selector);
  }
  invoke(command, replace(replace(base, ['scenarioAnchors', 0, 'selector'], 'x/a:b/:c::anchor:part'), ['scenarioAnchors', 0, 'sourcePath'], ' x/a:b/:c'));
  for (const [label, input] of [
    ['selector-path-drift', replace(base, ['scenarioAnchors', 0, 'selector'], 'service/tests/other_test.py::test_missing_header')],
    ['unsafe-source-path', replace(base, ['capabilities', 0, 'sourcePaths'], ['../backend'])],
    ['shell-command', replace(base, ['requiredVerification', 0, 'command'], 'uv run pytest && curl example.test')],
    ['unsorted-languages', replace(base, ['repository', 'primaryLanguages'], ['typescript', 'python'])],
    ['secret-text', replace(base, ['capabilities', 0, 'summary'], 'Bearer abcdefghijklmnopqrstuvwxyz')],
    ['timestamp-id', {...base, mapId: 'sample.20240101'}],
    ['duplicate-capability', {...base, capabilities: [base.capabilities[0], base.capabilities[0]]}],
  ]) {
    refused(command, input, false, 'native/' + label);
  }
});

test('deployment evidence states select one branch and keep caller JSON domains open but key-safe', () => {
  const command = 'deployment-evidence-admission', base = deployment();
  const fact = ['evidence', 'facts', 0];
  const cases = [
    ['passed', base, 0],
    ['blocked', {...base, evidence: null}, 1],
    ['failed', replace(base, [...fact, 'imageRefs'], ['registry.example.test/proofkit:latest']), 2],
    ['failed', replace(replace(base, ['evidence', 'facts'], []), ['evidence', 'foreign'], true), 3],
  ];
  for (const [phase, input, index] of cases) {
    const output = invoke(command, input, phase);
    assert.equal(branchIndex(command, output), index, phase + '/' + index);
    carrier(command, output, phase + '/' + index, {'summary.evidenceId': ['null', 'string']});
    reportPredicates(command, output, phase + '/' + index);
    for (const path of [['ruleResults', 0, 'message'], ['ruleResults', 0, 'diagnostics', 0, 'value']]) {
      rejected(command, 'output', replace(output, path, 'deployment evidence admission state is foreign'), 'result-rule/' + path.join('.'));
    }
  }
  const passed = invoke(command, base);
  for (const [path, value] of [[['summary', 'blockedReasonCount'], 1], [['summary', 'evidenceId'], ' padded'], [['diagnostics', 0, 'value'], ['blocked']],
    [['ruleResults', 1, 'message'], 'Foreign safety message.'], [['ruleResults', 2, 'diagnostics', 0, 'key'], 'failures']]) {
    rejected(command, 'output', replace(passed, path, value), 'passed/' + path.join('.'));
  }
  schema(command, 'output', replace(passed, ['summary', 'evidenceId'], null));
  const duplicateBuiltin = invoke(command, {...base, nonClaims: ['Deployment evidence admission reports do not read files or repositories.']});
  assert.equal(duplicateBuiltin.nonClaims.length, 7);
  assert.equal(new Set(duplicateBuiltin.nonClaims).size, 6, 'caller copies of builtin claims are retained');

  for (const key of rootInventory[command].required) refused(command, remove(base, [key]), true, 'required/' + key);
  invoke(command, remove(base, ['rawOperatorEvidence'])); invoke(command, {...base, rawOperatorEvidence: null});
  for (const record of [[], ['policy'], ['rawOperatorEvidence', 0]]) {
    const input = record[0] === 'rawOperatorEvidence' ? {...base, rawOperatorEvidence: [{evidenceRef: 'operator.note', payload: null}]} : base;
    refused(command, replace(input, [...record, 'foreign'], true), true, 'closed/' + record.join('.'));
  }
  for (const key of ['evidenceRef', 'payload']) refused(command, remove({...base, rawOperatorEvidence: [{evidenceRef: 'operator.note', payload: null}]}, ['rawOperatorEvidence', 0, key]), true, 'operator/' + key);
  const policyKeys = ['expectedDeploymentClaim', 'expectedEvidenceSchema', 'expectedProofScope', 'forbiddenValueIndicators', 'localRefIndicators',
    'requireDigestPinnedImageRefs', 'requireLowercaseSourceCommits', 'requiredFactIds', 'requiredFactKinds', 'requiredNonClaims', 'temporaryEndpointHostSuffixes'];
  assert.deepEqual(Object.keys(checks.get(command + '/input').schema.properties.policy.properties).sort(), policyKeys);
  for (const key of policyKeys) {
    refused(command, remove(base, ['policy', key]), true, 'policy/' + key);
    const type = key.startsWith('require') && !key.startsWith('required') ? 'boolean' : key.startsWith('expected') ? 'string' : 'array';
    wrongKinds(command, 'input', base, ['policy', key], [type], 'policy');
  }
  for (const evidence of [{}, {facts: [false], nested: {deep: [null, 1, {k: 'v'}]}}, {evidenceId: '  '}]) {
    invoke(command, {...base, evidence}, evidence.facts ? 'failed' : 'blocked');
  }
  for (const value of ['evidence', [], 1, true]) refused(command, {...base, evidence: value}, true, 'evidence-kind');
  for (const payload of [null, false, -1.5e3, '', [], {}, {nested: [{a: null}]}]) invoke(command, {...base, rawOperatorEvidence: [{evidenceRef: 'operator.note', payload}]});
  for (const key of ['', '\u0000', 'a\u001fb', '\u007f', '\n']) {
    refused(command, replace(base, ['evidence', 'metadata'], {outer: {[key]: 'value'}}), true, 'evidence-key');
    refused(command, {...base, rawOperatorEvidence: [{evidenceRef: 'operator.note', payload: [null, [{[key]: 1}]]}]}, true, 'payload-key');
  }
  for (const key of [' ', '\u0085', '\u00e9', 'api_key']) {
    const evidence = replace(base, ['evidence', 'metadata'], {[key]: 1});
    schema(command, 'input', evidence);
    assert.equal(run(command, evidence).stderr, '', 'safe key reaches evaluation');
  }
  const secret = invoke(command, {...base, rawOperatorEvidence: [{evidenceRef: 'operator.note', payload: {note: 'api_key=synthetic-fixture-value'}}]}, 'failed');
  assert.ok(!JSON.stringify(secret).includes('synthetic-fixture-value'));
  for (const ids of [[' \u3000proofkit.test.fact\t'], ['proofkit.test.fact', 'proofkit.test.fact'], ['\u0085' + 'a'.repeat(256) + ' ']]) {
    const input = replace(base, ['policy', 'requiredFactIds'], ids);
    schema(command, 'input', input);
    assert.equal(run(command, input).stderr, '', 'trimmed IDs are admitted');
  }
  for (const ids of [[' a' + 'a'.repeat(256)], ['1bad'], [' '], ['bad id']]) refused(command, replace(base, ['policy', 'requiredFactKinds'], ids), true, 'trimmed-id');
  refused(command, replace(replace(base, ['policy', 'requiredFactIds'], []), ['policy', 'requiredFactKinds'], []), true, 'no-required-facts');
  invoke(command, replace(base, ['policy', 'requiredFactIds'], []));
  for (const [key, value] of [['requiredNonClaims', []], ['localRefIndicators', []], ['forbiddenValueIndicators', [' ']], ['expectedProofScope', ' ']]) {
    refused(command, replace(base, ['policy', key], value), true, 'policy-value/' + key);
  }
  for (const [label, input] of [['duplicate-suffix', replace(base, ['policy', 'temporaryEndpointHostSuffixes'], ['Example.com', 'example.com'])],
    ['empty-normalized-indicator', replace(base, ['policy', 'localRefIndicators'], ['\u00ad'])], ['timestamp-id', replace(base, ['policy', 'requiredFactIds'], ['fact.20240101'])]]) {
    refused(command, input, false, 'native/' + label);
  }
  for (const value of [[], [' ']]) refused(command, {...base, nonClaims: value}, true, 'nonClaims');
  for (const version of [2, '1', 1.5]) refused(command, {...base, schemaVersion: version}, true, 'version');
});

test('repo profile optional version, trimmed vocabularies and failure rules keep native domains', () => {
  const command = 'repo-profile-admission', base = repoProfile();
  const passed = invoke(command, base);
  assert.equal(branchIndex(command, passed), 0);
  carrier(command, passed, 'passed'); reportPredicates(command, passed, 'passed');
  const failed = invoke(command, replace(replace(base, ['facts', 'rootPackageName'], 'other-root'), ['facts', 'trackedFiles'], []), 'failed');
  assert.equal(branchIndex(command, failed), 1);
  carrier(command, failed, 'failed'); reportPredicates(command, failed, 'failed');
  for (const [path, value] of [[['reportId'], 'proofkit.repo-profile-admission'], [['ruleResults', 0, 'ruleId'], 'proofkit.repo-profile-structural.failure.1'],
    [['ruleResults'], []], [['state'], 'passed'], [['summary', 'environmentClassCount'], 0]]) {
    rejected(command, 'output', replace(failed, path, value), 'failed/' + path.join('.'));
  }
  rejected(command, 'output', replace(passed, ['ruleResults'], [...passed.ruleResults, passed.ruleResults[0]]), 'passed-rule-tuple');
  invoke(command, {...base, schemaVersion: 1});
  for (const version of [2, null, '1', 1.5]) refused(command, {...base, schemaVersion: version}, true, 'version/' + version);
  for (const key of rootInventory[command].required) refused(command, remove(base, [key]), true, 'required/' + key);
  const closed = {
    profile: ['commandMatchers', 'documents', 'nonClaims', 'proofs', 'repository', 'requirements', 'schema'], 'profile.repository': ['name', 'primaryLanguages', 'rootPackageName'],
    'profile.documents': ['generatedArtifacts', 'policyPath', 'routerPath'], 'profile.requirements': ['idPattern', 'specGlobs'],
    'profile.proofs': ['bindingPath', 'environmentClasses', 'proofLikePaths', 'retiredProofLikePaths'],
    'profile.commandMatchers.0': ['credentialClass', 'id', 'kind', 'networkPolicy', 'parallelGroup'],
    facts: ['commandEnvironmentPairs', 'docsPolicyGeneratedArtifacts', 'packageScripts', 'rootPackageName', 'rootScripts', 'trackedFiles'],
    'facts.commandEnvironmentPairs.0': ['command', 'environmentClasses'], policy: ['environmentPolicy'],
    'policy.environmentPolicy': ['liveGithubRequiredClasses', 'localSecretRequiredClasses'],
  };
  for (const [name, keys] of Object.entries(closed)) {
    const path = name.split('.').map(segment => /^\d+$/.test(segment) ? Number(segment) : segment);
    refused(command, replace(base, [...path, 'foreign'], true), true, 'closed/' + name);
    for (const key of keys) refused(command, remove(base, [...path, key]), true, `required/${name}.${key}`);
    wrongKinds(command, 'input', base, path, ['object'], 'record');
  }
  const matcher = ['profile', 'commandMatchers', 0];
  for (const key of ['allowedArgv']) schema(command, 'input', remove(base, [...matcher, key]));
  for (const key of ['allowedArgv', 'allowedScripts', 'allowedTestPathGlobs']) refused(command, replace(base, [...matcher, key], null), true, 'nonnull/' + key);
  for (const [key, values, invalid] of [['kind', ['bun_workspace_package_script', 'bun_repo_script', 'exact_argv', 'python_pytest_contract'], ['bun_script', 'exact _argv', '']],
    ['networkPolicy', ['none', 'loopback', 'external'], ['internet', 'None']], ['credentialClass', ['none', 'local-secret', 'live-github', 'live-cloud'], ['token', 'live']]]) {
    for (const value of values) for (const padded of [value, ` ${value}`, `\u3000${value}\u0085`]) schema(command, 'input', replace(base, [...matcher, key], padded), true, key);
    for (const value of invalid) refused(command, replace(base, [...matcher, key], value), true, 'vocabulary/' + key);
  }
  invoke(command, replace(replace(replace(base, [...matcher, 'kind'], '\texact_argv '), [...matcher, 'networkPolicy'], ' none'), [...matcher, 'credentialClass'], 'none\u2028'));
  invoke(command, replace(base, [...matcher, 'allowedArgv'], [' ']), 'failed');
  for (const argv of [[], ['']]) refused(command, replace(base, [...matcher, 'allowedArgv'], argv), true, 'argv');
  for (const [path, value] of [[['profile', 'schema'], 'proofkit.repo-profile.v2'], [['profile', 'repository', 'primaryLanguages'], []], [['profile', 'nonClaims'], []],
    [['profile', 'requirements', 'specGlobs'], []], [['profile', 'proofs', 'environmentClasses'], []], [['profile', 'proofs', 'proofLikePaths'], []],
    [['profile', 'documents', 'policyPath'], '\u3000'], [['facts', 'trackedFiles'], [' ']], [['policy', 'environmentPolicy'], null],
    [['policy', 'packageNamePattern'], ' '], [['profile', 'repository', 'primaryLanguages'], ['go', 'go']], [['facts', 'rootScripts'], ['a', 'a']]]) {
    refused(command, replace(base, path, value), true, 'value/' + path.join('.'));
  }
  invoke(command, remove(base, ['policy', 'packageNamePattern'])); invoke(command, replace(base, ['policy', 'packageNamePattern'], '^example'));
  const policies = [{credentialClass: ' none', environmentClass: 'local-go', networkPolicy: 'none\t'}];
  invoke(command, replace(base, ['policy', 'environmentPolicy', 'environmentClassPolicies'], policies));
  invoke(command, replace(base, ['policy', 'environmentPolicy', 'environmentClassPolicies'], null));
  refused(command, replace(base, ['policy', 'environmentPolicy', 'environmentClassPolicies'], {}), true, 'class-policies');
  refused(command, replace(base, ['policy', 'environmentPolicy', 'environmentClassPolicies'], [{...policies[0], networkPolicy: 'internet'}]), true, 'class-policy-vocabulary');
  invoke(command, replace(base, ['facts', 'rootScripts'], ['test', 'build']));
  for (const [label, input] of [['unsorted', replace(base, ['profile', 'repository', 'primaryLanguages'], ['go', 'c'])],
    ['trimmed-duplicate', replace(base, ['profile', 'repository', 'primaryLanguages'], [' go', 'go'])],
    ['unsafe-tracked-file', replace(base, ['facts', 'trackedFiles'], ['../outside'])],
    ['shell-command', replace(base, ['facts', 'commandEnvironmentPairs', 0, 'command'], 'go test ./... && curl x')],
    ['invalid-package-pattern', replace(base, ['policy', 'packageNamePattern'], '(')]]) {
    refused(command, input, false, 'native/' + label);
  }
});

test('spec proof bundle whole chain composes public child commands and reuses their structures', () => {
  const command = 'spec-proof-bundle-admission';
  const input = bundle(), merge = bundle(true);
  for (const [child, operand] of [['requirement-bindings', input.requirementBindings], ['witness-scheduler-plan', input.witnessPlan]]) {
    const result = run(child, operand);
    assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).state, 'passed');
  }
  const passed = invoke(command, input);
  assert.equal(branchIndex(command, passed), 0);
  assert.deepEqual(passed.diagnostics[0].value, {receiptAdmissionState: 'passed', receiptProducerAdmissionState: 'not_attached', requirementBindingState: 'passed', witnessSchedulerState: 'passed'});
  carrier(command, passed, 'passed'); reportPredicates(command, passed, 'passed');
  const attached = invoke(command, merge);
  assert.equal(attached.summary.receiptProducerAttached, true); assert.equal(attached.summary.mergeRequiredReceiptCount, 1);
  const unattached = clone(input); delete unattached.receiptAdmission; delete unattached.receiptProducerAdmission;
  invoke(command, unattached);
  const unknown = replace(input, ['receiptAdmission'], receiptChild([receipt({witnessSelectors: ['REQ-PROOFKIT-UNKNOWN']})]));
  const failed = invoke(command, unknown, 'failed');
  assert.equal(branchIndex(command, failed), 1);
  carrier(command, failed, 'failed'); reportPredicates(command, failed, 'failed');
  const failedChild = receiptChild([receipt({finishedAt: '2026-06-21T00:00:00Z'})]);
  assert.equal(failedChild.report.state, 'failed'); assert.equal(failedChild.exitCode, 1);
  const childFailure = invoke(command, {...input, receiptAdmission: {...failedChild, failures: [null, {opaque: true}, 'recorded']}}, 'failed');
  assert.equal(childFailure.diagnostics[0].value.receiptAdmissionState, 'failed');
  for (const [path, value] of [[['diagnostics', 0, 'value', 'receiptAdmissionState'], 'failed'], [['diagnostics', 0, 'value', 'witnessSchedulerState'], 'failed'],
    [['diagnostics', 0, 'value', 'requirementBindingState'], 'blocked'], [['summary', 'witnessCommandCount'], 0], [['ruleResults', 0, 'ruleId'], 'proofkit.spec-proof-bundle-admission.failure.001']]) {
    rejected(command, 'output', replace(passed, path, value), 'passed/' + path.join('.'));
  }
  schema(command, 'output', replace(failed, ['diagnostics', 0, 'value', 'receiptAdmissionState'], 'failed'));
  for (const [path, value] of [[['ruleResults'], []], [['diagnostics', 1, 'value'], []], [['summary', 'failureCount'], 0],
    [['ruleResults', 0, 'ruleId'], 'proofkit.spec-proof-bundle-admission.failure.1'], [['ruleResults', 0, 'status'], 'passed']]) {
    rejected(command, 'output', replace(failed, path, value), 'failed/' + path.join('.'));
  }

  const shape = checks.get(command + '/input').schema.properties;
  const published = (name, direction) => checks.get(name + '/' + direction)?.schema ??
    expandSharedDefinitions(definitionOf(contract.commands.find(row => row.command === name)[direction + 'Contract'].rootDefinitionRef).fieldTree.variants[0].schema);
  assert.deepEqual(shape.requirementBindings, published('requirement-bindings', 'input'));
  assert.deepEqual(shape.witnessPlan, published('witness-scheduler-plan', 'input'));
  for (const [key, owner] of [['receiptAdmission', 'proof-receipt-admission'], ['receiptProducerAdmission', 'receipt-producer-admission']]) {
    const [nullBranch, child] = shape[key].anyOf;
    assert.deepEqual(nullBranch, {type: 'null'});
    assert.deepEqual(child.properties.report, published(owner, 'output'));
    assert.deepEqual(child.properties.receipts, published(owner, 'input').properties.receipts);
    assert.deepEqual(child.properties.nonClaims, published(owner, 'input').properties.nonClaims);
    const bindings = contract.commands.find(row => row.command === command).inputContract.childDefinitionBindings;
    assert.ok(bindings.some(row => row.pathSegments.join('/') === key + '/report' && row.definitionRef === `proofkit.${owner}.output.v1.json-schema`));
  }
});

test('spec proof bundle recorded children and own members agree with native admission', () => {
  const command = 'spec-proof-bundle-admission', input = bundle(), merge = bundle(true);
  for (const key of rootInventory[command].required) refused(command, remove(input, [key]), true, 'required/' + key);
  refused(command, {...input, foreign: true}, true, 'closed-root');
  invoke(command, {...input, receiptAdmission: null});
  for (const key of ['exitCode', 'failures', 'nonClaims', 'producers', 'receipts', 'report']) refused(command, remove(input, ['receiptAdmission', key]), true, 'child/' + key);
  for (const key of ['environmentClasses', 'receiptKinds']) {
    refused(command, remove(merge, ['receiptProducerAdmission', key]), true, 'producer-child/' + key);
    refused(command, replace(input, ['receiptAdmission', key], []), true, 'receipt-child-extra/' + key);
  }
  refused(command, replace(input, ['receiptAdmission', 'foreign'], true), true, 'child-closed');
  for (const exitCode of [2, -1, '0', null, 0.5]) refused(command, replace(input, ['receiptAdmission', 'exitCode'], exitCode), true, 'exit/' + exitCode);
  for (const raw of ['1.0', '-0', '1e0']) {
    const text = JSON.stringify(input).replace('"exitCode":0,"failures"', `"exitCode":${raw},"failures"`);
    assert.notEqual(text, JSON.stringify(input));
    refused(command, text, true, 'lexical-exit/' + raw);
  }
  for (const [path, value] of [[['receiptAdmission', 'report'], null], [['receiptAdmission', 'failures'], {}], [['receiptAdmission', 'producers'], ['producer']],
    [['receiptAdmission', 'receipts'], []], [['receiptAdmission', 'nonClaims'], ['']], [['receiptAdmission', 'report', 'reportKind'], 'proofkit.receipt-producer-admission'],
    [['receiptAdmission', 'report', 'schemaVersion'], 2], [['receiptAdmission', 'report', 'foreign'], true], [['receiptProducerAdmission', 'nonClaims'], []],
    [['receiptProducerAdmission', 'receiptKinds'], ['proofkit.go-test', 'proofkit.go-test']], [['receiptProducerAdmission', 'environmentClasses'], ['1bad']]]) {
    const base = path[0] === 'receiptProducerAdmission' ? merge : input;
    refused(command, replace(base, path, value), true, 'child-value/' + path.join('.'));
  }
  invoke(command, replace(input, ['receiptAdmission', 'producers'], [{any: [null]}, {}]));
  for (const [label, mutate] of [['forged-summary', value => replace(value, ['receiptAdmission', 'report', 'summary', 'receiptCount'], 2)],
    ['forged-state', value => replace(replace(replace(value, ['receiptAdmission', 'report', 'state'], 'failed'), ['receiptAdmission', 'exitCode'], 1), ['receiptAdmission', 'failures'], ['x'])],
    ['passed-with-failures', value => replace(value, ['receiptAdmission', 'failures'], ['recorded'])],
    ['blank-owner-claim', value => replace(value, ['receiptAdmission', 'nonClaims'], [' '])],
    ['modified-receipt-input', value => replace(value, ['receiptAdmission', 'receipts', 0, 'runnerClass'], 'remote')]]) {
    refused(command, mutate(input), false, 'native/' + label);
  }
  for (const [key, valid, invalid] of [['bundleId', 'b'.repeat(256), 'b'.repeat(257)], ['mergeRequiredReceiptIds', [], ['receipt.test.one', 'receipt.test.one']],
    ['nonClaims', ['Same claim.', ' Same claim.'], [' ']]]) {
    invoke(command, {...input, [key]: valid});
    refused(command, {...input, [key]: invalid}, true, 'own/' + key);
  }
  for (const version of [2, '1', 1.5]) refused(command, {...input, schemaVersion: version}, true, 'version');
  invoke(command, {...input, mergeRequiredReceiptIds: ['receipt.test.one'], receiptAdmission: null}, 'failed');
});

test('input pointer selects the described root without changing the structural variant', () => {
  const command = 'repo-profile-admission', input = repoProfile();
  const direct = invoke(command, input);
  const pointed = run(command, {wrapper: {selected: input}}, ['--input-pointer', '/wrapper/selected']);
  assert.equal(pointed.status, 0); assert.equal(pointed.stderr, '');
  assert.deepEqual(JSON.parse(pointed.stdout), direct);
  schema(command, 'input', {wrapper: {selected: input}}, false, 'pointer wrapper is not the described root');
});
