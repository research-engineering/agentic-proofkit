import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport, spawnWithInputFile} from './cli-process.mjs';
import {expandSharedDefinitions} from './schema-definitions.mjs';

// Independently authored expectations for adoption-doctor, scaffold-project-structure
// and scaffold-profile-plan. Expected inventories are never read from the schemas under test.
const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_SCAFFOLD_DOCTOR_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const commands = ['adoption-doctor', 'scaffold-project-structure', 'scaffold-profile-plan'];
const invalidWhen = '--agent-envelope after command admission rejects decoded input; JSON framing and argument errors use stderr';
const identities = {
  'adoption-doctor/input': ['proofkit.adoption-doctor.input.v1.json-schema', 'proofkit.adoption-doctor.input.v1', [['01-root', 'default JSON mode']]],
  'adoption-doctor/output': ['proofkit.adoption-doctor.output.v1.json-schema', 'proofkit.adoption-doctor.output.v1',
    [['01-agent-envelope', '--agent-envelope with admitted input'], ['02-report', 'without --agent-envelope'], ['03-invalid-input-envelope', invalidWhen]]],
  'scaffold-project-structure/input': ['proofkit.scaffold-project-structure.input.v2.json-schema', 'proofkit.scaffold-project-structure.input.v2', [['01-root', 'default JSON mode']]],
  'scaffold-project-structure/output': ['proofkit.scaffold-project-structure.output.v1.json-schema', 'proofkit.scaffold-project-structure.output.v1',
    [['01-agent-envelope', '--agent-envelope with admitted input'], ['02-scaffold', 'without --agent-envelope'], ['03-invalid-input-envelope', invalidWhen]]],
  'scaffold-profile-plan/input': ['proofkit.scaffold-profile-plan.input.v1.json-schema', 'proofkit.scaffold-profile-plan.input.v1', [['01-root', 'default JSON mode']]],
  'scaffold-profile-plan/output': ['proofkit.scaffold-profile-plan.output.v1.json-schema', 'proofkit.scaffold-profile-plan.output.v1', [['01-plan', 'default JSON mode']]],
};
const reportKeys = ['diagnostics', 'nonClaims', 'reportId', 'reportKind', 'ruleResults', 'schemaVersion', 'state', 'summary'];
const envelopeKeys = ['actionPlan', 'blockedPreconditions', 'bounds', 'clarificationQuestions', 'commands', 'contextRefs', 'costContract',
  'envelopeId', 'nonClaims', 'omitted', 'receiptRefs', 'routeQuestions', 'schemaVersion', 'sourceReport'];
const outputRoots = {
  'adoption-doctor': [envelopeKeys, reportKeys, envelopeKeys],
  'scaffold-project-structure': [envelopeKeys, ['adoptionWorkflowInput', 'adoptionWorkflowPlan', 'bootstrapReport', 'exitCode', 'materializationManifest', 'repoProfileScaffoldPlan', 'report'], envelopeKeys],
  'scaffold-profile-plan': [['callerRequiredGaps', 'nextCommands', 'nonClaims', 'planId', 'planKind', 'presetId', 'profilePath', 'provenance', 'repoProfileDraft', 'schemaVersion']],
};
// [required, optional, open] by input path; '*' addresses the first array item.
const inputObjects = {
  'adoption-doctor': {
    '': [['blockedPreconditions', 'checkedScope', 'childReports', 'doctorId', 'mode', 'nonClaims', 'ownerRoutes', 'schemaVersion'], ['modernization', 'staleAuthority', 'touchedRuleIds']],
    'ownerRoutes.*': [['owner', 'routeId'], ['commands', 'nativeWitnessRefs', 'nonClaims', 'proofBindingPaths', 'specPaths', 'touchedRuleIds']],
    'modernization': [['candidateBoundaries'], []],
    'modernization.candidateBoundaries.*': [['admissionState', 'boundaryId', 'candidateOwner'], ['affectedPaths', 'blockedPreconditions', 'contractWitnessRefs',
      'nativeWitnessRefs', 'nonClaims', 'observedFacts', 'ownerQuestions', 'proofBindingRefs', 'requirementRefs', 'uncertainties']],
    'childReports.*': [['nonClaim', 'reportId', 'reportKind', 'state', 'summary'], ['evidenceRefs', 'touchedRuleIds']],
    'blockedPreconditions.*': [['nonClaim', 'owner', 'preconditionId', 'reason'], ['evidenceRefs', 'touchedRuleIds']],
    'staleAuthority': [[], ['authoritySurfaces', 'currentPackage', 'forbiddenVocabulary', 'retiredScopes']],
    'staleAuthority.currentPackage': [['name', 'version'], []],
    'staleAuthority.forbiddenVocabulary.*': [['text', 'vocabularyId'], ['replacementText']],
    'staleAuthority.authoritySurfaces.*': [['authorityState', 'owner', 'path', 'surfaceId'], ['evidenceRefs', 'matchedVocabularyIds', 'nonClaims', 'retiredScopeId', 'touchedRuleIds']],
    'staleAuthority.retiredScopes.*': [['allowedVocabularyIds', 'nonClaim', 'pathPrefixes', 'scopeId'], []],
  },
  'scaffold-profile-plan': {
    '': [['nonClaims', 'paths', 'planId', 'repository', 'requirements', 'schemaVersion'], ['commandMatcherHints', 'environmentClasses', 'presetId']],
    'repository': [['name', 'primaryLanguages', 'profilePath', 'rootPackageName'], []],
    'paths': [['bindingPath', 'policyPath', 'routerPath'], ['generatedArtifacts', 'proofLikePaths', 'retiredProofLikePaths', 'specGlobs']],
    'paths.generatedArtifacts.*': [['generator', 'path', 'sourceOfTruth'], []],
    'requirements': [['idPattern'], []],
    'commandMatcherHints.*': [['allowedScripts', 'credentialClass', 'id', 'kind', 'networkPolicy', 'parallelGroup'], []],
  },
  'scaffold-project-structure': {
    '': [['bootstrap', 'nonClaims', 'paths', 'repoProfileScaffold', 'scaffoldId', 'schemaVersion', 'workflow'], []],
    'paths': [['bootstrapInputPath', 'repoProfileScaffoldInputPath', 'workflowInputPath'], [], true],
    'workflow': [['nonClaims', 'scenario', 'workflowId'], [], true],
    'bootstrap': [['bootstrapId', 'budget', 'guidanceMode', 'module', 'nativeWitnesses', 'packageVersionRef', 'paths', 'proofBindingPath', 'repository', 'rollback', 'schemaVersion'],
      ['checkedScope', 'commands', 'nonClaims', 'ownerRoute', 'touchedRuleIds']],
    'bootstrap.paths': [['adoptionGuidancePath', 'adoptionProfilePath', 'witnessPlanInputPath'], ['adoptionReportArtifactPath', 'guidanceReportArtifactPath'], true],
    'bootstrap.module': [['specPath'], ['moduleId', 'requirementIds'], true],
    'bootstrap.repository': [['profilePath'], ['customRuleBoundary', 'primaryLanguages', 'repositoryClass', 'repositoryId', 'verifierCodeCopied'], true],
  },
};
for (const [path, value] of Object.entries(inputObjects['scaffold-profile-plan'])) {
  inputObjects['scaffold-project-structure'][path ? 'repoProfileScaffold.' + path : 'repoProfileScaffold'] = value;
}
// Members whose explicit null is admitted as the native empty or preset default.
const nullableInputs = {
  'adoption-doctor': /^(modernization|staleAuthority|touchedRuleIds|staleAuthority\.(authoritySurfaces|currentPackage|forbiddenVocabulary|retiredScopes)|ownerRoutes\.\d+\.(commands|nativeWitnessRefs|nonClaims|proofBindingPaths|specPaths|touchedRuleIds)|modernization\.candidateBoundaries\.\d+\.(affectedPaths|blockedPreconditions|contractWitnessRefs|nativeWitnessRefs|nonClaims|observedFacts|ownerQuestions|proofBindingRefs|requirementRefs|uncertainties)|(childReports|blockedPreconditions)\.\d+\.(evidenceRefs|touchedRuleIds)|staleAuthority\.forbiddenVocabulary\.\d+\.replacementText|staleAuthority\.authoritySurfaces\.\d+\.(evidenceRefs|matchedVocabularyIds|nonClaims|retiredScopeId|touchedRuleIds))$/,
  'scaffold-profile-plan': /^(presetId|environmentClasses|commandMatcherHints|paths\.(generatedArtifacts|proofLikePaths|retiredProofLikePaths|specGlobs))$/,
  'scaffold-project-structure': /^repoProfileScaffold\.(presetId|environmentClasses|commandMatcherHints|paths\.(generatedArtifacts|proofLikePaths|retiredProofLikePaths|specGlobs))$/,
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
const ajv = new Ajv2020({strict: false, validateFormats: false});
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-scaffold-doctor-contract-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 300000, maxBuffer: 2 << 20,
    env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

function doctor() {
  return {
    schemaVersion: 1, doctorId: 'consumer.adoption-doctor', mode: 'observe', checkedScope: 'touched',
    touchedRuleIds: ['REQ-CONSUMER-001'], nonClaims: ['The consuming repository owns native witness execution.'], blockedPreconditions: [],
    childReports: [{evidenceRefs: ['docs/specs/consumer/requirements.json'], nonClaim: 'Child report state is caller-provided evidence only.',
      reportId: 'consumer.source-admission', reportKind: 'proofkit.requirement-source-admission', state: 'passed',
      summary: 'Requirement source admission passed.', touchedRuleIds: ['REQ-CONSUMER-001']}],
    modernization: {candidateBoundaries: [{admissionState: 'advisory', affectedPaths: ['packages/example/src/index.ts'], blockedPreconditions: [],
      boundaryId: 'consumer.example-boundary', candidateOwner: 'consumer.repository', contractWitnessRefs: [], nativeWitnessRefs: [],
      nonClaims: ['Candidate boundaries are advisory until owner admission.'], observedFacts: ['A cohesive module candidate was observed.'],
      ownerQuestions: ['Should this candidate become a stable requirement owner?'], proofBindingRefs: [], requirementRefs: ['REQ-CONSUMER-001'],
      uncertainties: ['Proof ownership still needs owner review.']}]},
    ownerRoutes: [{commands: [], nativeWitnessRefs: [], nonClaims: ['Owner route evidence is caller-provided.'], owner: 'consumer.repository',
      proofBindingPaths: [], routeId: 'consumer.example-route', specPaths: ['docs/specs/example/requirements.json'], touchedRuleIds: ['REQ-CONSUMER-001']}],
  };
}
function staleAuthority(state = 'retired', path = 'docs/archive/adr.md') {
  return {currentPackage: {name: 'agentic-proofkit', version: '0.1.133'},
    forbiddenVocabulary: [{replacementText: 'agentic-proofkit', text: 'legacy-proofkit-package', vocabularyId: 'legacy.old-proofkit-package'}],
    authoritySurfaces: [{authorityState: state, evidenceRefs: [], matchedVocabularyIds: ['legacy.old-proofkit-package'], nonClaims: ['Caller fact only.'],
      owner: 'consumer.docs', path, retiredScopeId: 'consumer.historical-proofkit', surfaceId: 'consumer.proofkit-adr', touchedRuleIds: ['REQ-CONSUMER-001']}],
    retiredScopes: [{allowedVocabularyIds: ['legacy.old-proofkit-package'], nonClaim: 'Retired scope admits historical evidence only.',
      pathPrefixes: ['docs/archive'], scopeId: 'consumer.historical-proofkit'}]};
}
function richDoctor() {
  const value = doctor();
  value.staleAuthority = staleAuthority();
  value.blockedPreconditions = [{evidenceRefs: ['docs/blocked.md'], nonClaim: 'Caller fact only.', owner: 'consumer.owner',
    preconditionId: 'consumer.blocked', reason: 'External approval is pending.', touchedRuleIds: ['REQ-CONSUMER-001']}];
  return value;
}
function completeDoctor() {
  const value = doctor();
  value.modernization = {candidateBoundaries: []};
  Object.assign(value.ownerRoutes[0], {commands: ['go test ./...'], nativeWitnessRefs: ['internal/example_test.go'], proofBindingPaths: ['proofkit/bindings.json']});
  return value;
}
function profile() {
  return {
    schemaVersion: 1, planId: 'consumer.repo-profile-scaffold', presetId: 'typescript_workspace',
    repository: {name: 'consumer-repo', primaryLanguages: ['go'], profilePath: 'proofkit/repo-profile.json', rootPackageName: 'consumer-repo'},
    paths: {bindingPath: 'proofkit/bindings.json', generatedArtifacts: [], policyPath: 'proofkit/repo-profile.json',
      proofLikePaths: ['docs/specs/review/requirements.json'], retiredProofLikePaths: [], routerPath: 'AGENTS.md', specGlobs: ['docs/specs/**/*.json']},
    requirements: {idPattern: 'REQ-CONSUMER-[0-9]+'}, environmentClasses: ['local-go'],
    commandMatcherHints: [{allowedScripts: ['check'], credentialClass: 'none', id: 'consumer.check', kind: 'bun_repo_script', networkPolicy: 'none', parallelGroup: 'local'}],
    nonClaims: ['Repo profile scaffold fixture does not prove repository facts.'],
  };
}
function bootstrap() {
  return {
    schemaVersion: 1, bootstrapId: 'consumer.bootstrap', packageVersionRef: 'agentic-proofkit@fixture', guidanceMode: 'observe',
    checkedScope: 'none', touchedRuleIds: [], commands: ['go test ./...'], nonClaims: ['Bootstrap fixture does not prove rollout readiness.'],
    proofBindingPath: 'proofkit/bindings.json',
    budget: {copiedVerifierFileCount: 0, customRuleCount: 0, maxAddedSeconds: 10, maxCustomRuleCount: 0, maxProfileLines: 80, maxSetupMinutes: 20, profileLines: 42},
    repository: {customRuleBoundary: 'profile_only', primaryLanguages: ['go'], profilePath: 'proofkit/repo-profile.json',
      repositoryClass: 'go_cli', repositoryId: 'consumer.repository', verifierCodeCopied: false},
    rollback: {disableCommand: 'remove proofkit report', owner: 'repository owner', versionPin: 'agentic-proofkit@fixture'},
    module: {moduleId: 'consumer.module', requirementIds: ['REQ-CONSUMER-001'], specPath: 'docs/specs/review/requirements.json'},
    nativeWitnesses: {commands: [{id: 'consumer.check', schemaVersion: 1, argv: ['go', 'test', './...'], cwd: '.', timeoutMs: 60000,
      networkPolicy: 'none', credentialClass: 'none', cachePolicy: 'read-only', parallelGroup: 'local-go',
      environment: {inherit: 'none', allowlist: [], classes: ['local-go']}, exitCodePolicy: {kind: 'zero', successCodes: [0]}, expectedArtifacts: []}],
    vocabulary: {artifactKinds: ['json'], credentialClasses: ['none'], environmentClasses: ['local-go'], parallelGroups: ['local-go'],
      environmentClassPolicies: [{environmentClass: 'local-go', credentialClasses: ['none'], networkPolicies: ['none'], cachePolicies: ['read-only']}]}},
    paths: {adoptionGuidancePath: 'proofkit/guidance.json', adoptionProfilePath: 'proofkit/adoption.json',
      adoptionReportArtifactPath: 'artifacts/adoption.json', guidanceReportArtifactPath: 'artifacts/guidance.json', witnessPlanInputPath: 'proofkit/witness.json'},
    ownerRoute: {evidencePaths: ['artifacts/adoption.json'], primaryOwner: 'repository owner', proofBindingPaths: ['proofkit/bindings.json'],
      specPaths: ['docs/specs/review/requirements.json']},
  };
}
function scaffold() {
  return {
    schemaVersion: 1, scaffoldId: 'consumer.project-structure', nonClaims: ['Project structure fixture does not write files.'],
    paths: {bootstrapInputPath: 'proofkit/bootstrap.json', repoProfileScaffoldInputPath: 'proofkit/profile-scaffold.json', workflowInputPath: 'proofkit/workflow.json'},
    workflow: {nonClaims: ['Workflow fixture does not execute commands.'], scenario: 'new_repository', workflowId: 'consumer.workflow'},
    repoProfileScaffold: profile(), bootstrap: bootstrap(),
  };
}
const fixtures = {'adoption-doctor': doctor, 'scaffold-project-structure': scaffold, 'scaffold-profile-plan': profile};

const kindOf = value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, replacement) {
  const result = structuredClone(value); at(result, path.slice(0, -1))[path.at(-1)] = replacement; return result;
}
function remove(value, path) {
  const result = structuredClone(value); delete at(result, path.slice(0, -1))[path.at(-1)]; return result;
}
function schema(command, direction, index, value, expected = true, label = '') {
  const check = checks.get(command + '/' + direction)[index].check;
  assert.equal(check(value), expected, `${command}/${direction}/${index}/${label}: ${JSON.stringify(check.errors?.slice(0, 3))}`);
}
// The selection rule: an observed stdout matches exactly the variant its flags and input phase select.
function selected(command, value) {
  return checks.get(command + '/output').map(row => row.check(value)).flatMap((ok, index) => ok ? [index] : []);
}
const pathLauncher = {AGENTIC_PROOFKIT_LAUNCHER_PROFILE: 'path', AGENTIC_PROOFKIT_PYTHON_EXECUTABLE: ''};
function run(command, input, flags = [], global = []) {
  const result = spawnWithInputFile(binary, [...global, command, '--input', '-', ...flags], {
    input: typeof input === 'string' ? input : JSON.stringify(input), encoding: 'utf8', timeout: 20000, maxBuffer: 16 << 20,
    env: {...process.env, ...pathLauncher},
  });
  assertCLITransport(result);
  return result;
}
function invoke(command, input, phase = 'passed', flags = [], global = []) {
  if (typeof input !== 'string' && phase !== 'refused' && phase !== 'repair') schema(command, 'input', 0, input, true, 'admitted-input');
  const result = run(command, input, flags, global);
  if (phase === 'refused') {
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.notEqual(result.stderr, ''); return result;
  }
  assert.equal(result.stderr, '', result.stderr);
  assert.equal(result.status, phase === 'passed' ? 0 : 1, result.stdout.slice(0, 400));
  const value = JSON.parse(result.stdout);
  const envelope = flags.includes('--agent-envelope');
  const index = command === 'scaffold-profile-plan' ? 0 : envelope ? (phase === 'repair' ? 2 : 0) : 1;
  assert.deepEqual(selected(command, value), [index], `${command} variant selection`);
  if (phase === 'repair') {
    assert.equal(value.envelopeId, 'proofkit.agent-envelope.invalid-input');
  } else {
    const state = command === 'scaffold-profile-plan' ? 'passed' : value.sourceReport?.state ?? value.report?.state ?? value.state;
    assert.equal(state, phase);
  }
  return value;
}

test('public identities conserve contract and wire versions and retire root-shape predecessors', () => {
  for (const [key, [definitionId, contractId, variants]] of Object.entries(identities)) {
    const [command, direction] = key.split('/');
    const record = contract.commands.find(row => row.command === command)[direction + 'Contract'];
    assert.equal(record.rootDefinitionRef, definitionId);
    assert.equal(record.contractId, contractId);
    assert.equal(record.schemaVersion, 1);
    const definition = contract.contractDefinitions.find(row => row.definitionId === definitionId);
    assert.equal(record.rootDefinitionDigest, definition.canonicalDigest);
    assert.deepEqual(definition.fieldTree.variants.map(row => [row.variantId, row.when]), variants.map(([id, when]) => [id, [when]]));
    const predecessor = `proofkit.${command}.${direction}.v1.root-shape`;
    assert.equal(contract.contractDefinitions.some(row => row.definitionId === predecessor), false, predecessor);
    assert(!record.compatibilitySummary.some(note => note.includes('root-shape-only')), key + ' kept a root-shape annotation');
  }
  const scaffoldInput = contract.commands.find(row => row.command === 'scaffold-project-structure').inputContract;
  assert(scaffoldInput.compatibilitySummary.includes('Bootstrap rejects secret-shaped keys and values in a detached strict JSON snapshot before decisions or payload emission; wire version is unchanged.'));
  assert.equal(contract.commands.find(row => row.command === 'scaffold-project-structure').outputContract.compatibilitySummary[0],
    'contractSchemaVersion=1 (aggregate; wire headers are defined per variant)');
});

function nodeAt(shape, path) {
  let node = shape;
  for (const part of path ? path.split('.') : []) {
    node = part === '*' ? node.items : node.properties[part];
    if (node.anyOf) node = node.anyOf.find(row => row.type !== 'null');
    if (node.oneOf && node.oneOf.every(row => row.properties?.kind)) node = node.oneOf.find(row => row.properties.kind.const === 'bun_repo_script');
  }
  return node;
}

test('root and nested key inventories are independently owned', () => {
  for (const command of commands) {
    const outputs = checks.get(command + '/output');
    assert.deepEqual(outputs.map(row => Object.keys(row.schema.properties).sort()), outputRoots[command].map(keys => [...keys].sort()), command + ' output roots');
    for (const [index, row] of outputs.entries()) assert.deepEqual([...row.schema.required].sort(), [...outputRoots[command][index]].sort());
    const input = checks.get(command + '/input')[0].schema;
    for (const [path, [required, optional, open]] of Object.entries(inputObjects[command])) {
      const node = nodeAt(input, path);
      // Open objects declare only the members native admission reads with refusal.
      assert.deepEqual(Object.keys(node.properties).sort(), (open ? [...required] : [...required, ...optional]).sort(), command + '/' + path + ' members');
      assert.deepEqual([...(node.required ?? [])].sort(), [...required].sort(), command + '/' + path + ' required');
      assert.equal(node.additionalProperties, Boolean(open), command + '/' + path + ' openness');
    }
  }
});

test('whole public variants conserve success, reporting failure, blocking, repair and refusal', () => {
  invoke('adoption-doctor', doctor());
  invoke('adoption-doctor', doctor(), 'passed', ['--agent-envelope']);
  invoke('adoption-doctor', completeDoctor(), 'passed', [], ['--json-layout', 'compact']);
  const failed = {...doctor(), mode: 'enforce-all', checkedScope: 'all'};
  invoke('adoption-doctor', failed, 'failed'); invoke('adoption-doctor', failed, 'failed', ['--agent-envelope']);
  invoke('adoption-doctor', richDoctor(), 'blocked'); invoke('adoption-doctor', richDoctor(), 'blocked', ['--agent-envelope']);
  invoke('adoption-doctor', '{}', 'repair', ['--agent-envelope']);
  invoke('adoption-doctor', {...doctor(), mode: 'audit'}, 'repair', ['--agent-envelope']);
  invoke('adoption-doctor', '{"schemaVersion":1,"schemaVersion":1}', 'refused', ['--agent-envelope']);
  invoke('adoption-doctor', '{}', 'refused');
  invoke('adoption-doctor', {...doctor(), foreign: true}, 'refused');

  invoke('scaffold-profile-plan', profile());
  invoke('scaffold-profile-plan', profile(), 'passed', [], ['--json-layout', 'compact']);
  invoke('scaffold-profile-plan', '{}', 'refused');
  invoke('scaffold-profile-plan', {...profile(), foreign: true}, 'refused');
  invoke('scaffold-profile-plan', profile(), 'refused', ['--agent-envelope']);

  const passed = invoke('scaffold-project-structure', scaffold());
  assert.equal(passed.exitCode, 0);
  invoke('scaffold-project-structure', scaffold(), 'passed', ['--agent-envelope']);
  const drift = replace(scaffold(), ['repoProfileScaffold', 'paths', 'bindingPath'], 'proofkit/other.json');
  assert.equal(invoke('scaffold-project-structure', drift, 'failed').exitCode, 1);
  invoke('scaffold-project-structure', drift, 'failed', ['--agent-envelope']);
  invoke('scaffold-project-structure', '{}', 'repair', ['--agent-envelope']);
  invoke('scaffold-project-structure', '{"schemaVersion":1,"schemaVersion":1}', 'refused', ['--agent-envelope']);
  invoke('scaffold-project-structure', '{}', 'refused');
  invoke('scaffold-project-structure', {...scaffold(), foreign: true}, 'refused');
  for (const command of commands) {
    // Only JSON output is published; no text variant exists for the schema to claim.
    const result = run(command, fixtures[command](), ['--format', 'text']);
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.match(result.stderr, /unsupported argument/);
    assert.deepEqual(contract.commands.find(row => row.command === command).outputModes, ['json']);
  }
});

// Reused bootstrap members other than the narrowed ones, and undeclared members
// of open objects, keep their own owner's evaluation and oracle.
const narrowedBootstrap = ['bootstrap.paths', 'bootstrap.module', 'bootstrap.repository', 'bootstrap.proofBindingPath'];
function visitInput(command, input, visit) {
  const objects = inputObjects[command];
  const pattern = path => path.map(part => typeof part === 'number' ? '*' : part).join('.');
  function walk(value, path) {
    const key = pattern(path);
    if (key.startsWith('bootstrap.') && !narrowedBootstrap.some(prefix => key === prefix || key.startsWith(prefix + '.'))) return;
    const object = objects[key];
    visit(value, path, object);
    if (value === null || typeof value !== 'object') return;
    for (const [child, item] of Object.entries(value)) {
      if (object?.[2] && !object[0].includes(child)) continue;
      walk(item, [...path, Array.isArray(value) ? Number(child) : child]);
    }
  }
  walk(input, []);
}

function cliVerdict(command, input) {
  const result = run(command, input);
  if (result.status === 1 && result.stdout === '') {
    assert.notEqual(result.stderr, ''); return false;
  }
  assert.equal(result.stderr, ''); JSON.parse(result.stdout); return true;
}

function agree(command, input, label) {
  const structural = checks.get(command + '/input')[0].check(input);
  assert.equal(cliVerdict(command, input), structural, `${command}/${label}: schema=${structural}`);
  return structural;
}

// Removing declared stale-authority vocabularies or scopes leaves admitted
// references dangling; native cross-record admission refuses those inputs.
const nativeOnlyInputs = new Set(['adoption-doctor/missing/staleAuthority.forbiddenVocabulary', 'adoption-doctor/missing/staleAuthority.retiredScopes',
  'adoption-doctor/kind/null/staleAuthority.forbiddenVocabulary', 'adoption-doctor/kind/null/staleAuthority.retiredScopes']);

test('input clause mutants are refused by schema and CLI alike', () => {
  const kinds = [['null', null], ['boolean', false], ['number', 42], ['string', 'wrong-type'], ['array', []], ['object', {}]];
  const verdict = (command, input, label, expected) => {
    const structural = checks.get(command + '/input')[0].check(input);
    assert.equal(structural, expected, `${command}/${label}: schema`);
    const native = nativeOnlyInputs.has(command + '/' + label);
    assert.equal(cliVerdict(command, input), native ? false : structural, `${command}/${label}: CLI`);
    if (native) assert.equal(structural, true, `${command}/${label}: native-only predicate must remain structurally admitted`);
  };
  for (const command of commands) {
    const inputs = command === 'adoption-doctor' ? [doctor(), richDoctor()] : [fixtures[command]()];
    if (command === 'scaffold-profile-plan') {
      const artifacts = profile(); artifacts.paths.generatedArtifacts = [{generator: 'scripts/gen.mjs', path: 'docs/generated.md', sourceOfTruth: ['docs/source.md']}];
      inputs.push(artifacts);
    }
    for (const input of inputs) {
      visitInput(command, input, (value, path, object) => {
        const name = path.join('.');
        if (path.length) {
          for (const [kind, replacement] of kinds) {
            if (kind === kindOf(value)) continue;
            verdict(command, replace(input, path, replacement), 'kind/' + kind + '/' + name, kind === 'null' && nullableInputs[command].test(name));
          }
        }
        if (object) {
          const [required, optional, open] = object;
          verdict(command, replace(input, [...path, 'foreign'], true), 'unknown/' + name, Boolean(open));
          for (const key of Object.keys(value)) {
            if (!required.includes(key) && !optional.includes(key)) continue;
            verdict(command, remove(input, [...path, key]), 'missing/' + (name ? name + '.' : '') + key, optional.includes(key));
          }
        }
      });
    }
  }
});

test('scalar, enum and bound clauses accept exact limits and refuse one beyond', () => {
  const id = (length, prefix = 'A') => prefix + 'a'.repeat(length - prefix.length);
  for (const [command, path] of [['adoption-doctor', ['doctorId']], ['scaffold-profile-plan', ['planId']], ['scaffold-project-structure', ['scaffoldId']],
    ['adoption-doctor', ['ownerRoutes', 0, 'routeId']], ['scaffold-project-structure', ['workflow', 'workflowId']]]) {
    const input = fixtures[command]();
    for (const length of [1, 255, 256]) assert.equal(agree(command, replace(input, path, id(length)), 'id/' + length), true);
    for (const value of [id(257), '', '1bad', 'bad.', 'bad..id', 'bad id']) assert.equal(agree(command, replace(input, path, value), 'id/' + value.slice(0, 8)), false);
  }
  const text = {'adoption-doctor': [['nonClaims', 0], ['childReports', 0, 'summary'], ['ownerRoutes', 0, 'owner']],
    'scaffold-profile-plan': [['nonClaims', 0], ['repository', 'name'], ['requirements', 'idPattern'], ['commandMatcherHints', 0, 'parallelGroup']],
    'scaffold-project-structure': [['nonClaims', 0], ['workflow', 'nonClaims', 0], ['paths', 'workflowInputPath'], ['bootstrap', 'proofBindingPath']]};
  for (const [command, paths] of Object.entries(text)) {
    for (const path of paths) {
      for (const blank of ['', ' ', '\t\n', '\u00a0', '\u2003', '\u3000']) assert.equal(agree(command, replace(fixtures[command](), path, blank), 'blank/' + path.join('.')), false);
    }
  }
  for (const [command, path] of [['scaffold-profile-plan', ['paths', 'routerPath']], ['adoption-doctor', ['ownerRoutes', 0, 'specPaths', 0]],
    ['scaffold-project-structure', ['bootstrap', 'paths', 'adoptionProfilePath']]]) {
    // Untrimmed native paths admit whitespace-only text but never the empty string.
    assert.equal(agree(command, replace(fixtures[command](), path, ' '), 'space-path/' + path.join('.')), true);
    assert.equal(agree(command, replace(fixtures[command](), path, ''), 'empty-path/' + path.join('.')), false);
  }
  const minimumOne = {'adoption-doctor': [['nonClaims']], 'scaffold-profile-plan': [['nonClaims'], ['repository', 'primaryLanguages'], ['paths', 'specGlobs'],
    ['paths', 'proofLikePaths'], ['environmentClasses'], ['commandMatcherHints', 0, 'allowedScripts']],
  'scaffold-project-structure': [['nonClaims'], ['workflow', 'nonClaims']]};
  for (const [command, paths] of Object.entries(minimumOne)) {
    for (const path of paths) assert.equal(agree(command, replace(fixtures[command](), path, []), 'empty-list/' + path.join('.')), false);
  }
  for (const [command, path, values, invalid] of [
    ['adoption-doctor', ['mode'], ['observe', 'warn', 'enforce-touched'], ['audit', 'Observe']],
    ['adoption-doctor', ['checkedScope'], ['touched', 'all'], ['partial', 'TOUCHED']],
    ['adoption-doctor', ['childReports', 0, 'state'], ['blocked', 'failed', 'passed', 'skipped', 'warning'], ['unknown']],
    ['adoption-doctor', ['modernization', 'candidateBoundaries', 0, 'admissionState'], ['advisory', 'owner_admitted'], ['approved']],
    ['scaffold-profile-plan', ['presetId'], ['agentic_runtime_repo', 'generated_docs_contract_repo', 'python_service', 'python_typescript_service', 'typescript_monorepo', 'typescript_workspace'], ['go_service']],
    ['scaffold-profile-plan', ['commandMatcherHints', 0, 'networkPolicy'], ['external', 'loopback', 'none'], ['internet']],
    ['scaffold-profile-plan', ['commandMatcherHints', 0, 'credentialClass'], ['live-cloud', 'live-github', 'local-secret', 'none'], ['root']],
    ['scaffold-project-structure', ['workflow', 'scenario'], ['new_repository'], ['release_channel', 'existing_gradual_adoption']],
  ]) {
    const input = fixtures[command]();
    for (const value of values) {
      const mutant = replace(input, path, value);
      // generated_docs_contract_repo has no docs/specs starter path; explicit specGlobs keep it admitted.
      assert.equal(agree(command, mutant, 'enum/' + value), true);
    }
    for (const value of invalid) assert.equal(agree(command, replace(input, path, value), 'enum/' + value), false);
  }
  // Owner decision C-05: only generated_docs_contract_repo suggests no docs/specs/
  // starter path, so with it an absent or null specGlobs is a caller obligation
  // refused by schema and CLI alike; every other preset supplies the default.
  for (const presetId of ['agentic_runtime_repo', 'generated_docs_contract_repo', 'python_service', 'python_typescript_service', 'typescript_monorepo', 'typescript_workspace']) {
    const callerRequired = presetId === 'generated_docs_contract_repo';
    for (const [label, mutate] of [['omitted', paths => { delete paths.specGlobs; }], ['null', paths => { paths.specGlobs = null; }]]) {
      const mutant = replace(profile(), ['presetId'], presetId);
      mutate(mutant.paths);
      assert.equal(agree('scaffold-profile-plan', mutant, `spec-globs/${presetId}/${label}`), !callerRequired);
      if (callerRequired) assert.match(run('scaffold-profile-plan', mutant).stderr, /paths\.specGlobs must be caller-provided/);
    }
  }
  const input = doctor(); delete input.staleAuthority;
  input.staleAuthority = staleAuthority();
  for (const [path, valid, invalid] of [
    [['staleAuthority', 'authoritySurfaces', 0, 'authorityState'], ['current', 'retired'], ['stale']],
    [['staleAuthority', 'retiredScopes', 0, 'pathPrefixes'], [['docs/archive']], [[]]],
  ]) {
    for (const value of valid) assert.equal(agree('adoption-doctor', replace(input, path, value), 'stale/' + path.at(-1)), true);
    for (const value of invalid) assert.equal(agree('adoption-doctor', replace(input, path, value), 'stale/' + path.at(-1)), false);
  }
  for (const version of [0, 2, 1.5, '1', null, false]) {
    for (const command of commands) assert.equal(agree(command, {...fixtures[command](), schemaVersion: version}, 'version/' + version), false);
  }
});

test('mode and checked-scope relation and matcher list ownership agree with native admission', () => {
  const pairs = [];
  for (const mode of ['enforce-all', 'enforce-touched', 'observe', 'warn']) {
    for (const scope of ['all', 'none', 'touched']) {
      const admitted = agree('adoption-doctor', {...doctor(), mode, checkedScope: scope}, mode + '/' + scope);
      if (admitted) pairs.push(mode + '/' + scope);
    }
  }
  assert.deepEqual(pairs, ['enforce-all/all', 'enforce-touched/all', 'enforce-touched/touched', 'observe/all', 'observe/none', 'observe/touched', 'warn/all', 'warn/none', 'warn/touched']);
  const lists = {allowedArgv: ['go', 'test'], allowedScripts: ['check'], allowedTestPathGlobs: ['tests/**/*.py']};
  const owned = {exact_argv: 'allowedArgv', python_pytest_contract: 'allowedTestPathGlobs', bun_repo_script: 'allowedScripts', bun_workspace_package_script: 'allowedScripts'};
  for (const [kind, member] of Object.entries(owned)) {
    for (let mask = 0; mask < 8; mask++) {
      const matcher = {credentialClass: 'none', id: 'consumer.matcher', kind, networkPolicy: 'none', parallelGroup: 'local'};
      Object.keys(lists).forEach((name, index) => {if (mask & 1 << index) matcher[name] = lists[name];});
      const admitted = agree('scaffold-profile-plan', {...profile(), commandMatcherHints: [matcher]}, kind + '/' + mask);
      assert.equal(admitted, Object.keys(matcher).filter(key => key in lists).join() === member, kind + '/' + mask);
    }
  }
});

function outputArrayRange(command, index, name, value) {
  if (command === 'scaffold-profile-plan') {
    return {callerRequiredGaps: [1, 3], nextCommands: [3, 3], nonClaims: [5, null], provenance: [10, 12], 'repoProfileDraft.nonClaims': [2, 2],
      'repoProfileDraft.proofs.environmentClasses': [1, null], 'repoProfileDraft.proofs.proofLikePaths': [1, null],
      'repoProfileDraft.requirements.specGlobs': [1, null], 'repoProfileDraft.repository.primaryLanguages': [1, null]}[name]
      ?? (/^repoProfileDraft\.commandMatchers\.\d+\.allowed/.test(name) ? [1, null] : undefined);
  }
  if (index !== 1) {
    if (/^actionPlan\.\d+\.evidenceRefs$/.test(name)) return [0, 96];
    if (/^actionPlan\.\d+\.nonClaims$/.test(name)) return [1, null];
    const limits = index === 2
      ? {actionPlan: [1, 1], blockedPreconditions: [1, 1], clarificationQuestions: [1, 1], commands: [0, 0], contextRefs: [0, 0], omitted: [0, 0], receiptRefs: [0, 0], routeQuestions: [3, 3]}
      : command === 'adoption-doctor'
      ? {actionPlan: [1, 24], blockedPreconditions: [0, 12], clarificationQuestions: [0, 1], commands: [0, 24], contextRefs: [0, 48], omitted: [0, 1], receiptRefs: [0, 0], routeQuestions: [3, 3]}
      : {actionPlan: [4, 4], blockedPreconditions: [0, 8], clarificationQuestions: [0, 8], commands: [0, 8], contextRefs: [0, 12], omitted: [0, 1], receiptRefs: [0, 0], routeQuestions: [3, 3]};
    return limits[name] ?? (name === 'nonClaims' ? [1, null] : undefined);
  }
  if (command === 'adoption-doctor') {
    if (name === 'diagnostics') return [6, 6];
    if (name === 'ruleResults') return [1, null];
    // Gap rules carry gapId/phase/touched; the gap-free rule carries none.
    if (/^ruleResults\.\d+\.diagnostics$/.test(name)) return value.length ? [3, 3] : [0, 0];
    return undefined;
  }
  return {'materializationManifest.files': [9, 9], 'materializationManifest.nextCommands': [6, 6], 'materializationManifest.nonClaims': [4, 4],
    'materializationManifest.sourceReports': [3, 3], 'adoptionWorkflowInput.inputRefs': [5, 5], 'adoptionWorkflowPlan.inputRefs': [5, 5],
    'adoptionWorkflowPlan.phases': [7, 7], 'report.diagnostics': [1, 1], 'report.diagnostics.0.value.files': [9, 9], 'report.ruleResults': [1, null]}[name];
}

const closedVocabularies = new Set(['state', 'status', 'kind', 'phase', 'mode', 'checkedScope', 'admissionState', 'authorityState', 'planKind', 'planState',
  'scenario', 'reportKind', 'manifestKind', 'contentKind', 'materializationStatus', 'source', 'inputKind', 'fanout', 'stopReason', 'expectedAnswerKind',
  'missingWitness', 'role', 'fieldPath', 'credentialClass', 'networkPolicy', 'schema', 'key', 'presetId']);
function outputPredicates(command, index, output, label, skip = () => false) {
  const reject = (path, replacement, why) => schema(command, 'output', index, replace(output, path, replacement), false, `${label}/${why}/${path.join('.')}`);
  const kinds = [['null', null], ['boolean', false], ['number', 42], ['string', 'wrong-type'], ['array', []], ['object', {}]];
  const optional = name => /^bounds\.(truncated|referenceClosurePreserved|prunedLocalReferenceCount|boundsViolationCount|boundsViolations)$/.test(name)
    || /^actionPlan\.\d+\.selectors\.(affectedPaths|candidateBoundaryId|contractWitnessRefs|nativeWitnessRefs|ownerRouteId|proofBindingPaths|proofBindingRefs|specPaths)$/.test(name)
    || name === 'diagnostics.5.value.retire-stale-authority' || name === 'adoptionWorkflowInput.presetId';
  const nullable = name => command === 'scaffold-profile-plan' && name === 'presetId';
  const emptyText = name => /(^|\.)reportId$/.test(name) && !name.startsWith('sourceReport') && !name.startsWith('materializationManifest')
    || /^(report\.)?nonClaims\.\d+$/.test(name) && index === 1
    || /^diagnostics\.4\.value\.(currentPackage\.(name|version)|forbiddenVocabulary\.\d+\.replacementText|authoritySurfaces\.\d+\.retiredScopeId)$/.test(name)
    || /^actionPlan\.\d+\.missingWitness$/.test(name);
  function visit(value, path) {
    const name = path.join('.');
    if (skip(name)) return;
    if (path.length) {
      for (const [kind, replacement] of kinds) {
        if (kind === kindOf(value) || kind === 'null' && nullable(name)) continue;
        reject(path, replacement, 'kind/' + kind);
      }
      const key = path.at(-1);
      if (typeof value === 'string') {
        if (closedVocabularies.has(key) || /^(adoptionWorkflowInput|adoptionWorkflowPlan)\.inputRefs\.\d+\.refId$/.test(name)
          || /^callerRequiredGaps\.\d+\.(gapId|owner)$/.test(name) || /^ruleResults\.\d+\.ruleId$/.test(name) || name === 'envelopeId'
          || /^diagnostics\.5\.value\./.test(name) || /^adoptionWorkflowPlan\.phases\.\d+\.commands\.\d+\.owner$/.test(name)) reject(path, 'foreign-fixture-value', 'vocabulary');
        if (/(^|\.)(planId|doctorId|workflowId|boundaryId|surfaceId|scopeId|vocabularyId)$/.test(name) || name === 'sourceReport.reportId') reject(path, '1bad', 'identifier');
        if (/(contentSha256|stableHash)$/.test(key)) for (const wrong of ['sha256:' + 'a'.repeat(63), 'sha256:' + 'A'.repeat(64), 'a'.repeat(64)]) reject(path, wrong, 'digest');
        if (!emptyText(name)) reject(path, '', 'empty-text');
      }
      if (typeof value === 'number') {
        reject(path, -1, 'negative'); reject(path, 0.5, 'fraction'); reject(path, 2 ** 64, 'overflow');
        if (key === 'exitCode') reject(path, 2, 'exit');
        if (key === 'fileCount') {reject(path, 8, 'files'); reject(path, 10, 'files');}
        if (key === 'sourceReportCount') {reject(path, 2, 'sources'); reject(path, 4, 'sources');}
        if (key === 'schemaVersion') {reject(path, 0, 'version'); reject(path, 2, 'version');}
        if (name === 'costContract.graphQueryCount') reject(path, 1, 'graph');
        const costMaximum = {actionEvidenceRefCount: 96, actionItemCount: 24, blockedPreconditionCount: 12, clarificationQuestionCount: 12,
          commandRefCount: 24, loadedRefCount: 48, receiptRecordCount: 24, routeQuestionCount: 12};
        if (path[0] === 'costContract' && key in costMaximum) reject(path, costMaximum[key] + 1, 'cost-bound');
      }
      if (typeof value === 'boolean' && ['costContract.omittedEdgesCounted', 'bounds.truncated', 'bounds.referenceClosurePreserved'].includes(name)) reject(path, !value, 'literal');
      if (Array.isArray(value)) {
        const range = outputArrayRange(command, index, name, value);
        if (range) {
          const [minimum, maximum] = range;
          if (minimum > 0) reject(path, value.slice(0, minimum - 1), 'minimum');
          if (maximum !== null && value.length) reject(path, Array.from({length: maximum + 1}, (_, i) => structuredClone(value[i % value.length])), 'maximum');
        }
        if (value.length && typeof value[0] === 'string') for (const bad of [null, false, 42, [], {}]) reject(path, [bad], 'item-kind');
      }
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      reject([...path, 'foreign'], true, 'closed');
      for (const key of Object.keys(value)) {
        const child = path.length ? name + '.' + key : key;
        if (skip(child) || optional(child)) continue;
        schema(command, 'output', index, remove(output, [...path, key]), false, `${label}/required/${child}`);
      }
    }
    if (value !== null && typeof value === 'object') for (const [key, child] of Object.entries(value)) visit(child, [...path, Array.isArray(value) ? Number(key) : key]);
  }
  visit(output, []);
}

test('output carriers refuse structural drift in every reachable variant', () => {
  const reused = name => /^(bootstrapReport|repoProfileScaffoldPlan)(\.|$)/.test(name);
  const doctorInputs = {observe: doctor(), complete: completeDoctor(), blocked: richDoctor(), failed: {...richDoctor(), mode: 'enforce-all', checkedScope: 'all', blockedPreconditions: []}};
  doctorInputs.failed.staleAuthority = staleAuthority('current', 'docs/adr.md');
  for (const [label, input] of Object.entries(doctorInputs)) {
    const phase = label === 'observe' || label === 'complete' ? 'passed' : label;
    outputPredicates('adoption-doctor', 1, invoke('adoption-doctor', input, phase), label);
    outputPredicates('adoption-doctor', 0, invoke('adoption-doctor', input, phase, ['--agent-envelope']), label + '-envelope');
  }
  outputPredicates('adoption-doctor', 2, invoke('adoption-doctor', '{}', 'repair', ['--agent-envelope']), 'repair');
  const generated = profile(); generated.paths.generatedArtifacts = [{generator: 'scripts/gen.mjs', path: 'docs/generated.md', sourceOfTruth: ['docs/source.md']}];
  for (const [label, input] of Object.entries({profile: profile(), generated, defaults: {...profile(), commandMatcherHints: [], presetId: null}})) {
    outputPredicates('scaffold-profile-plan', 0, invoke('scaffold-profile-plan', input), label);
  }
  const blocked = scaffold(); delete blocked.repoProfileScaffold.presetId;
  for (const [label, input, phase] of [['scaffold', scaffold(), 'passed'], ['blocked-workflow', blocked, 'failed']]) {
    outputPredicates('scaffold-project-structure', 1, invoke('scaffold-project-structure', input, phase), label, reused);
    outputPredicates('scaffold-project-structure', 0, invoke('scaffold-project-structure', input, phase, ['--agent-envelope']), label + '-envelope');
  }
  outputPredicates('scaffold-project-structure', 2, invoke('scaffold-project-structure', '{}', 'repair', ['--agent-envelope']), 'repair');
});

test('reachable native states and degradation stay inside the published unions', () => {
  const seen = new Set();
  const doctorStates = [];
  for (const mode of ['observe', 'warn', 'enforce-touched', 'enforce-all']) {
    for (const child of ['passed', 'failed', 'blocked', 'skipped', 'warning']) {
      const input = richDoctor(); input.mode = mode; input.checkedScope = mode === 'enforce-all' ? 'all' : 'touched';
      input.childReports[0].state = child; input.staleAuthority = staleAuthority(child === 'warning' ? 'current' : 'retired', child === 'warning' ? 'docs/adr.md' : 'docs/archive/adr.md');
      if (child !== 'blocked') input.blockedPreconditions = [];
      doctorStates.push(input);
    }
  }
  const sparse = completeDoctor(); sparse.staleAuthority = {forbiddenVocabulary: [{text: 'legacy', vocabularyId: 'legacy.term'}],
    authoritySurfaces: [{authorityState: 'retired', owner: 'docs', path: 'docs/old.md', surfaceId: 'consumer.surface', matchedVocabularyIds: ['legacy.term']}]};
  const noRoutes = {...doctor(), ownerRoutes: [], mode: 'enforce-touched'};
  const overlap = doctor(); overlap.modernization.candidateBoundaries[0].boundaryId = 'consumer.example-route.boundary';
  const degraded = doctor(); Object.assign(degraded.ownerRoutes[0], {routeId: 'consumer.' + 'r'.repeat(240), commands: ['go test ./...'], specPaths: ['docs/spec\u202e.md']});
  const redacted = {...doctor(), doctorId: 'eyJfixture.owner'};
  const many = {...doctor(), checkedScope: 'all', ownerRoutes: Array.from({length: 30}, (_, i) => ({owner: 'owner', routeId: `consumer.route-${String(i).padStart(2, '0')}`,
    specPaths: [`docs/spec-${String(i).padStart(2, '0')}.md`]}))};
  doctorStates.push(completeDoctor(), {...completeDoctor(), mode: 'enforce-all', checkedScope: 'all'}, sparse, noRoutes, overlap, degraded, redacted, many);
  for (const input of doctorStates) {
    const report = run('adoption-doctor', input);
    assert.equal(report.stderr, ''); const value = JSON.parse(report.stdout);
    assert.deepEqual(selected('adoption-doctor', value), [1]);
    assert.equal(report.status === 0, value.state === 'passed');
    seen.add('state/' + value.state);
    for (const rule of value.ruleResults) seen.add('status/' + rule.status);
    for (const [key, status] of Object.entries(value.diagnostics[5].value)) seen.add(`readiness/${key}/${status}`);
    for (const gap of value.diagnostics[1].value) seen.add('kind/' + gap.kind);
    const envelopeRun = run('adoption-doctor', input, ['--agent-envelope']);
    assert.equal(envelopeRun.stderr, ''); const envelope = JSON.parse(envelopeRun.stdout);
    assert.deepEqual(selected('adoption-doctor', envelope), [0], 'doctor envelope selection');
    assert.equal(envelope.sourceReport.reportId, value.reportId); assert.equal(envelope.sourceReport.state, value.state);
    assert.equal(envelopeRun.status, report.status);
    seen.add('omitted/' + envelope.omitted.length); seen.add('actions/' + Math.min(envelope.actionPlan.length, 24));
    if (envelope.envelopeId === '<redacted-diagnostic-value>') seen.add('envelope/redacted');
    if (envelope.bounds.boundsViolations) seen.add('bounds/violations');
    for (const action of envelope.actionPlan) {
      const route = action.selectors.ownerRouteId !== undefined; const candidate = action.selectors.candidateBoundaryId !== undefined;
      if (route || candidate) seen.add(route && candidate ? 'selectors/both' : route ? 'selectors/route' : 'selectors/candidate');
    }
  }
  for (const want of ['state/passed', 'state/failed', 'state/blocked', 'status/passed', 'status/failed', 'status/blocked', 'status/skipped', 'status/warning',
    'readiness/retire-stale-authority/blocked', 'readiness/promote/ready_for_owner_review', 'readiness/route/blocked_missing_owner_route',
    'kind/child_report_warning', 'kind/stale_authority_current_vocabulary', 'kind/stale_authority_retired_scope', 'omitted/1', 'actions/24',
    'envelope/redacted', 'bounds/violations', 'selectors/route', 'selectors/candidate']) assert(seen.has(want), 'unreached doctor domain ' + want);
  // Selectors come from the gap's exact owning record: the prefix-related overlap fixture must not give one action both selector sets.
  assert(!seen.has('selectors/both'), 'one doctor action carried both route and candidate selectors');
  const marker = run('adoption-doctor', redacted, ['--agent-envelope']);
  const value = JSON.parse(marker.stdout);
  schema('adoption-doctor', 'output', 0, {...value, envelopeId: 'foreign-fixture-value'}, false, 'redaction');
  schema('adoption-doctor', 'output', 0, {...value, envelopeId: 'consumer.other.agent-envelope'}, true, 'suffix');
  const scaffoldStates = {passed: scaffold()};
  scaffoldStates.otherProfile = replace(scaffold(), ['repoProfileScaffold', 'repository', 'profilePath'], 'proofkit/other-profile.json');
  scaffoldStates.replacedPayload = replace(scaffold(), ['repoProfileScaffold', 'repository', 'profilePath'], 'proofkit/adoption.json');
  scaffoldStates.failedBootstrap = replace(scaffold(), ['bootstrap', 'guidanceMode'], 'warn');
  scaffoldStates.unsafe = replace(replace(scaffold(), ['bootstrap', 'module', 'specPath'], 'docs/spec\u202e.md'), ['bootstrap', 'ownerRoute', 'specPaths'], ['docs/spec\u202e.md']);
  scaffoldStates.redacted = {...scaffold(), scaffoldId: 'eyJfixture.owner'};
  scaffoldStates.blocked = scaffold(); delete scaffoldStates.blocked.repoProfileScaffold.presetId;
  for (const [label, input] of Object.entries(scaffoldStates)) {
    const plain = run('scaffold-project-structure', input); assert.equal(plain.stderr, '', label);
    const value = JSON.parse(plain.stdout); assert.deepEqual(selected('scaffold-project-structure', value), [1], label);
    seen.add(`scaffold/${value.report.state}/${value.materializationManifest.payloadFileCount}/${value.adoptionWorkflowPlan.planState}/${value.bootstrapReport.report.state}`);
    const envelopeRun = run('scaffold-project-structure', input, ['--agent-envelope']); assert.equal(envelopeRun.stderr, '');
    const envelope = JSON.parse(envelopeRun.stdout); assert.deepEqual(selected('scaffold-project-structure', envelope), [0], label + '/envelope');
    seen.add('scaffold-omitted/' + envelope.omitted.length);
    if (envelope.envelopeId === '<redacted-diagnostic-value>') seen.add('scaffold/redacted');
  }
  for (const want of ['scaffold/passed/8/ready_for_caller_review/passed', 'scaffold/failed/7/ready_for_caller_review/passed', 'scaffold/failed/8/blocked/passed',
    'scaffold/failed/8/ready_for_caller_review/failed', 'scaffold-omitted/1', 'scaffold/redacted']) assert(seen.has(want), 'unreached scaffold domain ' + want);
});

test('reachable envelope limits are exact at the bound and refuse one beyond', () => {
  for (const count of [11, 12, 13]) {
    const input = completeDoctor();
    input.blockedPreconditions = Array.from({length: count}, (_, i) => ({nonClaim: 'Caller fact.', owner: 'owner',
      preconditionId: `consumer.blocked-${String(i).padStart(2, '0')}`, reason: 'External input.'}));
    const value = invoke('adoption-doctor', input, 'blocked', ['--agent-envelope']);
    assert.equal(value.blockedPreconditions.length, Math.min(count, 12));
    schema('adoption-doctor', 'output', 0, {...value, blockedPreconditions: [...value.blockedPreconditions, value.blockedPreconditions[0]].slice(0, 13)}, count < 12, 'blocked/' + count);
  }
  for (const count of [23, 24, 25]) {
    const input = {...completeDoctor(), checkedScope: 'all', ownerRoutes: Array.from({length: count}, (_, i) => ({owner: 'owner',
      routeId: `consumer.route-${String(i).padStart(2, '0')}`, commands: ['go test ./...'], nativeWitnessRefs: ['tests/a_test.go'], proofBindingPaths: ['proofkit/b.json'],
      specPaths: [`docs/spec-${String(i).padStart(2, '0')}.md`]}))};
    const value = invoke('adoption-doctor', input, 'passed', ['--agent-envelope']);
    assert.equal(value.commands.length, Math.min(count, 24));
    carrierBound(value, 'commands', 24);
  }
  for (const count of [16, 17]) {
    const input = {...completeDoctor(), checkedScope: 'all', ownerRoutes: Array.from({length: count}, (_, i) => ({owner: 'owner',
      routeId: `consumer.route-${String(i).padStart(2, '0')}`, commands: ['go test ./...'], nativeWitnessRefs: ['tests/a_test.go'], proofBindingPaths: ['proofkit/b.json'],
      specPaths: [`docs/spec-${String(i).padStart(2, '0')}.md`]}))};
    const value = invoke('adoption-doctor', input, 'passed', ['--agent-envelope']);
    assert.equal(value.contextRefs.length, Math.min(count * 3, 48));
    carrierBound(value, 'contextRefs', 48);
  }
  for (const count of [24, 25]) {
    const input = {...doctor(), checkedScope: 'all', ownerRoutes: Array.from({length: count}, (_, i) => ({owner: 'owner',
      routeId: `consumer.route-${String(i).padStart(2, '0')}`, commands: ['go test ./...'], nativeWitnessRefs: ['tests/a_test.go'], specPaths: [`docs/spec-${String(i).padStart(2, '0')}.md`]}))};
    const value = invoke('adoption-doctor', input, 'passed', ['--agent-envelope']);
    assert.equal(value.actionPlan.length, 24);
    carrierBound(value, 'actionPlan', 24);
  }
  function carrierBound(value, field, maximum) {
    const item = value[field][0];
    schema('adoption-doctor', 'output', 0, {...value, [field]: Array.from({length: maximum}, () => structuredClone(item))}, true, field + '/max');
    schema('adoption-doctor', 'output', 0, {...value, [field]: Array.from({length: maximum + 1}, () => structuredClone(item))}, false, field + '/max+1');
  }
  const evidence = invoke('adoption-doctor', {...doctor(), checkedScope: 'all', ownerRoutes: [{owner: 'owner', routeId: 'consumer.route',
    specPaths: Array.from({length: 97}, (_, i) => `docs/spec-${String(i).padStart(3, '0')}.md`)}]}, 'passed', ['--agent-envelope']);
  const total = evidence.actionPlan.reduce((sum, action) => sum + action.evidenceRefs.length, 0);
  assert(total <= 96 && evidence.omitted.length === 1, 'action evidence refs are bounded with one omission record');
  const action = evidence.actionPlan.findIndex(row => row.evidenceRefs.length > 0);
  const refs = Array.from({length: 96}, (_, i) => `docs/spec-${String(i).padStart(3, '0')}.md`);
  schema('adoption-doctor', 'output', 0, replace(evidence, ['actionPlan', action, 'evidenceRefs'], refs), true, 'evidence/96');
  schema('adoption-doctor', 'output', 0, replace(evidence, ['actionPlan', action, 'evidenceRefs'], [...refs, 'docs/extra.md']), false, 'evidence/97');
  const ids = [256, 257].map(length => 'A' + 'a'.repeat(length - 1));
  const plan = invoke('scaffold-profile-plan', profile());
  schema('scaffold-profile-plan', 'output', 0, {...plan, planId: ids[0]}, true, 'plan-id/256');
  schema('scaffold-profile-plan', 'output', 0, {...plan, planId: ids[1]}, false, 'plan-id/257');
});

test('whole chains reuse the producing commands and their published structures', () => {
  const input = scaffold();
  const value = invoke('scaffold-project-structure', input);
  const outputSchema = checks.get('scaffold-project-structure/output')[1].schema;
  const reusedDefinition = (command, direction, index) => {
    const ref = contract.commands.find(row => row.command === command)[direction + 'Contract'].rootDefinitionRef;
    return expandSharedDefinitions(contract.contractDefinitions.find(row => row.definitionId === ref).fieldTree.variants[index].schema);
  };
  assert.deepEqual(outputSchema.properties.bootstrapReport, reusedDefinition('gradual-adoption-bootstrap', 'output', 0));
  assert.deepEqual(outputSchema.properties.repoProfileScaffoldPlan, reusedDefinition('scaffold-profile-plan', 'output', 0));
  const inputSchema = checks.get('scaffold-project-structure/input')[0].schema;
  assert.deepEqual(inputSchema.properties.repoProfileScaffold, reusedDefinition('scaffold-profile-plan', 'input', 0));
  const standaloneBootstrap = reusedDefinition('gradual-adoption-bootstrap', 'input', 0);
  for (const [key, member] of Object.entries(standaloneBootstrap.properties)) {
    if (!['module', 'paths', 'proofBindingPath', 'repository'].includes(key)) assert.deepEqual(inputSchema.properties.bootstrap.properties[key], member, 'bootstrap/' + key);
  }
  const plan = invoke('scaffold-profile-plan', input.repoProfileScaffold);
  assert.deepEqual(value.repoProfileScaffoldPlan, plan);
  const bootstrapRun = run('gradual-adoption-bootstrap', input.bootstrap);
  assert.equal(bootstrapRun.status, 0); assert.equal(bootstrapRun.stderr, '');
  assert.deepEqual(value.bootstrapReport, JSON.parse(bootstrapRun.stdout));
  const workflow = spawnWithInputFile(binary, ['adoption-workflow-plan', '--input', '-', '--input-pointer', '/adoptionWorkflowInput'], {
    input: JSON.stringify(value), encoding: 'utf8', timeout: 20000, env: {...process.env, ...pathLauncher}});
  assert.equal(workflow.status, 0, workflow.stderr); assert.equal(workflow.stderr, '');
  assert.deepEqual(JSON.parse(workflow.stdout), value.adoptionWorkflowPlan);
  const files = Object.fromEntries(value.materializationManifest.files.map(file => [file.path, file]));
  assert.deepEqual(JSON.parse(files[input.paths.repoProfileScaffoldInputPath].content), input.repoProfileScaffold);
  assert.deepEqual(JSON.parse(files[input.paths.bootstrapInputPath].content), input.bootstrap);
  assert.deepEqual(JSON.parse(files[input.paths.workflowInputPath].content), value.adoptionWorkflowInput);
  assert.deepEqual(JSON.parse(files[input.repoProfileScaffold.repository.profilePath].content), value.repoProfileScaffoldPlan.repoProfileDraft);
  for (const path of [input.paths.repoProfileScaffoldInputPath, input.paths.bootstrapInputPath]) {
    const replay = spawnWithInputFile(binary, [path === input.paths.bootstrapInputPath ? 'gradual-adoption-bootstrap' : 'scaffold-profile-plan', '--input', '-'],
      {input: files[path].content, encoding: 'utf8', timeout: 20000, env: {...process.env, ...pathLauncher}});
    assert.equal(replay.status, 0, replay.stderr);
  }
  const envelope = invoke('scaffold-project-structure', input, 'passed', ['--agent-envelope']);
  assert.equal(envelope.sourceReport.reportId, value.report.reportId);
  assert.equal(envelope.sourceReport.state, value.report.state);
  assert.deepEqual(envelope.contextRefs.map(ref => ref.ref).sort(), value.materializationManifest.files.map(file => file.path).sort());
  const doctorReport = invoke('adoption-doctor', doctor());
  const doctorEnvelope = invoke('adoption-doctor', doctor(), 'passed', ['--agent-envelope']);
  assert.equal(doctorEnvelope.sourceReport.reportId, doctorReport.reportId);
  assert.equal(doctorEnvelope.sourceReport.reportKind, doctorReport.reportKind);
  assert.equal(doctorEnvelope.actionPlan.length, doctorReport.diagnostics[1].value.length);
});

test('described finite enums retain the independently authored owner vocabulary', () => {
  const states = {doctor: ['blocked', 'failed', 'passed'], child: ['blocked', 'failed', 'passed', 'skipped', 'warning']};
  const domains = {
    mode: ['enforce-all', 'enforce-touched', 'observe', 'warn'], checkedScope: ['all', 'none', 'touched'], admissionState: ['advisory', 'owner_admitted'],
    authorityState: ['current', 'retired'], credentialClass: ['live-cloud', 'live-github', 'local-secret', 'none'], networkPolicy: ['external', 'loopback', 'none'],
    presetId: ['agentic_runtime_repo', 'generated_docs_contract_repo', 'python_service', 'python_typescript_service', 'typescript_monorepo', 'typescript_workspace'],
    fanout: ['bounded', 'full-gate', 'wide', 'wide_or_full_gate_required'], stopReason: ['blocked_precondition', 'caller_review_required', 'wide_or_full_gate_required'],
    phase: ['bind', 'modernize-boundary', 'retire-stale-authority', 'route', 'verify'],
    missingWitness: ['', 'candidate_witness_not_admitted', 'missing_native_witness', 'missing_owner_route', 'missing_proof_binding'],
    source: ['bootstrap_manifest', 'project_scaffold', 'repo_profile_scaffold', 'caller_input', 'stack_preset'],
    role: ['command_registry', 'owner_surface', 'proof_binding', 'router', 'spec_source', 'supporting'],
    kind: ['candidate_boundary', 'owner_route', 'stale_authority_surface', 'blocked_precondition', 'candidate_boundary_not_admitted', 'child_report_blocked',
      'child_report_failed', 'child_report_skipped', 'child_report_warning', 'missing_command_route', 'missing_native_witness', 'missing_owner_route',
      'missing_proof_binding', 'stale_authority_current_vocabulary', 'stale_authority_retired_scope'],
    planState: ['blocked', 'ready_for_caller_review'], status: ['blocked', 'failed', 'skipped', 'warning'],
    fieldPath: ['commandMatchers', 'documents.generatedArtifacts', 'documents.policyPath', 'documents.routerPath', 'proofs.bindingPath', 'proofs.environmentClasses',
      'proofs.proofLikePaths', 'repository.name', 'repository.primaryLanguages', 'repository.rootPackageName', 'requirements.idPattern', 'requirements.specGlobs'],
    bind: ['blocked', 'caller_review_required'], verify: ['blocked', 'caller_review_required'], 'modernize-boundary': ['blocked', 'caller_review_required', 'ready_for_owner_review'],
    promote: ['not_ready', 'ready_for_owner_review'], route: ['blocked_missing_owner_route', 'ready_for_owner_review'],
  };
  const ruleIds = domains.kind.slice(3).map(kind => 'proofkit.adoption-doctor.' + kind);
  for (const command of commands) for (const direction of ['input', 'output']) {
    for (const [index, {schema: shape}] of checks.get(command + '/' + direction).entries()) {
      function visit(node, path) {
        if (!node || typeof node !== 'object') return;
        const joined = path.join('/');
        if (/properties\/(bootstrap|bootstrapReport|repoProfileScaffold|repoProfileScaffoldPlan)(\/|$)/.test(joined) && command === 'scaffold-project-structure') return;
        if (node.enum) {
          const key = path[path.lastIndexOf('properties') + 1];
          let expected = domains[key];
          if (key === 'state') expected = direction === 'input' ? states.child : command === 'adoption-doctor' ? states.doctor : ['failed', 'passed'];
          if (key === 'ruleId') expected = ruleIds;
          // The only enumerated rule diagnostic value is the gap phase.
          if (key === 'value' && command === 'adoption-doctor' && joined.includes('ruleResults')) expected = domains.phase;
          if (key === 'reportKind') expected = [command === 'adoption-doctor' ? 'proofkit.adoption-doctor' : 'proofkit.project-structure-scaffold'];
          if (key === 'items' || key === undefined) expected = undefined;
          // Owner decision C-05: the root not clause names exactly the presets
          // whose starter paths suggest no docs/specs/ spec source.
          if (key === 'presetId' && path[0] === 'not') expected = ['generated_docs_contract_repo'];
          assert(expected, `${command}/${direction}/${index}/${joined}: enum needs an independent owner domain`);
          assert.deepEqual(node.enum.filter(value => !expected.includes(value)), [], `${command}/${direction}/${index}/${joined}: enum outside owner domain`);
          // Root oneOf fragments project the native mode/scope relation as subsets.
          if (!['source', 'kind', 'status', 'state', 'missingWitness', 'phase'].includes(key) && path[0] !== 'oneOf') assert.deepEqual(node.enum, [...expected].sort(), `${command}/${direction}/${index}/${joined}: exact enum`);
        }
        for (const [key, value] of Object.entries(node)) visit(value, [...path, key]);
      }
      visit(shape, []);
    }
  }
  const report = checks.get('adoption-doctor/output')[1].schema;
  const gap = report.properties.diagnostics.prefixItems[1].properties.value.items;
  assert.deepEqual(gap.properties.kind.enum, domains.kind.slice(3));
  assert.deepEqual(gap.properties.phase.enum, domains.phase);
  const rules = report.properties.ruleResults.items.oneOf;
  assert.deepEqual(rules[1].properties.status.enum, domains.status);
  assert.equal(rules[0].properties.ruleId.const, 'proofkit.adoption-doctor.no-gaps');
});

test('isolated schema controls falsify widened optionality, relations and closed carriers', () => {
  const compile = value => ajv.compile(value);
  const doctorInput = structuredClone(checks.get('adoption-doctor/input')[0].schema);
  const relationFree = structuredClone(doctorInput); delete relationFree.oneOf;
  const invalidPair = {...doctor(), mode: 'enforce-all', checkedScope: 'touched'};
  schema('adoption-doctor', 'input', 0, invalidPair, false, 'relation');
  assert.equal(compile(relationFree)(invalidPair), true, 'mode/scope control did not distinguish the relation');
  const profileInput = structuredClone(checks.get('scaffold-profile-plan/input')[0].schema);
  const requirePreset = structuredClone(profileInput); requirePreset.required.push('presetId');
  const noPreset = profile(); delete noPreset.presetId;
  schema('scaffold-profile-plan', 'input', 0, noPreset);
  assert.equal(compile(requirePreset)(noPreset), false, 'optional preset control survived');
  const scaffoldInput = structuredClone(checks.get('scaffold-project-structure/input')[0].schema);
  const closedWorkflow = structuredClone(scaffoldInput); closedWorkflow.properties.workflow.additionalProperties = false;
  const extraWorkflow = replace(scaffold(), ['workflow', 'foreign'], true);
  schema('scaffold-project-structure', 'input', 0, extraWorkflow);
  assert.equal(compile(closedWorkflow)(extraWorkflow), false, 'open workflow control survived');
  const output = invoke('scaffold-project-structure', scaffold());
  const omitPlan = structuredClone(checks.get('scaffold-project-structure/output')[1].schema);
  delete omitPlan.properties.adoptionWorkflowPlan.properties.phases;
  assert.equal(compile(omitPlan)(output), false, 'closed workflow plan control survived');
});
