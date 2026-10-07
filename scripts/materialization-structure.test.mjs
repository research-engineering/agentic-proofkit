import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_MATERIALIZATION_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const requestSeed = JSON.parse(readFileSync(new URL('internal/app/testdata/materialization-native-request.v2.json', root)));
const directions = [['repository-inventory', 'output'], ['adopt-plan', 'output'],
  ['adopt-materialize-plan', 'input'], ['adopt-materialize-plan', 'output'],
  ['adopt-materialize-apply', 'input'], ['adopt-materialize-apply', 'output'], ['adopt-materialize-recover', 'output']];
const checks = new Map(directions.map(([command, direction]) => {
  const ref = contract.commands.find(row => row.command === command)[direction + 'Contract'].rootDefinitionRef;
  const definition = contract.contractDefinitions.find(row => row.definitionId === ref);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema');
  return [command + '/' + direction, new Ajv2020({strict: false, validateFormats: false})
    .compile({oneOf: definition.fieldTree.variants.map(row => row.schema)})];
}));
let directory, binary, rootCount = 0;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-materialization-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 120000, env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
function repository() {
  const path = join(directory, 'repository-' + rootCount++);
  mkdirSync(path); writeFileSync(join(path, 'README.md'), '# Pilot\n');
  return path;
}
function native(command, repo, value, flags = [], executable = binary) {
  const descriptor = contract.commands.find(row => row.command === command);
  const argv = [...(descriptor.route ?? [command]), '--repo-root', repo, ...flags];
  if (value !== undefined) argv.push('--input', '-');
  const result = spawnSync(executable, argv, {input: value === undefined ? undefined : JSON.stringify(value),
    encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20});
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  return result;
}
function validates(command, direction, value, expected = true, label = '') {
  const check = checks.get(command + '/' + direction);
  assert.equal(check(value), expected, `${command}/${direction}/${label}: ${JSON.stringify(check.errors)}`);
}
function report(command, result, exit = 0) {
  assert.equal(result.status, exit, result.stderr); assert.equal(result.stderr, '');
  const value = JSON.parse(result.stdout); validates(command, 'output', value); return value;
}
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replaced(value, path, next) {
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = next; return copy;
}
function walk(value, path = [], result = []) {
  result.push({path, value});
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
    walk(child, [...path, Array.isArray(value) ? Number(key) : key], result);
  }
  return result;
}
function closedObjectsAndDigests(command, direction, record) {
  for (const {path, value} of walk(record)) {
    const reusedCandidate = direction === 'input' && (path[0] === 'requirementSources'
      || path[1] === 'record' && ['requirementProofBinding', 'testEvidenceInventory'].includes(path[0]));
    if (value && !Array.isArray(value) && typeof value === 'object') {
      const copy = structuredClone(record); at(copy, path).foreign = true;
      validates(command, direction, copy, false, path + '/foreign');
      if (!reusedCandidate) for (const key of Object.keys(value)) {
        const missing = structuredClone(record); delete at(missing, path)[key];
        validates(command, direction, missing, false, path + '/' + key + '/missing');
      }
    }
    if (path.length && !reusedCandidate) {
      const dotted = path.join('.'), nested = path[0] === 'sourcePlan' ? path.slice(1).join('.') : dotted;
      if (nested === 'summary.codeBaselineDeclared') {
        validates(command, direction, replaced(record, path, !value), false, path + '/opposite-boolean');
      }
      const nullable = value === null || ['stackHint', 'summary.selectedStackPreset', 'failureClass', 'transactionResult'].includes(nested)
        || /^transactionResult\.(appliedCount|failureClass|recoveredBy|transactionId)$/.test(dotted);
      validates(command, direction, replaced(record, path, null), nullable, path + '/null');
      validates(command, direction, replaced(record, path, typeof value === 'string' || value === null ? 0 : 'wrong-type'), false, path + '/type');
      const literal = ['authority', 'planKind', 'inventoryKind', 'policyId', 'syntaxState', 'repositoryRootState', 'versionControlState', 'intent', 'declarationClass',
        'capabilityMapTrustMode', 'packetKind', 'commandId', 'instruction', 'order', 'outputKind', 'owner', 'taskId',
        'slotCount', 'guidanceId', 'requestKind', 'receiptKind', 'operation', 'state', 'sourceIntent',
        'generatedBindingCount', 'generatedRequirementCount', 'proposedBindingCount', 'proposedRequirementCount'].includes(path.at(-1))
        || ['class', 'role', 'path'].includes(path.at(-1)) && (command === 'repository-inventory' || path.includes('repositoryInventory'));
      if (value !== null && literal) validates(command, direction, replaced(record, path, typeof value === 'number' ? 99 : 'foreign'), false, path + '/literal');
    }
    if (path[0] !== 'manifest' && typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value)) {
      for (const digest of ['sha256:' + 'a'.repeat(63), 'sha256:' + 'a'.repeat(65), 'sha256:' + 'A'.repeat(64), 'sha256:' + 'g'.repeat(64)]) {
        validates(command, direction, replaced(record, path, digest), false, path + '/digest');
      }
      const fixedGuidanceDigest = path.at(-1) === 'contentSha256' && path.at(-2) === 'nativeEvidenceGuidance';
      validates(command, direction, replaced(record, path, 'sha256:' + '0'.repeat(64)), !fixedGuidanceDigest, path + '/valid-width');
    }
  }
}

test('all intent and stack plans preserve actual hierarchical CLI streams and nested owners', () => {
  const repo = repository();
  const inventory = report('repository-inventory', native('repository-inventory', repo));
  closedObjectsAndDigests('repository-inventory', 'output', inventory);
  const presets = ['agentic_runtime_repo', 'generated_docs_contract_repo', 'python_service',
    'python_typescript_service', 'typescript_monorepo', 'typescript_workspace'];
  for (const mode of ['fresh', 'code-baseline', 'audit-from-code']) for (const preset of ['', ...presets]) {
    for (const format of ['json', 'text']) {
      const flags = ['--mode', mode, '--format', format, ...(preset ? ['--stack', preset] : [])];
      const result = native('adopt-plan', repo, undefined, flags);
      assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
      if (process.env.PROOFKIT_MATERIALIZATION_BASELINE) {
        const old = native('adopt-plan', repo, undefined, flags, process.env.PROOFKIT_MATERIALIZATION_BASELINE);
        assert.deepEqual([result.status, result.stdout, result.stderr], [old.status, old.stdout, old.stderr]);
      }
      if (format === 'text') continue;
      const plan = report('adopt-plan', result);
      assert.equal(plan.intent, mode); assert.deepEqual(plan.repositoryInventory, inventory);
      assert.equal(plan.summary.taskCount, mode === 'fresh' ? 3 : 4);
      assert.equal(plan.summary.selectedStackPreset, preset || null);
      assert.equal(plan.stackHint?.presetId ?? null, preset || null);
      closedObjectsAndDigests('adopt-plan', 'output', plan);
      for (const change of ['short', 'long', 'reordered']) {
        const copy = structuredClone(plan), tasks = copy.authoringPacket.tasks;
        if (change === 'short') tasks.pop();
        else if (change === 'long') tasks.push(structuredClone(tasks[0]));
        else [tasks[0], tasks[1]] = [tasks[1], tasks[0]];
        validates('adopt-plan', 'output', copy, false, change);
      }
    }
  }
});

function filesystem(repo, prefix = '') {
  return readdirSync(join(repo, prefix)).sort().flatMap(name => {
    const path = prefix ? prefix + '/' + name : name, info = statSync(join(repo, path));
    return info.isDirectory() ? filesystem(repo, path) : [{path, mode: info.mode & 0o777, bytes: readFileSync(join(repo, path)).toString('base64')}];
  });
}
function chain(executable, repo, request) {
  const results = [], run = (command, value, flags = [], exit = 0) => {
    const result = native(command, repo, value, flags, executable);
    const valueOut = report(command, result, exit);
    results.push({command, exit: result.status, stdout: result.stdout, stderr: result.stderr});
    return valueOut;
  };
  const plan = run('adopt-materialize-plan', request), transaction = plan.transaction;
  assert.equal(plan.manifest.authority, 'routing_only'); assert.equal(plan.transaction.operations.length, 4);
  const flags = ['--expect-transaction', transaction.transactionId, '--expect-desired-state', transaction.desiredStateId];
  const applied = run('adopt-materialize-apply', request, flags);
  assert.equal(applied.state, 'passed'); assert.equal(applied.transactionResult.state, 'applied');
  assert.equal(applied.transactionResult.appliedCount, 4);
  assert.equal(run('adopt-materialize-apply', request, flags).transactionResult.state, 'already_satisfied');
  const resume = run('adopt-materialize-recover', undefined, ['--transaction', transaction.transactionId, '--action', 'resume']);
  assert.equal(resume.transactionResult.recoveredBy, 'resume');
  validates('adopt-materialize-recover', 'output', replaced(resume, ['expectedDesiredStateId'], transaction.desiredStateId), false);
  for (const state of ['blocked', 'cleanup_required', 'durability_unknown', 'failed', 'passed', 'recovery_required']) {
    validates('adopt-materialize-recover', 'output', replaced(resume, ['state'], state));
  }
  const rollback = run('adopt-materialize-recover', undefined, ['--transaction', transaction.transactionId, '--action', 'rollback'], 1);
  assert.equal(rollback.state, 'recovery_required'); assert.equal(rollback.failureClass, 'committed_state_mismatch');
  for (const [command, value] of [['adopt-materialize-plan', plan], ['adopt-materialize-apply', applied], ['adopt-materialize-recover', resume]]) {
    closedObjectsAndDigests(command, 'output', value);
  }
  const paths = filesystem(repo).filter(row => !row.path.startsWith('.agentic-proofkit/')).map(row => row.path);
  assert.deepEqual(paths, ['README.md', 'docs/specs/pilot/requirements.v2.json', 'proofkit/project.v1.json', 'proofkit/requirement-bindings.json', 'proofkit/test-evidence-inventory.json']);
  for (const path of paths.filter(path => path.endsWith('.json'))) assert.doesNotThrow(() => JSON.parse(readFileSync(join(repo, path))));
  return {results, files: filesystem(repo)};
}

test('actual materialization chain, replay and recovery preserve operation and filesystem outcomes', () => {
  const repo = repository(), request = structuredClone(requestSeed);
  validates('adopt-materialize-plan', 'input', request); validates('adopt-materialize-apply', 'input', request);
  closedObjectsAndDigests('adopt-materialize-plan', 'input', request);
  let old;
  if (process.env.PROOFKIT_MATERIALIZATION_BASELINE) {
    old = chain(process.env.PROOFKIT_MATERIALIZATION_BASELINE, repo, request);
    for (const name of readdirSync(repo)) if (name !== 'README.md') rmSync(join(repo, name), {recursive: true, force: true});
  }
  const current = chain(binary, repo, request);
  if (old) assert.deepEqual(current, old, 'undeclared process or filesystem predecessor delta');
});

test('parent cardinality, ID, claim and operation boundaries are not native write approval', () => {
  const repo = repository(), request = structuredClone(requestSeed);
  request.nonClaims = [];
  const plan = report('adopt-materialize-plan', native('adopt-materialize-plan', repo, request));
  assert.equal(plan.nonClaims.length, 4);
  for (const command of ['adopt-materialize-plan', 'adopt-materialize-apply']) {
    validates(command, 'input', replaced(request, ['schemaVersion'], 1), false, 'old-wire');
    validates(command, 'input', replaced(request, ['requestKind'], 'foreign'), false, 'foreign-request');
    for (const field of Object.keys(request)) {
      const copy = structuredClone(request); delete copy[field]; validates(command, 'input', copy, false, field + '/missing');
      validates(command, 'input', replaced(request, [field], null), false, field + '/null');
    }
    for (const count of [0, 1, 29, 30]) {
      const copy = structuredClone(request); copy.requirementSources = Array.from({length: count}, () => structuredClone(request.requirementSources[0]));
      validates(command, 'input', copy, count >= 1 && count <= 29, 'sources/' + count);
      if (count === 29) {
        const result = native('adopt-materialize-plan', repo, copy);
        assert.equal(result.status, 1); assert.equal(result.stdout, '');
        assert.equal(readdirSync(repo).length, 1, 'structural pass gained write authority');
      }
    }
    for (const field of ['projectId', 'requestId']) for (const [id, accept] of [['A', true], ['a:_-1.x', true], ['a'.repeat(256), true], ['0', false], [' a', false], ['a ', false], ['a/b', false], ['a'.repeat(257), false]]) {
      validates(command, 'input', replaced(request, [field], id), accept, field + '/ID');
    }
  }
  const blocked = report('adopt-materialize-apply', native('adopt-materialize-apply', repo, request,
    ['--expect-transaction', plan.transaction.transactionId, '--expect-desired-state', 'sha256:' + '0'.repeat(64)]), 1);
  assert.equal(blocked.state, 'blocked'); assert.equal(blocked.transactionResult, null);
  validates('adopt-materialize-apply', 'output', replaced(blocked, ['expectedTransactionId'], null), false);
  validates('adopt-materialize-apply', 'output', replaced(blocked, ['expectedDesiredStateId'], null), false);
  for (const state of ['blocked', 'cleanup_required', 'durability_unknown', 'failed', 'passed', 'recovery_required']) {
    validates('adopt-materialize-apply', 'output', replaced(blocked, ['state'], state));
  }
  validates('adopt-materialize-apply', 'output', replaced(blocked, ['state'], 'foreign'), false);
  validates('adopt-materialize-recover', 'output', blocked, false);
  validates('adopt-materialize-plan', 'output', replaced(plan, ['nonClaims'], plan.nonClaims.slice(0, 3)), false);
});

test('catalog omissions and public transaction snapshots preserve inclusive resource endpoints', () => {
  const repo = repository();
  writeFileSync(join(repo, 'README.md'), Buffer.alloc(1048577, 65));
  writeFileSync(join(repo, 'package.json'), Buffer.from([0]));
  const inventory = report('repository-inventory', native('repository-inventory', repo));
  assert.equal(inventory.entries.length, 0);
  assert.deepEqual(inventory.omissions.omittedRecognized.map(row => row.reason).sort(), ['non_text', 'over_file_limit']);
  closedObjectsAndDigests('repository-inventory', 'output', inventory);
  for (const field of ['rootEntryCount', 'unrecognizedCount']) for (const [count, valid] of [[0, true], [4096, true], [-1, false], [4097, false], [0.5, false]]) {
    validates('repository-inventory', 'output', replaced(inventory, ['omissions', field], count), valid, field + '/bound');
  }
  const ordinary = report('repository-inventory', native('repository-inventory', repository()));
  for (const [count, valid] of [[0, true], [1048576, true], [-1, false], [1048577, false], [0.5, false]]) {
    validates('repository-inventory', 'output', replaced(ordinary, ['entries', 0, 'byteLength'], count), valid, 'entry/bytes');
  }
  for (const [count, valid] of [[0, true], [25, true], [26, false]]) {
    validates('repository-inventory', 'output', replaced(ordinary, ['entries'], Array.from({length: count}, () => ordinary.entries[0])), valid, 'catalog/bound');
  }
  const candidateRoot = repository();
  const plan = report('adopt-materialize-plan', native('adopt-materialize-plan', candidateRoot, requestSeed));
  for (const [count, valid] of [[0, false], [1, true], [32, true], [33, false]]) {
    validates('adopt-materialize-plan', 'output', replaced(plan, ['transaction', 'operations'], Array.from({length: count}, () => plan.transaction.operations[0])), valid, 'operations/bound');
  }
  for (let index = 0; index < plan.transaction.operations.length; index++) {
    const path = ['transaction', 'operations', index, 'after'];
    for (const [count, valid] of [[0, true], [1048576, true], [-1, false], [1048577, false], [0.5, false]]) {
      validates('adopt-materialize-plan', 'output', replaced(plan, [...path, 'byteCount'], count), valid, path + '/bytes');
    }
    for (const [mode, valid] of [['0400', true], ['0777', true], ['0000', false], ['0300', false], ['0408', false], ['1400', false], ['400', false]]) {
      validates('adopt-materialize-plan', 'output', replaced(plan, [...path, 'mode'], mode), valid, path + '/mode');
    }
  }
  for (const version of [1, 2, 3]) validates('adopt-materialize-plan', 'output', replaced(plan, ['transaction', 'schemaVersion'], version));
  validates('adopt-materialize-plan', 'output', replaced(plan, ['transaction', 'schemaVersion'], 4), false);
});
