import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_INTEGRATION_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const commands = ['integration-source', 'integration-check', 'integration-plan', 'integration-apply', 'integration-recover'];
const checks = new Map(commands.map(command => {
  const ref = contract.commands.find(row => row.command === command).outputContract.rootDefinitionRef;
  const definition = contract.contractDefinitions.find(row => row.definitionId === ref);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema');
  return [command, new Ajv2020({strict: false, validateFormats: false})
    .compile({oneOf: definition.fieldTree.variants.map(row => row.schema)})];
}));
const fields = {
  'integration-source': ['bodyBytes', 'capabilityDigest', 'content', 'contentDigest', 'integrationId', 'kind', 'metadataBytes', 'nonClaims', 'schemaVersion', 'targetPath', 'tool'],
  'integration-check': ['expectedContentDigest', 'integrationId', 'kind', 'nonClaims', 'schemaVersion', 'state', 'targetPath', 'tool'],
  'integration-plan': ['failureClass', 'kind', 'nonClaims', 'operation', 'recoveryTransactionId', 'schemaVersion', 'state', 'tool', 'transaction'],
  'integration-apply': ['expectedDesiredStateId', 'expectedTransactionId', 'failureClass', 'kind', 'nonClaims', 'operation', 'schemaVersion', 'state', 'tool', 'transactionResult'],
};
fields['integration-recover'] = fields['integration-apply'];
const paths = {claude: '.claude/skills/agentic-proofkit/SKILL.md', codex: '.agents/skills/agentic-proofkit/SKILL.md'};
const nullableFields = {
  'integration-source': [], 'integration-check': [],
  'integration-plan': ['failureClass', 'recoveryTransactionId', 'transaction'],
  'integration-apply': ['failureClass', 'transactionResult'],
  'integration-recover': ['expectedDesiredStateId', 'failureClass', 'tool', 'transactionResult'],
};
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, next) {
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = next; return copy;
}
function valid(command, value, expected = true, label = '') {
  const check = checks.get(command);
  assert.equal(check(value), expected, `${command}/${label}: ${JSON.stringify(check.errors)}`);
}
let directory, binary, serial = 0;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-integration-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 120000, env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
function repository() {
  const path = join(directory, 'repository-' + serial++); mkdirSync(path); return path;
}
function invocation(command, flags, format) {
  const descriptor = contract.commands.find(row => row.command === command);
  const result = spawnSync(binary, [...descriptor.route, ...flags, '--format', format], {
    encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20,
  });
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  return result;
}
function native(command, flags, exit = 0, format = 'json') {
  const result = invocation(command, flags, format);
  assert.equal(result.status, exit, result.stderr); assert.equal(result.stderr, '');
  if (format === 'text') return result.stdout;
  const value = JSON.parse(result.stdout); valid(command, value);
  assert.deepEqual(Object.keys(value).sort(), fields[command]); return value;
}
function rootPredicates(command, specimen) {
  objectDomain(command, specimen, []);
  valid(command, {...specimen, foreign: true}, false, 'unknown');
  for (const field of fields[command]) {
    const missing = structuredClone(specimen); delete missing[field]; valid(command, missing, false, field + '/missing');
    // A string, null or number never substitutes for a complete object/tuple.
    const invalid = typeof specimen[field] === 'string' || specimen[field] === null ? {} : 'wrong-type';
    valid(command, replace(specimen, [field], invalid), false, field + '/type');
    valid(command, replace(specimen, [field], null), nullableFields[command].includes(field), field + '/null');
  }
  for (const version of [0, 2, 1.5, '1']) valid(command, {...specimen, schemaVersion: version}, false, 'wire');
  valid(command, {...specimen, kind: 'foreign'}, false, 'kind');
  for (const field of fields[command].filter(key => /Digest$|Id$/.test(key))) {
    if (command === 'integration-recover' && field === 'expectedDesiredStateId') continue;
    digestDomain(command, specimen, [field], nullableFields[command].includes(field));
  }
  for (const nonClaims of [specimen.nonClaims.slice(0, -1), [...specimen.nonClaims, specimen.nonClaims[0]]]) {
    valid(command, {...specimen, nonClaims}, false, 'denial-count');
  }
  for (let i = 0; i < specimen.nonClaims.length; i++) {
    valid(command, replace(specimen, ['nonClaims', i], 'A different denial.'), false, 'denial-literal');
    valid(command, replace(specimen, ['nonClaims', i], specimen.nonClaims[(i + 1) % specimen.nonClaims.length]), false, 'denial-position');
  }
}
function objectDomain(command, specimen, path) {
  for (const value of [null, [], 'record', 0, true]) {
    valid(command, path.length ? replace(specimen, path, value) : value, false,
      path.length ? path + '/object-type' : 'root/object-type');
  }
}
function digestDomain(command, specimen, path, nullable = false) {
  const digest = 'sha256:' + 'a'.repeat(64);
  const alphabet = '0123456789abcdef';
  for (const value of [...Array.from(alphabet, character => 'sha256:' + character.repeat(64)),
    'sha256:' + alphabet.repeat(4), ...(nullable ? [null] : [])]) {
    valid(command, replace(specimen, path, value), true, path + '/digest-member');
  }
  for (const value of ['', 'sha256:' + 'a'.repeat(63), 'sha256:' + 'a'.repeat(65), 'sha256:' + 'A'.repeat(64),
    'sha256:' + 'g'.repeat(64), 'sha255:' + 'a'.repeat(64), 'SHA256:' + 'a'.repeat(64),
    ' ' + digest, digest + ' ', digest + '\n', '\u0085' + digest, digest + '\u3000', {}, 0, ...(!nullable ? [null] : [])]) {
    valid(command, replace(specimen, path, value), false, path + '/digest');
  }
}
const stateVocabulary = ['missing', 'invalid', 'stale', 'current', 'ready', 'blocked', 'recovery_required',
  'passed', 'failed', 'cleanup_required', 'durability_unknown', 'applied', 'already_satisfied', 'rolled_back'];
const operationVocabulary = ['install', 'remove', 'update', 'recover'];
function enumDomain(command, specimen, path, values, neighbors = []) {
  for (const value of values) valid(command, replace(specimen, path, value), true, path + '/member');
  for (const value of ['foreign', '', 0, {}]) valid(command, replace(specimen, path, value), false, path + '/outside');
  for (const value of neighbors.filter(value => !values.includes(value))) {
    valid(command, replace(specimen, path, value), false, path + '/phase-domain');
  }
}
function canonicalText(command, specimen, path, nullable = false) {
  valid(command, replace(specimen, path, 'x'), true, path + '/canonical-minimum');
  for (const value of ['failure', 'a\nb', '\ufeffx', 'x\ufeff', ...(nullable ? [null] : [])]) {
    valid(command, replace(specimen, path, value), true, path + '/canonical-member');
  }
  for (const value of ['', 0, {}]) {
    valid(command, replace(specimen, path, value), false, path + '/canonical');
  }
  const whitespace = ['\t', '\n', '\v', '\f', '\r', ' ', '\u0085', '\u00a0', '\u1680',
    ...Array.from({length: 11}, (_, index) => String.fromCodePoint(0x2000 + index)),
    '\u2028', '\u2029', '\u202f', '\u205f', '\u3000'];
  for (const space of whitespace) {
    for (const value of [space + 'failure', 'failure' + space]) {
      valid(command, replace(specimen, path, value), false, path + '/canonical');
    }
    valid(command, replace(specimen, path, 'a' + space + 'b'), true, path + '/canonical-member');
  }
}

test('actual source, check, installation, replay, recovery and removal preserve classified CLI phases', () => {
  for (const tool of ['claude', 'codex']) {
    const repo = repository(), flags = ['--repo-root', repo, '--tool', tool];
    const source = native('integration-source', ['--tool', tool]);
    rootPredicates('integration-source', source);
    assert.equal(source.targetPath, paths[tool]);
    assert.equal(native('integration-source', ['--tool', tool], 0, 'text'), source.content);
    assert.equal(source.bodyBytes + source.metadataBytes, Buffer.byteLength(source.content));
    const check = exit => native('integration-check', flags, exit);
    const missing = check(2); assert.equal(missing.state, 'missing'); rootPredicates('integration-check', missing);
    const target = join(repo, paths[tool]); mkdirSync(dirname(target), {recursive: true});
    writeFileSync(target, Buffer.from([0])); assert.equal(check(2).state, 'invalid');
    writeFileSync(target, 'A valid but foreign instruction.\n'); assert.equal(check(2).state, 'stale');
    rmSync(target);
    const plan = operation => native('integration-plan', [...flags, '--operation', operation]);
    const installedPlan = plan('install'); rootPredicates('integration-plan', installedPlan);
    assert.equal(installedPlan.state, 'ready');
    assert.match(native('integration-plan', [...flags, '--operation', 'install'], 0, 'text'), /Integration plan: ready/);
    const apply = (operation, tx, desired, exit = 0) => native('integration-apply', [...flags, '--operation', operation,
      '--expect-transaction', tx, '--expect-desired-state', desired], exit);
    const transaction = installedPlan.transaction;
    const blocked = apply('install', transaction.transactionId, 'sha256:' + '0'.repeat(64), 1);
    assert.equal(blocked.state, 'blocked'); assert.equal(blocked.transactionResult, null); rootPredicates('integration-apply', blocked);
    const receipt = apply('install', transaction.transactionId, transaction.desiredStateId);
    assert.equal(receipt.state, 'passed'); assert.equal(receipt.transactionResult.state, 'applied'); rootPredicates('integration-apply', receipt);
    assert.equal(readFileSync(target, 'utf8'), source.content);
    assert.equal(check(0).state, 'current');
    assert.equal(apply('install', transaction.transactionId, transaction.desiredStateId).transactionResult.state, 'already_satisfied');
    const recoveryFlags = ['--repo-root', repo, '--transaction', transaction.transactionId];
    const resume = native('integration-recover', [...recoveryFlags, '--action', 'resume']);
    assert.equal(resume.state, 'passed'); assert.equal(resume.tool, null); assert.equal(resume.expectedDesiredStateId, null);
    assert.equal(resume.operation, 'recover'); assert.equal(resume.transactionResult.recoveredBy, 'resume');
    rootPredicates('integration-recover', resume);
    const rollback = native('integration-recover', [...recoveryFlags, '--action', 'rollback'], 1);
    assert.equal(rollback.state, 'recovery_required'); assert.equal(rollback.failureClass, 'committed_state_mismatch');
    const updated = plan('update');
    assert.equal(apply('update', updated.transaction.transactionId, updated.transaction.desiredStateId).state, 'passed');
    const removed = plan('remove');
    assert.equal(apply('remove', removed.transaction.transactionId, removed.transaction.desiredStateId).state, 'passed');
    assert.equal(check(2).state, 'missing');
  }
});

test('literal tool routes, raw source framing and complete field domains stay distinct from native approval', () => {
  const repo = repository(), flags = ['--repo-root', repo, '--tool', 'codex'];
  for (const selected of ['claude', 'codex']) {
    const source = native('integration-source', ['--tool', selected]);
    const check = native('integration-check', ['--repo-root', repo, '--tool', selected], 2);
    for (const command of ['integration-source', 'integration-check']) {
      const specimen = command === 'integration-source' ? source : check;
      for (const [tool, targetPath] of Object.entries(paths)) valid(command, {...specimen, tool, targetPath});
      valid(command, {...specimen, tool: selected === 'codex' ? 'claude' : 'codex'}, false, 'cross-tool-path');
      valid(command, {...specimen, tool: 'foreign'}, false, 'foreign-tool');
      valid(command, {...specimen, targetPath: paths.codex + '/'}, false, 'foreign-path');
    }
    for (const value of ['x', ' ', '\t', '\n', '\r', '\u00a0', '\0', '"', '\\', '\nx\n', 'x'.repeat(4608), '\u{1f600}'.repeat(4608)]) {
      valid('integration-source', {...source, content: value}, true, 'raw-content-member');
    }
    for (const value of ['', 'x'.repeat(4609), '\u{1f600}'.repeat(4609), null]) valid('integration-source', {...source, content: value}, false, 'content');
    for (const bodyBytes of [1, 4096]) valid('integration-source', {...source, bodyBytes});
    for (const bodyBytes of [0, -1, 4097, 1.5]) valid('integration-source', {...source, bodyBytes}, false, 'body-bound');
    for (const metadataBytes of [0, source.metadataBytes - 1, source.metadataBytes + 1, 512]) {
      if (metadataBytes !== source.metadataBytes) valid('integration-source', {...source, metadataBytes}, false, 'metadata-literal');
    }
    enumDomain('integration-check', check, ['state'], ['missing', 'invalid', 'stale', 'current'], stateVocabulary);
  }
  const plan = native('integration-plan', [...flags, '--operation', 'install']);
  enumDomain('integration-plan', plan, ['state'], ['ready', 'blocked', 'recovery_required'], stateVocabulary);
  enumDomain('integration-plan', plan, ['operation'], ['install', 'remove', 'update'], operationVocabulary);
  valid('integration-plan', {...plan, operation: 'recover'}, false, 'operation/recovery-excluded');
  enumDomain('integration-plan', plan, ['tool'], ['claude', 'codex']);
  canonicalText('integration-plan', plan, ['failureClass'], true);
  valid('integration-plan', {...plan, transaction: null});
  const blocked = native('integration-apply', [...flags, '--operation', 'install', '--expect-transaction', plan.transaction.transactionId,
    '--expect-desired-state', 'sha256:' + '0'.repeat(64)], 1);
  native('integration-apply', [...flags, '--operation', 'install', '--expect-transaction', plan.transaction.transactionId,
    '--expect-desired-state', plan.transaction.desiredStateId]);
  const recovery = native('integration-recover', ['--repo-root', repo, '--transaction', plan.transaction.transactionId, '--action', 'resume']);
  for (const [command, specimen] of [['integration-apply', blocked], ['integration-recover', recovery]]) {
    enumDomain(command, specimen, ['state'], ['passed', 'blocked', 'failed', 'recovery_required', 'cleanup_required', 'durability_unknown'], stateVocabulary);
    valid(command, {...specimen, state: 'rolled_back'}, false, 'parent-only-state');
    canonicalText(command, specimen, ['failureClass'], true);
    valid(command, {...specimen, transactionResult: null});
    if (command === 'integration-apply') {
      enumDomain(command, specimen, ['operation'], ['install', 'remove', 'update'], operationVocabulary);
      valid(command, {...specimen, operation: 'recover'}, false, 'operation/recovery-excluded');
      enumDomain(command, specimen, ['tool'], ['claude', 'codex']);
      valid(command, {...specimen, tool: null}, false); valid(command, {...specimen, expectedDesiredStateId: null}, false);
    } else {
      enumDomain(command, specimen, ['tool'], [null], ['claude', 'codex']);
      enumDomain(command, specimen, ['operation'], ['recover'], operationVocabulary);
      valid(command, {...specimen, expectedDesiredStateId: plan.transaction.desiredStateId}, false);
    }
  }
});

test('operational check failure with admitted tool has no report or caller-path disclosure', () => {
  const absent = join(repository(), 'unavailable-caller-owned-root');
  for (const tool of ['claude', 'codex']) for (const format of ['json', 'text']) {
    const result = invocation('integration-check', ['--repo-root', absent, '--tool', tool], format);
    assert.equal(result.status, 1, 'check operational exit');
    assert.equal(result.stdout, '', 'check operational stdout');
    assert.equal(result.stderr, 'integration check operation failed: open repository inspection lease\n', 'check operational diagnostic');
    assert.equal(result.stderr.includes(absent), false, 'check caller path');
  }
});

test('public transaction children retain closure, snapshot discriminants and inclusive grammar bounds', () => {
  const repo = repository(), flags = ['--repo-root', repo, '--tool', 'codex'];
  const plan = native('integration-plan', [...flags, '--operation', 'install']);
  const command = 'integration-plan';
  const transaction = plan.transaction;
  assert.deepEqual(Object.keys(transaction).sort(), ['createdDirectories', 'desiredStateId', 'nonClaims', 'operations', 'rootId', 'schemaVersion', 'transactionId', 'transactionKind']);
  for (const field of ['desiredStateId', 'rootId', 'transactionId']) digestDomain(command, plan, ['transaction', field]);
  valid(command, replace(plan, ['transaction', 'transactionKind'], 'proofkit.repository-write-plan'));
  valid(command, replace(plan, ['transaction', 'transactionKind'], 'foreign'), false, 'transactionKind/literal');
  const rowPath = ['transaction', 'operations', 0];
  objectDomain(command, plan, rowPath);
  assert.deepEqual(Object.keys(at(plan, rowPath)).sort(), ['action', 'after', 'before', 'path']);
  for (const field of ['action', 'after', 'before', 'path']) {
    const missing = structuredClone(plan); delete at(missing, rowPath)[field];
    valid(command, missing, false, 'operation-row/' + field + '/missing');
    valid(command, replace(plan, [...rowPath, field], null), false, 'operation-row/' + field + '/null');
    valid(command, replace(plan, [...rowPath, field], 0), false, 'operation-row/' + field + '/type');
  }
  valid(command, replace(plan, [...rowPath, 'foreign'], true), false, 'operation-row/closure');
  for (const version of [1, 2, 3]) valid(command, replace(plan, ['transaction', 'schemaVersion'], version));
  for (const version of [0, 4, 1.5]) valid(command, replace(plan, ['transaction', 'schemaVersion'], version), false);
  for (const count of [1, 32, 0, 33]) {
    valid(command, replace(plan, ['transaction', 'operations'], Array.from({length: count}, () => structuredClone(transaction.operations[0]))), count >= 1 && count <= 32);
  }
  enumDomain(command, plan, ['transaction', 'operations', 0, 'action'], ['create', 'replace', 'delete', 'unchanged']);
  canonicalText(command, plan, ['transaction', 'operations', 0, 'path']);
  canonicalText(command, replace(plan, ['transaction', 'createdDirectories'], ['x']), ['transaction', 'createdDirectories', 0]);
  for (const createdDirectories of [[], ['a'], ['a', 'a']]) valid(command, replace(plan, ['transaction', 'createdDirectories'], createdDirectories));
  for (const createdDirectories of [[''], [' a'], ['a '], [null]]) valid(command, replace(plan, ['transaction', 'createdDirectories'], createdDirectories), false);
  for (const position of ['before', 'after']) {
    const path = ['transaction', 'operations', 0, position];
    const absent = {byteCount: 0, exists: false, mode: '0000', sha256: null};
    const present = {byteCount: 1, exists: true, mode: '0644', sha256: 'sha256:' + '0'.repeat(64)};
    digestDomain(command, replace(plan, path, present), [...path, 'sha256']);
    for (const snapshot of [absent, present]) {
      const specimen = replace(plan, path, snapshot); valid(command, specimen);
      objectDomain(command, specimen, path);
      for (const field of Object.keys(snapshot)) {
        const copy = structuredClone(specimen); delete at(copy, path)[field]; valid(command, copy, false, position + '/required');
      }
      valid(command, replace(specimen, [...path, 'foreign'], true), false, position + '/closure');
      valid(command, replace(specimen, [...path, 'exists'], !snapshot.exists), false, position + '/discriminant');
      for (const field of Object.keys(snapshot)) {
        valid(command, replace(specimen, [...path, field], null), field === 'sha256' && !snapshot.exists, position + '/' + field + '/null');
        valid(command, replace(specimen, [...path, field], {}), false, position + '/' + field + '/type');
      }
    }
    for (const byteCount of [0, 1048576, -1, 1048577, 0.5]) valid(command, replace(plan, path, {...present, byteCount}), byteCount >= 0 && byteCount <= 1048576 && Number.isInteger(byteCount));
    for (const mode of ['0400', '0644', '0777']) valid(command, replace(plan, path, {...present, mode}));
    const modeCharacters = ['0', '4567', '01234567', '01234567'];
    for (let index = 0; index < modeCharacters.length; index++) for (const character of '0123456789a') {
      const mode = '0644'.slice(0, index) + character + '0644'.slice(index + 1);
      valid(command, replace(plan, path, {...present, mode}), modeCharacters[index].includes(character), position + '/mode-grammar');
    }
    for (const mode of ['064', '06444', '644', '00644', '0644 ', ' 0644', '\n0644', '0644\n', '0644\r', '0644\r\n', '0644\u2028', '0644\u2029']) {
      valid(command, replace(plan, path, {...present, mode}), false, position + '/mode-grammar');
    }
    for (const mode of ['0644', '00000', '']) valid(command, replace(plan, path, {...absent, mode}), false, position + '/absent-mode-literal');
    for (const byteCount of [-1, 1]) {
      valid(command, replace(plan, path, {...absent, byteCount}), false, position + '/absent-count-literal');
    }
    valid(command, replace(plan, path, {...absent, sha256: present.sha256}), false);
    valid(command, replace(plan, path, {...present, sha256: null}), false);
  }
  const applied = native('integration-apply', [...flags, '--operation', 'install', '--expect-transaction', transaction.transactionId,
    '--expect-desired-state', transaction.desiredStateId]);
  const recovered = native('integration-recover', ['--repo-root', repo, '--transaction', transaction.transactionId, '--action', 'resume']);
  for (const [output, specimen] of [['integration-apply', applied], ['integration-recover', recovered]]) {
    assert.deepEqual(Object.keys(specimen.transactionResult).sort(), ['appliedCount', 'failureClass', 'nonClaims', 'recoveredBy', 'schemaVersion', 'state', 'transactionId']);
    digestDomain(output, specimen, ['transactionResult', 'transactionId'], true);
    enumDomain(output, specimen, ['transactionResult', 'state'], ['applied', 'already_satisfied', 'rolled_back', 'recovery_required', 'cleanup_required', 'durability_unknown'], stateVocabulary);
    valid(output, replace(specimen, ['transactionResult', 'state'], 'failed'), false, 'parent-only-state');
    for (const count of [null, 0, 32, -1, 33, 0.5]) valid(output, replace(specimen, ['transactionResult', 'appliedCount'], count), count === null || Number.isInteger(count) && count >= 0 && count <= 32);
    enumDomain(output, specimen, ['transactionResult', 'recoveredBy'], [null, 'resume', 'rollback']);
    canonicalText(output, specimen, ['transactionResult', 'failureClass'], true);
  }
  for (const [output, specimen, child] of [['integration-plan', plan, 'transaction'], ['integration-apply', applied, 'transactionResult'], ['integration-recover', recovered, 'transactionResult']]) {
    const value = specimen[child];
    for (const incorrect of [[], 'record', 0, true]) valid(output, replace(specimen, [child], incorrect), false, child + '/object-type');
    valid(output, replace(specimen, [child, 'foreign'], true), false);
    for (const field of Object.keys(value)) {
      const missing = structuredClone(specimen); delete missing[child][field]; valid(output, missing, false, child + '/required');
      valid(output, replace(specimen, [child, field], {}), false, child + '/type');
      const nullable = child === 'transactionResult' && ['appliedCount', 'failureClass', 'recoveredBy', 'transactionId'].includes(field);
      valid(output, replace(specimen, [child, field], null), nullable, child + '/' + field + '/null');
    }
    const invalidVersions = child === 'transaction' ? [0, 4, 1.5] : [0, 2, 3, 4, 1.5];
    for (const version of invalidVersions) valid(output, replace(specimen, [child, 'schemaVersion'], version), false, child + '/schemaVersion');
    for (let i = 0; i < value.nonClaims.length; i++) valid(output, replace(specimen, [child, 'nonClaims', i], 'Different denial.'), false);
    for (let i = 0; i < value.nonClaims.length; i++) valid(output, replace(specimen, [child, 'nonClaims', i], value.nonClaims[(i + 1) % value.nonClaims.length]), false, child + '/denial-position');
    valid(output, replace(specimen, [child, 'nonClaims'], value.nonClaims.slice(0, -1)), false, child + '/denial-count');
    valid(output, replace(specimen, [child, 'nonClaims'], [...value.nonClaims, value.nonClaims[0]]), false, child + '/denial-count');
  }
});
