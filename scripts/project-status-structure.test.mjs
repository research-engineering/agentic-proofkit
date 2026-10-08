import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, lstatSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_STATUS_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const checks = new Map(['status', 'next'].map(command => {
  const ref = contract.commands.find(row => row.command === command).outputContract.rootDefinitionRef;
  const definition = contract.contractDefinitions.find(row => row.definitionId === ref);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema');
  return [command, new Ajv2020({strict: false, validateFormats: false}).compile({oneOf: definition.fieldTree.variants.map(row => row.schema)})];
}));
const claims = [
  'Project next actions are derived non-executable guidance; repository owners retain execution and policy authority.',
  'Project status does not approve merge, release, rollout, deployment, or production readiness.',
  'Project status does not execute native witnesses or verify receipt trust, currentness, or scope.',
];
const states = ['uninitialized', 'recovery_required', 'blocked', 'stale', 'verification_required'];
const issues = ['transaction_control_invalid', 'transaction_recovery_required', 'project_manifest_missing',
  'project_manifest_invalid', 'project_record_missing', 'project_record_digest_mismatch', 'project_record_invalid', 'project_cross_record_closure_invalid'];
const classes = ['repair_control_state', 'choose_recovery', 'choose_adoption_mode', 'repair_project_records',
  'rematerialize_project', 'run_repository_verification'];
const keys = {
  status: ['issueCodes', 'manifestId', 'nextAction', 'nonClaims', 'projectId', 'projectState', 'reportKind', 'schemaVersion', 'snapshotId', 'statusId'],
  next: ['action', 'issueCodes', 'nonClaims', 'packetId', 'packetKind', 'projectState', 'schemaVersion', 'snapshotId', 'statusRef'],
};
const actionKeys = ['actionClass', 'actionId', 'commandRoute', 'contextRef', 'executable', 'requiredDecision'];
const digest = 'sha256:' + 'a'.repeat(64);
function specimen(command) {
  const action = {actionClass: 'choose_adoption_mode', actionId: 'proofkit.project-status.action.choose_adoption_mode',
    commandRoute: ['adopt', 'plan'], contextRef: null, executable: false, requiredDecision: 'adoption_mode'};
  const common = {issueCodes: ['project_manifest_missing'], nonClaims: [...claims], projectState: 'uninitialized', schemaVersion: 1, snapshotId: digest};
  return command === 'status' ? {...common, manifestId: null, nextAction: action, projectId: null, reportKind: 'proofkit.project-status', statusId: digest} :
    {...common, action, packetId: digest, packetKind: 'proofkit.project-next-action', statusRef: digest};
}
const at = (value, path) => path.reduce((current, key) => current[key], value);
function replaced(value, path, next) {
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = next; return copy;
}
function valid(command, value, expected = true, label = '') {
  const check = checks.get(command);
  assert.equal(check(value), expected, `${command}/${label}: ${JSON.stringify(check.errors)}`);
}
function domain(command, value, path, accepted, rejected, label) {
  for (const member of accepted) valid(command, replaced(value, path, member), true, path + '/' + label + '-member');
  for (const member of rejected) valid(command, replaced(value, path, member), false, path + '/' + label + '-refusal');
}
function digestDomain(command, value, path, nullable) {
  const alphabet = '0123456789abcdef';
  domain(command, value, path, [...Array.from(alphabet, letter => 'sha256:' + letter.repeat(64)),
    'sha256:' + alphabet.repeat(4), ...(nullable ? [null] : [])],
    ['', 'sha256:' + 'a'.repeat(63), 'sha256:' + 'a'.repeat(65), 'sha256:' + 'A'.repeat(64), 'sha256:' + 'g'.repeat(64),
      'sha255:' + 'a'.repeat(64), 'SHA256:' + 'a'.repeat(64), ' ' + digest, digest + ' ', digest + '\n', 0, true, {}, [], ...(!nullable ? [null] : [])], 'digest');
}
function ruleDomain(command, value, path, nullable) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const body = alphabet + '0123456789_';
  domain(command, value, path, [...Array.from(alphabet), ...Array.from(body, letter => 'A' + letter),
    ...Array.from('._:-', separator => 'A' + separator + 'b'), 'a'.repeat(256), ...(nullable ? [null] : [])],
    ['', 'a'.repeat(257), '_a', '1a', '.a', 'a.', 'a..b', 'a/-b', 'a b', '\u00e9', ' a', 'a ', 'a\n', 0, true, [], {}, ...(!nullable ? [null] : [])], 'rule');
}

test('navigation output independent structural predicate matrix', () => {
  for (const command of checks.keys()) {
    const value = specimen(command), action = command === 'status' ? 'nextAction' : 'action';
    valid(command, value);
    for (const [path, fields] of [[[], keys[command]], [[action], actionKeys]]) {
      for (const member of [null, [], 'object', 0, true]) valid(command, path.length ? replaced(value, path, member) : member, false, path + '/object');
      const foreign = structuredClone(value); at(foreign, path).foreign = true; valid(command, foreign, false, path + '/closure');
      for (const field of fields) {
        const missing = structuredClone(value); delete at(missing, path)[field]; valid(command, missing, false, path + '/' + field + '/required');
        valid(command, replaced(value, [...path, field], {}), false, path + '/' + field + '/type');
        const nullable = ['manifestId', 'projectId', 'contextRef', 'requiredDecision'].includes(field);
        valid(command, replaced(value, [...path, field], null), nullable, path + '/' + field + '/null');
      }
    }
    domain(command, value, ['schemaVersion'], [1], [0, 2, 1.5, '1', null], 'wire');
    const kind = command === 'status' ? 'reportKind' : 'packetKind';
    domain(command, value, [kind], [command === 'status' ? 'proofkit.project-status' : 'proofkit.project-next-action'],
      ['foreign', command === 'status' ? 'proofkit.project-next-action' : 'proofkit.project-status', null], 'kind');
    domain(command, value, ['projectState'], states, [...classes, 'clean', 'foreign', '', null, 0], 'state');
    domain(command, value, [action, 'actionClass'], classes, [...states, 'foreign', '', null, 0], 'class');
    domain(command, value, [action, 'requiredDecision'], [null, 'adoption_mode', 'resume_or_rollback'], ['foreign', '', 0, true], 'decision');
    domain(command, value, [action, 'executable'], [false], [true, 0, 'false', null], 'executable');
    for (const field of command === 'status' ? ['statusId', 'snapshotId', 'manifestId'] : ['packetId', 'snapshotId', 'statusRef']) {
      digestDomain(command, value, [field], field === 'manifestId');
    }
    digestDomain(command, value, [action, 'contextRef'], true);
    ruleDomain(command, value, [action, 'actionId'], false);
    ruleDomain(command, value, [action, 'commandRoute', 0], false);
    if (command === 'status') ruleDomain(command, value, ['projectId'], true);
    for (const count of [0, 1, 4, 5]) valid(command, replaced(value, [action, 'commandRoute'], Array(count).fill('adopt')), count <= 4, 'route-bound');
    for (const index of [0, 1, 2, 3]) {
      const route = Array(4).fill('adopt');
      for (const bad of [null, {}, 0, 'bad token']) {
        const invalid = [...route]; invalid[index] = bad; valid(command, replaced(value, [action, 'commandRoute'], invalid), false, 'route-item/' + index);
      }
    }
    for (const issue of issues) valid(command, {...value, issueCodes: [issue]}, true, 'issue-member');
    for (const count of [0, 1, 16, 17]) valid(command, {...value, issueCodes: Array(count).fill('project_manifest_missing')}, count <= 16, 'issue-bound');
    for (const bad of ['foreign', '', null, 0, {}, []]) valid(command, {...value, issueCodes: [bad]}, false, 'issue-item');
    valid(command, {...value, issueCodes: [...issues].reverse()}, true, 'sortedness remains native');
    for (const count of [0, 1, 2, 3, 4]) valid(command, {...value, nonClaims: claims.slice(0, count).concat(count === 4 ? claims[0] : [])}, count === 3, 'claim-count');
    for (let index = 0; index < claims.length; index++) for (const bad of ['Different boundary.', claims[(index + 1) % claims.length], null, 0, {}]) {
      valid(command, replaced(value, ['nonClaims', index], bad), false, 'claim-position/' + index);
    }
  }
});

function treeSnapshot(root, relative = '') {
  return readdirSync(root).sort().flatMap(name => {
    const path = join(root, name), ref = relative ? relative + '/' + name : name, info = lstatSync(path);
    assert(!info.isSymbolicLink());
    return info.isDirectory() ? [{path: ref, mode: info.mode & 0o777}, ...treeSnapshot(path, ref)] :
      [{path: ref, mode: info.mode & 0o777, sha256: createHash('sha256').update(readFileSync(path)).digest('hex')}];
  });
}

test('actual navigation CLI preserves read-only states and its status-owned next action', () => {
  const directory = mkdtempSync(join(tmpdir(), 'proofkit-status-contract-'));
  try {
    const binary = join(directory, 'proofkit');
    execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
      cwd: root, timeout: 120000, env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
    });
    function invoke(command, repo, input, flags = [], expected = 0) {
      const descriptor = contract.commands.find(row => row.command === command);
      const args = [...(descriptor.route ?? [command]), '--repo-root', repo, ...flags];
      if (input !== undefined) args.push('--input', '-');
      const result = spawnSync(binary, args, {input: input === undefined ? undefined : JSON.stringify(input), encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20});
      assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, expected, result.stderr);
      return result;
    }
    const repo = join(directory, 'repository'); mkdirSync(repo); writeFileSync(join(repo, 'README.md'), '# Pilot\n');
    function navigation(state, actionClass) {
      const before = treeSnapshot(repo), records = {};
      for (const command of checks.keys()) {
        const result = invoke(command, repo); assert.equal(result.stderr, '');
        const value = JSON.parse(result.stdout); valid(command, value);
        assert.deepEqual(Object.keys(value).sort(), keys[command]); assert.equal(value.projectState, state);
        assert.equal((value.action ?? value.nextAction).actionClass, actionClass); assert.deepEqual(value.nonClaims, claims);
        records[command] = value;
        const text = invoke(command, repo, undefined, ['--format', 'text', '--color', 'never']);
        assert.equal(text.stderr, ''); assert(text.stdout.includes(state)); assert(!text.stdout.includes('\x1b['));
      }
      assert.deepEqual(records.status.nextAction, records.next.action);
      assert.equal(records.next.statusRef, records.status.statusId); assert.equal(records.next.snapshotId, records.status.snapshotId);
      assert.deepEqual(treeSnapshot(repo), before);
    }
    navigation('uninitialized', 'choose_adoption_mode');
    const request = JSON.parse(readFileSync(new URL('internal/app/testdata/materialization-native-request.v2.json', root)));
    request.sourcePlan = JSON.parse(invoke('adopt-plan', repo, undefined, ['--mode', 'fresh']).stdout);
    const plan = JSON.parse(invoke('adopt-materialize-plan', repo, request).stdout);
    const applied = invoke('adopt-materialize-apply', repo, request, ['--expect-transaction', plan.transaction.transactionId, '--expect-desired-state', plan.transaction.desiredStateId]);
    assert.equal(applied.stderr, ''); assert.equal(JSON.parse(applied.stdout).state, 'passed');
    navigation('verification_required', 'run_repository_verification');
    const sourcePath = join(repo, request.requirementProofBinding.record.requirements[0].specPath);
    writeFileSync(sourcePath, readFileSync(sourcePath, 'utf8') + '\n');
    navigation('stale', 'rematerialize_project');
    writeFileSync(join(repo, 'proofkit/project.v1.json'), '{');
    navigation('blocked', 'repair_project_records');
    for (const command of checks.keys()) {
      const absent = join(directory, 'absent');
      const failure = invoke(command, absent, undefined, [], 1);
      assert.equal(failure.stdout, ''); assert(failure.stderr.length > 0); assert(!failure.stderr.includes(absent));
    }
  } finally { rmSync(directory, {recursive: true, force: true}); }
});
