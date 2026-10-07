import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {before, after} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const root = new URL('../', import.meta.url);
const external = 'external-consumer', registry = 'registry-consumer', composer = 'registry-consumer-proof-input-compose';
const commands = [external, registry, composer];
const baseline = JSON.parse(readFileSync(new URL('internal/app/testdata/consumer-evidence-native-observations.json', root)));
assert.equal(baseline.head, '3e061a95d864c495f20bf6ebc6ff5f71e33b21c2');
assert.equal(baseline.tree, 'f978fcd9b669d349d337e18729a5fa93b5351b1e');
assert.equal(baseline.observations.length, 72);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_CONSUMER_EVIDENCE_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const ajv = new Ajv2020({strict: false, validateFormats: false});
const validators = Object.fromEntries(commands.map(command => [command, Object.fromEntries(['input', 'output'].map(direction => {
  const version = direction === 'input' ? 2 : 1;
  const id = `proofkit.${command}.${direction}.v${version}.json-schema`, binding = contract.commands.find(x => x.command === command)[direction + 'Contract'];
  assert.equal(binding.contractId, `proofkit.${command}.${direction}.v${version}`); assert.equal(binding.rootDefinitionRef, id);
  const variants = contract.contractDefinitions.find(x => x.definitionId === id).fieldTree.variants;
  assert.equal(variants.length, 1);
  return [direction, ajv.compile(variants[0].schema)];
}))]));
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-consumer-evidence-')); binary = join(directory, 'agentic-proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {cwd: root, timeout: 120000,
    env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'}});
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function invoke(command, input, argv = [command, '--input', '-']) {
  const result = spawnSync(binary, argv, {input: typeof input === 'string' ? input : JSON.stringify(input), encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20});
  assert.equal(result.error, undefined); assert.equal(result.signal, null); return result;
}
const seed = command => JSON.parse(baseline.observations.find(x => x.command === command && x.name === 'valid').input);
function output(command, input) {
  const result = invoke(command, input); assert.equal(result.stderr, ''); assert.ok(result.stdout);
  const record = JSON.parse(result.stdout); assert.equal(validators[command].input(input), true, `${command}/input`);
  assert.equal(validators[command].output(record), true, `${command}/output/${JSON.stringify(validators[command].output.errors)}`);
  return {record, status: result.status};
}

test('consumer structures conserve72actual predecessor streams and process classes', () => {
  for (const row of baseline.observations) {
    const result = invoke(row.command, row.input, row.argv);
    assert.equal(result.status, row.exitCode, row.command + '/' + row.name);
    assert.equal(hash(result.stdout), row.stdoutSHA256, row.command + '/' + row.name + '/stdout');
    assert.equal(hash(result.stderr), row.stderrSHA256, row.command + '/' + row.name + '/stderr');
    if (!row.report) continue;
    const input = row.name === 'pointer' ? JSON.parse(row.input).payload : JSON.parse(row.input), record = JSON.parse(result.stdout);
    assert.equal(validators[row.command].input(input), true, row.command + '/' + row.name + '/input');
    assert.equal(validators[row.command].output(record), true, row.command + '/' + row.name + '/output');
    assert.equal(record.schemaVersion, 1); assert.equal(record.state, row.exitCode ? row.name.startsWith('blocked') ? 'blocked' : 'failed' : 'passed');
    const source = input.input ?? input;
    assert.equal(record.reportId ?? record.compositionId, row.command === composer ? source.compositionId : source.pilotId ?? source.consumerId);
  }
});

test('consumer projections retain independently asserted declarations and absent proof shapes', () => {
  for (const command of [external, registry]) {
    const input = seed(command), {record, status} = output(command, input); assert.equal(status, 0);
    assert.equal(record.reportKind, `proofkit.${command}`);
    assert.equal(record.summary.packageName, input.input.packageName); assert.equal(record.summary.packageVersion, '1.2.3');
    const proof = command === external ? input.evidence.consumerProof : input.proof;
    const actual = record.diagnostics.find(x => x.key === 'consumerProof').value;
    const expected = structuredClone(proof);
    if (command === registry) for (const key of ['dependencySpec', 'registryPackIntegrityMatches', 'registryPackNameMatches', 'registryPackShasumMatches', 'registryPackVersionMatches']) delete expected[key];
    assert.deepEqual(actual, expected); assert.equal(Object.hasOwn(actual, 'executed'), false);
    assert.equal(record.ruleResults.length, 1); assert.equal(record.ruleResults[0].ruleId, `proofkit.${command}.accepted`);
    assert.equal(record.ruleResults[0].status, 'passed'); assert.deepEqual(record.ruleResults[0].diagnostics, []);
    if (command === external) input.evidence.consumerProof = null; else delete input.proof;
    const absent = output(command, input); assert.equal(absent.status, 1); assert.equal(absent.record.state, 'failed');
    assert.deepEqual(absent.record.diagnostics.find(x => x.key === 'consumerProof').value, {executed: false});
    if (command === external) assert.equal(absent.record.summary.consumerProofExecuted, false);
  }
});

test('composer whole CLI chain materializes only native accepted input and prioritizes blockers', () => {
  const input = seed(composer), pass = output(composer, input); assert.equal(pass.status, 0);
  assert.equal(pass.record.state, 'passed'); assert.equal(pass.record.compositionKind, `proofkit.${composer}`);
  assert.equal(pass.record.compositionId, input.compositionId); assert.equal(pass.record.summary.failureCount, 0);
  assert.equal(pass.record.summary.blockedPreconditionCount, 0); assert.equal(pass.record.ruleResults.length, 2);
  const child = pass.record.registryConsumerInput; assert.equal(validators[registry].input(child), true);
  assert.deepEqual(child.input.releaseAuthorityInput, input.releaseAuthorityInput);
  assert.equal(child.proof.releaseAuthorityOutputSha256, input.releaseAuthorityReport.outputSha256);
  assert.equal(child.proof.binarySmokeOutputSha256, input.smoke.binarySmokeOutputSha256);
  assert.equal(child.proof.cliWitnessPlanOutputSha256, input.smoke.cliWitnessPlanOutputSha256);
  const consumed = output(registry, child); assert.equal(consumed.status, 0); assert.equal(consumed.record.state, 'passed');
  for (const blocked of [false, true]) {
    const mixed = structuredClone(input); mixed.install.lockUsesWorkspace = true;
    if (blocked) mixed.preconditions[0].state = 'unavailable';
    const failed = output(composer, mixed); assert.equal(failed.status, 1);
    assert.equal(failed.record.state, blocked ? 'blocked' : 'failed'); assert.equal(failed.record.registryConsumerInput, null);
    assert.equal(failed.record.summary.blockedPreconditionCount, blocked ? 1 : 0); assert.equal(failed.record.summary.failureCount, 1);
    assert.deepEqual(failed.record.ruleResults.map(x => x.status), [blocked ? 'blocked' : 'passed', 'failed']);
  }
});

test('composer distinguishes precondition-only failure from downstream-only rejection', () => {
  const input = seed(composer), missing = structuredClone(input); missing.preconditions = [missing.preconditions[0]];
  const absent = output(composer, missing); assert.equal(absent.status, 1); assert.equal(absent.record.state, 'failed');
  assert.equal(absent.record.registryConsumerInput, null); assert.equal(absent.record.summary.failureCount, 6);
  assert.equal(absent.record.summary.blockedPreconditionCount, 0);
  assert.deepEqual(absent.record.ruleResults.map(x => [x.ruleId, x.status]), [[`proofkit.${composer}.preconditions`, 'failed'], [`proofkit.${composer}.accepted`, 'passed']]);
  const invalidChild = structuredClone(input); invalidChild.releaseAuthorityInput.package.artifactPath = 'artifacts/package/other-1.2.3.tgz';
  const release = invoke('release-authority', invalidChild.releaseAuthorityInput);
  assert.equal(release.status, 0); assert.equal(release.stderr, ''); assert.equal(JSON.parse(release.stdout).state, 'passed');
  assert.ok(release.stdout.endsWith('\n')); invalidChild.releaseAuthorityReport.outputSha256 = hash(release.stdout);
  const rejected = output(composer, invalidChild); assert.equal(rejected.status, 1); assert.equal(rejected.record.state, 'failed');
  assert.equal(rejected.record.registryConsumerInput, null); assert.equal(rejected.record.summary.failureCount, 1);
  assert.equal(rejected.record.summary.blockedPreconditionCount, 0);
  assert.deepEqual(rejected.record.ruleResults.map(x => [x.ruleId, x.status]), [[`proofkit.${composer}.preconditions`, 'passed'], [`proofkit.${composer}.failure.001`, 'failed']]);
  assert.equal(rejected.record.ruleResults[1].message, 'composed registry-consumer input must be accepted by registry-consumer');
});

const at = (value, path) => path.reduce((current, key) => current[key], value);
function arbitrary(command, direction, path) {
  return direction === 'input' && (path.includes('releaseAuthorityInput') || command === external && path.includes('witnessPlan') && (path.includes('vocabulary') || path.includes('commands') && path.some(x => typeof x === 'number')))
    || direction === 'output' && command === composer && path.includes('registryConsumerInput') && path.includes('releaseAuthorityInput');
}
function optional(command, direction, path) {
  return direction === 'input' && (path.at(-1) === 'releaseAuthorityInput' || command === registry && path.join('.') === 'proof')
    || direction === 'output' && command === composer && (path.join('.') === 'registryConsumerInput.proof' || path.at(-1) === 'releaseAuthorityInput');
}
function nullable(command, direction, path) {
  return arbitrary(command, direction, path) || direction === 'input' && (command === registry && path.join('.') === 'proof' || command === external && path.join('.') === 'evidence.consumerProof')
    || direction === 'output' && command === composer && ['registryConsumerInput', 'registryConsumerInput.proof'].includes(path.join('.'));
}
function paths(value, path = [], rows = []) {
  rows.push({path, value});
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) paths(child, [...path, Array.isArray(value) ? Number(key) : key], rows);
  return rows;
}
function replace(value, path, replacement) {
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = replacement; return copy;
}
test('populated consumer records close nested key type optional null and cardinality boundaries', () => {
  let checked = 0;
  for (const row of baseline.observations.filter(x => x.report && x.name !== 'pointer')) {
    const input = JSON.parse(row.input), record = JSON.parse(invoke(row.command, input).stdout);
    for (const [direction, specimen] of [['input', input], ['output', record]]) {
      const valid = validators[row.command][direction]; assert.equal(valid(specimen), true);
      for (const {path, value} of paths(specimen)) {
        if (arbitrary(row.command, direction, path)) continue;
        if (value && !Array.isArray(value) && typeof value === 'object') {
          const unknown = structuredClone(specimen); at(unknown, path).foreign = true;
          assert.equal(valid(unknown), false, `${row.command}/${direction}/${path}/unknown`);
          for (const key of Object.keys(value)) {
            const missing = structuredClone(specimen); delete at(missing, path)[key];
            assert.equal(valid(missing), optional(row.command, direction, [...path, key]), `${row.command}/${direction}/${path}/${key}/missing`);
          }
        }
        if (!path.length) continue;
        assert.equal(valid(replace(specimen, path, null)), nullable(row.command, direction, path), `${row.command}/${direction}/${path}/null`);
        const wrong = typeof value === 'string' || value === null ? 0 : 'wrong-type';
        assert.equal(valid(replace(specimen, path, wrong)), false, `${row.command}/${direction}/${path}/type`); checked++;
        if (typeof value === 'string') for (const blank of ['', ' \t\r\n']) {
          assert.equal(valid(replace(specimen, path, blank)), false, `${row.command}/${direction}/${path}/blank`);
        }
      }
    }
  }
  assert.ok(checked > 3000);
  const preconditions = seed(composer); preconditions.preconditions = [];
  assert.equal(validators[composer].input(preconditions), false, 'composer/preconditions/minItems');
  for (const command of commands) {
    const empty = seed(command); (empty.input ?? empty).nonClaims = [];
    assert.equal(validators[command].input(empty), command === composer, command + '/nonClaims/minItems');
  }
  const witness = seed(external); witness.input.witnessPlan.commands = [];
  assert.equal(validators[external].input(witness), false, 'external/witness/commands/minItems');
});

test('normalized text and unbounded registry identity do not acquire raw literal or RuleID restrictions', () => {
  for (const command of commands) {
    const input = seed(command), source = input.input ?? input;
    source.packageName = ' ' + source.packageName + ' ';
    if (command !== composer) (command === external ? input.evidence.consumerProof : input.proof).tempConsumerLocation = ' os-temp ';
    const normalized = output(command, input); assert.equal(normalized.status, 0);
  }
  const rawEnum = seed(composer); rawEnum.preconditions[0].state = ' available ';
  const rejected = invoke(composer, rawEnum); assert.equal(rejected.status, 1); assert.equal(rejected.stdout, ''); assert.notEqual(rejected.stderr, '');
  assert.equal(validators[composer].input(rawEnum), false);
  const input = seed(registry); input.input.consumerId = 'x'.repeat(300);
  assert.equal(output(registry, input).record.reportId.length, 300);
});

test('fixed output literals tuples and failure sequences have discriminating same-type neighbors', () => {
  for (const command of commands) {
    const input = seed(command), passed = output(command, input).record;
    for (const path of [['schemaVersion'], [command === composer ? 'compositionKind' : 'reportKind']]) {
      const value = at(passed, path), bad = typeof value === 'number' ? value + 1 : value + '.foreign';
      assert.equal(validators[command].output(replace(passed, path, bad)), false);
    }
    const extra = structuredClone(passed); extra.ruleResults.push(structuredClone(extra.ruleResults[0]));
    assert.equal(validators[command].output(extra), false);
    const diagnostic = structuredClone(passed);
    if (command !== composer) {diagnostic.diagnostics.reverse(); assert.equal(validators[command].output(diagnostic), false);}
    if (command === external) {
      assert.equal(validators[external].output(replace(passed, ['summary', 'localWorkspaceFallbackPreserved'], false)), false);
      assert.equal(validators[external].output(replace(passed, ['summary', 'pilotMode'], 'blocking')), false);
    }
    const failed = structuredClone(input); (failed.input ?? failed).releaseAuthorityInput = null;
    const record = output(command, failed).record;
    const bad = structuredClone(record); bad.ruleResults.at(-1).ruleId += '.foreign';
    assert.equal(validators[command].output(bad), false);
  }
  const input = seed(external); input.input.witnessPlan.vocabulary = null;
  assert.equal(validators[external].input(input), false);
  const arbitrary = seed(external); arbitrary.input.witnessPlan.commands = [{foreign: ['arbitrary child']}];
  assert.equal(validators[external].input(arbitrary), true); assert.equal(output(external, arbitrary).record.state, 'failed');
});

test('raw input literals and bounded identifiers retain independent same-type domain oracles', () => {
  const literals = {
    [external]: [[['schemaVersion'], 1], [['input', 'schemaVersion'], 1], [['evidence', 'schemaVersion'], 1],
      [['input', 'pilotMode'], 'non_blocking'], [['input', 'rollback', 'dependencyRemoval'], 'temp_consumer_package_and_lockfile'],
      [['input', 'rollback', 'localWorkspaceFallbackPreserved'], true]],
    [registry]: [[['schemaVersion'], 1], [['input', 'schemaVersion'], 1]],
    [composer]: [[['schemaVersion'], 1]],
  };
  for (const command of commands) {
    const valid = validators[command].input, input = seed(command);
    assert.equal(valid(input), true);
    for (const [path, expected] of literals[command]) {
      assert.equal(at(input, path), expected);
      const wrong = typeof expected === 'string' ? expected + '.foreign' : typeof expected === 'boolean' ? !expected : expected + 1;
      assert.equal(valid(replace(input, path, wrong)), false, `${command}/${path}/same-type-literal`);
    }
  }
  const bounds = {
    [external]: [['input', 'pilotId'], ['input', 'binarySmokeProbeRuleId']],
    [composer]: [['compositionId'], ['consumerId'], ['preconditions', 0, 'preconditionId']],
  };
  for (const [command, paths] of Object.entries(bounds)) for (const path of paths) {
    const input = seed(command), valid = validators[command].input;
    assert.equal(valid(replace(input, path, 'a'.repeat(256))), true, `${command}/${path}/accepted256`);
    assert.equal(valid(replace(input, path, 'a'.repeat(257))), false, `${command}/${path}/rejected257`);
    for (const value of ['A', 'a0', 'A_b.c:D-e']) assert.equal(valid(replace(input, path, value)), true, `${command}/${path}/grammar-positive`);
    for (const value of ['1bad', '.bad', 'bad.', 'bad..id', 'bad id', 'bad/id', 'bad\nid', '\u00e9']) {
      const bad = replace(input, path, value);
      assert.equal(valid(bad), false, `${command}/${path}/grammar-negative`);
      const result = invoke(command, bad);
      assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.match(result.stderr, /stable rule identifier text/);
    }
  }
  const input = seed(composer), state = ['preconditions', 0, 'state'];
  for (const value of ['available', 'unavailable']) assert.equal(validators[composer].input(replace(input, state, value)), true);
  for (const value of ['blocked', ' available ']) assert.equal(validators[composer].input(replace(input, state, value)), false);
});

test('output identifiers retain raw grammar and registry identity remains ordinary text', () => {
  for (const [command, path] of [[external, ['reportId']], [composer, ['compositionId']]]) {
    const record = output(command, seed(command)).record, valid = validators[command].output;
    for (const value of ['A', 'a0', 'A_b.c:D-e', 'a'.repeat(256)]) {
      assert.equal(valid(replace(record, path, value)), true, `${command}/${path}/grammar-positive`);
    }
    for (const value of ['1bad', '.bad', 'bad.', 'bad..id', 'bad id', 'bad/id', 'bad\nid', '\u00e9', 'a'.repeat(257)]) {
      assert.equal(valid(replace(record, path, value)), false, `${command}/${path}/grammar-negative`);
    }
  }
  for (const value of ['1bad', 'bad id', 'bad/id', '\u00e9']) {
    const input = seed(registry); input.input.consumerId = value;
    const result = output(registry, input);
    assert.equal(result.status, 0); assert.equal(result.record.reportId, value);
  }
});

test('output domains distinguish exact states literals counts and empty diagnostic tuples', () => {
  const acceptedMessages = {
    [external]: 'external consumer evidence is explicit and bounded to the tarball pilot channel',
    [registry]: 'registry consumer install proof accepted',
    [composer]: 'registry-consumer input composition is accepted by registry-consumer',
  };
  for (const command of commands) {
    const record = output(command, seed(command)).record, valid = validators[command].output;
    const states = command === composer ? ['passed', 'failed', 'blocked'] : ['passed', 'failed'];
    for (const value of states) assert.equal(valid(replace(record, ['state'], value)), true, `${command}/state/allowed`);
    for (const value of ['unknown', 'not_run', ...(command === composer ? [] : ['blocked'])]) {
      assert.equal(valid(replace(record, ['state'], value)), false, `${command}/state/forbidden`);
    }
    const index = command === composer ? 1 : 0;
    const literals = [[['ruleResults', index, 'ruleId'], `proofkit.${command}.accepted`],
      [['ruleResults', index, 'status'], 'passed'], [['ruleResults', index, 'message'], acceptedMessages[command]]];
    if (command === composer) {
      literals.push([['ruleResults', 0, 'ruleId'], 'proofkit.registry-consumer-proof-input-compose.preconditions']);
      for (const value of ['passed', 'failed', 'blocked']) assert.equal(valid(replace(record, ['ruleResults', 0, 'status'], value)), true);
      assert.equal(valid(replace(record, ['ruleResults', 0, 'status'], 'unknown')), false);
      for (const field of ['blockedPreconditionCount', 'failureCount']) {
        assert.equal(valid(replace(record, ['summary', field], 0)), true);
        for (const value of [-1, 0.5]) assert.equal(valid(replace(record, ['summary', field], value)), false, `${command}/${field}/numeric-domain`);
      }
    } else {
      const keys = command === external ? ['artifactEvidence', 'consumerProof'] : ['consumerProof', 'registryArtifact'];
      keys.forEach((key, i) => literals.push([['diagnostics', i, 'key'], key]));
    }
    if (command === external) {
      literals.push([['summary', 'packageName'], '@research-engineering/agentic-proofkit']);
      for (const channel of ['github_release_archive', 'pypi_registry_release', 'python_wheel_candidate', 'registry_release', 'tarball_pilot', 'invalid']) {
        assert.equal(valid(replace(record, ['summary', 'releaseAuthorityChannel'], channel)), true);
      }
      assert.equal(valid(replace(record, ['summary', 'releaseAuthorityChannel'], 'foreign')), false);
    }
    for (const [path, value] of literals) {
      assert.equal(at(record, path), value);
      assert.equal(valid(replace(record, path, value + '.foreign')), false, `${command}/${path}/literal`);
    }
    const minimum = command === composer ? 4 : 2;
    assert.equal(valid(replace(record, ['nonClaims'], record.nonClaims.slice(0, minimum))), true);
    assert.equal(valid(replace(record, ['nonClaims'], record.nonClaims.slice(0, minimum - 1))), false);
    const input = seed(command); (input.input ?? input).releaseAuthorityInput = null;
    const failed = output(command, input).record;
    for (const specimen of [record, failed]) {
      assert.equal(valid(replace(specimen, ['ruleResults'], [])), false);
      specimen.ruleResults.forEach((rule, i) => {
        assert.deepEqual(rule.diagnostics, []);
        assert.equal(valid(replace(specimen, ['ruleResults', i, 'diagnostics'], ['foreign'])), false);
        if (rule.status === 'failed') assert.equal(valid(replace(specimen, ['ruleResults', i, 'status'], 'passed')), false);
      });
    }
    if (command !== composer) {
      const absent = seed(command);
      if (command === external) absent.evidence.consumerProof = null; else delete absent.proof;
      const withoutProof = output(command, absent).record, i = command === external ? 1 : 0;
      assert.deepEqual(withoutProof.diagnostics[i].value, {executed: false});
      assert.equal(valid(replace(withoutProof, ['diagnostics', i, 'value', 'executed'], true)), false);
    }
  }
});
