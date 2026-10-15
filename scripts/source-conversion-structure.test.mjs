import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {after, before} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport} from './cli-process.mjs';

const root = new URL('../', import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_SOURCE_CONVERSION_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const command = 'requirement-source-conversion';
const record = contract.commands.find(row => row.command === command);
// Variants are keyed by the published --to target, never by a Go owner name.
const variants = Object.fromEntries(['input', 'output'].map(direction => {
  const binding = record[direction + 'Contract'];
  const definition = contract.contractDefinitions.find(row => row.definitionId === binding.rootDefinitionRef);
  assert.equal(definition.fieldTree.kind, 'structural_json_schema');
  assert.equal(definition.canonicalDigest, binding.rootDefinitionDigest);
  return [direction, Object.fromEntries(definition.fieldTree.variants.map(row => {
    const [flag, target] = row.when[0].split(' ');
    assert.equal(flag, '--to');
    return [target, new Ajv2020({strict: false, validateFormats: false}).compile(row.schema)];
  }))];
}));
const fixtures = new URL('internal/command/requirementsourceconversion/testdata/', root);
const fixtureText = name => readFileSync(new URL(name, fixtures), 'utf8');
const fixture = name => JSON.parse(fixtureText(name));
let directory, binary;

before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-source-conversion-'));
  binary = join(directory, 'proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {
    cwd: root, timeout: 120000, maxBuffer: 2 << 20,
    env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});

function valid(direction, target, value, expected = true, label = '') {
  const check = variants[direction][target];
  assert.ok(check, `${direction} variant --to ${target} is published`);
  assert.equal(check(value), expected, `${direction}/--to ${target}/${label}: ${JSON.stringify(check.errors)}`);
}

function run(input, args, options = {}) {
  const result = spawnSync(binary, [command, '--input', '-', ...args], {
    input, encoding: 'utf8', timeout: 20000, maxBuffer: 16 << 20, ...options,
  });
  return assertCLITransport(result);
}

function converted(input, args, options) {
  const result = run(input, args, options);
  assert.equal(result.stderr, '', result.stderr);
  assert.equal(result.status, 0);
  return JSON.parse(result.stdout);
}

function refused(input, args, fragment) {
  const result = run(input, args);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.ok(result.stderr.includes(fragment), result.stderr);
}

// Key-sorted text identity; arrays keep their order.
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

const byID = key => (left, right) => (left[key] < right[key] ? -1 : left[key] > right[key] ? 1 : 0);

// An independent projection of a canonical grouped source: profile and member
// fields are disjoint, a nonempty stem joins its completion with one space,
// and coordinates are listed in identity order. Go code is not consulted.
function expectedFlat(grouped, basisDigest) {
  const profiles = new Map((grouped.profiles ?? []).map(row => [row.profileId, row.fields]));
  const groups = [...grouped.groups].sort(byID('groupId'));
  const requirements = [];
  for (const group of groups) {
    for (const member of group.members) {
      const shared = profiles.get(group.profileId) ?? {};
      for (const name of Object.keys(member.fields)) assert.ok(!(name in shared), `${name} has two owners`);
      requirements.push({
        requirementId: member.requirementId,
        invariant: group.statementStem === '' ? member.statementCompletion : group.statementStem + ' ' + member.statementCompletion,
        sharedPremises: group.sharedPremises,
        fields: {...shared, ...member.fields},
      });
    }
  }
  return {
    kind: 'proofkit.requirement-source-flat', schemaVersion: 1, basisDigest,
    sourceId: grouped.sourceId, specPackagePath: grouped.specPackagePath, sourceNonClaims: grouped.sourceNonClaims,
    sourceNonClaimRefs: grouped.sourceNonClaimRefs ?? [], nonClaimDefinitions: grouped.nonClaimDefinitions ?? [],
    vocabulary: grouped.vocabulary ?? [], derivations: grouped.derivations ?? [], scenarios: grouped.scenarios ?? [],
    profiles: [...(grouped.profiles ?? [])].sort(byID('profileId')).map(row => ({profileId: row.profileId, fieldIds: Object.keys(row.fields).sort()})),
    groups: groups.map(group => ({
      groupId: group.groupId, profileId: group.profileId,
      statementStemBytes: Buffer.byteLength(group.statementStem, 'utf8'),
      requirementIds: group.members.map(member => member.requirementId).sort(),
    })),
    requirements: requirements.sort(byID('requirementId')),
  };
}

test('published variants are exactly the closed --to targets in both directions', () => {
  assert.deepEqual(Object.keys(variants.input).sort(), ['flat', 'grouped']);
  assert.deepEqual(Object.keys(variants.output).sort(), ['flat', 'grouped']);
  assert.deepEqual(record.flagChoices, {'--to': ['flat', 'grouped']});
  assert.deepEqual(record.flagValueRequirements, [{flag: '--to', requiredFlags: ['--baseline'], value: 'grouped'}]);
});

test('export, import and the independent projection agree with the hand-authored fixtures', () => {
  const groupedText = fixtureText('source.grouped.json');
  const grouped = JSON.parse(groupedText);
  const flat = fixture('source.flat.json');
  // The fixture is canonical grouped text with non-ASCII spelled as escapes.
  const canonicalText = groupedText.replace(/\\u([0-9a-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  const digest = 'sha256:' + createHash('sha256').update(canonicalText, 'utf8').digest('hex');
  assert.equal(flat.basisDigest, digest);
  assert.equal(canonical(expectedFlat(grouped, digest)), canonical(flat));
  valid('input', 'flat', grouped, true, 'grouped fixture');
  valid('input', 'grouped', flat, true, 'flat fixture');

  const exported = converted(groupedText, ['--to', 'flat']);
  valid('output', 'flat', exported, true, 'export');
  assert.equal(canonical(exported), canonical(flat));

  const baseline = join(directory, 'baseline.json');
  writeFileSync(baseline, groupedText);
  const imported = converted(JSON.stringify(exported), ['--to', 'grouped', '--baseline', baseline]);
  valid('output', 'grouped', imported, true, 'import');
  assert.equal(canonical(imported), canonical(grouped));

  // One permitted value edit and its same-shape prohibited neighbor.
  const edited = structuredClone(flat);
  edited.requirements[0].fields.riskClass = 'critical';
  edited.requirements[1].fields.riskClass = 'critical';
  const reconstructed = converted(JSON.stringify(edited), ['--to', 'grouped', '--baseline', baseline]);
  assert.equal(reconstructed.profiles.find(row => row.profileId === 'RPROF-CONV-BLOCKING').fields.riskClass, 'critical');
  const divergent = structuredClone(flat);
  divergent.requirements[0].fields.riskClass = 'critical';
  refused(JSON.stringify(divergent), ['--to', 'grouped', '--baseline', baseline], 'profile_value_disagreement at /requirements/1/fields/riskClass');
});

test('every published variant rejects same-shape structural mutants', () => {
  const grouped = fixture('source.grouped.json');
  const flat = fixture('source.flat.json');
  const mutants = [
    ['flat', flat, value => {value.layout = 'grouped';}, 'surplus root field'],
    ['flat', flat, value => {delete value.basisDigest;}, 'missing basisDigest'],
    ['flat', flat, value => {value.basisDigest = 'sha256:' + 'A'.repeat(64);}, 'uppercase digest'],
    ['flat', flat, value => {value.kind = 'proofkit.requirement-source';}, 'grouped kind'],
    ['flat', flat, value => {value.schemaVersion = 2;}, 'wrong flat version'],
    ['flat', flat, value => {delete value.requirements[0].fields.deferral;}, 'absent resolved field'],
    ['flat', flat, value => {value.requirements[0].groupId = 'RGRP-CONV-REQUESTS';}, 'duplicated membership fact'],
    ['flat', flat, value => {value.groups[1].statementStemBytes = '16';}, 'textual stem bytes'],
    ['flat', flat, value => {value.profiles[0].fieldIds = ['severity'];}, 'unknown profile field'],
    ['grouped', grouped, value => {value.requirements = [];}, 'flat records in grouped source'],
    ['grouped', grouped, value => {value.schemaVersion = 1;}, 'legacy version'],
    ['grouped', grouped, value => {delete value.groups[0].members;}, 'missing members'],
  ];
  for (const [target, base, mutate, label] of mutants) {
    const value = structuredClone(base);
    mutate(value);
    // A flat document is the input of --to grouped and the output of --to flat.
    const [inputTarget, outputTarget] = target === 'flat' ? ['grouped', 'flat'] : ['flat', 'grouped'];
    valid('input', inputTarget, value, false, label);
    valid('output', outputTarget, value, false, label);
  }
});

test('the installed command refuses stale, missing, foreign and legacy sources before output', () => {
  const groupedText = fixtureText('source.grouped.json');
  const flatText = fixtureText('source.flat.json');
  const stale = join(directory, 'stale.json');
  writeFileSync(stale, groupedText.replace('Deferred behavior remains owner-reviewed.', 'Deferred behavior remains reviewed.'));
  refused(flatText, ['--to', 'grouped'], '--to grouped requires --baseline');
  refused(flatText, ['--to', 'grouped', '--baseline', stale], 'refused input: stale_baseline at /basisDigest');
  refused(fixtureText('legacy.v1.json'), ['--to', 'flat'], 'refused input: legacy_source_unsupported at /schemaVersion');
  refused(flatText, ['--to', 'flat'], 'refused input: same_format at /kind');
});

test('--output publishes one new file and never replaces an existing one', () => {
  const groupedText = fixtureText('source.grouped.json');
  const workspace = mkdtempSync(join(directory, 'output-'));
  const published = run(groupedText, ['--to', 'flat', '--output', 'flat.json'], {cwd: workspace});
  assert.equal(published.status, 0, published.stderr);
  assert.equal(published.stdout, '');
  assert.equal(canonical(JSON.parse(readFileSync(join(workspace, 'flat.json'), 'utf8'))), canonical(fixture('source.flat.json')));
  writeFileSync(join(workspace, 'kept.json'), 'owner bytes');
  const refusedOutput = run(groupedText, ['--to', 'flat', '--output', 'kept.json'], {cwd: workspace});
  assert.equal(refusedOutput.status, 1);
  assert.ok(refusedOutput.stderr.includes('output path already exists'), refusedOutput.stderr);
  assert.equal(readFileSync(join(workspace, 'kept.json'), 'utf8'), 'owner bytes');
  assert.deepEqual(readdirSync(workspace).sort(), ['flat.json', 'kept.json']);
});
