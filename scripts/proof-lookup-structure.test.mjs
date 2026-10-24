import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test, {before, after} from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {assertCLITransport, spawnWithInputFile} from './cli-process.mjs';

const root = new URL('../', import.meta.url);
const source = 'requirement-proof-source-set', view = 'requirement-proof-view';
const baseline = JSON.parse(readFileSync(new URL('internal/app/testdata/proof-lookup-native-observations.json', root)));
assert.equal(baseline.head, 'a9f3964d1ca6b5526ee3cab6ba20d7e59f18acba');
assert.equal(baseline.tree, 'f7379a302945b684346604c21e68f26e8fe4f49b');
assert.equal(baseline.observations.length, 73);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_LOOKUP_CONTRACT || new URL('proofkit/cli-contract.v2.json', root)));
const validators = Object.fromEntries([source, view].map(command => [command, Object.fromEntries(['input', 'output'].map(direction => {
  const id = `proofkit.${command}.${direction}.v2.json-schema`;
  assert.equal(contract.commands.find(x => x.command === command)[direction + 'Contract'].rootDefinitionRef, id);
  return [direction, contract.contractDefinitions.find(x => x.definitionId === id).fieldTree.variants.map(row => {
    const ajv = new Ajv2020({strict: false, validateFormats: false});
    return {id: row.variantId, check: ajv.compile(row.schema)};
  })];
}))]));
function valid(command, direction, value) {
  const matches = validators[command][direction].filter(row => row.check(value));
  return matches.length === 1;
}
const hash = value => createHash('sha256').update(value).digest('hex');
// Declared, single-purpose deltas from the frozen predecessor streams. The
// corpus stays untouched; each delta names its rows and exact byte change.
// The deltas apply in order; a current stream is inverted newest first.
// The browserdoc stylesheet that the design-token delta replaced.
const tokenDeltaReplacedStyle = [
  ':root{color-scheme:light dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.45;background:#f7f7f4;color:#1f2428}',
  'body{margin:0;overflow-wrap:anywhere}',
  'main{max-width:1120px;margin:0 auto;padding:32px 20px 56px}',
  'header{margin-bottom:20px}',
  'h1{font-size:clamp(1.7rem,2.8vw,2.6rem);line-height:1.1;margin:0}',
  'h2{font-size:1.05rem;margin:0 0 12px}',
  'h3{font-size:.95rem;margin:18px 0 8px}',
  '.eyebrow{font-size:.78rem;font-weight:700;letter-spacing:0;text-transform:uppercase;color:#586069;margin:0 0 8px}',
  'a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}',
  '.summary,.hierarchy,.controls,.exports,.card,.table-view,.non-claims{background:#fff;border:1px solid #d8dee4;border-radius:8px;box-shadow:0 1px 2px rgba(31,35,40,.04)}',
  '.summary{padding:16px;margin-bottom:16px}',
  '.hierarchy{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;padding:16px;margin-bottom:16px}',
  '.hierarchy section{min-width:0}',
  '.hierarchy h2,.card-group>h2{font-size:.88rem;text-transform:uppercase;letter-spacing:0;color:#586069;margin:0 0 10px}',
  '.hierarchy ul{margin:0;padding-left:18px}',
  '.hierarchy li{margin:4px 0}.hierarchy span,.card-group>h2 span{font-weight:400;color:#586069}',
  'dl{display:grid;grid-template-columns:minmax(140px,220px) 1fr;gap:8px 14px;margin:0}',
  'dt{font-weight:700;color:#4b5563}',
  'dd{margin:0;min-width:0}',
  'code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em;background:#f1f5f9;border-radius:4px;padding:.1em .3em}',
  '.controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;align-items:end;padding:14px;margin-bottom:10px;position:sticky;top:0;z-index:1}',
  '.control{display:grid;gap:6px;min-width:0}',
  '.search-label{position:absolute;left:-10000px}',
  'input[type=search],select{width:100%;box-sizing:border-box;border:1px solid #768390;border-radius:6px;padding:8px 10px;background:#fff;color:inherit}',
  '.toggle{white-space:nowrap;font-size:.92rem}',
  '.exports{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:14px;margin-bottom:10px}',
  '.exports h2{font-size:.88rem;text-transform:uppercase;letter-spacing:0;color:#586069;margin:0 8px 0 0}',
  'button{border:1px solid #768390;border-radius:6px;background:#f6f8fa;color:inherit;padding:8px 10px;cursor:pointer}button:hover{background:#eef2f6}',
  '.result-count{margin:12px 2px;color:#586069}',
  '.cards{display:grid;gap:18px}',
  '.cards[hidden]{display:none}',
  '.card-group[hidden]{display:none}',
  '.card-group{display:grid;gap:12px;scroll-margin-top:86px}',
  '.card-group>h2{border-bottom:1px solid #d8dee4;padding-bottom:8px}',
  '.card{padding:18px}',
  '.proofkit-id{display:inline-block;margin-right:8px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}',
  'html[data-show-ids=false] .proofkit-id{display:none}',
  '.proofkit-title{font-weight:700}',
  'details{border:1px solid #d8dee4;border-radius:6px;margin-top:12px;padding:10px 12px}',
  'summary{cursor:pointer;font-weight:700}',
  '.table-view{padding:0;overflow:hidden}',
  '.table-scroll{overflow:auto}',
  'table{width:100%;border-collapse:collapse;font-size:.92rem}',
  'th,td{border-bottom:1px solid #d8dee4;padding:10px 12px;text-align:left;vertical-align:top}',
  'th{position:sticky;top:0;background:#f6f8fa;font-size:.78rem;text-transform:uppercase;letter-spacing:0;color:#586069}',
  '.non-claims{margin-top:18px;padding:18px}',
  'ul{margin:8px 0 0;padding-left:22px}',
  '@media (max-width:720px){main{padding:24px 12px 40px}.controls{grid-template-columns:1fr;position:static}dl{grid-template-columns:1fr}.summary,.controls,.exports,.card,.non-claims{border-radius:6px}}',
  '@media (prefers-color-scheme:dark){:root{background:#101418;color:#e6edf3}.summary,.hierarchy,.controls,.exports,.card,.table-view,.non-claims{background:#161b22;border-color:#30363d}.eyebrow,.result-count,dt,.hierarchy h2,.card-group>h2,.hierarchy span,.card-group>h2 span,th,.exports h2{color:#9da7b1}input[type=search],select,th{background:#0d1117}input[type=search],select,button{border-color:#8b949e}button{background:#21262d}button:hover{background:#30363d}code{background:#0d1117}details,th,td,.card-group>h2{border-color:#30363d}a{color:#58a6ff}}',
].join('');
const declaredStreamDeltas = Object.freeze([Object.freeze({
  id: 'KERNEL-02',
  reason: 'The shared browserdoc stylesheet hides card groups without a matching record.',
  rows: Object.freeze(['compact-html', 'maliciousCompact-html', 'structured-html']),
  anchor: '.cards[hidden]{display:none}',
  insertion: '.card-group[hidden]{display:none}',
}), Object.freeze({
  id: 'UI-DESIGN-01',
  reason: 'The single style element holds the design-token stylesheet and then the browserdoc stylesheet that reads its tokens.',
  rows: Object.freeze(['compact-html', 'maliciousCompact-html', 'structured-html']),
  styleSHA256: '24a618da1cb7e81b0dfa7e0c8d51d49bcfa06938419eae7af9b60dc2ccf4735d',
  replacedStyle: tokenDeltaReplacedStyle,
})]);
const count = (text, needle) => text.split(needle).length - 1;
// Returns the stream before one delta, or null when the bytes do not carry
// exactly that delta at exactly that position.
function invertDelta(delta, stdout) {
  const style = stdout.indexOf('<style>'), styleEnd = stdout.indexOf('</style>');
  if (count(stdout, '<style>') !== 1 || count(stdout, '</style>') !== 1 || styleEnd < style) return null;
  if (delta.replacedStyle !== undefined) {
    // The whole content of the only style element is the declared stylesheet;
    // every byte outside it is conserved.
    const content = style + '<style>'.length;
    if (hash(stdout.slice(content, styleEnd)) !== delta.styleSHA256) return null;
    return stdout.slice(0, content) + delta.replacedStyle + stdout.slice(styleEnd);
  }
  const at = stdout.indexOf(delta.anchor + delta.insertion);
  if (count(stdout, delta.insertion) !== 1 || at < style || at + delta.anchor.length + delta.insertion.length > styleEnd) return null;
  return stdout.slice(0, at + delta.anchor.length) + stdout.slice(at + delta.anchor.length + delta.insertion.length);
}
// Returns the predecessor stdout implied by the declared deltas, or null when
// the current bytes do not carry exactly those deltas.
function predecessorStdout(rowName, stdout, deltas = declaredStreamDeltas) {
  let current = stdout;
  for (const delta of deltas.toReversed()) {
    if (!delta.rows.includes(rowName)) continue;
    current = invertDelta(delta, current);
    if (current === null) return null;
  }
  return current;
}
const conservesPredecessor = (row, stdout, deltas = declaredStreamDeltas) => {
  const predecessor = predecessorStdout(row.name, stdout, deltas);
  return predecessor !== null && hash(predecessor) === row.stdoutSHA256;
};
const seed = name => JSON.parse(baseline.observations.find(row => row.name === name).input);
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'proofkit-lookup-')); binary = join(directory, 'agentic-proofkit');
  execFileSync('go', ['build', '-mod=readonly', '-o', binary, './cmd/agentic-proofkit'], {cwd: root, timeout: 120000,
    env: {...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off'}});
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
function invoke(command, value, flags = []) {
  const result = spawnWithInputFile(binary, [command, '--input', '-', ...flags], {
    input: JSON.stringify(value), encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20});
  return assertCLITransport(result);
}
function output(command, input, flags = []) {
  const result = invoke(command, input, flags);
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  const record = JSON.parse(result.stdout);
  assert.ok(valid(command, 'input', input)); assert.ok(valid(command, 'output', record));
  return record;
}

test('lookup contracts conserve73actual predecessor process and rendered streams', () => {
  for (const row of baseline.observations) {
    const result = spawnWithInputFile(binary, row.argv, {input: row.carrier === 'stdin' ? row.input : undefined,
      stdio: row.carrier === 'argv-only' ? ['ignore', 'pipe', 'pipe'] : undefined,
      encoding: 'utf8', timeout: 10000, maxBuffer: 2 << 20});
    assertCLITransport(result, row.name);
    assert.equal(result.status, row.exitCode, row.name);
    assert.ok(conservesPredecessor(row, result.stdout), row.name + '/stdout');
    assert.equal(hash(result.stderr), row.stderrSHA256, row.name + '/stderr');
    if (row.exitCode || row.format !== 'json') continue;
    const input = row.name === 'pointer' ? JSON.parse(row.input).payload : JSON.parse(row.input);
    assert.ok(valid(row.command, 'input', input), row.name + '/input');
    assert.ok(valid(row.command, 'output', JSON.parse(result.stdout)), row.name + '/output');
  }
});

test('the declared stream deltas are exact, positioned and limited to their rows', () => {
  const [kernel, tokens] = declaredStreamDeltas;
  assert.deepEqual(declaredStreamDeltas.map(delta => delta.id), ['KERNEL-02', 'UI-DESIGN-01']);
  const rows = baseline.observations.filter(row => row.format === 'html');
  for (const delta of declaredStreamDeltas) assert.deepEqual(rows.map(row => row.name), [...delta.rows]);
  const row = rows[0];
  const current = assertCLITransport(spawnWithInputFile(binary, row.argv, {input: row.input, encoding: 'utf8', timeout: 10000,
    maxBuffer: 2 << 20}), row.name).stdout;
  assert.ok(conservesPredecessor(row, current), 'current stdout must carry exactly the declared deltas');
  // The design-token delta: the style element moved, a second style element
  // and one changed byte outside the style each break conservation.
  const element = current.slice(current.indexOf('<style>'), current.indexOf('</style>') + '</style>'.length);
  const moved = current.replace(element, '').replace('</body>', element + '</body>');
  const second = current.replace('</head>', '<style></style></head>');
  const outside = current.replace('<main', '<main ');
  const inside = current.replace('</style>', ' </style>');
  for (const [name, mutated] of [['style moved', moved], ['second style', second], ['byte outside the style', outside], ['byte inside the style', inside]]) {
    assert.notEqual(mutated, current, name);
    assert.equal(conservesPredecessor(row, mutated), false, name);
  }
  // The card-group delta, checked in the stream before the design-token delta.
  const beforeTokens = invertDelta(tokens, current);
  assert.ok(beforeTokens !== null && conservesPredecessor(row, beforeTokens, [kernel]), 'the replaced style must carry exactly the card-group delta');
  const rule = kernel.insertion;
  const twice = beforeTokens.replace(kernel.anchor + rule, kernel.anchor + rule + rule);
  const ruleMoved = beforeTokens.replace(kernel.anchor + rule, kernel.anchor).replace('</style>', rule + '</style>');
  const otherByte = beforeTokens.replace('<main', '<main ');
  for (const [name, mutated] of [['rule twice', twice], ['rule moved', ruleMoved], ['other byte', otherByte]]) {
    assert.notEqual(mutated, beforeTokens, name);
    assert.equal(conservesPredecessor(row, mutated, [kernel]), false, name);
  }
  const unlisted = baseline.observations.find(item => item.format === 'json' && item.exitCode === 0);
  const unlistedCurrent = assertCLITransport(spawnWithInputFile(binary, unlisted.argv, {input: unlisted.input, encoding: 'utf8',
    timeout: 10000, maxBuffer: 2 << 20}), unlisted.name).stdout;
  assert.ok(conservesPredecessor(unlisted, unlistedCurrent), 'unlisted rows stay byte-exact');
  assert.equal(conservesPredecessor(unlisted, unlistedCurrent + kernel.anchor + rule), false, 'delta applied to an unlisted row');
});

test('source index selection preserves order and composes into resolver and view', () => {
  const input = seed('fragments');
  input.projection = {selectedSourceIds: input.sourceSet.sources.map(row => row[0]).reverse()};
  const canonical = output(source, input);
  assert.deepEqual(canonical.selectedSourceIds, input.sourceSet.sources.map(row => row[0]));
  assert.deepEqual(canonical.inputPaths, input.sourceSet.sources.map(row => row[1]).sort());
  assert.equal(canonical.sourceCount, 2); assert.equal(canonical.sourceSetCount, 2);
  assert.equal(canonical.contract.contract_id, input.canonicalEnvelope.contractId);
  input.projection.kind = 'resolver_input';
  const resolved = output(source, input);
  assert.equal(resolved.projectionKind, 'proofkit.requirement-proof-source-set.resolver_input');
  const routes = invoke('requirement-proof-resolver', resolved.resolverInput, ['--local-environment-class', 'local-go']);
  assert.equal(routes.status, 0, routes.stderr); const resolver = JSON.parse(routes.stdout);
  const lookup = output(view, resolved.resolverInput, ['--local-environment-class', 'local-go']);
  assert.equal(lookup.authority, 'lookup_only'); assert.equal(lookup.bindingCount, resolver.bindings.length);
  assert.equal(lookup.commandCount, resolver.commands.length); assert.equal(lookup.requirementCount, new Set(resolver.bindings.map(x => x.requirementId)).size);
  assert.equal(lookup.preconditionedBindingCount, resolver.bindings.filter(x => x.preconditioned).length);
  assert.deepEqual(lookup.bindings.map(x => x.declaredWitnessRoutes.map(r => r.role)), resolver.bindings.map(() => ['falsification', 'positive']));
  for (const binding of lookup.bindings) for (const route of binding.declaredWitnessRoutes) assert.equal(route.bindingRecordId, binding.bindingRecordId);
});

const at = (value, path) => path.reduce((current, key) => current[key], value);
function replace(value, path, replacement) {
  if (!path.length) return replacement;
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = replacement; return copy;
}
function walk(value, path = [], result = []) {
  result.push({path, value});
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) walk(child, [...path, Array.isArray(value) ? Number(key) : key], result);
  return result;
}
test('populated lookup variants close all object members and nonnull type boundaries', () => {
  let checked = 0;
  for (const [command, name, flags] of [[source, 'canonical', []], [source, 'canonical-resolver', []],
    [view, 'structured', []], [view, 'compact', ['--local-environment-class', 'local-go']]]) {
    const input = seed(name);
    if (command === source) input.projection = {kind: name.endsWith('resolver') ? 'resolver_input' : 'canonical_contract', selectedSourceIds: input.sourceSet.sources.map(row => row[0])};
    const record = output(command, input, flags);
    for (const [direction, specimen] of [['input', input], ['output', record]]) {
      for (const {path, value} of walk(specimen)) {
        const optional = command === source && direction === 'input' && (path.join('.') === 'projection' || path.join('.') === 'projection.kind' || path.join('.') === 'projection.selectedSourceIds')
          || command === view && direction === 'input' && name === 'structured' && (path[0] === 'selection' || path.at(-1) === 'witnessSelectors');
        if (value && !Array.isArray(value) && typeof value === 'object') {
          const unknown = structuredClone(specimen); at(unknown, path).foreign = true;
          assert.equal(valid(command, direction, unknown), false, `${name}/${direction}/${path}/unknown`);
          for (const key of Object.keys(value)) {
            const field = [...path, key], missing = structuredClone(specimen); delete at(missing, path)[key];
            const mayOmit = command === source && direction === 'input' && field[0] === 'projection'
              || command === view && direction === 'input' && name === 'structured' && (field[0] === 'selection' || key === 'witnessSelectors');
            assert.equal(valid(command, direction, missing), mayOmit, `${name}/${direction}/${field}/missing`);
          }
        }
        assert.equal(valid(command, direction, replace(specimen, path, null)), optional, `${name}/${direction}/${path}/null`);
        const wrong = typeof value === 'string' || value === null ? 0 : 'wrong-type';
        assert.equal(valid(command, direction, replace(specimen, path, wrong)), false, `${name}/${direction}/${path}/type`); checked++;
        if (typeof value === 'string' && (command === source || direction === 'output')) {
          assert.equal(valid(command, direction, replace(specimen, path, '')), false, `${name}/${direction}/${path}/empty`);
        }
      }
    }
  }
  assert.ok(checked > 350);
});

test('source index literals raw enums strict whitespace IDs and tuple arities are exact', () => {
  const input = seed('canonical');
  const populated = structuredClone(input);
  populated.projection = {kind: 'canonical_contract', selectedSourceIds: [input.sourceSet.sources[0][0]]};
  for (const {path, value} of walk(populated)) {
    if (typeof value !== 'string' || path[0] === 'sources' && path.at(-1) === 'text') continue;
    for (const padded of [' ' + value, value + '\n', '\u00a0' + value]) {
      assert.equal(valid(source, 'input', replace(populated, path, padded)), false, 'strict-input/' + path.join('.'));
    }
  }
  const paths = [['schemaVersion'], ['sourceSet', 'schema_version'], ['sourceSet', 'contract_kind'], ['sourceSet', 'contract_id'],
    ['sourceSet', 'authority_state'], ['sourceSet', 'normalization_profile'], ['canonicalEnvelope', 'schemaVersion'],
    ['canonicalEnvelope', 'contractKind'], ['canonicalEnvelope', 'authorityState'], ['canonicalEnvelope', 'normalizationProfile']];
  for (const path of paths) assert.equal(valid(source, 'input', replace(input, path, typeof at(input, path) === 'number' ? 3 : 'foreign')), false, path.join('.'));
  for (const path of [['sourceSet', 'source_columns'], ['canonicalEnvelope', 'surfaceColumns'], ['canonicalEnvelope', 'bindingColumns'], ['canonicalEnvelope', 'witnessColumns']]) {
    const columns = at(input, path);
    for (const invalid of [columns.slice(0, -1), [...columns, 'foreign'], columns.toReversed(), ...columns.map((_, index) => columns.map((x, i) => i === index ? 'foreign' : x))]) assert.equal(valid(source, 'input', replace(input, path, invalid)), false, path.join('.'));
  }
  for (const path of [['canonicalEnvelope', 'contractId'], ['sources', 0, 'path'], ['sourceSet', 'sources', 0, 1]]) {
    for (const value of ['', ' ', '\u00a0', ' padded', 'padded\n']) assert.equal(valid(source, 'input', replace(input, path, value)), false, path.join('.'));
    assert.equal(valid(source, 'input', replace(input, path, '\ufeff')), true, 'BOM is not Go TrimSpace whitespace');
  }
  const id = ['sourceSet', 'sources', 0, 0];
  for (const value of ['a'.repeat(256), 'source.example']) assert.ok(valid(source, 'input', replace(input, id, value)));
  for (const value of ['', 'a'.repeat(257), ' source.example', 'source/example']) assert.equal(valid(source, 'input', replace(input, id, value)), false);
  const selected = ['projection', 'selectedSourceIds', 0];
  for (const length of [256, 257]) {
    assert.equal(valid(source, 'input', replace(populated, selected, 'a'.repeat(length))), length === 256, 'selected-input/length-' + length);
  }
  const bounded = replace(populated, id, 'a'.repeat(256));
  bounded.projection.selectedSourceIds = ['a'.repeat(256)];
  for (const kind of ['canonical_contract', 'resolver_input']) {
    const variant = structuredClone(bounded); variant.projection.kind = kind;
    assert.deepEqual(output(source, variant).selectedSourceIds, bounded.projection.selectedSourceIds, kind + '/valid-maximum');
  }
  for (const sourceId of ['A', 'Source.Local', 'A_B.9-C:Part_3']) for (const kind of ['canonical_contract', 'resolver_input']) {
    const variant = replace(populated, id, sourceId);
    variant.projection = {kind, selectedSourceIds: [sourceId]};
    assert.deepEqual(output(source, variant).selectedSourceIds, [sourceId], kind + '/lexical-preservation');
  }
  assert.equal(invoke(source, replace(bounded, selected, 'a'.repeat(257))).status, 1);
  for (const value of ['', '0'.repeat(63), '0'.repeat(65), 'g'.repeat(64), 'A'.repeat(64), 'sha256:' + '0'.repeat(64)]) assert.equal(valid(source, 'input', replace(input, ['sourceSet', 'sources', 0, 2], value)), false);
  for (const role of ['foreign', ' requirement_proof_route_declaration_contract ']) assert.equal(valid(source, 'input', replace(input, ['sourceSet', 'sources', 0, 3], role)), false);
  for (const row of [input.sourceSet.sources[0].slice(0, -1), [...input.sourceSet.sources[0], 'foreign']]) assert.equal(valid(source, 'input', replace(input, ['sourceSet', 'sources', 0], row)), false);
  for (const path of [['canonicalEnvelope', 'nonClaims'], ['sourceSet', 'non_claims'], ['sourceSet', 'sources'], ['sourceSet', 'sources', 0, 4]]) assert.equal(valid(source, 'input', replace(input, path, [])), false);
  assert.ok(valid(source, 'input', replace(input, ['sources'], [])), 'cross-reference absence is native, not structural');
  assert.ok(valid(source, 'input', replace(input, ['sources', 0, 'text'], ' ')), 'raw nonempty text is not trimmed');
  assert.equal(valid(source, 'input', replace(input, ['sources', 0, 'text'], '')), false);
  for (const projection of [null, {}, {kind: null, selectedSourceIds: null}, {kind: 'canonical_contract'}, {kind: 'resolver_input'}]) assert.ok(valid(source, 'input', replace(input, ['projection'], projection)));
  for (const projection of [{kind: ' resolver_input '}, {kind: 'foreign'}, {selectedSourceIds: []}, {selectedSourceIds: [' a']}]) assert.equal(valid(source, 'input', replace(input, ['projection'], projection)), false);
});

test('source identifier grammar preserves exact guards at every parent occurrence', () => {
  const inputSchema = contract.contractDefinitions.find(row => row.definitionId === 'proofkit.requirement-proof-source-set.input.v2.json-schema').fieldTree.variants[0].schema;
  const outputSchemas = contract.contractDefinitions.find(row => row.definitionId === 'proofkit.requirement-proof-source-set.output.v2.json-schema').fieldTree.variants.map(row => row.schema);
  const schemas = [inputSchema.properties.sourceSet.properties.sources.items.prefixItems[0],
    inputSchema.properties.projection.anyOf[1].properties.selectedSourceIds.anyOf[1].items,
    ...outputSchemas.map(schema => schema.properties.selectedSourceIds.items)];
  for (const schema of schemas) {
    assert.equal(schema.pattern, '^(?:[A-Za-z][A-Za-z0-9_]*(?:[._:-][A-Za-z0-9_]+)*)(?![\\s\\S])');
    assert.equal(schema.maxLength, 256);
  }
  const input = seed('canonical');
  input.projection = {kind: 'canonical_contract', selectedSourceIds: [input.sourceSet.sources[0][0]]};
  const invalid = ['1A', '_A', '\u00c9A', 'A.', 'A..B', 'A-', 'A--B', 'A:', 'A::B', 'A\n'];
  for (const path of [['sourceSet', 'sources', 0, 0], ['projection', 'selectedSourceIds', 0]]) for (const value of invalid) {
    const specimen = replace(input, path, value);
    assert.equal(valid(source, 'input', specimen), false, path.join('/') + '/' + value);
    const result = invoke(source, specimen);
    assert.equal(result.status, 1); assert.equal(result.stdout, '');
    assert.match(result.stderr, /stable rule identifier text/);
  }
  for (const kind of ['canonical_contract', 'resolver_input']) {
    const specimen = structuredClone(input); specimen.projection.kind = kind;
    const record = output(source, specimen);
    for (const value of invalid) assert.equal(valid(source, 'output', replace(record, ['selectedSourceIds', 0], value)), false, kind + '/' + value);
    for (const sourceId of ['A_', 'A__B', 'A._', 'A:0', 'A-0', 'A.0']) {
      const variant = replace(specimen, ['sourceSet', 'sources', 0, 0], sourceId);
      variant.projection.selectedSourceIds = [sourceId];
      assert.deepEqual(output(source, variant).selectedSourceIds, [sourceId], kind + '/valid-segment');
    }
  }
});

test('lookup output identities wire versions counts and ordered route roles are independent', () => {
  for (const [command, name, flags, version] of [[source, 'canonical', [], 2], [source, 'canonical-resolver', [], 2], [view, 'structured', [], 1], [view, 'compact', ['--local-environment-class', 'local-go'], 2]]) {
    const record = output(command, seed(name), flags);
    assert.equal(record.schemaVersion, version);
    for (const key of ['schemaVersion', command === source ? 'projectionKind' : 'viewKind', ...(command === view ? ['authority'] : [])]) {
      assert.equal(valid(command, 'output', replace(record, [key], typeof record[key] === 'number' ? 99 : 'foreign')), false, name + '/' + key);
    }
    for (const key of Object.keys(record).filter(x => x.endsWith('Count'))) {
      for (const value of [-1, 1.5, '0', ...(command === source ? [0] : [])]) assert.equal(valid(command, 'output', replace(record, [key], value)), false, name + '/' + key);
    }
    if (name !== 'compact') continue;
    const path = ['bindings', 0, 'declaredWitnessRoutes'], routes = at(record, path);
    for (const value of [[], routes.slice(0, -1), [...routes, routes[0]], routes.toReversed()]) assert.equal(valid(command, 'output', replace(record, path, value)), false);
    for (const index of [0, 1]) {
      assert.equal(valid(command, 'output', replace(record, [...path, index, 'role'], 'foreign')), false);
      for (const value of [-1, 0.5, 9007199254740992]) assert.equal(valid(command, 'output', replace(record, [...path, index, 'resolutionOrderIndex'], value)), false);
      for (const order of [0, 9007199254740991]) {
        const boundaryInput = seed('compact'), role = routes[index].role;
        boundaryInput.bindings[0][boundaryInput.binding_columns.indexOf(role + '_witness')][boundaryInput.witness_columns.indexOf('resolution_order_index')] = order;
        const boundaryOutput = output(command, boundaryInput, flags);
        assert.equal(at(boundaryOutput, [...path, index, 'resolutionOrderIndex']), order, role + '/order-' + order);
      }
      for (const field of ['bindingRecordId', 'witnessRouteId']) assert.equal(valid(command, 'output', replace(record, [...path, index, field], 'sha256:' + 'A'.repeat(64))), false);
    }
    assert.equal(valid(command, 'output', replace(record, ['localEnvironmentPolicy', 'authority'], 'foreign')), false);
  }
});

test('view output scope and structured classifications retain their owned domains', () => {
  const record = output(view, seed('structured'));
  for (const value of ['foreign', ' slice ']) assert.equal(valid(view, 'output', replace(record, ['scope'], value)), false);
  for (const path of [['requirements', 0, 'claimLevel'], ['requirements', 0, 'proofState'], ['requirements', 0, 'scenarios', 0, 'witnessKind']]) {
    assert.equal(valid(view, 'output', replace(record, path, 'foreign')), false, path.join('.'));
  }
  const count = ['requirements', 0, 'scenarioCount'];
  for (const value of [-1, 1.5, '0']) assert.equal(valid(view, 'output', replace(record, count, value)), false);
  for (const [name, flags, minimum] of [['structured', [], 4], ['compact', ['--local-environment-class', 'local-go'], 6]]) {
    const specimen = output(view, seed(name), flags);
    for (const value of [[], specimen.nonClaims.slice(0, minimum - 1)]) assert.equal(valid(view, 'output', replace(specimen, ['nonClaims'], value)), false);
  }
});

test('empty declarations retain zero counts and explicit empty local policy', () => {
  const compact = seed('compact'); compact.surfaces = []; compact.bindings = []; compact.non_claims = [];
  const lookup = output(view, compact, ['--empty-local-environment-policy']);
  assert.deepEqual(lookup.bindings, []); assert.deepEqual(lookup.localEnvironmentPolicy, {authority: 'caller_provided', localEnvironmentClasses: []});
  for (const field of ['bindingCount', 'commandCount', 'preconditionedBindingCount', 'requirementCount']) assert.equal(lookup[field], 0);
  const structured = seed('structured'); structured.requirements = []; structured.bindings = []; structured.witnessCommands = []; structured.selection = null;
  const empty = output(view, structured); assert.deepEqual(empty.requirements, []);
  for (const field of ['commandCount', 'omittedRequirementCount', 'requirementCount']) assert.equal(empty[field], 0);
  assert.equal(empty.scope, 'slice'); assert.ok(empty.nonClaims.length >= 4);
  const minimum = structuredClone(structured); minimum.nonClaims = [];
  for (const scope of ['graph', 'slice']) {
    const record = output(view, minimum, ['--scope', scope]);
    assert.equal(record.nonClaims.length, 8, scope + '/native-nonclaim-minimum');
  }
});

test('unbound structured requirements retain zero scenarios and empty aggregates', () => {
  const input = seed('structured');
  input.bindings = []; input.witnessCommands = [];
  input.requirements[0].claimLevel = 'advisory'; input.requirements[0].proofState = 'not_bound';
  for (const scope of ['graph', 'slice']) {
    const record = output(view, input, ['--scope', scope]);
    assert.equal(record.scope, scope); assert.equal(record.requirementCount, 1); assert.equal(record.commandCount, 0);
    assert.equal(record.requirements.length, 1); assert.equal(record.requirements[0].requirementId, 'REQ-PROOFKIT-ONE');
    assert.equal(record.requirements[0].proofState, 'not_bound'); assert.equal(record.requirements[0].scenarioCount, 0);
    for (const field of ['scenarios', 'commandIds', 'environmentClasses', 'witnessPaths']) assert.deepEqual(record.requirements[0][field], [], field);
  }
});

test('source output array minima and canonical child headers have separating neighbors', () => {
  for (const name of ['canonical', 'canonical-resolver']) {
    const record = output(source, seed(name));
    for (const field of ['inputPaths', 'selectedSourceIds']) {
      assert.equal(record[field].length, 1);
      assert.ok(valid(source, 'output', replace(record, [field], [record[field][0]])), name + '/' + field + '/singleton');
      assert.equal(valid(source, 'output', replace(record, [field], [])), false, name + '/' + field + '/empty');
      assert.equal(valid(source, 'output', replace(record, [field, 0], ' padded ')), false, name + '/' + field + '/padding');
    }
    for (const value of ['foreign/id', 'a'.repeat(257)]) assert.equal(valid(source, 'output', replace(record, ['selectedSourceIds', 0], value)), false);
  }
  const input = seed('canonical'), payload = JSON.parse(input.sources[0].text);
  payload.surfaces = []; payload.bindings = [];
  input.sources[0].text = JSON.stringify(payload); input.sourceSet.sources[0][2] = hash(input.sources[0].text);
  const record = output(source, input); assert.deepEqual(record.contract.surfaces, []); assert.deepEqual(record.contract.bindings, []);
  for (const field of ['schema_version', 'contract_kind', 'authority_state', 'normalization_profile']) {
    assert.equal(valid(source, 'output', replace(record, ['contract', field], field === 'schema_version' ? 3 : 'foreign')), false, field);
  }
  for (const field of ['surface_columns', 'binding_columns', 'witness_columns']) {
    const columns = record.contract[field];
    for (const value of [columns.slice(0, -1), [...columns, 'foreign'], columns.toReversed(), ...columns.map((_, index) => columns.map((x, i) => i === index ? 'foreign' : x))]) {
      assert.equal(valid(source, 'output', replace(record, ['contract', field], value)), false, field);
    }
  }
  assert.equal(valid(source, 'output', replace(record, ['contract', 'non_claims'], [])), false);
  for (const [index, value] of record.contract.non_claims.entries()) {
    assert.ok(valid(source, 'output', replace(record, ['contract', 'non_claims', index], value)));
    for (const padded of [' ' + value, value + '\n', '\u00a0' + value]) {
      assert.equal(valid(source, 'output', replace(record, ['contract', 'non_claims', index], padded)), false, 'canonical-output/nonclaim-' + index + '/padding');
    }
  }
  for (const value of [' padded', 'padded\n']) assert.equal(valid(source, 'output', replace(record, ['contract', 'contract_id'], value)), false);
});
