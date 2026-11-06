import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Ajv from 'ajv';

import {runDiagnosticEntrypoint} from "./diagnostic.mjs";

await runDiagnosticEntrypoint(() => {
  const read = url => JSON.parse(readFileSync(url, 'utf8'));
  const schema = name => read(new URL('testdata/cyclonedx/' + name, import.meta.url));
  const bom = read(new URL('../artifacts/release/sbom.cdx.json', import.meta.url));

  const ajv = new Ajv({strict: false, validateFormats: false});
  ajv.addSchema(schema('spdx.schema.json'));
  ajv.addSchema(schema('jsf-0.82.schema.json'));
  const validate = ajv.compile(schema('bom-1.6.schema.json'));
  assert(validate(bom), ajv.errorsText(validate.errors));
  assert.equal(bom.specVersion, '1.6');

  const root = bom.metadata.component;
  const components = new Map(bom.components.map(component => [component['bom-ref'], component]));
  assert.equal(components.size, bom.components.length, 'duplicate SBOM component identity');
  assert(!components.has(root['bom-ref']), 'root component is duplicated');
  const dependencies = new Map(bom.dependencies.map(record => [record.ref, record.dependsOn ?? []]));
  assert.equal(dependencies.size, bom.dependencies.length, 'duplicate dependency subject');
  assert(root.purl.startsWith('pkg:npm/'), 'root identity must name its npm package');
  const files = bom.components.filter(component => component['bom-ref'].startsWith('file:'));
  assert(files.length > 0, 'release file inventory is empty');
  assert.deepEqual(dependencies.get(root['bom-ref']), files.map(file => file['bom-ref']).sort());
  for (const file of files) {
    assert(file.purl, 'release file is missing its package identity');
    const ref = file['bom-ref'];
    if (ref.startsWith('file:dist/platform/')) {
      assert(dependencies.get(ref)?.some(target => components.get(target)?.name === 'stdlib'),
        'platform binary is missing its Go standard-library edge');
    }
  }
  for (const [subject, targets] of dependencies) {
    assert(subject === root['bom-ref'] || components.has(subject), 'dangling dependency subject');
    assert(targets.every(target => components.has(target)), 'dangling dependency edge');
  }
});
