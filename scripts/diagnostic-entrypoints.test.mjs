import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";

import {runDiagnosticEntrypoint} from "./diagnostic.mjs";

test("repository-owned JavaScript entrypoints use the diagnostic boundary", () => {
  const manifest = JSON.parse(readFileSync("package.json", "utf8"));
  const browserInputs = JSON.parse(readFileSync("scripts/browser-runtime-proof-inputs.v1.json", "utf8"));
  const entrypoints = new Set([browserInputs.writerPath]);
  for (const command of Object.values(manifest.scripts)) {
    for (const match of command.matchAll(/(?:^|&&|\|\|)\s*node\s+(scripts\/[^\s]+\.mjs)(?:\s|$)/gu)) {
      entrypoints.add(match[1]);
    }
  }
  assert.deepEqual([...entrypoints].sort(), [
    "scripts/source-hygiene.mjs",
    "scripts/write-browser-proof.mjs",
  ]);
  for (const path of entrypoints) {
    const source = readFileSync(path, "utf8");
    assert.match(source, /import \{runDiagnosticEntrypoint\} from "\.\/diagnostic\.mjs";/u, path);
    assert.match(source, /await runDiagnosticEntrypoint\(/u, path);
  }
});

test("diagnostic entrypoint redacts quoted JSON secret-shaped input", async () => {
  const previousExitCode = process.exitCode;
  let output = "";
  try {
    await runDiagnosticEntrypoint(async () => {
      throw new Error('input rejected: {"password":"synthetic-fixture-value"}');
    }, {write(value) { output += value; }});
    assert.equal(output, "<redacted-diagnostic-value>\n");
    assert.equal(process.exitCode, 1);
  } finally {
    process.exitCode = previousExitCode;
  }
});
