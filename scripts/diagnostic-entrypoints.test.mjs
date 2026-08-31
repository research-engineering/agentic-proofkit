import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";

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
