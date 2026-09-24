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
  try {
    for (const count of [0, 2, 3]) {
      for (const label of ["password", "authorization"]) {
        let output = "";
        const key = `${label}${"\\".repeat(count)}"`;
        const value = label === "authorization" ? "Basic synthetic-fixture-value" : "synthetic-fixture-value";
        await runDiagnosticEntrypoint(async () => {
          throw new Error(`input rejected: {${key}:"${value}"}`);
        }, {write(value) { output += value; }});
        assert.equal(output, "<redacted-diagnostic-value>\n");
        assert.equal(process.exitCode, 1);
      }
    }
    let serialized = '{"password"\n:"synthetic-fixture-value"}';
    for (let depth = 1; depth <= 3; depth++) {
      serialized = JSON.stringify(serialized);
      let output = "";
      await runDiagnosticEntrypoint(async () => { throw new Error(serialized); }, {write(value) { output += value; }});
      assert.equal(output, "<redacted-diagnostic-value>\n");
    }
  } finally {
    process.exitCode = previousExitCode;
  }
});
