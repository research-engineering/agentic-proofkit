package jsonreportcliadaptersource

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedAdapterBoundsExpandedJSONBeforeEffects(t *testing.T) {
	const harness = `import assert from "node:assert/strict";
import { proofkitStableJsonString, proofkitStableJsonValue, runProofkitJsonCommand, writeProofkitJsonReportOutput } from "./adapter.ts";

const shared = {id: "shared", values: [1, "\""]};
const detached = [{id: "shared", values: [1, "\""]}, {id: "shared", values: [1, "\""]}];
assert.equal(proofkitStableJsonString([shared, shared], "compact"), JSON.stringify(detached) + "\n");
const normalized = proofkitStableJsonValue([shared, shared]);
assert.notEqual(normalized[0], normalized[1]);
assert.deepEqual(normalized[0], normalized[1]);

function oversizedGraph() {
  let visits = 0;
  let value = new Proxy({ payload: "x".repeat(256 * 1024) }, {
    ownKeys(target) {
      if (++visits > 200) throw new Error("test visit guard reached");
      return Reflect.ownKeys(target);
    }
  });
  for (let i = 0; i < 9; i++) value = [value, value];
  return value;
}

const refusal = /stable JSON value exceeds byte limit/u;
assert.throws(() => proofkitStableJsonValue(oversizedGraph()), refusal);
assert.throws(() => writeProofkitJsonReportOutput(oversizedGraph(), null, {
  jsonLayout: "compact",
  writeStdout() { assert.fail("refused output was written"); },
}), refusal);
assert.throws(() => runProofkitJsonCommand("text-policy", oversizedGraph(), [], {
  cwd: process.cwd(), binaryPath: "missing-proofkit-binary",
}), refusal);

const byteLimit = 32 * 1024 * 1024;
const prefix = "a".repeat(byteLimit - 5);
assert.equal(Buffer.byteLength(proofkitStableJsonString(prefix + "\u00e9", "compact")), byteLimit);
assert.throws(() => proofkitStableJsonString(prefix + "a\u00e9", "compact"), refusal);
assert.throws(() => proofkitStableJsonString(prefix + "\u2028", "compact"), refusal);
assert.equal(Buffer.byteLength(proofkitStableJsonString([prefix], "compact")), byteLimit);
assert.throws(() => proofkitStableJsonString([prefix], "pretty"), refusal);
`
	dir := t.TempDir()
	for name, source := range map[string]string{"adapter.ts": TypeScriptSource(), "harness.mjs": harness} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.CommandContext(t.Context(), "node", "--max-old-space-size=256", "harness.mjs")
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated adapter budget: %v\n%s", err, output)
	}
}
