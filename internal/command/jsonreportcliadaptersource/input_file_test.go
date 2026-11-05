package jsonreportcliadaptersource

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testGeneratedAdapterFIFO(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX filesystem FIFO")
	}
	dir := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "mkfifo", filepath.Join(dir, "input.fifo")).CombinedOutput(); err != nil {
		t.Fatalf("create real FIFO: %v\n%s", err, output)
	}
	for name, contents := range map[string]string{
		"adapter.ts": TypeScriptSource(),
		"input.json": "{}",
		"empty.txt":  "",
		"probe.mjs": `import assert from "node:assert/strict";
import {symlinkSync} from "node:fs";
import {readProofkitJsonReportInput, readProofkitTextReportInput} from "./adapter.ts";

symlinkSync("input.json", "linked.json");
assert.deepEqual(readProofkitJsonReportInput("linked.json", {maxInputBytes: 2}), {});
assert.equal(readProofkitTextReportInput("empty.txt", {maxInputBytes: 0}), "");
assert.throws(() => readProofkitTextReportInput("input.json", {maxInputBytes: 1}), /exceeds maxInputBytes/);
console.log("FIFO probe reached after regular-file controls");
assert.throws(() => readProofkitTextReportInput("input.fifo"), /input path must be a regular file/);
assert.throws(() => readProofkitJsonReportInput("input.fifo"), /input path must be a regular file/);
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "--experimental-strip-types", "probe.mjs")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated adapter file admission failed: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}
