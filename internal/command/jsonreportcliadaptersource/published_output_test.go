package jsonreportcliadaptersource

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedAdapterUsesNativePublishedOutput(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required to prove generated adapter output: %v", err)
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "agentic-proofkit")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/agentic-proofkit")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native CLI: %v\n%s", err, output)
	}
	fixture := filepath.Join(repo, "internal/app/testdata/spec-tree-native-observations.json")
	for name, content := range map[string]string{
		"adapter.ts": TypeScriptSource(),
		"harness.mjs": `import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { runProofkitJsonCommand, runProofkitTextCommand } from "./adapter.ts";

const [binaryPath, fixturePath] = process.argv.slice(2);
const rows = JSON.parse(readFileSync(fixturePath, "utf8"));
const input = rows.find(row => row.case === "valid" && row.kind === "view").input;
const cwd = resolve("repo");
mkdirSync(cwd);
const command = "requirement-spec-tree-view";
const options = {binaryPath, cwd};

const report = runProofkitJsonCommand(command, input, ["--output", "new/report.json"], options);
assert.equal(report.status, 0);
assert.equal(report.stdout, "");
assert.deepEqual(report.value, JSON.parse(readFileSync(join(cwd, "new/report.json"), "utf8")));

const text = runProofkitTextCommand(command, input, ["--format", "markdown", "--output", "new/report.md", "--mirror-output"], options);
assert.equal(text.status, 0);
assert.equal(text.stdout, text.text);
assert.equal(text.text, readFileSync(join(cwd, "new/report.md"), "utf8"));

const failed = rows.find(row => row.case === "failed" && row.kind === "view").input;
const failedArgs = ["--output", "new/failed.json"];
for (const args of [failedArgs, [...failedArgs, "--mirror-output"]]) {
  assert.throws(() => runProofkitJsonCommand(command, failed, args, options), /cannot build requirement spec tree view from failed requirement spec tree/);
  assert.equal(existsSync(join(cwd, "new/failed.json")), false);
}

mkdirSync(join(cwd, ".git"));
writeFileSync(join(cwd, ".git/config"), "metadata sentinel");
assert.throws(() => runProofkitJsonCommand(command, {}, ["--output", ".git/config"], options), /must not enter repository metadata/);
assert.equal(readFileSync(join(cwd, ".git/config"), "utf8"), "metadata sentinel");

const outside = resolve("outside");
mkdirSync(outside);
writeFileSync(join(outside, "sentinel.json"), "outside sentinel");
symlinkSync(outside, join(cwd, "outside-parent"), "dir");
symlinkSync(join(outside, "sentinel.json"), join(cwd, "linked.json"));
for (const path of ["outside-parent/sentinel.json", "linked.json"]) {
  assert.throws(() => runProofkitJsonCommand(command, input, ["--output", path], options), /symlink/);
}
assert.equal(readFileSync(join(outside, "sentinel.json"), "utf8"), "outside sentinel");
`,
	} {
		if err := os.WriteFile(filepath.Join(temp, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := exec.CommandContext(t.Context(), node, "--experimental-strip-types", "harness.mjs", binary, fixture)
	run.Dir = temp
	if output, err := run.CombinedOutput(); err != nil {
		t.Fatalf("native published output witness: %v\n%s", err, output)
	}
}
