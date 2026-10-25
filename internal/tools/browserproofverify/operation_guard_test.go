package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The writer records that it ran, then publishes the staged candidate exactly
// where runBrowserProof expects the browser proof candidate.
const fixtureWriter = `import {appendFileSync, copyFileSync} from "node:fs";
appendFileSync(process.env.PROOFKIT_OPERATION_MARKERS + "/writer.log", "executed\n");
copyFileSync(process.env.PROOFKIT_OPERATION_CANDIDATE, process.env.PROOFKIT_BROWSER_PROOF_CANDIDATE_PATH);
`

// Selectors restated independently: role-owned paths, manifest paths and the
// two Go package directories of the fixture module.
var fixtureSelectors = []any{
	"go.mod", "internal/tools/browserfixture", "internal/tools/browserproofverify",
	"scripts/browser-runtime-proof-inputs.v1.json", "scripts/writer.mjs", "tests/browser",
}

func browserOperationFixture(t *testing.T) string {
	t.Helper()
	version := strings.TrimPrefix(runtime.Version(), "go")
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`).MatchString(version) {
		t.Skipf("fixture module needs a release toolchain version, have %s", runtime.Version())
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("the fixture writer needs node")
	}
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.test/browserproof\n\ngo " + version + "\n",
		"internal/tools/browserproofverify/main.go": "package main\n\nfunc main() {}\n",
		"internal/tools/browserfixture/main.go":     "package main\n\nfunc main() {}\n",
		"scripts/browser-runtime-proof-inputs.v1.json": `{"schemaVersion":1,"proofKind":"proofkit.browser-runtime-proof-inputs",` +
			`"serverTarget":"./internal/tools/browserfixture","testRoot":"tests/browser","writerPath":"scripts/writer.mjs","paths":["go.mod"]}`,
		"scripts/writer.mjs":               fixtureWriter,
		"tests/browser/workspace.spec.mjs": "export {};\n",
	}
	for path, content := range files {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeWitnessPlan(t, root, fixtureSelectors)
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-q", "-m", "fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	// A deterministic dirty tree, independent of run-directory timing.
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeWitnessPlan(t *testing.T, root string, selectors []any) {
	t.Helper()
	plan, err := json.Marshal(map[string]any{"policies": []any{map[string]any{"commandId": "proofkit.browser-check", "inputSelectors": selectors}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proofkit"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proofkit", "witness-plan.json"), plan, 0o644); err != nil {
		t.Fatal(err)
	}
}

// stageCandidate writes the record the writer will publish; mutate may break it.
func stageCandidate(t *testing.T, root string, mutate func(map[string]any)) {
	t.Helper()
	manifest, err := loadProofInputManifest(root, runtimeProofKind())
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := resolveProofInputs(root, manifest, runtimeProofKind())
	if err != nil {
		t.Fatal(err)
	}
	revision, state, err := currentSourceIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	record := fixtureRecord(t, root, resolution)
	record["sourceRevision"], record["sourceTreeState"] = revision, state
	if mutate != nil {
		mutate(record)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(candidate, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROOFKIT_OPERATION_CANDIDATE", candidate)
}

func observeBrowserRun(t *testing.T, root string) (writerRan bool, proofWritten bool, artifactsCreated bool, err error) {
	t.Helper()
	markers := t.TempDir()
	t.Setenv("PROOFKIT_OPERATION_MARKERS", markers)
	err = runBrowserProof(root, runtimeProofKind(), false)
	_, writerErr := os.Stat(filepath.Join(markers, "writer.log"))
	_, proofErr := os.Stat(filepath.Join(root, filepath.FromSlash(runtimeProofKind().RecordPath)))
	_, artifactsErr := os.Lstat(filepath.Join(root, browserArtifactsDirectory))
	return writerErr == nil, proofErr == nil, artifactsErr == nil, err
}

// Whole-operation guard order of runBrowserProof: input admission precedes the
// run directory and writer execution, and candidate admission precedes the
// proof write. Each guard is injected to fail and then restored.
func TestRunBrowserProofGuardsPrecedeExecutionAndWrite(t *testing.T) {
	t.Run("input admission precedes run directory and writer", func(t *testing.T) {
		root := browserOperationFixture(t)
		stageCandidate(t, root, nil)
		writeWitnessPlan(t, root, fixtureSelectors[1:])
		writerRan, proofWritten, artifactsCreated, err := observeBrowserRun(t, root)
		if err == nil || !strings.Contains(err.Error(), "inputSelectors drifted") {
			t.Fatalf("drifted witness policy error=%v", err)
		}
		if writerRan || proofWritten || artifactsCreated {
			t.Fatalf("refused inputs had effects: writer=%v proof=%v artifacts=%v", writerRan, proofWritten, artifactsCreated)
		}
		writeWitnessPlan(t, root, fixtureSelectors)
		if writerRan, proofWritten, _, err := observeBrowserRun(t, root); err != nil || !writerRan || !proofWritten {
			t.Fatalf("restored inputs did not run and publish: writer=%v proof=%v err=%v", writerRan, proofWritten, err)
		}
	})

	t.Run("candidate admission precedes proof write", func(t *testing.T) {
		root := browserOperationFixture(t)
		stageCandidate(t, root, func(record map[string]any) {
			record["command"].(map[string]any)["exitCode"] = json.Number("1")
		})
		writerRan, proofWritten, _, err := observeBrowserRun(t, root)
		if err == nil || !strings.Contains(err.Error(), "admit browser proof candidate") {
			t.Fatalf("failed candidate error=%v", err)
		}
		if !writerRan || proofWritten {
			t.Fatalf("a refused candidate was published: writer=%v proof=%v", writerRan, proofWritten)
		}
		stageCandidate(t, root, nil)
		if writerRan, proofWritten, _, err := observeBrowserRun(t, root); err != nil || !writerRan || !proofWritten {
			t.Fatalf("restored candidate was not published: writer=%v proof=%v err=%v", writerRan, proofWritten, err)
		}
	})
}
