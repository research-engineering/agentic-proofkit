package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// visualRecordFixture builds the admitted record a writer would produce for
// root in the given state, recomputing every content-bound field.
func visualRecordFixture(t *testing.T, root string, resolution proofInputResolution, state string) map[string]any {
	t.Helper()
	assets := make([]any, 0, len(resolution.InputPaths))
	for _, path := range resolution.InputPaths {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		assets = append(assets, map[string]any{"path": path, "sha256": hex.EncodeToString(sum[:])})
	}
	inputResolution := map[string]any{"serverTarget": resolution.ServerTarget, "writerPath": resolution.WriterPath}
	encoded, err := stablejson.MarshalLayout(map[string]any{"assets": assets, "inputResolution": inputResolution}, stablejson.LayoutCompact)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := verifyVisualReferences(root)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[string]any{"cpu": map[string]any{"avx2": nil, "avx512f": nil, "features": "fp asimd sve sve2", "hypervisor": nil, "model": "part 0xd49", "vendor": "implementer 0x41"}}
	for key, value := range environment.Observed {
		observed[key] = value
	}
	nonClaims := make([]any, len(visualProofNonClaims))
	for index, nonClaim := range visualProofNonClaims {
		nonClaims[index] = nonClaim
	}
	record := map[string]any{
		"assets": assets, "command": nil, "divergentFields": []any{}, "engines": []any{},
		"inputDigest": digest.SHA256TextRef(strings.TrimSuffix(string(encoded), "\n")), "inputResolution": inputResolution,
		"nonClaims": nonClaims, "observedEnvironment": observed, "projects": []any{},
		"proofKind": "proofkit.browser-visual-proof",
		"referenceEnvironment": map[string]any{
			"environmentId": inventory.EnvironmentID, "referenceCount": json.Number("169"), "referencesDigest": inventory.ReferencesDigest,
		},
		"schemaVersion": json.Number("1"), "sourceRevision": "abc123", "sourceTreeState": "dirty", "state": state,
	}
	if state == "unverified" {
		observed["architecture"] = "x86_64"
		observed["packages"] = nil
		record["divergentFields"] = []any{"architecture", "packages"}
		return record
	}
	argv := make([]any, len(visualCommandArgv))
	for index, value := range visualCommandArgv {
		argv[index] = value
	}
	record["command"] = map[string]any{"argv": argv, "exitCode": json.Number("0"), "inputMode": "materialized_snapshot", "runner": "node"}
	engines, projects := []any{}, []any{}
	expected := expectedVisualProjectTests()
	for _, name := range visualEngines {
		ids := make([]any, len(expected[name]))
		for index, id := range expected[name] {
			ids[index] = id
		}
		count := json.Number(fmtInt(len(ids)))
		engines = append(engines, map[string]any{"name": name, "version": environment.BrowserVersions[name]})
		projects = append(projects, map[string]any{"browserName": name, "browserVersion": environment.BrowserVersions[name], "executedTestCount": count, "name": name, "passedTestCount": count, "testIds": ids})
	}
	record["engines"], record["projects"] = engines, projects
	return record
}

func fmtInt(value int) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func repositoryVisualResolution(t *testing.T) (string, proofInputResolution) {
	t.Helper()
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadProofInputManifest(root, visualProofKind())
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := resolveProofInputs(root, manifest, visualProofKind())
	if err != nil {
		t.Fatal(err)
	}
	return root, resolution
}

func TestVisualRecordAdmitsOnlyConsistentPassedOrUnverifiedStates(t *testing.T) {
	root, resolution := repositoryVisualResolution(t)
	for _, state := range []string{"passed", "unverified"} {
		if err := verifyVisualRecord(root, visualRecordFixture(t, root, resolution, state), resolution, "abc123", "dirty"); err != nil {
			t.Fatalf("%s visual record was refused: %v", state, err)
		}
	}
	emulated := visualRecordFixture(t, root, resolution, "unverified")
	emulated["observedEnvironment"].(map[string]any)["architecture"] = "aarch64"
	emulated["observedEnvironment"].(map[string]any)["packages"] = visualRecordFixture(t, root, resolution, "passed")["observedEnvironment"].(map[string]any)["packages"]
	emulated["observedEnvironment"].(map[string]any)["emulation"] = "translator-mapped"
	emulated["divergentFields"] = []any{"emulation"}
	if err := verifyVisualRecord(root, emulated, resolution, "abc123", "dirty"); err != nil {
		t.Fatalf("an emulated host was not admitted as unverified: %v", err)
	}
	cases := []struct {
		name   string
		state  string
		mutate func(map[string]any)
	}{
		{"passed with a divergent environment", "passed", func(record map[string]any) {
			record["observedEnvironment"].(map[string]any)["emulation"] = "translator-mapped"
		}},
		{"passed claiming a divergence", "passed", func(record map[string]any) { record["divergentFields"] = []any{"architecture"} }},
		{"unverified without a divergence", "passed", func(record map[string]any) { record["state"] = "unverified" }},
		{"unverified omitting a divergent field", "unverified", func(record map[string]any) { record["divergentFields"] = []any{"architecture"} }},
		{"unverified claiming an execution", "unverified", func(record map[string]any) {
			record["engines"] = []any{map[string]any{"name": "chromium", "version": "1"}}
		}},
		{"failed state", "passed", func(record map[string]any) { record["state"] = "failed" }},
		{"schema version", "passed", func(record map[string]any) { record["schemaVersion"] = json.Number("2") }},
		{"missing reference comparison", "passed", func(record map[string]any) {
			project := record["projects"].([]any)[1].(map[string]any)
			ids := project["testIds"].([]any)
			project["testIds"] = ids[:len(ids)-1]
			project["executedTestCount"], project["passedTestCount"] = json.Number(fmtInt(len(ids)-1)), json.Number(fmtInt(len(ids)-1))
		}},
		{"other engine version", "passed", func(record map[string]any) {
			record["projects"].([]any)[2].(map[string]any)["browserVersion"] = "0"
		}},
		{"command without the visual config", "passed", func(record map[string]any) {
			record["command"].(map[string]any)["argv"] = []any{"node_modules/@playwright/test/cli.js", "test"}
		}},
		{"failed command", "passed", func(record map[string]any) {
			record["command"].(map[string]any)["exitCode"] = json.Number("1")
		}},
		{"other environment identity", "passed", func(record map[string]any) {
			record["referenceEnvironment"].(map[string]any)["environmentId"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"other reference inventory", "unverified", func(record map[string]any) {
			record["referenceEnvironment"].(map[string]any)["referencesDigest"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"observed CPU omitted", "passed", func(record map[string]any) { delete(record["observedEnvironment"].(map[string]any), "cpu") }},
		{"weaker non-claim", "unverified", func(record map[string]any) { record["nonClaims"].([]any)[0] = "weaker" }},
		{"stale input digest", "unverified", func(record map[string]any) {
			record["inputDigest"] = "sha256:" + strings.Repeat("0", 64)
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			record := visualRecordFixture(t, root, resolution, item.state)
			item.mutate(record)
			if err := verifyVisualRecord(root, record, resolution, "abc123", "dirty"); err == nil {
				t.Fatalf("visual record mutant %q was admitted", item.name)
			}
		})
	}
}

// visualOperationFixture is a disposable repository with the committed visual
// records and references, a stub server package and a writer that publishes a
// staged candidate where the orchestrator expects it.
func visualOperationFixture(t *testing.T) string {
	t.Helper()
	root := browserOperationFixture(t)
	source, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(filepath.Join(source, "tests", "visual"), func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(root, relative), 0o755)
		}
		content, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, relative), content, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := `{"schemaVersion":1,"proofKind":"proofkit.browser-visual-proof-inputs","serverTarget":"./internal/tools/browserfixture","testRoot":"tests/visual","writerPath":"scripts/writer.mjs","paths":["go.mod"]}`
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(visualProofManifestPath)), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(map[string]any{"policies": []any{
		map[string]any{"commandId": "proofkit.browser-check", "inputSelectors": fixtureSelectors},
		map[string]any{"commandId": "proofkit.browser-visual", "inputSelectors": []any{
			"go.mod", "internal/tools/browserfixture", "internal/tools/browserproofverify",
			"scripts/browser-visual-proof-inputs.v1.json", "scripts/writer.mjs", "tests/visual",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proofkit", "witness-plan.json"), plan, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-q", "-m", "visual fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	// A deterministic dirty tree, independent of run-directory timing.
	if err := os.WriteFile(filepath.Join(root, "untracked-visual.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func stageVisualCandidate(t *testing.T, root, state string, mutate func(map[string]any)) {
	t.Helper()
	manifest, err := loadProofInputManifest(root, visualProofKind())
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := resolveProofInputs(root, manifest, visualProofKind())
	if err != nil {
		t.Fatal(err)
	}
	revision, treeState, err := currentSourceIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	record := visualRecordFixture(t, root, resolution, state)
	record["sourceRevision"], record["sourceTreeState"] = revision, treeState
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

func observeVisualRun(t *testing.T, root string, requireReference bool) (bool, error) {
	t.Helper()
	t.Setenv("PROOFKIT_OPERATION_MARKERS", t.TempDir())
	recordPath := filepath.Join(root, filepath.FromSlash(visualProofKind().RecordPath))
	_ = os.Remove(recordPath)
	err := runBrowserProof(root, visualProofKind(), requireReference)
	_, statErr := os.Stat(recordPath)
	return statErr == nil, err
}

// The visual orchestrator writes a record only for an admitted candidate;
// --require-reference-environment turns an unverified record into a failure.
func TestVisualProofRunWritesNoRecordOnFailureOrRequiredUnverified(t *testing.T) {
	root := visualOperationFixture(t)
	stageVisualCandidate(t, root, "unverified", nil)
	if written, err := observeVisualRun(t, root, false); err != nil || !written {
		t.Fatalf("local unverified run: written=%v err=%v, want an unverified record and exit 0", written, err)
	}
	if written, err := observeVisualRun(t, root, true); err == nil || written || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("required reference environment: written=%v err=%v, want failure without a record", written, err)
	}
	stageVisualCandidate(t, root, "passed", nil)
	if written, err := observeVisualRun(t, root, true); err != nil || !written {
		t.Fatalf("passed run: written=%v err=%v", written, err)
	}
	stageVisualCandidate(t, root, "passed", func(record map[string]any) {
		record["projects"].([]any)[0].(map[string]any)["testIds"] = []any{"tests/visual/references.spec.mjs::only"}
	})
	if written, err := observeVisualRun(t, root, false); err == nil || written {
		t.Fatalf("refused candidate: written=%v err=%v, want failure without a record", written, err)
	}
	stageVisualCandidate(t, root, "unverified", nil)
	editJSON(t, root, visualReferencesPath, func(record map[string]any) {
		entries := record["references"].([]any)
		record["references"] = entries[1:]
	})
	if written, err := observeVisualRun(t, root, false); err == nil || written {
		t.Fatalf("missing reference ID: written=%v err=%v, want failure without a record", written, err)
	}
}
