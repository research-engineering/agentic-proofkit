package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestInputManifestClosesGoDependenciesAndWitnessPolicy(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadProofInputManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TestRoot != "tests/browser" {
		t.Fatalf("manifest testRoot = %q, want tests/browser", manifest.TestRoot)
	}
	for _, required := range []string{"go.mod", "go.sum", "proofkit/witness-plan.json"} {
		if !slices.Contains(manifest.Paths, required) {
			t.Fatalf("manifest omits required browser proof input selector %q", required)
		}
	}
	resolution, err := resolveProofInputs(root, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(resolution.Selectors, "internal/command/requirementcontext") {
		t.Fatal("resolved witness selectors omit a transitive Go dependency")
	}
	if !slices.Contains(resolution.InputPaths, "internal/command/requirementcontext/slice.go") {
		t.Fatal("resolved proof assets omit a transitive Go source file")
	}
	weakened := slices.DeleteFunc(append([]string{}, resolution.Selectors...), func(path string) bool {
		return path == "internal/command/requirementcontext"
	})
	if err := validateBrowserWitnessPolicy(root, weakened); err == nil {
		t.Fatal("witness policy accepted a resolver projection with a missing Go dependency")
	}
}

func TestInputManifestRejectsNonCanonicalAuthority(t *testing.T) {
	validPrefix := `{"schemaVersion":1,"proofKind":"proofkit.browser-runtime-proof-inputs","serverTarget":"./internal/tools/browsertestserver","testRoot":"tests/browser","writerPath":"scripts/write-browser-proof.mjs",`
	tests := []struct {
		name string
		raw  string
	}{
		{name: "duplicate keys", raw: validPrefix + `"paths":["go.mod"],"paths":["go.sum"]}`},
		{name: "scheme path", raw: validPrefix + `"paths":["file:outside"]}`},
		{name: "role overlap", raw: validPrefix + `"paths":["scripts"]}`},
		{name: "test root overlap", raw: validPrefix + `"paths":["tests"]}`},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(proofInputManifestPath)), []byte(item.raw), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadProofInputManifest(root); err == nil {
				t.Fatalf("loadProofInputManifest accepted %s", item.name)
			}
		})
	}
}

func TestBrowserTestScriptUsesSingleGoOrchestrator(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	rawPackage, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	decodedPackage, err := admission.DecodeJSON(bytes.NewReader(rawPackage), int64(len(rawPackage)))
	if err != nil {
		t.Fatal(err)
	}
	script := decodedPackage.(map[string]any)["scripts"].(map[string]any)["browser:test"]
	if script != "go run ./internal/tools/browserproofverify --run" {
		t.Fatalf("browser:test must delegate execution to the single Go orchestrator, got %q", script)
	}
}

func TestVerifyRecordBindsExecutionAndSourceInputs(t *testing.T) {
	root := t.TempDir()
	paths := []string{"a.txt", "nested/b.txt"}
	for index, path := range paths {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte{byte('a' + index)}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resolution := fixtureResolution(paths)
	record := fixtureRecord(t, root, resolution)
	if err := verifyRecord(root, record, resolution, "abc123", "dirty"); err != nil {
		t.Fatalf("verifyRecord() error = %v", err)
	}
	record["command"].(map[string]any)["exitCode"] = json.Number("1")
	if err := verifyRecord(root, record, resolution, "abc123", "dirty"); err == nil {
		t.Fatal("verifyRecord accepted failed browser command")
	}
	record = fixtureRecord(t, root, resolution)
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyRecord(root, record, resolution, "abc123", "dirty"); err == nil {
		t.Fatal("verifyRecord accepted stale source input digest")
	}
}

func TestVerifyRecordRejectsAuthorityFieldMutations(t *testing.T) {
	root := t.TempDir()
	paths := []string{"a.txt", "b.txt"}
	for _, path := range paths {
		if err := os.WriteFile(filepath.Join(root, path), []byte(path), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resolution := fixtureResolution(paths)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "proof kind", mutate: func(record map[string]any) { record["proofKind"] = "proofkit.other" }},
		{name: "schema version", mutate: func(record map[string]any) { record["schemaVersion"] = json.Number("3") }},
		{name: "state", mutate: func(record map[string]any) { record["state"] = "failed" }},
		{name: "revision", mutate: func(record map[string]any) { record["sourceRevision"] = "other" }},
		{name: "tree state", mutate: func(record map[string]any) { record["sourceTreeState"] = "clean" }},
		{name: "command argv", mutate: func(record map[string]any) { record["command"].(map[string]any)["argv"] = []any{"playwright", "test"} }},
		{name: "command runner", mutate: func(record map[string]any) { record["command"].(map[string]any)["runner"] = "bun" }},
		{name: "command input mode", mutate: func(record map[string]any) { record["command"].(map[string]any)["inputMode"] = "mutable_worktree" }},
		{name: "command exit code", mutate: func(record map[string]any) { record["command"].(map[string]any)["exitCode"] = json.Number("1") }},
		{name: "input digest", mutate: func(record map[string]any) {
			record["inputDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{name: "server target", mutate: func(record map[string]any) {
			record["inputResolution"].(map[string]any)["serverTarget"] = "./internal/tools/other"
		}},
		{name: "writer path", mutate: func(record map[string]any) {
			record["inputResolution"].(map[string]any)["writerPath"] = "scripts/other.mjs"
		}},
		{name: "asset order", mutate: func(record map[string]any) {
			assets := record["assets"].([]any)
			assets[0], assets[1] = assets[1], assets[0]
		}},
		{name: "extra asset", mutate: func(record map[string]any) {
			record["assets"] = append(record["assets"].([]any), map[string]any{"path": "extra.txt", "sha256": "0000000000000000000000000000000000000000000000000000000000000000"})
		}},
		{name: "engine identity", mutate: func(record map[string]any) { record["engines"].([]any)[0].(map[string]any)["name"] = "chrome" }},
		{name: "engine version", mutate: func(record map[string]any) { record["engines"].([]any)[0].(map[string]any)["version"] = "" }},
		{name: "engine order", mutate: func(record map[string]any) {
			engines := record["engines"].([]any)
			engines[0], engines[1] = engines[1], engines[0]
		}},
		{name: "project identity", mutate: func(record map[string]any) { record["projects"].([]any)[0].(map[string]any)["name"] = "chrome" }},
		{name: "project browser version", mutate: func(record map[string]any) { record["projects"].([]any)[0].(map[string]any)["browserVersion"] = "2" }},
		{name: "project count", mutate: func(record map[string]any) {
			record["projects"].([]any)[0].(map[string]any)["passedTestCount"] = json.Number("2")
		}},
		{name: "project test mismatch", mutate: func(record map[string]any) {
			record["projects"].([]any)[1].(map[string]any)["testIds"] = []any{"tests/browser/other.spec.mjs::other"}
		}},
		{name: "project test order", mutate: func(record map[string]any) {
			record["projects"].([]any)[0].(map[string]any)["testIds"] = []any{"tests/browser/z.spec.mjs::z", "tests/browser/a.spec.mjs::a"}
			record["projects"].([]any)[0].(map[string]any)["executedTestCount"] = json.Number("2")
			record["projects"].([]any)[0].(map[string]any)["passedTestCount"] = json.Number("2")
		}},
		{name: "non-claim", mutate: func(record map[string]any) { record["nonClaims"].([]any)[0] = "weaker" }},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			record := fixtureRecord(t, root, resolution)
			item.mutate(record)
			if err := verifyRecord(root, record, resolution, "abc123", "dirty"); err == nil {
				t.Fatalf("verifyRecord accepted mutated %s", item.name)
			}
		})
	}
}

func fixtureResolution(paths []string) proofInputResolution {
	return proofInputResolution{InputPaths: paths, ServerTarget: "./internal/tools/browserfixture", WriterPath: "scripts/browser-fixture.mjs"}
}

func fixtureRecord(t *testing.T, root string, resolution proofInputResolution) map[string]any {
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
	encoded, err := json.Marshal(map[string]any{"assets": assets, "inputResolution": inputResolution})
	if err != nil {
		t.Fatal(err)
	}
	nonClaims := make([]any, len(proofNonClaims))
	for index, nonClaim := range proofNonClaims {
		nonClaims[index] = nonClaim
	}
	return map[string]any{
		"assets": assets, "command": map[string]any{"argv": []any{"node_modules/@playwright/test/cli.js", "test"}, "exitCode": json.Number("0"), "inputMode": "materialized_snapshot", "runner": "node"},
		"engines":     []any{map[string]any{"name": "chromium", "version": "1"}, map[string]any{"name": "firefox", "version": "1"}, map[string]any{"name": "webkit", "version": "1"}},
		"inputDigest": digest.SHA256TextRef(string(encoded)), "inputResolution": inputResolution, "nonClaims": nonClaims,
		"projects": []any{
			map[string]any{"browserName": "chromium", "browserVersion": "1", "executedTestCount": json.Number("1"), "name": "chromium", "passedTestCount": json.Number("1"), "testIds": []any{"tests/browser/workspace.spec.mjs::runs"}},
			map[string]any{"browserName": "firefox", "browserVersion": "1", "executedTestCount": json.Number("1"), "name": "firefox", "passedTestCount": json.Number("1"), "testIds": []any{"tests/browser/workspace.spec.mjs::runs"}},
			map[string]any{"browserName": "webkit", "browserVersion": "1", "executedTestCount": json.Number("1"), "name": "webkit", "passedTestCount": json.Number("1"), "testIds": []any{"tests/browser/workspace.spec.mjs::runs"}},
		},
		"proofKind": "proofkit.browser-runtime-proof", "schemaVersion": json.Number("2"), "sourceRevision": "abc123", "sourceTreeState": "dirty", "state": "passed",
	}
}
