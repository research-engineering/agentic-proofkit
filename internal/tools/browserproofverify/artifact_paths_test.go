package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareBrowserProofRunCreatesAConfinedDisposableDirectory(t *testing.T) {
	root := t.TempDir()
	paths, err := prepareBrowserProofRun(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(paths.RunDirectory, "artifacts/browser-run-") || paths.CandidatePath != paths.RunDirectory+"/"+browserProofCandidateName {
		t.Fatalf("unexpected confined run paths: %#v", paths)
	}
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(paths.RunDirectory)))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("run directory is not a confined directory: info=%v err=%v", info, err)
	}
	if err := cleanupBrowserProofRun(root, paths.RunDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(paths.RunDirectory))); !os.IsNotExist(err) {
		t.Fatalf("run directory survived cleanup: %v", err)
	}
}

func TestFinalizeBrowserProofRunCleansSuccessAndRetainsFailureDiagnostics(t *testing.T) {
	root := t.TempDir()
	successPaths, err := prepareBrowserProofRun(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeBrowserProofRun(root, successPaths.RunDirectory, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(successPaths.RunDirectory))); !os.IsNotExist(err) {
		t.Fatalf("successful run directory survived cleanup: %v", err)
	}

	failurePaths, err := prepareBrowserProofRun(root)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticPath := filepath.Join(root, filepath.FromSlash(failurePaths.RunDirectory), "playwright-report.json")
	if err := os.WriteFile(diagnosticPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runErr := errors.New("browser proof failed")
	if err := finalizeBrowserProofRun(root, failurePaths.RunDirectory, runErr); !errors.Is(err, runErr) {
		t.Fatalf("finalizeBrowserProofRun() error=%v, want original failure", err)
	}
	if content, err := os.ReadFile(diagnosticPath); err != nil || string(content) != "{}\n" {
		t.Fatalf("failed run diagnostic was not retained: content=%q err=%v", content, err)
	}
}

func TestPrepareBrowserProofRunRejectsArtifactRootSymlink(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	sentinel := filepath.Join(external, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, browserArtifactsDirectory)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := prepareBrowserProofRun(root); err == nil {
		t.Fatal("prepareBrowserProofRun accepted a symlinked artifact root")
	}
	content, err := os.ReadFile(sentinel)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("external sentinel changed: content=%q err=%v", content, err)
	}
	entries, err := os.ReadDir(external)
	if err != nil || len(entries) != 1 {
		t.Fatalf("external directory was mutated: entries=%v err=%v", entries, err)
	}
}

func TestWriteRootedJSONRejectsSymlinkDestination(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external.json")
	if err := os.WriteFile(external, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, browserProofDirectory), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, filepath.FromSlash(proofPath))); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writeRootedJSON(root, proofPath, map[string]any{"state": "passed"}); err == nil {
		t.Fatal("writeRootedJSON accepted a symlink destination")
	}
	content, err := os.ReadFile(external)
	if err != nil || string(content) != "sentinel" {
		t.Fatalf("external destination changed: content=%q err=%v", content, err)
	}
}
