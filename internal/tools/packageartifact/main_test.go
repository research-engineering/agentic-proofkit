package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
)

type runnerFunc func(root string, argv []string) (int, error)

func (run runnerFunc) Run(root string, argv []string) (int, error) {
	return run(root, argv)
}

func TestRunWithDependenciesRecordsCanonicalAndExecutionArgv(t *testing.T) {
	root := packageArtifactFixture(t)
	staleRecord := packageartifactrecord.Record{Status: "passed"}
	if err := packageartifactrecord.Write(root, staleRecord); err != nil {
		t.Fatal(err)
	}
	var actualArgv []string
	runner := runnerFunc(func(root string, argv []string) (int, error) {
		actualArgv = append([]string(nil), argv...)
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(packageartifactrecord.RecordPath))); !os.IsNotExist(err) {
			t.Fatalf("stale record exists when runner starts: %v", err)
		}
		writeArtifactFixture(t, root, "artifact-v2")
		return 0, nil
	})

	if err := runWithDependencies(root, runner, stableDependencies()); err != nil {
		t.Fatalf("runWithDependencies() error = %v", err)
	}
	if !reflect.DeepEqual(actualArgv, packageartifactrecord.CanonicalExecutionArgv()) {
		t.Fatalf("runner argv = %v, want %v", actualArgv, packageartifactrecord.CanonicalExecutionArgv())
	}
	record, err := packageartifactrecord.Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.Argv, packageartifactrecord.CanonicalCommandArgv()) {
		t.Fatalf("record argv = %v, want canonical %v", record.Argv, packageartifactrecord.CanonicalCommandArgv())
	}
	if !reflect.DeepEqual(record.ExecutionArgv, packageartifactrecord.CanonicalExecutionArgv()) {
		t.Fatalf("record executionArgv = %v, want %v", record.ExecutionArgv, packageartifactrecord.CanonicalExecutionArgv())
	}
	if record.Status != "passed" || record.ExitCode != 0 {
		t.Fatalf("record result = %s/%d, want passed/0", record.Status, record.ExitCode)
	}
	if err := packageartifactrecord.ValidateCurrent(root, record); err != nil {
		t.Fatalf("ValidateCurrent() error = %v", err)
	}
}

func TestRunWithDependenciesRejectsTimestampOnlyMutationOfPreexistingArtifact(t *testing.T) {
	root := packageArtifactFixture(t)
	writeArtifactFixture(t, root, "artifact-v1")
	artifactPath := filepath.Join(root, "artifacts", "package", "package.tgz")

	err := runWithDependencies(root, runnerFunc(func(string, []string) (int, error) {
		if touchErr := os.Chtimes(artifactPath, time.Now(), time.Now()); !os.IsNotExist(touchErr) {
			t.Fatalf("preexisting artifact remained available for timestamp-only mutation: %v", touchErr)
		}
		return 0, nil
	}), stableDependencies())
	if err == nil || !strings.Contains(err.Error(), "produced no artifacts") {
		t.Fatalf("runWithDependencies() error = %v", err)
	}
	record, readErr := packageartifactrecord.Read(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if record.Status != "failed" || record.ExitCode != 0 {
		t.Fatalf("record result = %s/%d, want failed/0", record.Status, record.ExitCode)
	}
	if validateErr := packageartifactrecord.ValidateCurrent(root, record); validateErr == nil {
		t.Fatal("ValidateCurrent() accepted evidence from a timestamp-only runner")
	}
}

func TestRunWithDependenciesInvalidatesPriorRecordButRetainsCandidateOutputsOnProviderEvidence(t *testing.T) {
	root := packageArtifactFixture(t)
	writeArtifactFixture(t, root, "candidate")
	writeFileFixture(t, root, "artifacts/registry/npm-registry.json", "provider")
	if err := packageartifactrecord.Write(root, packageartifactrecord.Record{Status: "passed"}); err != nil {
		t.Fatal(err)
	}
	runnerCalled := false

	err := runWithDependencies(root, runnerFunc(func(string, []string) (int, error) {
		runnerCalled = true
		return 0, nil
	}), stableDependencies())
	if err == nil || !strings.Contains(err.Error(), "rejects ambient provider evidence") {
		t.Fatalf("runWithDependencies() error = %v", err)
	}
	if runnerCalled {
		t.Fatal("runner executed after ambient provider evidence rejection")
	}
	if _, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(packageartifactrecord.RecordPath))); !os.IsNotExist(statErr) {
		t.Fatalf("prior execution record survived rejected package run: %v", statErr)
	}
	if content, readErr := os.ReadFile(filepath.Join(root, "artifacts/package/package.tgz")); readErr != nil || string(content) != "candidate" {
		t.Fatalf("candidate output changed before provider-evidence rejection: content=%q err=%v", content, readErr)
	}
}

func TestRunWithDependenciesRejectsExecutionRecordSymlinkBeforeRunner(t *testing.T) {
	root := packageArtifactFixture(t)
	external := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "artifacts", "proofkit")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	externalRecord := filepath.Join(external, filepath.Base(packageartifactrecord.RecordPath))
	if err := os.WriteFile(externalRecord, []byte("external-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	runnerCalled := false

	err := runWithDependencies(root, runnerFunc(func(string, []string) (int, error) {
		runnerCalled = true
		return 0, nil
	}), stableDependencies())
	if err == nil {
		t.Fatal("runWithDependencies() accepted an execution-record symlink escape")
	}
	if runnerCalled {
		t.Fatal("runner executed after execution-record root rejection")
	}
	if content, readErr := os.ReadFile(externalRecord); readErr != nil || string(content) != "external-sentinel" {
		t.Fatalf("external record changed: content=%q err=%v", content, readErr)
	}
}

func TestRunWithDependenciesAcceptsCleanRegenerationWithIdenticalBytes(t *testing.T) {
	root := packageArtifactFixture(t)
	writeArtifactFixture(t, root, "artifact-v1")
	artifactPath := filepath.Join(root, "artifacts", "package", "package.tgz")

	err := runWithDependencies(root, runnerFunc(func(root string, _ []string) (int, error) {
		if _, statErr := os.Stat(artifactPath); !os.IsNotExist(statErr) {
			t.Fatalf("preexisting artifact was not removed before regeneration: %v", statErr)
		}
		writeArtifactFixture(t, root, "artifact-v1")
		return 0, nil
	}), stableDependencies())
	if err != nil {
		t.Fatalf("runWithDependencies() error = %v", err)
	}
	record, readErr := packageartifactrecord.Read(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if record.Status != "passed" || record.ExitCode != 0 {
		t.Fatalf("record result = %s/%d, want passed/0", record.Status, record.ExitCode)
	}
}

func TestRunWithDependenciesInvalidatesPassedRecordOnFailedRun(t *testing.T) {
	root := packageArtifactFixture(t)
	writeArtifactFixture(t, root, "artifact-v1")
	if err := packageartifactrecord.Write(root, packageartifactrecord.Record{Status: "passed"}); err != nil {
		t.Fatal(err)
	}
	runner := runnerFunc(func(root string, _ []string) (int, error) {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(packageartifactrecord.RecordPath))); !os.IsNotExist(err) {
			t.Fatalf("stale passed record exists when failed runner starts: %v", err)
		}
		return 23, errors.New("runner failed")
	})

	err := runWithDependencies(root, runner, stableDependencies())
	if err == nil || !strings.Contains(err.Error(), "runner failed") {
		t.Fatalf("runWithDependencies() error = %v", err)
	}
	record, readErr := packageartifactrecord.Read(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if record.Status != "failed" || record.ExitCode != 23 {
		t.Fatalf("record result = %s/%d, want failed/23", record.Status, record.ExitCode)
	}
}

func TestRunWithDependenciesRejectsSourceAndExecutionContextMutation(t *testing.T) {
	root := packageArtifactFixture(t)
	toolchainCalls := 0
	environmentCalls := 0
	dependencies := stableDependencies()
	dependencies.toolchainDigest = func() (string, error) {
		toolchainCalls++
		return strings.Repeat(string(rune('a'+toolchainCalls-1)), 64), nil
	}
	dependencies.environ = func() []string {
		environmentCalls++
		return []string{"GOFLAGS=-mod=" + []string{"readonly", "vendor"}[environmentCalls-1]}
	}
	runner := runnerFunc(func(root string, _ []string) (int, error) {
		writeFileFixture(t, root, "source.txt", "source-v2")
		writeArtifactFixture(t, root, "artifact-v2")
		return 0, nil
	})

	err := runWithDependencies(root, runner, dependencies)
	if err == nil {
		t.Fatal("runWithDependencies() accepted mutated source and execution context")
	}
	for _, fragment := range []string{"changed its source snapshot", "changed its environment snapshot", "changed its toolchain snapshot"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("runWithDependencies() error %q does not contain %q", err, fragment)
		}
	}
	record, readErr := packageartifactrecord.Read(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if record.Status != "failed" {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
}

func stableDependencies() orchestrationDependencies {
	times := []time.Time{
		time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 11, 10, 0, 1, 0, time.UTC),
	}
	index := 0
	return orchestrationDependencies{
		environ: func() []string { return []string{"PATH=/test/bin", "PROOFKIT_TEST=1"} },
		now: func() time.Time {
			value := times[index]
			index++
			return value
		},
		toolchainDigest: func() (string, error) { return strings.Repeat("c", 64), nil },
	}
}

func packageArtifactFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runFixtureGit(t, root, "init")
	runFixtureGit(t, root, "config", "user.email", "proofkit@example.invalid")
	runFixtureGit(t, root, "config", "user.name", "Proofkit Test")
	writeFileFixture(t, root, ".gitignore", "artifacts/\n")
	writeFileFixture(t, root, "source.txt", "source-v1")
	runFixtureGit(t, root, "add", ".gitignore", "source.txt")
	runFixtureGit(t, root, "commit", "-m", "fixture")
	return root
}

func writeArtifactFixture(t *testing.T, root string, content string) {
	t.Helper()
	writeFileFixture(t, root, "artifacts/package/package.tgz", content)
}

func writeFileFixture(t *testing.T, root string, relativePath string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runFixtureGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
