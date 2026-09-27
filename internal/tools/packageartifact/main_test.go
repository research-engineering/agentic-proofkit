package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/gitfixture"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
)

type runnerFunc func(root string, argv []string) (int, error)

func (run runnerFunc) Run(root string, argv []string) (int, error) {
	return run(root, argv)
}

func TestRunWithDependenciesRecordsCanonicalAndExecutionArgv(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "commit.gpgSign")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")
	t.Setenv("GIT_CONFIG_KEY_1", "gpg.program")
	t.Setenv("GIT_CONFIG_VALUE_1", "proofkit-test-unavailable-signing-program")
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
	wantExecutionArgv := []string{"npm", "run", "package:artifact:steps"}
	wantCommandArgv := []string{"npm", "run", "package:artifact"}
	if !reflect.DeepEqual(actualArgv, wantExecutionArgv) {
		t.Fatalf("runner argv = %v, want %v", actualArgv, wantExecutionArgv)
	}
	record, err := packageartifactrecord.Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.Argv, wantCommandArgv) {
		t.Fatalf("record argv = %v, want canonical %v", record.Argv, wantCommandArgv)
	}
	if !reflect.DeepEqual(record.ExecutionArgv, wantExecutionArgv) {
		t.Fatalf("record executionArgv = %v, want %v", record.ExecutionArgv, wantExecutionArgv)
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
	for _, item := range []struct {
		name                           string
		source, environment, toolchain bool
	}{
		{name: "source only", source: true},
		{name: "environment only", environment: true},
		{name: "toolchain only", toolchain: true},
		{name: "combined", source: true, environment: true, toolchain: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			root := packageArtifactFixture(t)
			toolchainCalls := 0
			environmentCalls := 0
			dependencies := stableDependencies()
			dependencies.toolchainDigest = func() (string, error) {
				toolchainCalls++
				if item.toolchain && toolchainCalls > 1 {
					return strings.Repeat("b", 64), nil
				}
				return strings.Repeat("a", 64), nil
			}
			dependencies.environ = func() []string {
				environmentCalls++
				if item.environment && environmentCalls > 1 {
					return []string{"GOFLAGS=-mod=vendor"}
				}
				return []string{"GOFLAGS=-mod=readonly"}
			}
			runner := runnerFunc(func(root string, _ []string) (int, error) {
				if item.source {
					writeFileFixture(t, root, "source.txt", "source-v2")
				}
				writeArtifactFixture(t, root, "artifact-v2")
				return 0, nil
			})

			err := runWithDependencies(root, runner, dependencies)
			if err == nil {
				t.Fatal("runWithDependencies() accepted mutated source and execution context")
			}
			for _, diagnostic := range []struct {
				fragment string
				want     bool
			}{
				{"changed its source snapshot", item.source},
				{"changed its environment snapshot", item.environment},
				{"changed its toolchain snapshot", item.toolchain},
			} {
				if strings.Contains(err.Error(), diagnostic.fragment) != diagnostic.want {
					t.Errorf("runWithDependencies() error %q, diagnostic %q presence must be %v", err, diagnostic.fragment, diagnostic.want)
				}
			}
			record, readErr := packageartifactrecord.Read(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if record.Status != "failed" {
				t.Fatalf("record status = %q, want failed", record.Status)
			}
		})
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
	command := gitfixture.Command(root, args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
