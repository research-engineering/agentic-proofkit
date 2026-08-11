package commandoracle

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestExecuteBindsMaterializedSourceCandidatesAndRuntimeEvents(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	previousRunner := runSelectedTests
	runSelectedTests = emitPassingSelectedTestEvents
	t.Cleanup(func() { runSelectedTests = previousRunner })

	evidence, err := Execute(context.Background(), root)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(evidence.Candidates) == 0 || len(evidence.Record.Entries) != len(evidence.Candidates) {
		t.Fatalf("Execute() evidence is not candidate-closed: %#v", evidence.Record)
	}
	if evidence.Record.State != "passed" || !isSHA256(evidence.RecordDigest) || !isSHA256(evidence.Record.SourceSnapshotDigest) {
		t.Fatalf("Execute() identity is incomplete: %#v", evidence.Record)
	}
	if len(ExecutionCommandRefs(evidence)) == 0 || len(evidence.Record.ExecutionCommands) == 0 {
		t.Fatalf("Execute() command projection is incomplete: %#v", evidence.Record.ExecutionCommands)
	}
	if err := ValidateCurrent(context.Background(), root, evidence); err != nil {
		t.Fatalf("ValidateCurrent() rejected current evidence: %v", err)
	}
}

func TestValidateCurrentRejectsProducerUnreachableCandidateProjection(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	previousRunner := runSelectedTests
	runSelectedTests = emitPassingSelectedTestEvents
	t.Cleanup(func() { runSelectedTests = previousRunner })
	evidence, err := Execute(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	record := evidence.Record
	record.Entries = append([]JoinedEntry(nil), record.Entries...)
	record.Entries[0].Candidate.TestID += ".counterfeit"
	candidates := make([]app.CommandCoverageOracleCandidate, 0, len(record.Entries))
	for _, entry := range record.Entries {
		candidates = append(candidates, entry.Candidate)
	}
	record.CandidateSetDigest, err = CandidateSetDigest(candidates)
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := EvidenceForRecord(record)
	if err != nil {
		t.Fatalf("counterfeit record must remain internally valid: %v", err)
	}
	if err := ValidateCurrent(context.Background(), root, mutated); DecisionID(err) != "current.candidate_projection_mismatch" {
		t.Fatalf("ValidateCurrent() error = %v, want current.candidate_projection_mismatch", err)
	}
}

func emitPassingSelectedTestEvents(_ context.Context, _ string, _ []ExecutionCommand, ledger *eventLedger) error {
	packages := make([]string, 0, len(ledger.packages))
	for packagePath := range ledger.packages {
		packages = append(packages, packagePath)
	}
	sort.Strings(packages)
	for _, packagePath := range packages {
		if err := ledger.observe(testEvent{Action: "start", Package: packagePath}); err != nil {
			return err
		}
	}
	tests := make([]selectedTestKey, 0, len(ledger.tests))
	for key := range ledger.tests {
		tests = append(tests, key)
	}
	sort.Slice(tests, func(left, right int) bool {
		return tests[left].Package+"\x00"+tests[left].Test < tests[right].Package+"\x00"+tests[right].Test
	})
	for _, key := range tests {
		if err := ledger.observe(testEvent{Action: "run", Package: key.Package, Test: key.Test}); err != nil {
			return err
		}
		attributes := make([]string, 0, len(ledger.expectedAttributes[key]))
		for attribute := range ledger.expectedAttributes[key] {
			attributes = append(attributes, attribute)
		}
		sort.Strings(attributes)
		for _, attribute := range attributes {
			if err := ledger.observe(testEvent{Action: "attr", Package: key.Package, Test: key.Test, Key: commandcoverage.ExecutionAttributeKey, Value: attribute}); err != nil {
				return err
			}
		}
		if err := ledger.observe(testEvent{Action: "pass", Package: key.Package, Test: key.Test}); err != nil {
			return err
		}
	}
	for _, packagePath := range packages {
		if err := ledger.observe(testEvent{Action: "pass", Package: packagePath}); err != nil {
			return err
		}
	}
	return nil
}

func TestRejectReservedAttributeForgeryRejectsDirectOwnerKeyUse(t *testing.T) {
	root := t.TempDir()
	path := "sample_test.go"
	source := `package sample

import "testing"

func TestForged(t *testing.T) {
	t.Attr("proofkit.command-oracle", "counterfeit")
}
`
	if err := os.WriteFile(filepath.Join(root, path), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectReservedAttributeForgery(root, []string{path}); DecisionID(err) != "source.reserved_attribute_direct_use" {
		t.Fatalf("rejectReservedAttributeForgery() error = %v", err)
	}
}

func TestRunGoTestsTerminatesOnContextDeadline(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/timeout\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "timeout_test.go"), []byte(`package timeout

import (
	"testing"
	"time"
)

func TestHang(t *testing.T) { time.Sleep(time.Minute) }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := syntheticCandidates()[0]
	candidate.PackagePath = "."
	candidate.Selector = "timeout_test.go::TestHang"
	candidate.SourcePath = "timeout_test.go"
	candidate.TestName = "TestHang"
	ledger, err := newEventLedger([]app.CommandCoverageOracleCandidate{candidate}, map[string]string{".": "example.test/timeout"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = runGoTests(ctx, root, []ExecutionCommand{{
		Argv:        []string{"go", "test", "-json", "-count=1", "-run", "^TestHang$", "."},
		PackagePath: ".",
	}}, ledger)
	if DecisionID(err) != "process.timeout" {
		t.Fatalf("runGoTests() error = %v, want process.timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("runGoTests() termination took %s", elapsed)
	}
}

func TestRunGoTestCommandTerminatesImmediatelyWhenStderrExceedsBound(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\n/bin/dd if=/dev/zero bs=1048577 count=1 1>&2\n/bin/sleep 5\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	started := time.Now()
	err := runGoTestCommand(context.Background(), t.TempDir(), []string{"go", "test"}, nil)
	if DecisionID(err) != "process.stderr_exceeded" {
		t.Fatalf("runGoTestCommand() error = %v, want process.stderr_exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stderr overflow termination took %s", elapsed)
	}
}

func TestExecutionCommandsKeepPackageTestSetsDisjoint(t *testing.T) {
	candidates := syntheticCandidates()
	candidates[0].PackagePath = "./internal/one"
	candidates[0].TestName = "TestOne"
	candidates[1].PackagePath = "./internal/two"
	candidates[1].TestName = "TestTwo"

	commands := executionCommands(candidates)
	if len(commands) != 2 {
		t.Fatalf("executionCommands() count = %d, want 2", len(commands))
	}
	if got := commands[0].Argv[len(commands[0].Argv)-2:]; !slices.Equal(got, []string{"^(TestOne)$", "./internal/one"}) {
		t.Fatalf("first package command = %#v", commands[0].Argv)
	}
	if got := commands[1].Argv[len(commands[1].Argv)-2:]; !slices.Equal(got, []string{"^(TestTwo)$", "./internal/two"}) {
		t.Fatalf("second package command = %#v", commands[1].Argv)
	}
}

func TestRunGoTestsDoesNotExecuteCrossPackageNameMatches(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/exact\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writePackage := func(directory string, selectedName string, selectedMarker string, forbiddenName string) {
		t.Helper()
		path := filepath.Join(root, directory)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		source := "package " + directory + `

import "testing"

func ` + selectedName + `(t *testing.T) {
	t.Attr("proofkit.command-oracle", "` + selectedMarker + `")
}

func ` + forbiddenName + `(t *testing.T) {
	t.Fatal("cross-package selector executed a non-candidate test")
}
`
		if err := os.WriteFile(filepath.Join(path, directory+"_test.go"), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	candidates := syntheticCandidates()
	candidates[0].PackagePath = "./one"
	candidates[0].Selector = "one/one_test.go::TestOne"
	candidates[0].SourcePath = "one/one_test.go"
	candidates[0].TestName = "TestOne"
	candidates[1].PackagePath = "./two"
	candidates[1].Selector = "two/two_test.go::TestTwo"
	candidates[1].SourcePath = "two/two_test.go"
	candidates[1].TestName = "TestTwo"
	writePackage("one", "TestOne", candidates[0].SourceMarker, "TestTwo")
	writePackage("two", "TestTwo", candidates[1].SourceMarker, "TestOne")
	imports := map[string]string{
		"./one": "example.test/exact/one",
		"./two": "example.test/exact/two",
	}
	ledger, err := newEventLedger(candidates, imports)
	if err != nil {
		t.Fatal(err)
	}
	if err := runGoTests(context.Background(), root, executionCommands(candidates), ledger); err != nil {
		t.Fatalf("runGoTests() error = %v", err)
	}
	if err := ledger.finalize(); err != nil {
		t.Fatalf("event ledger did not close: %v", err)
	}
}
