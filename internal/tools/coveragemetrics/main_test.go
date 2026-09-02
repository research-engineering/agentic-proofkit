package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/tools/commandoracle"
)

func TestReadJSONRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.v1.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"schemaVersion":1}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := readJSON[requirementSource](path)
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("readJSON() error = %v, want duplicate-key rejection", err)
	}
}

func TestReadRequirementsRequiresOwnerAdmission(t *testing.T) {
	root := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})
	sourceDir := filepath.Join("docs", "specs", "test-source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("mkdir source: %v", err)
	}
	sourcePath := filepath.Join(sourceDir, "requirements.v1.json")
	source := `{
  "schemaVersion": 1,
  "sourceId": "proofkit.test.requirements",
  "specPackagePath": "docs/specs/test-source",
  "overviewPath": "docs/specs/test-source/overview.md",
  "requirementsPath": "docs/specs/test-source/requirements.v1.json",
  "requirements": []
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	_, err = readRequirements()
	if err == nil || !strings.Contains(err.Error(), "requirement source admission failed") {
		t.Fatalf("readRequirements() error = %v, want owner admission failure", err)
	}
}

func TestBuildCommandRouteMetricsReportsMissingDeclaredSemanticRoutes(t *testing.T) {
	metrics := buildCommandRouteMetrics(cliContractWithCommands("covered", "z-route-only", "a-route-only"), []app.CommandCoverageSummary{
		{Command: "covered", CommandRef: app.CommandCoverageCommandRef("covered"), RouteCount: 2, ProofRouteCandidateCount: 1},
		{Command: "z-route-only", CommandRef: app.CommandCoverageCommandRef("z-route-only"), RouteCount: 1, ProofRouteCandidateCount: 1},
		{Command: "a-route-only", CommandRef: app.CommandCoverageCommandRef("a-route-only"), RouteCount: 1, ProofRouteCandidateCount: 1},
	}, testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
		{CommandRefs: []string{app.CommandCoverageCommandRef("covered")}, EvidenceClass: "declared_semantic_falsifier_route"},
		{CommandRefs: []string{app.CommandCoverageCommandRef("z-route-only")}, EvidenceClass: "proof_route_candidate"},
		{CommandRefs: []string{app.CommandCoverageCommandRef("covered")}, EvidenceClass: "routing_smoke_nonclaim"},
	}})

	if metrics.CommandCount != 3 || metrics.RouteCount != 4 || metrics.ProofRouteCandidateRouteCount != 3 || metrics.RouteSmokeCount != 1 {
		t.Fatalf("unexpected metrics: %#v", metrics)
	}
	if metrics.AdmittedInventoryEntryCount != 3 || metrics.ProofRouteCandidateInventoryEntryCount != 1 || metrics.DeclaredSemanticFalsifierRouteEntryCount != 1 {
		t.Fatalf("unexpected inventory metrics: %#v", metrics)
	}
	if metrics.CommandWithoutDeclaredSemanticFalsifierRouteCount != 2 {
		t.Fatalf("missing declared semantic route count=%d, want 2", metrics.CommandWithoutDeclaredSemanticFalsifierRouteCount)
	}
	want := []string{"a-route-only", "z-route-only"}
	if strings.Join(metrics.CommandsWithoutDeclaredSemanticFalsifierRoute, ",") != strings.Join(want, ",") {
		t.Fatalf("missing commands=%#v, want %#v", metrics.CommandsWithoutDeclaredSemanticFalsifierRoute, want)
	}
}

func TestBuildCommandRouteMetricsRequiresMatchingDeclaredSemanticInventoryCommandRef(t *testing.T) {
	summaries := []app.CommandCoverageSummary{
		{Command: "target", CommandRef: app.CommandCoverageCommandRef("target"), RouteCount: 1},
	}
	contract := cliContractWithCommands("target")
	cases := []struct {
		name      string
		inventory testevidenceinventory.Inventory
	}{
		{
			name: "mismatched command ref",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{app.CommandCoverageCommandRef("other")}, EvidenceClass: "declared_semantic_falsifier_route"},
			}},
		},
		{
			name: "unknown command ref",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{"proofkit.cli.unknown"}, EvidenceClass: "declared_semantic_falsifier_route"},
			}},
		},
		{
			name: "route only evidence",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "routing_smoke_nonclaim"},
			}},
		},
		{
			name: "proof route candidate is not semantic evidence",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "proof_route_candidate"},
			}},
		},
		{
			name: "contract evidence is not semantic command falsifier",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "declared_contract_admission_route"},
			}},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			metrics := buildCommandRouteMetrics(contract, summaries, item.inventory)
			if metrics.CommandWithoutDeclaredSemanticFalsifierRouteCount != 1 ||
				strings.Join(metrics.CommandsWithoutDeclaredSemanticFalsifierRoute, ",") != "target" {
				t.Fatalf("metrics=%#v, want target missing declared semantic route", metrics)
			}
		})
	}
}

func TestBuildCommandRouteMetricsReportsUnknownDeclaredSemanticRouteCommandRefs(t *testing.T) {
	summaries := []app.CommandCoverageSummary{
		{Command: "target", CommandRef: app.CommandCoverageCommandRef("target"), RouteCount: 1},
	}
	metrics := buildCommandRouteMetrics(cliContractWithCommands("target"), summaries, testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
		{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "declared_semantic_falsifier_route"},
		{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "proof_route_candidate"},
		{CommandRefs: []string{"proofkit.cli.unknown"}, EvidenceClass: "declared_semantic_falsifier_route"},
	}})

	if metrics.CommandWithoutDeclaredSemanticFalsifierRouteCount != 0 {
		t.Fatalf("covered target was reported missing: %#v", metrics)
	}
	if metrics.UnknownDeclaredSemanticRouteCommandRefCount != 1 || strings.Join(metrics.UnknownDeclaredSemanticRouteCommandRefs, ",") != "proofkit.cli.unknown" {
		t.Fatalf("unknown semantic command refs not reported: %#v", metrics)
	}
	if err := requireCommandRouteInventoryClosure(metrics); err == nil || !strings.Contains(err.Error(), "unknownDeclaredSemanticRouteRefs") {
		t.Fatalf("requireCommandRouteInventoryClosure() error=%v, want unknown ref failure", err)
	}
}

func TestBuildCommandRouteMetricsSeparatesStaticDeclarationsFromExecutionEvidence(t *testing.T) {
	commandRef := app.CommandCoverageCommandRef("target")
	metrics := buildCommandRouteMetricsWithExecution(
		cliContractWithCommands("target"),
		[]app.CommandCoverageSummary{{Command: "target", CommandRef: commandRef, RouteCount: 1, ProofRouteCandidateCount: 1}},
		testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{{CommandRefs: []string{commandRef}, EvidenceClass: "proof_route_candidate"}}},
		commandExecutionSummary{
			CandidateCount:          1,
			CandidateSetDigest:      strings.Repeat("1", 64),
			CommandRefs:             []string{commandRef},
			CounterfeitCorpusDigest: strings.Repeat("2", 64),
			RecordDigest:            strings.Repeat("3", 64),
			SourceSnapshotDigest:    strings.Repeat("4", 64),
		},
	)

	if metrics.CommandWithoutExecutionBackedSemanticRouteCount != 0 || len(metrics.CommandsWithoutExecutionBackedSemanticRoute) != 0 {
		t.Fatalf("execution-backed route was not closed: %#v", metrics)
	}
	if metrics.CommandWithoutDeclaredSemanticFalsifierRouteCount != 1 || strings.Join(metrics.CommandsWithoutDeclaredSemanticFalsifierRoute, ",") != "target" {
		t.Fatalf("static declaration was incorrectly upgraded: %#v", metrics)
	}
	if metrics.ExecutionBackedSemanticRouteEntryCount != 1 || metrics.CommandOracleRecordDigest != strings.Repeat("3", 64) {
		t.Fatalf("execution evidence identity was not projected: %#v", metrics)
	}
	if err := requireCommandRouteInventoryClosure(metrics); err != nil {
		t.Fatalf("requireCommandRouteInventoryClosure() error = %v", err)
	}
}

func TestBuildCommandRouteMetricsRejectsExecutionEvidenceForUnknownCommand(t *testing.T) {
	metrics := buildCommandRouteMetricsWithExecution(
		cliContractWithCommands("target"),
		[]app.CommandCoverageSummary{{Command: "target", CommandRef: app.CommandCoverageCommandRef("target"), RouteCount: 1, ProofRouteCandidateCount: 1}},
		testevidenceinventory.Inventory{},
		commandExecutionSummary{CommandRefs: []string{"proofkit.cli.unknown"}},
	)
	if metrics.UnknownExecutionBackedSemanticRouteCommandRefCount != 1 || strings.Join(metrics.UnknownExecutionBackedSemanticRouteCommandRefs, ",") != "proofkit.cli.unknown" {
		t.Fatalf("unknown execution command ref was not retained: %#v", metrics)
	}
}

func TestBuildCommandRouteMetricsReportsContractRouteDrift(t *testing.T) {
	metrics := buildCommandRouteMetrics(cliContractWithCommands("contract-only", "shared"), []app.CommandCoverageSummary{
		{Command: "route-only", CommandRef: app.CommandCoverageCommandRef("route-only"), RouteCount: 1},
		{Command: "shared", CommandRef: app.CommandCoverageCommandRef("shared"), RouteCount: 1},
	}, testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
		{CommandRefs: []string{app.CommandCoverageCommandRef("shared")}, EvidenceClass: "declared_semantic_falsifier_route"},
	}})

	if got := strings.Join(metrics.ContractOnlyCommands, ","); got != "contract-only" {
		t.Fatalf("ContractOnlyCommands=%#v, want contract-only", metrics.ContractOnlyCommands)
	}
	if got := strings.Join(metrics.RouteOnlyCommands, ","); got != "route-only" {
		t.Fatalf("RouteOnlyCommands=%#v, want route-only", metrics.RouteOnlyCommands)
	}
	if err := requireCommandRouteInventoryClosure(metrics); err == nil || !strings.Contains(err.Error(), "contractOnly=[contract-only]") || !strings.Contains(err.Error(), "routeOnly=[route-only]") {
		t.Fatalf("requireCommandRouteInventoryClosure() error=%v, want contract/route drift failure", err)
	}
}

func TestReadCommandCoverageInventoryRejectsUnanchoredCandidate(t *testing.T) {
	mutated := mustAppCommandCoverageInventory(t)
	firstCandidateInventoryEntry(t, mutated)["ownerInvariantRefs"] = []any{}

	_, err := readCommandCoverageInventoryFrom(mutated)
	if err == nil || !strings.Contains(err.Error(), "missing_declared_route_anchor") {
		t.Fatalf("readCommandCoverageInventoryFrom() error = %v, want missing candidate anchor failure", err)
	}
}

func TestReadCommandCoverageInventoryRejectsSelectorSourcePathDrift(t *testing.T) {
	mutated := mustAppCommandCoverageInventory(t)
	firstCandidateInventoryEntry(t, mutated)["selector"] = "internal/app/other_test.go::TestDrift"

	_, err := readCommandCoverageInventoryFrom(mutated)
	if err == nil || !strings.Contains(err.Error(), "sourcePath must match selector path") {
		t.Fatalf("readCommandCoverageInventoryFrom() error = %v, want selector/sourcePath drift", err)
	}
}

func TestRunWritesCurrentMetricsWhenCommandCoverageInventoryFails(t *testing.T) {
	inventory := mustAppCommandCoverageInventory(t)
	firstCandidateInventoryEntry(t, inventory)["ownerInvariantRefs"] = []any{}

	root := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	writeMinimalCoverageMetricsRepo(t, root)
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})
	previousInput := commandCoverageInventoryInput
	t.Cleanup(func() { commandCoverageInventoryInput = previousInput })
	commandCoverageInventoryInput = func() (map[string]any, error) {
		return inventory, nil
	}

	if err := writeMetrics(metrics{
		ArtifactKind:  "proofkit.coverage-metrics.v1",
		SchemaVersion: 1,
		CommandRoutes: commandRouteMetrics{
			CommandWithoutDeclaredSemanticFalsifierRouteCount: 0,
		},
	}, nil); err != nil {
		t.Fatalf("write stale success: %v", err)
	}
	err = run()
	if err == nil || !strings.Contains(err.Error(), "missing_declared_route_anchor") {
		t.Fatalf("run() error = %v, want failed inventory error", err)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read current metrics: %v", err)
	}
	if !strings.Contains(string(content), `"admittedInventoryEntryCount": 0`) ||
		!strings.Contains(string(content), `"commandsWithoutDeclaredSemanticFalsifierRoute"`) ||
		strings.Contains(string(content), `"commandWithoutDeclaredSemanticFalsifierRouteCount": 0`) {
		t.Fatalf("failed inventory did not replace stale success artifact:\n%s", string(content))
	}
}

func TestRunWritesCurrentMetricsWhenCommandRouteInventoryBuilderFails(t *testing.T) {
	root := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	writeMinimalCoverageMetricsRepo(t, root)
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})
	previousInput := commandCoverageInventoryInput
	t.Cleanup(func() { commandCoverageInventoryInput = previousInput })
	commandCoverageInventoryInput = func() (map[string]any, error) {
		return nil, errors.New("semantic coverage route requires owner-declared proof metadata")
	}

	if err := writeMetrics(metrics{
		ArtifactKind:  "proofkit.coverage-metrics.v1",
		SchemaVersion: 1,
		CommandRoutes: commandRouteMetrics{
			CommandWithoutDeclaredSemanticFalsifierRouteCount: 0,
		},
	}, nil); err != nil {
		t.Fatalf("write stale success: %v", err)
	}
	err = run()
	if err == nil || !strings.Contains(err.Error(), "semantic coverage route requires owner-declared proof metadata") {
		t.Fatalf("run() error = %v, want route inventory builder failure", err)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read current metrics: %v", err)
	}
	if !strings.Contains(string(content), `"admittedInventoryEntryCount": 0`) ||
		strings.Contains(string(content), `"commandWithoutDeclaredSemanticFalsifierRouteCount": 0`) {
		t.Fatalf("failed route inventory builder did not replace stale success artifact:\n%s", string(content))
	}
}

func TestWriteCurrentExecutionMetricsInvalidatesBothArtifactsOnTerminalSourceDrift(t *testing.T) {
	root := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	previousValidate := commandOracleValidateCurrent
	previousWrite := commandOracleWriteDiagnostic
	previousInvalidate := commandOracleInvalidateDiagnostic
	t.Cleanup(func() {
		commandOracleValidateCurrent = previousValidate
		commandOracleWriteDiagnostic = previousWrite
		commandOracleInvalidateDiagnostic = previousInvalidate
	})
	validationCount := 0
	commandOracleValidateCurrent = func(context.Context, string, commandoracle.Evidence) error {
		validationCount++
		if validationCount == 2 {
			return errors.New("terminal source drift")
		}
		return nil
	}
	commandOracleWriteDiagnostic = func(root string, _ commandoracle.Evidence) error {
		path := filepath.Join(root, filepath.FromSlash(commandoracle.RecordPath))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("diagnostic"), 0o644)
	}
	commandOracleInvalidateDiagnostic = func(root string) error {
		err := os.Remove(filepath.Join(root, filepath.FromSlash(commandoracle.RecordPath)))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	err = writeCurrentExecutionMetrics(context.Background(), metrics{}, commandoracle.Evidence{})
	if err == nil || !strings.Contains(err.Error(), "terminal source drift") {
		t.Fatalf("writeCurrentExecutionMetrics() error = %v", err)
	}
	for _, path := range []string{outputPath, commandoracle.RecordPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale artifact %s remains after source drift: %v", path, err)
		}
	}
}

func TestWriteMetricsFileRejectsSymlinkEscapeWithoutMutation(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(t *testing.T, root, outside string)
	}{
		{
			name: "destination symlink",
			setup: func(t *testing.T, root, outside string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(root, "artifacts", "proofkit"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "victim.json"), filepath.Join(root, filepath.FromSlash(outputPath))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "parent symlink",
			setup: func(t *testing.T, root, outside string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(root, "artifacts"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "artifacts", "proofkit")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			testCase.setup(t, root, outside)
			oldwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(root); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldwd) })

			if err := writeMetricsFile(metrics{}); err == nil {
				t.Fatal("writeMetricsFile() admitted a symlink escape")
			}
			entries, err := os.ReadDir(outside)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("outside directory was mutated: %v", entries)
			}
		})
	}
}

func TestInvalidateMetricsFileRejectsSymlinkParentWithoutDeletingOutsideFile(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "artifacts", "proofkit")); err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(outside, "coverage-metrics.json")
	if err := os.WriteFile(outsidePath, []byte("outside sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })

	if err := invalidateMetricsFile(); err == nil {
		t.Fatal("invalidateMetricsFile() admitted a symlink escape")
	}
	content, err := os.ReadFile(outsidePath)
	if err != nil {
		t.Fatalf("outside file was removed: %v", err)
	}
	if string(content) != "outside sentinel" {
		t.Fatalf("outside file was mutated: %q", content)
	}
}

func TestEachCommandRouteClosureConjunctHasIndependentFalsifier(t *testing.T) {
	closed := closedCommandRouteMetricsFixture()
	cases := []struct {
		name    string
		metrics commandRouteMetrics
		want    string
	}{
		{name: "missing candidate", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) { value.CommandsWithoutProofRouteCandidate = []string{"target"} }), want: "missingCandidates=[target]"},
		{name: "unknown candidate ref", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) { value.UnknownProofRouteCandidateRefs = []string{"proofkit.unknown"} }), want: "unknownCandidateRefs=[proofkit.unknown]"},
		{name: "unknown declared route ref", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) {
			value.UnknownDeclaredSemanticRouteCommandRefs = []string{"proofkit.unknown"}
		}), want: "unknownDeclaredSemanticRouteRefs=[proofkit.unknown]"},
		{name: "missing execution-backed route", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) {
			value.CommandsWithoutExecutionBackedSemanticRoute = []string{"target"}
		}), want: "missingExecutionBackedRoutes=[target]"},
		{name: "unknown execution-backed ref", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) {
			value.UnknownExecutionBackedSemanticRouteCommandRefs = []string{"proofkit.unknown"}
		}), want: "unknownExecutionBackedRefs=[proofkit.unknown]"},
		{name: "execution candidate partition mismatch", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) { value.ExecutionBackedSemanticRouteEntryCount = 2 }), want: "executionEntries=2 candidateEntries=1"},
		{name: "invalid command oracle digest", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) { value.CommandOracleRecordDigest = "invalid" }), want: "commandOracleDigestsValid=false"},
		{name: "contract only", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) { value.ContractOnlyCommands = []string{"contract-only"} }), want: "contractOnly=[contract-only]"},
		{name: "route only", metrics: mutateCommandRouteMetrics(closed, func(value *commandRouteMetrics) { value.RouteOnlyCommands = []string{"route-only"} }), want: "routeOnly=[route-only]"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := requireCommandRouteInventoryClosure(test.metrics)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("requireCommandRouteInventoryClosure() error = %v, want %q", err, test.want)
			}
		})
	}
	if err := requireCommandRouteInventoryClosure(closed); err != nil {
		t.Fatalf("requireCommandRouteInventoryClosure() error = %v, want nil", err)
	}
}

func closedCommandRouteMetricsFixture() commandRouteMetrics {
	return commandRouteMetrics{
		ProofRouteCandidateInventoryEntryCount: 1,
		ExecutionBackedSemanticRouteEntryCount: 1,
		CommandOracleCandidateSetDigest:        strings.Repeat("1", 64),
		CommandOracleCounterfeitCorpusDigest:   strings.Repeat("2", 64),
		CommandOracleRecordDigest:              strings.Repeat("3", 64),
		CommandOracleSourceSnapshotDigest:      strings.Repeat("4", 64),
	}
}

func mutateCommandRouteMetrics(value commandRouteMetrics, mutate func(*commandRouteMetrics)) commandRouteMetrics {
	mutate(&value)
	return value
}

func TestEachLinkageDeadZoneConjunctHasIndependentFalsifier(t *testing.T) {
	cases := []struct {
		name    string
		metrics deadZoneMetrics
		want    string
	}{
		{name: "binding without requirement", metrics: deadZoneMetrics{BindingWithoutRequirementIDs: []string{"REQ-STALE"}}, want: "bindingWithoutRequirement=[REQ-STALE]"},
		{name: "requirement without binding", metrics: deadZoneMetrics{RequirementWithoutBindingIDs: []string{"REQ-MISSING"}}, want: "requirementWithoutBinding=[REQ-MISSING]"},
		{name: "scenario without command", metrics: deadZoneMetrics{ScenarioWithoutCommandIDs: []string{"scenario.missing-command"}}, want: "scenarioWithoutCommand=[scenario.missing-command]"},
		{name: "scenario without requirement", metrics: deadZoneMetrics{ScenarioWithoutRequirementIDs: []string{"scenario.missing-requirement"}}, want: "scenarioWithoutRequirement=[scenario.missing-requirement]"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := requireNoLinkageDeadZones(test.metrics)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("requireNoLinkageDeadZones() error = %v, want %q", err, test.want)
			}
		})
	}
	if err := requireNoLinkageDeadZones(deadZoneMetrics{}); err != nil {
		t.Fatalf("requireNoLinkageDeadZones() error = %v, want nil", err)
	}
}

func TestBindingWitnessSelectorsRejectMissingSemanticOwner(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	bindings, err := readJSON[bindingFile](filepath.Join(root, "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBindingWitnessSelectorsAtRoot(root, bindings); err != nil {
		t.Fatalf("current binding selectors are invalid: %v", err)
	}
	for index := range bindings.Bindings {
		if bindings.Bindings[index].ScenarioID != "proofkit.spec-proof-core.installed-readme-first-input" {
			continue
		}
		bindings.Bindings[index].WitnessSelectors[0].Selector = "TestDeletedSemanticOwner"
		bindings.Bindings[index].WitnessSelectors[0].Command = "go test ./internal/tools/packageverify -run '^TestDeletedSemanticOwner$'"
		err := validateBindingWitnessSelectorsAtRoot(root, bindings)
		if err == nil || !strings.Contains(err.Error(), "selector TestDeletedSemanticOwner is missing") {
			t.Fatalf("missing selector error=%v", err)
		}
		return
	}
	t.Fatal("installed README binding missing")
}

func TestBindingWitnessSelectorsRequireExactCriticalInventories(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	bindings, err := readJSON[bindingFile](filepath.Join(root, "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBindingWitnessSelectorsAtRoot(root, bindings); err != nil {
		t.Fatalf("current binding selectors are invalid: %v", err)
	}

	for _, scenarioID := range []string{
		"proofkit.agent-workflow.bounded-safe-text",
		"proofkit.agent-workflow.catalog-prerequisite-causality",
		"proofkit.agent-workflow.cli-presentation-capability-product",
		"proofkit.agent-workflow.installed-carrier-smoke-closure",
		"proofkit.agent-workflow.native-evidence-guidance-purity",
		"proofkit.agent-workflow.native-evidence-guidance-slot-closure",
		"proofkit.agent-workflow.no-ambient-authority",
		"proofkit.agent-workflow.prompt-coordinate-and-escalation-closure",
		"proofkit.agent-workflow.public-cli-relation-closure",
		"proofkit.agent-workflow.pure-single-admission-owner",
		"proofkit.agent-workflow.reference-closed-bounded-context",
		"proofkit.agent-workflow.review-identity-closure",
		"proofkit.agent-workflow.semantic-owner-minimality",
		"proofkit.agent-workflow.semantic-owner-topology",
		"proofkit.agent-workflow.stage-prefix-and-terminal-relation",
		"proofkit.agent-workflow.style-strip-parity",
		"proofkit.agent-workflow.total-checkpoint-successor-relation",
		"proofkit.agent-workflow.version-edge-wire-observation",
		"proofkit.package-boundary.cli-output-root-witnesses",
		"proofkit.package-boundary.generated-command-caller-preservation",
		"proofkit.package-boundary.generated-command-field-inventory",
		"proofkit.package-boundary.launcher-profile-admission",
		"proofkit.package-boundary.merge-critical-runtime-preconditions",
		"proofkit.package-boundary.outside-consumer-artifact",
		"proofkit.package-boundary.package-public-docs-no-mutable-release-facts",
		"proofkit.package-boundary.python-wheel-generated-continuation",
		"proofkit.supply-chain-quality.binding-selector-executability",
		"proofkit.supply-chain-quality.browser-failure-diagnostics-retention",
		"proofkit.supply-chain-quality.ci-required-aggregate-exactness",
		"proofkit.supply-chain-quality.cli-abi-golden",
		"proofkit.supply-chain-quality.cli-contract-topology",
		"proofkit.supply-chain-quality.cli-output-witness-contract",
		"proofkit.supply-chain-quality.codeql-permission-separation",
		"proofkit.supply-chain-quality.installed-package-json-abi-smoke",
		"proofkit.supply-chain-quality.osv-permission-separation",
		"proofkit.supply-chain-quality.python-wheel-platform-byte-compatibility",
		"proofkit.supply-chain-quality.release-closeout-npm-byte-admission",
		"proofkit.supply-chain-quality.release-platform-python-wheels",
		"proofkit.supply-chain-quality.release-change-record-projection",
		"proofkit.supply-chain-quality.release-predecessor-lineage",
		"proofkit.supply-chain-quality.release-predecessor-lineage-workflow",
		"proofkit.supply-chain-quality.scorecard-permission-and-publication-inputs",
		"proofkit.supply-chain-quality.workflow-package-gate-oracle",
		"proofkit.supply-chain-quality.workflow-source-oracles",
		"proofkit.spec-proof-core.adoption-contract-envelope-cli-abi",
		"proofkit.spec-proof-core.agent-route-brief-cli-abi",
		"proofkit.spec-proof-core.agent-route-brief-projection",
		"proofkit.spec-proof-core.agent-route-brief-version-edge",
		"proofkit.spec-proof-core.agent-route-flag-pre-read-admission",
		"proofkit.spec-proof-core.agent-route-materialized-ref-admission",
		"proofkit.spec-proof-core.agent-route-report-contract-closure",
		"proofkit.spec-proof-core.declared-route-mapping-without-assurance",
		"proofkit.spec-proof-core.requirement-authoring-ref-provenance",
		"proofkit.spec-proof-core.requirement-browser-one-shot-cleanup",
		"proofkit.spec-proof-core.test-inventory-and-coverage-view",
	} {
		index := -1
		for candidate := range bindings.Bindings {
			if bindings.Bindings[candidate].ScenarioID == scenarioID {
				index = candidate
				break
			}
		}
		if index < 0 {
			t.Fatalf("critical binding %s is missing", scenarioID)
		}
		original := append([]witnessSelector(nil), bindings.Bindings[index].WitnessSelectors...)
		if len(original) < 1 {
			t.Fatalf("critical binding %s has no removable selector", scenarioID)
		}

		t.Run(scenarioID+"/empty", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].WitnessSelectors = nil
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "witness selectors=[]") {
				t.Fatalf("empty selector error=%v", err)
			}
		})
		t.Run(scenarioID+"/missing", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].WitnessSelectors = append([]witnessSelector(nil), original[:len(original)-1]...)
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "witness selectors=") {
				t.Fatalf("missing selector error=%v", err)
			}
		})
		t.Run(scenarioID+"/surplus", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].WitnessSelectors = append(append([]witnessSelector(nil), original...), original[0])
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "witness selectors=") {
				t.Fatalf("surplus selector error=%v", err)
			}
		})
		t.Run(scenarioID+"/owner-transfer", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].RequirementID = "REQ-PROOFKIT-QUALITY-009"
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "required independent-falsifier binding is missing") {
				t.Fatalf("owner-transfer error=%v", err)
			}
		})
		t.Run(scenarioID+"/scenario-transfer", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].ScenarioID += ".transferred"
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			want := "required independent-falsifier binding is missing"
			if strings.HasPrefix(bindings.Bindings[index].RequirementID, "REQ-PROOFKIT-WORKFLOW-") {
				want = "workflow binding is absent from the exact independent-falsifier inventory"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("scenario-transfer error=%v", err)
			}
		})
		t.Run(scenarioID+"/selector-substitution", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].WitnessSelectors[0].Selector = "TestSubstitutedSemanticOwner"
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "witness selectors=") {
				t.Fatalf("selector-substitution error=%v", err)
			}
		})
		t.Run(scenarioID+"/command-drift", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].WitnessSelectors[0].Command = "go test ./internal/app -run '^TestSubstitutedSemanticOwner$'"
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "selector command=") {
				t.Fatalf("command-drift error=%v", err)
			}
		})
	}

	t.Run("workflow/surplus-binding", func(t *testing.T) {
		mutated := cloneBindingFile(bindings)
		mutated.Bindings = append(mutated.Bindings, bindingScenario{
			RequirementID: "REQ-PROOFKIT-WORKFLOW-001",
			ScenarioID:    "proofkit.agent-workflow.uninventoried-surplus",
		})
		err := validateBindingWitnessSelectorsAtRoot(root, mutated)
		if err == nil || !strings.Contains(err.Error(), "workflow binding is absent from the exact independent-falsifier inventory") {
			t.Fatalf("surplus workflow binding error=%v", err)
		}
	})
	t.Run("workflow/duplicate-binding", func(t *testing.T) {
		mutated := cloneBindingFile(bindings)
		for _, binding := range bindings.Bindings {
			if binding.ScenarioID != "proofkit.agent-workflow.pure-single-admission-owner" {
				continue
			}
			mutated.Bindings = append(mutated.Bindings, binding)
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "required independent-falsifier binding is duplicated") {
				t.Fatalf("duplicate workflow binding error=%v", err)
			}
			return
		}
		t.Fatal("workflow duplicate-binding seed is missing")
	})

	for _, scenarioID := range []string{
		"proofkit.package-boundary.cli-output-root-witnesses",
		"proofkit.package-boundary.generated-command-caller-preservation",
		"proofkit.package-boundary.generated-command-field-inventory",
		"proofkit.package-boundary.launcher-profile-admission",
		"proofkit.package-boundary.merge-critical-runtime-preconditions",
		"proofkit.package-boundary.outside-consumer-artifact",
		"proofkit.package-boundary.package-public-docs-no-mutable-release-facts",
		"proofkit.package-boundary.python-wheel-generated-continuation",
		"proofkit.supply-chain-quality.browser-failure-diagnostics-retention",
		"proofkit.supply-chain-quality.cli-abi-golden",
		"proofkit.supply-chain-quality.cli-contract-topology",
		"proofkit.supply-chain-quality.cli-output-witness-contract",
		"proofkit.supply-chain-quality.codeql-permission-separation",
		"proofkit.supply-chain-quality.installed-package-json-abi-smoke",
		"proofkit.supply-chain-quality.osv-permission-separation",
		"proofkit.supply-chain-quality.python-wheel-platform-byte-compatibility",
		"proofkit.supply-chain-quality.release-platform-python-wheels",
		"proofkit.supply-chain-quality.scorecard-permission-and-publication-inputs",
		"proofkit.supply-chain-quality.workflow-source-oracles",
		"proofkit.spec-proof-core.adoption-contract-envelope-cli-abi",
		"proofkit.spec-proof-core.declared-route-mapping-without-assurance",
		"proofkit.spec-proof-core.requirement-authoring-ref-provenance",
		"proofkit.spec-proof-core.requirement-browser-one-shot-cleanup",
		"proofkit.spec-proof-core.test-inventory-and-coverage-view",
	} {
		index := -1
		for candidate := range bindings.Bindings {
			if bindings.Bindings[candidate].ScenarioID == scenarioID {
				index = candidate
				break
			}
		}
		if index < 0 {
			t.Fatalf("split binding %s is missing", scenarioID)
		}
		t.Run(scenarioID+"/relocated-witness-path", func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			mutated.Bindings[index].WitnessPath = "scripts/workflow_package_gate_oracle_test.go"
			err := validateBindingWitnessSelectorsAtRoot(root, mutated)
			if err == nil || !strings.Contains(err.Error(), "witness path=") ||
				!strings.Contains(err.Error(), ", want exact ") {
				t.Fatalf("relocated witness path error=%v", err)
			}
		})
	}
}

func TestExactSelectorInventoryRejectsExistingUnrelatedTests(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	bindings, err := readJSON[bindingFile](filepath.Join(root, "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	unrelated := map[string]witnessSelector{
		"proofkit.spec-proof-core.declared-route-mapping-without-assurance": {
			Selector: "TestBuildJSONRequiresExactlyOneProofInput",
			Command:  "go test ./internal/command/requirementcoverageview -run '^TestBuildJSONRequiresExactlyOneProofInput$'",
		},
		"proofkit.spec-proof-core.requirement-authoring-ref-provenance": {
			Selector: "TestBuildDoesNotReadAuthoringRefPaths",
			Command:  "go test ./internal/command/requirementauthoringplan -run '^TestBuildDoesNotReadAuthoringRefPaths$'",
		},
		"proofkit.spec-proof-core.test-inventory-and-coverage-view": {
			Selector: "TestBuildJSONRequiresExactlyOneProofInput",
			Command:  "go test ./internal/command/requirementcoverageview -run '^TestBuildJSONRequiresExactlyOneProofInput$'",
		},
	}
	for scenarioID, replacement := range unrelated {
		t.Run(scenarioID, func(t *testing.T) {
			mutated := cloneBindingFile(bindings)
			for index := range mutated.Bindings {
				if mutated.Bindings[index].ScenarioID != scenarioID {
					continue
				}
				mutated.Bindings[index].WitnessSelectors = []witnessSelector{replacement}
				err := validateBindingWitnessSelectorsAtRoot(root, mutated)
				if err == nil || !strings.Contains(err.Error(), "witness selectors=") {
					t.Fatalf("unrelated existing selector error=%v", err)
				}
				return
			}
			t.Fatalf("binding %s is missing", scenarioID)
		})
	}
}

func cloneBindingFile(source bindingFile) bindingFile {
	clone := bindingFile{
		Requirements: append([]bindingRequirement(nil), source.Requirements...),
		Bindings:     append([]bindingScenario(nil), source.Bindings...),
	}
	for index := range clone.Bindings {
		clone.Bindings[index].CommandIDs = append([]string(nil), source.Bindings[index].CommandIDs...)
		clone.Bindings[index].WitnessSelectors = append([]witnessSelector(nil), source.Bindings[index].WitnessSelectors...)
	}
	return clone
}

func TestBindingWitnessSelectorsAcceptUnnamedGoTestParameter(t *testing.T) {
	root := t.TempDir()
	witnessPath := filepath.Join("internal", "sample", "sample_test.go")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(witnessPath)), 0o755); err != nil {
		t.Fatalf("mkdir witness directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/sample\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatalf("write go.mod fixture: %v", err)
	}
	source := "package sample\n\nimport \"testing\"\n\nfunc TestRunnable(*testing.T) { if testing.Short() { panic(\"short-mode falsifier\") } }\n"
	if err := os.WriteFile(filepath.Join(root, witnessPath), []byte(source), 0o644); err != nil {
		t.Fatalf("write witness fixture: %v", err)
	}
	bindings := bindingFile{
		Bindings: []bindingScenario{bindingSelectorFixture(
			"scenario.unnamed-parameter", witnessPath, "TestRunnable",
		)},
	}

	command := exec.Command("go", "test", "./internal/sample", "-run", "^TestRunnable$", "-count=1")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Go toolchain rejected unnamed test parameter: %v\n%s", err, output)
	}
	if err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings); err != nil {
		t.Fatalf("valid unnamed Go test parameter rejected: %v", err)
	}
}

func TestBindingWitnessSelectorsRejectInvalidGoTestSignature(t *testing.T) {
	root := t.TempDir()
	witnessPath := filepath.Join("internal", "sample", "sample_test.go")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(witnessPath)), 0o755); err != nil {
		t.Fatalf("mkdir witness directory: %v", err)
	}
	source := "package sample\n\nimport \"testing\"\n\nfunc TestNotRunnable() {}\n"
	if err := os.WriteFile(filepath.Join(root, witnessPath), []byte(source), 0o644); err != nil {
		t.Fatalf("write witness fixture: %v", err)
	}
	bindings := bindingFile{
		Bindings: []bindingScenario{{
			ScenarioID:  "scenario.invalid-signature",
			WitnessPath: witnessPath,
			WitnessSelectors: []witnessSelector{{
				Selector: "TestNotRunnable",
				Command:  "go test ./internal/sample -run '^TestNotRunnable$'",
			}},
		}},
	}

	err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings)
	if err == nil || !strings.Contains(err.Error(), "is not a valid Go test function") {
		t.Fatalf("invalid signature error=%v", err)
	}
}

func TestBindingWitnessSelectorsRejectSkippingTest(t *testing.T) {
	root := t.TempDir()
	witnessPath := filepath.Join("internal", "sample", "sample_test.go")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(witnessPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/sample\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := "package sample\n\nimport \"testing\"\n\nfunc TestSkipping(t *testing.T) { t.Skip(\"blocked\") }\n"
	if err := os.WriteFile(filepath.Join(root, witnessPath), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	bindings := bindingFile{Bindings: []bindingScenario{bindingSelectorFixture(
		"scenario.skipping", witnessPath, "TestSkipping",
	)}}

	err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings)
	if err == nil || !strings.Contains(err.Error(), "contains t.Skip") {
		t.Fatalf("skipping witness error=%v", err)
	}
}

func TestBindingWitnessSelectorsRejectVacuousTestBody(t *testing.T) {
	root := t.TempDir()
	witnessPath := filepath.Join("internal", "sample", "sample_test.go")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(witnessPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/sample\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, witnessPath), []byte("package sample\n\nimport \"testing\"\n\nfunc TestVacuous(t *testing.T) { _ = t }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bindings := bindingFile{Bindings: []bindingScenario{bindingSelectorFixture(
		"scenario.vacuous", witnessPath, "TestVacuous",
	)}}

	err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings)
	if err == nil || !strings.Contains(err.Error(), "no failure-capable assertion candidate") {
		t.Fatalf("vacuous witness error=%v", err)
	}
}

func TestBindingWitnessSelectorsRejectNonTestAndBuildExcludedFiles(t *testing.T) {
	t.Run("non-test source", func(t *testing.T) {
		root := t.TempDir()
		witnessPath := filepath.Join("internal", "sample", "sample.go")
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(witnessPath)), 0o755); err != nil {
			t.Fatalf("mkdir witness directory: %v", err)
		}
		source := "package sample\n\nimport \"testing\"\n\nfunc TestLooksRunnable(t *testing.T) {}\n"
		if err := os.WriteFile(filepath.Join(root, witnessPath), []byte(source), 0o644); err != nil {
			t.Fatalf("write witness fixture: %v", err)
		}
		bindings := bindingFile{Bindings: []bindingScenario{bindingSelectorFixture(
			"scenario.non-test", witnessPath, "TestLooksRunnable",
		)}}

		err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings)
		if err == nil || !strings.Contains(err.Error(), "must be an active _test.go file") {
			t.Fatalf("non-test witness error=%v", err)
		}
	})

	t.Run("build-excluded test", func(t *testing.T) {
		root := t.TempDir()
		packageDir := filepath.Join(root, "internal", "sample")
		if err := os.MkdirAll(packageDir, 0o755); err != nil {
			t.Fatalf("mkdir witness directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.invalid/fixture\n\ngo 1.25.0\n"), 0o644); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		if err := os.WriteFile(filepath.Join(packageDir, "sample.go"), []byte("package sample\n"), 0o644); err != nil {
			t.Fatalf("write package fixture: %v", err)
		}
		witnessPath := filepath.Join("internal", "sample", "excluded_test.go")
		source := "//go:build proofkit_never\n\npackage sample\n\nimport \"testing\"\n\nfunc TestExcluded(t *testing.T) {}\n"
		if err := os.WriteFile(filepath.Join(root, witnessPath), []byte(source), 0o644); err != nil {
			t.Fatalf("write excluded witness: %v", err)
		}
		bindings := bindingFile{Bindings: []bindingScenario{bindingSelectorFixture(
			"scenario.excluded", witnessPath, "TestExcluded",
		)}}

		err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings)
		if err == nil || !strings.Contains(err.Error(), "is not active for the current Go build") {
			t.Fatalf("build-excluded witness error=%v", err)
		}
	})
}

func bindingSelectorFixture(scenarioID, witnessPath, selector string) bindingScenario {
	return bindingScenario{
		ScenarioID:  scenarioID,
		WitnessPath: witnessPath,
		WitnessSelectors: []witnessSelector{{
			Selector: selector,
			Command:  fmt.Sprintf("go test ./%s -run '^%s$'", filepath.ToSlash(filepath.Dir(witnessPath)), selector),
		}},
	}
}

func TestBuildMetricsReportsScenarioWithoutRequirement(t *testing.T) {
	metrics := buildMetrics(
		[]requirementRecord{{RequirementID: "REQ-OK", ClaimLevel: "blocking", Lifecycle: lifecycle{State: "active"}}},
		bindingFile{
			Requirements: []bindingRequirement{{RequirementID: "REQ-OK", ProofState: "witness_backed"}},
			Bindings:     []bindingScenario{{ScenarioID: "scenario.bogus", RequirementID: "REQ-BOGUS", CommandIDs: []string{"proofkit.command"}}},
		},
		witnessPlan{Commands: []struct {
			ID string `json:"id"`
		}{{ID: "proofkit.command"}}},
		cliContractWithCommands(),
		testevidenceinventory.Inventory{},
	)
	if got := strings.Join(metrics.DeadZones.ScenarioWithoutRequirementIDs, ","); got != "scenario.bogus" {
		t.Fatalf("ScenarioWithoutRequirementIDs=%#v, want scenario.bogus", metrics.DeadZones.ScenarioWithoutRequirementIDs)
	}
}

func TestBuildMetricsProjectsExactCLIContractCommandInventory(t *testing.T) {
	metrics := buildMetrics(
		nil,
		bindingFile{},
		witnessPlan{},
		cliContractWithCommands("z-command", "a-command"),
		testevidenceinventory.Inventory{},
	)
	if metrics.CLIContract.CommandCount != 2 || strings.Join(metrics.CLIContract.Commands, ",") != "a-command,z-command" {
		t.Fatalf("CLIContract=%#v, want exact sorted command inventory", metrics.CLIContract)
	}
}

func TestWriteMetricsWritesCurrentReportBeforeRouteFailure(t *testing.T) {
	root := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	err = writeMetrics(metrics{
		ArtifactKind:  "proofkit.coverage-metrics.v1",
		SchemaVersion: 1,
		CommandRoutes: commandRouteMetrics{
			CommandWithoutDeclaredSemanticFalsifierRouteCount: 1,
			CommandsWithoutDeclaredSemanticFalsifierRoute:     []string{"route-only"},
		},
	}, errors.New("route failure"))
	if err == nil || !strings.Contains(err.Error(), "route failure") {
		t.Fatalf("writeMetrics() error = %v, want route failure", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(content), `"commandsWithoutDeclaredSemanticFalsifierRoute"`) || !strings.Contains(string(content), `"route-only"`) {
		t.Fatalf("output did not preserve current route failure report:\n%s", string(content))
	}
}

func cliContractWithCommands(commands ...string) cliContract {
	contract := cliContract{}
	for _, command := range commands {
		contract.Commands = append(contract.Commands, struct {
			Command string `json:"command"`
		}{Command: command})
	}
	return contract
}

func TestBuildMetricsCarriesRealCommandRouteCandidatesAndNonClaim(t *testing.T) {
	metrics := buildMetrics(
		[]requirementRecord{{RequirementID: "REQ-1", ClaimLevel: "blocking", Lifecycle: lifecycle{State: "active"}}},
		bindingFile{
			Requirements: []bindingRequirement{{
				RequirementID: "REQ-1",
				ProofState:    "witness_backed",
			}},
			Bindings: []bindingScenario{{
				RequirementID: "REQ-1",
				ScenarioID:    "scenario-1",
				CommandIDs:    []string{"command-1"},
			}},
		},
		witnessPlan{Commands: []struct {
			ID string `json:"id"`
		}{{ID: "command-1"}}},
		cliContract{Commands: []struct {
			Command string `json:"command"`
		}{{Command: "command-1"}}},
		mustReadCommandCoverageInventory(t),
	)

	if metrics.CommandRoutes.CommandCount == 0 || metrics.CommandRoutes.ProofRouteCandidateRouteCount == 0 || metrics.CommandRoutes.ProofRouteCandidateInventoryEntryCount == 0 {
		t.Fatalf("real command route inventory was not loaded: %#v", metrics.CommandRoutes)
	}
	if metrics.CommandRoutes.DeclaredSemanticFalsifierRouteEntryCount != 0 {
		t.Fatalf("static command routes were counted as semantic evidence: %#v", metrics.CommandRoutes)
	}
	if metrics.CommandRoutes.CommandWithoutDeclaredSemanticFalsifierRouteCount != metrics.CommandRoutes.CommandCount {
		t.Fatalf("candidate-only commands did not remain missing semantic evidence: %#v", metrics.CommandRoutes)
	}
	if metrics.CommandRoutes.CommandWithoutExecutionBackedSemanticRouteCount != metrics.CommandRoutes.CommandCount {
		t.Fatalf("unexecuted candidates did not remain missing execution evidence: %#v", metrics.CommandRoutes)
	}
	if !containsNonClaim(metrics.NonClaims, "do not become execution-backed semantic evidence") {
		t.Fatalf("metrics nonClaims=%#v, want static-evidence boundary", metrics.NonClaims)
	}
}

func mustReadCommandCoverageInventory(t *testing.T) testevidenceinventory.Inventory {
	t.Helper()
	inventory, err := readCommandCoverageInventory()
	if err != nil {
		t.Fatalf("readCommandCoverageInventory() error = %v", err)
	}
	return inventory
}

func mustAppCommandCoverageInventory(t *testing.T) map[string]any {
	t.Helper()
	inventory, err := app.CommandCoverageInventory()
	if err != nil {
		t.Fatalf("CommandCoverageInventory() error = %v", err)
	}
	return inventory
}

func firstCandidateInventoryEntry(t *testing.T, inventory map[string]any) map[string]any {
	t.Helper()
	for _, raw := range inventory["entries"].([]any) {
		entry := raw.(map[string]any)
		if entry["evidenceClass"] == "proof_route_candidate" {
			return entry
		}
	}
	t.Fatal("inventory has no proof-route candidate entry")
	return nil
}

func writeMinimalCoverageMetricsRepo(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "docs/specs/test-source/requirements.v1.json"), `{
  "schemaVersion": 1,
  "sourceId": "proofkit.test.requirements",
  "specPackagePath": "docs/specs/test-source",
  "overviewPath": "docs/specs/test-source/overview.md",
  "requirementsPath": "docs/specs/test-source/requirements.v1.json",
  "requirements": [
    {
      "requirementId": "REQ-PROOFKIT-TEST-001",
      "ownerId": "proofkit.test",
      "invariant": "Test coverage metrics fixture must have a bound active requirement.",
      "claimLevel": "blocking",
      "riskClass": "medium",
      "proofBindingRefs": ["proofkit/requirement-bindings.json"],
      "nonClaimRefs": [],
      "nonClaims": ["Fixture requirement does not execute tests."],
      "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
      "deferral": null,
      "updatePolicy": {"reviewOwnerId": "proofkit.test", "requiresImpactDeclaration": true, "requiresProofBindingReview": true}
    }
  ],
  "nonClaims": ["Fixture source does not own production behavior."]
}
`)
	writeFile(t, filepath.Join(root, "proofkit/requirement-bindings.json"), `{
  "requirements": [{"requirementId": "REQ-PROOFKIT-TEST-001", "proofState": "witness_backed"}],
  "bindings": [{"requirementId": "REQ-PROOFKIT-TEST-001", "scenarioId": "proofkit.test.scenario", "witnessId": "proofkit.test.witness", "commandIds": ["proofkit.test.command"]}]
}
`)
	writeFile(t, filepath.Join(root, "proofkit/witness-plan.json"), `{"commands": [{"id": "proofkit.test.command"}]}`)
	writeFile(t, filepath.Join(root, "proofkit/cli-contract.v2.json"), `{"commands": [{"command": "target"}]}`)
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func containsNonClaim(nonClaims []string, fragment string) bool {
	for _, nonClaim := range nonClaims {
		if strings.Contains(nonClaim, fragment) {
			return true
		}
	}
	return false
}
