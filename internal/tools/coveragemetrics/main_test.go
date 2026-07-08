package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
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

func TestBuildCommandRouteMetricsReportsMissingSemanticRoutes(t *testing.T) {
	metrics := buildCommandRouteMetrics(cliContractWithCommands("covered", "z-route-only", "a-route-only"), []app.CommandCoverageSummary{
		{Command: "covered", CommandRef: app.CommandCoverageCommandRef("covered"), RouteCount: 2, SemanticRouteCount: 1},
		{Command: "z-route-only", CommandRef: app.CommandCoverageCommandRef("z-route-only"), RouteCount: 1, SemanticRouteCount: 1},
		{Command: "a-route-only", CommandRef: app.CommandCoverageCommandRef("a-route-only"), RouteCount: 1, SemanticRouteCount: 1},
	}, testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
		{CommandRefs: []string{app.CommandCoverageCommandRef("covered")}, EvidenceClass: "semantic_falsifier"},
		{CommandRefs: []string{app.CommandCoverageCommandRef("covered")}, EvidenceClass: "routing_smoke_nonclaim"},
	}})

	if metrics.CommandCount != 3 || metrics.RouteCount != 4 || metrics.SemanticRouteCount != 3 || metrics.RouteSmokeCount != 1 {
		t.Fatalf("unexpected metrics: %#v", metrics)
	}
	if metrics.AdmittedInventoryEntryCount != 2 || metrics.SemanticInventoryEntryCount != 1 {
		t.Fatalf("unexpected inventory metrics: %#v", metrics)
	}
	if metrics.CommandWithoutSemanticFalsifierRouteCount != 2 {
		t.Fatalf("missing semantic route count=%d, want 2", metrics.CommandWithoutSemanticFalsifierRouteCount)
	}
	want := []string{"a-route-only", "z-route-only"}
	if strings.Join(metrics.CommandsWithoutSemanticFalsifierRoute, ",") != strings.Join(want, ",") {
		t.Fatalf("missing commands=%#v, want %#v", metrics.CommandsWithoutSemanticFalsifierRoute, want)
	}
}

func TestBuildCommandRouteMetricsRequiresMatchingSemanticInventoryCommandRef(t *testing.T) {
	summaries := []app.CommandCoverageSummary{
		{Command: "target", CommandRef: app.CommandCoverageCommandRef("target"), RouteCount: 1, SemanticRouteCount: 1},
	}
	contract := cliContractWithCommands("target")
	cases := []struct {
		name      string
		inventory testevidenceinventory.Inventory
	}{
		{
			name: "mismatched command ref",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{app.CommandCoverageCommandRef("other")}, EvidenceClass: "semantic_falsifier"},
			}},
		},
		{
			name: "unknown command ref",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{"proofkit.cli.unknown"}, EvidenceClass: "semantic_falsifier"},
			}},
		},
		{
			name: "route only evidence",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "routing_smoke_nonclaim"},
			}},
		},
		{
			name: "contract evidence is not semantic command falsifier",
			inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
				{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "contract_admission"},
			}},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			metrics := buildCommandRouteMetrics(contract, summaries, item.inventory)
			if metrics.CommandWithoutSemanticFalsifierRouteCount != 1 ||
				strings.Join(metrics.CommandsWithoutSemanticFalsifierRoute, ",") != "target" {
				t.Fatalf("metrics=%#v, want target missing semantic command coverage", metrics)
			}
		})
	}
}

func TestBuildCommandRouteMetricsReportsUnknownSemanticCommandRefs(t *testing.T) {
	summaries := []app.CommandCoverageSummary{
		{Command: "target", CommandRef: app.CommandCoverageCommandRef("target"), RouteCount: 1, SemanticRouteCount: 1},
	}
	metrics := buildCommandRouteMetrics(cliContractWithCommands("target"), summaries, testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
		{CommandRefs: []string{app.CommandCoverageCommandRef("target")}, EvidenceClass: "semantic_falsifier"},
		{CommandRefs: []string{"proofkit.cli.unknown"}, EvidenceClass: "semantic_falsifier"},
	}})

	if metrics.CommandWithoutSemanticFalsifierRouteCount != 0 {
		t.Fatalf("covered target was reported missing: %#v", metrics)
	}
	if metrics.UnknownSemanticCommandRefCount != 1 || strings.Join(metrics.UnknownSemanticCommandRefs, ",") != "proofkit.cli.unknown" {
		t.Fatalf("unknown semantic command refs not reported: %#v", metrics)
	}
	if err := requireCommandSemanticFalsifierRoutes(metrics); err == nil || !strings.Contains(err.Error(), "unknownRefs") {
		t.Fatalf("requireCommandSemanticFalsifierRoutes() error=%v, want unknown ref failure", err)
	}
}

func TestBuildCommandRouteMetricsReportsContractRouteDrift(t *testing.T) {
	metrics := buildCommandRouteMetrics(cliContractWithCommands("contract-only", "shared"), []app.CommandCoverageSummary{
		{Command: "route-only", CommandRef: app.CommandCoverageCommandRef("route-only"), RouteCount: 1, SemanticRouteCount: 1},
		{Command: "shared", CommandRef: app.CommandCoverageCommandRef("shared"), RouteCount: 1, SemanticRouteCount: 1},
	}, testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{
		{CommandRefs: []string{app.CommandCoverageCommandRef("shared")}, EvidenceClass: "semantic_falsifier"},
	}})

	if got := strings.Join(metrics.ContractOnlyCommands, ","); got != "contract-only" {
		t.Fatalf("ContractOnlyCommands=%#v, want contract-only", metrics.ContractOnlyCommands)
	}
	if got := strings.Join(metrics.RouteOnlyCommands, ","); got != "route-only" {
		t.Fatalf("RouteOnlyCommands=%#v, want route-only", metrics.RouteOnlyCommands)
	}
	if err := requireCommandSemanticFalsifierRoutes(metrics); err == nil || !strings.Contains(err.Error(), "contractOnly=[contract-only]") || !strings.Contains(err.Error(), "routeOnly=[route-only]") {
		t.Fatalf("requireCommandSemanticFalsifierRoutes() error=%v, want contract/route drift failure", err)
	}
}

func TestReadCommandCoverageInventoryRejectsFailedInventory(t *testing.T) {
	mutated := mustAppCommandCoverageInventory(t)
	firstSemanticInventoryEntry(t, mutated)["oracle"].(map[string]any)["assertionSummary"] = ""

	_, err := readCommandCoverageInventoryFrom(mutated)
	if err == nil || !strings.Contains(err.Error(), "weak_or_empty_oracle") {
		t.Fatalf("readCommandCoverageInventoryFrom() error = %v, want weak oracle failure", err)
	}
}

func TestReadCommandCoverageInventoryRejectsSelectorSourcePathDrift(t *testing.T) {
	mutated := mustAppCommandCoverageInventory(t)
	firstSemanticInventoryEntry(t, mutated)["selector"] = "internal/app/other_test.go::TestDrift"

	_, err := readCommandCoverageInventoryFrom(mutated)
	if err == nil || !strings.Contains(err.Error(), "sourcePath must match selector path") {
		t.Fatalf("readCommandCoverageInventoryFrom() error = %v, want selector/sourcePath drift", err)
	}
}

func TestRunWritesCurrentMetricsWhenCommandCoverageInventoryFails(t *testing.T) {
	inventory := mustAppCommandCoverageInventory(t)
	firstSemanticInventoryEntry(t, inventory)["oracle"].(map[string]any)["assertionSummary"] = ""

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
			CommandWithoutSemanticFalsifierRouteCount: 0,
		},
	}, nil); err != nil {
		t.Fatalf("write stale success: %v", err)
	}
	err = run()
	if err == nil || !strings.Contains(err.Error(), "weak_or_empty_oracle") {
		t.Fatalf("run() error = %v, want failed inventory error", err)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read current metrics: %v", err)
	}
	if !strings.Contains(string(content), `"admittedInventoryEntryCount": 0`) ||
		!strings.Contains(string(content), `"commandsWithoutSemanticFalsifierRoute"`) ||
		strings.Contains(string(content), `"commandWithoutSemanticFalsifierRouteCount": 0`) {
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
			CommandWithoutSemanticFalsifierRouteCount: 0,
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
		strings.Contains(string(content), `"commandWithoutSemanticFalsifierRouteCount": 0`) {
		t.Fatalf("failed route inventory builder did not replace stale success artifact:\n%s", string(content))
	}
}

func TestRequireCommandSemanticFalsifierRoutesFailsClosed(t *testing.T) {
	err := requireCommandSemanticFalsifierRoutes(commandRouteMetrics{
		CommandsWithoutSemanticFalsifierRoute: []string{"route-only"},
	})
	if err == nil || !strings.Contains(err.Error(), "missing=[route-only]") {
		t.Fatalf("requireCommandSemanticFalsifierRoutes() error = %v, want semantic-route failure", err)
	}

	if err := requireCommandSemanticFalsifierRoutes(commandRouteMetrics{}); err != nil {
		t.Fatalf("requireCommandSemanticFalsifierRoutes() error = %v, want nil", err)
	}
}

func TestRequireNoLinkageDeadZonesFailsClosed(t *testing.T) {
	err := requireNoLinkageDeadZones(deadZoneMetrics{
		BindingWithoutRequirementIDs:  []string{"REQ-STALE"},
		RequirementWithoutBindingIDs:  []string{"REQ-MISSING"},
		ScenarioWithoutCommandIDs:     []string{"scenario.missing-command"},
		ScenarioWithoutRequirementIDs: []string{"scenario.missing-requirement"},
	})
	if err == nil || !strings.Contains(err.Error(), "requirement/proof linkage dead zones") {
		t.Fatalf("requireNoLinkageDeadZones() error = %v, want dead-zone failure", err)
	}

	if err := requireNoLinkageDeadZones(deadZoneMetrics{}); err != nil {
		t.Fatalf("requireNoLinkageDeadZones() error = %v, want nil", err)
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
			CommandWithoutSemanticFalsifierRouteCount: 1,
			CommandsWithoutSemanticFalsifierRoute:     []string{"route-only"},
		},
	}, errors.New("route failure"))
	if err == nil || !strings.Contains(err.Error(), "route failure") {
		t.Fatalf("writeMetrics() error = %v, want route failure", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(content), `"commandsWithoutSemanticFalsifierRoute"`) || !strings.Contains(string(content), `"route-only"`) {
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

func TestBuildMetricsCarriesRealCommandRouteInventoryAndNonClaim(t *testing.T) {
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

	if metrics.CommandRoutes.CommandCount == 0 || metrics.CommandRoutes.SemanticRouteCount == 0 {
		t.Fatalf("real command route inventory was not loaded: %#v", metrics.CommandRoutes)
	}
	if metrics.CommandRoutes.CommandWithoutSemanticFalsifierRouteCount != 0 {
		t.Fatalf("real command route inventory has missing semantic routes: %#v", metrics.CommandRoutes)
	}
	if !containsNonClaim(metrics.NonClaims, "do not execute those tests") {
		t.Fatalf("metrics nonClaims=%#v, want command-route execution non-claim", metrics.NonClaims)
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

func firstSemanticInventoryEntry(t *testing.T, inventory map[string]any) map[string]any {
	t.Helper()
	for _, raw := range inventory["entries"].([]any) {
		entry := raw.(map[string]any)
		if entry["evidenceClass"] == "semantic_falsifier" {
			return entry
		}
	}
	t.Fatal("inventory has no semantic entry")
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
	writeFile(t, filepath.Join(root, "proofkit/cli-contract.v1.json"), `{"commands": [{"command": "target"}]}`)
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
