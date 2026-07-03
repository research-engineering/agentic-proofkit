package requirementcoverageinput

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestBuildComposesInputPreservesDeclaredUniverseAndAllowsDownstreamFailures(t *testing.T) {
	output, exitCode, err := Build(validComposeInput(t, baseInventoryEntries()))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exitCode=%d output=%#v", exitCode, output)
	}
	universe := output["coverageUniverse"].(map[string]any)
	if got := stringsOf(universe["commandRefs"]); strings.Join(got, ",") != "proofkit.coverage.command,proofkit.coverage.missing" {
		t.Fatalf("commandRefs=%v", got)
	}
	testSurfacePaths := surfacePaths(universe["testSurfaces"])
	if strings.Join(testSurfacePaths, ",") != "internal/command/requirementcoverageinput/missing_test.go,internal/command/requirementcoverageinput/requirementcoverageinput_test.go" {
		t.Fatalf("test surface paths=%v", testSurfacePaths)
	}
	view, viewExitCode, err := requirementcoverageview.BuildJSON(output, requirementcoverageview.Options{})
	if err != nil {
		t.Fatalf("composed input should be coverage-view admitted: %v", err)
	}
	if viewExitCode == 0 {
		t.Fatalf("downstream coverage view should still report declared missing command/test surface: %#v", view)
	}
}

func TestBuildRejectsDirectInventoryWithoutNormalizedEnvelope(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	normalized := input["normalizedTestEvidenceInventory"].(map[string]any)
	input["normalizedTestEvidenceInventory"] = normalized["inventory"]

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "normalizedTestEvidenceInventory") {
		t.Fatalf("Build() error=%v, want normalized envelope failure", err)
	}
}

func TestBuildRejectsFabricatedDirectEnvelopeWithSourceMetadata(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	normalized := input["normalizedTestEvidenceInventory"].(map[string]any)
	normalized["sourceCount"] = json.Number("1")
	normalized["sources"] = []any{
		[]any{"source.coverage", "docs/contracts/test-inventory/coverage.v1.json", "sha256:abc", "test_evidence_inventory_fragment", []any{"Fabricated source metadata."}},
	}
	normalized["inputPaths"] = []any{"docs/contracts/test-inventory/coverage.v1.json"}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "direct inventory envelope must not declare source-set metadata") {
		t.Fatalf("Build() error=%v, want fabricated direct envelope failure", err)
	}
}

func TestBuildRejectsSourceSetEnvelopeMissingEntrySourceCoverage(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	normalized := input["normalizedTestEvidenceInventory"].(map[string]any)
	normalized["sourceAuthority"] = "caller_owned_inventory_source_set"
	normalized["sourceCount"] = json.Number("1")
	normalized["sources"] = []any{
		[]any{"source.coverage", "docs/contracts/test-inventory/coverage.v1.json", "sha256:abc", "test_evidence_inventory_fragment", []any{"Source metadata is fixture-only."}},
	}
	normalized["inputPaths"] = []any{"docs/contracts/test-inventory/coverage.v1.json"}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "entrySources must cover every nested inventory entry") {
		t.Fatalf("Build() error=%v, want missing entrySources coverage failure", err)
	}
}

func TestBuildRejectsWrongNormalizedSourceColumns(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	normalized := input["normalizedTestEvidenceInventory"].(map[string]any)
	normalized["sourceColumns"] = []any{"source_id", "path", "role", "sha256", "non_claims"}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "sourceColumns must equal") {
		t.Fatalf("Build() error=%v, want sourceColumns exact-order failure", err)
	}
}

func TestBuildRejectsSelectedOwnerScopeDrift(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	input["selectedOwnerIds"] = []any{"proofkit.other"}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "selectedOwnerIds must equal coverageUniverse ownerIds") {
		t.Fatalf("Build() error=%v, want selected owner mismatch", err)
	}
}

func TestBuildRejectsInventoryOwnerOutsideSelectedScope(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	normalized := input["normalizedTestEvidenceInventory"].(map[string]any)
	inventory := normalized["inventory"].(map[string]any)
	entry := inventory["entries"].([]any)[0].(map[string]any)
	entry["ownerId"] = "proofkit.other"

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "outside selectedOwnerIds") {
		t.Fatalf("Build() error=%v, want inventory owner scope failure", err)
	}
}

func TestBuildPreservesInventoryQualityFindings(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	normalized := input["normalizedTestEvidenceInventory"].(map[string]any)
	inventory := normalized["inventory"].(map[string]any)
	entry := inventory["entries"].([]any)[0].(map[string]any)
	entry["qualityFindings"] = []any{
		map[string]any{
			"findingId":        "finding.coverage.warning",
			"class":            "tautology",
			"severity":         "warning",
			"ownerReviewState": "candidate",
			"evidenceRefs":     []any{"proofkit.coverage.command"},
			"nonClaims":        []any{"Quality finding fixture is warning-only."},
		},
	}

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exitCode=%d output=%#v", exitCode, output)
	}
	outputInventory := output["testEvidenceInventory"].(map[string]any)
	outputEntry := outputInventory["entries"].([]any)[0].(map[string]any)
	findings := outputEntry["qualityFindings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("qualityFindings len=%d want 1: %#v", len(findings), outputEntry)
	}
	finding := findings[0].(map[string]any)
	if finding["findingId"] != "finding.coverage.warning" ||
		finding["class"] != "tautology" ||
		finding["severity"] != "warning" {
		t.Fatalf("quality finding was not preserved: %#v", finding)
	}
}

func TestBuildOutputIsStableForReorderedInventoryEntries(t *testing.T) {
	first := inventoryEntry("test.coverage.first", "proofkit.coverage.first", "internal/command/requirementcoverageinput/first_test.go", "first")
	second := inventoryEntry("test.coverage.second", "proofkit.coverage.second", "internal/command/requirementcoverageinput/second_test.go", "second")
	left, _, err := Build(validComposeInput(t, first+","+second))
	if err != nil {
		t.Fatalf("Build(left) error = %v", err)
	}
	right, _, err := Build(validComposeInput(t, second+","+first))
	if err != nil {
		t.Fatalf("Build(right) error = %v", err)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatalf("marshal left: %v", err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatalf("marshal right: %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("composed output must be stable for reordered inventory entries\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
}

func TestBuildRejectsObservedSurfaceIDCollisionWithDeclaredSurface(t *testing.T) {
	input := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	universe := input["coverageUniverse"].(map[string]any)
	universe["testSurfaces"] = []any{
		map[string]any{
			"surfaceId": observedTestSurfaceID("proofkit.coverage", "internal/command/requirementcoverageinput/requirementcoverageinput_test.go"),
			"ownerId":   "proofkit.coverage",
			"path":      "internal/command/requirementcoverageinput/other_test.go",
		},
	}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "observed test surface id collision") {
		t.Fatalf("Build() error=%v, want observed surface collision", err)
	}
}

func validComposeInput(t *testing.T, inventoryEntries string) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 1,
  "composerInputId": "proofkit.coverage.compose",
  "viewInputId": "proofkit.coverage.view",
  "selectedOwnerIds": ["proofkit.coverage"],
  "requirementSource": {
    "schemaVersion": 1,
    "sourceId": "proofkit.coverage.source",
    "specPackagePath": "docs/specs/proofkit-coverage",
    "overviewPath": "docs/specs/proofkit-coverage/overview.md",
    "requirementsPath": "docs/specs/proofkit-coverage/requirements.v1.json",
    "requirements": [
      {
        "requirementId": "REQ-PROOFKIT-COVERAGE-001",
        "ownerId": "proofkit.coverage",
        "invariant": "Coverage input composition must preserve declared coverage universe facts.",
        "claimLevel": "blocking",
        "riskClass": "high",
        "proofBindingRefs": ["proofkit/requirement-bindings.json"],
        "nonClaimRefs": [],
        "nonClaims": ["Coverage composer fixture does not execute native tests."],
        "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
        "deferral": null,
        "updatePolicy": {
          "reviewOwnerId": "proofkit.coverage",
          "requiresImpactDeclaration": true,
          "requiresProofBindingReview": true
        }
      }
    ],
    "nonClaims": ["Coverage composer fixture source is test-only."]
  },
  "compactProofContract": {
    "schema_version": 1,
    "authority_state": "canonical",
    "contract_id": "proofkit.coverage.compact",
    "contract_kind": "requirement_proof_binding",
    "normalization_profile": "proofkit.compact.v1",
    "non_claims": ["Compact fixture does not execute witnesses."],
    "surface_columns": ["surface_id", "required_environment_classes", "preconditioned_environment_classes"],
    "surfaces": [["proofkit.coverage", ["local-go"], []]],
    "witness_columns": ["selector", "environment_classes", "verify_commands", "resolution_order_index"],
    "binding_columns": ["requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "proof_contract_state", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "mutation_resistance_state"],
    "bindings": [[
      "REQ-PROOFKIT-COVERAGE-001",
      "proofkit.coverage",
      "proofkit.coverage::scenario",
      "contract",
      "proofkit.coverage.invariant",
      "witness_backed",
      "blocking",
      ["local-go"],
      ["internal/command/requirementcoverageinput/requirementcoverageinput_test.go::positive", ["local-go"], ["go test ./internal/command/requirementcoverageinput"], 0],
      ["internal/command/requirementcoverageinput/requirementcoverageinput_test.go::falsification", ["local-go"], ["go test ./internal/command/requirementcoverageinput"], 1],
      ["go test ./internal/command/requirementcoverageinput"],
      "no_known_advisory_gap"
    ]]
  },
  "normalizedTestEvidenceInventory": {
    "schemaVersion": 1,
    "normalizedInventoryId": "proofkit.coverage.inventory.normalized",
    "normalizedKind": "proofkit.test-evidence-inventory.normalized",
    "sourceAuthority": "caller_owned_inventory",
    "sourceCount": 0,
    "sourceColumns": ["source_id", "path", "sha256", "role", "non_claims"],
    "sources": [],
    "entrySources": [],
    "inputPaths": [],
    "inventory": {
      "schemaVersion": 1,
      "inventoryId": "proofkit.coverage.inventory",
      "authority": "caller_owned_inventory",
      "entries": [`+inventoryEntries+`],
      "nonClaims": ["Inventory fixture does not execute native tests."]
    },
    "nonClaims": ["Normalized fixture is a caller-owned data product."]
  },
  "coverageUniverse": {
    "schemaVersion": 1,
    "universeId": "proofkit.coverage.universe",
    "authority": "caller_owned_inventory",
    "completenessDeclaration": "selected_owner_surfaces",
    "ownerIds": ["proofkit.coverage"],
    "codeSurfaces": [{"surfaceId": "proofkit.coverage.code", "ownerId": "proofkit.coverage", "path": "internal/command/requirementcoverageinput"}],
    "specSurfaces": [{"surfaceId": "proofkit.coverage.spec", "ownerId": "proofkit.coverage", "path": "docs/specs/proofkit-coverage/requirements.v1.json"}],
    "testSurfaces": [{"surfaceId": "proofkit.coverage.missing_test", "ownerId": "proofkit.coverage", "path": "internal/command/requirementcoverageinput/missing_test.go"}],
    "commandRefs": ["proofkit.coverage.missing"],
    "nonClaims": ["Coverage composer fixture is selected-owner scope only."]
  },
  "ownerInvariantRegistry": null,
  "localEnvironmentPolicy": {"authority": "caller_provided", "localEnvironmentClasses": ["local-go"]},
  "options": {"scope": "graph"}
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return input
}

func baseInventoryEntries() string {
	return inventoryEntry(
		"test.coverage.semantic",
		"proofkit.coverage.command",
		"internal/command/requirementcoverageinput/requirementcoverageinput_test.go",
		"semantic",
	)
}

func inventoryEntry(testID string, commandRef string, sourcePath string, suffix string) string {
	return `{
  "testId": "` + testID + `",
  "selector": "` + sourcePath + `::` + suffix + `",
  "sourcePath": "` + sourcePath + `",
  "ownerId": "proofkit.coverage",
  "evidenceClass": "semantic_falsifier",
  "requirementRefs": ["REQ-PROOFKIT-COVERAGE-001"],
  "ownerInvariantRefs": [],
  "commandRefs": ["` + commandRef + `"],
  "witnessRefs": [],
  "falsifier": {
    "falsifierId": "falsifier.coverage.` + suffix + `",
    "negativeCaseId": "case.coverage.` + suffix + `",
    "wrongImplementationClassId": "wrong.coverage.` + suffix + `",
    "dominanceGroup": "coverage.` + suffix + `",
    "supersedes": []
  },
  "oracle": {
    "oracleId": "oracle.coverage.` + suffix + `",
    "oracleKind": "negative_exit_and_diagnostic",
    "assertionSummary": "Coverage composer fixture has a semantic falsifier."
  },
  "nonClaims": []
}`
}

func stringsOf(raw any) []string {
	values := raw.([]any)
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.(string))
	}
	return out
}

func surfacePaths(raw any) []string {
	values := raw.([]any)
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.(map[string]any)["path"].(string))
	}
	sort.Strings(out)
	return out
}
