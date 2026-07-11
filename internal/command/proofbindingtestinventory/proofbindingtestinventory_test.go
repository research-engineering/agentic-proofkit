package proofbindingtestinventory

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildProjectsCompactProofBindingToAdmittedInventory(t *testing.T) {
	output, exitCode, err := Build(validInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit=%d, want 0", exitCode)
	}
	record := output.(map[string]any)
	if record["projectionKind"] != ProjectionKind || record["entryCount"] != 1 {
		t.Fatalf("unexpected projection metadata: %#v", record)
	}
	commandRefs := stringValues(record["commandRefs"].([]any))
	if len(commandRefs) != 1 || commandRefs[0] != "proofkit_repo.proofkit.surface.verify.go_test" {
		t.Fatalf("commandRefs=%v", commandRefs)
	}
	inventory := record["inventory"].(map[string]any)
	entries := inventory["entries"].([]any)
	if record["entryCount"] != len(entries) {
		t.Fatalf("entryCount=%v len(entries)=%d", record["entryCount"], len(entries))
	}
	entry := entries[0].(map[string]any)
	if entry["testId"] != "test.proofkit.surface.req_proofkit_compact_001" {
		t.Fatalf("testId=%v", entry["testId"])
	}
	if entry["sourcePath"] != "tests/proofkit_falsification_test.go" || entry["selector"] != "tests/proofkit_falsification_test.go::TestRejectsCompactRegression" {
		t.Fatalf("selector/sourcePath drift: %#v", entry)
	}
	if entry["ownerId"] != "proofkit.spec" || entry["evidenceClass"] != "proof_route_candidate" {
		t.Fatalf("owner/evidence drift: %#v", entry)
	}
	if got := stringValues(entry["commandRefs"].([]any)); len(got) != 1 || got[0] != commandRefs[0] {
		t.Fatalf("entry commandRefs=%v outer=%v", got, commandRefs)
	}
	if entry["oracle"] != nil || entry["falsifier"] != nil {
		t.Fatalf("proof-route projection must not synthesize a semantic oracle: %#v", entry)
	}
	nonClaims := stringValues(entry["nonClaims"].([]any))
	if len(nonClaims) != 2 ||
		nonClaims[0] != "This inventory entry does not execute native tests or authenticate receipts." ||
		nonClaims[1] != "This inventory entry projects proof-route wiring only and cannot satisfy semantic coverage." {
		t.Fatalf("entry nonClaims=%v", nonClaims)
	}
	report, reportExitCode, err := BuildReport(validInput())
	if err != nil || reportExitCode != 0 {
		t.Fatalf("BuildReport() exit=%d err=%v", reportExitCode, err)
	}
	if report.Summary["proofRouteCandidateCount"] != 1 || report.Summary["semanticFalsifierCount"] != 0 {
		t.Fatalf("downstream evidence classification summary=%#v", report.Summary)
	}
	for _, rule := range report.RuleResults {
		if rule.RuleID == "test_inventory.route_only_warnings_are_advisory" && rule.Status != "passed" {
			t.Fatalf("proof-route candidate incorrectly failed route-only rule: %#v", rule)
		}
	}
}

func TestBuildRejectsMissingRequirementOwner(t *testing.T) {
	input := validInput()
	input["requirementSource"].(map[string]any)["requirements"] = []any{}

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "has no owner") {
		t.Fatalf("Build() exit=%d err=%v, want missing owner rejection", exitCode, err)
	}
}

func TestBuildRejectsUnstructuredFalsificationSelector(t *testing.T) {
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[9].([]any)
	falsification[0] = "go test ./..."

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "repo/path::stable_anchor") {
		t.Fatalf("Build() exit=%d err=%v, want structured selector rejection", exitCode, err)
	}
}

func TestBuildRejectsSemanticFalsifierWithoutVerifyCommand(t *testing.T) {
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[9].([]any)
	falsification[2] = []any{}

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "proof route requires at least one verify command") {
		t.Fatalf("Build() exit=%d err=%v, want missing verify command rejection", exitCode, err)
	}
}

func TestBuildRejectsUnsafeStructuredFalsificationSelector(t *testing.T) {
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[9].([]any)
	falsification[0] = "../proofkit_falsification_test.go::TestRejectsCompactRegression"

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "escape the repository root") {
		t.Fatalf("Build() exit=%d err=%v, want unsafe structured selector rejection", exitCode, err)
	}
}

func TestBuildRejectsDerivedCommandRefCollision(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.045998791748895126484384867727425029606933562065763381226241226336418593975574")
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[9].([]any)
	falsification[2] = []any{"go test", "go-test"}

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "commandRef collision") {
		t.Fatalf("Build() exit=%d err=%v, want commandRef collision", exitCode, err)
	}
}

func validInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"inventoryId":   "proofkit.derived.inventory",
		"commandRefPolicy": map[string]any{
			"prefix": "proofkit_repo",
		},
		"requirementSource": map[string]any{
			"requirements": []any{
				map[string]any{
					"requirementId": "REQ-PROOFKIT-COMPACT-001",
					"ownerId":       "proofkit.spec",
				},
			},
		},
		"compactProofContract": validCompactContract(),
		"nonClaims":            []any{"Fixture projection does not execute native tests."},
	}
}

func validCompactContract() map[string]any {
	return map[string]any{
		"schema_version":        json.Number("1"),
		"authority_state":       "canonical",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_binding",
		"normalization_profile": "proofkit.compact.v1",
		"non_claims":            []any{"Compact test input does not execute witnesses."},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.surface", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "proof_contract_state", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "mutation_resistance_state"},
		"bindings": []any{
			[]any{
				"REQ-PROOFKIT-COMPACT-001",
				"proofkit.surface",
				"proofkit.surface::scenario.compact",
				"contract",
				"proofkit.compact",
				"witness_backed",
				"blocking",
				[]any{"local-go"},
				positiveWitnessRow(),
				falsificationWitnessRow(),
				[]any{"go test"},
				"no_known_advisory_gap",
			},
		},
	}
}

func positiveWitnessRow() []any {
	return []any{"tests/proofkit_positive_test.go::TestAcceptsCompactContract", []any{"local-go"}, []any{"go test"}, json.Number("0")}
}

func falsificationWitnessRow() []any {
	return []any{"tests/proofkit_falsification_test.go::TestRejectsCompactRegression", []any{"local-go"}, []any{"go test"}, json.Number("0")}
}

func stringValues(values []any) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.(string)
	}
	return result
}
