package proofbindingtestinventory

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
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
	if !strings.HasPrefix(entry["testId"].(string), "test.proof_route.") {
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
	mappings := record["routeEntryMappings"].([]any)
	if len(mappings) != 1 {
		t.Fatalf("routeEntryMappings=%#v, want one", mappings)
	}
	mapping := mappings[0].(map[string]any)
	if mapping["testId"] != entry["testId"] || mapping["scenarioId"] != "proofkit.surface::scenario.compact" || mapping["role"] != "falsification" {
		t.Fatalf("route mapping=%#v entry=%#v", mapping, entry)
	}
	if mapping["resolutionOrderIndex"] != json.Number("0") {
		t.Fatalf("route mapping resolutionOrderIndex=%#v, want 0", mapping["resolutionOrderIndex"])
	}
	if refs := stringValues(entry["witnessRefs"].([]any)); len(refs) != 1 || refs[0] != mapping["witnessRouteId"] {
		t.Fatalf("entry witnessRefs=%v mapping=%#v", refs, mapping)
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
	if report.Summary["proofRouteCandidateCount"] != 1 || report.Summary["declaredSemanticFalsifierRouteCount"] != 0 {
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

func TestBuildPreservesTwoScenarioRoutesForOneRequirement(t *testing.T) {
	input := validInput()
	contract := input["compactProofContract"].(map[string]any)
	first := contract["bindings"].([]any)[0].([]any)
	second := append([]any{}, first...)
	second[2] = "proofkit.surface::scenario.second"
	second[7] = append([]any{}, first[7].([]any)...)
	second[8] = append([]any{}, first[8].([]any)...)
	contract["bindings"] = []any{first, second}

	output, exitCode, err := Build(input)
	if err != nil || exitCode != 0 {
		t.Fatalf("Build() exit=%d error=%v", exitCode, err)
	}
	record := output.(map[string]any)
	entries := record["inventory"].(map[string]any)["entries"].([]any)
	mappings := record["routeEntryMappings"].([]any)
	if len(entries) != 2 || len(mappings) != 2 {
		t.Fatalf("entries=%#v mappings=%#v", entries, mappings)
	}
	if entries[0].(map[string]any)["testId"] == entries[1].(map[string]any)["testId"] {
		t.Fatalf("scenario-distinct routes collapsed to one testId: %#v", entries)
	}
	if mappings[0].(map[string]any)["witnessRouteId"] == mappings[1].(map[string]any)["witnessRouteId"] {
		t.Fatalf("scenario-distinct routes collapsed to one route: %#v", mappings)
	}
}

func TestBuildNormalizedEmitsAndReadmitsExactRouteEntryMapping(t *testing.T) {
	normalized, exitCode, err := BuildNormalized(validInput())
	if err != nil || exitCode != 0 {
		t.Fatalf("BuildNormalized() exit=%d error=%v", exitCode, err)
	}
	summary := normalized["projectionSummary"].(map[string]any)
	if summary["schemaVersion"] != json.Number("2") || len(summary["routeEntryMappings"].([]any)) != 1 {
		t.Fatalf("projectionSummary=%#v", summary)
	}
	if _, err := testevidenceinventory.AdmitNormalizedProjection(normalized, nil, "test normalized projection"); err != nil {
		t.Fatalf("AdmitNormalizedProjection() error=%v", err)
	}
	summary["routeEntryMappings"].([]any)[0].(map[string]any)["testId"] = "test.proof_route.missing"
	if _, err := testevidenceinventory.AdmitNormalizedProjection(normalized, nil, "test normalized projection"); err == nil || !strings.Contains(err.Error(), "does not match witnessRouteId") {
		t.Fatalf("AdmitNormalizedProjection() error=%v, want derived testId rejection", err)
	}
}

func TestBuildNormalizedPreservesFalsificationResolutionOrder(t *testing.T) {
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	witness := append([]any{}, binding[8].([]any)...)
	witness[3] = json.Number("9")
	binding[8] = witness

	normalized, exitCode, err := BuildNormalized(input)
	if err != nil || exitCode != 0 {
		t.Fatalf("BuildNormalized() exit=%d error=%v", exitCode, err)
	}
	mapping := normalized["projectionSummary"].(map[string]any)["routeEntryMappings"].([]any)[0].(map[string]any)
	if mapping["resolutionOrderIndex"] != json.Number("9") {
		t.Fatalf("resolutionOrderIndex=%#v, want 9", mapping["resolutionOrderIndex"])
	}
	delete(mapping, "resolutionOrderIndex")
	if _, err := testevidenceinventory.AdmitNormalizedProjection(normalized, nil, "test normalized projection"); err == nil || !strings.Contains(err.Error(), "resolutionOrderIndex") {
		t.Fatalf("AdmitNormalizedProjection() error=%v, want missing order rejection", err)
	}
}

func TestNormalizedProjectionRejectsSynchronizedDerivedIDForgery(t *testing.T) {
	normalized, exitCode, err := BuildNormalized(validInput())
	if err != nil || exitCode != 0 {
		t.Fatalf("BuildNormalized() exit=%d error=%v", exitCode, err)
	}
	forgedID := "test.proof_route.forged"
	normalized["inventory"].(map[string]any)["entries"].([]any)[0].(map[string]any)["testId"] = forgedID
	normalized["projectionSummary"].(map[string]any)["routeEntryMappings"].([]any)[0].(map[string]any)["testId"] = forgedID

	if _, err := testevidenceinventory.AdmitNormalizedProjection(normalized, nil, "test normalized projection"); err == nil || !strings.Contains(err.Error(), "does not match witnessRouteId") {
		t.Fatalf("AdmitNormalizedProjection() error=%v, want synchronized derived ID rejection", err)
	}
}

func TestNormalizedProjectionRejectsSemanticPromotion(t *testing.T) {
	normalized, exitCode, err := BuildNormalized(validInput())
	if err != nil || exitCode != 0 {
		t.Fatalf("BuildNormalized() exit=%d error=%v", exitCode, err)
	}
	entry := normalized["inventory"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["evidenceClass"] = testevidenceinventory.EvidenceClassDeclaredSemanticFalsifierRoute
	entry["falsifier"] = map[string]any{
		"dominanceGroup":             "proof.route.promoted",
		"falsifierId":                "falsifier.proof.route.promoted",
		"negativeCaseId":             "case.proof.route.promoted",
		"supersedes":                 []any{},
		"wrongImplementationClassId": "wrong.proof.route.promoted",
	}
	entry["oracle"] = map[string]any{
		"assertionSummary":      "A promoted route is rejected by normalized projection admission.",
		"expectedPublicOutcome": "failed report with diagnostic",
		"oracleId":              "oracle.proof.route.promoted",
		"oracleKind":            "negative_exit_and_diagnostic",
	}

	if _, err := testevidenceinventory.AdmitNormalizedProjection(normalized, nil, "test normalized projection"); err == nil || !strings.Contains(err.Error(), "exact proof-route-candidate semantics") {
		t.Fatalf("AdmitNormalizedProjection() error=%v, want semantic promotion rejection", err)
	}
}

func TestBuildRejectsUnstructuredFalsificationSelector(t *testing.T) {
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[8].([]any)
	falsification[0] = "go test ./..."

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "repo/path::stable_anchor") {
		t.Fatalf("Build() exit=%d err=%v, want structured selector rejection", exitCode, err)
	}
}

func TestBuildRejectsProofRouteCandidateWithoutVerifyCommand(t *testing.T) {
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[8].([]any)
	falsification[2] = []any{}

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "proof route requires at least one verify command") {
		t.Fatalf("Build() exit=%d err=%v, want missing verify command rejection", exitCode, err)
	}
}

func TestBuildRejectsUnsafeStructuredFalsificationSelector(t *testing.T) {
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[8].([]any)
	falsification[0] = "../proofkit_falsification_test.go::TestRejectsCompactRegression"

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "escape the repository root") {
		t.Fatalf("Build() exit=%d err=%v, want unsafe structured selector rejection", exitCode, err)
	}
}

func TestBuildRejectsDerivedCommandRefCollision(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.015764554175908530517697174697685677859930004803180746537891295020670383915624")
	input := validInput()
	binding := input["compactProofContract"].(map[string]any)["bindings"].([]any)[0].([]any)
	falsification := binding[8].([]any)
	falsification[2] = []any{"go test", "go-test"}

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "commandRef collision") {
		t.Fatalf("Build() exit=%d err=%v, want commandRef collision", exitCode, err)
	}
}

func validInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("2"),
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
		"schema_version":        json.Number("2"),
		"authority_state":       "caller_owned_declaration",
		"contract_id":           "proofkit.test.compact",
		"contract_kind":         "requirement_proof_route_declaration",
		"normalization_profile": "proofkit.compact.declaration.v2",
		"non_claims":            []any{"Compact test input does not execute witnesses."},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.surface", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"},
		"bindings": []any{
			[]any{
				"REQ-PROOFKIT-COMPACT-001",
				"proofkit.surface",
				"proofkit.surface::scenario.compact",
				"contract",
				"proofkit.compact",
				"blocking",
				[]any{"local-go"},
				positiveWitnessRow(),
				falsificationWitnessRow(),
				[]any{"go test"},
				"proofkit.claim.mutation.compact",
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
