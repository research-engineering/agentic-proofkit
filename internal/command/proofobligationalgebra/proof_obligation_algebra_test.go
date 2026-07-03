package proofobligationalgebra

import (
	"encoding/json"
	"testing"
)

func TestBuildAdmitsAtomicObligationAndRejectsMissingRoute(t *testing.T) {
	input := validProofObligationAlgebraInput()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input = validProofObligationAlgebraInput()
	input["obligations"].([]any)[0].(map[string]any)["proofRouteRefs"] = []any{}
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build(mutated) error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build(mutated) exit=%d state=%s, want failed", exitCode, record.State)
	}
}

func validProofObligationAlgebraInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"algebraId":     "proofkit.test.algebra",
		"obligations": []any{
			map[string]any{
				"obligationId":       "proofkit.test.obligation",
				"obligationKind":     "atomic",
				"requirementId":      "REQ-PROOFKIT-TEST-001",
				"owner":              "proofkit.test.owner",
				"proofRouteRefs":     []any{"proofkit.test.route"},
				"childObligationIds": []any{},
				"conditionRefs":      []any{},
				"delegationRefs":     []any{},
				"evidenceRefs":       []any{"artifacts/proofkit/test.json"},
				"expiryRef":          nil,
				"reviewConditionRef": nil,
				"rationale":          "test route is required",
				"nonClaims":          []any{"Proof obligation test input does not execute witnesses."},
			},
		},
		"nonClaims": []any{"Proof obligation algebra test input is not merge proof."},
	}
}
