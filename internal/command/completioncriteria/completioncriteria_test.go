package completioncriteria

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildBlocksUnsatisfiedBlockingCriterion(t *testing.T) {
	record, exitCode, err := Build(validCompletionCriteriaInput("satisfied"))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	record, exitCode, err = Build(validCompletionCriteriaInput("missing_evidence"))
	if err != nil {
		t.Fatalf("Build() missing evidence error = %v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "blockingUnsatisfiedCriterionIds") {
		t.Fatalf("Build() accepted unsatisfied blocking criterion: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func validCompletionCriteriaInput(status string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"completionId":  "proofkit.test.completion",
		"nonClaims":     []any{"Completion criteria test input does not approve merge."},
		"criteria": []any{
			map[string]any{
				"criterionId":            "proofkit.test.criterion",
				"criterion":              "Blocking criterion must be satisfied before completion.",
				"criterionClass":         "blocking",
				"status":                 status,
				"owner":                  "proofkit.test",
				"blocker":                nil,
				"evidenceRefs":           []any{"artifacts/proofkit/evidence.json"},
				"failsWhen":              []any{"Required evidence is missing or failed."},
				"nonClaims":              []any{"This criterion does not execute native proof."},
				"proofRefs":              []any{"proofkit.test.proof"},
				"structuredDecisionRefs": []any{},
				"validatorRefs":          []any{},
			},
		},
	}
}
