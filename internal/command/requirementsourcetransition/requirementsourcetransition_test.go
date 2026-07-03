package requirementsourcetransition

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRejectsLifecycleTransitionWithoutNewEvidence(t *testing.T) {
	record, exitCode, err := Build(validRequirementSourceTransitionInput(false))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	record, exitCode, err = Build(validRequirementSourceTransitionInput(true))
	if err != nil {
		t.Fatalf("Build() lifecycle transition error = %v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "removed requirement transition must declare new lifecycle evidenceRefs") {
		t.Fatalf("Build() accepted lifecycle transition without new evidence: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func validRequirementSourceTransitionInput(removeWithoutNewEvidence bool) map[string]any {
	previous := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
	next := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
	if removeWithoutNewEvidence {
		next = transitionRequirementSource("removed", []any{"docs/evidence/previous.md"})
	}
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"transitionId":  "proofkit.test.requirement-source-transition",
		"nonClaims":     []any{"Requirement source transition test input does not approve deletion."},
		"previous":      previous,
		"next":          next,
	}
}

func transitionRequirementSource(lifecycleState string, lifecycleEvidenceRefs []any) map[string]any {
	claimLevel := "blocking"
	if lifecycleState != "active" {
		claimLevel = "advisory"
	}
	return map[string]any{
		"schemaVersion":    json.Number("1"),
		"sourceId":         "proofkit.test.requirements",
		"specPackagePath":  "docs/specs/proofkit-test",
		"overviewPath":     "docs/specs/proofkit-test/overview.md",
		"requirementsPath": "docs/specs/proofkit-test/requirements.v1.json",
		"nonClaims":        []any{"Requirement source transition fixture does not execute native witnesses."},
		"requirements": []any{
			map[string]any{
				"claimLevel": claimLevel,
				"deferral":   nil,
				"invariant":  "Requirement source transition must preserve lifecycle evidence monotonicity.",
				"lifecycle": map[string]any{
					"evidenceRefs":              lifecycleEvidenceRefs,
					"replacementRequirementIds": []any{},
					"state":                     lifecycleState,
				},
				"nonClaimRefs": []any{},
				"nonClaims":    []any{"This requirement does not prove merge readiness."},
				"ownerId":      "proofkit.test",
				"proofBindingRefs": []any{
					"docs/contracts/requirement-proof-binding-sources.v1.json",
				},
				"requirementId": "REQ-PROOFKIT-TRANSITION-001",
				"riskClass":     "medium",
				"updatePolicy": map[string]any{
					"requiresImpactDeclaration":  true,
					"requiresProofBindingReview": true,
					"reviewOwnerId":              "proofkit.test",
				},
			},
		},
	}
}
