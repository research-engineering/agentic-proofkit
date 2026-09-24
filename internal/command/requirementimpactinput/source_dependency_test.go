package requirementimpactinput

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
)

func TestReferencedSourceMeaningChangesReachImpact(t *testing.T) {
	for _, plane := range []string{"named_nonclaim", "scenario"} {
		t.Run(plane, func(t *testing.T) {
			input := validComposeInput(t)
			before := input["baseRequirementSources"].([]any)[0].(map[string]any)
			fields := impactSourceGroup(before)["members"].([]any)[0].(map[string]any)["fields"].(map[string]any)
			if plane == "named_nonclaim" {
				fields["nonClaimRefs"] = []any{"NCL-SCOPE"}
				before["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-SCOPE", "statement": "This requirement does not cover untrusted clients."}}
			} else {
				before["scenarios"] = []any{map[string]any{
					"scenarioId": "scenario.one", "requirementIds": []any{"REQ-PROOFKIT-IMPACT-001"},
					"parameters": []any{}, "preconditions": []any{"A client is connected."},
					"actionSequence":        []any{"Submit a request."},
					"expectedObservations":  []any{"The request is accepted."},
					"forbiddenObservations": []any{}, "examples": []any{},
					"vocabularyRefs": []any{}, "nonClaimRefs": []any{},
				}}
			}
			input["currentRequirementSources"] = []any{cloneAny(t, before)}
			control, code, err := Build(input)
			if err != nil || code != 0 || len(control["changedRequirementIds"].([]any)) != 0 {
				t.Fatalf("unchanged source changed impact: %v %d", err, code)
			}
			after := input["currentRequirementSources"].([]any)[0].(map[string]any)
			if plane == "named_nonclaim" {
				after["nonClaimDefinitions"].([]any)[0].(map[string]any)["statement"] = "This requirement does not cover trusted clients."
			} else {
				after["scenarios"].([]any)[0].(map[string]any)["expectedObservations"] = []any{"The request is rejected."}
			}
			output, code, err := Build(input)
			if err != nil || code != 0 {
				t.Fatalf("changed source rejected: %v %d", err, code)
			}
			if len(output["changedRequirementIds"].([]any)) == 0 {
				t.Fatal("referenced meaning changed without a changed requirement")
			}
			report, _, err := impact.Build(output)
			if err != nil || len(report["obligations"].([]any)) == 0 {
				t.Fatalf("changed requirement lost its impact obligation: %v", err)
			}
		})
	}
}

func TestImpactComposeRejectsWrongMemberOfDeclaredScopedScenario(t *testing.T) {
	input := validComposeInput(t)
	source := input["currentRequirementSources"].([]any)[0].(map[string]any)
	scenario := map[string]any{
		"scenarioId": "proofkit.impact.surface::scenario_one", "requirementIds": []any{"REQ-PROOFKIT-IMPACT-002"},
		"parameters": []any{}, "preconditions": []any{"The source is admitted."},
		"actionSequence":        []any{"Run the declared route."},
		"expectedObservations":  []any{"The response is accepted."},
		"forbiddenObservations": []any{}, "examples": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}
	source["scenarios"] = []any{scenario}
	if _, code, err := Build(input); err == nil || code != 1 {
		t.Fatalf("wrong source-qualified compact scenario membership admitted: %v, exit=%d", err, code)
	}
	scenario["requirementIds"] = []any{"REQ-PROOFKIT-IMPACT-001", "REQ-PROOFKIT-IMPACT-002"}
	if _, code, err := Build(input); err != nil || code != 0 {
		t.Fatalf("declared many-to-many compact scenario rejected: %v, exit=%d", err, code)
	}
}
