package requirementsourceadmission

import "testing"

func TestScenarioLinksPreserveMembershipAndReferenceOnlyRoutes(t *testing.T) {
	input := validSource()
	group := input["groups"].([]any)[0].(map[string]any)
	second := validSource()["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
	second["requirementId"] = "REQ-PROOFKIT-SOURCE-002"
	group["members"] = append(group["members"].([]any), second)
	input["scenarios"] = []any{map[string]any{
		"scenarioId": "proofkit.test.surface::scenario_one", "requirementIds": []any{"REQ-PROOFKIT-SOURCE-001"},
		"parameters": []any{}, "preconditions": []any{"An admitted request is ready."},
		"actionSequence": []any{"Submit the request."}, "expectedObservations": []any{"The response is accepted."},
		"forbiddenObservations": []any{}, "examples": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}}
	result, err := Evaluate(input)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("scoped scenario source: %v", err)
	}
	sources := []Source{result.Source}
	for _, item := range []struct {
		name  string
		link  ScenarioLink
		valid bool
	}{
		{"declared member", ScenarioLink{"REQ-PROOFKIT-SOURCE-001", "proofkit.test.surface::scenario_one"}, true},
		{"wrong member", ScenarioLink{"REQ-PROOFKIT-SOURCE-002", "proofkit.test.surface::scenario_one"}, false},
		{"reference only", ScenarioLink{"REQ-PROOFKIT-SOURCE-002", "proofkit.test.surface::scenario_two"}, true},
		{"unknown requirement", ScenarioLink{"REQ-PROOFKIT-SOURCE-003", "proofkit.test.surface::scenario_one"}, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := AdmitScenarioLinks(sources, []ScenarioLink{item.link}); (err == nil) != item.valid {
				t.Fatalf("scenario link admission = %v, want valid=%t", err, item.valid)
			}
		})
	}
}
