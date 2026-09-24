package requirementsourceadmission

import "testing"

func TestSourceReviewDigestTracksOnlyReachableDependencies(t *testing.T) {
	build := func(used, unused, observation string) string {
		t.Helper()
		input := validSource()
		fields := sourceMember(input, 0)["fields"].(map[string]any)
		fields["nonClaimRefs"] = []any{"NCL-USED"}
		second := validSource()["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
		second["requirementId"] = "REQ-PROOFKIT-SOURCE-002"
		second["fields"].(map[string]any)["nonClaimRefs"] = []any{"NCL-UNUSED"}
		group := input["groups"].([]any)[0].(map[string]any)
		group["members"] = append(group["members"].([]any), second)
		input["nonClaimDefinitions"] = []any{
			map[string]any{"nonClaimId": "NCL-UNUSED", "statement": unused},
			map[string]any{"nonClaimId": "NCL-USED", "statement": used},
		}
		input["scenarios"] = []any{map[string]any{
			"scenarioId": "proofkit.test.surface::scenario_one", "requirementIds": []any{"REQ-PROOFKIT-SOURCE-001"},
			"parameters": []any{}, "preconditions": []any{"An admitted request is ready."},
			"actionSequence": []any{"Submit the request."}, "expectedObservations": []any{observation},
			"forbiddenObservations": []any{}, "examples": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
		}}
		result, err := Evaluate(input)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("admit source dependencies: %v", err)
		}
		return RequirementValue(result.Source.Requirements()[0])["sourceReviewDigest"].(string)
	}
	baseline := build("This named denial excludes untrusted clients.", "This separate denial excludes staging.", "The request is accepted.")
	if baseline == "" || baseline != build("This named denial excludes untrusted clients.", "This separate denial excludes previews.", "The request is accepted.") {
		t.Fatal("another requirement's definition changed this requirement's review digest")
	}
	if baseline == build("This named denial excludes trusted clients.", "This separate denial excludes staging.", "The request is accepted.") {
		t.Fatal("referenced definition did not change a requirement review digest")
	}
	if baseline == build("This named denial excludes untrusted clients.", "This separate denial excludes staging.", "The request is rejected.") {
		t.Fatal("scenario body did not change a requirement review digest")
	}
}
