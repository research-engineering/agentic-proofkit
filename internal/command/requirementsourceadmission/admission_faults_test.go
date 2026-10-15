package requirementsourceadmission

import (
	"encoding/json"
	"testing"
)

// One run must describe every independent authoring fault so an agent does not
// need one correction run per fault; the source still admits nothing.
func TestBuildReportsEveryIndependentAdmissionFaultInOneRun(t *testing.T) {
	input := validSource()
	group := input["groups"].([]any)[0].(map[string]any)
	duplicate := map[string]any{}
	encoded, err := json.Marshal(sourceMember(input, 0))
	if err != nil {
		t.Fatal(err)
	}
	decodeTestJSON(t, encoded, &duplicate)
	duplicate["fields"].(map[string]any)["ownerId"] = ""
	group["members"] = append(group["members"].([]any), duplicate)
	input["scenarios"] = []any{map[string]any{
		"scenarioId": "SCN-PROOFKIT-SOURCE-001", "requirementIds": []any{"REQ-PROOFKIT-SOURCE-404"},
		"parameters": []any{}, "preconditions": []any{"A source is submitted."}, "actionSequence": []any{"Admit it."},
		"expectedObservations": []any{"It is rejected."}, "forbiddenObservation": []any{}, "examples": []any{},
		"vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}}
	delete(group, "sharedPremises")

	_, exitCode, err := Build(input)
	want := "unknown_field: /scenarios/0/<unknown>; missing_field: /groups/0/sharedPremises; missing_field: /scenarios/0/forbiddenObservations"
	if err == nil || err.Error() != want || exitCode != 1 {
		t.Fatalf("Build() error = %v exit=%d, want grammar faults %q before semantics", err, exitCode, want)
	}
	scenario := input["scenarios"].([]any)[0].(map[string]any)
	scenario["forbiddenObservations"] = scenario["forbiddenObservation"]
	delete(scenario, "forbiddenObservation")
	group["sharedPremises"] = []any{}
	_, exitCode, err = Build(input)
	want = "duplicate_requirement_id: /groups/0/members/1/requirementId; dangling_requirement_ref: /scenarios/0/requirementIds"
	if err == nil || err.Error() != want || exitCode != 1 {
		t.Fatalf("Build() error = %v exit=%d, want %q", err, exitCode, want)
	}
}

func decodeTestJSON(t *testing.T, encoded []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatal(err)
	}
}
