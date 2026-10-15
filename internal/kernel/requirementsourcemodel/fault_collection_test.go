package requirementsourcemodel

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func collectedFaults(t *testing.T, err error) ([]ValidationError, int) {
	t.Helper()
	var many *ValidationErrors
	if errors.As(err, &many) {
		result := make([]ValidationError, len(many.Errors))
		for index, item := range many.Errors {
			result[index] = *item
		}
		return result, many.Omitted
	}
	var one *ValidationError
	if errors.As(err, &one) {
		return []ValidationError{*one}, 0
	}
	t.Fatalf("error %v is not a validation error", err)
	return nil, 0
}

func TestNormalizeReportsIndependentEntityFaultsTogetherInSourceOrder(t *testing.T) {
	draft := validDraft()
	draft.Groups[1].Members[0].Fields.OwnerID = Own("")
	draft.Groups[2].Members[0].RequirementID = "REQ-MODEL-001"
	draft.Scenarios[0].RequirementIDs = []string{"REQ-MODEL-404"}
	draft.Derivations[0].SourceKind = "guess"
	_, err := Normalize(draft)
	got, omitted := collectedFaults(t, err)
	want := []ValidationError{
		{Code: "invalid_id", Path: "groups[1].members[0].fields.ownerId"},
		{Code: "duplicate_requirement_id", Path: "groups[2].members[0].requirementId"},
		{Code: "dangling_requirement_ref", Path: "scenarios[0].requirementIds"},
		{Code: "invalid_source_kind", Path: "derivations[0].sourceKind"},
	}
	if !reflect.DeepEqual(got, want) || omitted != 0 {
		t.Fatalf("faults = %+v omitted=%d, want %+v", got, omitted, want)
	}
	if ErrorCode(err) != "invalid_id" {
		t.Fatalf("ErrorCode() = %q, want first fault code", ErrorCode(err))
	}
	assessment, assessErr := Assess(draft)
	if assessErr == nil || assessErr.Error() != err.Error() {
		t.Fatalf("Assess error = %v, want the same structural faults", assessErr)
	}
	if _, admitted := assessment.Model(); admitted {
		t.Fatal("a faulty snapshot admitted a model")
	}
	if _, admitted := assessment.Summary(); admitted {
		t.Fatal("a faulty snapshot admitted a summary")
	}
}

func TestNormalizeKeepsSingleFaultIdentityAndText(t *testing.T) {
	draft := validDraft()
	draft.Groups[1].Members[0].Fields.OwnerID = Own("")
	_, err := Normalize(draft)
	var one *ValidationError
	if !errors.As(err, &one) || err != error(one) {
		t.Fatalf("single fault error = %T, want *ValidationError", err)
	}
	if err.Error() != "invalid_id: groups[1].members[0].fields.ownerId" {
		t.Fatalf("single fault text = %q", err.Error())
	}
}

// A declared requirement with a faulty body still exists for references; its
// fault must not be repeated as dangling scenario or derivation references.
func TestNormalizeDoesNotInventDependentFaultsFromDeclaredIdentities(t *testing.T) {
	draft := validDraft()
	draft.Groups[0].Members[0].StatementCompletion = ""
	draft.Groups[0].GroupID = "not-a-group"
	draft.Vocabulary[0].Label = ""
	_, err := Normalize(draft)
	got, _ := collectedFaults(t, err)
	want := []ValidationError{
		{Code: "invalid_text", Path: "vocabulary[0].label"},
		{Code: "invalid_id", Path: "groups[0].groupId"},
		{Code: "invalid_text", Path: "groups[0].members[0].statementCompletion"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("faults = %+v, want only independent faults %+v", got, want)
	}
}

func TestNormalizeStopsBeforeGroupsWhenProfileMetadataIsUnadmitted(t *testing.T) {
	draft := validDraft()
	draft.Profiles[0].Fields.RiskClass = Own(RiskClass("severe"))
	draft.SourceID = ""
	_, err := Normalize(draft)
	got, _ := collectedFaults(t, err)
	want := []ValidationError{
		{Code: "invalid_id", Path: "sourceId"},
		{Code: "invalid_risk_class", Path: "profiles[0].fields.riskClass"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("faults = %+v, want no group fault inferred from an unadmitted profile %+v", got, want)
	}
}

func TestDuplicateIdentityFaultsLocateTheRepeatedEntry(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Draft)
		want   ValidationError
	}{
		{"requirement", func(draft *Draft) { draft.Groups[2].Members[0].RequirementID = "REQ-MODEL-002" }, ValidationError{"duplicate_requirement_id", "groups[2].members[0].requirementId"}},
		{"group", func(draft *Draft) { draft.Groups[2].GroupID = draft.Groups[1].GroupID }, ValidationError{"duplicate_id", "groups[2].groupId"}},
		{"definition", func(draft *Draft) { draft.NonClaimDefinitions[3].NonClaimID = "NCL-MODEL-001" }, ValidationError{"duplicate_id", "nonClaimDefinitions[3].nonClaimId"}},
		{"term", func(draft *Draft) {
			draft.Vocabulary = append(draft.Vocabulary, draft.Vocabulary[0])
		}, ValidationError{"duplicate_id", "vocabulary[1].termId"}},
		{"profile", func(draft *Draft) {
			draft.Profiles = append(draft.Profiles, draft.Profiles[0])
		}, ValidationError{"duplicate_id", "profiles[1].profileId"}},
		{"scenario", func(draft *Draft) {
			draft.Scenarios = append(draft.Scenarios, draft.Scenarios[0])
		}, ValidationError{"duplicate_id", "scenarios[1].scenarioId"}},
		{"derivation", func(draft *Draft) {
			draft.Derivations = append(draft.Derivations, draft.Derivations[0])
		}, ValidationError{"duplicate_id", "derivations[1].derivationId"}},
		{"example", func(draft *Draft) {
			draft.Scenarios[0].Examples[1].ExampleID = draft.Scenarios[0].Examples[0].ExampleID
		}, ValidationError{"duplicate_id", "scenarios[0].examples[1].exampleId"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := validDraft()
			test.mutate(&draft)
			_, err := Normalize(draft)
			got, _ := collectedFaults(t, err)
			if len(got) == 0 || got[0] != test.want {
				t.Fatalf("faults = %+v, want first %+v", got, test.want)
			}
		})
	}
}

func TestReportedFaultsAreBoundedAndOmissionsCounted(t *testing.T) {
	draft := validDraft()
	extra := MaxReportedValidationErrors + 3
	for index := 0; index < extra; index++ {
		scenario := draft.Scenarios[0]
		scenario.ScenarioID = fmt.Sprintf("SCN-MODEL-EXTRA-%02d", index)
		scenario.RequirementIDs = []string{fmt.Sprintf("REQ-MODEL-9%02d", index)}
		draft.Scenarios = append(draft.Scenarios, scenario)
	}
	_, err := Normalize(draft)
	got, omitted := collectedFaults(t, err)
	if len(got) != MaxReportedValidationErrors || omitted != extra-MaxReportedValidationErrors {
		t.Fatalf("described=%d omitted=%d, want %d and %d", len(got), omitted, MaxReportedValidationErrors, extra-MaxReportedValidationErrors)
	}
	for index, fault := range got {
		if want := (ValidationError{Code: "dangling_requirement_ref", Path: fmt.Sprintf("scenarios[%d].requirementIds", index+1)}); fault != want {
			t.Fatalf("fault %d = %+v, want %+v in source order", index, fault, want)
		}
	}
	if want := fmt.Sprintf("; %d more", extra-MaxReportedValidationErrors); err.Error()[len(err.Error())-len(want):] != want {
		t.Fatalf("error text %q does not end with the omitted count", err.Error())
	}
	_, again := Normalize(draft)
	if again.Error() != err.Error() {
		t.Fatal("fault order is not deterministic")
	}
}
