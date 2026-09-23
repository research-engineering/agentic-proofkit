package requirementsourcemodel

import (
	"reflect"
	"strings"
	"testing"
)

func TestScenarioResolutionPreservesTheCompleteQualifiedIdentity(t *testing.T) {
	alphaDraft, betaDraft := validDraft(), validDraft()
	alphaDraft.SourceID, betaDraft.SourceID = "source.alpha", "source.beta"
	betaDraft.Scenarios[0].ExpectedObservations = []string{"The request is rejected by the alternate source."}
	alpha, err := Normalize(alphaDraft)
	if err != nil {
		t.Fatal(err)
	}
	beta, err := Normalize(betaDraft)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []Model{alpha, beta} {
		atomic := source.Atomic()
		reference := ScenarioReference{SourceID: atomic.SourceID, RequirementID: "REQ-MODEL-001", ScenarioID: "SCN-MODEL-REQUEST"}
		resolved, err := ResolveScenario(source, reference)
		if err != nil || resolved.Reference != reference || resolved.Body == nil || !reflect.DeepEqual(*resolved.Body, atomic.Scenarios[0]) {
			t.Fatalf("qualified resolution lost its source/body: %v", err)
		}
		foreign := reference
		if reference.SourceID == "source.alpha" {
			foreign.SourceID = "source.beta"
		} else {
			foreign.SourceID = "source.alpha"
		}
		wrong, err := ResolveScenario(source, foreign)
		if ErrorCode(err) != "scenario_source_mismatch" || !reflect.DeepEqual(wrong, ScenarioResolution{}) {
			t.Fatalf("matching local IDs authorized a foreign body: %v", err)
		}
	}
}

func TestScenarioResolutionDistinguishesAbsentBodyFromWrongMembership(t *testing.T) {
	source, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	reference := ScenarioReference{SourceID: source.Atomic().SourceID, RequirementID: "REQ-MODEL-001", ScenarioID: "scenario.reference-only"}
	result, err := ResolveScenario(source, reference)
	if err != nil || result.Reference != reference || result.Body != nil {
		t.Fatalf("absent body was not an explicit reference-only result: %v", err)
	}
	for _, item := range []struct{ requirementID, scenarioID, code string }{
		{"REQ-MODEL-002", "SCN-MODEL-REQUEST", "scenario_requirement_mismatch"},
		{"REQ-UNKNOWN", "SCN-MODEL-REQUEST", "unknown_requirement"},
		{"REQ-UNKNOWN", "scenario.reference-only", "unknown_requirement"},
	} {
		reference.RequirementID, reference.ScenarioID = item.requirementID, item.scenarioID
		result, err := ResolveScenario(source, reference)
		if ErrorCode(err) != item.code || !reflect.DeepEqual(result, ScenarioResolution{}) {
			t.Fatalf("%s/%s: %v", item.requirementID, item.scenarioID, err)
		}
	}
}

func TestScenarioResolutionAllowsSharedMeaningAndReturnsDetachedBodies(t *testing.T) {
	draft := validDraft()
	draft.Scenarios[0].RequirementIDs = []string{"REQ-MODEL-002", "REQ-MODEL-001"}
	source, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	atomic, layout, references := source.Atomic(), source.Layout(), source.References()
	for _, requirementID := range []string{"REQ-MODEL-001", "REQ-MODEL-002"} {
		reference := ScenarioReference{SourceID: atomic.SourceID, RequirementID: requirementID, ScenarioID: "SCN-MODEL-REQUEST"}
		lookup := func() ScenarioResolution {
			result, err := ResolveScenario(source, reference)
			if err != nil || result.Reference != reference || result.Body == nil || !reflect.DeepEqual(*result.Body, atomic.Scenarios[0]) {
				t.Fatalf("shared scenario lookup: %v", err)
			}
			return result
		}
		assertAccessorReturnsDetachedState(t, requirementID, lookup)
		lookup()
	}
	if !reflect.DeepEqual(source.Atomic(), atomic) || !reflect.DeepEqual(source.Layout(), layout) || !reflect.DeepEqual(source.References(), references) {
		t.Fatal("derived lookup mutated the owner model")
	}
}

func TestScenarioResolutionAdmitsReferencesBeforeLookupWithoutDisclosure(t *testing.T) {
	source, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	valid := ScenarioReference{SourceID: source.Atomic().SourceID, RequirementID: "REQ-MODEL-001", ScenarioID: "SCN-MODEL-REQUEST"}
	for _, field := range []string{"SourceID", "RequirementID", "ScenarioID"} {
		for _, invalid := range []string{"", " invalid id ", "api_key=untrusted-coordinate-value"} {
			reference := valid
			reflect.ValueOf(&reference).Elem().FieldByName(field).SetString(invalid)
			result, err := ResolveScenario(source, reference)
			if ErrorCode(err) != "invalid_id" || !reflect.DeepEqual(result, ScenarioResolution{}) {
				t.Fatalf("invalid %s did not fail closed: %v", field, err)
			}
			if strings.Contains(err.Error(), "untrusted-coordinate-value") {
				t.Fatal("lookup error disclosed rejected reference text")
			}
		}
	}
	result, err := ResolveScenario(Model{}, valid)
	if ErrorCode(err) != "scenario_source_mismatch" || !reflect.DeepEqual(result, ScenarioResolution{}) {
		t.Fatalf("zero model authorized a lookup: %v", err)
	}
}
