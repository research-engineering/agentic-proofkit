package app

import (
	"reflect"
	"slices"
	"testing"

	codec "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestSourceQualifiedScenariosSurviveTheActualWire(t *testing.T) {
	for _, namespace := range []string{"alpha", "beta"} {
		draft := sourceCompatDraft(sourceCompatSource(2))
		draft.SourceID = "source." + namespace
		draft.SpecPackagePath = "docs/specs/" + namespace
		observation := "The " + namespace + " observer retains the result."
		draft.Scenarios = []model.Scenario{{
			ScenarioID: "scenario.shared", RequirementIDs: []string{"REQ-COMPAT-00000"}, Parameters: []string{"value"},
			Preconditions: []string{"The ${value} input is available."}, ActionSequence: []string{"Inspect ${value}."},
			ExpectedObservations: []string{observation},
			Examples: []model.Example{
				{ExampleID: "EX-SHARED-A", Values: map[string]model.ScenarioValue{"value": "primary"}},
				{ExampleID: "EX-SHARED-B", Values: map[string]model.ScenarioValue{"value": "secondary"}},
			},
		}, {
			ScenarioID: "scenario.alternate", RequirementIDs: []string{"REQ-COMPAT-00000"},
			Preconditions:        []string{"The alternate input is available."},
			ActionSequence:       []string{"Inspect the alternate input."},
			ExpectedObservations: []string{"The " + namespace + " observer reports an alternate result."},
		}}
		for _, reversed := range []bool{false, true} {
			if reversed {
				slices.Reverse(draft.Scenarios)
			}
			assertSourceQualifiedScenarioWire(t, draft, map[string]string{
				"scenario.shared":    observation,
				"scenario.alternate": "The " + namespace + " observer reports an alternate result.",
			})
		}
	}
}

func assertSourceQualifiedScenarioWire(t *testing.T, draft model.Draft, observations map[string]string) {
	t.Helper()
	admitted, err := model.Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := codec.Format(admitted)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := codec.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenarioID := range []string{"scenario.alternate", "scenario.shared"} {
		observation := observations[scenarioID]
		reference := model.ScenarioReference{SourceID: draft.SourceID, RequirementID: "REQ-COMPAT-00000", ScenarioID: scenarioID}
		before, err := model.ResolveScenario(admitted, reference)
		if err != nil {
			t.Fatal(err)
		}
		after, err := model.ResolveScenario(parsed.Model, reference)
		if err != nil || !reflect.DeepEqual(before, after) || after.Reference != reference || after.Body == nil ||
			!reflect.DeepEqual(after.Body.ExpectedObservations, []string{observation}) {
			t.Fatalf("wire lookup lost qualified scenario meaning: %v", err)
		}
		foreign := reference
		if draft.SourceID == "source.alpha" {
			foreign.SourceID = "source.beta"
		} else {
			foreign.SourceID = "source.alpha"
		}
		if result, err := model.ResolveScenario(parsed.Model, foreign); model.ErrorCode(err) != "scenario_source_mismatch" ||
			!reflect.DeepEqual(result, model.ScenarioResolution{}) {
			t.Fatalf("wire lookup admitted a known foreign source: %v", err)
		}
		reference.RequirementID = "REQ-COMPAT-00001"
		if result, err := model.ResolveScenario(parsed.Model, reference); model.ErrorCode(err) != "scenario_requirement_mismatch" ||
			!reflect.DeepEqual(result, model.ScenarioResolution{}) {
			t.Fatalf("wire lookup admitted a known nonmember requirement: %v", err)
		}
	}
	absent := model.ScenarioReference{SourceID: draft.SourceID, RequirementID: "REQ-COMPAT-00000", ScenarioID: "scenario.unwritten"}
	if result, err := model.ResolveScenario(parsed.Model, absent); err != nil || result.Reference != absent || result.Body != nil {
		t.Fatalf("wire lookup invented an absent body: %v", err)
	}
}
