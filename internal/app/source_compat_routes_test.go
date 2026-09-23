package app

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/projectfixture"
)

func TestSourceCompatibilityQualifiedBindingRowsSurviveCLI(t *testing.T) {
	fixture := projectfixture.New(t)
	result, err := requirementbinding.Build(fixture.Project["proofBinding"])
	if err != nil || result.Record.State != "passed" {
		t.Fatal("binding fixture was not admitted", err)
	}
	input := result.Input
	for i := range input.Bindings {
		input.Bindings[i].ScenarioID = "scenario.shared"
		input.Bindings[i].WitnessID = "witness.shared"
	}
	originalSelectors := slices.Clone(input.Bindings[0].WitnessSelectors)
	otherScenario, otherWitness := input.Bindings[0], input.Bindings[0]
	otherScenario.ScenarioID = "scenario.other"
	otherScenario.WitnessSelectors = []requirementbinding.WitnessSelector{{Command: "go test ./tests -run TestScenarioVariant", Selector: "TestScenarioVariant"}}
	otherWitness.WitnessID = "witness.other"
	otherWitness.WitnessSelectors = []requirementbinding.WitnessSelector{{Command: "go test ./tests -run TestWitnessVariant", Selector: "TestWitnessVariant"}}
	if !reflect.DeepEqual(input.Bindings[0].WitnessSelectors, originalSelectors) {
		t.Fatal("fixture variants mutated the original selector payload")
	}
	input.Bindings = append(input.Bindings, otherScenario, otherWitness)
	slices.SortFunc(input.Bindings, func(a, b requirementbinding.Binding) int {
		for _, pair := range [][2]string{{a.RequirementID, b.RequirementID}, {a.ScenarioID, b.ScenarioID}, {a.WitnessID, b.WitnessID}} {
			if order := strings.Compare(pair[0], pair[1]); order != 0 {
				return order
			}
		}
		return 0
	})
	graphBytes := runCLI(t, []string{"evidence-graph", "--input", "-"}, string(sourceCompatJSON(t, requirementbinding.InputValue(input))))
	graph := sourceCompatDecode(t, graphBytes).(map[string]any)
	if graph["graphKind"] != "proofkit.requirement-evidence-graph" || graph["bindingId"] != "shared.identity" {
		t.Fatal("wrong graph identity")
	}
	actual := map[[3]string]map[string]any{}
	sourcePaths := map[string]string{}
	for _, raw := range graph["requirements"].([]any) {
		requirement := raw.(map[string]any)
		id := requirement["requirementId"].(string)
		sourcePaths[id] = requirement["specPath"].(string)
		for _, raw := range requirement["scenarios"].([]any) {
			row := raw.(map[string]any)
			key := [3]string{id, row["scenarioId"].(string), row["witnessId"].(string)}
			if _, duplicate := actual[key]; duplicate {
				t.Fatal("duplicate qualified graph tuple")
			}
			actual[key] = row
		}
	}
	if !reflect.DeepEqual(sourcePaths, map[string]string{"REQ-WIRE-001": "docs/specs/a/requirements.v2.json", "REQ-WIRE-002": "docs/specs/z/requirements.v2.json", "REQ-WIRE-003": "docs/specs/z/requirements.v2.json"}) {
		t.Fatal("source-qualified requirement paths changed")
	}
	if len(actual) != 5 {
		t.Fatalf("qualified rows=%d, want5", len(actual))
	}
	for _, expected := range input.Bindings {
		row := actual[[3]string{expected.RequirementID, expected.ScenarioID, expected.WitnessID}]
		selectors := []any{}
		for _, selector := range expected.WitnessSelectors {
			selectors = append(selectors, map[string]any{"command": selector.Command, "selector": selector.Selector})
		}
		want := map[string]any{"scenarioId": expected.ScenarioID, "witnessId": expected.WitnessID,
			"witnessPath": expected.WitnessPath, "witnessKind": expected.WitnessKind, "witnessSelectors": selectors,
			"commandIds": sourceCompatDecode(t, sourceCompatJSON(t, expected.CommandIDs)), "environmentClasses": sourceCompatDecode(t, sourceCompatJSON(t, expected.EnvironmentClasses))}
		if !reflect.DeepEqual(row, want) {
			t.Fatalf("lost qualified route operands for %s/%s/%s", expected.RequirementID, expected.ScenarioID, expected.WitnessID)
		}
	}
	input.Bindings = append(input.Bindings, input.Bindings[0])
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"evidence-graph", "--input", "-"}, bytes.NewReader(sourceCompatJSON(t, requirementbinding.InputValue(input))), &stdout, &stderr)
	if exit != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatal("complete duplicate binding tuple was not rejected")
	}
}

func TestSourceCompatibilityRejectsKnownButWrongSourcePath(t *testing.T) {
	fixture := projectfixture.New(t)
	project, err := adoptionmaterialization.AdmitProject(fixture.Project)
	if err != nil {
		t.Fatal("project premise failed", err)
	}
	for _, substitute := range []string{"docs/specs/z/requirements.v2.json", "docs/specs/missing/requirements.v2.json"} {
		value, err := project.JSONValue()
		if err != nil {
			t.Fatal(err)
		}
		rows := value["proofBinding"].(map[string]any)["requirements"].([]any)
		rows[0].(map[string]any)["specPath"] = substitute
		_, err = adoptionmaterialization.AdmitProject(value)
		if err == nil || !strings.Contains(err.Error(), "binding requirement projection does not match its source owner") {
			t.Fatalf("wrong source path did not fail the owner relation before digest comparison: %v", err)
		}
	}
	value, err := project.JSONValue()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adoptionmaterialization.AdmitProject(value); err != nil {
		t.Fatal("original project no longer re-admits", err)
	}
}
