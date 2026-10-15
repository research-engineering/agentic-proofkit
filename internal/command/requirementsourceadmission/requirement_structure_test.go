package requirementsourceadmission

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestAtomicRequirementStructurePreservesPresenceAndOwnerProjection(t *testing.T) {
	result, err := Evaluate(validSource())
	if err != nil {
		t.Fatal(err)
	}
	requirement := result.Source.Requirements()[0]
	for _, deferred := range []bool{false, true} {
		if deferred {
			requirement.Deferral = &Deferral{OwnerID: "owner", RiskAcceptedBy: "owner", ReviewCondition: "Review before release.", ExpiryRef: "review.next", MergePolicy: "owner_review", EvidenceRefs: []string{"review.proof"}}
		}
		value := RequirementValue(requirement)
		if err := RequirementShape().CheckGenerated(value, "requirement"); err != nil {
			t.Fatal(err)
		}
		wire := outputWire(t, value)
		admitted, err := RequirementShape().Admit(wire, "requirement")
		if err != nil || !reflect.DeepEqual(admitted, wire) {
			t.Fatalf("atomic projection changed: %v", err)
		}
		if _, present := value["deferral"]; present != deferred {
			t.Fatal("absent deferral changed presence")
		}
		for key := range value {
			mutated := outputWire(t, value)
			delete(mutated, key)
			err := RequirementShape().CheckGenerated(mutated, "requirement")
			if (err == nil) != (key == "deferral") {
				t.Fatalf("unexpected requiredness for %s: %v", key, err)
			}
		}
		value["deferral"] = nil
		if err := RequirementShape().CheckGenerated(value, "requirement"); err == nil {
			t.Fatal("null substituted for absent or object deferral")
		}
	}
}

// The comparison union is exclusive, so [] must belong to exactly one array
// alternative: the string array. The examples alternative requires an item and
// keeps the codec's per-scenario bound.
func TestComparisonValueShapeArrayAlternativesAreDisjoint(t *testing.T) {
	shape := ComparisonValueShape()
	example := map[string]any{"exampleId": "EX-25KG", "values": map[string]any{"weight": "25 kg"}}
	for _, value := range []any{[]any{}, []any{"The service is available."}, []any{example}} {
		if err := shape.CheckGenerated(value, "comparison value"); err != nil {
			t.Fatalf("comparison value %#v: %v", value, err)
		}
	}
	arrays := map[string][2]any{}
	for _, raw := range shape.JSONSchema()["oneOf"].([]any) {
		alternative := raw.(map[string]any)
		if alternative["type"] != "array" {
			continue
		}
		element, _ := alternative["items"].(map[string]any)["type"].(string)
		arrays[element] = [2]any{alternative["minItems"], alternative["maxItems"]}
	}
	maximum := json.Number(fmt.Sprint(requirementsourcemodel.DefaultLimits().MaxExamplesPerScenario))
	want := map[string][2]any{"string": {nil, nil}, "object": {1, maximum}}
	if !reflect.DeepEqual(arrays, want) {
		t.Fatalf("array alternatives (minItems, maxItems) = %#v, want %#v", arrays, want)
	}
}
