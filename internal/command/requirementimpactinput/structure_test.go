package requirementimpactinput

import (
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
)

func TestComposedOutputRetainsConsumerStructureAndRefinesNonClaims(t *testing.T) {
	consumer, output := impact.InputStructure(), OutputStructure()
	if !reflect.DeepEqual(output["properties"], consumer["properties"]) || output["additionalProperties"] != false {
		t.Fatal("producer changed a consumer-owned property domain")
	}
	if !slices.Contains(output["required"].([]any), any("nonClaims")) || slices.Contains(consumer["required"].([]any), any("nonClaims")) {
		t.Fatal("producer nonClaims presence was not separately refined")
	}
	want := []any{map[string]any{"properties": map[string]any{"nonClaims": map[string]any{"type": "array", "minItems": 1}}}}
	if !reflect.DeepEqual(output["allOf"], want) {
		t.Fatal("producer lost its nonnull nonempty nonClaims refinement")
	}
	input, err := InputStructure()
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(input["required"].([]any), any("headCommit")) {
		t.Fatal("optional composer headCommit became required")
	}
}
