package nativeevidenceguidance

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func decodedGuidance(t *testing.T) map[string]any {
	t.Helper()
	guidance, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := stablejson.Marshal(guidance.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func cloneGuidanceValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[key] = cloneGuidanceValue(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = cloneGuidanceValue(child)
		}
		return result
	default:
		return typed
	}
}

func TestOutputStructureAdmitsExactlyTheNativeGuidance(t *testing.T) {
	shape, err := OutputShape()
	if err != nil {
		t.Fatal(err)
	}
	guidance, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := shape.CheckGenerated(guidance.JSONValue(), "guidance"); err != nil {
		t.Fatal(err)
	}
	original := decodedGuidance(t)
	if _, err := shape.Admit(original, "guidance"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(original)), []string{"guidanceId", "nonClaims", "schemaVersion", "slots"}) {
		t.Fatal("native guidance root inventory changed")
	}
	reject := func(label string, mutate func(map[string]any)) {
		t.Helper()
		value := cloneGuidanceValue(original).(map[string]any)
		mutate(value)
		if _, err := shape.Admit(value, "guidance"); err == nil {
			t.Fatalf("structure accepted %s", label)
		}
	}
	for _, key := range []string{"guidanceId", "nonClaims", "schemaVersion", "slots"} {
		reject("missing "+key, func(value map[string]any) { delete(value, key) })
		reject("null "+key, func(value map[string]any) { value[key] = nil })
	}
	reject("foreign root", func(value map[string]any) { value["foreign"] = true })
	reject("schema version", func(value map[string]any) { value["schemaVersion"] = json.Number("2") })
	reject("schema version spelling", func(value map[string]any) { value["schemaVersion"] = json.Number("1.0") })
	reject("guidance identity", func(value map[string]any) { value["guidanceId"] = GuidanceID + ".foreign" })
	reject("non-claim text", func(value map[string]any) { value["nonClaims"].([]any)[0] = "foreign" })
	reject("extra non-claim", func(value map[string]any) { value["nonClaims"] = append(value["nonClaims"].([]any), "foreign") })
	reject("missing slot", func(value map[string]any) { value["slots"] = value["slots"].([]any)[1:] })
	reject("extra slot", func(value map[string]any) {
		slots := value["slots"].([]any)
		value["slots"] = append(slots, cloneGuidanceValue(slots[0]))
	})
	reject("reordered slots", func(value map[string]any) {
		slots := value["slots"].([]any)
		slots[0], slots[1] = slots[1], slots[0]
	})
	for index := range SlotCount {
		for _, key := range []string{"applicabilityClass", "completionCriterion", "order", "question", "requiredConsumerDecision", "slotId"} {
			reject("missing slot field", func(value map[string]any) { delete(value["slots"].([]any)[index].(map[string]any), key) })
			reject("changed slot field", func(value map[string]any) {
				slot := value["slots"].([]any)[index].(map[string]any)
				if key == "order" {
					slot[key] = json.Number("99")
					return
				}
				slot[key] = slot[key].(string) + " "
			})
		}
		reject("foreign slot field", func(value map[string]any) { value["slots"].([]any)[index].(map[string]any)["foreign"] = true })
	}
	reject("neighbor applicability class", func(value map[string]any) {
		value["slots"].([]any)[0].(map[string]any)["applicabilityClass"] = ApplicabilityExternalProcess
	})
}

func TestOutputStructureIsDetachedAndJSONModeOnly(t *testing.T) {
	first, err := OutputStructure()
	if err != nil {
		t.Fatal(err)
	}
	first["properties"].(map[string]any)["guidanceId"] = map[string]any{"type": "string"}
	second, err := OutputStructure()
	if err != nil {
		t.Fatal(err)
	}
	if second["properties"].(map[string]any)["guidanceId"].(map[string]any)["const"] != GuidanceID {
		t.Fatal("output structure shares mutable projection state")
	}
	shape, err := OutputShape()
	if err != nil {
		t.Fatal(err)
	}
	projected := shape.JSONSchema()
	description, ok := second["description"].(string)
	if !ok || description == "" {
		t.Fatal("output structure lost its native-owner boundary description")
	}
	delete(second, "description")
	if !jsonshapeEqual(projected, second) {
		t.Fatal("output structure differs from its native shape projection")
	}
	text, err := RenderPlainText()
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if json.Unmarshal([]byte(text), &decoded) == nil {
		t.Fatal("text presentation unexpectedly parses as JSON")
	}
}

func jsonshapeEqual(left, right map[string]any) bool {
	leftBytes, leftErr := stablejson.Marshal(left)
	rightBytes, rightErr := stablejson.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
