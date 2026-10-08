package stackpreset

import (
	"bytes"
	"maps"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestPlanningHintShapeMatchesNativePresetProjections(t *testing.T) {
	shape := PlanningHintShape()
	for _, id := range IDs() {
		t.Run(id, func(t *testing.T) {
			hint, ok := PlanningHintFor(id)
			if !ok {
				t.Fatal("missing native planning hint")
			}
			encoded, err := stablejson.Marshal(hint.JSONValue())
			if err != nil {
				t.Fatal(err)
			}
			value, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := shape.Admit(value, "hint"); err != nil {
				t.Fatal(err)
			}
			if _, err := AdmitPlanningHint(value); err != nil {
				t.Fatal(err)
			}
			original := value.(map[string]any)
			for _, field := range []string{"presetId", "primaryLanguages", "starterEnvironmentClasses", "starterWitnessKinds"} {
				for _, neighbor := range []string{"absent", "null", "foreign", "padded", "short", "long", "reordered"} {
					changed := maps.Clone(original)
					switch neighbor {
					case "absent":
						delete(changed, field)
					case "null":
						changed[field] = nil
					default:
						if field == "presetId" {
							if neighbor != "foreign" && neighbor != "padded" {
								continue
							}
							changed[field] = "foreign"
							if neighbor == "padded" {
								changed[field] = id + " "
							}
						} else {
							items := append([]any(nil), original[field].([]any)...)
							switch neighbor {
							case "foreign":
								items[0] = "foreign"
							case "padded":
								items[0] = items[0].(string) + " "
							case "short":
								items = items[:len(items)-1]
							case "long":
								items = append(items, "foreign")
							case "reordered":
								if len(items) < 2 {
									continue
								}
								items[0], items[1] = items[1], items[0]
							}
							changed[field] = items
						}
					}
					if _, err := shape.Admit(changed, "hint"); err == nil {
						t.Fatalf("shape accepted %s/%s", field, neighbor)
					}
					if _, err := AdmitPlanningHint(changed); err == nil {
						t.Fatalf("native owner accepted %s/%s", field, neighbor)
					}
				}
			}
			extra := maps.Clone(original)
			extra["unexpected"] = true
			if _, err := shape.Admit(extra, "hint"); err == nil {
				t.Fatal("shape accepted an extra member")
			}
			if _, err := AdmitPlanningHint(extra); err == nil {
				t.Fatal("native owner accepted an extra member")
			}
		})
	}
	schema := shape.JSONSchema()
	schema["oneOf"].([]any)[0].(map[string]any)["properties"].(map[string]any)["presetId"] = nil
	first, _ := PlanningHintFor(IDs()[0])
	if err := PlanningHintShape().CheckGenerated(first.JSONValue(), "fresh hint"); err != nil {
		t.Fatalf("schema projection leaked mutable state: %v", err)
	}
}
