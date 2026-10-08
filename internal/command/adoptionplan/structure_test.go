package adoptionplan

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestPlanStructurePreservesAllNativeIntentAndHintVariants(t *testing.T) {
	shape, err := OutputShape()
	if err != nil {
		t.Fatal(err)
	}
	inventory := adoptionInventory(t)
	for _, intent := range []string{"fresh", "code-baseline", "audit-from-code"} {
		for _, preset := range append([]string{""}, stackpreset.IDs()...) {
			t.Run(intent+"/"+preset, func(t *testing.T) {
				plan, err := Build(intent, inventory, preset)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := stablejson.Marshal(plan.JSONValue())
				if err != nil {
					t.Fatal(err)
				}
				wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := shape.Admit(wire, "plan"); err != nil {
					t.Fatal(err)
				}
				if _, err := AdmitOutput(wire); err != nil {
					t.Fatal(err)
				}
				value := wire.(map[string]any)
				for _, field := range []string{"observedCatalogFileCount", "omittedRecognizedCount", "unrecognizedRootEntryCount"} {
					for _, count := range []json.Number{"0", "1", "-1", "0.5"} {
						changed := maps.Clone(value)
						summary := maps.Clone(value["summary"].(map[string]any))
						summary[field] = count
						changed["summary"] = summary
						_, err := shape.Admit(changed, "plan")
						if (err == nil) != (count == "0" || count == "1") {
							t.Fatalf("summary count boundary %s=%s: %v", field, count, err)
						}
					}
				}
				for field := range value {
					missing := maps.Clone(value)
					delete(missing, field)
					if _, err := shape.Admit(missing, "plan"); err == nil {
						t.Fatalf("accepted missing %s", field)
					}
					if field != "stackHint" {
						null := maps.Clone(value)
						null[field] = nil
						if _, err := shape.Admit(null, "plan"); err == nil {
							t.Fatalf("accepted null %s", field)
						}
					}
				}
				for _, field := range []string{"authority", "intent", "planKind", "schemaVersion", "state"} {
					changed := maps.Clone(value)
					changed[field] = "foreign"
					if _, err := shape.Admit(changed, "plan"); err == nil {
						t.Fatalf("accepted a foreign %s", field)
					}
				}
				extra := maps.Clone(value)
				extra["unexpected"] = true
				if _, err := shape.Admit(extra, "plan"); err == nil {
					t.Fatal("accepted an extra root member")
				}
				packet := value["authoringPacket"].(map[string]any)
				tasks := packet["tasks"].([]any)
				wantCount := 4
				if intent == "fresh" {
					wantCount = 3
				}
				if len(tasks) != wantCount {
					t.Fatalf("task count=%d, want%d", len(tasks), wantCount)
				}
				for _, variant := range []string{"short", "long", "reordered", "foreign"} {
					changed := maps.Clone(value)
					changedPacket := maps.Clone(packet)
					changedTasks := append([]any(nil), tasks...)
					switch variant {
					case "short":
						changedTasks = changedTasks[:len(tasks)-1]
					case "long":
						changedTasks = append(changedTasks, tasks[0])
					case "reordered":
						changedTasks[0], changedTasks[1] = changedTasks[1], changedTasks[0]
					case "foreign":
						first := maps.Clone(tasks[0].(map[string]any))
						first["order"] = json.Number("0")
						changedTasks[0] = first
					}
					changedPacket["tasks"] = changedTasks
					changed["authoringPacket"] = changedPacket
					if _, err := shape.Admit(changed, "plan"); err == nil {
						t.Fatalf("accepted %s tasks", variant)
					}
				}
			})
		}
	}
	schema, err := OutputStructure()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := stablejson.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("complete plan schema bytes=%d", len(encoded))
}
