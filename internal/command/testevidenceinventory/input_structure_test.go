package testevidenceinventory

import (
	"bytes"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func inventoryStructureWire(t *testing.T, value any) any {
	t.Helper()
	data, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.DecodeJSON(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func assertInventoryStructure(t *testing.T, shape jsonshape.Shape, value any) {
	t.Helper()
	if _, err := shape.Admit(inventoryStructureWire(t, value), "inventory structure"); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryInputStructuresPreserveNativeModesAndWireOutputs(t *testing.T) {
	for _, sourceSet := range []bool{false, true} {
		for _, wrapped := range []bool{false, true} {
			input := validInventory(t)
			if sourceSet {
				input = validSourceSetInventory(t)
				input.(map[string]any)["sourceColumns"].([]any)[0] = " \tsource_id\u2000"
			}
			if wrapped {
				input = map[string]any{"schema": wrappedInventorySchema, "inventory": input}
			}
			assertInventoryStructure(t, InventoryInputShape(), input)
			result, err := Evaluate(input)
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("sourceSet=%v wrapped=%v: exit=%d err=%v", sourceSet, wrapped, result.ExitCode, err)
			}
			assertInventoryStructure(t, ReportOutputShape(), result.Report.JSONValue())
			assertInventoryStructure(t, CanonicalInventoryShape(), InventoryValue(result.Inventory))
			if _, err := DirectBoundaryShape().Admit(input, "direct inventory"); (err == nil) == sourceSet {
				t.Fatalf("direct boundary/sourceSet=%v wrapped=%v: %v", sourceSet, wrapped, err)
			}
		}
	}
	input := validInventory(t).(map[string]any)
	input["entries"].([]any)[0].(map[string]any)["commandRefs"] = []any{}
	failed, code, err := BuildNormalized(input)
	if err != nil || code != 1 || failed["state"] != "failed" {
		t.Fatalf("failed normalization: code=%d err=%v", code, err)
	}
	assertInventoryStructure(t, ReportOutputShape(), failed)
}

func TestInventoryInputStructuresRejectClosedBoundaryDrift(t *testing.T) {
	for _, change := range []string{"wrapper-version", "nested-wrapper", "row-width", "row-digest", "row-role", "missing-text", "unknown-field"} {
		t.Run(change, func(t *testing.T) {
			source := validSourceSetInventory(t).(map[string]any)
			input := map[string]any{"schema": wrappedInventorySchema, "inventory": source}
			row := source["sources"].([]any)[0].([]any)
			switch change {
			case "wrapper-version":
				input["schemaVersion"] = 1
			case "nested-wrapper":
				input["inventory"] = map[string]any{"schema": wrappedInventorySchema, "inventory": source}
			case "row-width":
				source["sources"].([]any)[0] = row[:4]
			case "row-digest":
				row[2] = "not-a-digest"
			case "row-role":
				row[3] = "unknown"
			case "missing-text":
				delete(source["sourceTexts"].([]any)[0].(map[string]any), "text")
			case "unknown-field":
				source["unknown"] = true
			}
			if _, err := InventoryInputShape().Admit(input, "inventory"); err == nil {
				t.Fatal("invalid input shape was accepted")
			}
			if _, err := Evaluate(input); err == nil {
				t.Fatal("native owner accepted invalid input")
			}
		})
	}
}

func TestDiscoveryStructuresPreserveOptionalInputAndCandidateOutput(t *testing.T) {
	for _, variant := range []string{"complete", "absent", "null", "unasserted"} {
		t.Run(variant, func(t *testing.T) {
			input := validDiscoveryDraft()
			if variant == "absent" || variant == "null" {
				for _, record := range []map[string]any{input, input["repository"].(map[string]any), input["runner"].(map[string]any), firstDiscoveryTest(input)} {
					delete(record, "nonClaims")
					if variant == "null" {
						record["nonClaims"] = nil
					}
				}
			}
			if variant == "unasserted" {
				firstDiscoveryTest(input)["oracleSignals"] = []any{}
			}
			assertInventoryStructure(t, DiscoveryInputShape(), input)
			output, code, err := BuildDiscoveryDraft(input)
			if err != nil || code != 0 {
				t.Fatalf("discovery code=%d err=%v", code, err)
			}
			assertInventoryStructure(t, DiscoveryOutputShape(), output.JSONValue())
		})
	}
	for _, value := range []any{nil, true, []any{}} {
		input := validDiscoveryDraft()
		firstDiscoveryTest(input)["title"] = value
		if _, err := DiscoveryInputShape().Admit(input, "discovery"); err == nil {
			t.Fatal("invalid nested title was accepted")
		}
		if _, _, err := BuildDiscoveryDraft(input); err == nil {
			t.Fatal("native discovery accepted invalid title")
		}
	}
}
