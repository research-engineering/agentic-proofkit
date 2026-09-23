package testevidenceinventory

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestDirectInventoryStructurePreservesOptionalDomainAndProjection(t *testing.T) {
	for _, variant := range []string{"complete", "absent", "null", "empty-oracle-text"} {
		t.Run(variant, func(t *testing.T) {
			record := validInventory(t).(map[string]any)
			entry := record["entries"].([]any)[0].(map[string]any)
			switch variant {
			case "absent", "null":
				for _, key := range []string{"falsifier", "oracle", "qualityFindings"} {
					delete(entry, key)
					if variant == "null" {
						entry[key] = nil
					}
				}
				if variant == "null" {
					record["ownerId"], record["sourceId"] = nil, nil
				}
			case "empty-oracle-text":
				entry["oracle"].(map[string]any)["assertionSummary"] = ""
				entry["oracle"].(map[string]any)["expectedPublicOutcome"] = ""
			}
			value, err := DirectInputShape().Admit(record, "inventory")
			if err != nil {
				t.Fatal(err)
			}
			result, err := EvaluateDirect(value)
			if err != nil {
				t.Fatal(err)
			}
			projection := InventoryValue(result.Inventory)
			if _, err := DirectInputShape().Admit(projection, "projection"); err != nil {
				t.Fatal(err)
			}
			rebuilt, err := EvaluateDirect(projection)
			if err != nil {
				t.Fatal(err)
			}
			before, err := stablejson.Marshal(projection)
			if err != nil {
				t.Fatal(err)
			}
			after, err := stablejson.Marshal(InventoryValue(rebuilt.Inventory))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("inventory projection changed on rebuild")
			}
			value.(map[string]any)["entries"].([]any)[0].(map[string]any)["selector"] = "changed"
			if entry["selector"] == "changed" {
				t.Fatal("input aliases detached snapshot")
			}
		})
	}
}

func TestDirectInventoryOracleTextIsRequiredDespiteOptionalHelperName(t *testing.T) {
	for _, field := range []string{"assertionSummary", "expectedPublicOutcome"} {
		for _, variant := range []string{"missing", "null", "number"} {
			t.Run(field+"/"+variant, func(t *testing.T) {
				record := validInventory(t).(map[string]any)
				oracle := record["entries"].([]any)[0].(map[string]any)["oracle"].(map[string]any)
				switch variant {
				case "missing":
					delete(oracle, field)
				case "null":
					oracle[field] = nil
				case "number":
					oracle[field] = 1
				}
				if _, err := DirectInputShape().Admit(record, "inventory"); err == nil {
					t.Fatal("invalid oracle text accepted by shape")
				}
				if _, err := EvaluateDirect(record); err == nil {
					t.Fatal("invalid oracle text accepted by owner")
				}
			})
		}
	}
}
