package impact

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestImpactStructuresAreDetached(t *testing.T) {
	for _, build := range []func() map[string]any{InputStructure, OutputStructure} {
		first := build()
		before, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		first["properties"].(map[string]any)["baseRef"].(map[string]any)["type"] = "number"
		after, err := json.Marshal(build())
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("caller mutation changed the structure owner")
		}
	}
}
