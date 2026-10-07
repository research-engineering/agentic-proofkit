package requirementspectree

import (
	"reflect"
	"testing"
)

func TestSpecTreeOutputStructuresAreDetached(t *testing.T) {
	for _, build := range []func() map[string]any{OutputStructure, ViewOutputStructure} {
		first, expected := build(), build()
		first["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = 999
		first["required"] = []any{}
		if !reflect.DeepEqual(expected, build()) {
			t.Fatal("caller mutation changed the owner output structure")
		}
	}
}
