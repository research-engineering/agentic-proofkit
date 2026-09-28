package compactproofcontract

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCompactInputStructureIsDetachedAndPreservesNativeAdmission(t *testing.T) {
	first := InputStructure()
	second := InputStructure()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("structure projection is nondeterministic")
	}
	first["required"].([]any)[0] = "foreign"
	first["$defs"].(map[string]any)["column-surface_id"].(map[string]any)["pattern"] = "^foreign$"
	first["properties"].(map[string]any)["schema_version"].(map[string]any)["const"] = json.Number("3")
	if !reflect.DeepEqual(second, InputStructure()) {
		t.Fatal("caller mutated another projection or the structure owner")
	}
	if _, err := Admit(validCompactContract()); err != nil {
		t.Fatalf("projection mutation changed native admission: %v", err)
	}
}
