package requirementcontext

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSliceQueryStructureDoesNotNarrowNullOrNegativeZero(t *testing.T) {
	for _, raw := range []any{
		map[string]any{"profile": "routing"},
		map[string]any{"profile": "routing", "nodeIds": nil, "maxNodes": nil, "maxRequirements": nil, "maxDepth": nil},
		map[string]any{"profile": "specification", "nodeIds": []any{"spec.root"}, "maxDepth": json.Number("-0")},
	} {
		before, err := admitSliceQuery(raw)
		if err != nil {
			t.Fatal(err)
		}
		shaped, err := sliceQueryShape.Admit(raw, "query")
		if err != nil {
			t.Fatal(err)
		}
		after, err := admitSliceQuery(shaped)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("query meaning drift: %v", err)
		}
	}
}

func TestSliceInputStructureRetainsEveryRootAndNestedSelectorType(t *testing.T) {
	context := snapshotStructureCases(t)["catalog"]
	for _, field := range []string{"schemaVersion", "sliceId", "context", "query"} {
		input := map[string]any{"schemaVersion": json.Number("2"), "sliceId": "slice.structure", "context": context, "query": map[string]any{"profile": "routing"}}
		delete(input, field)
		if _, err := sliceInputShape.Admit(input, "slice"); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
		if _, err := Slice(input); err == nil {
			t.Fatalf("native slice accepted missing %s", field)
		}
	}
	for _, key := range []string{"nodeIds", "ownerIds", "requirementIds", "lifecycleStates"} {
		query := map[string]any{"profile": "routing", key: []any{true}}
		if _, err := sliceQueryShape.Admit(query, "query"); err == nil {
			t.Fatal("wrong selector type accepted")
		}
		if _, err := admitSliceQuery(query); err == nil {
			t.Fatal("native query accepted wrong selector type")
		}
	}
}
