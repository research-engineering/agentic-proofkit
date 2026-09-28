package requirementcontext

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
)

func TestSliceNumericStructureMatchesNativeLimits(t *testing.T) {
	context, err := Compose(fixtureRepository(t), fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct {
		name             string
		minimum, maximum int
	}{
		{"maxNodes", 1, 4096},
		{"maxRequirements", 1, 16384},
		{"maxDepth", 0, 512},
	} {
		t.Run(field.name, func(t *testing.T) {
			shape, ok := sliceQueryShape.Property(field.name)
			if !ok {
				t.Fatal("missing numeric field")
			}
			for _, token := range []string{strconv.Itoa(field.minimum - 1), strconv.Itoa(field.minimum), strconv.Itoa(field.maximum), strconv.Itoa(field.maximum + 1), "-0", "1.0", "1e0", "9223372036854775808"} {
				t.Run(token, func(t *testing.T) {
					raw := json.Number(token)
					query := map[string]any{"profile": "specification", "nodeIds": []any{"spec.root"}, field.name: raw}
					value, parseErr := strconv.ParseInt(token, 10, 64)
					want := parseErr == nil && value >= int64(field.minimum) && value <= int64(field.maximum)
					_, nativeErr := admitSliceQuery(query)
					shaped, shapeErr := shape.Admit(raw, "limit")
					output, operationErr := Slice(map[string]any{"schemaVersion": json.Number("2"), "sliceId": "slice.numeric", "context": context, "query": query})
					if (nativeErr == nil) != want || (shapeErr == nil) != want || (operationErr == nil) != want {
						t.Fatalf("expected admission %v, native=%v shape=%v operation=%v", want, nativeErr, shapeErr, operationErr)
					}
					if want && shaped != raw {
						t.Fatal("shape changed the numeric token")
					}
					if want && output["sliceId"] != "slice.numeric" {
						t.Fatal("valid numeric query did not complete the slice")
					}
				})
			}
		})
	}
}

func TestSliceNativeLimitDiagnosticsAndPrecedence(t *testing.T) {
	context, err := Compose(fixtureRepository(t), fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		query map[string]any
		want  string
	}{
		{"nodes", map[string]any{"maxNodes": json.Number("4097")}, "requirement context slice maxNodes must be between 1 and 4096"},
		{"requirements", map[string]any{"maxRequirements": json.Number("16385")}, "requirement context slice maxRequirements must be between 1 and 16384"},
		{"depth", map[string]any{"nodeIds": []any{"spec.root"}, "maxDepth": json.Number("513")}, "requirement context slice maxDepth must be between 0 and 512"},
		{"nodes-before-requirements", map[string]any{"maxNodes": json.Number("4097"), "maxRequirements": json.Number("16385")}, "requirement context slice maxNodes must be between 1 and 4096"},
		{"requirements-before-depth", map[string]any{"maxRequirements": json.Number("16385"), "maxDepth": json.Number("513"), "nodeIds": []any{"spec.root"}}, "requirement context slice maxRequirements must be between 1 and 16384"},
		{"depth-selector-before-bound", map[string]any{"maxDepth": json.Number("513")}, "requirement context slice maxDepth requires nodeIds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.query["profile"] = "routing"
			_, directErr := admitSliceQuery(test.query)
			_, operationErr := Slice(map[string]any{"schemaVersion": json.Number("2"), "sliceId": "slice.numeric", "context": context, "query": test.query})
			for _, err := range []error{directErr, operationErr} {
				if err == nil || err.Error() != test.want {
					t.Fatalf("numeric diagnostic = %v, want %q", err, test.want)
				}
			}
		})
	}
}

func TestSliceLimitSchemaDefaultsAndBounds(t *testing.T) {
	properties := SliceInputStructure()["properties"].(map[string]any)["query"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []struct{ name, minimum, maximum, fallback string }{
		{"maxNodes", "1", "4096", "256"},
		{"maxRequirements", "1", "16384", "2048"},
		{"maxDepth", "0", "512", ""},
	} {
		schema := properties[field.name].(map[string]any)
		numeric := schema["anyOf"].([]any)[1].(map[string]any)
		if numeric["type"] != "integer" || numeric["minimum"] != json.Number(field.minimum) || numeric["maximum"] != json.Number(field.maximum) {
			t.Fatalf("incomplete numeric schema for %s", field.name)
		}
		if field.fallback == "" {
			if _, exists := schema["default"]; exists {
				t.Fatal("absent maxDepth must not acquire a numeric default")
			}
		} else if schema["default"] != json.Number(field.fallback) {
			t.Fatalf("wrong default annotation for %s", field.name)
		}
	}
	for _, query := range []map[string]any{
		{"profile": "routing"},
		{"profile": "routing", "maxNodes": nil, "maxRequirements": nil, "maxDepth": nil},
	} {
		shaped, err := sliceQueryShape.Admit(query, "query")
		if err != nil || !reflect.DeepEqual(shaped, query) {
			t.Fatalf("default annotation altered null or absence: %v", err)
		}
		result, err := admitSliceQuery(query)
		if err != nil || result.MaxNodes != 256 || result.MaxRequirements != 2048 || result.MaxDepth != nil {
			t.Fatalf("native defaults drifted: %+v, %v", result, err)
		}
	}
}

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
