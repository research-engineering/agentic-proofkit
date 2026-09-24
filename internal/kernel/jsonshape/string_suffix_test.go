package jsonshape

import "testing"

func TestStringSuffixUsesTheSameNativeAndSchemaBoundary(t *testing.T) {
	shape := StringSuffix("/requirements.v2.json")
	for _, item := range []struct {
		value any
		valid bool
	}{
		{"docs/specs/a/requirements.v2.json", true},
		{"docs/specs/a/requirements.v1.json", false},
		{"requirements.v2.json", false},
		{"docs/specs/a/requirements.v2.json\n", false},
		{42, false},
	} {
		_, err := shape.Admit(item.value, "requirements path")
		if (err == nil) != item.valid {
			t.Fatalf("%v: native error=%v, want valid=%t", item.value, err, item.valid)
		}
	}
	schema := shape.JSONSchema()
	if schema["type"] != "string" || schema["pattern"] != `/requirements\.v2\.json(?![\s\S])` {
		t.Fatalf("suffix schema does not match native predicate: %v", schema)
	}
}
