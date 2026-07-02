package stablejson

import (
	"encoding/json"
	"testing"
)

func TestMarshalSortsObjectKeys(t *testing.T) {
	output, err := Marshal(map[string]any{
		"z": "last",
		"a": []any{"first", true},
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	const expected = "{\n  \"a\": [\n    \"first\",\n    true\n  ],\n  \"z\": \"last\"\n}\n"
	if string(output) != expected {
		t.Fatalf("unexpected stable JSON:\n%s", output)
	}
}

func TestMarshalRejectsNonNumberJSONNumberTokens(t *testing.T) {
	for _, value := range []json.Number{
		"true",
		"null",
		"{}",
		"[]",
		`"1"`,
		"01",
		"+1",
		"1.",
		"NaN",
	} {
		t.Run(value.String(), func(t *testing.T) {
			if _, err := Marshal(map[string]any{"value": value}); err == nil {
				t.Fatalf("Marshal accepted invalid JSON number token %q", value.String())
			}
		})
	}
}

func TestMarshalAcceptsJSONNumberGrammar(t *testing.T) {
	for _, value := range []json.Number{"0", "-0", "12", "-12.5", "1e9", "1E-9"} {
		t.Run(value.String(), func(t *testing.T) {
			if _, err := Marshal(map[string]any{"value": value}); err != nil {
				t.Fatalf("Marshal rejected valid JSON number token %q: %v", value.String(), err)
			}
		})
	}
}
