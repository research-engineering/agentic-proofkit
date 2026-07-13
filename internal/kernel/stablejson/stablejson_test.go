package stablejson

import (
	"encoding/json"
	"fmt"
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

func TestMarshalLayoutCompactPreservesSortedJSONValue(t *testing.T) {
	value := map[string]any{"z": "last", "a": []any{"first", true}}
	pretty, err := MarshalLayout(value, LayoutPretty)
	if err != nil {
		t.Fatalf("marshal pretty failed: %v", err)
	}
	compact, err := MarshalLayout(value, LayoutCompact)
	if err != nil {
		t.Fatalf("marshal compact failed: %v", err)
	}
	if got, want := string(compact), "{\"a\":[\"first\",true],\"z\":\"last\"}\n"; got != want {
		t.Fatalf("compact output = %q, want %q", got, want)
	}
	var prettyValue any
	var compactValue any
	if err := json.Unmarshal(pretty, &prettyValue); err != nil {
		t.Fatalf("decode pretty output: %v", err)
	}
	if err := json.Unmarshal(compact, &compactValue); err != nil {
		t.Fatalf("decode compact output: %v", err)
	}
	if fmt.Sprint(prettyValue) != fmt.Sprint(compactValue) {
		t.Fatalf("layout changed JSON value: pretty=%v compact=%v", prettyValue, compactValue)
	}
}

func TestMarshalLayoutRejectsUnknownLayout(t *testing.T) {
	if _, err := MarshalLayout(map[string]any{}, Layout("dense")); err == nil {
		t.Fatal("MarshalLayout accepted an unknown layout")
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
