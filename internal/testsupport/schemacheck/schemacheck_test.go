package schemacheck

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestValidateImplementsTheDeclaredKeywordSubset(t *testing.T) {
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"required": []any{"id", "items"},
		"properties": map[string]any{
			"id":    jsonshape.NonBlankString().JSONSchema(),
			"items": map[string]any{"type": "array", "prefixItems": []any{map[string]any{"$ref": "#/$defs/count"}}, "items": false, "minItems": 1, "uniqueItems": true},
			"kind":  map[string]any{"oneOf": []any{map[string]any{"const": "a"}, map[string]any{"enum": []any{"b", "c"}}}},
			"open":  map[string]any{"type": "object", "additionalProperties": true, "not": map[string]any{"required": []any{"forbidden"}}},
		},
		"$defs": map[string]any{"count": map[string]any{"type": "integer", "minimum": json.Number("0"), "maximum": 3}},
	}
	for _, accepted := range []any{
		map[string]any{"id": " x ", "items": []any{json.Number("3")}},
		map[string]any{"id": "x", "items": []any{3.0}, "kind": "c", "open": map[string]any{"extra": nil}},
	} {
		if err := Validate(schema, accepted); err != nil {
			t.Fatalf("accepted value refused: %v", err)
		}
	}
	for name, refused := range map[string]any{
		"blank":    map[string]any{"id": "\u3000", "items": []any{1}},
		"extra":    map[string]any{"id": "x", "items": []any{1}, "foreign": true},
		"missing":  map[string]any{"id": "x"},
		"range":    map[string]any{"id": "x", "items": []any{4}},
		"fraction": map[string]any{"id": "x", "items": []any{json.Number("1.5")}},
		"tuple":    map[string]any{"id": "x", "items": []any{1, 1}},
		"empty":    map[string]any{"id": "x", "items": []any{}},
		"sum":      map[string]any{"id": "x", "items": []any{1}, "kind": "d"},
		"not":      map[string]any{"id": "x", "items": []any{1}, "open": map[string]any{"forbidden": 1}},
		"type":     map[string]any{"id": 1, "items": []any{1}},
	} {
		if err := Validate(schema, refused); err == nil {
			t.Fatalf("%s: refused value accepted", name)
		}
	}
}

// An unsupported subschema below a combinator is reported as unsupported, not
// counted as a mismatch that not or oneOf could turn into acceptance.
func TestValidateFailsClosedOnUnimplementedKeywords(t *testing.T) {
	unsupported := map[string]any{"if": map[string]any{}}
	for name, test := range map[string]struct {
		schema map[string]any
		value  any
	}{
		"keyword":           {map[string]any{"if": map[string]any{}}, "a"},
		"reference":         {map[string]any{"$ref": "#/properties/x"}, "a"},
		"lookahead":         {map[string]any{"pattern": "^(?=a)a"}, "a"},
		"type-union":        {map[string]any{"type": []any{"string", "null"}}, "a"},
		"schema node":       {map[string]any{"not": "string"}, "a"},
		"not":               {map[string]any{"not": unsupported}, "x"},
		"oneOf":             {map[string]any{"oneOf": []any{true, unsupported}}, "x"},
		"anyOf":             {map[string]any{"anyOf": []any{true, unsupported}}, "x"},
		"allOf":             {map[string]any{"allOf": []any{unsupported}}, "x"},
		"contains":          {map[string]any{"contains": unsupported}, []any{"x"}},
		"not reference":     {map[string]any{"not": map[string]any{"$ref": "#/properties/x"}}, "x"},
		"not type-union":    {map[string]any{"not": map[string]any{"type": []any{"string", "null"}}}, "x"},
		"oneOf lookahead":   {map[string]any{"oneOf": []any{true, map[string]any{"pattern": "^(?=a)a"}}}, "x"},
		"nested combinator": {map[string]any{"not": map[string]any{"anyOf": []any{map[string]any{"properties": map[string]any{"a": unsupported}}}}}, map[string]any{"a": "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			err := Validate(test.schema, test.value)
			if err == nil || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("unsupported schema was not reported as unsupported: %v", err)
			}
		})
	}
}
