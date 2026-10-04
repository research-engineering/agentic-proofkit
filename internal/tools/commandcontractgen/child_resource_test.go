package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestChildBindingsResolveOnlyUniqueMaterializedLocalResources(t *testing.T) {
	child := map[string]any{"$id": "urn:test:child", "type": "object", "additionalProperties": false}
	for _, union := range []string{"", "anyOf", "oneOf"} {
		ref := map[string]any{"$ref": "urn:test:child"}
		var value any = ref
		if union != "" {
			value = map[string]any{union: []any{map[string]any{"type": "null"}, ref}}
		}
		root := map[string]any{"$defs": map[string]any{"child": child}, "properties": map[string]any{"value": value}}
		before, err := json.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := schemaChildAtPath(root, []any{"value"})
		if err != nil || !equalBoundChildSchema(leaf, child) {
			t.Fatalf("union=%q did not preserve the exact child: %v", union, err)
		}
		after, err := json.Marshal(root)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("resolving an alias mutated the public schema")
		}
	}
	for _, test := range []struct {
		name string
		refs map[string]any
		leaf map[string]any
	}{
		{"missing", nil, map[string]any{"$ref": "urn:test:child"}},
		{"external", map[string]any{"child": child}, map[string]any{"$ref": "https://example.invalid/schema"}},
		{"duplicate", map[string]any{"a": child, "b": child}, map[string]any{"$ref": "urn:test:child"}},
		{"sibling", map[string]any{"child": child}, map[string]any{"$ref": "urn:test:child", "type": "array"}},
		{"alias-chain", map[string]any{"child": map[string]any{"$id": "urn:test:child", "$ref": "urn:test:child"}}, map[string]any{"$ref": "urn:test:child"}},
		{"non-text", map[string]any{"child": child}, map[string]any{"$ref": 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := map[string]any{"$defs": test.refs, "properties": map[string]any{"value": test.leaf}}
			if _, err := schemaChildAtPath(root, []any{"value"}); err == nil {
				t.Fatal("unsupported child alias was admitted")
			}
		})
	}
}
