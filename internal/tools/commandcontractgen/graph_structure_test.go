package main

import (
	"reflect"
	"slices"
	"testing"
)

func TestGraphOutputStructureRejectsRehashedNestedDrift(t *testing.T) {
	const id = "proofkit.requirement-traceability-graph.output.v1.json-schema"
	owner, ok := nativeStructureOwner(id)
	if !ok || owner.direction != "output" || !slices.Equal(owner.commands, []string{"requirement-traceability-graph"}) {
		t.Fatal("incorrect graph output owner")
	}
	for _, mutation := range []string{"none", "required", "planes", "bounds", "unknown"} {
		t.Run(mutation, func(t *testing.T) {
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			pristine, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			version, err := owner.contractVersion(definition)
			if err != nil || version.String() != "1" {
				t.Fatal("graph output identity changed")
			}
			schema := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
			properties := schema["properties"].(map[string]any)
			switch mutation {
			case "required":
				schema["required"] = []any{}
			case "planes":
				properties["nodes"].(map[string]any)["items"] = map[string]any{"type": "object"}
			case "bounds":
				delete(properties["edges"].(map[string]any), "maxItems")
			case "unknown":
				schema["additionalProperties"] = true
			}
			fresh, err := owner.definition()
			if err != nil || !reflect.DeepEqual(fresh, pristine) {
				t.Fatal("caller changed the native structure owner")
			}
			delete(definition, "canonicalDigest")
			encoded, err := canonicalJSON(definition)
			if err != nil {
				t.Fatal(err)
			}
			definition["canonicalDigest"] = sha256Digest(encoded)
			if (admitNativeStructureDefinition(id, definition) == nil) != (mutation == "none") {
				t.Fatal("rehashed graph structure drift admitted")
			}
		})
	}
}
