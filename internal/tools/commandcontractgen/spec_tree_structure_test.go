package main

import (
	"reflect"
	"slices"
	"testing"
)

func TestSpecTreeOutputStructuresRejectRehashedNestedDrift(t *testing.T) {
	for _, row := range []struct{ command, id, version string }{
		{"requirement-spec-tree", "proofkit.requirement-spec-tree.output.v1.json-schema", "1"},
		{"requirement-spec-tree-view", "proofkit.requirement-spec-tree-view.output.v2.json-schema", "2"},
	} {
		owner, ok := nativeStructureOwner(row.id)
		if !ok || owner.direction != "output" || !slices.Equal(owner.commands, []string{row.command}) {
			t.Fatal("incorrect output owner")
		}
		for _, mutation := range []string{"none", "required", "type", "bounds", "unknown"} {
			t.Run(row.command+"/"+mutation, func(t *testing.T) {
				definition, err := owner.definition()
				if err != nil {
					t.Fatal(err)
				}
				version, err := owner.contractVersion(definition)
				if err != nil || version.String() != row.version {
					t.Fatal("incorrect output schema identity")
				}
				pristine, err := owner.definition()
				if err != nil {
					t.Fatal(err)
				}
				schema := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
				properties := schema["properties"].(map[string]any)
				if row.command == "requirement-spec-tree" {
					properties = properties["summary"].(map[string]any)["properties"].(map[string]any)
				}
				counter := properties["nodeCount"].(map[string]any)
				switch mutation {
				case "required":
					schema["required"] = []any{}
				case "type":
					counter["type"] = "string"
				case "bounds":
					delete(counter, "minimum")
				case "unknown":
					schema["additionalProperties"] = true
				}
				fresh, err := owner.definition()
				if err != nil || !reflect.DeepEqual(fresh, pristine) {
					t.Fatal("caller mutation changed native owner")
				}
				delete(definition, "canonicalDigest")
				encoded, err := canonicalJSON(definition)
				if err != nil {
					t.Fatal(err)
				}
				definition["canonicalDigest"] = sha256Digest(encoded)
				if (admitNativeStructureDefinition(row.id, definition) == nil) != (mutation == "none") {
					t.Fatal("rehashed structural drift was incorrectly admitted")
				}
			})
		}
	}
}
