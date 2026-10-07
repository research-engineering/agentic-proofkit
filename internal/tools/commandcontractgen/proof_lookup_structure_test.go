package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofsourceset"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

func TestProofLookupStructuresPreserveVersionsAndOwnerIsolation(t *testing.T) {
	for _, row := range []struct {
		id     string
		builds []func() map[string]any
		wires  []json.Number
	}{
		{"proofkit.requirement-proof-source-set.input.v2.json-schema", []func() map[string]any{requirementproofsourceset.InputStructure}, []json.Number{"2"}},
		{"proofkit.requirement-proof-source-set.output.v2.json-schema", []func() map[string]any{requirementproofsourceset.CanonicalOutputStructure, requirementproofsourceset.ResolverOutputStructure}, []json.Number{"2", "2"}},
		{"proofkit.requirement-proof-view.input.v2.json-schema", []func() map[string]any{requirementproofview.CompactInputStructure, requirementproofview.StructuredInputStructure}, []json.Number{"2", "1"}},
		{"proofkit.requirement-proof-view.output.v2.json-schema", []func() map[string]any{requirementproofview.CompactOutputStructure, requirementproofview.StructuredOutputStructure}, []json.Number{"2", "1"}},
	} {
		owner, exists := nativeStructureOwner(row.id)
		if !exists {
			t.Fatalf("missing owner %s", row.id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != "2" {
			t.Fatalf("%s semantic version drift: %s %v", row.id, version, err)
		}
		variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
		if len(variants) != len(row.builds) {
			t.Fatalf("%s alternatives drift", row.id)
		}
		for i, build := range row.builds {
			want := build()
			variant := variants[i].(map[string]any)
			field := "schemaVersion"
			if row.id == "proofkit.requirement-proof-view.input.v2.json-schema" && i == 0 {
				field = "schema_version"
			}
			wire, wireErr := nativeSchemaVersion(want, field)
			if !reflect.DeepEqual(variant["schema"], want) || wireErr != nil || wire != row.wires[i] {
				t.Fatalf("%s/%d native structure or wire drift", row.id, i)
			}
			want["properties"].(map[string]any)["foreign"] = true
			if reflect.DeepEqual(want, build()) {
				t.Fatalf("%s/%d returned shared mutable state", row.id, i)
			}
			for _, mutation := range []string{"open", "required", "version"} {
				changed, err := owner.definition()
				if err != nil {
					t.Fatal(err)
				}
				schema := changed["fieldTree"].(map[string]any)["variants"].([]any)[i].(map[string]any)["schema"].(map[string]any)
				switch mutation {
				case "open":
					schema["additionalProperties"] = true
				case "required":
					schema["required"] = []any{}
				case "version":
					field := "schemaVersion"
					if row.id == "proofkit.requirement-proof-view.input.v2.json-schema" && i == 0 {
						field = "schema_version"
					}
					schema["properties"].(map[string]any)[field].(map[string]any)["const"] = json.Number("99")
				}
				delete(changed, "canonicalDigest")
				bytes, err := canonicalJSON(changed)
				if err != nil {
					t.Fatal(err)
				}
				changed["canonicalDigest"] = sha256Digest(bytes)
				if admitNativeStructureDefinition(row.id, changed) == nil {
					t.Fatalf("%s/%d accepted rehashed %s", row.id, i, mutation)
				}
			}
		}
	}
	resolver := requirementproofsourceset.ResolverOutputStructure()["properties"].(map[string]any)["resolverInput"]
	if !reflect.DeepEqual(resolver, compactproofcontract.InputStructure()) || !reflect.DeepEqual(requirementproofview.CompactInputStructure(), compactproofcontract.InputStructure()) {
		t.Fatal("compact child schema was redefined by a parent")
	}
}
