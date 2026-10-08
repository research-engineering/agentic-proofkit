package main

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
)

func TestProjectNavigationStructuresBindTwoOutputDirections(t *testing.T) {
	for _, row := range []struct {
		command string
		build   func() map[string]any
	}{
		{"status", projectstatus.StatusOutputStructure}, {"next", projectstatus.NextOutputStructure},
	} {
		id := "proofkit." + row.command + ".output.v1.json-schema"
		owner, ok := nativeStructureOwner(id)
		if !ok || owner.direction != "output" || !slices.Equal(owner.commands, []string{row.command}) || !slices.Equal(owner.predecessors, []string{"proofkit." + row.command + ".output.v1.root-shape"}) {
			t.Fatalf("wrong native navigation owner: %s", id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != json.Number("1") || owner.contractID(row.command, version) != "proofkit."+row.command+".output.v1" {
			t.Fatalf("wire or semantic identity drift: %s", id)
		}
		schema := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"]
		if !reflect.DeepEqual(schema, row.build()) {
			t.Fatalf("schema is not owner derived: %s", id)
		}
		for _, mutation := range []string{"open", "required", "version"} {
			changed, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			schema := changed["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
			switch mutation {
			case "open":
				schema["additionalProperties"] = true
			case "required":
				schema["required"] = []any{}
			case "version":
				schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = json.Number("2")
			}
			delete(changed, "canonicalDigest")
			encoded, err := canonicalJSON(changed)
			if err != nil {
				t.Fatal(err)
			}
			changed["canonicalDigest"] = sha256Digest(encoded)
			if admitNativeStructureDefinition(id, changed) == nil {
				t.Fatalf("accepted rehashed %s/%s drift", id, mutation)
			}
		}
		annotation := "root-shape-only definition " + owner.predecessors[0] + "; nested fields, types, cardinalities, and native witness execution remain native-owner claims"
		policy := "Preserve this independent caller policy."
		got, err := enrichedCompatibilitySummary(owner, "1", []any{"schemaVersion=1", annotation, policy})
		if err != nil || !reflect.DeepEqual(got, append(owner.summary("1"), policy)) {
			t.Fatalf("owned annotation or independent note lost: %s", id)
		}
		if _, err := enrichedCompatibilitySummary(owner, "1", []any{"schemaVersion=1", annotation + " " + policy}); err == nil {
			t.Fatal("accepted ambiguous annotation suffix")
		}
	}
}
