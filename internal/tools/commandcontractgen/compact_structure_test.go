package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

func TestCompactStructureVersionAndRehashedClausesRemainOwnerBound(t *testing.T) {
	owner, ok := nativeStructureOwner(compactV2DefinitionID)
	if !ok || owner.schemaVersionField() != "schema_version" || !slices.Equal(owner.commands, []string{"requirement-proof-resolver"}) {
		t.Fatal("compact owner or version field is missing")
	}
	if _, err := nativeSchemaVersion(compactproofcontract.InputStructure(), "schemaVersion"); err == nil {
		t.Fatal("version was inferred from an unselected field")
	}
	for _, mutation := range []string{"none", "remove-condition", "weaken-order", "unknown-column", "wrong-version-field"} {
		t.Run(mutation, func(t *testing.T) {
			record, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			version, err := owner.contractVersion(record)
			if err != nil || version != json.Number("2") {
				t.Fatalf("compact wire version=%s: %v", version, err)
			}
			variant := record["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
			schema := variant["schema"].(map[string]any)
			switch mutation {
			case "remove-condition":
				schema["allOf"] = schema["allOf"].([]any)[1:]
			case "weaken-order":
				delete(schema["$defs"].(map[string]any)["order"].(map[string]any), "maximum")
			case "unknown-column":
				schema["$defs"].(map[string]any)["column-surface_id"].(map[string]any)["pattern"] = "^foreign$"
			case "wrong-version-field":
				properties := schema["properties"].(map[string]any)
				properties["schemaVersion"] = properties["schema_version"]
				delete(properties, "schema_version")
			}
			delete(record, "canonicalDigest")
			encoded, err := canonicalJSON(record)
			if err != nil {
				t.Fatal(err)
			}
			record["canonicalDigest"] = sha256Digest(encoded)
			err = admitNativeStructureDefinition(compactV2DefinitionID, record)
			if (err == nil) != (mutation == "none") {
				t.Fatalf("rehashed clause admission: %v", err)
			}
		})
	}
}

func TestCompactChildBindingsHaveExactIndependentConsumers(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	want := []nativeChildBinding{
		{"requirement-proof-view", "input", compactV2DefinitionID, [][]string{{}}, "01-compact"},
		{"requirement-browser-server", "input", compactV2DefinitionID, [][]string{{}}, "03-proof-compact"},
		{"requirement-browser-server", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, "01-coverage-compact"},
		{"requirement-coverage-input-compose", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, ""},
		{"requirement-coverage-input-compose", "output", compactV2DefinitionID, [][]string{{"compactProofContract"}}, ""},
		{"requirement-coverage-view", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, ""},
		{"requirement-impact-input-compose", "input", compactV2DefinitionID, [][]string{{"baseCompactProofContract"}, {"currentCompactProofContract"}}, ""},
		{"test-evidence-inventory", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, "03-proof-binding-derived"},
		{"requirement-proof-source-set", "output", compactV2DefinitionID, [][]string{{"resolverInput"}}, ""},
	}
	got := []nativeChildBinding{}
	for _, row := range nativeChildBindings() {
		if row.definition == compactV2DefinitionID {
			got = append(got, row)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compact consumer inventory differs: %#v", got)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range want {
		direction := commandAt(contract, row.command)[row.direction+"Contract"].(map[string]any)
		root := definitions[direction["rootDefinitionRef"].(string)]
		wantKind := "root_shape_only"
		if slices.Contains([]string{"requirement-impact-input-compose", "requirement-coverage-input-compose", "requirement-coverage-view", "test-evidence-inventory"}, row.command) {
			wantKind = "structural_json_schema"
		}
		if root.Content["fieldTree"].(map[string]any)["kind"] != wantKind {
			t.Fatalf("%s parent structure changed outside its declared closure", row.command)
		}
		bindings := direction["childDefinitionBindings"].([]any)
		for index, raw := range bindings {
			if raw.(map[string]any)["definitionRef"] != compactV2DefinitionID {
				continue
			}
			candidate := cloneRecord(direction)
			candidate["childDefinitionBindings"] = append(slices.Clone(bindings[:index]), bindings[index+1:]...)
			if admitChildBindings(row.command, row.direction, candidate, root, definitions) == nil {
				t.Fatalf("removed compact link admitted for %s/%s", row.command, row.direction)
			}
		}
	}
}
