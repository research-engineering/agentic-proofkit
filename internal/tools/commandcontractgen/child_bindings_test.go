package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestChangedSourceChildrenBindTheSinglePublishedOwner(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	checked := map[string]struct{}{}
	for _, owner := range nativeChildBindings() {
		key := owner.command + "/" + owner.direction
		if _, duplicate := checked[key]; duplicate {
			continue
		}
		checked[key] = struct{}{}
		command := commandAt(contract, owner.command)
		direction := command[owner.direction+"Contract"].(map[string]any)
		root := definitions[direction["rootDefinitionRef"].(string)]
		if err := admitChildBindings(owner.command, owner.direction, direction, root, definitions); err != nil {
			t.Fatal(err)
		}
		bindings := direction["childDefinitionBindings"].([]any)
		expected, err := childBindingValues(owner.command, owner.direction, definitions)
		if err != nil || len(bindings) != len(expected) {
			t.Fatalf("%s %s omitted changed child paths", owner.command, owner.direction)
		}
		seen += len(bindings)
		for _, mutation := range []string{"missing", "wrong-path", "wrong-ref", "wrong-digest", "wrong-variant"} {
			t.Run(owner.command+"/"+owner.direction+"/"+mutation, func(t *testing.T) {
				candidate := cloneRecord(direction)
				copyBindings := make([]any, len(bindings))
				for index, raw := range bindings {
					copyBindings[index] = cloneRecord(raw.(map[string]any))
				}
				candidate["childDefinitionBindings"] = copyBindings
				first := copyBindings[0].(map[string]any)
				switch mutation {
				case "missing":
					candidate["childDefinitionBindings"] = []any{}
				case "wrong-path":
					first["pathSegments"] = []any{"unrelated"}
				case "wrong-ref":
					first["definitionRef"] = root.ID
				case "wrong-digest":
					first["definitionDigest"] = root.Digest
				case "wrong-variant":
					first["variantId"] = "nonexistent-variant"
				}
				if reflect.DeepEqual(candidate, direction) || admitChildBindings(owner.command, owner.direction, candidate, root, definitions) == nil {
					t.Fatal("changed source-child relation lost its guard")
				}
			})
		}
	}
	if seen != 32 {
		t.Fatalf("changed source-child path count=%d, want 32", seen)
	}
}

func TestNullableChildBindingPreservesExactNonnullOwner(t *testing.T) {
	child := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"id": map[string]any{"type": "string"}}}
	for _, keyword := range []string{"anyOf", "oneOf"} {
		for _, reversed := range []bool{false, true} {
			values := []any{map[string]any{"type": "null"}, child}
			if reversed {
				values[0], values[1] = values[1], values[0]
			}
			if !equalBoundChildSchema(map[string]any{keyword: values}, child) {
				t.Fatal("nullable child lost its owner")
			}
		}
		for _, bad := range []map[string]any{
			{keyword: []any{map[string]any{"type": "null"}, map[string]any{"type": "object"}}},
			{keyword: []any{map[string]any{"type": "null"}, child, map[string]any{"type": "string"}}},
			{keyword: []any{child, child}},
			{keyword: []any{map[string]any{"type": "null", "not": true}, child}},
			{keyword: []any{map[string]any{"type": "null"}, child}, "not": true},
			{keyword: []any{nil, child}},
		} {
			if equalBoundChildSchema(bad, child) {
				t.Fatal("nullable wrapper admitted unowned semantics")
			}
		}
	}
}

func TestContextCatalogPathIsAFileReferenceNotAnInlineSource(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	command := commandAt(contract, "requirement-context-compose")
	input := command["inputContract"].(map[string]any)
	root := definitions[input["rootDefinitionRef"].(string)]
	schema := root.Content["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
	leaf, err := schemaChildAtPath(schema, []any{"requirementSources", "*"})
	if err != nil {
		t.Fatal(err)
	}
	child := definitions[sourceV2DefinitionID].Content["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
	if equalSchemaIgnoringDialect(leaf, child) || leaf["properties"].(map[string]any)["path"] == nil {
		t.Fatal("catalog path reference was promoted to inline source content")
	}
	if _, claimed := input["childDefinitionBindings"]; claimed {
		t.Fatal("catalog input claims an inline source child")
	}
}
