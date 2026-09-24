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
	if seen != 17 {
		t.Fatalf("changed source-child path count=%d, want 17", seen)
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
