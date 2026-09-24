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
	for _, owner := range nativeChildBindings() {
		command := commandAt(contract, owner.command)
		direction := command[owner.direction+"Contract"].(map[string]any)
		root := definitions[direction["rootDefinitionRef"].(string)]
		if err := admitChildBindings(owner.command, owner.direction, direction, root, definitions); err != nil {
			t.Fatal(err)
		}
		bindings := direction["childDefinitionBindings"].([]any)
		if len(bindings) != len(owner.paths) {
			t.Fatalf("%s %s omitted changed child paths", owner.command, owner.direction)
		}
		seen += len(bindings)
		for _, mutation := range []string{"missing", "wrong-path", "wrong-ref", "wrong-digest"} {
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
				}
				if reflect.DeepEqual(candidate, direction) || admitChildBindings(owner.command, owner.direction, candidate, root, definitions) == nil {
					t.Fatal("changed source-child relation lost its guard")
				}
			})
		}
	}
	if seen != 7 {
		t.Fatalf("changed source-child path count=%d, want 7", seen)
	}
}
