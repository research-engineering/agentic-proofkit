package main

import (
	"path/filepath"
	"testing"
)

func TestBothBrowserEntrypointsBindTheChangedHandoffAnchor(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"requirement-browser-server", "view"} {
		t.Run(name, func(t *testing.T) {
			output := commandAt(contract, name)["outputContract"].(map[string]any)
			root := definitions[output["rootDefinitionRef"].(string)]
			if err := admitHandoffClauses(name, "output", output, root); err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []string{"missing", "old-space", "missing-source"} {
				t.Run(mutation, func(t *testing.T) {
					candidate := cloneRecord(output)
					clause := cloneRecord(candidate["handoffClauses"].([]any)[0].(map[string]any))
					candidate["handoffClauses"] = []any{clause}
					schema := cloneRecord(clause["anchorSchema"].(map[string]any))
					clause["anchorSchema"] = schema
					properties := cloneRecord(schema["properties"].(map[string]any))
					schema["properties"] = properties
					switch mutation {
					case "missing":
						delete(candidate, "handoffClauses")
					case "old-space":
						space := cloneRecord(properties["coordinateSpace"].(map[string]any))
						space["const"] = "source_wire"
						properties["coordinateSpace"] = space
					case "missing-source":
						delete(properties, "sourceId")
					}
					if err := admitHandoffClauses(name, "output", candidate, root); err == nil {
						t.Fatal("browser handoff contract drift was accepted")
					}
				})
			}
		})
	}
}
