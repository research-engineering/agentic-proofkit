package main

import (
	"path/filepath"
	"testing"
)

func TestSpecOverviewPathRelationIsBoundToItsChangedContract(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	input := commandAt(contract, "spec-overview-claims")["inputContract"].(map[string]any)
	root := definitions[input["rootDefinitionRef"].(string)]
	if err := admitPathRelations("spec-overview-claims", "input", input, root); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"old-id", "missing", "old-suffix", "wrong-field"} {
		t.Run(mutation, func(t *testing.T) {
			candidate := cloneRecord(input)
			relation := cloneRecord(candidate["pathRelations"].([]any)[0].(map[string]any))
			candidate["pathRelations"] = []any{relation}
			switch mutation {
			case "old-id":
				candidate["contractId"] = "proofkit.spec-overview-claims.input.v1"
			case "missing":
				delete(candidate, "pathRelations")
			case "old-suffix":
				relation["suffix"] = "/requirements.v1.json"
			case "wrong-field":
				relation["targetField"] = "overviewPath"
			}
			if err := admitPathRelations("spec-overview-claims", "input", candidate, root); err == nil {
				t.Fatal("source path relation drift was accepted")
			}
		})
	}
}
